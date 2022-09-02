/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "routing.h"

struct route_args {
	char *iface;
	char *metric;
	char destination[16];
	char gateway[16];
	char mask[16];
};

struct route6_args {
	char *iface;
	char *metric;
	char destination[INET6_ADDRSTRLEN + 8];
	char gateway[INET6_ADDRSTRLEN + 8];
};

struct routingfwdargs
{
	char *permission;
	struct uci_section *routefwdsection;
	int type;
};

enum enum_route_type {
	ROUTE_STATIC,
	ROUTE_DYNAMIC
};

#define MAX_ROUTE_LEN 512

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_router(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rt_table", linker);
	return 0;
}

/********************************
 * init function
 ********************************/
static inline int init_args_ipv4forward(struct routingfwdargs *args, struct uci_section *s, char *permission, int type)
{
	args->permission = permission;
	args->routefwdsection = s;
	args->type = type;
	return 0;
}

static inline int init_args_ipv6forward(struct routingfwdargs *args, struct uci_section *s, char *permission, int type)
{
	args->permission = permission;
	args->routefwdsection = s;
	args->type = type;
	return 0;
}

/************************************************************************************* 
**** function related to get_object_router_ipv4forwarding ****
**************************************************************************************/
static bool is_route_in_config(struct route_args *route)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "route", "target", route->destination, s) {
		char *mask = NULL;

		dmuci_get_value_by_section_string(s, "netmask", &mask);
		if (DM_STRLEN(mask) == 0)
			return true;

		if (DM_STRCMP(route->mask, mask) == 0)
			return true;
	}

	uci_path_foreach_sections(bbfdm, "dmmap_routing", "route_dynamic", s) {
		char *target = NULL, *gateway = NULL, *device = NULL;

		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "gateway", &gateway);
		dmuci_get_value_by_section_string(s, "device", &device);
		if (DM_STRCMP(target, route->destination) == 0 && DM_STRCMP(gateway, route->gateway) == 0 && DM_STRCMP(device, route->iface) == 0)
			return true;
	}

	return false;
}

static bool is_route6_in_config(struct route6_args *route6)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("network", "route6", s) {
		char *ip_r = NULL, *gw_r = NULL, *intf_r = NULL;

		dmuci_get_value_by_section_string(s, "target", &ip_r);
		dmuci_get_value_by_section_string(s, "gateway", &gw_r);
		dmuci_get_value_by_section_string(s, "interface", &intf_r);
		char *dev_r = get_l3_device(intf_r);
		if (DM_STRCMP(route6->iface, dev_r) == 0 && DM_STRCMP(route6->gateway, gw_r) == 0 && DM_STRCMP(route6->destination, ip_r) == 0)
			return true;
	}

	uci_path_foreach_sections(bbfdm, "dmmap_routing", "route6_dynamic", s) {
		char *ip_r6d = NULL, *gw_r6d = NULL, *dev_r6d = NULL;

		dmuci_get_value_by_section_string(s, "target", &ip_r6d);
		dmuci_get_value_by_section_string(s, "gateway", &gw_r6d);
		dmuci_get_value_by_section_string(s, "device", &dev_r6d);
		if (DM_STRCMP(route6->iface, dev_r6d) == 0 && DM_STRCMP(route6->gateway, gw_r6d) == 0 && DM_STRCMP(route6->destination, ip_r6d) == 0)
			return true;
	}

	return false;
}

static void parse_route_line(char *line, struct route_args *route)
{
	size_t length = 0;

	char **arr = strsplit(line, " ", &length);
	if (arr == NULL || length == 0)
		return;

	for (int i = 0; i < length; i++) {
		if (strcmp(arr[i], "default") == 0) {
			DM_STRNCPY(route->gateway, arr[i + 2], sizeof(route->gateway));
			DM_STRNCPY(route->destination, "0.0.0.0", sizeof(route->destination));
			DM_STRNCPY(route->mask, "0.0.0.0", sizeof(route->mask));
			i += 2;
		}

		if (i == 0 && strcmp(arr[i], "default") != 0) {
			char *p = strchr(arr[i], '/');
			if (p) *p = 0;

			DM_STRNCPY(route->destination, arr[i], sizeof(route->destination));
			DM_STRNCPY(route->mask, (p && DM_STRLEN(p + 1)) ? cidr2netmask(DM_STRTOL(p + 1)) : "0.0.0.0", sizeof(route->mask));
			DM_STRNCPY(route->gateway, "0.0.0.0", sizeof(route->gateway));
		}

		if (strcmp(arr[i], "dev") == 0) {
			route->iface = arr[i + 1];
			i += 1;
		}

		if (strcmp(arr[i], "metric") == 0) {
			route->metric = arr[i + 1];
			i += 1;
		}
	}

	if (route->metric == NULL)
		route->metric = "0";

	if (route->iface == NULL)
		route->iface = "";
}

static int parse_route6_line(const char *line, struct route6_args *route6)
{
	size_t length = 0;

	char **arr = strsplit(line, " ", &length);
	if (arr == NULL || length == 0)
		return -1;

	for (int i = 0; i < length; i++) {

		if (strcmp(arr[i], "dev") == 0 && strcmp(arr[i + 1], "lo") == 0)
			return -1;

		if (strcmp(arr[i], "default") == 0) {
			DM_STRNCPY(route6->gateway, arr[i + 2], sizeof(route6->gateway));
			DM_STRNCPY(route6->destination, "::", sizeof(route6->destination));
			i += 2;
		}

		if (i == 0 && strcmp(arr[i], "default") != 0) {
			DM_STRNCPY(route6->destination, arr[i], sizeof(route6->destination));
			DM_STRNCPY(route6->gateway, "::", sizeof(route6->gateway));
		}

		if (strcmp(arr[i], "dev") == 0) {
			route6->iface = arr[i + 1];
			i += 1;
		}

		if (strcmp(arr[i], "metric") == 0) {
			route6->metric = arr[i + 1];
			i += 1;
		}
	}

	if (route6->metric == NULL)
		route6->metric = "0";

	if (route6->iface == NULL)
		route6->iface = "";

	return 0;
}

static void dmmap_synchronizeRoutingRouterIPv4Forwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *router_s = (struct uci_section *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct route_args route = {0};
	FILE *pp = NULL;
	char *rt_table = NULL;
	char line[MAX_ROUTE_LEN] = {0};
	char cmd[32] = {0};

	dmuci_get_value_by_section_string(router_s, "rt_table", &rt_table);
	snprintf(cmd, sizeof(cmd), "ip route show table %s", rt_table);

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_routing", "route_dynamic", "table", rt_table, stmp, s) {
		char *target = NULL, *iface = NULL;

		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "device", &iface);

		pp = popen(cmd, "r");
		if (pp != NULL) {
			bool found = false;

			while (fgets(line, MAX_ROUTE_LEN, pp) != NULL) {
				remove_new_line(line);
				parse_route_line(line, &route);
				if ((DM_STRCMP(iface, route.iface) == 0) && DM_STRCMP(target, route.destination) == 0) {
					found = true;
					break;
				}
			}

			if (!found)
				dmuci_delete_by_section(s, NULL, NULL);

			pclose(pp);
		}
	}

	pp = popen(cmd, "r");
	if (pp != NULL) {
		while (fgets(line, MAX_ROUTE_LEN, pp) != NULL) {
			remove_new_line(line);

			parse_route_line(line, &route);
			if (is_route_in_config(&route))
				continue;

			char *iface = NULL;
			uci_foreach_sections("network", "interface", s) {
				char *str = get_l3_device(section_name(s));
				if (DM_STRCMP(str, route.iface) == 0) {
					iface = section_name(s);
					break;
				}
			}

			dmuci_add_section_bbfdm("dmmap_routing", "route_dynamic", &s);
			dmuci_set_value_by_section_bbfdm(s, "target", route.destination);
			dmuci_set_value_by_section_bbfdm(s, "netmask", route.mask);
			dmuci_set_value_by_section_bbfdm(s, "metric", route.metric);
			dmuci_set_value_by_section_bbfdm(s, "gateway", route.gateway);
			dmuci_set_value_by_section_bbfdm(s, "device", route.iface);
			dmuci_set_value_by_section_bbfdm(s, "interface", iface ? iface : "");
			dmuci_set_value_by_section_bbfdm(s, "table", rt_table);
		}
		pclose(pp);
	}
}

static void dmmap_synchronizeRoutingRouterIPv6Forwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *router_s = (struct uci_section *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct route6_args route6 = {0};
	FILE *pp = NULL;
	char *rt_table = NULL;
	char line[MAX_ROUTE_LEN] = {0};
	char cmd[32] = {0};

	dmuci_get_value_by_section_string(router_s, "rt_table", &rt_table);
	snprintf(cmd, sizeof(cmd), "ip -6 route show table %s", rt_table);

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_routing", "route6_dynamic", "table", rt_table, stmp, s) {
		char *iface = NULL, *target = NULL;

		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "device", &iface);

		pp = popen(cmd, "r");
		if (pp != NULL) {
			bool found = false;

			while (fgets(line, MAX_ROUTE_LEN, pp) != NULL) {
				remove_new_line(line);

				if (parse_route6_line(line, &route6))
					continue;

				if (DM_STRCMP(iface, route6.iface) == 0 && DM_STRCMP(route6.destination, target) == 0) {
					found = 1;
					break;
				}
			}

			if (!found)
				dmuci_delete_by_section(s, NULL, NULL);

			pclose(pp);
		}
	}

	pp = popen(cmd, "r");
	if (pp != NULL) {
		while (fgets(line, MAX_ROUTE_LEN, pp) != NULL) {
			remove_new_line(line);

			if (parse_route6_line(line, &route6))
				continue;

			if (is_route6_in_config(&route6))
				continue;

			char *iface = NULL;
			uci_foreach_sections("network", "interface", s) {
				char *str = get_l3_device(section_name(s));
				if (DM_STRCMP(str, route6.iface) == 0) {
					iface = section_name(s);
					break;
				}
			}

			dmuci_add_section_bbfdm("dmmap_routing", "route6_dynamic", &s);
			dmuci_set_value_by_section_bbfdm(s, "target", route6.destination);
			dmuci_set_value_by_section_bbfdm(s, "gateway", route6.gateway);
			dmuci_set_value_by_section_bbfdm(s, "interface", iface ? iface : "");
			dmuci_set_value_by_section_bbfdm(s, "device", route6.iface);
			dmuci_set_value_by_section_bbfdm(s, "metric", route6.metric);
			dmuci_set_value_by_section_bbfdm(s, "table", rt_table);
		}
		pclose(pp);
	}
}

static void create_routing_route_section(char *rt_table)
{
	if (!is_dmmap_section_exist_eq("dmmap_routing", "router", "rt_table", rt_table)) {
		struct uci_section *s = NULL;

		dmuci_add_section_bbfdm("dmmap_routing", "router", &s);
		dmuci_set_value_by_section(s, "rt_table", rt_table);
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseRouterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL, *idx = NULL, *device = NULL, *proto = NULL;
	struct uci_section *dmmap_route = NULL;

	create_routing_route_section("254");
	uci_foreach_sections("network", "interface", s) {

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "device", &device);
		dmuci_get_value_by_section_string(s, "ip4table", &idx);

		if (strcmp(section_name(s), "loopback") == 0 ||
			*proto == '\0' ||
			DM_STRCHR(device, '@'))
			continue;

		if (DM_STRLEN(idx))
			create_routing_route_section(idx);
	}

	uci_path_foreach_sections(bbfdm, "dmmap_routing", "router", dmmap_route) {

		inst = handle_instance(dmctx, parent_node, dmmap_route, "router_instance", "router_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dmmap_route, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.!UCI:network/route/dmmap_routing*/
static int browseIPv4ForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *router_s = (struct uci_section *)prev_data;
	struct routingfwdargs curr_routefwdargs = {0};
	struct uci_section *s = NULL;
	struct dmmap_dup *p = NULL;
	char *rt_table = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	dmuci_get_value_by_section_string(router_s, "rt_table", &rt_table);

	// Enable Routes
	synchronize_specific_config_sections_with_dmmap("network", "route", "dmmap_routing", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *table = NULL;

		dmuci_get_value_by_section_string(p->config_section, "table", &table);
		if (DM_STRCMP(rt_table, table) != 0 || (DM_STRLEN(table) == 0 && DM_STRCMP(rt_table, "254") != 0))
			continue;

		init_args_ipv4forward(&curr_routefwdargs, p->config_section, "1", ROUTE_STATIC);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "route_instance", "route_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Dynamic Routes
	dmmap_synchronizeRoutingRouterIPv4Forwarding(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_routing", "route_dynamic", "table", rt_table, s) {

		init_args_ipv4forward(&curr_routefwdargs, s, "0", ROUTE_DYNAMIC);

		inst = handle_instance(dmctx, parent_node, s, "route_instance", "route_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, inst) == DM_STOP)
			goto end;
	}

end:
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.!UCI:network/route6/dmmap_routing*/
static int browseIPv6ForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *router_s = (struct uci_section *)prev_data;
	struct routingfwdargs curr_route6fwdargs = {0};
	struct uci_section *s = NULL;
	struct dmmap_dup *p = NULL;
	char *rt_table = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	dmuci_get_value_by_section_string(router_s, "rt_table", &rt_table);

	// Enable Routes
	synchronize_specific_config_sections_with_dmmap("network", "route6", "dmmap_routing", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *table = NULL;

		dmuci_get_value_by_section_string(p->config_section, "table", &table);
		if (DM_STRCMP(rt_table, table) != 0 || (DM_STRLEN(table) == 0 && DM_STRCMP(rt_table, "254") != 0))
			continue;

		init_args_ipv6forward(&curr_route6fwdargs, p->config_section, "1", ROUTE_STATIC);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "route6_instance", "route6_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Dynamic Routes
	dmmap_synchronizeRoutingRouterIPv6Forwarding(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_routing", "route6_dynamic", "table", rt_table, s) {

		init_args_ipv6forward(&curr_route6fwdargs, s, "0", ROUTE_DYNAMIC);

		inst = handle_instance(dmctx, parent_node, s, "route6_instance", "route6_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, inst) == DM_STOP)
			goto end;
	}

end:
	return 0;
}

static int browseRoutingRouteInformationInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;
	int id = 0, i;

	uci_foreach_sections("network", "interface", s) {
		char *proto = NULL, *ip6addr = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ip6addr", &ip6addr);
		if ((proto && DM_LSTRCMP(proto, "dhcpv6") == 0) || (ip6addr && ip6addr[0] != '\0')) {
			json_object *res = NULL, *route_obj = NULL, *arrobj = NULL;

			char *if_name = section_name(s);
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
			dmjson_foreach_obj_in_array(res, arrobj, route_obj, i, 1, "route") {
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)route_obj, inst) == DM_STOP)
					break;
			}
		}
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_router_nbr_entry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_RoutingRouter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_RoutingRouter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_RoutingRouter_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4ForwardingNumberOfEntries!UCI:network/route/*/
static int get_RoutingRouter_IPv4ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPv4ForwardingInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6ForwardingNumberOfEntries!UCI:network/route6/*/
static int get_RoutingRouter_IPv6ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPv6ForwardingInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_router_ipv4forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC) {
		*value = "1";
	} else {
		char *disabled = NULL;

		dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "disabled", &disabled);
		*value = (disabled && *disabled == '1') ? "0" : "1";
	}
	return 0;
}

static int set_router_ipv4forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_router_ipv4forwarding_enable(refparam, ctx, data, instance, value);
	*value = ((*value)[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.DestIPAddress!UCI:network/route,@i-1/target*/
static int get_router_ipv4forwarding_destip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "target", value);
	return 0;
}

static int set_router_ipv4forwarding_destip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "target", value);
			return 0;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.DestSubnetMask!UCI:network/route,@i-1/netmask*/
static int get_router_ipv4forwarding_destmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "netmask", value);
	return 0;
}

static int set_router_ipv4forwarding_destmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "netmask", value);
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_static_route(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (((struct routingfwdargs *)data)->type != ROUTE_DYNAMIC) ? "1" : "0";
	return 0;
}

static int get_router_ipv4forwarding_forwarding_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "table", "-1");
	return 0;
}

static int set_router_ipv4forwarding_forwarding_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;

			uci_path_foreach_sections(bbfdm, "dmmap_routing", "router", s) {
				char *rt_table = NULL;

				dmuci_get_value_by_section_string(s, "rt_table", &rt_table);
				if (DM_STRCMP(value, rt_table) == 0)
					return 0;
			}

			return FAULT_9007;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "table", value);

			get_dmmap_section_of_config_section("dmmap_routing", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "route_instance", "");
			break;
	}
	return 0;
}

static int get_router_ipv4forwarding_origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct routingfwdargs *)data)->type != ROUTE_DYNAMIC)
		*value = "Static";
	else {
		json_object *res = NULL;
		char *interface;

		dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "interface", &interface);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
		DM_ASSERT(res, *value = "DHCPv4");
		char *proto = dmjson_get_value(res, 1, "proto");
		*value = (proto && DM_LSTRNCMP(proto, "ppp", 3) == 0) ? "IPCP" : "DHCPv4";
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.GatewayIPAddress!UCI:network/route,@i-1/gateway*/
static int get_router_ipv4forwarding_gatewayip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "gateway", value);
	return 0;
}

static int set_router_ipv4forwarding_gatewayip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "gateway", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "interface", &linker);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int set_RoutingRouterForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "interface", linker ? linker : "");
			return 0;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.ForwardingMetric!UCI:network/route,@i-1/metric*/
static int get_router_ipv4forwarding_metric(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "metric", "0");
	return 0;
}

static int set_router_ipv4forwarding_metric(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "metric", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC) {
		*value = "1";
	} else {
		char *disabled = NULL;

		dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "disabled", &disabled);
		*value = (disabled && *disabled == '1') ? "0" : "1";
	}
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_RoutingRouterIPv6Forwarding_Enable(refparam, ctx, data, instance, value);
	*value = ((*value)[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.DestIPPrefix!UCI:network/route,@i-1/target*/
static int get_RoutingRouterIPv6Forwarding_DestIPPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "target", value);
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_DestIPPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, IPv6Prefix))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "target", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "table", "-1");
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;

			uci_path_foreach_sections(bbfdm, "dmmap_routing", "router", s) {
				char *rt_table = NULL;

				dmuci_get_value_by_section_string(s, "rt_table", &rt_table);
				if (DM_STRCMP(value, rt_table) == 0)
					return 0;
			}

			return FAULT_9007;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "table", value);

			get_dmmap_section_of_config_section("dmmap_routing", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "route_instance", "");
			break;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.NextHop!UCI:network/route,@i-1/gateway*/
static int get_RoutingRouterIPv6Forwarding_NextHop(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct routingfwdargs *)data)->routefwdsection, "gateway", value);
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_NextHop(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPv6Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "gateway", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (((struct routingfwdargs *)data)->type != ROUTE_DYNAMIC) ? "Static" : "DHCPv6";
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.ForwardingMetric!UCI:network/route,@i-1/metric*/
static int get_RoutingRouterIPv6Forwarding_ForwardingMetric(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "metric", "0");
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_ForwardingMetric(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "metric", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_ExpirationTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "9999-12-31T23:59:59Z";
	return 0;
}

static int get_RoutingRouteInformation_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_RoutingRouteInformation_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_RoutingRouteInformation_InterfaceSettingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	size_t nbre_routes = 0;

	uci_foreach_sections("network", "interface", s) {
		char *proto = NULL, *ip6addr = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ip6addr", &ip6addr);
		if ((proto && DM_LSTRCMP(proto, "dhcpv6") == 0) || (ip6addr && ip6addr[0] != '\0')) {
			json_object *res = NULL, *routes = NULL;

			char *if_name = section_name(s);
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
			DM_ASSERT(res, *value = "0");
			json_object_object_get_ex(res, "route", &routes);
			nbre_routes = (routes) ? json_object_array_length(routes) : 0;
		}
	}
	dmasprintf(value, "%d", nbre_routes);
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *target, *mask, *nexthop, *gateway, *ip_target, buf[64];

	*value = "NoForwardingEntry";
	target = dmjson_get_value((struct json_object *)data, 1, "target");
	mask = dmjson_get_value((struct json_object *)data, 1, "mask");
	snprintf(buf, sizeof(buf), "%s/%s", target, mask);
	nexthop = dmjson_get_value((struct json_object *)data, 1, "nexthop");
	uci_foreach_sections("network", "route6", s) {
		dmuci_get_value_by_section_string(s, "target", &ip_target);
		dmuci_get_value_by_section_string(s, "gateway", &gateway);
		if(DM_STRCMP(ip_target, buf) == 0 && DM_STRCMP(nexthop, gateway) == 0) {
			*value = "ForwardingEntryCreated";
			return 0;
		}
	}
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct route6_args route6 = {0};
	struct uci_section *s = NULL;
	char line[MAX_ROUTE_LEN] = {0};
	char cmd[32] = {0};
	char *iface = NULL;

	char *source = dmjson_get_value((struct json_object *)data, 1, "source");
	char *nexthop = dmjson_get_value((struct json_object *)data, 1, "nexthop");

	snprintf(cmd, sizeof(cmd), "ip -6 route show");

	FILE *pp = fopen(PROC_ROUTE6, "r");
	if (pp != NULL) {
		while (fgets(line, MAX_ROUTE_LEN, pp) != NULL) {
			remove_new_line(line);

			if (parse_route6_line(line, &route6))
				continue;

			if((DM_STRCMP(source, route6.destination) == 0) && (DM_STRCMP(nexthop, route6.gateway) == 0))
				break;
		}

		pclose(pp);
	}

	if (DM_STRLEN(route6.iface)) {
		uci_foreach_sections("network", "interface", s) {
			char *str = get_l3_device(section_name(s));
			if (DM_STRCMP(str, route6.iface) == 0) {
				iface = section_name(s);
				break;
			}
		}
	}

	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", iface, value);
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_SourceRouter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((struct json_object *)data, 1, "target");
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_RouteLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";

	char *valid = dmjson_get_value((struct json_object *)data, 1, "valid");
	if (valid && *valid != '\0' && DM_STRTOL(valid) > 0) {
		char local_time[32] = {0};

		if (get_shift_utc_time(DM_STRTOL(valid), local_time, sizeof(local_time)) == -1)
			return 0;
		*value = dmstrdup(local_time);
	}
	return 0;
}

/*************************************************************
* SET AND GET ALIAS FOR ROUTER OBJ
**************************************************************/
static int get_RoutingRouter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "router_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_RoutingRouter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "router_alias", value);
			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int route_type = ((struct routingfwdargs *)data)->type;
	struct uci_section *dmmap_section = NULL;

	if (route_type == ROUTE_DYNAMIC)
		dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
	else
		get_dmmap_section_of_config_section("dmmap_routing", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

	dmuci_get_value_by_section_string(dmmap_section, "route_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_router_ipv4forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int route_type = ((struct routingfwdargs *)data)->type;
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (route_type == ROUTE_DYNAMIC)
				dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
			else
				get_dmmap_section_of_config_section("dmmap_routing", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

			dmuci_set_value_by_section(dmmap_section, "route_alias", value);
			return 0;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int route6_type = ((struct routingfwdargs *)data)->type;
	struct uci_section *dmmap_section = NULL;

	if (route6_type == ROUTE_DYNAMIC)
		dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
	else
		get_dmmap_section_of_config_section("dmmap_routing", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

	dmuci_get_value_by_section_string(dmmap_section, "route6_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int route6_type = ((struct routingfwdargs *)data)->type;
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (route6_type == ROUTE_DYNAMIC)
				dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
			else
				get_dmmap_section_of_config_section("dmmap_routing", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

			dmuci_set_value_by_section(dmmap_section, "route6_alias", value);
			return 0;
	}
	return 0;
}

static char *get_routing_perm(char *refparam, struct dmctx *dmctx, void *data, char *instance)
{
	if (data != NULL)
		return ((struct routingfwdargs *)data)->permission;

	return NULL;
}

struct dm_permession_s DMRouting = {"1", &get_routing_perm};

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_router(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
#define LOCAL_TABLE_ID 255
	struct uci_section *dmmap_s = NULL;
	char rt_table[32] = {0};

	snprintf(rt_table, sizeof(rt_table), "%ld", LOCAL_TABLE_ID + DM_STRTOL(*instance) - 1);

	dmuci_add_section_bbfdm("dmmap_routing", "router", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "rt_table", rt_table);
	dmuci_set_value_by_section(dmmap_s, "router_instance", *instance);
	return 0;
}

static int delete_router(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL;
	char *rt_table = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "rt_table", &rt_table);
			if(DM_LSTRCMP(rt_table, "254") == 0)
				break;

			uci_foreach_sections("network", "interface", s) {
				char *curr_rt_table = NULL;

				dmuci_get_value_by_section_string(s, "ip4table", &curr_rt_table);
				if (DM_STRCMP(curr_rt_table, rt_table) == 0)
					dmuci_set_value_by_section(s, "ip4table", "");
			}

			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			return FAULT_9005;
		}
	return 0;
}

static int add_ipv4forwarding(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_route = NULL;
	char *rt_table = NULL;
	char route_name[32];

	dmuci_get_value_by_section_string((struct uci_section *)data, "rt_table", &rt_table);
	snprintf(route_name, sizeof(route_name), "route_%s", *instance);

	dmuci_add_section("network", "route", &s);
	dmuci_rename_section_by_section(s, route_name);
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "table", rt_table);

	dmuci_add_section_bbfdm("dmmap_routing", "route", &dmmap_route);
	dmuci_set_value_by_section(dmmap_route, "section_name", route_name);
	dmuci_set_value_by_section(dmmap_route, "route_instance", *instance);
	return 0;
}

static int delete_ipv4forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *route_s = NULL, *stmp = NULL, *dmmap_section = NULL;
	char *rt_table = NULL;

	switch (del_action) {
		case DEL_INST:
			// Return 9008 error if the removed route is dynamic
			if (((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
				return FAULT_9008;

			// Remove dmmap section
			get_dmmap_section_of_config_section("dmmap_routing", "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove config section
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "rt_table", &rt_table);

			// Remove all static routes
			uci_foreach_option_eq_safe("network", "route", "rt_table", rt_table, stmp, route_s) {

				// Remove dmmap section
				get_dmmap_section_of_config_section("dmmap_routing", "route", section_name(route_s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove config section
				dmuci_delete_by_section(route_s, NULL, NULL);
			}
			break;
		}
	return 0;
}

static int add_ipv6Forwarding(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_route6 = NULL;
	char *rt_table = NULL;
	char route6_name[32];

	dmuci_get_value_by_section_string((struct uci_section *)data, "rt_table", &rt_table);
	snprintf(route6_name, sizeof(route6_name), "route6_%s", *instance);

	dmuci_add_section("network", "route6", &s);
	dmuci_rename_section_by_section(s, route6_name);
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "table", rt_table);

	dmuci_add_section_bbfdm("dmmap_routing", "route6", &dmmap_route6);
	dmuci_set_value_by_section(dmmap_route6, "section_name", route6_name);
	dmuci_set_value_by_section(dmmap_route6, "route6_instance", *instance);
	return 0;
}

static int delete_ipv6Forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *route6_s = NULL, *stmp = NULL, *dmmap_section = NULL;
	char *rt_table = NULL;

	switch (del_action) {
		case DEL_INST:
			// Return 9008 error if the removed route6 is dynamic
			if (((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
				return FAULT_9008;

			// Remove dmmap section
			get_dmmap_section_of_config_section("dmmap_routing", "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove config section
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "rt_table", &rt_table);

			// Remove all static enable routes
			uci_foreach_option_eq_safe("network", "route6", "rt_table", rt_table, stmp, route6_s) {

				// Remove dmmap section
				get_dmmap_section_of_config_section("dmmap_routing", "route6", section_name(route6_s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove config section
				dmuci_delete_by_section(route6_s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Routing. *** */
DMOBJ tRoutingObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Router", &DMWRITE, add_router, delete_router, NULL, browseRouterInst, NULL, NULL, tRoutingRouterObj, tRoutingRouterParams, get_linker_router, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
{"RouteInformation", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tRoutingRouteInformationObj, tRoutingRouteInformationParams, NULL, BBFDM_BOTH, NULL, "2.2"},
{0}
};

DMLEAF tRoutingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"RouterNumberOfEntries", &DMREAD, DMT_UNINT, get_router_nbr_entry, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.Routing.Router.{i}. *** */
DMOBJ tRoutingRouterObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"IPv4Forwarding", &DMWRITE, add_ipv4forwarding, delete_ipv4forwarding, NULL, browseIPv4ForwardingInst, NULL, NULL, NULL, tRoutingRouterIPv4ForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"DestIPAddress", "DestSubnetMask", "ForwardingPolicy", "GatewayIPAddress", "Interface", "ForwardingMetric", "Alias", NULL}, "2.0"},
{"IPv6Forwarding", &DMWRITE, add_ipv6Forwarding, delete_ipv6Forwarding, NULL, browseIPv6ForwardingInst, NULL, NULL, NULL, tRoutingRouterIPv6ForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"DestIPPrefix", "ForwardingPolicy", "NextHop", "Interface", "ForwardingMetric", "Alias", NULL}, "2.2"},
{0}
};

DMLEAF tRoutingRouterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_RoutingRouter_Enable, set_RoutingRouter_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_RoutingRouter_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_RoutingRouter_Alias, set_RoutingRouter_Alias, BBFDM_BOTH, "2.0"},
{"IPv4ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouter_IPv4ForwardingNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"IPv6ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouter_IPv6ForwardingNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Routing.Router.{i}.IPv4Forwarding.{i}. *** */
DMLEAF tRoutingRouterIPv4ForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMRouting, DMT_BOOL, get_router_ipv4forwarding_enable, set_router_ipv4forwarding_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_router_ipv4forwarding_status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_router_ipv4forwarding_alias, set_router_ipv4forwarding_alias, BBFDM_BOTH, "2.0"},
{"StaticRoute", &DMREAD, DMT_BOOL, get_router_ipv4forwarding_static_route, NULL, BBFDM_BOTH, "2.0"},
{"DestIPAddress", &DMRouting, DMT_STRING, get_router_ipv4forwarding_destip, set_router_ipv4forwarding_destip, BBFDM_BOTH, "2.0"},
{"DestSubnetMask", &DMRouting, DMT_STRING, get_router_ipv4forwarding_destmask, set_router_ipv4forwarding_destmask, BBFDM_BOTH, "2.0"},
{"ForwardingPolicy", &DMRouting, DMT_INT, get_router_ipv4forwarding_forwarding_policy, set_router_ipv4forwarding_forwarding_policy, BBFDM_BOTH, "2.0"},
{"GatewayIPAddress", &DMRouting, DMT_STRING, get_router_ipv4forwarding_gatewayip, set_router_ipv4forwarding_gatewayip, BBFDM_BOTH, "2.0"},
{"Interface", &DMRouting, DMT_STRING, get_RoutingRouterForwarding_Interface, set_RoutingRouterForwarding_Interface, BBFDM_BOTH, "2.0"},
{"Origin", &DMREAD, DMT_STRING, get_router_ipv4forwarding_origin, NULL, BBFDM_BOTH, "2.2"},
{"ForwardingMetric", &DMRouting, DMT_INT, get_router_ipv4forwarding_metric, set_router_ipv4forwarding_metric, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.Routing.Router.{i}.IPv6Forwarding.{i}. *** */
DMLEAF tRoutingRouterIPv6ForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMRouting, DMT_BOOL, get_RoutingRouterIPv6Forwarding_Enable, set_RoutingRouterIPv6Forwarding_Enable, BBFDM_BOTH, "2.2"},
{"Status", &DMREAD, DMT_STRING, get_RoutingRouterIPv6Forwarding_Status, NULL, BBFDM_BOTH, "2.2"},
{"Alias", &DMWRITE, DMT_STRING, get_RoutingRouterIPv6Forwarding_Alias, set_RoutingRouterIPv6Forwarding_Alias, BBFDM_BOTH, "2.2"},
{"DestIPPrefix", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_DestIPPrefix, set_RoutingRouterIPv6Forwarding_DestIPPrefix, BBFDM_BOTH, "2.2"},
{"ForwardingPolicy", &DMRouting, DMT_INT, get_RoutingRouterIPv6Forwarding_ForwardingPolicy, set_RoutingRouterIPv6Forwarding_ForwardingPolicy, BBFDM_BOTH, "2.2"},
{"NextHop", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_NextHop, set_RoutingRouterIPv6Forwarding_NextHop, BBFDM_BOTH, "2.2"},
{"Interface", &DMRouting, DMT_STRING, get_RoutingRouterForwarding_Interface, set_RoutingRouterForwarding_Interface, BBFDM_BOTH, "2.2"},
{"Origin", &DMREAD, DMT_STRING, get_RoutingRouterIPv6Forwarding_Origin, NULL, BBFDM_BOTH, "2.2"},
{"ForwardingMetric", &DMRouting, DMT_INT, get_RoutingRouterIPv6Forwarding_ForwardingMetric, set_RoutingRouterIPv6Forwarding_ForwardingMetric, BBFDM_BOTH, "2.2"},
{"ExpirationTime", &DMREAD, DMT_TIME, get_RoutingRouterIPv6Forwarding_ExpirationTime, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Routing.RouteInformation. *** */
DMOBJ tRoutingRouteInformationObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"InterfaceSetting", &DMREAD, NULL, NULL, NULL, browseRoutingRouteInformationInterfaceSettingInst, NULL, NULL, NULL, tRoutingRouteInformationInterfaceSettingParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", NULL}, "2.2"},
{0}
};

DMLEAF tRoutingRouteInformationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_RoutingRouteInformation_Enable, set_RoutingRouteInformation_Enable, BBFDM_BOTH, "2.2"},
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouteInformation_InterfaceSettingNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Routing.RouteInformation.InterfaceSetting.{i}. *** */
DMLEAF tRoutingRouteInformationInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Status", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_Status, NULL, BBFDM_BOTH, "2.2"},
{"Interface", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_Interface, NULL, BBFDM_BOTH, "2.2"},
{"SourceRouter", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_SourceRouter, NULL, BBFDM_BOTH, "2.2"},
{"RouteLifetime", &DMREAD, DMT_TIME, get_RoutingRouteInformationInterfaceSetting_RouteLifetime, NULL, BBFDM_BOTH, "2.2"},
{0}
};
