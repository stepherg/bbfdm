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

#include "dmentry.h"
#include "routing.h"

struct proc_routing {
	char *iface;
	char *flags;
	char *refcnt;
	char *use;
	char *metric;
	char *mtu;
	char *window;
	char *irtt;
	char destination[16];
	char gateway[16];
	char mask[16];
};

struct routingfwdargs
{
	char *permission;
	struct uci_section *routefwdsection;
	int type;
};

enum enum_route_type {
	ROUTE_STATIC,
	ROUTE_DYNAMIC,
	ROUTE_DISABLED
};

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
static bool is_proc_route_in_config(struct proc_routing *proute)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "route", "target", proute->destination, s) {
		char *mask;

		dmuci_get_value_by_section_string(s, "netmask", &mask);
		if (mask[0] == '\0' || strcmp(proute->mask, mask) == 0)
			return true;
	}

	uci_foreach_option_eq("network", "route_disabled", "target", proute->destination, s) {
		char *mask;

		dmuci_get_value_by_section_string(s, "netmask", &mask);
		if (mask[0] == '\0' || strcmp(proute->mask, mask) == 0)
			return true;
	}

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", s) {
		char *target, *gateway, *device;

		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "gateway", &gateway);
		dmuci_get_value_by_section_string(s, "device", &device);
		if (strcmp(target, proute->destination) == 0 && strcmp(gateway, proute->gateway) == 0 && strcmp(device, proute->iface) == 0)
			return true;
	}

	return false;
}

static bool is_proc_route6_in_config(char *cdev, char *cip, char *cgw)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("network", "route6", s) {
		char *ip_r, *gw_r, *intf_r;
		json_object *jobj = NULL;

		dmuci_get_value_by_section_string(s, "target", &ip_r);
		dmuci_get_value_by_section_string(s, "gateway", &gw_r);
		dmuci_get_value_by_section_string(s, "interface", &intf_r);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", intf_r, String}}, 1, &jobj);
		char *dev_r = (jobj) ? dmjson_get_value(jobj, 1, "device") : "";
		if (strcmp(cdev, dev_r) == 0 && strcmp(cgw, gw_r) == 0 && strcmp(cip, ip_r) == 0)
			return true;
	}

	uci_foreach_sections("network", "route6_disabled", s) {
		char *ip_r6, *gw_r6, *intf_r6;
		json_object *jobj = NULL;

		dmuci_get_value_by_section_string(s, "target", &ip_r6);
		dmuci_get_value_by_section_string(s, "gateway", &gw_r6);
		dmuci_get_value_by_section_string(s, "interface", &intf_r6);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", intf_r6, String}}, 1, &jobj);
		char *dev_r6 = (jobj) ? dmjson_get_value(jobj, 1, "device") : "";
		if (strcmp(cdev, dev_r6) == 0 && strcmp(cgw, gw_r6) == 0 && strcmp(cip, ip_r6) == 0)
			return true;
	}

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", s) {
		char *ip_r6d, *gw_r6d, *dev_r6d;

		dmuci_get_value_by_section_string(s, "target", &ip_r6d);
		dmuci_get_value_by_section_string(s, "gateway", &gw_r6d);
		dmuci_get_value_by_section_string(s, "device", &dev_r6d);
		if (strcmp(cdev, dev_r6d) == 0 && strcmp(cgw, gw_r6d) == 0 && strcmp(cip, ip_r6d) == 0)
			return true;
	}

	return false;
}

static void parse_proc_route_line(char *line, struct proc_routing *proute)
{
	char *pch, *spch;

	proute->iface = strtok_r(line, " \t", &spch);
	pch = strtok_r(NULL, " \t", &spch);
	hex_to_ip(pch, proute->destination);
	pch = strtok_r(NULL, " \t", &spch);
	hex_to_ip(pch, proute->gateway);
	proute->flags = strtok_r(NULL, " \t", &spch);
	proute->refcnt = strtok_r(NULL, " \t", &spch);
	proute->use = strtok_r(NULL, " \t", &spch);
	proute->metric = strtok_r(NULL, " \t", &spch);
	pch = strtok_r(NULL, " \t", &spch);
	hex_to_ip(pch, proute->mask);
	proute->mtu = strtok_r(NULL, " \t", &spch);
	proute->window = strtok_r(NULL, " \t", &spch);
	proute->irtt = strtok_r(NULL, " \t\n\r", &spch);
}

static int parse_proc_route6_line(const char *line, char *ipstr, char *gwstr, char *dev, unsigned int *metric)
{
	unsigned int ip[4], gw[4], flags, refcnt, use, prefix;
	char ipbuf[INET6_ADDRSTRLEN];

	if (*line == '\n' || *line == '\0')
		return -1;

	sscanf(line, "%8x%8x%8x%8x %x %*s %*s %8x%8x%8x%8x %x %x %x %x %31s",
				&ip[0], &ip[1], &ip[2], &ip[3], &prefix,
				&gw[0], &gw[1], &gw[2], &gw[3], metric,
				&refcnt, &use, &flags, dev);

	if (strcmp(dev, "lo") == 0)
		return -1;

	ip[0] = htonl(ip[0]);
	ip[1] = htonl(ip[1]);
	ip[2] = htonl(ip[2]);
	ip[3] = htonl(ip[3]);
	gw[0] = htonl(gw[0]);
	gw[1] = htonl(gw[1]);
	gw[2] = htonl(gw[2]);
	gw[3] = htonl(gw[3]);

	inet_ntop(AF_INET6, ip, ipbuf, INET6_ADDRSTRLEN);
	sprintf(ipstr, "%s/%u", ipbuf, prefix);
	inet_ntop(AF_INET6, gw, gwstr, INET6_ADDRSTRLEN);

	return 0;
}

static int get_forwarding_last_inst(bool ipv6)
{
	char *rinst = NULL, *drinst = NULL, *dsinst = NULL, *tmp = NULL;
	int r = 0, dr = 0, ds = 0;
	struct uci_section *s = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", ipv6 ? "route6" : "route", s) {
		dmuci_get_value_by_section_string(s, ipv6 ? "route6instance" : "routeinstance", &tmp);
		if (tmp && tmp[0] == '\0')
			break;
		rinst = tmp;
	}

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", ipv6 ? "route6_disabled" : "route_disabled", s) {
		dmuci_get_value_by_section_string(s, ipv6 ? "route6instance" : "routeinstance", &tmp);
		if (tmp && tmp[0] == '\0')
			break;
		dsinst = tmp;
	}

	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", ipv6 ? "route6_dynamic" : "route_dynamic", s) {
		dmuci_get_value_by_section_string(s, ipv6 ? "route6instance" : "routeinstance", &tmp);
		if (tmp && tmp[0] == '\0')
			break;
		drinst = tmp;
	}

	if (rinst) r = atoi(rinst);
	if (dsinst) ds = atoi(dsinst);
	if (drinst) dr = atoi(drinst);

	return (r > ds && r > dr ? r : ds > dr ? ds : dr);
}

static char *forwarding_update_instance_alias_bbfdm(int action, char **last_inst, char **max_inst, void *argv[])
{
	char *instance, *alias;
	char buf[64] = {0};

	struct uci_section *s = (struct uci_section *) argv[0];
	char *inst_opt = (char *) argv[1];
	char *alias_opt = (char *) argv[2];
	bool *ipv4_forwarding = (bool *) argv[3];
	bool *find_max = (bool *) argv[4];

	dmuci_get_value_by_section_string(s, inst_opt, &instance);
	if (instance[0] == '\0') {
		if (*find_max) {
			int m = get_forwarding_last_inst((*ipv4_forwarding) ? false : true);
			snprintf(buf, sizeof(buf), "%d", m+1);
			*find_max = false;
		} else if (max_inst == NULL) {
			snprintf(buf, sizeof(buf), "%d", 1);
		} else {
			snprintf(buf, sizeof(buf), "%d", atoi(*max_inst)+1);
		}
		instance = dmuci_set_value_by_section_bbfdm(s, inst_opt, buf);
	}
	*max_inst = instance;
	*last_inst = instance;
	if (action == INSTANCE_MODE_ALIAS) {
		dmuci_get_value_by_section_string(s, alias_opt, &alias);
		if (alias[0] == '\0') {
			snprintf(buf, sizeof(buf), "cpe-%s", instance);
			alias = dmuci_set_value_by_section_bbfdm(s, alias_opt, buf);
		}
		snprintf(buf, sizeof(buf), "[%s]", alias);
		instance = dmstrdup(buf);
	}
	return instance;
}

static int dmmap_synchronizeRoutingRouterIPv4Forwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp;
	struct proc_routing proute = {0};
	json_object *jobj;
	FILE* fp = NULL;
	char *target, *iface, *str, line[MAX_PROC_ROUTING];
	int found, lines;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_route_forwarding", "route_dynamic", stmp, s) {
		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "device", &iface);
		found = 0;
		fp = fopen(PROC_ROUTE, "r");
		if ( fp != NULL) {
			lines = 0;
			while (fgets(line, MAX_PROC_ROUTING, fp) != NULL) {
				if (line[0] == '\n' || lines == 0) { /* skip the first line or skip the line if it's empty */
					lines++;
					continue;
				}
				parse_proc_route_line(line, &proute);
				if ((strcmp(iface, proute.iface) == 0) && strcmp(target, proute.destination) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				dmuci_delete_by_section(s, NULL, NULL);
			fclose(fp);
		}
	}

	fp = fopen(PROC_ROUTE, "r");
	if ( fp != NULL) {
		lines = 0;
		while (fgets(line, MAX_PROC_ROUTING, fp) != NULL) {
			if (line[0] == '\n' || lines == 0) { /* skip the first line or skip the line if it's empty */
				lines++;
				continue;
			}
			parse_proc_route_line(line, &proute);
			if (is_proc_route_in_config(&proute))
				continue;
			iface = "";
			uci_foreach_sections("network", "interface", s) {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &jobj);
				if (!jobj) {
					fclose(fp);
					return 0;
				}
				str = dmjson_get_value(jobj, 1, "device");
				if (strcmp(str, proute.iface) == 0) {
					iface = section_name(s);
					break;
				}
			}
			char instance[16];

			snprintf(instance, sizeof(instance), "%d", get_forwarding_last_inst(false) + 1);
			dmuci_add_section_bbfdm("dmmap_route_forwarding", "route_dynamic", &s);
			dmuci_set_value_by_section_bbfdm(s, "target", proute.destination);
			dmuci_set_value_by_section_bbfdm(s, "netmask", proute.mask);
			dmuci_set_value_by_section_bbfdm(s, "metric", proute.metric);
			dmuci_set_value_by_section_bbfdm(s, "gateway", proute.gateway);
			dmuci_set_value_by_section_bbfdm(s, "device", proute.iface);
			dmuci_set_value_by_section_bbfdm(s, "interface", iface);
			dmuci_set_value_by_section_bbfdm(s, "routeinstance", instance);
		}
		fclose(fp);
	}
	return 0;
}

static int dmmap_synchronizeRoutingRouterIPv6Forwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char buf[512] = {0}, dev[32] = {0}, ipstr[INET6_ADDRSTRLEN + 8] = {0}, gwstr[INET6_ADDRSTRLEN + 8] = {0};
	char *iface, *target;
	unsigned int metric;
	FILE *fp = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_route_forwarding", "route6_dynamic", stmp, s) {
		dmuci_get_value_by_section_string(s, "target", &target);
		dmuci_get_value_by_section_string(s, "device", &iface);

		fp = fopen(PROC_ROUTE6, "r");
		if (fp == NULL)
			return 0;

		int found = 0;
		while (fgets(buf, 512, fp) != NULL) {

			if (parse_proc_route6_line(buf, ipstr, gwstr, dev, &metric))
				continue;

			if (strcmp(iface, dev) == 0 && strcmp(ipstr, target) == 0) {
				found = 1;
				break;
			}
		}
		fclose(fp);

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	fp = fopen(PROC_ROUTE6, "r");
	if (fp == NULL)
		return 0;

	while (fgets(buf , 512 , fp) != NULL) {

		if (parse_proc_route6_line(buf, ipstr, gwstr, dev, &metric))
			continue;

		if (is_proc_route6_in_config(dev, ipstr, gwstr))
			continue;

		iface = "";
		uci_foreach_sections("network", "interface", s) {
			json_object *jobj = NULL;

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &jobj);
			if (!jobj) {
				fclose(fp);
				return 0;
			}
			char *str = dmjson_get_value(jobj, 1, "device");
			if (strcmp(str, dev) == 0) {
				iface = section_name(s);
				break;
			}
		}
		char instance[16];

		snprintf(instance, sizeof(instance), "%d", get_forwarding_last_inst(true) + 1);
		dmuci_add_section_bbfdm("dmmap_route_forwarding", "route6_dynamic", &s);
		dmuci_set_value_by_section_bbfdm(s, "target", ipstr);
		dmuci_set_value_by_section_bbfdm(s, "gateway", gwstr);
		dmuci_set_value_by_section_bbfdm(s, "interface", iface);
		dmuci_set_value_by_section_bbfdm(s, "device", dev);
		snprintf(buf, sizeof(buf), "%u", metric);
		dmuci_set_value_by_section_bbfdm(s, "metric", buf);
		dmuci_set_value_by_section_bbfdm(s, "route6instance", instance);
	}
	fclose(fp);
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
	struct uci_section *s;
	int cnt = 0;

	uci_foreach_sections("network", "route", s) {
		cnt++;
	}
	uci_foreach_sections("network", "route_disabled", s) {
		cnt++;
	}
	dmmap_synchronizeRoutingRouterIPv4Forwarding(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6ForwardingNumberOfEntries!UCI:network/route6/*/
static int get_RoutingRouter_IPv6ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int cnt = 0;

	uci_foreach_sections("network", "route6", s) {
		cnt++;
	}
	uci_foreach_sections("network", "route6_disabled", s) {
		cnt++;
	}
	dmmap_synchronizeRoutingRouterIPv6Forwarding(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int get_router_ipv4forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (((struct routingfwdargs *)data)->type == ROUTE_DISABLED) ? "0" : "1";
	return 0;
}

static int set_router_ipv4forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int route_type = ((struct routingfwdargs *)data)->type;
	struct uci_section *dmmap_section = NULL;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);

			if ((b && route_type == ROUTE_STATIC) || (!b && route_type == ROUTE_DISABLED))
				return 0;

			// Update config section
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, b ? "route" : "route_disabled");

			// Update dmmap section
			get_dmmap_section_of_config_section("dmmap_route_forwarding", b ? "route_disabled" : "route", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, NULL, b ? "route" : "route_disabled");

			return 0;
	}
	return 0;
}

static int get_router_ipv4forwarding_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (((struct routingfwdargs *)data)->type == ROUTE_DISABLED) ? "Disabled" : "Enabled";
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
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
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
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
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
	*value = "-1";
	return 0;
}

static int set_router_ipv4forwarding_forwarding_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
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
		*value = (proto && strncmp(proto, "ppp", 3) == 0) ? "IPCP" : "DHCPv4";
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
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
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
	if (linker && linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_RoutingRouterForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.ForwardingMetric!UCI:network/route,@i-1/metric*/
static int get_router_ipv4forwarding_metric(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "metric", "-1");
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
	*value = (((struct routingfwdargs *)data)->type == ROUTE_DISABLED) ? "0" : "1";
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int route6_type = ((struct routingfwdargs *)data)->type;
	struct uci_section *dmmap_section = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			if ((b && route6_type == ROUTE_STATIC) || (!b && route6_type == ROUTE_DISABLED))
				break;

			// Update config section
			dmuci_set_value_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, b ? "route6" : "route6_disabled");

			// Update dmmap section
			get_dmmap_section_of_config_section("dmmap_route_forwarding", b ? "route6_disabled" : "route6", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, NULL, b ? "route6" : "route6_disabled");

			break;
	}
	return 0;
}

static int get_RoutingRouterIPv6Forwarding_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (((struct routingfwdargs *)data)->type == ROUTE_DISABLED) ? "Disabled" : "Enabled";
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
			if (dm_validate_string(value, -1, 49, NULL, 0, IPv6Prefix, 2))
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
	*value = "-1";
	return 0;
}

static int set_RoutingRouterIPv6Forwarding_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
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
			if (dm_validate_string(value, -1, 45, NULL, 0, IPv6Address, 2))
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
	*value = dmuci_get_value_by_section_fallback_def(((struct routingfwdargs *)data)->routefwdsection, "metric", "-1");
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
		if ((proto && strcmp(proto, "dhcpv6") == 0) || (ip6addr && ip6addr[0] != '\0')) {
			json_object *res = NULL, *routes = NULL;

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
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
		if(strcmp(ip_target, buf) == 0 && strcmp(nexthop, gateway) == 0) {
			*value = "ForwardingEntryCreated";
			return 0;
		}
	}
	return 0;
}

static int get_RoutingRouteInformationInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char buf[512] = {0}, dev[32] = {0}, ipstr[INET6_ADDRSTRLEN + 8] = {0}, gwstr[INET6_ADDRSTRLEN + 8] = {0};
	unsigned int metric;
	char *iface = "";

	char *source = dmjson_get_value((struct json_object *)data, 1, "source");
	char *nexthop = dmjson_get_value((struct json_object *)data, 1, "nexthop");

	FILE *fp = fopen(PROC_ROUTE6, "r");
	if (fp == NULL)
		return 0;

	while (fgets(buf , 512 , fp) != NULL) {

		if (parse_proc_route6_line(buf, ipstr, gwstr, dev, &metric))
			continue;

		if((strcmp(source, ipstr) == 0) && (strcmp(nexthop, gwstr) == 0))
			break;
	}
	fclose(fp);

	uci_foreach_sections("network", "interface", s) {
		json_object *jobj = NULL;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &jobj);
		if (!jobj) return 0;
		char *str = dmjson_get_value(jobj, 1, "device");
		if (strcmp(str, dev) == 0) {
			iface = section_name(s);
			break;
		}
	}

	if (iface[0] != '\0') {
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", iface, value);
		if (*value == NULL)
			*value = "";
	}
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
	if (valid && *valid != '\0' && atoi(valid) > 0) {
		char local_time[32] = {0};

		if (get_shift_time_time(atoi(valid), local_time, sizeof(local_time)) == -1)
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
		get_dmmap_section_of_config_section("dmmap_route_forwarding", (route_type == ROUTE_STATIC) ? "route" : "route_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

	dmuci_get_value_by_section_string(dmmap_section, "routealias", value);
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (route_type == ROUTE_DYNAMIC)
				dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
			else
				get_dmmap_section_of_config_section("dmmap_route_forwarding", (route_type == ROUTE_STATIC) ? "route" : "route_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

			dmuci_set_value_by_section(dmmap_section, "routealias", value);
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
		get_dmmap_section_of_config_section("dmmap_route_forwarding", (route6_type == ROUTE_STATIC) ? "route6" : "route6_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

	dmuci_get_value_by_section_string(dmmap_section, "route6alias", value);
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (route6_type == ROUTE_DYNAMIC)
				dmmap_section = ((struct routingfwdargs *)data)->routefwdsection;
			else
				get_dmmap_section_of_config_section("dmmap_route_forwarding", (route6_type == ROUTE_STATIC) ? "route6" : "route6_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);

			dmuci_set_value_by_section(dmmap_section, "route6alias", value);
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
static int add_ipv4forwarding(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *s = NULL, *dmmap_route = NULL;
	char instance[16], route_name[32];

	int last_inst = get_forwarding_last_inst(false);
	snprintf(instance, sizeof(instance), "%d", last_inst);
	snprintf(route_name, sizeof(route_name), "route_%d", (last_inst == 0) ? 1 : last_inst + 1);

	dmuci_add_section("network", "route_disabled", &s);
	dmuci_rename_section_by_section(s, route_name);

	dmuci_add_section_bbfdm("dmmap_route_forwarding", "route_disabled", &dmmap_route);
	dmuci_set_value_by_section(dmmap_route, "section_name", route_name);
	*instancepara = update_instance(instance, 2, dmmap_route, "routeinstance");
	return 0;
}

static int delete_ipv4forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *route_s = NULL, *stmp = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			// Return 9008 error if the removed route is dynamic
			if (((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
				return FAULT_9008;

			// Remove dmmap section
			get_dmmap_section_of_config_section("dmmap_route_forwarding", (((struct routingfwdargs *)data)->type == ROUTE_STATIC) ? "route" : "route_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove config section
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);
			break;
		case DEL_ALL:
			// Remove all static enable routes
			uci_foreach_sections_safe("network", "route", stmp, route_s) {

				// Remove dmmap section
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route", section_name(route_s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove config section
				dmuci_delete_by_section(route_s, NULL, NULL);
			}

			// Remove all static disable routes
			uci_foreach_sections_safe("network", "route_disabled", stmp, route_s) {

				// Remove dmmap section
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route_disabled", section_name(route_s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove config section
				dmuci_delete_by_section(route_s, NULL, NULL);
			}

			break;
		}
	return 0;
}

static int add_ipv6Forwarding(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *s = NULL, *dmmap_route6 = NULL;
	char instance[16], route6_name[32];

	int last_inst = get_forwarding_last_inst(true);
	snprintf(instance, sizeof(instance), "%d", last_inst);
	snprintf(route6_name, sizeof(route6_name), "route6_%d", (last_inst == 0) ? 1 : last_inst + 1);

	dmuci_add_section("network", "route6_disabled", &s);
	dmuci_rename_section_by_section(s, route6_name);

	dmuci_add_section_bbfdm("dmmap_route_forwarding", "route6_disabled", &dmmap_route6);
	dmuci_set_value_by_section(dmmap_route6, "section_name", route6_name);
	*instancepara = update_instance(instance, 2, dmmap_route6, "route6instance");
	return 0;
}

static int delete_ipv6Forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *route6_s = NULL, *stmp = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			// Return 9008 error if the removed route6 is dynamic
			if (((struct routingfwdargs *)data)->type == ROUTE_DYNAMIC)
				return FAULT_9008;

			// Remove dmmap section
			get_dmmap_section_of_config_section("dmmap_route_forwarding", (((struct routingfwdargs *)data)->type == ROUTE_STATIC) ? "route6" : "route6_disabled", section_name(((struct routingfwdargs *)data)->routefwdsection), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove config section
			dmuci_delete_by_section(((struct routingfwdargs *)data)->routefwdsection, NULL, NULL);
			break;
		case DEL_ALL:
			// Remove all static enable routes
			uci_foreach_sections_safe("network", "route6", stmp, route6_s) {

				// Remove dmmap section
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route6", section_name(route6_s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove config section
				dmuci_delete_by_section(route6_s, NULL, NULL);
			}

			// Remove all static disable routes
			uci_foreach_sections_safe("network", "route6_disabled", stmp, route6_s) {

				// Remove dmmap section
				get_dmmap_section_of_config_section("dmmap_route_forwarding", "route6_disabled", section_name(route6_s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove config section
				dmuci_delete_by_section(route6_s, NULL, NULL);
			}

			break;
	}
	return 0;
}

/*************************************************************
* SUB ENTRIES
**************************************************************/
static int browseRouterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL, *max_inst = NULL;

	update_section_list(DMMAP,"router", NULL, 1, NULL, NULL, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap", "router", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   s, "router_instance", "router_alias");

		DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst);
		break;
	}
	return 0;
}

/*#Device.Routing.Router.{i}.IPv4Forwarding.{i}.!UCI:network/route/dmmap_route_forwarding*/
static int browseIPv4ForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct uci_section *ss = NULL;
	bool find_max = true, ipv4_forwarding = true;
	struct routingfwdargs curr_routefwdargs = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	// Enable Routes
	synchronize_specific_config_sections_with_dmmap("network", "route", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		init_args_ipv4forward(&curr_routefwdargs, p->config_section, "1", ROUTE_STATIC);

		inst = handle_update_instance(2, dmctx, &max_inst, forwarding_update_instance_alias_bbfdm, 5,
			   p->dmmap_section, "routeinstance", "routealias", &ipv4_forwarding, &find_max);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Disable Routes
	synchronize_specific_config_sections_with_dmmap("network", "route_disabled", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		init_args_ipv4forward(&curr_routefwdargs, p->config_section, "1", ROUTE_DISABLED);

		inst = handle_update_instance(2, dmctx, &max_inst, forwarding_update_instance_alias_bbfdm, 5,
			   p->dmmap_section, "routeinstance", "routealias", &ipv4_forwarding, &find_max);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Dynamic Routes
	dmmap_synchronizeRoutingRouterIPv4Forwarding(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route_dynamic", ss) {

		init_args_ipv4forward(&curr_routefwdargs, ss, "0", ROUTE_DYNAMIC);

		inst = handle_update_instance(2, dmctx, &max_inst, forwarding_update_instance_alias_bbfdm, 5,
			   ss, "routeinstance", "routealias", &ipv4_forwarding, &find_max);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_routefwdargs, inst) == DM_STOP)
			goto end;
	}

end:
	return 0;
}

/*#Device.Routing.Router.{i}.IPv6Forwarding.{i}.!UCI:network/route6/dmmap_route_forwarding*/
static int browseIPv6ForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct uci_section *ss = NULL;
	bool find_max = true, ipv4_forwarding = false;
	struct routingfwdargs curr_route6fwdargs = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	// Enable Routes
	synchronize_specific_config_sections_with_dmmap("network", "route6", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		init_args_ipv6forward(&curr_route6fwdargs, p->config_section, "1", ROUTE_STATIC);

		inst = handle_update_instance(2, dmctx, &max_inst, forwarding_update_instance_alias_bbfdm, 5,
			   p->dmmap_section, "route6instance", "route6alias", &ipv4_forwarding, &find_max);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Disable Routes
	synchronize_specific_config_sections_with_dmmap("network", "route6_disabled", "dmmap_route_forwarding", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		init_args_ipv6forward(&curr_route6fwdargs, p->config_section, "1", ROUTE_DISABLED);

		inst = handle_update_instance(2, dmctx, &max_inst, forwarding_update_instance_alias_bbfdm, 5,
			   p->dmmap_section, "route6instance", "route6alias", &ipv4_forwarding, &find_max);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Dynamic Routes
	dmmap_synchronizeRoutingRouterIPv6Forwarding(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_route_forwarding", "route6_dynamic", ss) {

		init_args_ipv6forward(&curr_route6fwdargs, ss, "0", ROUTE_DYNAMIC);

		inst = handle_update_instance(2, dmctx, &max_inst, forwarding_update_instance_alias_bbfdm, 5,
			   ss, "route6instance", "route6alias", &ipv4_forwarding, &find_max);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_route6fwdargs, inst) == DM_STOP)
			goto end;
	}

end:
	return 0;
}

static int browseRoutingRouteInformationInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst, *max_inst = NULL;
	int id = 0, i = 0;

	uci_foreach_sections("network", "interface", s) {
		char *proto = NULL, *ip6addr = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ip6addr", &ip6addr);
		if ((proto && strcmp(proto, "dhcpv6") == 0) || (ip6addr && ip6addr[0] != '\0')) {
			json_object *res = NULL, *route_obj = NULL, *arrobj = NULL;

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			dmjson_foreach_obj_in_array(res, arrobj, route_obj, i, 1, "route") {
				inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)route_obj, inst) == DM_STOP)
					break;
			}
		}
	}
	return 0;
}

/* *** Device.Routing. *** */
DMOBJ tRoutingObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Router", &DMREAD, NULL, NULL, NULL, browseRouterInst, NULL, tRoutingRouterObj, tRoutingRouterParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"RouteInformation", &DMREAD, NULL, NULL, NULL, NULL, NULL, tRoutingRouteInformationObj, tRoutingRouteInformationParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tRoutingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"RouterNumberOfEntries", &DMREAD, DMT_UNINT, get_router_nbr_entry, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.Router.{i}. *** */
DMOBJ tRoutingRouterObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPv4Forwarding", &DMWRITE, add_ipv4forwarding, delete_ipv4forwarding, NULL, browseIPv4ForwardingInst, NULL, NULL, tRoutingRouterIPv4ForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"DestIPAddress", "DestSubnetMask", "ForwardingPolicy", "GatewayIPAddress", "Interface", "ForwardingMetric", "Alias", NULL}},
{"IPv6Forwarding", &DMWRITE, add_ipv6Forwarding, delete_ipv6Forwarding, NULL, browseIPv6ForwardingInst, NULL, NULL, tRoutingRouterIPv6ForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"DestIPPrefix", "ForwardingPolicy", "NextHop", "Interface", "ForwardingMetric", "Alias", NULL}},
{0}
};

DMLEAF tRoutingRouterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_RoutingRouter_Enable, set_RoutingRouter_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_RoutingRouter_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RoutingRouter_Alias, set_RoutingRouter_Alias, BBFDM_BOTH},
{"IPv4ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouter_IPv4ForwardingNumberOfEntries, NULL, BBFDM_BOTH},
{"IPv6ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouter_IPv6ForwardingNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.Router.{i}.IPv4Forwarding.{i}. *** */
DMLEAF tRoutingRouterIPv4ForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMRouting, DMT_BOOL, get_router_ipv4forwarding_enable, set_router_ipv4forwarding_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_router_ipv4forwarding_status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_router_ipv4forwarding_alias, set_router_ipv4forwarding_alias, BBFDM_BOTH},
{"StaticRoute", &DMREAD, DMT_BOOL, get_router_ipv4forwarding_static_route, NULL, BBFDM_BOTH},
{"DestIPAddress", &DMRouting, DMT_STRING, get_router_ipv4forwarding_destip, set_router_ipv4forwarding_destip, BBFDM_BOTH},
{"DestSubnetMask", &DMRouting, DMT_STRING, get_router_ipv4forwarding_destmask, set_router_ipv4forwarding_destmask, BBFDM_BOTH},
{"ForwardingPolicy", &DMRouting, DMT_INT, get_router_ipv4forwarding_forwarding_policy, set_router_ipv4forwarding_forwarding_policy, BBFDM_BOTH},
{"GatewayIPAddress", &DMRouting, DMT_STRING, get_router_ipv4forwarding_gatewayip, set_router_ipv4forwarding_gatewayip, BBFDM_BOTH},
{"Interface", &DMRouting, DMT_STRING, get_RoutingRouterForwarding_Interface, set_RoutingRouterForwarding_Interface, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_router_ipv4forwarding_origin, NULL, BBFDM_BOTH},
{"ForwardingMetric", &DMRouting, DMT_INT, get_router_ipv4forwarding_metric, set_router_ipv4forwarding_metric, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.Router.{i}.IPv6Forwarding.{i}. *** */
DMLEAF tRoutingRouterIPv6ForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMRouting, DMT_BOOL, get_RoutingRouterIPv6Forwarding_Enable, set_RoutingRouterIPv6Forwarding_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_RoutingRouterIPv6Forwarding_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RoutingRouterIPv6Forwarding_Alias, set_RoutingRouterIPv6Forwarding_Alias, BBFDM_BOTH},
{"DestIPPrefix", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_DestIPPrefix, set_RoutingRouterIPv6Forwarding_DestIPPrefix, BBFDM_BOTH},
{"ForwardingPolicy", &DMRouting, DMT_INT, get_RoutingRouterIPv6Forwarding_ForwardingPolicy, set_RoutingRouterIPv6Forwarding_ForwardingPolicy, BBFDM_BOTH},
{"NextHop", &DMRouting, DMT_STRING, get_RoutingRouterIPv6Forwarding_NextHop, set_RoutingRouterIPv6Forwarding_NextHop, BBFDM_BOTH},
{"Interface", &DMRouting, DMT_STRING, get_RoutingRouterForwarding_Interface, set_RoutingRouterForwarding_Interface, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_RoutingRouterIPv6Forwarding_Origin, NULL, BBFDM_BOTH},
{"ForwardingMetric", &DMRouting, DMT_INT, get_RoutingRouterIPv6Forwarding_ForwardingMetric, set_RoutingRouterIPv6Forwarding_ForwardingMetric, BBFDM_BOTH},
{"ExpirationTime", &DMREAD, DMT_TIME, get_RoutingRouterIPv6Forwarding_ExpirationTime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.RouteInformation. *** */
DMOBJ tRoutingRouteInformationObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"InterfaceSetting", &DMREAD, NULL, NULL, NULL, browseRoutingRouteInformationInterfaceSettingInst, NULL, NULL, tRoutingRouteInformationInterfaceSettingParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", NULL}},
{0}
};

DMLEAF tRoutingRouteInformationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_RoutingRouteInformation_Enable, set_RoutingRouteInformation_Enable, BBFDM_BOTH},
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_RoutingRouteInformation_InterfaceSettingNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Routing.RouteInformation.InterfaceSetting.{i}. *** */
DMLEAF tRoutingRouteInformationInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Status", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_Status, NULL, BBFDM_BOTH},
{"Interface", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_Interface, NULL, BBFDM_BOTH},
{"SourceRouter", &DMREAD, DMT_STRING, get_RoutingRouteInformationInterfaceSetting_SourceRouter, NULL, BBFDM_BOTH},
{"RouteLifetime", &DMREAD, DMT_TIME, get_RoutingRouteInformationInterfaceSetting_RouteLifetime, NULL, BBFDM_BOTH},
{0}
};
