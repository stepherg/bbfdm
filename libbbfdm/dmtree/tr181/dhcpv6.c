/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dhcpv4.h"
#include "dhcpv6.h"


struct dhcpv6_client_args
{
	struct uci_section *iface_s;
	struct uci_section *dmmap_s;
};

struct dhcpv6_args
{
	struct dmmap_dup *dhcp_sections;
	char *interface;
};

struct clientv6_args
{
	json_object *client;
	json_object *clientparam;
	int idx;
};

struct dhcpv6_client_option_args {
	struct uci_section *client_sect;
	struct uci_section *dmmap_sect;
	char *option_tag;
	char *value;
};

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static bool is_dhcpv6_client_section_exist(char *sec_name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcpv6", "interface", "iface_name", sec_name, s) {
		return true;
	}

	return false;
}

static void dmmap_synchronizeDHCPv6Client(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcpv6", "interface", stmp, s) {
		char *added_by_controller = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(s, "added_by_controller", &added_by_controller);
		if (DM_LSTRCMP(added_by_controller, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name)) {
			struct uci_section *iface_s = NULL;

			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

			if (!iface_s)
				dmuci_delete_by_section(s, NULL, NULL);
		}
	}

	uci_foreach_sections("network", "interface", s) {
		struct uci_section *ppp_s = NULL;
		char *proto = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (DM_LSTRCMP(proto, "dhcpv6") != 0)
			continue;

		if (is_dhcpv6_client_section_exist(section_name(s)))
			continue;

		dmuci_add_section_bbfdm("dmmap_dhcpv6", "interface", &ppp_s);
		dmuci_set_value_by_section(ppp_s, "iface_name", section_name(s));
	}
}

static struct uci_section *get_dhcpv6_classifier(char *classifier_name, const char *network)
{
	struct uci_section *s = NULL;
	char *v;

	uci_foreach_sections("dhcp", classifier_name, s) {
		dmuci_get_value_by_section_string(s, "networkid", &v);
		if (DM_STRCMP(v, network) == 0)
			return s;
	}
	return NULL;
}

static int get_value_in_date_time_format(json_object *json_obj, char *option_name, char **value)
{
	const char *option_value = dmjson_get_value(json_obj, 1, option_name);
	if (option_value && *option_value != '\0' && DM_STRTOL(option_value) > 0) {
		time_t time_value = DM_STRTOL(option_value);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		if (strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", gmtime(&time_value)) == 0)
			return -1;
		*value = dmstrdup(s_now); // MEM WILL BE FREED IN DMMEMCLEAN
	}
	return 0;	
}

/*************************************************************
* INIT
**************************************************************/
static inline int init_dhcpv6_client_args(struct clientv6_args *args, json_object *client, json_object *client_param, int i)
{
	args->client = client;
	args->clientparam = client_param;
	args->idx = i;
	return 0;
}

static inline int init_dhcpv6_args(struct dhcpv6_args *args, struct dmmap_dup *s, char *interface)
{
	args->dhcp_sections = s;
	args->interface = interface;
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.DHCPv6.Client.{i}.!UCI:network/interface/dmmap_dhcpv6*/
static int browseDHCPv6ClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcpv6_client_args curr_dhcpv6_client_args = {0};
	struct uci_section *dmmap_s = NULL;
	char *inst = NULL;

	dmmap_synchronizeDHCPv6Client(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap_dhcpv6", "interface", dmmap_s) {
		struct uci_section *iface_s = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name))
			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

		curr_dhcpv6_client_args.iface_s = iface_s;
		curr_dhcpv6_client_args.dmmap_s = dmmap_s;

		inst = handle_instance(dmctx, parent_node, dmmap_s, "bbf_dhcpv6client_instance", "bbf_dhcpv6client_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcpv6_client_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.!UCI:dhcp/dhcp/dmmap_dhcpv6*/
static int browseDHCPv6ServerPoolInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ignore = NULL, *interface, *inst = NULL, *v;
	struct dhcpv6_args curr_dhcp6_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_dhcpv6", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(p->config_section, "ignore", &ignore);
		if (ignore && DM_LSTRCMP(ignore, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "interface", &interface);
		init_dhcpv6_args(&curr_dhcp6_args, p, interface);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "dhcpv6_serv_pool_instance", "dhcpv6_serv_pool_alias");

		dmuci_get_value_by_section_string(p->dmmap_section, "order", &v);
		if (v == NULL || DM_STRLEN(v) == 0)
			set_section_order("dhcp", "dmmap_dhcpv6", "dhcp", p->dmmap_section, p->config_section, 0, inst);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp6_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);

	return 0;
}

static int browseDHCPv6ServerPoolClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcpv6_args *dhcp_arg= (struct dhcpv6_args *)prev_data;
	json_object *res = NULL, *res1 = NULL, *jobj = NULL, *dev_obj = NULL, *net_obj = NULL;
	struct clientv6_args curr_dhcp_client_args = {0};
	int i = 0;
	char *inst = NULL, *device;

	char *if_name = section_name(dhcp_arg->dhcp_sections->config_section);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res1);
	if (!res1) return 0;
	device = dmjson_get_value(res1, 1, "device");
	dmubus_call("dhcp", "ipv6leases", UBUS_ARGS{0}, 0, &res);
	if (!res) return 0;
	dev_obj = dmjson_get_obj(res, 1, "device");
	if (!dev_obj) return 0;
	net_obj = dmjson_get_obj(dev_obj, 1, device);
	if (!net_obj) return 0;

	while (1) {
		jobj = dmjson_select_obj_in_array_idx(net_obj, i, 1, "leases");
		if (!jobj) break;
		init_dhcpv6_client_args(&curr_dhcp_client_args, jobj, NULL, i);
		i++;
		inst = handle_instance_without_section(dmctx, parent_node, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_client_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv6ServerPoolOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcpv6_args *curr_dhcp_args = (struct dhcpv6_args *)prev_data;
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e = NULL;
	struct uci_section *dmmap_sect = NULL;
	char **dhcpv6_option = NULL, *inst = NULL, *dhcpv6_tag, *dhcpv6_value;
	size_t length = 0;
	struct dhcpv6_client_option_args dhcpv6_client_opt_args = {0};

	dmuci_get_value_by_section_list(curr_dhcp_args->dhcp_sections->config_section, "dhcp_option", &dhcp_options_list);

	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {

			dhcpv6_option = strsplit(e->name, ",", &length);
			if (!dhcpv6_option)
				continue;

			if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcpv6", "servpool_option", section_name(curr_dhcp_args->dhcp_sections->config_section), "option_tag", dhcpv6_option[0])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcpv6", "servpool_option", &dmmap_sect);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", dhcpv6_option[0]);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(curr_dhcp_args->dhcp_sections->config_section));
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_value", length > 1 ? dhcpv6_option[1] : "");
			}
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcpv6", "servpool_option", "section_name", section_name(curr_dhcp_args->dhcp_sections->config_section), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &dhcpv6_tag);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &dhcpv6_value);

		dhcpv6_client_opt_args.client_sect = curr_dhcp_args->dhcp_sections->config_section;
		dhcpv6_client_opt_args.dmmap_sect = dmmap_sect;
		dhcpv6_client_opt_args.option_tag = dhcpv6_tag;
		dhcpv6_client_opt_args.value = dhcpv6_value;

		inst = handle_instance(dmctx, parent_node, dmmap_sect, "bbf_dhcpv6_servpool_option_instance", "bbf_dhcpv6_servpool_option_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcpv6_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv6ServerPoolClientIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct clientv6_args *dhcpv6_serv_pool_client = (struct clientv6_args *)prev_data;
	json_object *address_obj= NULL;
	struct clientv6_args curr_dhcv6_address_args = {0};
	char *inst = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(dhcpv6_serv_pool_client->client, i, 1, "ipv6-addr");
		if (address_obj == NULL)
			break;
		init_dhcpv6_client_args(&curr_dhcv6_address_args, dhcpv6_serv_pool_client->client, address_obj, i);
		i++;
		inst = handle_instance_without_section(dmctx, parent_node, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcv6_address_args, inst) == DM_STOP)
			break;
	}

	return 0;
}

static int browseDHCPv6ServerPoolClientIPv6PrefixInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct clientv6_args *dhcpv6_serv_pool_client = (struct clientv6_args *)prev_data;
	json_object *address_obj = NULL;
	struct clientv6_args curr_dhcv6_address_args = {0};
	char *inst = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(dhcpv6_serv_pool_client->client, i, 1, "ipv6-prefix");
		if (address_obj == NULL)
			break;
		init_dhcpv6_client_args(&curr_dhcv6_address_args, dhcpv6_serv_pool_client->client, address_obj, i);
		i++;
		inst = handle_instance_without_section(dmctx, parent_node, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcv6_address_args, inst) == DM_STOP)
			break;
	}

	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjDHCPv6Client(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_sect = NULL;

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "interface", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "proto", "dhcpv6");
	dmuci_set_value_by_section(dmmap_sect, "disabled", "1");
	dmuci_set_value_by_section(dmmap_sect, "reqaddress", "force");
	dmuci_set_value_by_section(dmmap_sect, "reqprefix", "no");
	dmuci_set_value_by_section(dmmap_sect, "added_by_controller", "1");
	dmuci_set_value_by_section(dmmap_sect, "bbf_dhcpv6client_instance", *instance);
	return 0;
}

static int delObjDHCPv6Client(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dhcpv6_client_args *)data)->dmmap_s, NULL, NULL);

			if (((struct dhcpv6_client_args *)data)->iface_s) {
				dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->iface_s, "proto", "none");
				dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->iface_s, "reqaddress", "");
				dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->iface_s, "reqprefix", "");
				dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->iface_s, "reqopts", "");
			}
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcpv6", "interface", stmp, s) {
				struct uci_section *iface_s = NULL;
				char *iface_name = NULL;

				dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
				if (DM_STRLEN(iface_name))
					get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

				if (iface_s) {
					dmuci_set_value_by_section(iface_s, "proto", "none");
					dmuci_set_value_by_section(iface_s, "reqaddress", "");
					dmuci_set_value_by_section(iface_s, "reqprefix", "");
					dmuci_set_value_by_section(iface_s, "reqopts", "");
				}

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv6ServerPool(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_dhcp = NULL;
	char dhcpv6_sname[32] = {0};

	snprintf(dhcpv6_sname, sizeof(dhcpv6_sname), "dhcpv6_%s", *instance);

	dmuci_add_section("dhcp", "dhcp", &s);
	dmuci_rename_section_by_section(s, dhcpv6_sname);
	dmuci_set_value_by_section(s, "ignore", "0");
	dmuci_set_value_by_section(s, "dhcpv6", "disabled");

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "dhcp", &dmmap_dhcp);
	dmuci_set_value_by_section(dmmap_dhcp, "section_name", dhcpv6_sname);
	dmuci_set_value_by_section(dmmap_dhcp, "dhcpv6_serv_pool_instance", *instance);
	return 0;
}

static int delObjDHCPv6ServerPool(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((((struct dhcpv6_args *)data)->dhcp_sections)->config_section, NULL, NULL);
			dmuci_delete_by_section((((struct dhcpv6_args *)data)->dhcp_sections)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("dhcp", "dhcp", stmp, s) {
				char *dhcpv6 = NULL;

				dmuci_get_value_by_section_string(s, "dhcpv6", &dhcpv6);
				if (DM_LSTRCMP(dhcpv6, "server") == 0) {
					struct uci_section *dmmap_section = NULL;

					get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(s), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);

					dmuci_delete_by_section(s, NULL, NULL);
				}
			}
			break;
	}
	return 0;
}

static int addObjDHCPv6ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcpv6_args *dhcpv6_arg = (struct dhcpv6_args *)data;
	struct uci_section *dmmap_sect;

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "servpool_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcpv6_arg->dhcp_sections->config_section));
	char *option_tag = generate_tag_option("dmmap_dhcpv6", "servpool_option", "section_name", section_name(dhcpv6_arg->dhcp_sections->config_section), "option_tag");
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", option_tag);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "bbf_dhcpv6_servpool_option_instance", *instance);
	return 0;
}

static int delObjDHCPv6ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_list *dhcp_options_list = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_options_list);
			if (dhcp_options_list != NULL) {
				char tag_value[128] = {0};

				snprintf(tag_value, sizeof(tag_value), "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);
				dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", tag_value);
			}

			dmuci_delete_by_section(((struct dhcpv6_client_option_args *)data)->dmmap_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section((((struct dhcpv6_args *)data)->dhcp_sections)->config_section, "dhcp_option", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcpv6", "servpool_option", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_DHCPv6_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv6ClientInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv6.Client.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv6Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	char *disabled = NULL;

	dmuci_get_value_by_section_string(dhcpv6_client->iface_s ? dhcpv6_client->iface_s : dhcpv6_client->dmmap_s, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "0" : "1";
	return 0;
}

static int set_DHCPv6Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	bool b;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		return 0;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(dhcpv6_client->dmmap_s, "disabled", b ? "0" : "1");
		if (dhcpv6_client->iface_s)
			dmuci_set_value_by_section(dhcpv6_client->iface_s, "disabled", b ? "0" : "1");
		return 0;
	}
	return 0;
}

static int get_DHCPv6Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dmmap_s, "bbf_dhcpv6client_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv6Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dmmap_s, "bbf_dhcpv6client_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv6Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	char *iface_name = NULL;

	dmuci_get_value_by_section_string(dhcpv6_client->dmmap_s, "iface_name", &iface_name);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", iface_name, value);

	if (DM_STRLEN(*value) == 0 && dhcpv6_client->iface_s) {
		struct uci_section *s = NULL;
		char *device = NULL;

		dmuci_get_value_by_section_string(dhcpv6_client->iface_s, "device", &device);
		if (DM_STRLEN(device) == 0)
			return 0;

		uci_foreach_option_eq("network", "interface", "device", device, s) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", section_name(s), value);
			if (DM_STRLEN(*value))
				return 0;
		}
	}
	return 0;
}

static int set_DHCPv6Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			// Get linker
			adm_entry_get_linker_value(ctx, value, &linker);

			if (dhcpv6_client->iface_s) {
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "proto", "none");
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "reqaddress", "");
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "reqprefix", "");
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "reqopts", "");
			}

			if (!linker || *linker == 0) {
				dmuci_set_value_by_section_bbfdm(dhcpv6_client->dmmap_s, "iface_name", "");
			} else {
				struct uci_section *interface_s = NULL;
				char *reqaddress = NULL;
				char *reqprefix = NULL;
				char *reqopts = NULL;

				get_config_section_of_dmmap_section("network", "interface", linker, &interface_s);
				if (interface_s == NULL)
					return FAULT_9007;

				// Update proto option of config section
				dmuci_set_value_by_section(interface_s, "proto", "dhcpv6");

				// Update dmmap section
				dmuci_set_value_by_section_bbfdm(dhcpv6_client->dmmap_s, "iface_name", linker);

				// Get the current value of requested parameters
				dmuci_get_value_by_section_string(dhcpv6_client->dmmap_s, "reqaddress", &reqaddress);
				dmuci_get_value_by_section_string(dhcpv6_client->dmmap_s, "reqprefix", &reqprefix);
				dmuci_get_value_by_section_string(dhcpv6_client->dmmap_s, "reqopts", &reqopts);

				// Set requested parameters
				dmuci_set_value_by_section(interface_s, "reqaddress", reqaddress);
				dmuci_set_value_by_section(interface_s, "reqprefix", reqprefix);
				dmuci_set_value_by_section(interface_s, "reqopts", reqopts);
			}
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv6Client_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_DHCPv6Client_Enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.DHCPv6.Client.{i}.DUID!UBUS:network.interface/status/interface,@Name/data.passthru*/
static int get_DHCPv6Client_DUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv6_s = ((struct dhcpv6_client_args *)data)->iface_s;
	if (dhcpv6_s) {
		json_object *res = NULL;

		char *if_name = section_name(dhcpv6_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		*value = res ? dmjson_get_value(res, 2, "data", "passthru") : "";
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestAddresses!UCI:network/interface,@i-1/reqaddress*/
static int get_DHCPv6Client_RequestAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	char *reqaddress = NULL;

	dmuci_get_value_by_section_string(dhcpv6_client->iface_s ? dhcpv6_client->iface_s : dhcpv6_client->dmmap_s, "reqaddress", &reqaddress);
	*value = (reqaddress && DM_LSTRCMP(reqaddress, "none") == 0) ? "0" : "1";
	return 0;
}

static int set_DHCPv6Client_RequestAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(dhcpv6_client->dmmap_s, "reqaddress", b ? "force" : "none");
			if (dhcpv6_client->iface_s)
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "reqaddress", b ? "force" : "none");
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestPrefixes!UCI:network/interface,@i-1/reqprefix*/
static int get_DHCPv6Client_RequestPrefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	char *reqprefix = NULL;

	dmuci_get_value_by_section_string(dhcpv6_client->iface_s ? dhcpv6_client->iface_s : dhcpv6_client->dmmap_s, "reqprefix", &reqprefix);
	*value = (reqprefix && DM_LSTRCMP(reqprefix, "auto") == 0) ? "1" : "0";
	return 0;
}

static int set_DHCPv6Client_RequestPrefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(dhcpv6_client->dmmap_s, "reqprefix", b ? "auto" : "no");
			if (dhcpv6_client->iface_s)
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "reqprefix", b ? "auto" : "no");
			return 0;
	}
	return 0;
}

static int get_DHCPv6Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_DHCPv6Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcpv6_s = ((struct dhcpv6_client_args *)data)->iface_s;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (!b) break;
			if (dhcpv6_s) {
				char *if_name = section_name(dhcpv6_s);
				dmubus_call_set("network.interface", "renew", UBUS_ARGS{{"interface", if_name, String}}, 1);
			}
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestedOptions!UCI:network/interface,@i-1/reqopts*/
static int get_DHCPv6Client_RequestedOptions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;

	dmuci_get_value_by_section_string(dhcpv6_client->iface_s ? dhcpv6_client->iface_s : dhcpv6_client->dmmap_s, "reqopts", value);
	return 0;
}

static int set_DHCPv6Client_RequestedOptions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_args *dhcpv6_client = (struct dhcpv6_client_args *)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, -1, -1, -1, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(dhcpv6_client->dmmap_s, "reqopts", value);
			if (dhcpv6_client->iface_s)
				dmuci_set_value_by_section(dhcpv6_client->iface_s, "reqopts", value);
			break;
	}
	return 0;
}

static int get_DHCPv6Server_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*odhcpd";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv6Server_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmcmd("/etc/init.d/odhcpd", 1, b ? "enable" : "disable");
			break;
	}
    return 0;
}

static int get_DHCPv6Server_PoolNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv6ServerPoolInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Enable!UCI:dhcp/dhcp,@i-1/dhcpv6*/
static int get_DHCPv6ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcpv6_args *)data)->dhcp_sections)->config_section, "dhcpv6", value);
	*value = (*value && DM_LSTRCMP(*value, "disabled") == 0) ? "0" : "1";
	return 0;
}

static int set_DHCPv6ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct dhcpv6_args *)data)->dhcp_sections)->config_section, "dhcpv6", b ? "server" : "disabled");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Status!UCI:dhcp/dhcp,@i-1/dhcpv6*/
static int get_DHCPv6ServerPool_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcpv6_args *)data)->dhcp_sections)->config_section, "dhcpv6", value);
	*value = (*value && DM_LSTRCMP(*value, "disabled") == 0) ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Alias!UCI:dmmap_dhcpv6/dhcp,@i-1/dhcpv6_serv_pool_alias*/
static int get_DHCPv6ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcpv6_args *)data)->dhcp_sections)->dmmap_section, "dhcpv6_serv_pool_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv6ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm((((struct dhcpv6_args *)data)->dhcp_sections)->dmmap_section, "dhcpv6_serv_pool_alias", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv6ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcpv6_args *)data)->dhcp_sections)->dmmap_section, "order", value);
	return 0;
}

static int set_DHCPv6ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			set_section_order("dhcp", "dmmap_dhcpv6", "dhcp", (((struct dhcpv6_args *)data)->dhcp_sections)->dmmap_section, (((struct dhcpv6_args *)data)->dhcp_sections)->config_section, 1, value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmstrdup(((struct dhcpv6_args *)data)->interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_DHCPv6ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section((((struct dhcpv6_args *)data)->dhcp_sections)->config_section, "interface", linker ? linker : "");
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.VendorClassID!UCI:dhcp/dhcp,@i-1/vendorclass*/
static int get_DHCPv6ServerPool_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char hex[256] = {0}, *vcid = NULL;

	struct uci_section *vendorclassidclassifier = get_dhcpv6_classifier("vendorclass", ((struct dhcpv6_args *)data)->interface);
	dmuci_get_value_by_section_string(vendorclassidclassifier, "vendorclass", &vcid);

	if (vcid && *vcid)
		convert_string_to_hex(vcid, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv6ServerPool_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *vendorclassidclassifier = NULL;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_to_string(value, res, sizeof(res));

			vendorclassidclassifier = get_dhcpv6_classifier("vendorclass", ((struct dhcpv6_args *)data)->interface);
			if (!vendorclassidclassifier) {
				dmuci_add_section("dhcp", "vendorclass", &vendorclassidclassifier);
				dmuci_set_value_by_section(vendorclassidclassifier, "networkid", ((struct dhcpv6_args *)data)->interface);
			}
			dmuci_set_value_by_section(vendorclassidclassifier, "vendorclass", res);
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.UserClassID!UCI:dhcp/dhcp,@i-1/userclass*/
static int get_DHCPv6ServerPool_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char hex[256] = {0}, *ucid = NULL;

	struct uci_section *userclassidclassifier = get_dhcpv6_classifier("userclass", ((struct dhcpv6_args *)data)->interface);
	dmuci_get_value_by_section_string(userclassidclassifier, "userclass", &ucid);

	if (ucid && *ucid)
		convert_string_to_hex(ucid, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv6ServerPool_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *userclassidclassifier = NULL;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_to_string(value, res, sizeof(res));

			userclassidclassifier = get_dhcpv6_classifier("userclass", ((struct dhcpv6_args *)data)->interface);
			if (!userclassidclassifier) {
				dmuci_add_section("dhcp", "userclass", &userclassidclassifier);
				dmuci_set_value_by_section(userclassidclassifier, "networkid", ((struct dhcpv6_args *)data)->interface);
			}
			dmuci_set_value_by_section(userclassidclassifier, "userclass", res);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_SourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *classifier_s = get_dhcpv6_classifier("mac", ((struct dhcpv6_args *)data)->interface);
	if (classifier_s == NULL) {
		*value = "";
		return 0;
	}

	return get_value_in_mac_format(classifier_s, "mac", false, value);
}

static int set_DHCPv6ServerPool_SourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPv6Address))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_SourceAddressMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *classifier_s = get_dhcpv6_classifier("mac", ((struct dhcpv6_args *)data)->interface);
	if (classifier_s == NULL) {
		*value = "";
		return 0;
	}

	return get_value_in_mac_format(classifier_s, "mac", true, value);
}

static int set_DHCPv6ServerPool_SourceAddressMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPv6Address))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv6ServerPoolClientInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv6ServerPool_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv6ServerPoolOptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv6ServerPoolClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *src_addr = ""; //should be updated when SourceAddress parameter is implemented

	uci_path_foreach_sections(bbfdm, "dmmap", "dhcpv6clients", s) {
		char *srcaddr;
		dmuci_get_value_by_section_string(s, "srcaddr", &srcaddr);
		if (DM_STRCMP(src_addr, srcaddr) == 0) {
			dmuci_get_value_by_section_string(s, "alias", value);
			break;
		}
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv6ServerPoolClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *src_addr = "";

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "dhcpv6clients", "srcaddr", src_addr, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "dhcpv6clients", &dmmap);
			dmuci_set_value_by_section(dmmap, "srcaddr", src_addr);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPoolClient_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv6ServerPoolClientIPv6AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv6ServerPoolClient_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv6ServerPoolClientIPv6PrefixInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "address");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_value_in_date_time_format(((struct clientv6_args *)data)->clientparam, "preferred-lifetime", value);
}

static int get_DHCPv6ServerPoolClientIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_value_in_date_time_format(((struct clientv6_args *)data)->clientparam, "valid-lifetime", value);
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "address");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";

	char *preferred = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "preferred-lifetime");
	if (preferred && *preferred != '\0' && DM_STRTOL(preferred) > 0) {
		time_t time_value = DM_STRTOL(preferred);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		if (strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", gmtime(&time_value)) == 0)
			return -1;
		*value = dmstrdup(s_now); // MEM WILL BE FREED IN DMMEMCLEAN
	}

	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";

	char *valid = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "valid-lifetime");
	if (valid && *valid != '\0' && DM_STRTOL(valid) > 0) {
		time_t time_value = DM_STRTOL(valid);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		if (strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", gmtime(&time_value)) == 0)
			return -1;
		*value = dmstrdup(s_now);
	}

	return 0;
}

static int get_DHCPv6ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcpv6_client_option_args *dhcpv6_client_s = (struct dhcpv6_client_option_args *)data;
	struct uci_list *dhcp_option_list;

	dmuci_get_value_by_section_list(dhcpv6_client_s->client_sect, "dhcp_option", &dhcp_option_list);
	if (dhcp_option_list != NULL) {
		struct uci_element *e = NULL;
		size_t length;

		uci_foreach_element(dhcp_option_list, e) {
			char **buf = strsplit(e->name, ",", &length);
			if (buf && *buf && DM_STRCMP(buf[0], dhcpv6_client_s->option_tag) == 0) {
				*value = "1";
				return 0;
			}
		}
	}
	*value= "0";
	return 0;
}

static int set_DHCPv6ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_option_args *dhcpv6_client_s = (struct dhcpv6_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;
	char opt_value[128] = {0};
	bool option_enabled = false, b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_list(dhcpv6_client_s->client_sect, "dhcp_option", &dhcp_option_list);
			snprintf(opt_value, sizeof(opt_value), "%s,%s", dhcpv6_client_s->option_tag, dhcpv6_client_s->value);

			if (dhcp_option_list != NULL) {
				struct uci_element *e = NULL;
				size_t length;

				uci_foreach_element(dhcp_option_list, e) {
					char **buf = strsplit(e->name, ",", &length);
					if (buf && *buf && DM_STRCMP(buf[0], dhcpv6_client_s->option_tag) == 0) {
						option_enabled = true;
						if (!b)
							dmuci_del_list_value_by_section(dhcpv6_client_s->client_sect, "dhcp_option", opt_value);
						break;
					}
				}
			}

			if(!option_enabled && b)
				dmuci_add_list_value_by_section(dhcpv6_client_s->client_sect, "dhcp_option", opt_value);
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_option_args *)data)->dmmap_sect, "bbf_dhcpv6_servpool_option_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;

}

static int set_DHCPv6ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dhcpv6_client_option_args *)data)->dmmap_sect, "bbf_dhcpv6_servpool_option_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcpv6_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv6ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_option_args *dhcpv6_client_s = (struct dhcpv6_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;
	bool option_enabled = false;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;

			if (dhcpv6_client_s->option_tag && DM_STRCMP(dhcpv6_client_s->option_tag, value) == 0)
				break;

			char *name = section_name(dhcpv6_client_s->client_sect);
			if (tag_option_exists("dmmap_dhcpv6", "servpool_option", "section_name", name, "option_tag", value))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_get_value_by_section_list(dhcpv6_client_s->client_sect, "dhcp_option", &dhcp_option_list);

			if (dhcp_option_list != NULL) {
				struct uci_element *e = NULL;
				size_t length;

				uci_foreach_element(dhcp_option_list, e) {
					char **buf = strsplit(e->name, ",", &length);
					if (buf && *buf && DM_STRCMP(buf[0], dhcpv6_client_s->option_tag) == 0) {
						option_enabled = true;
						break;
					}
				}
			}

			if (option_enabled) {
				char new_tag_value[128] = {0}, old_tag_value[128] = {0};

				snprintf(old_tag_value, sizeof(old_tag_value), "%s,%s", dhcpv6_client_s->option_tag, dhcpv6_client_s->value);
				snprintf(new_tag_value, sizeof(new_tag_value), "%s,%s", value, dhcpv6_client_s->value);
				dmuci_del_list_value_by_section(dhcpv6_client_s->client_sect, "dhcp_option", old_tag_value);
				dmuci_add_list_value_by_section(dhcpv6_client_s->client_sect, "dhcp_option", new_tag_value);
			}

			dmuci_set_value_by_section_bbfdm(dhcpv6_client_s->dmmap_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_value = ((struct dhcpv6_client_option_args *)data)->value;
	char hex[256] = {0};

	if (tag_value && *tag_value)
		convert_string_to_hex(tag_value, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv6ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcpv6_client_option_args *dhcpv6_client_s = (struct dhcpv6_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;
	char res[256] = {0};
	bool option_enabled = false;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_list(dhcpv6_client_s->client_sect, "dhcp_option", &dhcp_option_list);

			if (dhcp_option_list != NULL) {
				struct uci_element *e = NULL;
				size_t length;

				uci_foreach_element(dhcp_option_list, e) {
					char **buf = strsplit(e->name, ",", &length);
					if (buf && *buf && DM_STRCMP(buf[0], dhcpv6_client_s->option_tag) == 0) {
						option_enabled = true;
						break;
					}
				}
			}

			convert_hex_to_string(value, res, sizeof(res));

			if (option_enabled) {
				char new_tag_value[512] = {0}, old_tag_value[128] = {0};

				snprintf(old_tag_value, sizeof(old_tag_value), "%s,%s", dhcpv6_client_s->option_tag, dhcpv6_client_s->value);
				snprintf(new_tag_value, sizeof(new_tag_value), "%s,%s", dhcpv6_client_s->option_tag, res);
				dmuci_del_list_value_by_section(dhcpv6_client_s->client_sect, "dhcp_option", old_tag_value);
				dmuci_add_list_value_by_section(dhcpv6_client_s->client_sect, "dhcp_option", new_tag_value);
			}

			dmuci_set_value_by_section_bbfdm(dhcpv6_client_s->dmmap_sect, "option_value", res);
			break;
	}
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_DHCPv6Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcpv6_s = ((struct dhcpv6_client_args *)data)->iface_s;

	if (dhcpv6_s) {
		char *if_name = section_name(dhcpv6_s);
		dmubus_call_set("network.interface", "renew", UBUS_ARGS{{"interface", if_name, String}}, 1);
	}

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DHCPv6. *** */
DMOBJ tDHCPv6Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Client", &DMWRITE, addObjDHCPv6Client, delObjDHCPv6Client, NULL, browseDHCPv6ClientInst, NULL, NULL, NULL, tDHCPv6ClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", "Alias", NULL}, "2.2"},
{"Server", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv6ServerObj, tDHCPv6ServerParams, NULL, BBFDM_BOTH, NULL, "2.2"},
{0}
};

DMLEAF tDHCPv6Params[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6_ClientNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

DMLEAF tDHCPv6ClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6Client_Enable, set_DHCPv6Client_Enable, BBFDM_BOTH, "2.2"},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6Client_Alias, set_DHCPv6Client_Alias, BBFDM_BOTH, "2.2"},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv6Client_Interface, set_DHCPv6Client_Interface, BBFDM_BOTH, "2.2"},
{"Status", &DMREAD, DMT_STRING, get_DHCPv6Client_Status, NULL, BBFDM_BOTH, "2.2"},
{"DUID", &DMREAD, DMT_HEXBIN, get_DHCPv6Client_DUID, NULL, BBFDM_BOTH, "2.2"},
{"RequestAddresses", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RequestAddresses, set_DHCPv6Client_RequestAddresses, BBFDM_BOTH, "2.2"},
{"RequestPrefixes", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RequestPrefixes, set_DHCPv6Client_RequestPrefixes, BBFDM_BOTH, "2.2"},
//{"RapidCommit", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RapidCommit, set_DHCPv6Client_RapidCommit, BBFDM_BOTH, "2.2"},
{"Renew", &DMWRITE, DMT_BOOL, get_DHCPv6Client_Renew, set_DHCPv6Client_Renew, BBFDM_CWMP, "2.2"},
//{"SuggestedT1", &DMWRITE, DMT_INT, get_DHCPv6Client_SuggestedT1, set_DHCPv6Client_SuggestedT1, BBFDM_BOTH, "2.2"},
//{"SuggestedT2", &DMWRITE, DMT_INT, get_DHCPv6Client_SuggestedT2, set_DHCPv6Client_SuggestedT2, BBFDM_BOTH, "2.2"},
//{"SupportedOptions", &DMREAD, DMT_STRING, get_DHCPv6Client_SupportedOptions, NULL, BBFDM_BOTH, "2.2"},
{"RequestedOptions", &DMWRITE, DMT_STRING, get_DHCPv6Client_RequestedOptions, set_DHCPv6Client_RequestedOptions, BBFDM_BOTH, "2.2"},
//{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_ServerNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
//{"SentOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_SentOptionNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
//{"ReceivedOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_ReceivedOptionNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{"Renew()", &DMSYNC, DMT_COMMAND, NULL, operate_DHCPv6Client_Renew, BBFDM_USP, "2.12"},
{0}
};

/* *** Device.DHCPv6.Server. *** */
DMOBJ tDHCPv6ServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Pool", &DMWRITE, addObjDHCPv6ServerPool, delObjDHCPv6ServerPool, NULL, browseDHCPv6ServerPoolInst, NULL, NULL, tDHCPv6ServerPoolObj, tDHCPv6ServerPoolParams, NULL, BBFDM_BOTH, LIST_KEY{"Order", "Alias", NULL}, "2.2"},
{0}
};

DMLEAF tDHCPv6ServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6Server_Enable, set_DHCPv6Server_Enable, BBFDM_BOTH, "2.2"},
{"PoolNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Server_PoolNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}. *** */
DMOBJ tDHCPv6ServerPoolObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Client", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientInst, NULL, NULL, tDHCPv6ServerPoolClientObj, tDHCPv6ServerPoolClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.2"},
{"Option", &DMWRITE, addObjDHCPv6ServerPoolOption, delObjDHCPv6ServerPoolOption, NULL, browseDHCPv6ServerPoolOptionInst, NULL, NULL, NULL, tDHCPv6ServerPoolOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}, "2.2"},
{0}
};

DMLEAF tDHCPv6ServerPoolParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_Enable, set_DHCPv6ServerPool_Enable, BBFDM_BOTH, "2.2"},
{"Status", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_Status, NULL, BBFDM_BOTH, "2.2"},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_Alias, set_DHCPv6ServerPool_Alias, BBFDM_BOTH, "2.2"},
{"Order", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPool_Order, set_DHCPv6ServerPool_Order, BBFDM_BOTH, "2.2"},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_Interface, set_DHCPv6ServerPool_Interface, BBFDM_BOTH, "2.2"},
//{"DUID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_DUID, set_DHCPv6ServerPool_DUID, BBFDM_BOTH, "2.2"},
//{"DUIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_DUIDExclude, set_DHCPv6ServerPool_DUIDExclude, BBFDM_BOTH, "2.2"},
{"VendorClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_VendorClassID, set_DHCPv6ServerPool_VendorClassID, BBFDM_BOTH, "2.2"},
//{"VendorClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_VendorClassIDExclude, set_DHCPv6ServerPool_VendorClassIDExclude, BBFDM_BOTH, "2.2"},
{"UserClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_UserClassID, set_DHCPv6ServerPool_UserClassID, BBFDM_BOTH, "2.2"},
//{"UserClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_UserClassIDExclude, set_DHCPv6ServerPool_UserClassIDExclude, BBFDM_BOTH, "2.2"},
{"SourceAddress", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_SourceAddress, set_DHCPv6ServerPool_SourceAddress, BBFDM_BOTH, "2.2"},
{"SourceAddressMask", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_SourceAddressMask, set_DHCPv6ServerPool_SourceAddressMask, BBFDM_BOTH, "2.2"},
//{"SourceAddressExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_SourceAddressExclude, set_DHCPv6ServerPool_SourceAddressExclude, BBFDM_BOTH, "2.2"},
//{"IANAEnable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_IANAEnable, set_DHCPv6ServerPool_IANAEnable, BBFDM_BOTH, "2.2"},
//{"IANAManualPrefixes", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_IANAManualPrefixes, set_DHCPv6ServerPool_IANAManualPrefixes, BBFDM_BOTH, "2.2"},
//{"IANAPrefixes", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_IANAPrefixes, NULL, BBFDM_BOTH, "2.2"},
//{"IAPDEnable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_IAPDEnable, set_DHCPv6ServerPool_IAPDEnable, BBFDM_BOTH, "2.2"},
//{"IAPDManualPrefixes", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_IAPDManualPrefixes, set_DHCPv6ServerPool_IAPDManualPrefixes, BBFDM_BOTH, "2.2"},
//{"IAPDPrefixes", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_IAPDPrefixes, NULL, BBFDM_BOTH, "2.2"},
//{"IAPDAddLength", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPool_IAPDAddLength, set_DHCPv6ServerPool_IAPDAddLength, BBFDM_BOTH, "2.2"},
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPool_ClientNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPool_OptionNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}. *** */
DMOBJ tDHCPv6ServerPoolClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientIPv6AddressInst, NULL, NULL, NULL, tDHCPv6ServerPoolClientIPv6AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"IPAddress", NULL}, "2.2"},
{"IPv6Prefix", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientIPv6PrefixInst, NULL, NULL, NULL, tDHCPv6ServerPoolClientIPv6PrefixParams, NULL, BBFDM_BOTH, LIST_KEY{"Prefix", NULL}, "2.2"},
//{"Option", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientOptionInst, NULL, NULL, NULL, tDHCPv6ServerPoolClientOptionParams, NULL, BBFDM_BOTH, NULL, "2.2"},
{0}
};

DMLEAF tDHCPv6ServerPoolClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolClient_Alias, set_DHCPv6ServerPoolClient_Alias, BBFDM_BOTH, "2.2"},
//{"SourceAddress", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClient_SourceAddress, NULL, BBFDM_BOTH, "2.2"},
//{"Active", &DMREAD, DMT_BOOL, get_DHCPv6ServerPoolClient_Active, NULL, BBFDM_BOTH, "2.2"},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_IPv6AddressNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{"IPv6PrefixNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_IPv6PrefixNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
//{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_OptionNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Address.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClientIPv6Address_IPAddress, NULL, BBFDM_BOTH, "2.2"},
{"PreferredLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Address_PreferredLifetime, NULL, BBFDM_BOTH, "2.2"},
{"ValidLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Address_ValidLifetime, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Prefix.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientIPv6PrefixParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Prefix", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClientIPv6Prefix_Prefix, NULL, BBFDM_BOTH, "2.2"},
{"PreferredLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Prefix_PreferredLifetime, NULL, BBFDM_BOTH, "2.2"},
{"ValidLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Prefix_ValidLifetime, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.Option.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Tag", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClientOption_Tag, NULL, BBFDM_BOTH, "2.2"},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv6ServerPoolClientOption_Value, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Option.{i}. *** */
DMLEAF tDHCPv6ServerPoolOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPoolOption_Enable, set_DHCPv6ServerPoolOption_Enable, BBFDM_BOTH, "2.2"},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolOption_Alias, set_DHCPv6ServerPoolOption_Alias, BBFDM_BOTH, "2.2"},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPoolOption_Tag, set_DHCPv6ServerPoolOption_Tag, BBFDM_BOTH, "2.2"},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPoolOption_Value, set_DHCPv6ServerPoolOption_Value, BBFDM_BOTH, "2.2"},
//{"PassthroughClient", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolOption_PassthroughClient, set_DHCPv6ServerPoolOption_PassthroughClient, BBFDM_BOTH, "2.2"},
{0}
};
