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

#include "dmentry.h"
#include "dhcpv4.h"
#include "dhcpv6.h"


struct dhcpv6_client_args
{
	struct uci_section *dhcp_client_conf;
	struct uci_section *dhcp_client_dm;
	char *ip;
};

struct dhcpv6_args
{
	struct uci_section *dhcp_sec;
	char *interface;
};

struct clientv6_args
{
	json_object *client;
	json_object *clientparam;
	int idx;
};

struct dhcpv6_client_option_args {
	struct uci_section *opt_sect;
	struct uci_section *client_sect;
	char *option_tag;
	char *value;
};

static struct uci_section *get_dhcpv6_classifier(char *classifier_name, const char *network)
{
	struct uci_section *s = NULL;
	char *v;

	uci_foreach_sections("dhcp", classifier_name, s) {
		dmuci_get_value_by_section_string(s, "networkid", &v);
		if (strcmp(v, network) == 0)
			return s;
	}
	return NULL;
}

static int get_value_in_date_time_format(json_object *json_obj, char *option_name, char **value)
{
	const char *option_value = dmjson_get_value(json_obj, 1, option_name);
	if (option_value && *option_value != '\0' && atoi(option_value) > 0) {
		time_t time_value = atoi(option_value);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		if (strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", localtime(&time_value)) == 0)
			return -1;
		*value = dmstrdup(s_now); // MEM WILL BE FREED IN DMMEMCLEAN
	}
	return 0;	
}

static inline int init_dhcpv6_client_args(struct clientv6_args *args, json_object *client, json_object *client_param, int i)
{
	args->client = client;
	args->clientparam = client_param;
	args->idx = i;
	return 0;
}

static inline int init_dhcpv6_args(struct dhcpv6_args *args, struct uci_section *s, char *interface)
{
	args->interface = interface;
	args->dhcp_sec = s;
	return 0;
}

/*#Device.DHCPv6.Client.{i}.!UCI:network/interface/dmmap_dhcpv6*/
static int browseDHCPv6ClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcpv6_client_args dhcpv6_client_arg = {0};
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_dhcpv6", "proto", "dhcpv6", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *ipv6addr = NULL;

		dmuci_get_value_by_section_string(p->config_section, "ip6addr", &ipv6addr);
		if (ipv6addr && ipv6addr[0] == '\0') {
			json_object *res = NULL;

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
			if (res) {
				json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
				ipv6addr = dmjson_get_value(jobj, 1, "address");
			}
		}

		dhcpv6_client_arg.dhcp_client_conf = p->config_section;
		dhcpv6_client_arg.dhcp_client_dm = p->dmmap_section;
		dhcpv6_client_arg.ip = dmstrdup(ipv6addr ? ipv6addr : "");

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "bbf_dhcpv6client_instance", "bbf_dhcpv6client_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcpv6_client_arg, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.!UCI:dhcp/dhcp/dmmap_dhcpv6*/
static int browseDHCPv6ServerPoolInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ignore = NULL, *interface, *inst = NULL, *max_inst = NULL, *v;
	struct dhcpv6_args curr_dhcp6_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_dhcpv6", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(p->config_section, "ignore", &ignore);
		if (ignore && strcmp(ignore, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "interface", &interface);
		init_dhcpv6_args(&curr_dhcp6_args, p->config_section, interface);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "dhcpv6_serv_pool_instance", "dhcpv6_serv_pool_alias");

		dmuci_get_value_by_section_string(p->dmmap_section, "order", &v);
		if (v == NULL || strlen(v) == 0)
			set_section_order("dhcp", "dmmap_dhcpv6", "dhcp", p->dmmap_section, p->config_section, 0, inst);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp6_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);

	return 0;
}

static int browseDHCPv6ServerPoolClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcpv6_args *dhcp_arg= (struct dhcpv6_args*)prev_data;
	json_object *res = NULL, *res1 = NULL, *jobj = NULL, *dev_obj = NULL, *net_obj = NULL;
	struct clientv6_args curr_dhcp_client_args = {0};
	int i = 0;
	char *inst = NULL, *max_inst = NULL, *device;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(dhcp_arg->dhcp_sec), String}}, 1, &res1);
	if (!res1) return 0;
	device = dmjson_get_value(res1, 1, "device");
	dmubus_call("dhcp", "ipv6leases", UBUS_ARGS{}, 0, &res);
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
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_client_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv6ServerPoolOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e = NULL;
	struct dhcpv6_args *curr_dhcp_args = (struct dhcpv6_args*)prev_data;
	struct uci_section *dmmap_sect = NULL;
	struct browse_args browse_args = {0};
	char **dhcpv6_option = NULL, *inst = NULL, *max_inst = NULL, *optionvalue = NULL, *tmp = NULL, *dhcpv6_tag, *dhcpv6_value;
	size_t length;
	struct dhcpv6_client_option_args dhcpv6_client_opt_args = {0};

	dmuci_get_value_by_section_list(curr_dhcp_args->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			dhcpv6_option = strsplit(e->name, ",", &length);
			if (!dhcpv6_option)
				continue;

			if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcpv6", "servpool_option", section_name(curr_dhcp_args->dhcp_sec), "option_tag", dhcpv6_option[0])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcpv6", "servpool_option", &dmmap_sect);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", dhcpv6_option[0]);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(curr_dhcp_args->dhcp_sec));
			}
			optionvalue = dmstrdup(length > 1 ? dhcpv6_option[1] : "");
			if (length > 2) {
				int j;

				for (j = 2; j < length; j++){
					tmp = dmstrdup(optionvalue);
					dmfree(optionvalue);
					optionvalue = NULL;
					dmasprintf(&optionvalue, "%s,%s", tmp, dhcpv6_option[j]);
					dmfree(tmp);
					tmp = NULL;
				}
			}
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_value", optionvalue);
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcpv6", "servpool_option", "section_name", section_name(curr_dhcp_args->dhcp_sec), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &dhcpv6_tag);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &dhcpv6_value);

		dhcpv6_client_opt_args.client_sect = curr_dhcp_args->dhcp_sec;
		dhcpv6_client_opt_args.opt_sect = dmmap_sect;
		dhcpv6_client_opt_args.option_tag = dhcpv6_tag;
		dhcpv6_client_opt_args.value = dhcpv6_value;

		browse_args.option = "section_name";
		browse_args.value = section_name(curr_dhcp_args->dhcp_sec);

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   dmmap_sect, "bbf_dhcpv6_servpool_option_instance", "bbf_dhcpv6_servpool_option_alias",
			   check_browse_section, (void *)&browse_args);

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
	char *inst = NULL, *max_inst = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(dhcpv6_serv_pool_client->client, i, 1, "ipv6-addr");
		if (address_obj == NULL)
			break;
		init_dhcpv6_client_args(&curr_dhcv6_address_args, dhcpv6_serv_pool_client->client, address_obj, i);
		i++;
		inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, i);
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
	char *inst = NULL, *max_inst = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(dhcpv6_serv_pool_client->client, i, 1, "ipv6-prefix");
		if (address_obj == NULL)
			break;
		init_dhcpv6_client_args(&curr_dhcv6_address_args, dhcpv6_serv_pool_client->client, address_obj, i);
		i++;
		inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcv6_address_args, inst) == DM_STOP)
			break;
	}

	return 0;
}

static int addObjDHCPv6Client(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_sect = NULL;
	char dhcpv6_s[32];

	char *last_inst = get_last_instance_bbfdm("dmmap_dhcpv6", "interface", "bbf_dhcpv6client_instance");
	snprintf(dhcpv6_s, sizeof(dhcpv6_s), "dhcpv6_intf_%d", last_inst ? atoi(last_inst) + 1 : 1);

	dmuci_add_section("network", "interface", &s);
	dmuci_rename_section_by_section(s, dhcpv6_s);
	dmuci_set_value_by_section(s, "proto", "dhcpv6");
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "reqaddress", "force");
	dmuci_set_value_by_section(s, "reqprefix", "no");

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "interface", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "section_name", dhcpv6_s);
	dmuci_set_value_by_section(dmmap_sect, "added_by_controller", "1");
	*instance = update_instance(last_inst, 2, dmmap_sect, "bbf_dhcpv6client_instance");
	return 0;
}

static int delObjDHCPv6Client(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *s_tmp = NULL;
	char *added_by_controller = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct dhcpv6_client_args*)data)->dhcp_client_dm, "added_by_controller", &added_by_controller);
			if (added_by_controller && strcmp(added_by_controller, "1") == 0) {
				dmuci_delete_by_section(((struct dhcpv6_client_args*)data)->dhcp_client_conf, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct dhcpv6_client_args*)data)->dhcp_client_conf, "proto", "none");
			}

			dmuci_delete_by_section(((struct dhcpv6_client_args*)data)->dhcp_client_dm, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("network", "interface", "proto", "dhcpv6", s_tmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_dhcpv6", "interface", section_name(s), &dmmap_section);

				dmuci_get_value_by_section_string(dmmap_section, "added_by_controller", &added_by_controller);
				if (added_by_controller && strcmp(added_by_controller, "1") == 0) {
					dmuci_delete_by_section(s, NULL, NULL);
				} else {
					dmuci_set_value_by_section(s, "proto", "none");
				}

				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv6ServerPool(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_dhcp = NULL;
	char dhcpv6_sname[32] = {0};

	char *inst_para = get_dhcp_server_pool_last_instance("dhcp", "dhcp", "dmmap_dhcpv6", "dhcpv6_serv_pool_instance");
	snprintf(dhcpv6_sname, sizeof(dhcpv6_sname), "dhcpv6_%d", inst_para ? atoi(inst_para) + 1 : 1);

	dmuci_add_section("dhcp", "dhcp", &s);
	dmuci_rename_section_by_section(s, dhcpv6_sname);
	dmuci_set_value_by_section(s, "dhcpv6", "server");
	dmuci_set_value_by_section(s, "start", "100");
	dmuci_set_value_by_section(s, "leasetime", "12h");
	dmuci_set_value_by_section(s, "limit", "150");
	dmuci_set_value_by_section(s, "ignore", "0");

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "dhcp", &dmmap_dhcp);
	dmuci_set_value_by_section(dmmap_dhcp, "section_name", dhcpv6_sname);
	*instance = update_instance(inst_para, 2, dmmap_dhcp, "dhcpv6_serv_pool_instance");
	return 0;
}

static int delObjDHCPv6ServerPool(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	char *dhcpv6 = NULL;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name(((struct dhcpv6_args *)data)->dhcp_sec))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcpv6", "dhcp", "dhcpv6_serv_pool_instance", section_name(((struct dhcpv6_args *)data)->dhcp_sec), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "dhcpv6_serv_pool_instance", "dmmap_dhcpv6", "dhcp");
				dmuci_delete_by_section_unnamed(((struct dhcpv6_args *)data)->dhcp_sec, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_section);
				if(dmmap_section) dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(((struct dhcpv6_args *)data)->dhcp_sec, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("dhcp", "dhcp", s) {
				if (found != 0){
					dmuci_get_value_by_section_string(ss, "dhcpv6", &dhcpv6);
					if(strcmp(dhcpv6, "server") == 0){
						get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(s), &dmmap_section);
						if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
						dmuci_delete_by_section(ss, NULL, NULL);
					}
				}
				ss = s;
				found++;
			}
			if (ss != NULL){
				dmuci_get_value_by_section_string(ss, "dhcpv6", &dhcpv6);
				if(strcmp(dhcpv6, "server") == 0){
					get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(ss), &dmmap_section);
					if(dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
			}
			break;
	}
	return 0;
}

static int addObjDHCPv6ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcpv6_args *dhcp_arg = (struct dhcpv6_args*)data;
	struct uci_section *dmmap_sect;
	struct browse_args browse_args = {0};

	char *inst_para = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcpv6", "servpool_option", "bbf_dhcpv6_servpool_option_instance", "section_name", section_name(dhcp_arg->dhcp_sec));

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "servpool_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_arg->dhcp_sec));
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", "0");

	browse_args.option = "section_name";
	browse_args.value = section_name(dhcp_arg->dhcp_sec);

	*instance = update_instance(inst_para, 5, dmmap_sect, "bbf_dhcpv6_servpool_option_instance", NULL, check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjDHCPv6ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *opt_value = NULL;
	struct uci_list *dhcp_options_list = NULL;

	switch (del_action) {
		case DEL_INST:
			if (strcmp(((struct dhcpv6_client_option_args*) data)->option_tag, "0") != 0) {
				dmasprintf(&opt_value, "%s,%s", ((struct dhcpv6_client_option_args*) data)->option_tag, ((struct dhcpv6_client_option_args*) data)->value);
				dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args*) data)->client_sect, "dhcp_option", &dhcp_options_list);
				if (dhcp_options_list != NULL) {
					dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args*) data)->client_sect, "dhcp_option", opt_value);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcpv6_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcpv6_args*) data)->dhcp_sec, "dhcp_option", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcpv6", "servpool_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int get_DHCPv6_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_sections(bbfdm, "dmmap_dhcpv6", "interface", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv6.Client.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv6Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "0" : "1";
	return 0;
}

static int set_DHCPv6Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		return 0;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "disabled", b ? "0" : "1");
		return 0;
	}
	return 0;
}

static int get_DHCPv6Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_dm, "bbf_dhcpv6client_alias", value);
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
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_dm, "bbf_dhcpv6client_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv6Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv6_s = ((struct dhcpv6_client_args *)data)->dhcp_client_conf;
	char *ifname = NULL;

	dmuci_get_value_by_section_string(dhcpv6_s, "ifname", &ifname);
	char *parent_s = (ifname && *ifname) ? strchr(ifname, '@') : NULL;

	char *linker = dmstrdup(parent_s ? parent_s + 1 : dhcpv6_s ? section_name(dhcpv6_s) : "");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_DHCPv6Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_DHCP_Interface(ctx, value, ((struct dhcpv6_client_args *)data)->dhcp_client_conf, ((struct dhcpv6_client_args *)data)->dhcp_client_dm, "dmmap_dhcpv6", "dhcpv6", action);
}

/*#Device.DHCPv6.Client.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv6Client_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv6.Client.{i}.DUID!UBUS:network.interface/status/interface,@Name/data.passthru*/
static int get_DHCPv6Client_DUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv6_s = ((struct dhcpv6_client_args *)data)->dhcp_client_conf;
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dhcpv6_s ? section_name(dhcpv6_s) : "", String}}, 1, &res);
	*value = res ? dmjson_get_value(res, 2, "data", "passthru") : "";
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestAddresses!UCI:network/interface,@i-1/reqaddress*/
static int get_DHCPv6Client_RequestAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *reqaddress = NULL;

	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqaddress", &reqaddress);
	*value = (reqaddress && strcmp(reqaddress, "none") == 0) ? "0" : "1";
	return 0;
}

static int set_DHCPv6Client_RequestAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqaddress", b ? "force" : "none");
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestPrefixes!UCI:network/interface,@i-1/reqprefix*/
static int get_DHCPv6Client_RequestPrefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *reqprefix = NULL;

	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqprefix", &reqprefix);
	*value = (reqprefix && strcmp(reqprefix, "auto") == 0) ? "1" : "0";
	return 0;
}

static int set_DHCPv6Client_RequestPrefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqprefix", b ? "auto" : "no");
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
	struct uci_section *dhcpv6_s = ((struct dhcpv6_client_args *)data)->dhcp_client_conf;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (!b) break;
			dmubus_call_set("network.interface", "renew", UBUS_ARGS{{"interface", dhcpv6_s ? section_name(dhcpv6_s) : "", String}}, 1);
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestedOptions!UCI:network/interface,@i-1/reqopts*/
static int get_DHCPv6Client_RequestedOptions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqopts", value);
	return 0;
}

static int set_DHCPv6Client_RequestedOptions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, -1, -1, -1, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqopts", value);
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
	struct uci_section *s = NULL;
	char *ignore = NULL;
	int i = 0;

	uci_foreach_sections("dhcp", "dhcp", s) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(s, "ignore", &ignore);
		if (ignore && strcmp(ignore, "1") == 0)
			continue;

		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Enable!UCI:dhcp/dhcp,@i-1/dhcpv6*/
static int get_DHCPv6ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_args *)data)->dhcp_sec, "dhcpv6", value);
	*value = (*value && strcmp(*value, "disabled") == 0) ? "0" : "1";
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
			dmuci_set_value_by_section(((struct dhcpv6_args *)data)->dhcp_sec, "dhcpv6", b ? "server" : "disabled");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Status!UCI:dhcp/dhcp,@i-1/dhcpv6*/
static int get_DHCPv6ServerPool_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_args *)data)->dhcp_sec, "dhcpv6", value);
	*value = (*value && strcmp(*value, "disabled") == 0) ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Alias!UCI:dmmap_dhcpv6/dhcp,@i-1/dhcpv6_serv_pool_alias*/
static int get_DHCPv6ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "dhcpv6_serv_pool_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv6ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "dhcpv6_serv_pool_alias", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv6ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "order", value);
	return 0;
}

static int set_DHCPv6ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
			if (dmmap_sect)
				set_section_order("dhcp", "dmmap_dhcpv6", "dhcp", dmmap_sect, ((struct dhcpv6_args *)data)->dhcp_sec, 1, value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	linker = dmstrdup(((struct dhcpv6_args *)data)->interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	if (*value == NULL)
		*value = "";
	dmfree(linker);
	return 0;
}

static int set_DHCPv6ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section(((struct dhcpv6_args *)data)->dhcp_sec, "interface", linker);
				dmfree(linker);
			}
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
		convert_string_to_hex(vcid, hex);

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
			convert_hex_to_string(value, res);

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
		convert_string_to_hex(ucid, hex);

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
			convert_hex_to_string(value, res);

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

static int get_DHCPv6ServerPool_SourceAddressMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)  //TODO: return wrong value
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
	json_object *res = NULL, *res1 = NULL, *jobj = NULL, *dev_obj = NULL, *next_obj = NULL;
	char *device;
	int i = 0;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcpv6_args *)data)->dhcp_sec), String}}, 1, &res1);
	DM_ASSERT(res1, *value = "0");
	device = dmjson_get_value(res1, 1, "device");
	dmubus_call("dhcp", "ipv6leases", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	dev_obj = dmjson_get_obj(res, 1, "device");
	DM_ASSERT(dev_obj, *value = "0");
	next_obj = dmjson_get_obj(dev_obj, 1, device);
	DM_ASSERT(next_obj, *value = "0");
	while (1) {
		jobj = dmjson_select_obj_in_array_idx(next_obj, i, 1, "leases");
		if (jobj == NULL)
			break;
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPool_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e = NULL;
	int i = 0;

	dmuci_get_value_by_section_list(((struct dhcpv6_args *)data)->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			i++;
		}
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPoolClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *src_addr = ""; //should be updated when SourceAddress parameter is implemented

	uci_path_foreach_sections(bbfdm, "dmmap", "dhcpv6clients", s) {
		char *srcaddr;
		dmuci_get_value_by_section_string(s, "srcaddr", &srcaddr);
		if (strcmp(src_addr, srcaddr) == 0) {
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
	json_object *address_obj = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(((struct clientv6_args *)data)->client, i, 1, "ipv6-addr");
		if (address_obj == NULL)
			break;
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPoolClient_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *address_obj = NULL;
	int i= 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(((struct clientv6_args *)data)->client, i, 1, "ipv6-prefix");
		if (address_obj == NULL)
			break;
		i++;
	}
	dmasprintf(value, "%d", i);
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
	if (preferred && *preferred != '\0' && atoi(preferred) > 0) {
		time_t time_value = atoi(preferred);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		if (strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", localtime(&time_value)) == 0)
			return -1;
		*value = dmstrdup(s_now); // MEM WILL BE FREED IN DMMEMCLEAN
	}

	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";

	char *valid = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "valid-lifetime");
	if (valid && *valid != '\0' && atoi(valid) > 0) {
		time_t time_value = atoi(valid);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		if (strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", localtime(&time_value)) == 0)
			return -1;
		*value = dmstrdup(s_now);
	}

	return 0;
}

static int get_DHCPv6ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_option_list;
	struct uci_element *e = NULL;
	char **buf = NULL;
	size_t length;

	if(strcmp(((struct dhcpv6_client_option_args *)data)->option_tag, "0") == 0){
		*value = "0";
		return 0;
	}

	dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
	if (dhcp_option_list != NULL) {
		uci_foreach_element(dhcp_option_list, e) {
			buf = strsplit(e->name, ",", &length);
			if (buf && *buf && strcmp(buf[0], ((struct dhcpv6_client_option_args *)data)->option_tag) == 0) {
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
	struct uci_list *dhcp_option_list;
	struct uci_element *e = NULL;
	char **buf = NULL, *opt_value;
	size_t length;
	bool test = false, b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			if (strcmp(((struct dhcpv6_client_option_args *)data)->option_tag, "0") == 0)
				return 0;

			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmasprintf(&opt_value, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);

			if (dhcp_option_list != NULL) {
				uci_foreach_element(dhcp_option_list, e) {
					buf = strsplit(e->name, ",", &length);
					if (buf && *buf && strcmp(buf[0], ((struct dhcpv6_client_option_args *)data)->option_tag) == 0) {
						test = true;
						if (!b)
							dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
						break;
					}
				}
			}
			if (!test && b)
				dmuci_add_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_option_args *)data)->opt_sect, "bbf_dhcpv6_servpool_option_alias", value);
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
			dmuci_set_value_by_section_bbfdm(((struct dhcpv6_client_option_args *)data)->opt_sect, "bbf_dhcpv6_servpool_option_alias", value);
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
	char *opttagvalue, **option = NULL, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list= NULL;
	struct uci_element *e = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);

			if (dhcp_option_list == NULL)
				return 0;

			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (option && *option && strcmp(option[0], value)==0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", value, ((struct dhcpv6_client_option_args *)data)->value);
			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			dmuci_set_value_by_section_bbfdm(((struct dhcpv6_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_value = ((struct dhcpv6_client_option_args *)data)->value;
	char hex[256] = {0};

	if (tag_value && *tag_value)
		convert_string_to_hex(tag_value, hex);

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv6ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option = NULL, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e = NULL;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			if (dhcp_option_list == NULL)
				return 0;

			convert_hex_to_string(value, res);

			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (option && *option && strcmp(option[0], res) == 0)
					return FAULT_9007;
			}
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, res);
			dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			dmuci_set_value_by_section_bbfdm(((struct dhcpv6_client_option_args *)data)->opt_sect, "option_value", res);
			break;
	}
	return 0;
}

/* *** Device.DHCPv6. *** */
DMOBJ tDHCPv6Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Client", &DMWRITE, addObjDHCPv6Client, delObjDHCPv6Client, NULL, browseDHCPv6ClientInst, NULL, tDHCPv6ClientObj, tDHCPv6ClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", "Alias", NULL}},
{"Server", &DMREAD, NULL, NULL, NULL, NULL, NULL, tDHCPv6ServerObj, tDHCPv6ServerParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6Params[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}. *** */
DMOBJ tDHCPv6ClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
//{"Server", &DMREAD, NULL, NULL, NULL, browseDHCPv6ClientServerInst, NULL, NULL, tDHCPv6ClientServerParams, NULL, BBFDM_BOTH, LIST_KEY{"SourceAddress", NULL}},
//{"SentOption", &DMWRITE, addObjDHCPv6ClientSentOption, delObjDHCPv6ClientSentOption, NULL, browseDHCPv6ClientSentOptionInst, NULL, NULL, tDHCPv6ClientSentOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
//{"ReceivedOption", &DMREAD, NULL, NULL, NULL, browseDHCPv6ClientReceivedOptionInst, NULL, NULL, tDHCPv6ClientReceivedOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6ClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6Client_Enable, set_DHCPv6Client_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6Client_Alias, set_DHCPv6Client_Alias, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv6Client_Interface, set_DHCPv6Client_Interface, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv6Client_Status, NULL, BBFDM_BOTH},
{"DUID", &DMREAD, DMT_HEXBIN, get_DHCPv6Client_DUID, NULL, BBFDM_BOTH},
{"RequestAddresses", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RequestAddresses, set_DHCPv6Client_RequestAddresses, BBFDM_BOTH},
{"RequestPrefixes", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RequestPrefixes, set_DHCPv6Client_RequestPrefixes, BBFDM_BOTH},
//{"RapidCommit", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RapidCommit, set_DHCPv6Client_RapidCommit, BBFDM_BOTH},
{"Renew", &DMWRITE, DMT_BOOL, get_DHCPv6Client_Renew, set_DHCPv6Client_Renew, BBFDM_CWMP},
//{"SuggestedT1", &DMWRITE, DMT_INT, get_DHCPv6Client_SuggestedT1, set_DHCPv6Client_SuggestedT1, BBFDM_BOTH},
//{"SuggestedT2", &DMWRITE, DMT_INT, get_DHCPv6Client_SuggestedT2, set_DHCPv6Client_SuggestedT2, BBFDM_BOTH},
//{"SupportedOptions", &DMREAD, DMT_STRING, get_DHCPv6Client_SupportedOptions, NULL, BBFDM_BOTH},
{"RequestedOptions", &DMWRITE, DMT_STRING, get_DHCPv6Client_RequestedOptions, set_DHCPv6Client_RequestedOptions, BBFDM_BOTH},
//{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_ServerNumberOfEntries, NULL, BBFDM_BOTH},
//{"SentOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_SentOptionNumberOfEntries, NULL, BBFDM_BOTH},
//{"ReceivedOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_ReceivedOptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}.Server.{i}. *** */
DMLEAF tDHCPv6ClientServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"SourceAddress", &DMREAD, DMT_STRING, get_DHCPv6ClientServer_SourceAddress, NULL, BBFDM_BOTH},
//{"DUID", &DMREAD, DMT_HEXBIN, get_DHCPv6ClientServer_DUID, NULL, BBFDM_BOTH},
//{"InformationRefreshTime", &DMREAD, DMT_TIME, get_DHCPv6ClientServer_InformationRefreshTime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}.SentOption.{i}. *** */
DMLEAF tDHCPv6ClientSentOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ClientSentOption_Enable, set_DHCPv6ClientSentOption_Enable, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ClientSentOption_Alias, set_DHCPv6ClientSentOption_Alias, BBFDM_BOTH},
//{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv6ClientSentOption_Tag, set_DHCPv6ClientSentOption_Tag, BBFDM_BOTH},
//{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv6ClientSentOption_Value, set_DHCPv6ClientSentOption_Value, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}.ReceivedOption.{i}. *** */
DMLEAF tDHCPv6ClientReceivedOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Tag", &DMREAD, DMT_UNINT, get_DHCPv6ClientReceivedOption_Tag, NULL, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv6ClientReceivedOption_Value, NULL, BBFDM_BOTH},
//{"Server", &DMREAD, DMT_STRING, get_DHCPv6ClientReceivedOption_Server, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server. *** */
DMOBJ tDHCPv6ServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Pool", &DMWRITE, addObjDHCPv6ServerPool, delObjDHCPv6ServerPool, NULL, browseDHCPv6ServerPoolInst, NULL, tDHCPv6ServerPoolObj, tDHCPv6ServerPoolParams, NULL, BBFDM_BOTH, LIST_KEY{"Order", "Alias", NULL}},
{0}
};

DMLEAF tDHCPv6ServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6Server_Enable, set_DHCPv6Server_Enable, BBFDM_BOTH},
{"PoolNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Server_PoolNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}. *** */
DMOBJ tDHCPv6ServerPoolObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Client", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientInst, NULL, tDHCPv6ServerPoolClientObj, tDHCPv6ServerPoolClientParams, NULL, BBFDM_BOTH, LIST_KEY{"SourceAddress", "Alias", NULL}},
{"Option", &DMWRITE, addObjDHCPv6ServerPoolOption, delObjDHCPv6ServerPoolOption, NULL, browseDHCPv6ServerPoolOptionInst, NULL, NULL, tDHCPv6ServerPoolOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{0}
};

DMLEAF tDHCPv6ServerPoolParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_Enable, set_DHCPv6ServerPool_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_Alias, set_DHCPv6ServerPool_Alias, BBFDM_BOTH},
{"Order", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPool_Order, set_DHCPv6ServerPool_Order, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_Interface, set_DHCPv6ServerPool_Interface, BBFDM_BOTH},
//{"DUID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_DUID, set_DHCPv6ServerPool_DUID, BBFDM_BOTH},
//{"DUIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_DUIDExclude, set_DHCPv6ServerPool_DUIDExclude, BBFDM_BOTH},
{"VendorClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_VendorClassID, set_DHCPv6ServerPool_VendorClassID, BBFDM_BOTH},
//{"VendorClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_VendorClassIDExclude, set_DHCPv6ServerPool_VendorClassIDExclude, BBFDM_BOTH},
{"UserClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_UserClassID, set_DHCPv6ServerPool_UserClassID, BBFDM_BOTH},
//{"UserClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_UserClassIDExclude, set_DHCPv6ServerPool_UserClassIDExclude, BBFDM_BOTH},
{"SourceAddress", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_SourceAddress, set_DHCPv6ServerPool_SourceAddress, BBFDM_BOTH},
{"SourceAddressMask", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_SourceAddressMask, set_DHCPv6ServerPool_SourceAddressMask, BBFDM_BOTH},
//{"SourceAddressExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_SourceAddressExclude, set_DHCPv6ServerPool_SourceAddressExclude, BBFDM_BOTH},
//{"IANAEnable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_IANAEnable, set_DHCPv6ServerPool_IANAEnable, BBFDM_BOTH},
//{"IANAManualPrefixes", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_IANAManualPrefixes, set_DHCPv6ServerPool_IANAManualPrefixes, BBFDM_BOTH},
//{"IANAPrefixes", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_IANAPrefixes, NULL, BBFDM_BOTH},
//{"IAPDEnable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_IAPDEnable, set_DHCPv6ServerPool_IAPDEnable, BBFDM_BOTH},
//{"IAPDManualPrefixes", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_IAPDManualPrefixes, set_DHCPv6ServerPool_IAPDManualPrefixes, BBFDM_BOTH},
//{"IAPDPrefixes", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_IAPDPrefixes, NULL, BBFDM_BOTH},
//{"IAPDAddLength", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPool_IAPDAddLength, set_DHCPv6ServerPool_IAPDAddLength, BBFDM_BOTH},
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPool_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPool_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}. *** */
DMOBJ tDHCPv6ServerPoolClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientIPv6AddressInst, NULL, NULL, tDHCPv6ServerPoolClientIPv6AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"IPAddress", NULL}},
{"IPv6Prefix", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientIPv6PrefixInst, NULL, NULL, tDHCPv6ServerPoolClientIPv6PrefixParams, NULL, BBFDM_BOTH, LIST_KEY{"Prefix", NULL}},
//{"Option", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientOptionInst, NULL, NULL, tDHCPv6ServerPoolClientOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6ServerPoolClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolClient_Alias, set_DHCPv6ServerPoolClient_Alias, BBFDM_BOTH},
//{"SourceAddress", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClient_SourceAddress, NULL, BBFDM_BOTH},
//{"Active", &DMREAD, DMT_BOOL, get_DHCPv6ServerPoolClient_Active, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_IPv6AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"IPv6PrefixNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_IPv6PrefixNumberOfEntries, NULL, BBFDM_BOTH},
//{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Address.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClientIPv6Address_IPAddress, NULL, BBFDM_BOTH},
{"PreferredLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Address_PreferredLifetime, NULL, BBFDM_BOTH},
{"ValidLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Address_ValidLifetime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Prefix.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientIPv6PrefixParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Prefix", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClientIPv6Prefix_Prefix, NULL, BBFDM_BOTH},
{"PreferredLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Prefix_PreferredLifetime, NULL, BBFDM_BOTH},
{"ValidLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Prefix_ValidLifetime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.Option.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Tag", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClientOption_Tag, NULL, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv6ServerPoolClientOption_Value, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Option.{i}. *** */
DMLEAF tDHCPv6ServerPoolOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPoolOption_Enable, set_DHCPv6ServerPoolOption_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolOption_Alias, set_DHCPv6ServerPoolOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPoolOption_Tag, set_DHCPv6ServerPoolOption_Tag, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPoolOption_Value, set_DHCPv6ServerPoolOption_Value, BBFDM_BOTH},
//{"PassthroughClient", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolOption_PassthroughClient, set_DHCPv6ServerPoolOption_PassthroughClient, BBFDM_BOTH},
{0}
};
