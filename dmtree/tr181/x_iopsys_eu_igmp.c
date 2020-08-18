/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Rahul Thakur <rahul.thakur@iopsys.eu>
 *
 */

#include "dmentry.h"
#include "x_iopsys_eu_igmp.h"

static void get_mcast_iface_key(char *p_ifname, char *key, size_t key_size)
{
	int itf_found = 0;
	struct uci_section *n_sec;
	char *intf_name;

	uci_foreach_sections("network", "interface", n_sec) {
		itf_found = 0;
		dmuci_get_value_by_section_string(n_sec, "ifname", &intf_name);

		intf_name = dmstrdup(intf_name);
		char *pch, *spch;
		pch = strtok_r(intf_name, " ", &spch);
		while (pch != NULL) {
			if (strcmp(pch, p_ifname) == 0) {
				strncpy(key, section_name(n_sec), key_size - 1);
				itf_found = 1;
				break;
			}
			pch = strtok_r(NULL, " ", &spch);
		}

		if (itf_found)
			break;
	}
}

static void sync_mcast_dmmap_iface_sec(struct uci_list *proxy_iface, char *s_mode,
                struct uci_section *s, char *dmmap_package, char *dmmap_sec,
                struct list_head *dup_list, char *up_iface)
{
	struct uci_element *e;
	struct uci_section *d_sec;
	int found = 0;
	char key[1024] = "";
	char *s_name;
	char *v;

	uci_foreach_element(proxy_iface, e) {
		char *p_ifname = dmstrdup(e->name);
		if (strstr(p_ifname, "br-") != NULL)
			strncpy(key, p_ifname, sizeof(key) - 1);
		else
			get_mcast_iface_key(p_ifname, key, sizeof(key));

		// Now that we have the key which is the ifname, verify if interface
		// section for this already exists in dmmap_mcast file. In case yes,
		// add this to the dup_list, else create entry in the dmmap_mcast
		// file corresponding to this interface
		uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "ifname", key, d_sec) {
			dmuci_get_value_by_section_string(d_sec, "section_name", &s_name);
			if (strcmp(s_name, section_name(s)) == 0) {
				add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
				found = 1;
				break;
			}
		}

		if (found == 0) {
			// add entry in dmmap for this
			dmuci_add_section_bbfdm(dmmap_package, dmmap_sec, &d_sec, &v);
			dmuci_set_value_by_section_bbfdm(d_sec, "section_name", section_name(s));
			dmuci_set_value_by_section_bbfdm(d_sec, "ifname", key);
			dmuci_set_value_by_section_bbfdm(d_sec, "upstream", up_iface);
			dmuci_set_value_by_section_bbfdm(d_sec, "snooping_mode", s_mode);
			add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
		}
	}
}

static void add_empty_mcast_iface_to_list(char *dmmap_package, char *dmmap_sec,
                struct uci_section *s, struct list_head *dup_list)
{
	struct uci_section *dmmap_sect;
	char *f_ifname;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "section_name", section_name(s), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "ifname", &f_ifname);

		if (strcmp(f_ifname, "") == 0)
			add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_mcast_iface(char *package, char *section_type,
		void *data, char *dmmap_package, char *dmmap_sec, char *proto,
		struct list_head *dup_list)
{
	struct uci_section *s, *stmp;
	char *v;

	dmmap_file_path_get(dmmap_package);
	uci_foreach_option_eq(package, section_type, "proto", proto, s) {
		if (strcmp(section_name(s), section_name((struct uci_section *)data)) != 0)
			continue;

		// The list snooping_interface and proxy_interface in the uci file corresponds to the
		// proxy_interface section in the dmmap. First, read the list of proxy interfaces
		// and update the dmmap section accordingly. The do the same exercise for the list
		// snooping_interface
		struct uci_list *proxy_iface = NULL;

		dmuci_get_value_by_section_list(s, "upstream_interface", &proxy_iface);
		if (proxy_iface != NULL)
			sync_mcast_dmmap_iface_sec(proxy_iface, "0", s, dmmap_package, dmmap_sec, dup_list, "1");

		struct uci_list *snooping_iface = NULL;
		char *s_mode;
		dmuci_get_value_by_section_list(s, "downstream_interface", &snooping_iface);
		dmuci_get_value_by_section_string(s, "snooping_mode", &s_mode);
		if (snooping_iface != NULL)
			sync_mcast_dmmap_iface_sec(snooping_iface, s_mode, s, dmmap_package, dmmap_sec, dup_list, "0");

		// There can be entries in the dmmap_mcast file that do not have an ifname set.
		// For such entries, now add to dup_list
		add_empty_mcast_iface_to_list(dmmap_package, dmmap_sec, s, dup_list);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_sec, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

void synchronize_specific_config_sections_with_dmmap_mcast_filter(char *package, char *section_type,
		void *data, char *dmmap_package, char *dmmap_sec, char *proto,
		struct list_head *dup_list)
{
	struct uci_section *s, *dmmap_sect, *d_sec, *stmp;
	char *v, *s_name;

	dmmap_file_path_get(dmmap_package);
	uci_foreach_option_eq(package, section_type, "proto", proto, s) {
		if (strcmp(section_name(s), section_name((struct uci_section *)data)) != 0)
			continue;
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		struct uci_list *l = NULL;

		dmuci_get_value_by_section_list(s, "filter", &l);
		if (l != NULL) {
			struct uci_element *e;
			uci_foreach_element(l, e) {
				char *ip_addr = dmstrdup(e->name);
				int found = 0;
				uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "ipaddr", ip_addr, d_sec) {
					dmuci_get_value_by_section_string(d_sec, "section_name", &s_name);
					if (strcmp(s_name, section_name(s)) == 0) {
						add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
						found = 1;
						break;
					}
				}

				if (found == 0) {
					// add entry in dmmap for this
					dmuci_add_section_bbfdm(dmmap_package, dmmap_sec, &d_sec, &v);
					dmuci_set_value_by_section_bbfdm(d_sec, "section_name", section_name(s));
					dmuci_set_value_by_section_bbfdm(d_sec, "ipaddr", ip_addr);
					dmuci_set_value_by_section_bbfdm(d_sec, "enable", "1");
					add_sectons_list_paramameter(dup_list, s, d_sec, NULL);
				}
			}
		}

		char *f_ip, *f_enable;
		// There can be entries in the dmmap_mcast file that do not have an IP address set.
		// For such entries, now add to dup_list
		uci_path_foreach_option_eq(bbfdm, dmmap_package, dmmap_sec, "section_name", section_name(s), dmmap_sect) {
			dmuci_get_value_by_section_string(dmmap_sect, "ipaddr", &f_ip);
			dmuci_get_value_by_section_string(dmmap_sect, "enable", &f_enable);

			if ((f_ip[0] == '\0') || (strcmp(f_enable, "0") == 0))
				add_sectons_list_paramameter(dup_list, s, dmmap_sect, NULL);
		}
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_sec, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
	}
}

static int get_br_key_from_lower_layer(char *lower_layer, char *key, size_t s_key)
{
	char *p = strstr(lower_layer, "Port");

	if (!p)
		return -1;

	/* Get the bridge_key. */
	int len = strlen(p);
	char new_if[250] = {0};
	int i;
	for (i = 0; i < strlen(lower_layer) - len; i++) {
		new_if[i] = lower_layer[i];
	}

	char br_key = new_if[strlen(new_if) - 2];

	snprintf(key, s_key, "%c", br_key);

	return 0;
}

int get_mcast_snooping_interface_val(char *value, char *ifname, size_t s_ifname)
{
	char lower_layer[250] = {0};

	if (value[strlen(value)-1] != '.')
		snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
	else
		strncpy(lower_layer, value, sizeof(lower_layer) - 1);

	/* Check if the value is valid or not. */
	if (strncmp(lower_layer, "Device.Bridging.Bridge.", 23) != 0)
		return -1;

	char key[10] = {0};
	if (get_br_key_from_lower_layer(lower_layer, key, sizeof(key)) != 0)
		return -1;

	/* Find out bridge section name using bridge key. */
	struct uci_section *s = NULL;
	char *sec_name;
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "bridge_instance", key, s) {
		dmuci_get_value_by_section_string(s, "section_name", &sec_name);
		break;
	}

	// Check if network uci file has this section, if yes, then
	// update the snooping interface with value as br-<section name>
	struct uci_section *intf_s = NULL;
	uci_foreach_sections("network", "interface", intf_s) {
		char  sec[20] = {0};
		strncpy(sec, section_name(intf_s), sizeof(sec) - 1);
		if (strncmp(sec, sec_name, sizeof(sec)) != 0)
			continue;

		char *type;
		dmuci_get_value_by_section_string(intf_s, "type", &type);
		if (*type == '\0' || strcmp(type, "bridge") != 0)
			continue;

		snprintf(ifname, s_ifname, "br-%s", sec_name);
		break;
	}

	return 0;
}

static int add_igmp_proxy_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v, *s_name;
	struct uci_section  *dmmap = NULL, *s = NULL;
	char i_no[16];

	check_create_dmmap_package("dmmap_mcast");
	inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "proxy", "proxy_instance",
						"proto", "igmp");
	snprintf(i_no, sizeof(i_no), "%d", inst ? atoi(inst)+1 : 1);

	dmasprintf(&s_name, "igmp_proxy_%s", i_no);

	dmuci_add_section("mcast", "proxy", &s, &value);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "proto", "igmp");
	dmuci_set_value_by_section(s, "version", "2");
	dmuci_set_value_by_section(s, "robustness", "2");
	dmuci_set_value_by_section(s, "aggregation", "0");

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "proto", "igmp");
	*instance = update_instance_bbfdm(dmmap, inst, "proxy_instance");

	return 0;
}

static int del_igmp_proxy_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		// first delete all filter child nodes related to this object
		del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_filter",
			"section_name", section_name((struct uci_section *)data));
		// Now delete all interface child nodes related to this object
		del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data));

		// Now delete the proxy node
		get_dmmap_section_of_config_section("dmmap_mcast", "proxy", section_name((struct uci_section *)data), &dmmap_section);

		if (dmmap_section != NULL)
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

		dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_option_eq("mcast", "proxy", "proto", "igmp", s) {
			if (found != 0) {
				get_dmmap_section_of_config_section("dmmap_mcast", "proxy", section_name(s), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL) {
			get_dmmap_section_of_config_section("dmmap_mcast", "proxy", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
		}

		break;
	}
	return 0;
}

static int browse_igmp_proxy_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("mcast", "proxy", "dmmap_mcast", "proto", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "proxy_instance", "proxy_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_igmp_snooping_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v, *s_name;
	struct uci_section  *dmmap = NULL, *s = NULL;
	char i_no[16];

	check_create_dmmap_package("dmmap_mcast");
	inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "snooping",
					"snooping_instance", "proto", "igmp");
	snprintf(i_no, sizeof(i_no), "%d", inst ? atoi(inst)+1 : 1);

	dmasprintf(&s_name, "igmp_snoop_%s", i_no);

	dmuci_add_section("mcast", "snooping", &s, &value);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "proto", "igmp");
	dmuci_set_value_by_section(s, "version", "2");
	dmuci_set_value_by_section(s, "robustness", "2");
	dmuci_set_value_by_section(s, "aggregation", "0");

	dmuci_add_section_bbfdm("dmmap_mcast", "snooping", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "proto", "igmp");
	*instance = update_instance_bbfdm(dmmap, inst, "snooping_instance");

	return 0;
}

static int del_igmp_snooping_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		// first delete all filter child nodes related to this object
		del_dmmap_sec_with_opt_eq("dmmap_mcast", "snooping_filter",
			"section_name", section_name((struct uci_section *)data));
		// Now delete all interface child nodes related to this object
		del_dmmap_sec_with_opt_eq("dmmap_mcast", "snooping_interface",
			"section_name", section_name((struct uci_section *)data));
		get_dmmap_section_of_config_section("dmmap_mcast", "snooping", section_name((struct uci_section *)data), &dmmap_section);

		if (dmmap_section != NULL)
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

		dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_option_eq("mcast", "snooping", "proto", "igmp", s) {
			if (found != 0) {
				get_dmmap_section_of_config_section("dmmap_mcast", "snooping", section_name(s), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL) {
			get_dmmap_section_of_config_section("dmmap_mcast", "snooping", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
		}

		break;
	}
	return 0;
}

static int browse_igmp_snooping_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("mcast", "snooping", "dmmap_mcast", "proto", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "snooping_instance", "snooping_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int get_igmps_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("mcast", "snooping", "proto", "igmp", s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_igmpp_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("mcast", "proxy", "proto", "igmp", s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int browse_igmp_cgrp_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//perform ubus call to mcast stats and browse through each igmp group json object
	int i = 0, id = 0;
	json_object *res = NULL, *jobj = NULL, *arrobj = NULL, *group_obj = NULL;
	char *idx, *idx_last = NULL;

	dmubus_call("mcast", "stats", UBUS_ARGS{}, 0, &res);
	if (res) {
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "snooping");
		dmjson_foreach_obj_in_array(jobj, arrobj, group_obj, i, 1, "groups") {
			idx = handle_update_instance(1, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)group_obj, idx) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int add_igmps_filter_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *last_inst, *v;
	struct uci_section *dmmap_igmps_filter = NULL;

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "snooping_filter", "filter_instance",
					"section_name", section_name((struct uci_section *)data));

	dmuci_add_section_bbfdm("dmmap_mcast", "snooping_filter", &dmmap_igmps_filter, &v);
	dmuci_set_value_by_section(dmmap_igmps_filter, "section_name", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_igmps_filter, "enable", "0");
	*instance = update_instance_bbfdm(dmmap_igmps_filter, last_inst, "filter_instance");

	return 0;
}

int del_mcasts_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *d_sec = NULL;
	char *f_inst, *ip_addr;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);

			if (strcmp(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
				dmuci_delete_by_section(d_sec, NULL, NULL);
				found = 1;
			}

			if (found) {
				dmuci_del_list_value_by_section((struct uci_section *)data, "filter", ip_addr);
				break;
			}
		}

		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
			if (ip_addr[0] != '\0') {
				dmuci_del_list_value_by_section((struct uci_section *)data,
						"filter", ip_addr);
			}
		}

		del_dmmap_sec_with_opt_eq("dmmap_mcast", "snooping_filter",
			"section_name", section_name((struct uci_section *)data));
		break;
	}

	return 0;
}

static int browse_igmps_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *inst_last = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_mcast_filter("mcast", "snooping", prev_data, "dmmap_mcast",
			"snooping_filter", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (!p->config_section)
			break;

		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3,
				p->dmmap_section, "filter_instance", "filter_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int get_mcasts_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter", "section_name",
				section_name((struct uci_section *)data), s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_igmp_cgrps_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i = 0, cnt = 0;
	json_object *res = NULL, *jobj = NULL, *arrobj = NULL, *group_obj = NULL;

	dmubus_call("mcast", "stats", UBUS_ARGS{}, 0, &res);
	if (res) {
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "snooping");
		dmjson_foreach_obj_in_array(jobj, arrobj, group_obj, i, 1, "groups") {
			cnt++;
		}
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_mcasts_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *f_sec;
	char *f_inst, *f_enable;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
			"section_name", section_name((struct uci_section *)data), f_sec) {
		dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(f_sec, "enable", &f_enable);
			break;
		}
	}

	if (strcmp(f_enable, "1") == 0) {
		*value = "true";
	} else {
		*value = "false";
	}

	return 0;
}

int set_mcasts_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *f_sec;
	char *f_inst, *ip_addr;
	bool b;
	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
				"section_name", section_name((struct uci_section *)data), f_sec) {
			dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
			if (strcmp(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(f_sec, "ipaddr", &ip_addr);
				dmuci_set_value_by_section(f_sec, "enable", (b) ? "1" : "0");
				if (ip_addr[0] != '\0') {
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"filter", ip_addr, b);
				}
				break;
			}
		}
		break;
	}

	return 0;
}

int get_mcasts_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *ip_addr;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
			break;
		}
	}

	if (ip_addr[0] == '\0') {
		*value = "";
	} else {
		*value = dmstrdup(ip_addr);
	}

	return 0;
}

int set_mcasts_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *s_inst, *up;
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
			return FAULT_9007;

		break;
	case VALUESET:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
				"section_name", section_name((struct uci_section *)data), s) {
			dmuci_get_value_by_section_string(s, "filter_instance", &s_inst);
			if (strcmp(s_inst, instance) == 0) {
				dmuci_set_value_by_section(s, "ipaddr", value);
				dmuci_get_value_by_section_string(s, "enable", &up);
				string_to_bool(up, &b);
				sync_dmmap_bool_to_uci_list((struct uci_section *)data,
						"filter", value, b);
				break;
			}
		}

		break;
	}

	return 0;
}

int get_mcast_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

int set_mcast_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "enable", (b) ? "1" : "0");
		break;
	}

	return 0;
}

static int get_igmp_snooping_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", &val);
	*value = (strcmp(val, "2") == 0) ? "V2" : "V3";
	return 0;
}

static int set_igmp_snooping_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if ((strcmp("V2", value) != 0) && (strcmp("V3", value) != 0))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "version", (strcmp(value, "V2") == 0) ? "2" : "3");
		break;
	}

	return 0;
}

int get_mcast_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "snooping_mode", &val);

	if (strcmp(val, "1") == 0)
		*value = "Standard";
	else if (strcmp(val, "2") == 0)
		*value = "Blocking";
	else
		*value = "Disabled";

	return 0;
}

int set_mcast_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char val[4];

	switch (action) {
	case VALUECHECK:
		if ((strcmp("Standard", value) != 0)
			&& (strcmp("Blocking", value) != 0)
			&& (strcmp("Disabled", value) != 0))
			return FAULT_9007;
		break;
	case VALUESET:
		if (strcmp(value, "Standard") == 0)
			strcpy(val, "1");
		else if (strcmp(value, "Blocking") == 0)
			strcpy(val, "2");
		else
			strcpy(val, "0");

		dmuci_set_value_by_section((struct uci_section *)data, "snooping_mode", val);
		break;
	}

	return 0;
}

int get_mcast_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "robustness", value);
	return 0;
}

int set_mcast_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "robustness", value);
		break;
	}

	return 0;
}

int get_mcast_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "aggregation", &val);
	*value = (strcmp(val, "1") == 0) ? "true" : "false";
	return 0;
}

int set_mcast_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "aggregation", (b) ? "1" : "0");
		break;
	}

	return 0;
}

int get_mcast_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char val[16] = {0}, sec_name[16] = {0}; // taking 16 here is same as that is size of linux names usually supported
	char *val1;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &val1);

	// The value is linux interface name so it would be br-wan for example, but the network
	// section would be wan, so extract wan from br-wan
	char *tok, *end;

	strncpy(val, val1, sizeof(val) - 1);
	tok = strtok_r(val, "-", &end);
	if ((tok == NULL) || (end == NULL)) {
		return 0;
	}

	if (strcmp(tok, "br") != 0) {
		return 0;
	}

	strncpy(sec_name, end, sizeof(sec_name) - 1);
	// In the dmmap_network file, the details related to the instance id etc. associated with this bridge
	// is stored, we now switch our focus to it to extract the necessary information.
	struct uci_section *dmmap_section, *port;

	get_dmmap_section_of_config_section("dmmap_network", "interface", sec_name, &dmmap_section);
	if (dmmap_section != NULL) {
		char *br_inst, *mg;
		dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port) {
			dmuci_get_value_by_section_string(port, "management", &mg);
			if (strcmp(mg, "1") == 0) {
				char *device, linker[512] = "";
				dmuci_get_value_by_section_string(port, "device", &device);
				snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, section_name(port), device);
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot,
							dm_delim, dm_delim, dm_delim), linker, value);
				break;
			}
		}
	}

	if (*value == NULL)
		*value = "";

	return 0;
}

int set_mcast_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char ifname[16];

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		if (get_mcast_snooping_interface_val(value, ifname, sizeof(ifname)) != 0)
			return -1;

		dmuci_set_value_by_section((struct uci_section *)data, "interface", ifname);
		break;
	}

	return 0;
}

static int add_igmpp_interface_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	// This section works but commented for now as it is tested not much yet.
	char *last_inst, *v;
	struct uci_section *dmmap_igmpp_interface = NULL;

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "proxy_interface", "iface_instance",
					"section_name", section_name((struct uci_section *)data));

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy_interface", &dmmap_igmpp_interface, &v);
	dmuci_set_value_by_section(dmmap_igmpp_interface, "section_name",
				section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_igmpp_interface, "upstream", "0");
	dmuci_set_value_by_section(dmmap_igmpp_interface, "snooping_mode", "0");

	*instance = update_instance_bbfdm(dmmap_igmpp_interface, last_inst, "iface_instance");
	return 0;
}

static void get_igmpp_iface_del_key_val(char *key, size_t key_size, char *if_name)
{
	struct uci_section *s;
	char *ifval;
	if (strstr(if_name, "br-") != NULL) {
		strncpy(key, if_name, key_size - 1);
	} else {
		uci_foreach_sections("network", "interface", s) {
			if(strcmp(section_name(s), if_name) == 0) {
				dmuci_get_value_by_section_string(s, "ifname", &ifval);
				strncpy(key, ifval, key_size - 1);
				break;
			}
		}
	}
}
static void del_igmpp_iface_val(char *upstream, void *data, char *pch)
{
	if (strcmp(upstream, "1") == 0) {
		dmuci_del_list_value_by_section((struct uci_section *)data,
				"upstream_interface", pch);
	} else {
		dmuci_del_list_value_by_section((struct uci_section *)data,
				"downstream_interface", pch);
	}
}

static int del_igmpp_interface_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *d_sec = NULL;
	char *f_inst, *if_name, *upstream;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);

			if (strcmp(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(d_sec, "ifname", &if_name);
				dmuci_get_value_by_section_string(d_sec, "upstream", &upstream);
				dmuci_delete_by_section(d_sec, NULL, NULL);
				found = 1;
			} else {
				continue;
			}

			if (found) {
				char key[1024];
				get_igmpp_iface_del_key_val(key, sizeof(key), if_name);

				char *pch, *spch;
				pch = strtok_r(key, " ", &spch);
				while (pch != NULL) {
					del_igmpp_iface_val(upstream, data, pch);
					pch = strtok_r(NULL, " ", &spch);
				}
				del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_interface",
						"ifname", if_name);
				break;
			}
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "ifname", &if_name);
			dmuci_get_value_by_section_string(d_sec, "upstream", &upstream);
			if (if_name[0] != '\0') {
				char key[1024];
				get_igmpp_iface_del_key_val(key, sizeof(key), if_name);

				char *pch, *spch;
				pch = strtok_r(key, " ", &spch);
				while (pch != NULL) {
					del_igmpp_iface_val(upstream, data, pch);
					pch = strtok_r(NULL, " ", &spch);
				}
			}
		}

		del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data));
		break;
	}

	return 0;
}

static int browse_igmpp_interface_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *inst_last = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_mcast_iface("mcast", "proxy", prev_data,
			"dmmap_mcast", "proxy_interface", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (!p->config_section)
			break;

		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3,
				p->dmmap_section, "iface_instance", "iface_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;

	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_igmpp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *last_inst, *v;
	struct uci_section *dmmap_igmpp_filter = NULL;

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "proxy_filter", "filter_instance",
			"section_name", section_name((struct uci_section *)data));

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy_filter", &dmmap_igmpp_filter, &v);
	dmuci_set_value_by_section(dmmap_igmpp_filter, "section_name",
			section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_igmpp_filter, "enable", "0");

	*instance = update_instance_bbfdm(dmmap_igmpp_filter, last_inst, "filter_instance");

	return 0;
}

int del_mcastp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *d_sec = NULL;
	char *f_inst, *ip_addr;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);

			if (strcmp(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
				dmuci_delete_by_section(d_sec, NULL, NULL);
				found = 1;
			}

			if (found) {
				dmuci_del_list_value_by_section((struct uci_section *)data,
						"filter", ip_addr);
				break;
			}
		}

		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
			if (ip_addr[0] != '\0')
				dmuci_del_list_value_by_section((struct uci_section *)data,
						"filter", ip_addr);
		}

		del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_filter", "section_name",
				section_name((struct uci_section *)data));

		break;
	}

	return 0;
}

static int browse_igmpp_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *inst_last = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_mcast_filter("mcast", "proxy", prev_data, "dmmap_mcast",
			"proxy_filter", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (!p->config_section)
			break;

		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3,
				p->dmmap_section, "filter_instance", "filter_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;

	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int get_mcastp_interface_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface", "section_name",
			section_name((struct uci_section *)data), s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_mcastp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *f_sec;
	char *f_inst, *f_enable;
	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
			"section_name", section_name((struct uci_section *)data), f_sec) {
		dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(f_sec, "enable", &f_enable);
			break;
		}
	}

	if (strcmp(f_enable, "1") == 0) {
		*value = "true";
	} else {
		*value = "false";
	}

	return 0;
}

int set_mcastp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *f_sec;
	char *f_inst, *ip_addr;
	bool b;
	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
				"section_name", section_name((struct uci_section *)data), f_sec) {
			dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
			if (strcmp(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(f_sec, "ipaddr", &ip_addr);
				dmuci_set_value_by_section(f_sec, "enable", (b) ? "1" : "0");
				sync_dmmap_bool_to_uci_list((struct uci_section *)data,
						"filter", ip_addr, b);
				break;
			}
		}
		break;
	}

	return 0;
}

int get_mcastp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *ip_addr;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
			break;
		}
	}

	if (ip_addr[0] == '\0') {
		*value = "";
	} else {
		*value = dmstrdup(ip_addr);
	}

	return 0;
}

static int set_igmpp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *s_inst, *up;
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
			return FAULT_9007;

		break;
	case VALUESET:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
				"section_name", section_name((struct uci_section *)data), s) {
			dmuci_get_value_by_section_string(s, "filter_instance", &s_inst);
			if (strcmp(s_inst, instance) == 0) {
				dmuci_set_value_by_section(s, "ipaddr", value);
				dmuci_get_value_by_section_string(s, "enable", &up);
				string_to_bool(up, &b);
				sync_dmmap_bool_to_uci_list((struct uci_section *)data,
						"filter", value, b);
				break;
			}
		}
		break;
	}

	return 0;
}

static int browse_igmp_cgrp_assoc_dev_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//parse and browse through prev_data(it will be json object containing group address and details of its clients)

	int i = 0, id = 0;
	json_object *arrobj = NULL, *client_jobj = NULL;
	char *idx, *idx_last = NULL;

	dmjson_foreach_obj_in_array((struct json_object *)prev_data, arrobj, client_jobj, i, 1, "clients") {
		idx = handle_update_instance(1, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)client_jobj, idx) == DM_STOP)
				break;
	}
	return 0;
}

#if 0
static int browse_igmps_cgrp_stats_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_igmpp_cgrp_stats_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}
#endif

static int get_igmp_cgrp_gaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "groupaddr");
	return 0;
}

static int get_igmp_cgrp_assoc_dev_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i = 0, cnt = 0;
	json_object *arrobj = NULL, *client_obj = NULL;

	dmjson_foreach_obj_in_array((json_object *)data, arrobj, client_obj, i, 1, "clients") {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_igmp_cgrp_adev_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname = dmjson_get_value((json_object *)data, 1, "device");

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_igmp_cgrp_adev_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipaddr = dmjson_get_value((json_object *)data, 1, "ipaddr");

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cHosts%cHost%c", dmroot, dm_delim, dm_delim, dm_delim), ipaddr, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_igmp_cgrp_adev_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "timeout");
	return 0;
}

#if 0
static int get_igmps_cgrp_stats_rsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_rsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_rrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_rrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_qsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_qsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_qrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_qrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_lsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_lsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_lrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_lrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}
#endif

int get_mcast_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &val);
	*value = (strcmp(val, "1") == 0) ? "true" : "false";
	return 0;
}
int set_mcast_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "enable", (b) ? "1" : "0");
		break;
	}

	return 0;
}

static int get_igmp_proxy_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", &val);
	*value = (strcmp(val, "2") == 0) ? "V2" : "V3";
	return 0;
}

static int set_igmp_proxy_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if ((strcmp("V2", value) != 0) && (strcmp("V3", value) != 0))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "version", (strcmp(value, "V2") == 0) ? "2" : "3");
		break;
	}

	return 0;
}

int get_mcast_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "robustness", value);
	return 0;
}

int get_mcastp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "query_interval", value);
	return 0;
}

int get_mcastp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "query_response_interval", value);
	return 0;
}

int get_mcastp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "last_member_query_interval", value);
	return 0;
}

int set_mcastp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "query_interval", value);
		break;
	}

	return 0;
}

int set_mcastp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "query_response_interval", value);
		break;
	}

	return 0;
}

int set_mcastp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "last_member_query_interval", value);
		break;
	}

	return 0;
}

int set_mcast_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "robustness", value);
		break;
	}

	return 0;
}

int get_mcast_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "aggregation", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

int get_mcast_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "fast_leave", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

int set_mcast_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "fast_leave", (b) ? "1" : "0");
		break;
	}

	return 0;
}

int set_mcast_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "aggregation", (b) ? "1" : "0");
		break;
	}

	return 0;
}

int get_mcastp_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter", "section_name",
			section_name((struct uci_section *)data), s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

void update_snooping_mode(struct uci_section *s)
{
	// Update snooping mode as per downstream interface
	struct uci_list *v = NULL;
	struct uci_element *e;
	struct uci_section *itf_sec;
	char *val, *s_mode, *up;
	bool b;

	dmuci_get_value_by_section_list(s, "downstream_interface", &v);
	if (v != NULL) {
		uci_foreach_element(v, e) {
			val = dmstrdup(e->name);
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
					"ifname", val, itf_sec) {
				dmuci_get_value_by_section_string(itf_sec, "upstream", &up);
				string_to_bool(up, &b);
				if (b)
					continue;

				dmuci_get_value_by_section_string(itf_sec, "snooping_mode", &s_mode);
				dmuci_set_value_by_section(s, "snooping_mode", s_mode);
				break;
			}

			// Further action is not required
			break;
		}
	} else {
		dmuci_set_value_by_section(s, "snooping_mode", "0");
	}
	return;
}

static void sync_proxy_interface_sections(struct uci_section *s, char *section,
                                char *value, bool up_iface)
{
        struct uci_list *v = NULL;
        struct uci_element *e;
        char *val;

	dmuci_get_value_by_section_list(s, section, &v);
	// value here is a list of space separated names of interface so,
	// the first task is to tokenise this and then for each interface,
	// update the downstream or upstream interface list.
	value = dmstrdup(value);

	char *pch = NULL, *spch = NULL;
	pch = strtok_r(value, " ", &spch);
	while (pch != NULL) {
		int found = 0; // use to avoid duplicate entries

		if (v != NULL) {
			// For each pch value check if entry already exists
			// in the qos uci file in the downstream or upstream list
			uci_foreach_element(v, e) {
				val = dmstrdup(e->name);
				if (strcmp(val, pch) == 0) {
					found = 1;
					if (!up_iface) {
						// if entry is found and upstream was set to
						// false, then, remove this entry
						dmuci_del_list_value_by_section(s, section, val);
					}

					// Further action is not required
					break;
				}
			}

			// if entry was not found and b is true create entry. Check for
			// found in needed otherwise, duplicate entry maybe created
			if (up_iface && !found) {
				dmuci_add_list_value_by_section(s, section, pch);
			}
		} else {
			// The list of downstream or upstream interfaces in uci file is
			// empty, so just add entries if needed
			if (up_iface) {
				dmuci_add_list_value_by_section(s, section, pch);
			}
		}

		pch = strtok_r(NULL, " ", &spch);
	}
}

static void set_igmpp_iface_val(void *data, char *instance, char *linker, char *interface_linker, bool is_br)
{
	struct uci_section *d_sec;
	char *up, *f_inst;
	bool b;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			if (is_br)
				dmuci_set_value_by_section(d_sec, "ifname", interface_linker);
			else
				dmuci_set_value_by_section(d_sec, "ifname", linker);

			dmuci_get_value_by_section_string(d_sec, "upstream", &up);
			string_to_bool(up, &b);
			sync_proxy_interface_sections((struct uci_section *)data,
					"downstream_interface", interface_linker, !b);

			// Now update the proxy_interface list
			sync_proxy_interface_sections((struct uci_section *)data,
					"upstream_interface", interface_linker, b);
			update_snooping_mode((struct uci_section *)data);
			break;
		}
	}
}

static int set_igmpp_interface_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker, *interface_linker = NULL;
	char ifname[16];
	char *if_type;
	struct uci_section *s;
	bool is_br = false;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		// First check if this is a bridge type interface
		if (get_mcast_snooping_interface_val(value, ifname, sizeof(ifname)) == 0) {
			interface_linker = dmstrdup(ifname);
			is_br = true;
		} else {
			adm_entry_get_linker_value(ctx, value, &linker);
			uci_foreach_sections("network", "interface", s) {
				if(strcmp(section_name(s), linker) != 0) {
					continue;
				}

				dmuci_get_value_by_section_string(s, "type", &if_type);
				if (strcmp(if_type, "bridge") == 0) {
					dmasprintf(&interface_linker, "br-%s", linker);
					is_br = true;
				} else {
					dmuci_get_value_by_section_string(s, "ifname", &interface_linker);
				}
				break;
			}
		}

		set_igmpp_iface_val(data, instance, linker, interface_linker, is_br);
		break;
	}

	return 0;
}

static int get_igmpp_interface_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec, *s;
	char *ifname, *f_inst;
	char sec_name[16] = {0};
	int found = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "ifname", &ifname);
			found = 1;
			break;
		}
	}

	if ((found == 0) || (ifname[0] == '\0')) {
		*value = "";
		return 0;
	}

	// Check if this is bridge type interface
	if (strstr(ifname, "br-")) {
		// Interface is bridge type, convert to network uci file section name
		char val[16] = {0};
		strncpy(val, ifname, sizeof(val) - 1);
		char *tok, *end;
		tok = strtok_r(val, "-", &end);
		if (strcmp(tok, "br") == 0) {
			strncpy(sec_name, end, sizeof(sec_name) - 1);
		} else {
			goto end;
		}

		char *proto;
		uci_foreach_sections("network", "interface", s) {
			if(strcmp(section_name(s), sec_name) != 0)
				continue;

			dmuci_get_value_by_section_string(s, "proto", &proto);
			if (proto[0] != '\0') {
				// It is a L3 bridge, get the linker accordingly
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c",
					dmroot, dm_delim, dm_delim, dm_delim), sec_name, value);
			} else {
				// It is a L2 bridge, get the linker accordingly
				struct uci_section *dmmap_section, *port;
				char *br_inst, *mg, linker[64] = "";

				get_dmmap_section_of_config_section("dmmap_network", "interface", sec_name,
						&dmmap_section);
				if (dmmap_section != NULL) {
					dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port",
							"bridge_port", "bridge_key", br_inst, port) {
						dmuci_get_value_by_section_string(port, "mg_port", &mg);
						if (strcmp(mg, "true") == 0)
							snprintf(linker, sizeof(linker), "%s+", section_name(port));
						else
							continue;

						adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot,
									dm_delim, dm_delim, dm_delim), linker, value);
						break;
					}
				}
			}
			break;
		}
	} else {
		// in case its a L3 interface, the ifname would be section name of network file in the dmmap file,
		// which infact is the linker, just use that directly.
		if (ifname == NULL)
			goto end;

		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim,
					dm_delim, dm_delim), ifname, value);
	}

end:
	if (*value == NULL)
		*value = "";

	return 0;
}

static int set_igmpp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *f_inst, *ifname;
	struct uci_section *d_sec, *s;
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
			if (strcmp(instance, f_inst) == 0) {
				// The interface is a part of downstream or upstream list in the
				// uci file based on the value of upstream parameter, hence, when
				// this parameter is updated, need arises to update the lists as well.
				// Reading the interface name to be updated associated with the
				// instance for which upstream parameter is being updated is hence
				// needed. This value is read into variable key.
				char key[1024];
				char *ifval;
				dmuci_get_value_by_section_string(d_sec, "ifname", &ifname);
				if (strstr(ifname, "br-") != NULL) {
					strncpy(key, ifname, sizeof(key) - 1);
				} else {
					uci_foreach_sections("network", "interface", s) {
						if(strcmp(section_name(s), ifname) == 0) {
							dmuci_get_value_by_section_string(s, "ifname", &ifval);
							strncpy(key, ifval, sizeof(key) - 1);
							break;
						}
					}
				}

				dmuci_set_value_by_section(d_sec, "upstream", (b) ? "1" : "0");
				sync_proxy_interface_sections((struct uci_section *)data, "downstream_interface", key, !b);
				sync_proxy_interface_sections((struct uci_section *)data, "upstream_interface", key, b);
				update_snooping_mode((struct uci_section *)data);

				break;
			}
		}

		break;
	}

	return 0;
}

int get_mcastp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *up;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "upstream", &up);
			break;
		}
	}

	*value = (strcmp(up, "1") == 0) ? "true" : "false";
	return 0;
}

int get_mcastp_iface_snoop_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *val;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "snooping_mode", &val);
			break;
		}
	}

	if (strcmp(val, "1") == 0)
		*value = "Standard";
	else if (strcmp(val, "2") == 0)
		*value = "Blocking";
	else
		*value = "Disabled";

	return 0;
}

int set_mcastp_iface_snoop_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *f_inst, *up;
	struct uci_section *d_sec;
	char val[4];
	bool b;

	switch (action) {
	case VALUECHECK:
		if ((strcmp("Standard", value) != 0)
			&& (strcmp("Blocking", value) != 0)
			&& (strcmp("Disabled", value) != 0))
			return FAULT_9007;
		break;
	case VALUESET:
		if (strcmp(value, "Standard") == 0)
			strcpy(val, "1");
		else if (strcmp(value, "Blocking") == 0)
			strcpy(val, "2");
		else
			strcpy(val, "0");

		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
			if (strcmp(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(d_sec, "upstream", &up);
				dmuci_set_value_by_section(d_sec, "snooping_mode", val);

				string_to_bool(up, &b);
				if (!b) {
					dmuci_set_value_by_section((struct uci_section *)data, "snooping_mode", val);
				}
				break;
			}
		}
		break;
	}

	return 0;
}

/* ***Device.X_IOPSYS_EU_IGMP. *** */
DMOBJ X_IOPSYS_EU_IGMPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Snooping", &DMWRITE, add_igmp_snooping_obj, del_igmp_snooping_obj, NULL, browse_igmp_snooping_inst, NULL, NULL, NULL, X_IOPSYS_EU_IGMPSnoopingObj, X_IOPSYS_EU_IGMPSnoopingParams, NULL, BBFDM_BOTH},
{"Proxy", &DMWRITE, add_igmp_proxy_obj, del_igmp_proxy_obj, NULL, browse_igmp_proxy_inst, NULL, NULL, NULL, X_IOPSYS_EU_IGMPProxyObj, X_IOPSYS_EU_IGMPProxyParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_IGMPParams[] = {
{"SnoopingNumberOfEntries", &DMREAD, DMT_UNINT, get_igmps_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"ProxyNumberOfEntries", &DMREAD, DMT_UNINT, get_igmpp_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_IGMPSnoopingObj[] = {
{"ClientGroup", &DMREAD, NULL, NULL, NULL, browse_igmp_cgrp_inst, NULL, NULL, NULL, IGMPSnoopingCLientGroupObj, IGMPSnoopingClientGroupParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, add_igmps_filter_obj, del_mcasts_filter_obj, NULL, browse_igmps_filter_inst, NULL, NULL, NULL, NULL, IGMPSnoopingFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ IGMPSnoopingCLientGroupObj[] = {
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_igmp_cgrp_assoc_dev_inst, NULL, NULL, NULL, NULL, IGMPSnoopingClientGroupAssociatedDeviceParams, NULL, BBFDM_BOTH},
//{"ClientGroupStats", &DMREAD, NULL, NULL, NULL, browse_igmps_cgrp_stats_inst, NULL, NULL, NULL, NULL, IGMPSnoopingClientGroupStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingClientGroupParams[] = {
{"GroupAddress", &DMREAD, DMT_STRING, get_igmp_cgrp_gaddr, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_igmp_cgrp_assoc_dev_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingFilterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcasts_filter_enable, set_mcasts_filter_enable, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_mcasts_filter_address, set_mcasts_filter_address, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingClientGroupAssociatedDeviceParams[] = {
{"Interface", &DMREAD, DMT_STRING, get_igmp_cgrp_adev_iface, NULL, NULL, NULL, BBFDM_BOTH},
{"Host", &DMREAD, DMT_STRING, get_igmp_cgrp_adev_host, NULL, NULL, NULL, BBFDM_BOTH},
{"Timeout", &DMREAD, DMT_UNINT, get_igmp_cgrp_adev_timeout, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingClientGroupStatsParams[] = {
//{"ReportsSent", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_rsent, NULL, NULL, NULL, BBFDM_BOTH},
//{"ReportsReceived", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_rrcvd, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueriesSent", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_qsent, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueriesReceived", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_qrcvd, NULL, NULL, NULL, BBFDM_BOTH},
//{"LeavesSent", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_lsent, NULL, NULL, NULL, BBFDM_BOTH},
//{"LeavesReceived", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_lrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_IGMPSnoopingParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcast_snooping_enable, set_mcast_snooping_enable, NULL, NULL, BBFDM_BOTH},
{"Version", &DMWRITE, DMT_STRING, get_igmp_snooping_version, set_igmp_snooping_version, NULL, NULL, BBFDM_BOTH},
{"Robustness", &DMWRITE, DMT_UNINT, get_mcast_snooping_robustness, set_mcast_snooping_robustness, NULL, NULL, BBFDM_BOTH},
{"Aggregation", &DMWRITE, DMT_BOOL, get_mcast_snooping_aggregation, set_mcast_snooping_aggregation, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_mcast_snooping_interface, set_mcast_snooping_interface, NULL, NULL, BBFDM_BOTH},
{"Mode", &DMWRITE, DMT_STRING, get_mcast_snooping_mode, set_mcast_snooping_mode, NULL, NULL, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_mcasts_filter_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"ClientGroupNumberOfEntries", &DMREAD, DMT_UNINT, get_igmp_cgrps_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_IGMPProxyObj[] = {
{"Interface", &DMWRITE, add_igmpp_interface_obj, del_igmpp_interface_obj, NULL, browse_igmpp_interface_inst, NULL, NULL, NULL, NULL, IGMPProxyInterfaceParams, NULL, BBFDM_BOTH},
{"ClientGroup", &DMREAD, NULL, NULL, NULL, browse_igmp_cgrp_inst, NULL, NULL, NULL, IGMPProxyCLientGroupObj, IGMPProxyClientGroupParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, add_igmpp_filter_obj, del_mcastp_filter_obj, NULL, browse_igmpp_filter_inst, NULL, NULL, NULL, NULL, IGMPProxyFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ IGMPProxyCLientGroupObj[] = {
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_igmp_cgrp_assoc_dev_inst, NULL, NULL, NULL, NULL, IGMPProxyClientGroupAssociatedDeviceParams, NULL, BBFDM_BOTH},
//{"ClientGroupStats", &DMREAD, NULL, NULL, NULL, browse_igmpp_cgrp_stats_inst, NULL, NULL, NULL, NULL, IGMPProxyClientGroupStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyClientGroupParams[] = {
{"GroupAddress", &DMREAD, DMT_STRING, get_igmp_cgrp_gaddr, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_igmp_cgrp_assoc_dev_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyFilterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcastp_filter_enable, set_mcastp_filter_enable, NULL, NULL, BBFDM_BOTH},
{"IPPrefix", &DMWRITE, DMT_STRING, get_mcastp_filter_address, set_igmpp_filter_address, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyClientGroupAssociatedDeviceParams[] = {
{"Interface", &DMREAD, DMT_STRING, get_igmp_cgrp_adev_iface, NULL, NULL, NULL, BBFDM_BOTH},
{"Host", &DMREAD, DMT_STRING, get_igmp_cgrp_adev_host, NULL, NULL, NULL, BBFDM_BOTH},
{"Timeout", &DMREAD, DMT_UNINT, get_igmp_cgrp_adev_timeout, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyClientGroupStatsParams[] = {
//{"ReportsSent", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_rsent, NULL, NULL, NULL, BBFDM_BOTH},
//{"ReportsReceived", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_rrcvd, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueriesSent", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_qsent, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueriesReceived", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_qrcvd, NULL, NULL, NULL, BBFDM_BOTH},
//{"LeavesSent", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_lsent, NULL, NULL, NULL, BBFDM_BOTH},
//{"LeavesReceived", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_lrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyInterfaceParams[] = {
{"Interface", &DMWRITE, DMT_STRING, get_igmpp_interface_iface, set_igmpp_interface_iface, NULL, NULL, BBFDM_BOTH},
{"Upstream", &DMWRITE, DMT_BOOL, get_mcastp_interface_upstream, set_igmpp_interface_upstream, NULL, NULL, BBFDM_BOTH},
{"SnoopingMode", &DMWRITE, DMT_STRING, get_mcastp_iface_snoop_mode, set_mcastp_iface_snoop_mode, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_IGMPProxyParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcast_proxy_enable, set_mcast_proxy_enable, NULL, NULL, BBFDM_BOTH},
{"Version", &DMWRITE, DMT_STRING, get_igmp_proxy_version, set_igmp_proxy_version, NULL, NULL, BBFDM_BOTH},
{"QueryInterval",&DMWRITE, DMT_UNINT, get_mcastp_query_interval, set_mcastp_query_interval, NULL, NULL, BBFDM_BOTH},
{"QueryResponseInterval",&DMWRITE, DMT_UNINT, get_mcastp_q_response_interval, set_mcastp_q_response_interval, NULL, NULL, BBFDM_BOTH},
{"LastMemberQueryInterval",&DMWRITE, DMT_UNINT, get_mcastp_last_mq_interval, set_mcastp_last_mq_interval, NULL, NULL, BBFDM_BOTH},
{"ImmediateLeave", &DMWRITE, DMT_BOOL, get_mcast_proxy_fast_leave, set_mcast_proxy_fast_leave, NULL, NULL, BBFDM_BOTH},
{"Robustness", &DMWRITE, DMT_UNINT, get_mcast_proxy_robustness, set_mcast_proxy_robustness, NULL, NULL, BBFDM_BOTH},
{"Aggregation", &DMWRITE, DMT_BOOL, get_mcast_proxy_aggregation, set_mcast_proxy_aggregation, NULL, NULL, BBFDM_BOTH},
{"ClientGroupNumberOfEntries", &DMREAD, DMT_UNINT, get_igmp_cgrps_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_mcastp_filter_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_mcastp_interface_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
