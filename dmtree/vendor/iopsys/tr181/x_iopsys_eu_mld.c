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

#include "x_iopsys_eu_mld.h"
#include "x_iopsys_eu_igmp.h"

static int add_mld_proxy_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;
	char s_name[32];

	snprintf(s_name, sizeof(s_name), "mld_proxy_%s", *instance);

	dmuci_add_section("mcast", "proxy", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "proto", "mld");
	dmuci_set_value_by_section(s, "last_member_query_interval", "10");
        dmuci_set_value_by_section(s, "query_interval", "125");
        dmuci_set_value_by_section(s, "query_response_interval", "100");
	dmuci_set_value_by_section(s, "version", "2");
	dmuci_set_value_by_section(s, "robustness", "2");
	dmuci_set_value_by_section(s, "aggregation", "0");

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", s_name);
	dmuci_set_value_by_section(dmmap, "proto", "mld");
	dmuci_set_value_by_section(dmmap, "proxy_instance", *instance);
	return 0;
}

static int del_mld_proxy_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return del_proxy_obj(data, "mld", del_action);
}

static int browse_mld_proxy_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("mcast", "proxy", "dmmap_mcast", "proto", "mld", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "proxy_instance", "proxy_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_mld_snooping_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section  *dmmap = NULL, *s = NULL;
	char s_name[32];

	snprintf(s_name, sizeof(s_name), "mld_snoop_%s", *instance);

	dmuci_add_section("mcast", "snooping", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "proto", "mld");
	dmuci_set_value_by_section(s, "last_member_query_interval", "10");
	dmuci_set_value_by_section(s, "fast_leave", "1");
	dmuci_set_value_by_section(s, "version", "2");
	dmuci_set_value_by_section(s, "robustness", "2");
	dmuci_set_value_by_section(s, "aggregation", "0");

	dmuci_add_section_bbfdm("dmmap_mcast", "snooping", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", s_name);
	dmuci_set_value_by_section(dmmap, "proto", "mld");
	dmuci_set_value_by_section(dmmap, "snooping_instance", *instance);
	return 0;
}

static int del_mld_snooping_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return del_snooping_obj(data, "mld", del_action);
}

static int browse_mld_snooping_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("mcast", "snooping", "dmmap_mcast", "proto", "mld", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "snooping_instance", "snooping_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int get_mlds_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("mcast", "snooping", "proto", "mld", s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_mldp_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("mcast", "proxy", "proto", "mld", s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

#if 0
static int browse_mlds_cgrp_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_mldp_cgrp_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}
#endif

static int add_mlds_filter_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_mlds_filter = NULL;

	dmuci_add_section_bbfdm("dmmap_mcast", "snooping_filter", &dmmap_mlds_filter);
	dmuci_set_value_by_section(dmmap_mlds_filter, "section_name", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_mlds_filter, "enable", "0");
	dmuci_set_value_by_section(dmmap_mlds_filter, "filter_instance", *instance);
	return 0;
}

static int browse_mlds_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return browse_filter_inst(dmctx, parent_node, prev_data, "snooping", "snooping_filter", "mld");
}

static int get_mld_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", &val);
	*value = (DM_LSTRCMP(val, "1") == 0) ? "V1" : "V2";
	return 0;
}

static int set_mld_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if ((DM_LSTRCMP(value, "V2") != 0) && (DM_LSTRCMP(value, "V1") != 0))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "version", (DM_LSTRCMP(value, "V2") == 0) ? "2" : "1");
		break;
	}

	return 0;
}

static int add_mldp_interface_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_mldp_interface = NULL;

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy_interface", &dmmap_mldp_interface);
	dmuci_set_value_by_section(dmmap_mldp_interface, "section_name", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_mldp_interface, "upstream", "0");
	dmuci_set_value_by_section(dmmap_mldp_interface, "snooping_mode", "0");
	dmuci_set_value_by_section(dmmap_mldp_interface, "iface_instance", *instance);
	return 0;
}

static int del_mldp_interface_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *mldp_s = NULL;

	switch (del_action) {
	case DEL_INST:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface", "section_name", section_name((struct uci_section *)data), mldp_s) {
			char *f_inst = NULL, *if_name = NULL, *upstream = NULL;
			int found = 0;

			dmuci_get_value_by_section_string(mldp_s, "iface_instance", &f_inst);

			if (f_inst && DM_STRCMP(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(mldp_s, "ifname", &if_name);
				dmuci_get_value_by_section_string(mldp_s, "upstream", &upstream);
				dmuci_delete_by_section(mldp_s, NULL, NULL);
				found = 1;
			}

			if (found) {
				if (upstream && DM_LSTRCMP(upstream, "1") == 0)
					dmuci_del_list_value_by_section((struct uci_section *)data, "upstream_interface", if_name);
				else
					dmuci_del_list_value_by_section((struct uci_section *)data, "downstream_interface", if_name);
				break;
			}
		}

		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface", "section_name", section_name((struct uci_section *)data), mldp_s) {
			char *if_name = NULL, *upstream = NULL;

			dmuci_get_value_by_section_string(mldp_s, "ifname", &if_name);
			dmuci_get_value_by_section_string(mldp_s, "upstream", &upstream);

			if (if_name[0] != '\0') {
				if (DM_LSTRCMP(upstream, "1") == 0)
					dmuci_del_list_value_by_section((struct uci_section *)data, "upstream_interface", if_name);
				else
					dmuci_del_list_value_by_section((struct uci_section *)data, "downstream_interface", if_name);
			}
		}

		del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_interface", "section_name", section_name((struct uci_section *)data));
		break;
	}

	return 0;
}

static int browse_mldp_interface_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return browse_proxy_interface_inst(dmctx, parent_node, prev_data, "mld");
}

static int add_mldp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_mldp_filter = NULL;

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy_filter", &dmmap_mldp_filter);
	dmuci_set_value_by_section(dmmap_mldp_filter, "section_name", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_mldp_filter, "enable", "0");
	dmuci_set_value_by_section(dmmap_mldp_filter, "filter_instance", *instance);
	return 0;
}

static int browse_mldp_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return browse_filter_inst(dmctx, parent_node, prev_data, "proxy", "proxy_filter", "mld");
}

static int set_mldp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *s_inst, *up;
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 45, NULL, IPv6Address))
			return FAULT_9007;
		break;
	case VALUESET:
		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
				"section_name", section_name((struct uci_section *)data), s) {
			dmuci_get_value_by_section_string(s, "filter_instance", &s_inst);
			if (DM_STRCMP(s_inst, instance) == 0) {
				dmuci_set_value_by_section(s, "ipaddr", value);
				dmuci_get_value_by_section_string(s, "enable", &up);
				string_to_bool(up, &b);
				sync_dmmap_bool_to_uci_list((struct uci_section *)data, "filter", value, b);
				break;
			}
		}
		break;
	}

	return 0;
}

#if 0
static int browse_mlds_cgrp_assoc_dev_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_mldp_cgrp_assoc_dev_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_mlds_cgrp_stats_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_mldp_cgrp_stats_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}
static int get_mlds_cgrp_gaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_gaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_assoc_dev_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_assoc_dev_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_adev_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_adev_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_stats_rsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_stats_rsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_stats_rrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_stats_rrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_stats_qsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_stats_qsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_stats_qrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_stats_qrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_stats_lsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_stats_lsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mlds_cgrp_stats_lrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_mldp_cgrp_stats_lrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}
#endif

static int set_mldp_interface_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *linker = NULL, *interface_linker = NULL;
	char ifname[16];
	char *up, *f_inst, *if_type;
	struct uci_section *d_sec = NULL, *s = NULL;
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, NULL))
			return FAULT_9007;

		if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
			return FAULT_9007;

		break;
	case VALUESET:
		// First check if this is a bridge type interface
		if (get_mcast_snooping_interface_val(ctx, value, ifname, sizeof(ifname)) == 0) {
			interface_linker = dmstrdup(ifname);
		} else {
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				uci_foreach_sections("network", "interface", s) {
					if(strcmp(section_name(s), linker) != 0) {
						continue;
					}
					dmuci_get_value_by_section_string(s, "type", &if_type);
					if (DM_LSTRCMP(if_type, "bridge") == 0)
						dmasprintf(&interface_linker, "br-%s", linker);
					else
						dmuci_get_value_by_section_string(s, "device", &interface_linker);
					break;
				}
			} else {
				interface_linker = "";
			}
		}

		uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data), d_sec) {
			dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
			if (DM_STRCMP(instance, f_inst) == 0) {
				dmuci_set_value_by_section(d_sec, "ifname", interface_linker);
				dmuci_get_value_by_section_string(d_sec, "upstream", &up);
				string_to_bool(up, &b);
				sync_dmmap_bool_to_uci_list((struct uci_section *)data, "downstream_interface", interface_linker, !b);

				// Now update the proxy_interface list
				sync_dmmap_bool_to_uci_list((struct uci_section *)data, "upstream_interface", interface_linker, b);
				update_snooping_mode((struct uci_section *)data);
				break;
			}
		}

		break;
	}

	return 0;
}

static int get_mldp_interface_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *mldp_s = NULL;
	char *mldp_ifname = NULL, *f_inst;
	char sec_name[16] = {0};
	int found = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface", "section_name", section_name((struct uci_section *)data), mldp_s) {
		dmuci_get_value_by_section_string(mldp_s, "iface_instance", &f_inst);
		if (DM_STRCMP(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(mldp_s, "ifname", &mldp_ifname);
			found = 1;
			break;
		}
	}

	if ((found == 0) || DM_STRLEN(mldp_ifname) == 0) {
		*value = "";
		return 0;
	}

	// Check if this is bridge type interface
	if (DM_LSTRSTR(mldp_ifname, "br-")) {
		// Interface is bridge type, convert to network uci file section name
		char val[16] = {0};
		DM_STRNCPY(val, mldp_ifname, sizeof(val));
		char *tok, *end;
		tok = strtok_r(val, "-", &end);
		if (DM_LSTRCMP(tok, "br") == 0) {
			DM_STRNCPY(sec_name, end, sizeof(sec_name));
		} else {
			goto end;
		}

		struct uci_section *intf_s = NULL;
		uci_foreach_sections("network", "interface", intf_s) {
			if(strcmp(section_name(intf_s), sec_name) != 0)
				continue;

			char *proto = NULL;
			dmuci_get_value_by_section_string(intf_s, "proto", &proto);
			if (proto && proto[0] != '\0') {
				// It is a L3 bridge, get the linker accordingly
				adm_entry_get_linker_param(ctx, "Device.IP.Interface.", sec_name, value);
			} else {
				// It is a L2 bridge, get the linker accordingly
				adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", mldp_ifname, value);
			}
			break;
		}
	} else {
		char *device_name, *tmp_linker = NULL;
		// it is a L3 interface, get the section name from device name to construct the linker
		struct uci_section *intf_s = NULL;
		uci_foreach_sections("network", "interface", intf_s) {
			dmuci_get_value_by_section_string(intf_s, "device", &device_name);
			if (DM_STRCMP(device_name, mldp_ifname) == 0) {
				tmp_linker = dmstrdup(section_name(intf_s));
				break;
			}
		}

		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", tmp_linker, value);
	}

end:
	return 0;
}

static int set_mldp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *f_inst, *ifname;
	struct uci_section *d_sec;
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
			if (DM_STRCMP(instance, f_inst) == 0) {
				dmuci_get_value_by_section_string(d_sec, "ifname", &ifname);
				dmuci_set_value_by_section(d_sec, "upstream", (b) ? "1" : "0");

				sync_dmmap_bool_to_uci_list((struct uci_section *)data, "downstream_interface", ifname, !b);
				sync_dmmap_bool_to_uci_list((struct uci_section *)data, "upstream_interface", ifname, b);
				update_snooping_mode((struct uci_section *)data);

				break;
			}
		}
		break;
	}

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* ***Device.X_IOPSYS_EU_MLD. *** */
DMOBJ X_IOPSYS_EU_MLDObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Snooping", &DMWRITE, add_mld_snooping_obj, del_mld_snooping_obj, NULL, browse_mld_snooping_inst, NULL, NULL, X_IOPSYS_EU_MLDSnoopingObj, X_IOPSYS_EU_MLDSnoopingParams, NULL, BBFDM_BOTH},
{"Proxy", &DMWRITE, add_mld_proxy_obj, del_mld_proxy_obj, NULL, browse_mld_proxy_inst, NULL, NULL, X_IOPSYS_EU_MLDProxyObj, X_IOPSYS_EU_MLDProxyParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_MLDParams[] = {
{"SnoopingNumberOfEntries", &DMREAD, DMT_UNINT, get_mlds_no_of_entries, NULL, BBFDM_BOTH},
{"ProxyNumberOfEntries", &DMREAD, DMT_UNINT, get_mldp_no_of_entries, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_MLDSnoopingObj[] = {
//{"ClientGroup", &DMREAD, NULL, NULL, NULL, browse_mlds_cgrp_inst, NULL, NULL, NULL, MLDSnoopingCLientGroupObj, MLDSnoopingClientGroupParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, add_mlds_filter_obj, del_mcasts_filter_obj, NULL, browse_mlds_filter_inst, NULL, NULL, NULL, MLDSnoopingFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ MLDSnoopingCLientGroupObj[] = {
//{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_mlds_cgrp_assoc_dev_inst, NULL, NULL, NULL, MLDSnoopingClientGroupAssociatedDeviceParams, NULL, BBFDM_BOTH},
//{"ClientGroupStats", &DMREAD, NULL, NULL, NULL, browse_mlds_cgrp_stats_inst, NULL, NULL, NULL, MLDSnoopingClientGroupStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDSnoopingClientGroupParams[] = {
//{"GroupAddress", &DMREAD, DMT_STRING, get_mlds_cgrp_gaddr, NULL, BBFDM_BOTH},
//{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_mlds_cgrp_assoc_dev_no_of_entries, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDSnoopingFilterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcasts_filter_enable, set_mcasts_filter_enable, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_mcasts_filter_address, set_mcasts_filter_address, BBFDM_BOTH},
{0}
};

DMLEAF MLDSnoopingClientGroupAssociatedDeviceParams[] = {
//{"Interface", &DMREAD, DMT_STRING, get_mlds_cgrp_adev_iface, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDSnoopingClientGroupStatsParams[] = {
//{"ReportsSent", &DMREAD, DMT_UNINT, get_mlds_cgrp_stats_rsent, NULL, BBFDM_BOTH},
//{"ReportsReceived", &DMREAD, DMT_UNINT, get_mlds_cgrp_stats_rrcvd, NULL, BBFDM_BOTH},
//{"QueriesSent", &DMREAD, DMT_UNINT, get_mlds_cgrp_stats_qsent, NULL, BBFDM_BOTH},
//{"QueriesReceived", &DMREAD, DMT_UNINT, get_mlds_cgrp_stats_qrcvd, NULL, BBFDM_BOTH},
//{"LeavesSent", &DMREAD, DMT_UNINT, get_mlds_cgrp_stats_lsent, NULL, BBFDM_BOTH},
//{"LeavesReceived", &DMREAD, DMT_UNINT, get_mlds_cgrp_stats_lrcvd, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_MLDSnoopingParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcast_snooping_enable, set_mcast_snooping_enable, BBFDM_BOTH},
{"Version", &DMWRITE, DMT_STRING, get_mld_version, set_mld_version, BBFDM_BOTH},
{"Robustness", &DMWRITE, DMT_UNINT, get_mcast_snooping_robustness, set_mcast_snooping_robustness, BBFDM_BOTH},
{"Aggregation", &DMWRITE, DMT_BOOL, get_mcast_snooping_aggregation, set_mcast_snooping_aggregation, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_mcast_snooping_interface, set_mcast_snooping_interface, BBFDM_BOTH},
{"Mode", &DMWRITE, DMT_STRING, get_mcast_snooping_mode, set_mcast_snooping_mode, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_mcasts_filter_no_of_entries, NULL, BBFDM_BOTH},
{"LastMemberQueryInterval", &DMWRITE, DMT_UNINT, get_mcasts_last_mq_interval, set_mcasts_last_mq_interval, BBFDM_BOTH},
{"ImmediateLeave", &DMWRITE, DMT_BOOL, get_mcasts_fast_leave, set_mcasts_fast_leave, BBFDM_BOTH},
//{"ClientGroupNumberOfEntries", &DMREAD, DMT_UNINT, get_mldp_cgrps_no_of_entries, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_MLDProxyObj[] = {
{"Interface", &DMWRITE, add_mldp_interface_obj, del_mldp_interface_obj, NULL, browse_mldp_interface_inst, NULL, NULL, NULL, MLDProxyInterfaceParams, NULL, BBFDM_BOTH},
//{"ClientGroup", &DMREAD, NULL, NULL, NULL, browse_mldp_cgrp_inst, NULL, NULL, MLDProxyCLientGroupObj, MLDProxyClientGroupParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, add_mldp_filter_obj, del_mcastp_filter_obj, NULL, browse_mldp_filter_inst, NULL, NULL, NULL, MLDProxyFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ MLDProxyCLientGroupObj[] = {
//{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_mldp_cgrp_assoc_dev_inst, NULL, NULL, NULL, MLDProxyClientGroupAssociatedDeviceParams, NULL, BBFDM_BOTH},
//{"ClientGroupStats", &DMREAD, NULL, NULL, NULL, browse_mldp_cgrp_stats_inst, NULL, NULL, NULL, MLDProxyClientGroupStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDProxyClientGroupParams[] = {
//{"GroupAddress", &DMREAD, DMT_STRING, get_mldp_cgrp_gaddr, NULL, BBFDM_BOTH},
//{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_mldp_cgrp_assoc_dev_no_of_entries, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDProxyFilterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcastp_filter_enable, set_mcastp_filter_enable, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_mcastp_filter_address, set_mldp_filter_address, BBFDM_BOTH},
{0}
};

DMLEAF MLDProxyClientGroupAssociatedDeviceParams[] = {
//{"Interface", &DMREAD, DMT_STRING, get_mldp_cgrp_adev_iface, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDProxyClientGroupStatsParams[] = {
//{"ReportsSent", &DMREAD, DMT_UNINT, get_mldp_cgrp_stats_rsent, NULL, BBFDM_BOTH},
//{"ReportsReceived", &DMREAD, DMT_UNINT, get_mldp_cgrp_stats_rrcvd, NULL, BBFDM_BOTH},
//{"QueriesSent", &DMREAD, DMT_UNINT, get_mldp_cgrp_stats_qsent, NULL, BBFDM_BOTH},
//{"QueriesReceived", &DMREAD, DMT_UNINT, get_mldp_cgrp_stats_qrcvd, NULL, BBFDM_BOTH},
//{"LeavesSent", &DMREAD, DMT_UNINT, get_mldp_cgrp_stats_lsent, NULL, BBFDM_BOTH},
//{"LeavesReceived", &DMREAD, DMT_UNINT, get_mldp_cgrp_stats_lrcvd, NULL, BBFDM_BOTH},
{0}
};

DMLEAF MLDProxyInterfaceParams[] = {
{"Interface", &DMWRITE, DMT_STRING, get_mldp_interface_iface, set_mldp_interface_iface, BBFDM_BOTH},
{"Upstream", &DMWRITE, DMT_BOOL, get_mcastp_interface_upstream, set_mldp_interface_upstream, BBFDM_BOTH},
{"SnoopingMode", &DMWRITE, DMT_STRING, get_mcastp_iface_snoop_mode, set_mcastp_iface_snoop_mode, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_MLDProxyParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_mcast_proxy_enable, set_mcast_proxy_enable, BBFDM_BOTH},
{"Version", &DMWRITE, DMT_STRING, get_mld_version, set_mld_version, BBFDM_BOTH},
{"QueryInterval", &DMWRITE, DMT_UNINT, get_mcastp_query_interval, set_mcastp_query_interval, BBFDM_BOTH},
{"QueryResponseInterval", &DMWRITE, DMT_UNINT, get_mcastp_q_response_interval, set_mcastp_q_response_interval, BBFDM_BOTH},
{"LastMemberQueryInterval", &DMWRITE, DMT_UNINT, get_mcastp_last_mq_interval, set_mcastp_last_mq_interval, BBFDM_BOTH},
{"ImmediateLeave", &DMWRITE, DMT_BOOL, get_mcast_proxy_fast_leave, set_mcast_proxy_fast_leave, BBFDM_BOTH},
{"Robustness", &DMWRITE, DMT_UNINT, get_mcast_proxy_robustness, set_mcast_proxy_robustness, BBFDM_BOTH},
{"Aggregation", &DMWRITE, DMT_BOOL, get_mcast_proxy_aggregation, set_mcast_proxy_aggregation, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_mcastp_filter_no_of_entries, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_mcastp_interface_no_of_entries, NULL, BBFDM_BOTH},
{0}
};
