/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dhcpv4.h"
#include "routeradvertisement.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.RouterAdvertisement.InterfaceSetting.{i}.!UCI:dhcp/dhcp/dmmap_radv*/
static int browseRouterAdvertisementInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *ignore = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_radv", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(p->config_section, "ignore", &ignore);
		if (ignore && strcmp(ignore, "1") == 0)
			continue;

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "radv_intf_instance", "radv_intf_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjRouterAdvertisementInterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;
	char ra_sname[32] = {0};

	char *inst = get_dhcp_server_pool_last_instance("dhcp", "dhcp", "dmmap_radv", "radv_intf_instance");
	snprintf(ra_sname, sizeof(ra_sname), "ra_%d", inst ? atoi(inst) + 1 : 1);

	dmuci_add_section("dhcp", "dhcp", &s);
	dmuci_rename_section_by_section(s, ra_sname);
	dmuci_set_value_by_section(s, "ignore", "0");
	dmuci_set_value_by_section(s, "ra", "disabled");
	dmuci_set_value_by_section(s, "ra_management", "3");

	dmuci_add_section_bbfdm("dmmap_radv", "dhcp", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", ra_sname);
	*instance = update_instance(inst, 2, dmmap, "radv_intf_instance");
	return 0;
}

static int delObjRouterAdvertisementInterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_radv", "dhcp", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("dhcp", "dhcp", stmp, s) {
				get_dmmap_section_of_config_section("dmmap_radv", "dhcp", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.RouterAdvertisement.Enable!UCI:dhcp/dnsmasq,@dnsmasq[0]/raserver*/
static int get_RouterAdvertisement_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("dhcp", "@dnsmasq[0]", "raserver", "1");
	return 0;
}

static int set_RouterAdvertisement_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("dhcp", "@dnsmasq[0]", "raserver", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_RouterAdvertisement_InterfaceSettingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.Enable!UCI:dhcp/dhcp,@i-1/ra*/
static int get_RouterAdvertisementInterfaceSetting_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ra", value);
	*value = (*value && strcmp(*value, "disabled") == 0) ? "0" : "1";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "ra", b ? "server" : "disabled");
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.Status!UCI:dhcp/dhcp,@i-1/ra*/
static int get_RouterAdvertisementInterfaceSetting_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ra", value);
	*value = (*value && strcmp(*value, "disabled") == 0) ? "Disabled" : "Enabled";
	return 0;
}

static int get_RouterAdvertisementInterfaceSetting_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_radv", "dhcp", section_name((struct uci_section *)data), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "radv_intf_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_radv", "dhcp", section_name((struct uci_section *)data), &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "radv_intf_alias", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.Interface!UCI:dhcp/dhcp,@i-1/interface*/
static int get_RouterAdvertisementInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &linker);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section((struct uci_section *)data, "interface", linker);
				dmfree(linker);
			}
			break;
	}
	return 0;
}

static int get_RouterAdvertisementInterfaceSetting_Prefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *ipv6_prefix_obj = NULL, *arrobj = NULL;
	char *interface = NULL, *ip_inst = NULL, list_val[512];
	struct uci_section *dmmap_section = NULL;
	int i = 0, pos = 0;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
	get_dmmap_section_of_config_section("dmmap_network", "interface", interface, &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ip_int_instance", &ip_inst);

	list_val[0] = 0;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix-assignment") {
		char ipv6_prefix[64], *ipv6_prefix_inst = NULL;

		char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
		char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
		snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);

		uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "section_name", interface, dmmap_section) {
			dmuci_get_value_by_section_string(dmmap_section, "address", &address);
			if (address && strcmp(address, ipv6_prefix) == 0) {
				dmuci_get_value_by_section_string(dmmap_section, "ipv6_prefix_instance", &ipv6_prefix_inst);
				break;
			}
		}

		if (ip_inst && *ip_inst && ipv6_prefix_inst && *ipv6_prefix_inst)
			pos += snprintf(&list_val[pos], sizeof(list_val) - pos, "Device.IP.Interface.%s.IPv6Prefix.%s,", ip_inst, ipv6_prefix_inst);
	}

	/* cut tailing ',' */
	if (pos)
		list_val[pos - 1] = 0;

	*value = dmstrdup(list_val);
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.MaxRtrAdvInterval!UCI:dhcp/dhcp,@i-1/ra_maxinterval*/
static int get_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_maxinterval", "600");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"4","1800"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_maxinterval", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.MinRtrAdvInterval!UCI:dhcp/dhcp,@i-1/ra_mininterval*/
static int get_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_mininterval", "200");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"3","1350"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_mininterval", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvDefaultLifetime!UCI:dhcp/dhcp,@i-1/ra_lifetime*/
static int get_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_lifetime", "1800");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_lifetime", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvManagedFlag!UCI:dhcp/dhcp,@i-1/ra_management*/
static int get_RouterAdvertisementInterfaceSetting_AdvManagedFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ra_flag = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "ra_management", &ra_flag);
	*value = (ra_flag && (*ra_flag == '0' || *ra_flag == '3')) ? "0" : "1";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvManagedFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				dmuci_set_value_by_section((struct uci_section *)data, "ra_management", "1");
			} else {
				char *ra_flag = NULL;

				dmuci_get_value_by_section_string((struct uci_section *)data, "ra_management", &ra_flag);
				dmuci_set_value_by_section((struct uci_section *)data, "ra_management", (ra_flag && *ra_flag != '3') ? "0" : "3");
			}
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvOtherConfigFlag!UCI:dhcp/dhcp,@i-1/ra_management*/
static int get_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ra_flag = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "ra_management", &ra_flag);
	*value = (ra_flag && *ra_flag == '3') ? "0" : "1";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (!b) {
				dmuci_set_value_by_section((struct uci_section *)data, "ra_management", "3");
			} else {
				char *ra_flag = NULL;

				dmuci_get_value_by_section_string((struct uci_section *)data, "ra_management", &ra_flag);
				if (ra_flag && *ra_flag == '3')
					dmuci_set_value_by_section((struct uci_section *)data, "ra_management", "0");
			}
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvPreferredRouterFlag!UCI:dhcp/dhcp,@i-1/ra_preference*/
static int get_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *preferenece = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "ra_preference", &preferenece);
	*value = (preferenece && *preferenece == 'h') ? "High" : (preferenece && *preferenece == 'l') ? "Low" : "Medium";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, AdvPreferredRouterFlag, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_preference", (*value == 'H') ? "high" : (*value == 'L') ? "low" : "medium");
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvLinkMTU!UCI:dhcp/dhcp,@i-1/ra_mtu*/
static int get_RouterAdvertisementInterfaceSetting_AdvLinkMTU(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_mtu", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvLinkMTU(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_mtu", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvReachableTime!UCI:dhcp/dhcp,@i-1/ra_reachabletime*/
static int get_RouterAdvertisementInterfaceSetting_AdvReachableTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_reachabletime", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvReachableTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"3600000"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_reachabletime", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvRetransTimer!UCI:dhcp/dhcp,@i-1/ra_retranstime*/
static int get_RouterAdvertisementInterfaceSetting_AdvRetransTimer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_retranstime", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvRetransTimer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_retranstime", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvCurHopLimit!UCI:dhcp/dhcp,@i-1/ra_hoplimit*/
static int get_RouterAdvertisementInterfaceSetting_AdvCurHopLimit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ra_hoplimit", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvCurHopLimit(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ra_hoplimit", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.RouterAdvertisement. *** */
DMOBJ tRouterAdvertisementObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"InterfaceSetting", &DMWRITE, addObjRouterAdvertisementInterfaceSetting, delObjRouterAdvertisementInterfaceSetting, NULL, browseRouterAdvertisementInterfaceSettingInst, NULL, NULL, NULL, tRouterAdvertisementInterfaceSettingParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Interface", NULL}},
{0}
};

DMLEAF tRouterAdvertisementParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_RouterAdvertisement_Enable, set_RouterAdvertisement_Enable, BBFDM_BOTH},
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_RouterAdvertisement_InterfaceSettingNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.RouterAdvertisement.InterfaceSetting.{i}. *** */
DMLEAF tRouterAdvertisementInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_Enable, set_RouterAdvertisementInterfaceSetting_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Alias, set_RouterAdvertisementInterfaceSetting_Alias, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Interface, set_RouterAdvertisementInterfaceSetting_Interface, BBFDM_BOTH},
//{"ManualPrefixes", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_ManualPrefixes, set_RouterAdvertisementInterfaceSetting_ManualPrefixes, BBFDM_BOTH},
{"Prefixes", &DMREAD, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Prefixes, NULL, BBFDM_BOTH},
{"MaxRtrAdvInterval", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval, set_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval, BBFDM_BOTH},
{"MinRtrAdvInterval", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval, set_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval, BBFDM_BOTH},
{"AdvDefaultLifetime", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime, set_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime, BBFDM_BOTH},
{"AdvManagedFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvManagedFlag, set_RouterAdvertisementInterfaceSetting_AdvManagedFlag, BBFDM_BOTH},
{"AdvOtherConfigFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag, set_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag, BBFDM_BOTH},
//{"AdvMobileAgentFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvMobileAgentFlag, set_RouterAdvertisementInterfaceSetting_AdvMobileAgentFlag, BBFDM_BOTH},
{"AdvPreferredRouterFlag", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag, set_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag, BBFDM_BOTH},
//{"AdvNDProxyFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvNDProxyFlag, set_RouterAdvertisementInterfaceSetting_AdvNDProxyFlag, BBFDM_BOTH},
{"AdvLinkMTU", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvLinkMTU, set_RouterAdvertisementInterfaceSetting_AdvLinkMTU, BBFDM_BOTH},
{"AdvReachableTime", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvReachableTime, set_RouterAdvertisementInterfaceSetting_AdvReachableTime, BBFDM_BOTH},
{"AdvRetransTimer", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvRetransTimer, set_RouterAdvertisementInterfaceSetting_AdvRetransTimer, BBFDM_BOTH},
{"AdvCurHopLimit", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvCurHopLimit, set_RouterAdvertisementInterfaceSetting_AdvCurHopLimit, BBFDM_BOTH},
//{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};
