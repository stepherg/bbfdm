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
* COMMON FUNCTIONS
**************************************************************/
/* Returns dnsmasq section name belonging to LAN network */
char *get_dhcp_dnsmasq_section_name(void)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("dhcp", "dnsmasq", s) {
		char *sec = section_name(s);
		if (DM_STRCMP(sec, "dns_client") != 0)
			return sec;
	}

	return "";
}

static int radv_get_option_value(struct uci_section *s, char *option_list, const char *option_value, char **value)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(s, option_list, &uci_list);
	*value = (value_exists_in_uci_list(uci_list, option_value)) ? "1" : "0";
	return 0;
}

static int radv_set_option_value(struct uci_section *s, char *option_list, const char *option_value, bool b)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(s, option_list, &uci_list);
	if (b) {
		if (!value_exists_in_uci_list(uci_list, option_value))
			dmuci_add_list_value_by_section(s, option_list, (char *)option_value);
	} else {
		if (value_exists_in_uci_list(uci_list, option_value))
			dmuci_del_list_value_by_section(s, option_list, (char *)option_value);
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.RouterAdvertisement.InterfaceSetting.{i}.!UCI:dhcp/dhcp/dmmap_radv*/
static int browseRouterAdvertisementInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *ignore = NULL;
	struct dm_data *curr_data = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_radv", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(curr_data->config_section, "ignore", &ignore);
		if (ignore && DM_LSTRCMP(ignore, "1") == 0)
			continue;

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "radv_intf_instance", "radv_intf_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseRouterAdvertisementInterfaceSettingOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *dhcp_s = ((struct dm_data *)prev_data)->config_section;
	struct uci_section *dhcp_dmmap_s = NULL;
	struct dm_data curr_data = {0};
	struct uci_list *dns_list = NULL;
	char *inst = NULL, *option_value = NULL;

	dmuci_get_value_by_section_list(dhcp_s, "dns", &dns_list);

	if (dns_list != NULL) {
		struct uci_element *e = NULL;

		uci_foreach_element(dns_list, e) {
			if ((dhcp_dmmap_s = get_dup_section_in_dmmap_eq("dmmap_radv", "radv_option", section_name(dhcp_s), "option_value", e->name)) == NULL) {
				dmuci_add_section_bbfdm("dmmap_radv", "radv_option", &dhcp_dmmap_s);
				dmuci_set_value_by_section_bbfdm(dhcp_dmmap_s, "option_value", e->name);
				dmuci_set_value_by_section_bbfdm(dhcp_dmmap_s, "section_name", section_name(dhcp_s));
			}
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_radv", "radv_option", "section_name", section_name(dhcp_s), dhcp_dmmap_s) {
		dmuci_get_value_by_section_string(dhcp_dmmap_s, "option_value", &option_value);

		curr_data.config_section = dhcp_s;
		curr_data.dmmap_section = dhcp_dmmap_s;
		curr_data.additional_data = (void *)option_value;

		inst = handle_instance(dmctx, parent_node, dhcp_dmmap_s, "radv_option_instance", "radv_option_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjRouterAdvertisementInterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;
	char ra_sname[32] = {0};

	snprintf(ra_sname, sizeof(ra_sname), "ra_%s", *instance);

	dmuci_add_section("dhcp", "dhcp", &s);
	dmuci_rename_section_by_section(s, ra_sname);
	dmuci_set_value_by_section(s, "ignore", "0");
	dmuci_set_value_by_section(s, "ra", "disabled");
	dmuci_set_value_by_section(s, "ra_flags", "none");

	dmuci_add_section_bbfdm("dmmap_radv", "dhcp", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", ra_sname);
	dmuci_set_value_by_section(dmmap, "radv_intf_instance", *instance);
	return 0;
}

static int delObjRouterAdvertisementInterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dm_data *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dm_data *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("dhcp", "dhcp", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_radv", "dhcp", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjRouterAdvertisementInterfaceSettingOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_sect = NULL;

	dmuci_add_section_bbfdm("dmmap_radv", "radv_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(((struct dm_data *)data)->config_section));
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", "23");
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "radv_option_instance", *instance);
	return 0;
}

static int delObjRouterAdvertisementInterfaceSettingOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_list *dns_list = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_list(((struct dm_data *)data)->config_section, "dns", &dns_list);
			if (value_exists_in_uci_list(dns_list, ((struct dm_data *)data)->additional_data))
				dmuci_del_list_value_by_section(((struct dm_data *)data)->config_section, "dns", ((struct dm_data *)data)->additional_data);

			dmuci_delete_by_section(((struct dm_data *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "dns", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_radv", "radv_option", stmp, s) {
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
	char *sec = get_dhcp_dnsmasq_section_name();

	if (DM_STRLEN(sec) == 0)
		return 0;

	*value = dmuci_get_option_value_fallback_def("dhcp", sec, "raserver", "1");
	return 0;
}

static int set_RouterAdvertisement_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *sec;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			sec = get_dhcp_dnsmasq_section_name();
			if (DM_STRLEN(sec) == 0)
				return 0;

			string_to_bool(value, &b);
			dmuci_set_value("dhcp", sec, "raserver", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_RouterAdvertisement_InterfaceSettingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseRouterAdvertisementInterfaceSettingInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.Enable!UCI:dhcp/dhcp,@i-1/ra*/
static int get_RouterAdvertisementInterfaceSetting_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "ra", value);
	*value = (*value && DM_LSTRCMP(*value, "disabled") == 0) ? "0" : "1";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra", b ? "server" : "disabled");
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.Status!UCI:dhcp/dhcp,@i-1/ra*/
static int get_RouterAdvertisementInterfaceSetting_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "ra", value);
	*value = (*value && DM_LSTRCMP(*value, "disabled") == 0) ? "Disabled" : "Enabled";
	return 0;
}

static int get_RouterAdvertisementInterfaceSetting_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "radv_intf_alias", instance, value);
}

static int set_RouterAdvertisementInterfaceSetting_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "radv_intf_alias", instance, value);
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.Interface!UCI:dhcp/dhcp,@i-1/interface*/
static int get_RouterAdvertisementInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "interface", &linker);
	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", linker, value);
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "interface", reference.value);
			break;
	}
	return 0;
}

static int get_RouterAdvertisementInterfaceSetting_Prefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *ipv6_prefix_obj = NULL, *arrobj = NULL;
	char *interface = NULL, *ip_inst = NULL, list_val[512];
	struct uci_section *dmmap_s = NULL;
	int i = 0, pos = 0;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "interface", &interface);
	dmuci_get_value_by_section_string(((struct dm_data *)data)->dmmap_section, "ip_int_instance", &ip_inst);

	list_val[0] = 0;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix-assignment") {
		char ipv6_prefix[64], *ipv6_prefix_inst = NULL;

		char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
		char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
		snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);

		uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "section_name", interface, dmmap_s) {
			dmuci_get_value_by_section_string(dmmap_s, "address", &address);
			if (address && DM_STRCMP(address, ipv6_prefix) == 0) {
				dmuci_get_value_by_section_string(dmmap_s, "ipv6_prefix_instance", &ipv6_prefix_inst);
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
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_maxinterval", "600");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"4","1800"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_maxinterval", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.MinRtrAdvInterval!UCI:dhcp/dhcp,@i-1/ra_mininterval*/
static int get_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_mininterval", "200");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"3","1350"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_mininterval", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvDefaultLifetime!UCI:dhcp/dhcp,@i-1/ra_lifetime*/
static int get_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_lifetime", "1800");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_lifetime", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvManagedFlag!UCI:dhcp/dhcp,@i-1/ra_flags*/
static int get_RouterAdvertisementInterfaceSetting_AdvManagedFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radv_get_option_value(((struct dm_data *)data)->config_section, "ra_flags", "managed-config", value);
}

static int set_RouterAdvertisementInterfaceSetting_AdvManagedFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			return radv_set_option_value(((struct dm_data *)data)->config_section, "ra_flags", "managed-config", b);
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvOtherConfigFlag!UCI:dhcp/dhcp,@i-1/ra_flags*/
static int get_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radv_get_option_value(((struct dm_data *)data)->config_section, "ra_flags", "other-config", value);
}

static int set_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			return radv_set_option_value(((struct dm_data *)data)->config_section, "ra_flags", "other-config", b);
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvMobileAgentFlag!UCI:dhcp/dhcp,@i-1/ra_flags*/
static int get_RouterAdvertisementInterfaceSetting_AdvMobileAgentFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radv_get_option_value(((struct dm_data *)data)->config_section, "ra_flags", "home-agent", value);
}

static int set_RouterAdvertisementInterfaceSetting_AdvMobileAgentFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			return radv_set_option_value(((struct dm_data *)data)->config_section, "ra_flags", "home-agent", b);
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvPreferredRouterFlag!UCI:dhcp/dhcp,@i-1/ra_preference*/
static int get_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *preferenece = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "ra_preference", &preferenece);
	*value = (preferenece && *preferenece == 'h') ? "High" : (preferenece && *preferenece == 'l') ? "Low" : "Medium";
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *Adv_Preferred_RouterFlag[] = {"High", "Medium", "Low", NULL};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, Adv_Preferred_RouterFlag, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_preference", (*value == 'H') ? "high" : (*value == 'L') ? "low" : "medium");
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvLinkMTU!UCI:dhcp/dhcp,@i-1/ra_mtu*/
static int get_RouterAdvertisementInterfaceSetting_AdvLinkMTU(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_mtu", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvLinkMTU(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_mtu", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvReachableTime!UCI:dhcp/dhcp,@i-1/ra_reachabletime*/
static int get_RouterAdvertisementInterfaceSetting_AdvReachableTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_reachabletime", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvReachableTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"3600000"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_reachabletime", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvRetransTimer!UCI:dhcp/dhcp,@i-1/ra_retranstime*/
static int get_RouterAdvertisementInterfaceSetting_AdvRetransTimer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_retranstime", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvRetransTimer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_retranstime", value);
			break;
	}
	return 0;
}

/*#Device.RouterAdvertisement.InterfaceSetting.{i}.AdvCurHopLimit!UCI:dhcp/dhcp,@i-1/ra_hoplimit*/
static int get_RouterAdvertisementInterfaceSetting_AdvCurHopLimit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "ra_hoplimit", "0");
	return 0;
}

static int set_RouterAdvertisementInterfaceSetting_AdvCurHopLimit(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "ra_hoplimit", value);
			break;
	}
	return 0;
}

static int get_RouterAdvertisementInterfaceSetting_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseRouterAdvertisementInterfaceSettingOptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_RouterAdvertisementInterfaceSettingOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_data *radv_option_s = (struct dm_data *)data;
	return radv_get_option_value(radv_option_s->config_section, "dns", radv_option_s->additional_data, value);
}

static int set_RouterAdvertisementInterfaceSettingOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_data *radv_option_s = (struct dm_data *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			return radv_set_option_value(radv_option_s->config_section, "dns", radv_option_s->additional_data, b);
	}
	return 0;
}

static int get_RouterAdvertisementInterfaceSettingOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "radv_option_alias", instance, value);
}

static int set_RouterAdvertisementInterfaceSettingOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "radv_option_alias", instance, value);
}

static int get_RouterAdvertisementInterfaceSettingOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "23";
	return 0;
}

static int set_RouterAdvertisementInterfaceSettingOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_RouterAdvertisementInterfaceSettingOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *option_value = ((struct dm_data *)data)->additional_data;
	char hex[65535] = {0};

	if (option_value && *option_value)
		convert_string_to_hex(option_value, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_RouterAdvertisementInterfaceSettingOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_data *radv_option_s = (struct dm_data *)data;
	struct uci_list *dns_list = NULL;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_to_string(value, res, sizeof(res));

			dmuci_get_value_by_section_list(radv_option_s->config_section, "dns", &dns_list);
			if (value_exists_in_uci_list(dns_list, radv_option_s->additional_data)) {
				dmuci_del_list_value_by_section(radv_option_s->config_section, "dns", radv_option_s->additional_data);
				dmuci_add_list_value_by_section(radv_option_s->config_section, "dns", res);
			}

			dmuci_set_value_by_section_bbfdm(radv_option_s->dmmap_section, "option_value", res);
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
{"InterfaceSetting", &DMWRITE, addObjRouterAdvertisementInterfaceSetting, delObjRouterAdvertisementInterfaceSetting, NULL, browseRouterAdvertisementInterfaceSettingInst, NULL, NULL, tRouterAdvertisementInterfaceSettingObj, tRouterAdvertisementInterfaceSettingParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tRouterAdvertisementParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_RouterAdvertisement_Enable, set_RouterAdvertisement_Enable, BBFDM_BOTH},
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_RouterAdvertisement_InterfaceSettingNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.RouterAdvertisement.InterfaceSetting.{i}. *** */
DMOBJ tRouterAdvertisementInterfaceSettingObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Option", &DMWRITE, addObjRouterAdvertisementInterfaceSettingOption, delObjRouterAdvertisementInterfaceSettingOption, NULL, browseRouterAdvertisementInterfaceSettingOptionInst, NULL, NULL, NULL, tRouterAdvertisementInterfaceSettingOptionParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tRouterAdvertisementInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_Enable, set_RouterAdvertisementInterfaceSetting_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Alias, set_RouterAdvertisementInterfaceSetting_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Interface", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Interface, set_RouterAdvertisementInterfaceSetting_Interface, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_REFERENCE},
//{"ManualPrefixes", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_ManualPrefixes, set_RouterAdvertisementInterfaceSetting_ManualPrefixes, BBFDM_BOTH},
{"Prefixes", &DMREAD, DMT_STRING, get_RouterAdvertisementInterfaceSetting_Prefixes, NULL, BBFDM_BOTH},
{"MaxRtrAdvInterval", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval, set_RouterAdvertisementInterfaceSetting_MaxRtrAdvInterval, BBFDM_BOTH},
{"MinRtrAdvInterval", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval, set_RouterAdvertisementInterfaceSetting_MinRtrAdvInterval, BBFDM_BOTH},
{"AdvDefaultLifetime", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime, set_RouterAdvertisementInterfaceSetting_AdvDefaultLifetime, BBFDM_BOTH},
{"AdvManagedFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvManagedFlag, set_RouterAdvertisementInterfaceSetting_AdvManagedFlag, BBFDM_BOTH},
{"AdvOtherConfigFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag, set_RouterAdvertisementInterfaceSetting_AdvOtherConfigFlag, BBFDM_BOTH},
{"AdvMobileAgentFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvMobileAgentFlag, set_RouterAdvertisementInterfaceSetting_AdvMobileAgentFlag, BBFDM_BOTH},
{"AdvPreferredRouterFlag", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag, set_RouterAdvertisementInterfaceSetting_AdvPreferredRouterFlag, BBFDM_BOTH},
//{"AdvNDProxyFlag", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSetting_AdvNDProxyFlag, set_RouterAdvertisementInterfaceSetting_AdvNDProxyFlag, BBFDM_BOTH},
{"AdvLinkMTU", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvLinkMTU, set_RouterAdvertisementInterfaceSetting_AdvLinkMTU, BBFDM_BOTH},
{"AdvReachableTime", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvReachableTime, set_RouterAdvertisementInterfaceSetting_AdvReachableTime, BBFDM_BOTH},
{"AdvRetransTimer", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvRetransTimer, set_RouterAdvertisementInterfaceSetting_AdvRetransTimer, BBFDM_BOTH},
{"AdvCurHopLimit", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_AdvCurHopLimit, set_RouterAdvertisementInterfaceSetting_AdvCurHopLimit, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_RouterAdvertisementInterfaceSetting_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.RouterAdvertisement.InterfaceSetting.{i}.Option.{i}. *** */
DMLEAF tRouterAdvertisementInterfaceSettingOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_RouterAdvertisementInterfaceSettingOption_Enable, set_RouterAdvertisementInterfaceSettingOption_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_RouterAdvertisementInterfaceSettingOption_Alias, set_RouterAdvertisementInterfaceSettingOption_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Tag", &DMWRITE, DMT_UNINT, get_RouterAdvertisementInterfaceSettingOption_Tag, set_RouterAdvertisementInterfaceSettingOption_Tag, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Value", &DMWRITE, DMT_HEXBIN, get_RouterAdvertisementInterfaceSettingOption_Value, set_RouterAdvertisementInterfaceSettingOption_Value, BBFDM_BOTH},
{0}
};
