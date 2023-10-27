/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "hosts.h"

static char *AccessPolicy[] = {"Allow", "Deny", NULL};
static char *Day[] = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", NULL};
static char *StartTime[] = {"^$", "^([01][0-9]|2[0-3]):[0-5][0-9]$", NULL};

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Hosts.Host.{i}.!UBUS:topology/hosts//hosts*/
static int browseHostsHostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *host_obj = NULL, *arrobj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("topology", "hosts", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, host_obj, i, 1, "hosts") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)host_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv4Address.{i}.!UBUS:topology/hosts//hosts[@i-1].ipv4addr*/
static int browseHostsHostIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ip_arr = NULL, *host_obj = (json_object *)prev_data;
	char *inst = NULL, *ipv4addr = NULL;
	int id = 0, i = 0;

	dmjson_foreach_value_in_array(host_obj, ip_arr, ipv4addr, i, 1, "ipv4addr") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv4addr, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv6Address.{i}.!UBUS:topology/hosts//hosts[@i-1].ipv6addr*/
static int browseHostsHostIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ip_arr = NULL, *host_obj = (json_object *)prev_data;
	char *inst = NULL, *ipv6addr = NULL;
	int id = 0, i = 0;

	dmjson_foreach_value_in_array(host_obj, ip_arr, ipv6addr, i, 1, "ipv6addr") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv6addr, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseHostsAccessControlInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);
	char *inst = NULL;

	synchronize_specific_config_sections_with_dmmap("hosts", "access_control", "dmmap_hosts", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "access_control_instance", "access_control_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;

}

static int browseHostsAccessControlScheduleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *ac_s = ((struct dmmap_dup *)prev_data)->config_section;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);
	char *inst = NULL;

	synchronize_specific_config_sections_with_dmmap_eq("hosts", "ac_schedule", "dmmap_hosts", "dm_parent", section_name(ac_s), &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "schedule_instance", "schedule_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;

}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjHostsAccessControl(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *ac_s = NULL, *dmmap_s = NULL;
	char ac_name[32] = {0};

	snprintf(ac_name, sizeof(ac_name), "ac_%s", *instance);

	dmuci_add_section("hosts", "access_control", &ac_s);
	dmuci_rename_section_by_section(ac_s, ac_name);
	dmuci_set_value_by_section(ac_s, "enable", "0");
	dmuci_set_value_by_section(ac_s, "access_policy", "Allow");

	dmuci_add_section_bbfdm("dmmap_hosts", "access_control", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", section_name(ac_s));
	dmuci_set_value_by_section(dmmap_s, "access_control_instance", *instance);
	return 0;
}

static int delObjHostsAccessControl(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *dmmap_section = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			// AccessControl Schedule section
			uci_foreach_option_eq_safe("hosts", "ac_schedule", "dm_parent", section_name(((struct dmmap_dup *)data)->config_section), stmp, s) {

				// dmmap AccessControl Schedule section
				get_dmmap_section_of_config_section("dmmap_hosts", "ac_schedule", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}

			// AccessControl section
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);

			// Dmmap AccessControl section
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);

			break;
		case DEL_ALL:
			// AccessControl section
			uci_foreach_sections_safe("hosts", "access_control", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			// dmmap AccessControl section
			uci_path_foreach_sections_safe(bbfdm, "dmmap_hosts", "access_control", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			// AccessControl Schedule section
			uci_foreach_sections_safe("hosts", "ac_schedule", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			// dmmap AccessControl Schedule section
			uci_path_foreach_sections_safe(bbfdm, "dmmap_hosts", "ac_schedule", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			break;
	}
	return 0;
}

static int addObjHostsAccessControlSchedule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *ac_s = ((struct dmmap_dup *)data)->config_section;
	struct uci_section *ac_schedule_s = NULL, *dmmap_s = NULL;
	char ac_schedule_name[32] = {0};

	snprintf(ac_schedule_name, sizeof(ac_schedule_name), "%s_s_%s", section_name(ac_s), *instance);

	dmuci_add_section("hosts", "ac_schedule", &ac_schedule_s);
	dmuci_rename_section_by_section(ac_schedule_s, ac_schedule_name);
	dmuci_set_value_by_section(ac_schedule_s, "dm_parent", section_name(ac_s));
	dmuci_set_value_by_section(ac_schedule_s, "enable", "0");

	dmuci_add_section_bbfdm("dmmap_hosts", "ac_schedule", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", section_name(ac_schedule_s));
	dmuci_set_value_by_section(dmmap_s, "schedule_instance", *instance);
	return 0;

}

static int delObjHostsAccessControlSchedule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *ac_s = NULL, *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			ac_s = ((struct dmmap_dup *)data)->config_section;

			// AccessControl Schedule section
			uci_foreach_option_eq_safe("hosts", "ac_schedule", "dm_parent", section_name(ac_s), stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_hosts", "ac_schedule", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}

			break;
	}
	return 0;
}

/*************************************************************
* LINKER
**************************************************************/
static int get_linker_host(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Hosts.HostNumberOfEntries!UBUS:topology/hosts//hosts*/
static int get_Hosts_HostNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseHostsHostInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Hosts_AccessControlNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseHostsAccessControlInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Hosts.Host.{i}.PhysAddress!UBUS:topology/hosts//hosts[@i-1].macaddr*/
static int get_HostsHost_PhysAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddr");
	return 0;
}

/*#Device.Hosts.Host.{i}.IPAddress!UBUS:topology/hosts//hosts[@i-1].ipaddr*/
static int get_HostsHost_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipaddr");
	return 0;
}

static int get_HostsHost_DHCPClient(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	adm_entry_get_linker_param(ctx, "Device.DHCPv4.Server.Pool.", linker, value);
	return 0;
}

static int get_HostsHost_AssociatedDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "link_macaddr");
	adm_entry_get_linker_param(ctx, "Device.WiFi.AccessPoint.", linker, value);
	if (!(*value) || (*value)[0] == 0)
		adm_entry_get_linker_param(ctx, "Device.WiFi.DataElements.Network.Device.", linker, value);
	return 0;
}

static int get_HostsHost_Layer1Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "device");
	char *type = dmjson_get_value((json_object *)data, 1, "interface_type");
	if (DM_LSTRCMP(type, "Wi-Fi") == 0) {
		char *mac_addr = dmjson_get_value((json_object *)data, 1, "link_macaddr");
		adm_entry_get_linker_param(ctx, "Device.WiFi.AccessPoint.", mac_addr, value);
		if (DM_STRLEN(*value) == 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", linker, value);
		if (!(*value) || (*value)[0] == 0) {
			char *device = dmjson_get_value((json_object *)data, 1, "parent_device");
			struct uci_section *iface_s = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", DM_STRLEN(device) ? device : linker);
			dmuci_get_value_by_section_string(iface_s, "device", &linker);
			adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", linker, value);
		}
	} else {
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
		if (!(*value) || (*value)[0] == 0) {
			struct uci_section *device_s = get_dup_section_in_config_opt("network", "device", "name", linker);
			dmuci_get_value_by_section_string(device_s, "ifname", &linker);
			adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
		}
	}
	return 0;
}

static int get_HostsHost_Layer3Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "network");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

/*#Device.Hosts.Host.{i}.InterfaceType!UBUS:topology/hosts//hosts[@i-1].interface_type*/
static int get_HostsHost_InterfaceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "interface_type");
	return 0;
}

/*#Device.Hosts.Host.{i}.HostName!UBUS:topology/hosts//hosts[@i-1].hostname*/
static int get_HostsHost_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "hostname");
	return 0;
}

/*#Device.Hosts.Host.{i}.Active!UBUS:topology/hosts//hosts[@i-1].active*/
static int get_HostsHost_Active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "active");
	return 0;
}

/*#Device.Hosts.Host.{i}.ActiveLastChange!UBUS:topology/hosts//hosts[@i-1].active_last_change*/
static int get_HostsHost_ActiveLastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "active_last_change");
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv4AddressNumberOfEntries!UBUS:topology/hosts//hosts[@i-1].ipv4addr*/
static int get_HostsHost_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseHostsHostIPv4AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv6AddressNumberOfEntries!UBUS:topology/hosts//hosts[@i-1].ipv6addr*/
static int get_HostsHost_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseHostsHostIPv6AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv4Address.{i}.IPAddress!UBUS:topology/hosts//hosts[@i-1].ipv4addr[@i-1]*/
static int get_HostsHostIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)data;
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv6Address.{i}.IPAddress!UBUS:topology/hosts//hosts[@i-1].ipv6addr[@i-1]*/
static int get_HostsHostIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)data;
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.BytesSent!UBUS:topology/hosts//hosts[@i-1].stats.tx_bytes*/
static int get_HostsHostWANStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_bytes");
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.BytesReceived!UBUS:topology/hosts//hosts[@i-1].stats.rx_bytes*/
static int get_HostsHostWANStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_bytes");
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.PacketsSent!UBUS:topology/hosts//hosts[@i-1].stats.tx_packets*/
static int get_HostsHostWANStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_packets");
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.PacketsReceived!UBUS:topology/hosts//hosts[@i-1].stats.rx_packets*/
static int get_HostsHostWANStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_packets");
	return 0;
}

static int get_HostsAccessControl_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "access_control_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_HostsAccessControl_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "access_control_alias", value);
			break;
	}
	return 0;
}

static int get_HostsAccessControl_PhysAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "macaddr", value);
	return 0;
}

static int set_HostsAccessControl_PhysAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "macaddr", value);
			break;
	}
	return 0;
}

static int get_HostsAccessControl_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "host", value);
	return 0;
}

static int set_HostsAccessControl_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "host", value);
			break;
	}
	return 0;
}

static int get_HostsAccessControl_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_HostsAccessControl_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_HostsAccessControl_AccessPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "access_policy", value);
	return 0;
}

static int set_HostsAccessControl_AccessPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, AccessPolicy, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "access_policy", value);
			break;
	}
	return 0;
}

static int get_HostsAccessControl_ScheduleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseHostsAccessControlScheduleInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_HostsAccessControlSchedule_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "schedule_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_HostsAccessControlSchedule_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "schedule_alias", value);
			break;
	}
	return 0;
}

static int get_HostsAccessControlSchedule_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_HostsAccessControlSchedule_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_HostsAccessControlSchedule_Day(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *days_list = NULL;
	char buf[64] = {0};

	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "day", &days_list);

	if (days_list != NULL) {
		struct uci_element *e = NULL;
		unsigned pos = 0;

		buf[0] = 0;
		uci_foreach_element(days_list, e) {

			if (sizeof(buf) - pos < DM_STRLEN(e->name))
				break;

			pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", e->name);
		}

		if (pos)
			buf[pos - 1] = 0;
	}

	*value = (buf[0] != '\0') ? dmstrdup(buf) : "";
	return 0;
}

static int set_HostsAccessControlSchedule_Day(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch = NULL, *spch = NULL;
	char value_buf[64] = {0};

	DM_STRNCPY(value_buf, value, sizeof(value_buf));

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, Day, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "day", "");
			for (pch = strtok_r(value_buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch))
				dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "day", pch);
			break;
	}
	return 0;
}

static int get_HostsAccessControlSchedule_StartTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "start_time", value);
	return 0;
}

static int set_HostsAccessControlSchedule_StartTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 5, NULL, StartTime))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "start_time", value);
			break;
	}
	return 0;
}

static int get_HostsAccessControlSchedule_Duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "duration", value);
	return 0;
}

static int set_HostsAccessControlSchedule_Duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "duration", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.Hosts. *** */
DMOBJ tHostsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Host", &DMREAD, NULL, NULL, NULL, browseHostsHostInst, NULL, NULL, tHostsHostObj, tHostsHostParams, get_linker_host, BBFDM_BOTH, LIST_KEY{"PhysAddress", NULL}, "2.0"},
{"AccessControl", &DMWRITE, addObjHostsAccessControl, delObjHostsAccessControl, NULL, browseHostsAccessControlInst, NULL, NULL, tHostsAccessControlObj, tHostsAccessControlParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "PhysAddress", NULL}, "2.14"},
{0}
};

DMLEAF tHostsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HostNumberOfEntries", &DMREAD, DMT_UNINT, get_Hosts_HostNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"AccessControlNumberOfEntries", &DMREAD, DMT_UNINT, get_Hosts_AccessControlNumberOfEntries, NULL, BBFDM_BOTH, "2.14"},
{0}
};

/* *** Device.Hosts.Host.{i}. *** */
DMOBJ tHostsHostObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseHostsHostIPv4AddressInst, NULL, NULL, NULL, tHostsHostIPv4AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"IPAddress", NULL}, "2.2"},
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseHostsHostIPv6AddressInst, NULL, NULL, NULL, tHostsHostIPv6AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"IPAddress", NULL}, "2.2"},
{"WANStats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tHostsHostWANStatsParams, NULL, BBFDM_BOTH, NULL, "2.12"},
{0}
};

DMLEAF tHostsHostParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"PhysAddress", &DMREAD, DMT_STRING, get_HostsHost_PhysAddress, NULL, BBFDM_BOTH, "2.0"},
{"IPAddress", &DMREAD, DMT_STRING, get_HostsHost_IPAddress, NULL, BBFDM_BOTH, "2.0"},
{"DHCPClient", &DMREAD, DMT_STRING, get_HostsHost_DHCPClient, NULL, BBFDM_BOTH, "2.0"},
{"AssociatedDevice", &DMREAD, DMT_STRING, get_HostsHost_AssociatedDevice, NULL, BBFDM_BOTH, "2.2"},
{"Layer1Interface", &DMREAD, DMT_STRING, get_HostsHost_Layer1Interface, NULL, BBFDM_BOTH, "2.0"},
{"Layer3Interface", &DMREAD, DMT_STRING, get_HostsHost_Layer3Interface, NULL, BBFDM_BOTH, "2.0"},
{"InterfaceType", &DMREAD, DMT_STRING, get_HostsHost_InterfaceType, NULL, BBFDM_BOTH, "2.0"},
{"HostName", &DMREAD, DMT_STRING, get_HostsHost_HostName, NULL, BBFDM_BOTH, "2.0"},
{"Active", &DMREAD, DMT_BOOL, get_HostsHost_Active, NULL, BBFDM_BOTH, "2.0"},
{"ActiveLastChange", &DMREAD, DMT_TIME, get_HostsHost_ActiveLastChange, NULL, BBFDM_BOTH, "2.10"},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_HostsHost_IPv4AddressNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_HostsHost_IPv6AddressNumberOfEntries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Hosts.Host.{i}.IPv4Address.{i}. *** */
DMLEAF tHostsHostIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IPAddress", &DMREAD, DMT_STRING, get_HostsHostIPv4Address_IPAddress, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Hosts.Host.{i}.IPv6Address.{i}. *** */
DMLEAF tHostsHostIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IPAddress", &DMREAD, DMT_STRING, get_HostsHostIPv6Address_IPAddress, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Hosts.Host.{i}.WANStats. *** */
DMLEAF tHostsHostWANStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNINT, get_HostsHostWANStats_BytesSent, NULL, BBFDM_BOTH, "2.12"},
{"BytesReceived", &DMREAD, DMT_UNINT, get_HostsHostWANStats_BytesReceived, NULL, BBFDM_BOTH, "2.12"},
{"PacketsSent", &DMREAD, DMT_UNINT, get_HostsHostWANStats_PacketsSent, NULL, BBFDM_BOTH, "2.12"},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_HostsHostWANStats_PacketsReceived, NULL, BBFDM_BOTH, "2.12"},
{0}
};

/* *** Device.Hosts.AccessControl.{i}. *** */
DMOBJ tHostsAccessControlObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Schedule", &DMWRITE, addObjHostsAccessControlSchedule, delObjHostsAccessControlSchedule, NULL, browseHostsAccessControlScheduleInst, NULL, NULL, NULL, tHostsAccessControlScheduleParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.14"},
{0}
};

DMLEAF tHostsAccessControlParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_HostsAccessControl_Alias, set_HostsAccessControl_Alias, BBFDM_BOTH, "2.14"},
{"PhysAddress", &DMWRITE, DMT_STRING, get_HostsAccessControl_PhysAddress, set_HostsAccessControl_PhysAddress, BBFDM_BOTH, "2.14"},
{"HostName", &DMWRITE, DMT_STRING, get_HostsAccessControl_HostName, set_HostsAccessControl_HostName, BBFDM_BOTH, "2.14"},
{"Enable", &DMWRITE, DMT_BOOL, get_HostsAccessControl_Enable, set_HostsAccessControl_Enable, BBFDM_BOTH, "2.14"},
{"AccessPolicy", &DMWRITE, DMT_STRING, get_HostsAccessControl_AccessPolicy, set_HostsAccessControl_AccessPolicy, BBFDM_BOTH, "2.14"},
{"ScheduleNumberOfEntries", &DMREAD, DMT_UNINT, get_HostsAccessControl_ScheduleNumberOfEntries, NULL, BBFDM_BOTH, "2.14"},
{0}
};

/* *** Device.Hosts.AccessControl.{i}.Schedule.{i}. *** */
DMLEAF tHostsAccessControlScheduleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_HostsAccessControlSchedule_Alias, set_HostsAccessControlSchedule_Alias, BBFDM_BOTH, "2.14"},
{"Enable", &DMWRITE, DMT_BOOL, get_HostsAccessControlSchedule_Enable, set_HostsAccessControlSchedule_Enable, BBFDM_BOTH, "2.14"},
{"Day", &DMWRITE, DMT_STRING, get_HostsAccessControlSchedule_Day, set_HostsAccessControlSchedule_Day, BBFDM_BOTH, "2.14"},
{"StartTime", &DMWRITE, DMT_STRING, get_HostsAccessControlSchedule_StartTime, set_HostsAccessControlSchedule_StartTime, BBFDM_BOTH, "2.14"},
{"Duration", &DMWRITE, DMT_UNINT, get_HostsAccessControlSchedule_Duration, set_HostsAccessControlSchedule_Duration, BBFDM_BOTH, "2.14"},
{0}
};
