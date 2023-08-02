/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "ethernet.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseEthernetMACVLANInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);
	char *inst = NULL;

	synchronize_specific_config_sections_with_dmmap_eq("network", "device", "dmmap_network", "type", "macvlan", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "mac_vlan_instance", "mac_vlan_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* LINKER
**************************************************************/
static int get_linker_mac_vlan(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", linker);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjEthernetMACVLAN(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_network = NULL;
	char device_name[32];

	snprintf(device_name, sizeof(device_name), "mac_vlan_%s", *instance);

	// Add device section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "macvlan");

	// Add device section in dmmap_network file
	dmuci_add_section_bbfdm("dmmap_network", "device", &dmmap_network);
	dmuci_set_value_by_section(dmmap_network, "section_name", device_name);
	dmuci_set_value_by_section(dmmap_network, "mac_vlan_instance", *instance);
	return 0;
}

static int delObjEthernetMACVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		// Remove device section
		dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);

		// Remove device section in dmmap_network file
		dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_option_eq_safe("network", "device", "type", "macvlan", stmp, s) {

			// Remove dmmap section
			struct uci_section *dmmap_section = NULL;
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove device section
			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_EthernetMACVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "1");
	return 0;
}

static int set_EthernetMACVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_EthernetMACVLAN_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", &device);
	return get_net_device_status(device, value);
}

static int get_EthernetMACVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "mac_vlan_alias", instance, value);
}

static int set_EthernetMACVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "mac_vlan_alias", instance, value);
}

static int get_EthernetMACVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", value);
	return 0;
}

static int get_EthernetMACVLAN_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ifname", &linker);
		if (!linker || *linker == '\0')
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.VLANTermination.", linker, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Link.", linker, value);
	} else {
		adm_entry_get_linker_value(ctx, *value, &linker);
		if (!linker || *linker == 0)
			*value = "";
	}
	return 0;
}

static int set_EthernetMACVLAN_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.Ethernet.VLANTermination.",
			"Device.Ethernet.Link.",
			NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);

			// Store LowerLayers value under dmmap section
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "LowerLayers", value);

			if (DM_STRLEN(linker)) {
				char name[16] = {0};

				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ifname", linker);

				char *vid = DM_STRCHR(linker, '.');
				if (vid) *vid = 0;

				snprintf(name, sizeof(name), "%s_%s", linker, instance);

				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", name);
			} else {
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ifname", "");
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", "");

			}
			break;
	}
	return 0;
}

static int get_EthernetMACVLAN_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "macaddr", value);
	return 0;
}

static int set_EthernetMACVLAN_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "macaddr", value);
			break;
	}
	return 0;
}

static int eth_macvlan_sysfs(const struct uci_section *data, const char *name, char **value)
{
	char *device;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", &device);
	return get_net_device_sysfs(device, name, value);
}

static int get_EthernetMACVLANStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/tx_bytes", value);
}

static int get_EthernetMACVLANStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/rx_bytes", value);
}

static int get_EthernetMACVLANStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/tx_packets", value);
}

static int get_EthernetMACVLANStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/rx_packets", value);
}

static int get_EthernetMACVLANStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/tx_errors", value);
}

static int get_EthernetMACVLANStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/rx_errors", value);
}

static int get_EthernetMACVLANStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/tx_dropped", value);
}

static int get_EthernetMACVLANStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/rx_dropped", value);
}

static int get_EthernetMACVLANStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_macvlan_sysfs(data, "statistics/multicast", value);
}
/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMOBJ tIOPSYS_EthernetObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{BBF_VENDOR_PREFIX"MACVLAN", &DMWRITE, addObjEthernetMACVLAN, delObjEthernetMACVLAN, NULL, browseEthernetMACVLANInst, NULL, NULL, tEthernetMACVLANObj, tEthernetMACVLANParams, get_linker_mac_vlan, BBFDM_BOTH, NULL, "2.16"},
{0}
};

DMLEAF tEthernetMACVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetMACVLAN_Enable, set_EthernetMACVLAN_Enable, BBFDM_BOTH, "2.16"},
{"Status", &DMREAD, DMT_STRING, get_EthernetMACVLAN_Status, NULL, BBFDM_BOTH, "2.16"},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetMACVLAN_Alias, set_EthernetMACVLAN_Alias, BBFDM_BOTH, "2.16"},
{"Name", &DMREAD, DMT_STRING, get_EthernetMACVLAN_Name, NULL, BBFDM_BOTH, "2.16"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetMACVLAN_LowerLayers, set_EthernetMACVLAN_LowerLayers, BBFDM_BOTH, "2.16"},
{"MACAddress", &DMWRITE, DMT_STRING, get_EthernetMACVLAN_MACAddress, set_EthernetMACVLAN_MACAddress, BBFDM_BOTH, "2.16"},
{0}
};

DMOBJ tEthernetMACVLANObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetMACVLANStatsParams, NULL, BBFDM_BOTH, NULL, "2.16"},
{0}
};

DMLEAF tEthernetMACVLANStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_BytesSent, NULL, BBFDM_BOTH, "2.16"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_BytesReceived, NULL, BBFDM_BOTH, "2.16"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_PacketsSent, NULL, BBFDM_BOTH, "2.16"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_PacketsReceived, NULL, BBFDM_BOTH, "2.16"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_ErrorsSent, NULL, BBFDM_BOTH, "2.16"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.16"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.16"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.16"},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_MulticastPacketsReceived, NULL, BBFDM_BOTH, "2.16"},
{0}
};
