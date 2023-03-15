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

static int get_EthernetMACVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_EthernetMACVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			//TODO
			break;
	}
	return 0;
}

static int get_EthernetMACVLAN_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
	return get_net_device_status(device, value);
}

static int get_EthernetMACVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "link_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_EthernetMACVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "link_alias", value);
			break;
	}
	return 0;
}

static int get_EthernetMACVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", value);
	return 0;
}

static int get_EthernetMACVLAN_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		dmuci_get_value_by_section_string((struct uci_section *)data, "device", &linker);
		if (!linker || *linker == '\0')
			return 0;

		adm_entry_get_linker_param(ctx, "Device.ATM.Link.", linker, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.PTM.Link.", linker, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", linker, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
	} else {
		adm_entry_get_linker_value(ctx, *value, &linker);
		if (!linker || *linker == 0)
			*value = "";
	}
	return 0;
}

static int set_EthernetMACVLAN_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char eth_interface[64] = "Device.Ethernet.Interface.";
	char bridge_port[64] = "Device.Bridging.Bridge.*.Port.";
	char atm_link[32] = "Device.ATM.Link.";
	char ptm_link[32] = "Device.PTM.Link.";
	char *allowed_objects[] = {
			eth_interface,
			bridge_port,
			atm_link,
			ptm_link,
			NULL};
	char *link_linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &link_linker);

			// Store LowerLayers value under dmmap section
			dmuci_set_value_by_section((struct uci_section *)data, "LowerLayers", value);

			if (!link_linker || link_linker[0] == 0) {
				dmuci_set_value_by_section((struct uci_section *)data, "device", "");
			}
			break;
	}
	return 0;
}

static int get_EthernetMACVLAN_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "mac", value);
	return 0;
}

static int eth_iface_sysfs(const struct uci_section *data, const char *name, char **value)
{
	char *device;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
	return get_net_device_sysfs(device, name, value);
}

static int get_EthernetMACVLANStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_bytes", value);
}

static int get_EthernetMACVLANStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_bytes", value);
}

static int get_EthernetMACVLANStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_packets", value);
}

static int get_EthernetMACVLANStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_packets", value);
}

static int get_EthernetMACVLANStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_errors", value);
}

static int get_EthernetMACVLANStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_errors", value);
}

static int get_EthernetMACVLANStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_dropped", value);
}

static int get_EthernetMACVLANStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_dropped", value);
}

static int get_EthernetMACVLANStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/multicast", value);
}
/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMOBJ tIOPSYS_EthernetObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{BBF_VENDOR_PREFIX"MACVLAN", &DMWRITE, NULL, NULL, NULL, NULL, NULL, NULL, X_IOPSYS_EU_MACVLANObj, X_IOPSYS_EU_MACVLANParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_MACVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetMACVLAN_Enable, set_EthernetMACVLAN_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_EthernetMACVLAN_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetMACVLAN_Alias, set_EthernetMACVLAN_Alias, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_EthernetMACVLAN_Name, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetMACVLAN_LowerLayers, set_EthernetMACVLAN_LowerLayers, BBFDM_BOTH, "2.0"},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetMACVLAN_MACAddress, NULL, BBFDM_BOTH, "2.0"},
{0}
};

DMOBJ X_IOPSYS_EU_MACVLANObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, X_IOPSYS_EU_MACVLANStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_MACVLANStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_BytesSent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_BytesReceived, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_PacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_PacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetMACVLANStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetMACVLANStats_MulticastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{0}
};
