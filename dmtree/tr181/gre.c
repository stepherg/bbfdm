/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "gre.h"

/*************************************************************
* ENTRY METHOD
*************************************************************/
static int browseGRETunnelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_network", "proto", "gre", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "gretunnel_instance", "gretunnel_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static struct uci_section *has_tunnel_interface_route(char *interface)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "route", "interface", interface, s) {
		return s;
	}
	return NULL;
}

static int browseGRETunnelInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, device[128] = {0};
	struct dmmap_dup *p = NULL, *dm = (struct dmmap_dup *)prev_data;
	struct uci_section *s = NULL;
	LIST_HEAD(dup_list);

	snprintf(device, sizeof(device), "@%s", section_name(dm->config_section));
	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_network", "device", device, &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		if ((s = has_tunnel_interface_route(section_name(p->config_section))) == NULL)
			continue;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "greiface_instance", "greiface_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
*************************************************************/
static int addObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *gre_sec = NULL, *dmmap_sec = NULL;

	dmuci_add_section("network", "interface", &gre_sec);
	dmuci_set_value_by_section(gre_sec, "proto", "gre");

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(gre_sec));
	dmuci_set_value_by_section(dmmap_sec, "gretunnel_instance", *instance);
	return 0;
}

static int delObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "gretunnel_instance", "");
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "gretunnel_alias", "");
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("network", "interface", "proto", "gre", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(s), &dmmap_section);
				dmuci_set_value_by_section(dmmap_section, "gretunnel_instance", "");
				dmuci_set_value_by_section(dmmap_section, "gretunnel_alias", "");

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *greiface_sec = NULL, *dmmap_sec = NULL, *route_sec = NULL;
	char device_buf[32];

	dmuci_add_section("network", "interface", &greiface_sec);
	snprintf(device_buf, sizeof(device_buf), "@%s", section_name(((struct dmmap_dup *)data)->config_section));
	dmuci_set_value_by_section(greiface_sec, "device", device_buf);

	dmuci_add_section("network", "route", &route_sec);
	dmuci_set_value_by_section(route_sec, "interface", section_name(greiface_sec));

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(greiface_sec));
	dmuci_set_value_by_section(dmmap_sec, "gre_tunnel_sect", section_name(((struct dmmap_dup *)data)->config_section));
	dmuci_set_value_by_section(dmmap_sec, "greiface_instance", *instance);
	return 0;
}

static int delObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "greiface_instance", "");
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "greiface_alias", "");

			if ((s = has_tunnel_interface_route(section_name(((struct dmmap_dup *)data)->config_section))) != NULL)
				dmuci_delete_by_section(s, NULL, NULL);

			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("network", "interface", stmp, s) {
				struct uci_section *ss = NULL, *dmmap_section = NULL;
				char device_buf[32] = {0};
				char *device = NULL;

				dmuci_get_value_by_section_string(s, "device", &device);
				snprintf(device_buf, sizeof(device_buf), "@%s", section_name(((struct dmmap_dup *)data)->config_section));

				if (!device || DM_STRCMP(device, device_buf) != 0)
					continue;

				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(s), &dmmap_section);
				dmuci_set_value_by_section(dmmap_section, "greiface_instance", "");
				dmuci_set_value_by_section(dmmap_section, "greiface_alias", "");

				if ((ss = has_tunnel_interface_route(section_name(s))) != NULL)
					dmuci_delete_by_section(ss, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
*************************************************************/
static char *get_gre_tunnel_interface_statistics(char *interface, char *key)
{
	json_object *res = NULL, *diag = NULL;
	char *device, *value = "0";

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	if (!res) return value;
	device = dmjson_get_value(res, 1, "device");
	if(device[0] != '\0') {
		dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &diag);
		if (diag)
			value = dmjson_get_value(diag, 2, "statistics", key);
	}
	return value;
}

static int get_GRE_TunnelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseGRETunnelInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.GRE.Tunnel.{i}.Alias!UCI:dmmap_network/interface,@i-1/gretunnel_alias*/
static int get_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "gretunnel_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "gretunnel_alias", value);
			break;
	}
	return 0;
}

static int get_GRETunnel_KeepAliveThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "keepalive", "3");
	return 0;
}

static int set_GRETunnel_KeepAliveThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "keepalive", value);
			break;
	}
	return 0;
}

static int get_GRETunnel_ConnectedRemoteEndpoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "peeraddr", value);
	return 0;
}

static int get_GRETunnel_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseGRETunnelInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_GRETunnelStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_bytes");
	return 0;
}

static int get_GRETunnelStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_bytes");
	return 0;
}

static int get_GRETunnelStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_packets");
	return 0;
}

static int get_GRETunnelStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_packets");
	return 0;
}

static int get_GRETunnelStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_errors");
	return 0;
}

static int get_GRETunnelStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_errors");
	return 0;
}

/*#Device.GRE.Tunnel.{i}.Interface.{i}.Alias!UCI:dmmap_network/interface,@i-1/greiface_alias*/
static int get_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "greiface_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "greiface_alias", value);
			break;
	}
	return 0;
}

static int get_GRETunnelInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct dmmap_dup *)data)->config_section));
	return 0;
}

static int get_GRETunnelInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_bytes");
	return 0;
}

static int get_GRETunnelInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_bytes");
	return 0;
}

static int get_GRETunnelInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_packets");
	return 0;
}

static int get_GRETunnelInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_packets");
	return 0;
}

static int get_GRETunnelInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_errors");
	return 0;
}

static int get_GRETunnelInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_errors");
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.GRE. *** */
DMOBJ tGREObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Tunnel", &DMWRITE, addObjGRETunnel, delObjGRETunnel, NULL, browseGRETunnelInst, NULL, NULL, tGRETunnelObj, tGRETunnelParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.8"},
//{"Filter", &DMWRITE, addObjGREFilter, delObjGREFilter, NULL, browseGREFilterInst, NULL, NULL, NULL, tGREFilterParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.8"},
{0}
};

DMLEAF tGREParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version, version*/
{"TunnelNumberOfEntries", &DMREAD, DMT_UNINT, get_GRE_TunnelNumberOfEntries, NULL, BBFDM_BOTH, "2.8"},
//{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_GRE_FilterNumberOfEntries, NULL, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.GRE.Tunnel.{i}. *** */
DMOBJ tGRETunnelObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGRETunnelStatsParams, NULL, BBFDM_BOTH, NULL, "2.8"},
{"Interface", &DMWRITE, addObjGRETunnelInterface, delObjGRETunnelInterface, NULL, browseGRETunnelInterfaceInst, NULL, NULL, tGRETunnelInterfaceObj, tGRETunnelInterfaceParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.8"},
{0}
};

DMLEAF tGRETunnelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_GRETunnel_Enable, set_GRETunnel_Enable, BBFDM_BOTH, "2.8"},
//{"Status", &DMREAD, DMT_STRING, get_GRETunnel_Status, NULL, BBFDM_BOTH, "2.8"},
{"Alias", &DMWRITE, DMT_STRING, get_GRETunnel_Alias, set_GRETunnel_Alias, BBFDM_BOTH, "2.8"},
//{"RemoteEndpoints", &DMWRITE, DMT_STRING, get_GRETunnel_RemoteEndpoints, set_GRETunnel_RemoteEndpoints, BBFDM_BOTH, "2.8"},
//{"KeepAlivePolicy", &DMWRITE, DMT_STRING, get_GRETunnel_KeepAlivePolicy, set_GRETunnel_KeepAlivePolicy, BBFDM_BOTH, "2.8"},
//{"KeepAliveTimeout", &DMWRITE, DMT_UNINT, get_GRETunnel_KeepAliveTimeout, set_GRETunnel_KeepAliveTimeout, BBFDM_BOTH, "2.8"},
{"KeepAliveThreshold", &DMWRITE, DMT_UNINT, get_GRETunnel_KeepAliveThreshold, set_GRETunnel_KeepAliveThreshold, BBFDM_BOTH, "2.8"},
//{"DeliveryHeaderProtocol", &DMWRITE, DMT_STRING, get_GRETunnel_DeliveryHeaderProtocol, set_GRETunnel_DeliveryHeaderProtocol, BBFDM_BOTH, "2.8"},
//{"DefaultDSCPMark", &DMWRITE, DMT_UNINT, get_GRETunnel_DefaultDSCPMark, set_GRETunnel_DefaultDSCPMark, BBFDM_BOTH, "2.8"},
{"ConnectedRemoteEndpoint", &DMREAD, DMT_STRING, get_GRETunnel_ConnectedRemoteEndpoint, NULL, BBFDM_BOTH, "2.8"},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_GRETunnel_InterfaceNumberOfEntries, NULL, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Stats. *** */
DMLEAF tGRETunnelStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"KeepAliveSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_KeepAliveSent, NULL, BBFDM_BOTH, "2.8"},
//{"KeepAliveReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_KeepAliveReceived, NULL, BBFDM_BOTH, "2.8"},
{"BytesSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_BytesSent, NULL, BBFDM_BOTH, "2.8"},
{"BytesReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_BytesReceived, NULL, BBFDM_BOTH, "2.8"},
{"PacketsSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_PacketsSent, NULL, BBFDM_BOTH, "2.8"},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_PacketsReceived, NULL, BBFDM_BOTH, "2.8"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_ErrorsSent, NULL, BBFDM_BOTH, "2.8"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Interface.{i}. *** */
DMOBJ tGRETunnelInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGRETunnelInterfaceStatsParams, NULL, BBFDM_BOTH, NULL, "2.8"},
{0}
};

DMLEAF tGRETunnelInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_Enable, set_GRETunnelInterface_Enable, BBFDM_BOTH, "2.8"},
//{"Status", &DMREAD, DMT_STRING, get_GRETunnelInterface_Status, NULL, BBFDM_BOTH, "2.8"},
{"Alias", &DMWRITE, DMT_STRING, get_GRETunnelInterface_Alias, set_GRETunnelInterface_Alias, BBFDM_BOTH, "2.8"},
{"Name", &DMREAD, DMT_STRING, get_GRETunnelInterface_Name, NULL, BBFDM_BOTH, "2.8"},
//{"LastChange", &DMREAD, DMT_UNINT, get_GRETunnelInterface_LastChange, NULL, BBFDM_BOTH, "2.8"},
//{"LowerLayers", &DMWRITE, DMT_STRING, get_GRETunnelInterface_LowerLayers, set_GRETunnelInterface_LowerLayers, BBFDM_BOTH, "2.8"},
//{"ProtocolIdOverride", &DMWRITE, DMT_UNINT, get_GRETunnelInterface_ProtocolIdOverride, set_GRETunnelInterface_ProtocolIdOverride, BBFDM_BOTH, "2.8"},
//{"UseChecksum", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_UseChecksum, set_GRETunnelInterface_UseChecksum, BBFDM_BOTH, "2.8"},
//{"KeyIdentifierGenerationPolicy", &DMWRITE, DMT_STRING, get_GRETunnelInterface_KeyIdentifierGenerationPolicy, set_GRETunnelInterface_KeyIdentifierGenerationPolicy, BBFDM_BOTH, "2.8"},
//{"KeyIdentifier", &DMWRITE, DMT_UNINT, get_GRETunnelInterface_KeyIdentifier, set_GRETunnelInterface_KeyIdentifier, BBFDM_BOTH, "2.8"},
//{"UseSequenceNumber", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_UseSequenceNumber, set_GRETunnelInterface_UseSequenceNumber, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Interface.{i}.Stats. *** */
DMLEAF tGRETunnelInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_BytesSent, NULL, BBFDM_BOTH, "2.8"},
{"BytesReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_BytesReceived, NULL, BBFDM_BOTH, "2.8"},
{"PacketsSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_PacketsSent, NULL, BBFDM_BOTH, "2.8"},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH, "2.8"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH, "2.8"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.8"},
//{"DiscardChecksumReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_DiscardChecksumReceived, NULL, BBFDM_BOTH, "2.8"},
//{"DiscardSequenceNumberReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_DiscardSequenceNumberReceived, NULL, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.GRE.Filter.{i}. *** */
DMLEAF tGREFilterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_GREFilter_Enable, set_GREFilter_Enable, BBFDM_BOTH, "2.8"},
//{"Status", &DMREAD, DMT_STRING, get_GREFilter_Status, NULL, BBFDM_BOTH, "2.8"},
//{"Order", &DMWRITE, DMT_UNINT, get_GREFilter_Order, set_GREFilter_Order, BBFDM_BOTH, "2.8"},
//{"Alias", &DMWRITE, DMT_STRING, get_GREFilter_Alias, set_GREFilter_Alias, BBFDM_BOTH, "2.8"},
//{"Interface", &DMWRITE, DMT_STRING, get_GREFilter_Interface, set_GREFilter_Interface, BBFDM_BOTH, "2.8"},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_GREFilter_AllInterfaces, set_GREFilter_AllInterfaces, BBFDM_BOTH, "2.8"},
//{"VLANIDCheck", &DMWRITE, DMT_INT, get_GREFilter_VLANIDCheck, set_GREFilter_VLANIDCheck, BBFDM_BOTH, "2.8"},
//{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_GREFilter_VLANIDExclude, set_GREFilter_VLANIDExclude, BBFDM_BOTH, "2.8"},
//{"DSCPMarkPolicy", &DMWRITE, DMT_INT, get_GREFilter_DSCPMarkPolicy, set_GREFilter_DSCPMarkPolicy, BBFDM_BOTH, "2.8"},
{0}
};
