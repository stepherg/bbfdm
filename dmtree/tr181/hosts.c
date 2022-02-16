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
#include "dmentry.h"

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

/*************************************************************
* LINKER
**************************************************************/
static int get_linker_host(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = dmjson_get_value((json_object *)data, 1, "ipaddr");
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
	char *linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	adm_entry_get_linker_param(ctx, "Device.WiFi.AccessPoint.", linker, value);
	return 0;
}

static int get_HostsHost_Layer1Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "device");
	char *type = dmjson_get_value((json_object *)data, 1, "interface_type");
	if (DM_STRCMP(type, "Wi-Fi") == 0)
		adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", linker, value);
	else
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
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

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.Hosts. *** */
DMOBJ tHostsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Host", &DMREAD, NULL, NULL, NULL, browseHostsHostInst, NULL, NULL, tHostsHostObj, tHostsHostParams, get_linker_host, BBFDM_BOTH, LIST_KEY{"PhysAddress", NULL}, "2.0"},
{0}
};

DMLEAF tHostsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HostNumberOfEntries", &DMREAD, DMT_UNINT, get_Hosts_HostNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
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
