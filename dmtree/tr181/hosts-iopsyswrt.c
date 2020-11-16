/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "os.h"
#include "dmentry.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Hosts.Host.{i}.!UBUS:router.network/hosts//hosts*/
int os__browseHostsHostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *host_obj = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("router.network", "hosts", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, host_obj, i, 1, "hosts") {
			inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)host_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv4Address.{i}.!UBUS:router.network/hosts//hosts[@i-1].ipv4addr*/
int os__browseHostsHostIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ip_arr, *host_obj = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL, *ipv4addr = NULL;
	int id = 0, i = 0;

	dmjson_foreach_value_in_array(host_obj, ip_arr, ipv4addr, i, 1, "ipv4addr") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv4addr, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv6Address.{i}.!UBUS:router.network/hosts//hosts[@i-1].ipv6addr*/
int os__browseHostsHostIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ip_arr, *host_obj = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL, *ipv6addr = NULL;
	int id = 0, i = 0;

	dmjson_foreach_value_in_array(host_obj, ip_arr, ipv6addr, i, 1, "ipv6addr") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv6addr, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* LINKER
**************************************************************/
int get_linker_host(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = dmjson_get_value((json_object *)data, 1, "ipaddr");
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Hosts.HostNumberOfEntries!UBUS:router.network/hosts//hosts*/
int os__get_Hosts_HostNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *hosts = NULL;
	size_t nbre_hosts = 0;

	dmubus_call("router.network", "hosts", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "hosts", &hosts);
	nbre_hosts = (hosts) ? json_object_array_length(hosts) : 0;
	dmasprintf(value, "%d", nbre_hosts);
	return 0;
}

/*#Device.Hosts.Host.{i}.PhysAddress!UBUS:router.network/hosts//hosts[@i-1].macaddr*/
int os__get_HostsHost_PhysAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddr");
	return 0;
}

/*#Device.Hosts.Host.{i}.IPAddress!UBUS:router.network/hosts//hosts[@i-1].ipaddr*/
int os__get_HostsHost_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipaddr");
	return 0;
}

int os__get_HostsHost_DHCPClient(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cDHCPv4%cServer%cPool%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int os__get_HostsHost_AssociatedDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cAccessPoint%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int os__get_HostsHost_Layer1Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "device");
	char *type = dmjson_get_value((json_object *)data, 1, "type");
	if (strcmp(type, "wifi") == 0)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	else
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int os__get_HostsHost_Layer3Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "network");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

/*#Device.Hosts.Host.{i}.InterfaceType!UBUS:router.network/hosts//hosts[@i-1].type*/
int os__get_HostsHost_InterfaceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "type");
	*value = (strcmp(*value, "ethernet") == 0) ? "Ethernet" : "Wi-Fi";
	return 0;
}

/*#Device.Hosts.Host.{i}.HostName!UBUS:router.network/hosts//hosts[@i-1].hostname*/
int os__get_HostsHost_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "hostname");
	return 0;
}

/*#Device.Hosts.Host.{i}.Active!UBUS:router.network/hosts//hosts[@i-1].active*/
int os__get_HostsHost_Active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "active");
	return 0;
}

/*#Device.Hosts.Host.{i}.ActiveLastChange!UBUS:router.network/hosts//hosts[@i-1].activelstch*/
int os__get_HostsHost_ActiveLastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";

	char *lastchange = dmjson_get_value((json_object *)data, 1, "activelstch");
	if (lastchange && *lastchange != '\0' && atoi(lastchange) > 0) {
		time_t t_time = atoi(lastchange);
		if (localtime(&t_time) == NULL)
			return -1;

		char local_time[32] = {0};

		if (strftime(local_time, sizeof(local_time), "%Y-%m-%dT%H:%M:%SZ", localtime(&t_time)) == 0)
			return -1;

		*value = dmstrdup(local_time);
	}
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv4AddressNumberOfEntries!UBUS:router.network/hosts//hosts[@i-1].ipv4addr*/
int os__get_HostsHost_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *ipv4addr = NULL;
	size_t nbre_addr = 0;

	json_object_object_get_ex((json_object *)data, "ipv4addr", &ipv4addr);
	nbre_addr = (ipv4addr) ? json_object_array_length(ipv4addr) : 0;
	dmasprintf(value, "%d", nbre_addr);
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv6AddressNumberOfEntries!UBUS:router.network/hosts//hosts[@i-1].ipv6addr*/
int os__get_HostsHost_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *ipv6addr = NULL;
	size_t nbre_addr = 0;

	json_object_object_get_ex((json_object *)data, "ipv6addr", &ipv6addr);
	nbre_addr = (ipv6addr) ? json_object_array_length(ipv6addr) : 0;
	dmasprintf(value, "%d", nbre_addr);
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv4Address.{i}.IPAddress!UBUS:router.network/hosts//hosts[@i-1].ipv4addr[@i-1]*/
int os__get_HostsHostIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)data;
	return 0;
}

/*#Device.Hosts.Host.{i}.IPv6Address.{i}.IPAddress!UBUS:router.network/hosts//hosts[@i-1].ipv6addr[@i-1]*/
int os__get_HostsHostIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)data;
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.BytesSent!UBUS:router.network/hosts//hosts[@i-1].stats.tx_bytes*/
int os__get_HostsHostWANStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_bytes");
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.BytesReceived!UBUS:router.network/hosts//hosts[@i-1].stats.rx_bytes*/
int os__get_HostsHostWANStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_bytes");
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.PacketsSent!UBUS:router.network/hosts//hosts[@i-1].stats.tx_packets*/
int os__get_HostsHostWANStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_packets");
	return 0;
}

/*#Device.Hosts.Host.{i}.WANStats.PacketsReceived!UBUS:router.network/hosts//hosts[@i-1].stats.rx_packets*/
int os__get_HostsHostWANStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_packets");
	return 0;
}
