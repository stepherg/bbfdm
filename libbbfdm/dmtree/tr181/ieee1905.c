/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *      Author: Nevadita Chatterjee <nevadita.chatterjee@iopsys.eu>
 */

#include "ieee1905.h"

struct ieee1905_device_args
{
	char *mac_addr;
	json_object *dev_obj;
};

struct ieee1905_device_nonieee1905neighbor_args
{
	char *mac_addr;
	char *neighbor;
};

struct ieee1905_device_ieee1905neighbor_args
{
	char *mac_addr;
	char *neighbor_device_id;
	char *neighbor_macaddress;
	char *num_metrics;
	json_object *dev_obj;
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.IEEE1905.AL.Interface.{i}.!UBUS:ieee1905/info//interface*/
static int browseIEEE1905ALInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *interface_obj = NULL, *arrobj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("ieee1905", "info", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, interface_obj, i, 1, "interface") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)interface_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}.!UBUS:ieee1905/info//interface[@i-1].properties*/
static int browseIEEE1905ALInterfaceVendorPropertiesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *propertie_obj = NULL, *interface = (json_object *)prev_data;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(interface, arrobj, propertie_obj, i, 1, "properties") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)propertie_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.!UBUS:ieee1905/info//interface[@i-1].links*/
static int browseIEEE1905ALInterfaceLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *link_obj = NULL, *interface = (json_object *)prev_data;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(interface, arrobj, link_obj, i, 1, "links") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)link_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.!UCI:ieee1905/forwarding_rule/dmmap_forwarding_rule*/
static int browseIEEE1905ALForwardingTableForwardingRuleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ieee1905", "forwarding_rule", "dmmap_forwarding_rule", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "forwardingruleinstance", "forwardingrulealias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

#if 0
static int browseIEEE1905ALNetworkTopologyChangeLogInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.!UBUS:ieee1905/info//topology.device*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *device_obj = NULL, *arrobj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("ieee1905", "info", UBUS_ARGS{0}, 0, &res);
	if (!res)
		return 0;

	// Self node in the network
	inst = handle_instance_without_section(dmctx, parent_node, ++id);
	if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)res, inst) == DM_STOP)
		return 0;

	// Discovered 1905 Devices in the network
	dmjson_foreach_obj_in_array(res, arrobj, device_obj, i, 2, "topology", "device") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)device_obj, inst) == DM_STOP)
			break;
	}

	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ip4arrobj = NULL, *ipv4_address = NULL, *ifacearrobj = NULL, *interface = NULL;
	struct ieee1905_device_args curr_ipv4address_args = {0};
	char *inst = NULL;
	int id = 0, i = 0, j = 0;

	if (DM_STRCMP(prev_instance, "1") == 0) { // Self node in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ifacearrobj, interface, i, 1, "interface") {
			curr_ipv4address_args.mac_addr = dmjson_get_value(interface, 1, "macaddress");
			dmjson_foreach_obj_in_array(interface, ip4arrobj, ipv4_address, j, 1, "ipv4_address") {
				curr_ipv4address_args.dev_obj = ipv4_address;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv4address_args, inst) == DM_STOP)
					goto end;
			}
		}
	} else { // Discovered 1905 Devices in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ip4arrobj, ipv4_address, i, 1, "ipv4_address") {
			curr_ipv4address_args.mac_addr = dmjson_get_value(ipv4_address, 1, "macaddress");
			curr_ipv4address_args.dev_obj = ipv4_address;
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv4address_args, inst) == DM_STOP)
				break;
		}
	}

end:
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ip6arrobj = NULL, *ipv6_address = NULL, *ifacearrobj = NULL, *interface = NULL;
	struct ieee1905_device_args curr_ipv6address_args = {0};
	char *inst = NULL;
	int id = 0, i = 0, j = 0;

	if (DM_STRCMP(prev_instance, "1") == 0) { // Self node in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ifacearrobj, interface, i, 1, "interface") {
			curr_ipv6address_args.mac_addr = dmjson_get_value(interface, 1, "macaddress");
			dmjson_foreach_obj_in_array(interface, ip6arrobj, ipv6_address, j, 1, "ipv6_address") {
				curr_ipv6address_args.dev_obj = ipv6_address;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv6address_args, inst) == DM_STOP)
					goto end;
			}
		}
	} else { // Discovered 1905 Devices in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ip6arrobj, ipv6_address, i, 1, "ipv6_address") {
			curr_ipv6address_args.mac_addr = dmjson_get_value(ipv6_address, 1, "macaddress");
			curr_ipv6address_args.dev_obj = ipv6_address;
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv6address_args, inst) == DM_STOP)
				break;
		}
	}

end:
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}.!UBUS:ieee1905/info//topology.device[@i-1].vendor_properties*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *vendor_properties = NULL, *ifacearrobj = NULL, *interface = NULL;
	char *inst = NULL;
	int id = 0, i = 0, j = 0;

	if (DM_STRCMP(prev_instance, "1") == 0) { // Self node in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ifacearrobj, interface, i, 1, "interface") {
			dmjson_foreach_obj_in_array(interface, arrobj, vendor_properties, j, 1, "properties") {
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)vendor_properties, inst) == DM_STOP)
					goto end;
			}
		}
	} else { // Discovered 1905 Devices in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, arrobj, vendor_properties, i, 1, "vendor_properties") {
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)vendor_properties, inst) == DM_STOP)
				break;
		}
	}

end:
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.!UBUS:ieee1905/info//topology.device[@i-1].interface*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *interface = NULL, *device = (json_object *)prev_data;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, interface, i, 1, "interface") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)interface, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.!UBUS:ieee1905/info//topology.device[@i-1].non1905_neighbors*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *non1905arrobj = NULL, *non1905 = NULL, *ifacearrobj = NULL, *interface = NULL, *neighbor_val = NULL;
	struct ieee1905_device_nonieee1905neighbor_args curr_nonieee1905neighbor_args = {0};
	char *inst = NULL, *neighbor = NULL;
	int id = 0, i = 0, j = 0;

	if (DM_STRCMP(prev_instance, "1") == 0) { // Self node in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ifacearrobj, interface, i, 1, "interface") {
			curr_nonieee1905neighbor_args.mac_addr = dmjson_get_value(interface, 1, "macaddress");
			dmjson_foreach_value_in_array(non1905, neighbor_val, neighbor, j, 1, "non1905_neighbors") {
				curr_nonieee1905neighbor_args.neighbor = neighbor;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_nonieee1905neighbor_args, inst) == DM_STOP)
					goto end;
			}
		}
	} else { // Discovered 1905 Devices in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, non1905arrobj, non1905, i, 1, "non1905_neighbors") {
			curr_nonieee1905neighbor_args.mac_addr = dmjson_get_value(non1905, 1, "interface_macaddress");
			dmjson_foreach_value_in_array(non1905, neighbor_val, neighbor, j, 1, "neighbors") {
				curr_nonieee1905neighbor_args.neighbor = neighbor;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_nonieee1905neighbor_args, inst) == DM_STOP)
					goto end;
			}
		}
	}

end:
	return 0;
}

#if 0
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ieee1905_neighborsarrobj = NULL, *ieee1905_neighbors = NULL, *ifacearrobj = NULL, *interface = NULL;
	struct ieee1905_device_ieee1905neighbor_args curr_ieee1905_neighbors_args = {0};
	char *inst = NULL;
	int id = 0, i = 0, j = 0;

	if (DM_STRCMP(prev_instance, "1") == 0) { // Self node in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ifacearrobj, interface, i, 1, "interface") {
			curr_ieee1905_neighbors_args.mac_addr = dmjson_get_value(interface, 1, "macaddress");
			dmjson_foreach_obj_in_array(interface, ieee1905_neighborsarrobj, ieee1905_neighbors, j, 1, "links") {
				curr_ieee1905_neighbors_args.neighbor_device_id = dmjson_get_value(ieee1905_neighbors, 1, "ieee1905id");
				curr_ieee1905_neighbors_args.num_metrics = "1";
				curr_ieee1905_neighbors_args.dev_obj = ieee1905_neighbors;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ieee1905_neighbors_args, inst) == DM_STOP)
					goto end;
			}
		}
	} else { // Discovered 1905 Devices in the network
		dmjson_foreach_obj_in_array((json_object *)prev_data, ieee1905_neighborsarrobj, ieee1905_neighbors, i, 1, "ieee1905_neighbors") {
			curr_ieee1905_neighbors_args.mac_addr = dmjson_get_value(ieee1905_neighbors, 1, "macaddress");
			curr_ieee1905_neighbors_args.neighbor_device_id = dmjson_get_value(ieee1905_neighbors, 1, "neighbor_device_id");
			curr_ieee1905_neighbors_args.num_metrics = dmjson_get_value(ieee1905_neighbors, 1, "num_metrics");
			curr_ieee1905_neighbors_args.dev_obj = ieee1905_neighbors;
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ieee1905_neighbors_args, inst) == DM_STOP)
				break;
		}
	}

end:
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.!UBUS:ieee1905/info//topology.device[@i-1].bridge_tuples*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *bridge_tuple = NULL, *device = (json_object *)prev_data;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, bridge_tuple, i, 1, "bridge_tuples") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bridge_tuple, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct ieee1905_device_ieee1905neighbor_args *ieee1905neighbor_arg = (struct ieee1905_device_ieee1905neighbor_args *)prev_data;
	json_object *arrobj = NULL, *metric = NULL, *ieee1905_neighbors = ieee1905neighbor_arg->dev_obj;
	char *inst = NULL;
	int id = 0, i = 0;

	json_object_object_get_ex(ieee1905_neighbors, "metric", &metric);
	if (metric && json_object_get_type(metric) == json_type_array) { // Discovered 1905 Devices in the network
		dmjson_foreach_obj_in_array(ieee1905_neighbors, arrobj, metric, i, 1, "metric") {
			ieee1905neighbor_arg->neighbor_macaddress = dmjson_get_value(metric, 1, "neighbor_macaddress");
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, inst) == DM_STOP)
				break;
		}
	} else { // Self node in the network
		ieee1905neighbor_arg->neighbor_macaddress = dmjson_get_value(ieee1905_neighbors, 1, "macaddress");
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, inst) == DM_STOP)
			goto end;
	}

end:
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjIEEE1905ALForwardingTableForwardingRule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	dmuci_add_section("ieee1905", "forwarding_rule", &s);

	dmuci_add_section_bbfdm("dmmap_forwarding_rule", "forwarding_rule", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "forwardingruleinstance", *instance);
	return 0;
}

static int delObjIEEE1905ALForwardingTableForwardingRule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
		dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("ieee1905", "forwarding_rule", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_forwarding_rule", "forwarding_rule", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static int ubus_ieee1905_info(const char *option, char **value)
{
	json_object *res = NULL;
	dmubus_call("ieee1905", "info", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, option);
	return 0;
}

static int ubus_ieee1905_info_options(const char *option1, const char *option2, char **value)
{
	json_object *res = NULL;
	dmubus_call("ieee1905", "info", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, option1, option2);
	return 0;
}

static char *get_datamodel_media_type(const char *media, const char *band)
{
	if (!DM_LSTRCMP(media, "IEEE 802_3U_FAST_ETHERNET"))
		return "IEEE 802.3u";
	else if (!DM_LSTRCMP(media, "IEEE 802_3AB_GIGABIT_ETHERNET"))
		return "IEEE 802.3ab";
	else if (!DM_LSTRCMP(media, "IEEE 802_11B"))
		return "IEEE 802.11b";
	else if (!DM_LSTRCMP(media, "IEEE 802_11G"))
		return "IEEE 802.11g";
	else if (!DM_LSTRCMP(media, "IEEE 802_11A"))
		return "IEEE 802.11a";
	else if (!DM_LSTRCMP(media, "IEEE 802_11N") && !DM_LSTRCMP(band, "2"))
		return "IEEE 802.11n 2.4";
	else if (!DM_LSTRCMP(media, "IEEE 802_11N") && !DM_LSTRCMP(band, "5"))
		return "IEEE 802.11n 5.0";
	else if (!DM_LSTRCMP(media, "IEEE 802_11AC"))
		return "IEEE 802.11ac";
	else if (!DM_LSTRCMP(media, "IEEE 802_11AX") && !DM_LSTRCMP(band, "2"))
		return "IEEE 802.11ax 2.4";
	else if (!DM_LSTRCMP(media, "IEEE 802_11AX") && !DM_LSTRCMP(band, "5"))
		return "IEEE 802.11ax 5.0";
	else if (!DM_LSTRCMP(media, "IEEE 802_11AX") && !DM_LSTRCMP(band, "6"))
		return "IEEE 802.11ax 6.0";
	else if (!DM_LSTRCMP(media, "IEEE 802_11AD") && !DM_LSTRCMP(band, "60"))
		return "IEEE 802.11ad";
	else if (!DM_LSTRCMP(media, "IEEE 802_11AF"))
		return "IEEE 802.11af";
	else if (!DM_LSTRCMP(media, "IEEE 1901_WAVELET"))
		return "IEEE 1901 Wavelet";
	else if (!DM_LSTRCMP(media, "IEEE 1901_FFT"))
		return "IEEE 1901 FFT";
	else if (!DM_LSTRCMP(media, "IEEE MOCA_V1_1"))
		return "MoCAv1.1";
	else
		return (char *)media;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.IEEE1905.Version!UBUS:ieee1905/info//version*/
static int get_IEEE1905_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("version", value);
}

/*#Device.IEEE1905.AL.IEEE1905Id!UBUS:ieee1905/info//ieee1905id*/
static int get_IEEE1905AL_IEEE1905Id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("ieee1905id", value);
}

/*#Device.IEEE1905.AL.Status!UBUS:ieee1905/info//status*/
static int get_IEEE1905AL_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val = NULL;

	ubus_ieee1905_info("status", &val);
	if (!strcasecmp(val, "enabled"))
		*value = "Enabled";
	else if (!strcasecmp(val, "disabled"))
		*value = "Disabled";
	else if (!strcasecmp(val, "error_misconfigured"))
		*value = "Error_Misconfigured";
	else if (!strcasecmp(val, "error"))
		*value = "Error";
	else
		*value = val;

	return 0;
}

/*#Device.IEEE1905.AL.RegistrarFreqBand!UBUS:ieee1905/info//registrar_band*/
static int get_IEEE1905AL_RegistrarFreqBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("ieee1905", "info", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");

	*value = dmjson_get_value_array_all(res, ",", 1, "registrar_band");

	return 0;
}

/*#Device.IEEE1905.AL.InterfaceNumberOfEntries!UBUS:ieee1905/info//num_interfaces*/
static int get_IEEE1905AL_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("num_interfaces", value);
}

/*#Device.IEEE1905.AL.Interface.{i}.InterfaceId!UBUS:ieee1905/info//interface[@i-1].macaddress*/
static int get_IEEE1905ALInterface_InterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddress");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Status!UBUS:ieee1905/info//interface[@i-1].status*/
static int get_IEEE1905ALInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = dmjson_get_value((json_object *)data, 1, "status");
	*value = !strcasecmp(status, "up") ? "Up" : "Down";
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.LowerLayers!UBUS:ieee1905/info//interface[@i-1].ifname*/
static int get_IEEE1905ALInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "ifname");

	adm_entry_get_reference_param(ctx, "Device.Ethernet.Interface.*.Name", linker, value);

	if (!DM_STRLEN(*value)) {
		struct uci_section *s = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", linker);
		dmuci_get_value_by_section_string(s, "device", &linker);
		adm_entry_get_reference_param(ctx, "Device.WiFi.Radio.*.Name", linker, value);
	}

	return 0;
}

#if 0
static int get_IEEE1905ALInterface_InterfaceStackReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.MediaType!UBUS:ieee1905/info//interface[@i-1].media*/
static int get_IEEE1905ALInterface_MediaType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *media = dmjson_get_value((json_object *)data, 1, "media");
	char *band = dmjson_get_value((json_object *)data, 1, "band");

	*value = get_datamodel_media_type(media, band);
	return 0;
}

#if 0 // Below parameters not supported by ieee1905
/*#Device.IEEE1905.AL.Interface.{i}.GenericPhyOUI!UBUS:ieee1905/info//interface[@i-1].genphy_oui*/
static int get_IEEE1905ALInterface_GenericPhyOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_oui");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.GenericPhyVariant!UBUS:ieee1905/info//interface[@i-1].genphy_variant*/
static int get_IEEE1905ALInterface_GenericPhyVariant(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_variant");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.GenericPhyURL!UBUS:ieee1905/info//interface[@i-1].genphy_url*/
static int get_IEEE1905ALInterface_GenericPhyURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_url");
	return 0;
}
#endif

#if 0
static int get_IEEE1905ALInterface_SetIntfPowerStateEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_IEEE1905ALInterface_SetIntfPowerStateEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.PowerState!UBUS:ieee1905/info//interface[@i-1].power*/
static int get_IEEE1905ALInterface_PowerState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *power = dmjson_get_value((json_object *)data, 1, "power");
	*value = !strcasecmp(power, "on") ? "On" : "Off";
	return 0;
}

static int set_IEEE1905ALInterface_PowerState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, -1, PowerState, NULL))
		      return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.VendorPropertiesNumberOfEntries!UBUS:ieee1905/info//interface[@i-1].num_vendor_properties*/
static int get_IEEE1905ALInterface_VendorPropertiesNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_vendor_properties");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.LinkNumberOfEntries!UBUS:ieee1905/info//interface[@i-1].num_links*/
static int get_IEEE1905ALInterface_LinkNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_links");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}.OUI!UBUS:ieee1905/info//interface[@i-1].properties[@i-1].oui*/
static int get_IEEE1905ALInterfaceVendorProperties_OUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "oui");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}.Information!UBUS:ieee1905/info//interface[@i-1].properties[@i-1].data*/
static int get_IEEE1905ALInterfaceVendorProperties_Information(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "data");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.InterfaceId!UBUS:ieee1905/info//interface[@i-1].links[@i-1].macaddress*/
static int get_IEEE1905ALInterfaceLink_InterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddress");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.IEEE1905Id!UBUS:ieee1905/info//interface[@i-1].links[@i-1].ieee1905id*/
static int get_IEEE1905ALInterfaceLink_IEEE1905Id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ieee1905id");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.MediaType!UBUS:ieee1905/info//interface[@i-1].links[@i-1].media*/
static int get_IEEE1905ALInterfaceLink_MediaType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *media = dmjson_get_value((json_object *)data, 1, "media");
	char *band = dmjson_get_value((json_object *)data, 1, "band");

	*value = get_datamodel_media_type(media, band);
	return 0;
}

#if 0 // Generic interfaces not supported by ieee1905
/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.GenericPhyOUI!UBUS:ieee1905/info//interface[@i-1].links[@i-1].genphy_oui*/
static int get_IEEE1905ALInterfaceLink_GenericPhyOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_oui");
	return 0;
}


/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.GenericPhyVariant!UBUS:ieee1905/info//interface[@i-1].links[@i-1].genphy_variant*/
static int get_IEEE1905ALInterfaceLink_GenericPhyVariant(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_variant");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.GenericPhyURL!UBUS:ieee1905/info//interface[@i-1].links[@i-1].genphy_url*/
static int get_IEEE1905ALInterfaceLink_GenericPhyURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_url");
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.IEEE802dot1Bridge!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.has_bridge*/
static int get_IEEE1905ALInterfaceLinkMetric_IEEE802dot1Bridge(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "has_bridge");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PacketErrors!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.tx_errors*/
static int get_IEEE1905ALInterfaceLinkMetric_PacketErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "tx_errors");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PacketErrorsReceived!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.rx_errors*/
static int get_IEEE1905ALInterfaceLinkMetric_PacketErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "rx_errors");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.TransmittedPackets!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.tx_packets*/
static int get_IEEE1905ALInterfaceLinkMetric_TransmittedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "tx_packets");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PacketsReceived!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.rx_packets*/
static int get_IEEE1905ALInterfaceLinkMetric_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "rx_packets");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.MACThroughputCapacity!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.max_macrate*/
static int get_IEEE1905ALInterfaceLinkMetric_MACThroughputCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "max_macrate");
	return 0;
}

#if 0
static int get_IEEE1905ALInterfaceLinkMetric_LinkAvailability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PHYRate!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.max_phyrate*/
static int get_IEEE1905ALInterfaceLinkMetric_PHYRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "max_phyrate");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.RSSI!UBUS:ieee1905/info//interface[@i-1].links[@i-1].metric.rssi*/
static int get_IEEE1905ALInterfaceLinkMetric_RSSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "metric", "rssi");
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.SetForwardingEnabled!UCI:ieee1905/forwarding_table,forwarding_table/forwarding_enabled*/
static int get_IEEE1905ALForwardingTable_SetForwardingEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("ieee1905", "forwarding_table", "forwarding_enabled", value);
	return 0;
}

static int set_IEEE1905ALForwardingTable_SetForwardingEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = 0;
	bool b;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		res = dmuci_set_value("ieee1905", "forwarding_table", "forwarding_enabled", b ? "1" : "0");
		if (res) {
			struct uci_section *s = NULL;

			dmuci_add_section("ieee1905", "forwarding_table", &s);
			dmuci_rename_section_by_section(s, "forwarding_table");
			dmuci_set_value("ieee1905", "forwarding_table", "forwarding_enabled", b ? "1" : "0");
		}
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRuleNumberOfEntries!UCI:ieee1905/forwarding_rule*/
static int get_IEEE1905ALForwardingTable_ForwardingRuleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("ieee1905", "forwarding_rule", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.InterfaceList!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/interface_list*/
static int get_IEEE1905ALForwardingTableForwardingRule_InterfaceList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface_list", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_InterfaceList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, 256, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "interface_list", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACDestinationAddress!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_destination_addr*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "mac_destination_addr", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "mac_destination_addr", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACDestinationAddressFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_destination_addr_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "mac_destination_addr_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "mac_destination_addr_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACSourceAddress!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_source_addr*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
        dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "mac_source_addr", value);
        return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "mac_source_addr", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACSourceAddressFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_source_addr_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
        dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "mac_source_addr_flag", value);
        return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "mac_source_addr_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.EtherType!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/ether_type*/
static int get_IEEE1905ALForwardingTableForwardingRule_EtherType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "ether_type", "0");
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_EtherType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ether_type", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.EtherTypeFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/ether_type_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ether_type_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ether_type_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.Vid!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/vid*/
static int get_IEEE1905ALForwardingTableForwardingRule_Vid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "vid", "0");
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_Vid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","4095"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "vid", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.VidFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/vid_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_VidFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "vid_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_VidFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "vid_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.PCP!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/pcp*/
static int get_IEEE1905ALForwardingTableForwardingRule_PCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "pcp", "0");
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_PCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","7"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "pcp", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.PCPFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/pcp_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_PCPFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "pcp_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_PCPFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "pcp_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.Enable!UBUS:ieee1905/info//topology.enabled*/
static int get_IEEE1905ALNetworkTopology_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("topology", "enabled", value);
}

static int set_IEEE1905ALNetworkTopology_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.Status!UBUS:ieee1905/info//topology.status*/
static int get_IEEE1905ALNetworkTopology_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = NULL;
	ubus_ieee1905_info_options("topology", "status", &status);
	*value = !strcasecmp(status, "available") ? "Available" : "Incomplete";
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.MaxChangeLogEntries!UBUS:ieee1905/info//topology.max_changelog*/
static int get_IEEE1905ALNetworkTopology_MaxChangeLogEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("topology", "max_changelog", value);
}

static int set_IEEE1905ALNetworkTopology_MaxChangeLogEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.LastChange!UBUS:ieee1905/info//topology.last_change*/
static int get_IEEE1905ALNetworkTopology_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("topology", "last_change", value);
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905DeviceNumberOfEntries!UBUS:ieee1905/info//topology.num_device*/
static int get_IEEE1905ALNetworkTopology_IEEE1905DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.ChangeLogNumberOfEntries!UBUS:ieee1905/info//topology.num_changelog*/
static int get_IEEE1905ALNetworkTopology_ChangeLogNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("topology", "num_changelog", value);
}

#if 0
static int get_IEEE1905ALNetworkTopologyChangeLog_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_EventType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_ReporterDeviceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_ReporterInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_NeighborType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_NeighborId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Id!UBUS:ieee1905/info//topology.device[@i-1].ieee1905id*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905Id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ieee1905id");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Version!UBUS:ieee1905/info//topology.device[@i-1].version*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "version");
	return 0;
}

#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_RegistrarFreqBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.FriendlyName!UBUS:ieee1905/info//topology.device[@i-1].name*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_FriendlyName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "name");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.ManufacturerName!UBUS:ieee1905/info//topology.device[@i-1].manufacturer*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "manufacturer");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.ManufacturerModel!UBUS:ieee1905/info//topology.device[@i-1].model*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerModel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "model");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.ControlURL!UBUS:ieee1905/info//topology.device[@i-1].url*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_ControlURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "url");
	return 0;
}
#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_AssocWiFiNetworkDeviceRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorPropertiesNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_vendor_properties*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_VendorPropertiesNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4AddressNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_ipv4*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6AddressNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_ipv6*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.InterfaceNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_interface*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905NeighborNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_neighbor_non1905*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_NonIEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905NeighborNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_neighbor_1905*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2NeighborNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_neighbor_l2*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_L2NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_neighbor_l2");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTupleNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_bridge_tuple*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_BridgingTupleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_bridge_tuple");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.MACAddress!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ieee1905_device_args *)data)->mac_addr;
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.IPv4Address!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].ip*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_args *)data)->dev_obj, 1, "ip");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.IPv4AddressType!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].type*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4AddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_args *)data)->dev_obj, 1, "type");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.DHCPServer!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].dhcpserver*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_DHCPServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_args *)data)->dev_obj, 1, "dhcpserver");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.MACAddress!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ieee1905_device_args *)data)->mac_addr;
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.IPv6Address!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].ip*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_args *)data)->dev_obj, 1, "ip");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.IPv6AddressType!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].type*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_args *)data)->dev_obj, 1, "type");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.IPv6AddressOrigin!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].dhcpserver*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressOrigin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_args *)data)->dev_obj, 1, "dhcpserver");
	return 0;
}
#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_MessageType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}.OUI!UBUS:ieee1905/info//topology.device[@i-1].vendor_properties[@i-1].oui*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_OUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "oui");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}.Information!UBUS:ieee1905/info//topology.device[@i-1].vendor_properties[@i-1].data*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_Information(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "data");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.InterfaceId!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_InterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddress");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.MediaType!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].media*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_MediaType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *media = dmjson_get_value((json_object *)data, 1, "media");
	char *band = dmjson_get_value((json_object *)data, 1, "band");

	*value = get_datamodel_media_type(media, band);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.PowerState!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].power*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_PowerState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *power = dmjson_get_value((json_object *)data, 1, "power");
	*value = !strcasecmp(power, "on") ? "On" : "Off";
	return 0;
}

#if 0 // Genric interfaces not supported by ieee1905
/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.GenericPhyOUI!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].genphy_oui*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_oui");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.GenericPhyVariant!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].genphy_variant*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyVariant(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_variant");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.GenericPhyURL!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].genphy_url*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "genphy_url");
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.NetworkMembership!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].bssid*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_NetworkMembership(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "bssid");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.Role!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].role*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_Role(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *role = dmjson_get_value((json_object *)data, 1, "role");

	if (!DM_LSTRCMP(role, "ap"))
		*value = "AP";
	else if (!DM_LSTRCMP(role, "sta"))
		*value = "non-AP/non-PCP STA";
	else if (!DM_LSTRCMP(role, "p2p_client"))
		*value = "Wi-Fi P2P Client";
	else if (!DM_LSTRCMP(role, "p2p_go"))
		*value = "Wi-Fi P2P Group Owner";
	else if (!DM_LSTRCMP(role, "pcp"))
		*value = "802.11adPCP";
	else
		*value = role;

	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.APChannelBand!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].bandwidth*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_APChannelBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val = dmjson_get_value((json_object *)data, 1, "bandwidth");
	int bw = DM_STRTOL(val);

	switch (bw) {
		case 20:
			*value = "00";
			break;
		case 40:
			*value = "01";
			break;
		case 80:
			*value = "02";
			break;
		case 160:
			*value = "03";
			break;
		case 8080:
			*value = "04";
			break;
		default:
			*value = "";
	}

	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.FrequencyIndex1!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].freq_seg0_idx*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex1(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val = dmjson_get_value((json_object *)data, 1, "freq_seg0_idx");
	char freq_str[3] = {0};
	int freq = DM_STRTOL(val);

	snprintf(freq_str, 3, "%02x", freq);

	*value = dmstrdup(freq_str);

	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.FrequencyIndex2!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].freq_seg1_idx*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex2(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val = dmjson_get_value((json_object *)data, 1, "freq_seg1_idx");
	char freq_str[3] = {0};
	int freq = DM_STRTOL(val);

	snprintf(freq_str, 3, "%02x", freq);
	*value = dmstrdup(freq_str);

	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.LocalInterface!UBUS:ieee1905/info//topology.device[@i-1].non1905_neighbors[@i-1].interface_macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_reference_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.*.Interface.*.InterfaceId", ((struct ieee1905_device_nonieee1905neighbor_args *)data)->mac_addr, value);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.NeighborInterfaceId!UBUS:ieee1905/info//topology.device[@i-1].non1905_neighbors[@i-1].neighbors*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_NeighborInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (data && ((struct ieee1905_device_nonieee1905neighbor_args *)data)->neighbor) ? ((struct ieee1905_device_nonieee1905neighbor_args *)data)->neighbor : "";
	return 0;
}

#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_NeighborInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_BehindInterfaceIds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.LocalInterface!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = ((struct ieee1905_device_ieee1905neighbor_args *)data)->mac_addr;
	adm_entry_get_reference_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.*.Interface.*.InterfaceId", linker, value);
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.NeighborDeviceId!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].neighbor_device_id*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_NeighborDeviceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ieee1905_device_ieee1905neighbor_args *)data)->neighbor_device_id;
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.MetricNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].num_metrics*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_MetricNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ieee1905_device_ieee1905neighbor_args *)data)->num_metrics;
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.NeighborMACAddress!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].neighbor_macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_NeighborMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ieee1905_device_ieee1905neighbor_args *)data)->neighbor_macaddress;
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.IEEE802dot1Bridge!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].has_bridge*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_IEEE802dot1Bridge(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "has_bridge");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PacketErrors!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].tx_errors*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "tx_errors");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PacketErrorsReceived!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].rx_errors*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "rx_errors");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.TransmittedPackets!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].tx_packets*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_TransmittedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "tx_packets");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PacketsReceived!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].rx_packets*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "rx_packets");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.MACThroughputCapacity!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].max_macrate*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_MACThroughputCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "max_macrate");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.LinkAvailability!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].link_available*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_LinkAvailability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "link_available");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PHYRate!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].max_phyrate*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PHYRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "max_phyrate");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.RSSI!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].rssi*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_RSSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct ieee1905_device_ieee1905neighbor_args *)data)->dev_obj, 2, "metric", "rssi");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.InterfaceList!UBUS:ieee1905/info//topology.device[@i-1].bridge_tuples[@i-1].tuple*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTuple_InterfaceList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *json_obj = NULL;
	char *mac_addr = NULL;
	char buf[4096] = {0};
	unsigned pos = 0;
	int idx = 0;

	buf[0] = 0;
	dmjson_foreach_value_in_array((json_object *)data, json_obj, mac_addr, idx, 1, "tuple") {
		char *linker = NULL;

		adm_entry_get_reference_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.*.Interface.*.InterfaceId", mac_addr, &linker);
		if (DM_STRLEN(linker) && (sizeof(buf) - pos) > 0)
			pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", linker);
	}

	if (pos)
		buf[pos - 1] = 0;

	*value = (buf[0] != '\0') ? dmstrdup(buf) : "";
	return 0;
}

/*#Device.IEEE1905.AL.Security.SetupMethod!UCI:ieee1905/security,security/method*/
static int get_IEEE1905ALSecurity_SetupMethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("ieee1905", "security", "method", "PBC");
	return 0;
}

static int set_IEEE1905ALSecurity_SetupMethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value("ieee1905", "security", "method", value);
		break;
	}
	return 0;
}

static int set_IEEE1905ALSecurity_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value("ieee1905", "security", "key", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkingRegistrar.Registrar2dot4!UBUS:ieee1905/info//network_registrars.registrar_2*/
static int get_IEEE1905ALNetworkingRegistrar_Registrar2dot4(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("network_registrars", "registrar_2", value);
}

/*#Device.IEEE1905.AL.NetworkingRegistrar.Registrar5!UBUS:ieee1905/info//network_registrars.registrar_5*/
static int get_IEEE1905ALNetworkingRegistrar_Registrar5(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("network_registrars", "registrar_5", value);
}

/*#Device.IEEE1905.AL.NetworkingRegistrar.Registrar60!UBUS:ieee1905/info//network_registrars.registrar_60*/
static int get_IEEE1905ALNetworkingRegistrar_Registrar60(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info_options("network_registrars", "registrar_60", value);
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.IEEE1905. *** */
DMOBJ tIEEE1905Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"AL", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALObj, tIEEE1905ALParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905Params[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Version", &DMREAD, DMT_STRING, get_IEEE1905_Version, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL. *** */
DMOBJ tIEEE1905ALObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceInst, NULL, NULL, tIEEE1905ALInterfaceObj, tIEEE1905ALInterfaceParams, NULL, BBFDM_BOTH, NULL},
{"ForwardingTable", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALForwardingTableObj, tIEEE1905ALForwardingTableParams, NULL, BBFDM_BOTH, NULL},
{"NetworkTopology", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyObj, tIEEE1905ALNetworkTopologyParams, NULL, BBFDM_BOTH, NULL},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALSecurityParams, NULL, BBFDM_BOTH, NULL},
{"NetworkingRegistrar", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkingRegistrarParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905AL_IEEE1905Id, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905AL_Status, NULL, BBFDM_BOTH},
{"RegistrarFreqBand", &DMREAD, DMT_STRING, get_IEEE1905AL_RegistrarFreqBand, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905AL_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}. *** */
DMOBJ tIEEE1905ALInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"VendorProperties", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceVendorPropertiesInst, NULL, NULL, NULL, tIEEE1905ALInterfaceVendorPropertiesParams, NULL, BBFDM_BOTH},
{"Link", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceLinkInst, NULL, NULL, tIEEE1905ALInterfaceLinkObj, tIEEE1905ALInterfaceLinkParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_InterfaceId, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_Status, NULL, BBFDM_BOTH},
{"LowerLayers", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_LowerLayers, NULL, BBFDM_BOTH, DM_FLAG_REFERENCE},
//{"InterfaceStackReference", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_InterfaceStackReference, NULL, BBFDM_BOTH},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_MediaType, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_GenericPhyOUI, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterface_GenericPhyVariant, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_GenericPhyURL, NULL, BBFDM_BOTH},
//{"SetIntfPowerStateEnabled", &DMWRITE, DMT_BOOL, get_IEEE1905ALInterface_SetIntfPowerStateEnabled, set_IEEE1905ALInterface_SetIntfPowerStateEnabled, BBFDM_BOTH},
{"PowerState", &DMWRITE, DMT_STRING, get_IEEE1905ALInterface_PowerState, set_IEEE1905ALInterface_PowerState, BBFDM_BOTH},
{"VendorPropertiesNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALInterface_VendorPropertiesNumberOfEntries, NULL, BBFDM_BOTH},
{"LinkNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALInterface_LinkNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}. *** */
DMLEAF tIEEE1905ALInterfaceVendorPropertiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceVendorProperties_OUI, NULL, BBFDM_BOTH},
{"Information", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterfaceVendorProperties_Information, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.Link.{i}. *** */
DMOBJ tIEEE1905ALInterfaceLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Metric", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALInterfaceLinkMetricParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALInterfaceLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_InterfaceId, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_IEEE1905Id, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_MediaType, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_GenericPhyOUI, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterfaceLink_GenericPhyVariant, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_GenericPhyURL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric. *** */
DMLEAF tIEEE1905ALInterfaceLinkMetricParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IEEE802dot1Bridge", &DMREAD, DMT_BOOL, get_IEEE1905ALInterfaceLinkMetric_IEEE802dot1Bridge, NULL, BBFDM_BOTH},
{"PacketErrors", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PacketErrors, NULL, BBFDM_BOTH},
{"PacketErrorsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PacketErrorsReceived, NULL, BBFDM_BOTH},
{"TransmittedPackets", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_TransmittedPackets, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PacketsReceived, NULL, BBFDM_BOTH},
{"MACThroughputCapacity", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_MACThroughputCapacity, NULL, BBFDM_BOTH},
//{"LinkAvailability", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_LinkAvailability, NULL, BBFDM_BOTH},
{"PHYRate", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PHYRate, NULL, BBFDM_BOTH},
{"RSSI", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_RSSI, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.ForwardingTable. *** */
DMOBJ tIEEE1905ALForwardingTableObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"ForwardingRule", &DMWRITE, addObjIEEE1905ALForwardingTableForwardingRule, delObjIEEE1905ALForwardingTableForwardingRule, NULL, browseIEEE1905ALForwardingTableForwardingRuleInst, NULL, NULL, NULL, tIEEE1905ALForwardingTableForwardingRuleParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALForwardingTableParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SetForwardingEnabled", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTable_SetForwardingEnabled, set_IEEE1905ALForwardingTable_SetForwardingEnabled, BBFDM_BOTH},
{"ForwardingRuleNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALForwardingTable_ForwardingRuleNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}. *** */
DMLEAF tIEEE1905ALForwardingTableForwardingRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceList", &DMWRITE, DMT_STRING, get_IEEE1905ALForwardingTableForwardingRule_InterfaceList, set_IEEE1905ALForwardingTableForwardingRule_InterfaceList, BBFDM_BOTH},
{"MACDestinationAddress", &DMWRITE, DMT_STRING, get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress, set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress, BBFDM_BOTH},
{"MACDestinationAddressFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag, set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag, BBFDM_BOTH},
{"MACSourceAddress", &DMWRITE, DMT_STRING, get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress, set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress, BBFDM_BOTH},
{"MACSourceAddressFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag, set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag, BBFDM_BOTH},
{"EtherType", &DMWRITE, DMT_UNINT, get_IEEE1905ALForwardingTableForwardingRule_EtherType, set_IEEE1905ALForwardingTableForwardingRule_EtherType, BBFDM_BOTH},
{"EtherTypeFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag, set_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag, BBFDM_BOTH},
{"Vid", &DMWRITE, DMT_UNINT, get_IEEE1905ALForwardingTableForwardingRule_Vid, set_IEEE1905ALForwardingTableForwardingRule_Vid, BBFDM_BOTH},
{"VidFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_VidFlag, set_IEEE1905ALForwardingTableForwardingRule_VidFlag, BBFDM_BOTH},
{"PCP", &DMWRITE, DMT_UNINT, get_IEEE1905ALForwardingTableForwardingRule_PCP, set_IEEE1905ALForwardingTableForwardingRule_PCP, BBFDM_BOTH},
{"PCPFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_PCPFlag, set_IEEE1905ALForwardingTableForwardingRule_PCPFlag, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology. *** */
DMOBJ tIEEE1905ALNetworkTopologyObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"ChangeLog", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyChangeLogInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyChangeLogParams, NULL, BBFDM_BOTH},
{"IEEE1905Device", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInst, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceObj, tIEEE1905ALNetworkTopologyIEEE1905DeviceParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_IEEE1905ALNetworkTopology_Enable, set_IEEE1905ALNetworkTopology_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopology_Status, NULL, BBFDM_BOTH},
{"MaxChangeLogEntries", &DMWRITE, DMT_UNINT, get_IEEE1905ALNetworkTopology_MaxChangeLogEntries, set_IEEE1905ALNetworkTopology_MaxChangeLogEntries, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopology_LastChange, NULL, BBFDM_BOTH},
{"IEEE1905DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopology_IEEE1905DeviceNumberOfEntries, NULL, BBFDM_BOTH},
{"ChangeLogNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopology_ChangeLogNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.ChangeLog.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyChangeLogParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"TimeStamp", &DMREAD, DMT_TIME, get_IEEE1905ALNetworkTopologyChangeLog_TimeStamp, NULL, BBFDM_BOTH},
//{"EventType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_EventType, NULL, BBFDM_BOTH},
//{"ReporterDeviceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_ReporterDeviceId, NULL, BBFDM_BOTH},
//{"ReporterInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_ReporterInterfaceId, NULL, BBFDM_BOTH},
//{"NeighborType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_NeighborType, NULL, BBFDM_BOTH},
//{"NeighborId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_NeighborId, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}. *** */
DMOBJ tIEEE1905ALNetworkTopologyIEEE1905DeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressParams, NULL, BBFDM_BOTH, NULL},
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressParams, NULL, BBFDM_BOTH, NULL},
{"VendorProperties", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesParams, NULL, BBFDM_BOTH, NULL},
{"Interface", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceParams, NULL, BBFDM_BOTH, NULL},
{"NonIEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborParams, NULL, BBFDM_BOTH, NULL},
//{"L2Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborParams, NULL, BBFDM_BOTH, NULL},
{"IEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborInst, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborObj, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborParams, NULL, BBFDM_BOTH, NULL},
{"BridgingTuple", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905Id, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Version", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_Version, NULL, BBFDM_BOTH},
//{"RegistrarFreqBand", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_RegistrarFreqBand, NULL, BBFDM_BOTH},
{"FriendlyName", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_FriendlyName, NULL, BBFDM_BOTH},
{"ManufacturerName", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerName, NULL, BBFDM_BOTH},
{"ManufacturerModel", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerModel, NULL, BBFDM_BOTH},
{"ControlURL", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_ControlURL, NULL, BBFDM_BOTH},
//{"AssocWiFiNetworkDeviceRef", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_AssocWiFiNetworkDeviceRef, NULL, BBFDM_BOTH},
{"VendorPropertiesNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_VendorPropertiesNumberOfEntries, NULL, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv4AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv6AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"NonIEEE1905NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_NonIEEE1905NeighborNumberOfEntries, NULL, BBFDM_BOTH},
{"IEEE1905NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905NeighborNumberOfEntries, NULL, BBFDM_BOTH},
{"L2NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_L2NeighborNumberOfEntries, NULL, BBFDM_BOTH},
{"BridgingTupleNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_BridgingTupleNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_MACAddress, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IPv4Address", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4Address, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IPv4AddressType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4AddressType, NULL, BBFDM_BOTH},
{"DHCPServer", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_DHCPServer, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_MACAddress, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IPv6Address", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6Address, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IPv6AddressType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressType, NULL, BBFDM_BOTH},
{"IPv6AddressOrigin", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressOrigin, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"MessageType", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_MessageType, NULL, BBFDM_BOTH},
{"OUI", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_OUI, NULL, BBFDM_BOTH},
{"Information", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_Information, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_InterfaceId, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_MediaType, NULL, BBFDM_BOTH},
{"PowerState", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_PowerState, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyOUI, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyVariant, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyURL, NULL, BBFDM_BOTH},
{"NetworkMembership", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_NetworkMembership, NULL, BBFDM_BOTH},
{"Role", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_Role, NULL, BBFDM_BOTH},
{"APChannelBand", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_APChannelBand, NULL, BBFDM_BOTH},
{"FrequencyIndex1", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex1, NULL, BBFDM_BOTH},
{"FrequencyIndex2", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex2, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_LocalInterface, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_REFERENCE},
{"NeighborInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_NeighborInterfaceId, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_LocalInterface, NULL, BBFDM_BOTH},
//{"NeighborInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_NeighborInterfaceId, NULL, BBFDM_BOTH},
//{"BehindInterfaceIds", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_BehindInterfaceIds, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}. *** */
DMOBJ tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Metric", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_LocalInterface, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_REFERENCE},
{"NeighborDeviceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_NeighborDeviceId, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"MetricNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_MetricNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"NeighborMACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_NeighborMACAddress, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IEEE802dot1Bridge", &DMREAD, DMT_BOOL, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_IEEE802dot1Bridge, NULL, BBFDM_BOTH},
{"PacketErrors", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrors, NULL, BBFDM_BOTH},
{"PacketErrorsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrorsReceived, NULL, BBFDM_BOTH},
{"TransmittedPackets", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_TransmittedPackets, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketsReceived, NULL, BBFDM_BOTH},
{"MACThroughputCapacity", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_MACThroughputCapacity, NULL, BBFDM_BOTH},
{"LinkAvailability", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_LinkAvailability, NULL, BBFDM_BOTH},
{"PHYRate", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PHYRate, NULL, BBFDM_BOTH},
{"RSSI", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_RSSI, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceList", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTuple_InterfaceList, NULL, BBFDM_BOTH, DM_FLAG_REFERENCE},
{0}
};

/* *** Device.IEEE1905.AL.Security. *** */
DMLEAF tIEEE1905ALSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SetupMethod", &DMWRITE, DMT_STRING, get_IEEE1905ALSecurity_SetupMethod, set_IEEE1905ALSecurity_SetupMethod, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_IEEE1905ALSecurity_Password, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkingRegistrar. *** */
DMLEAF tIEEE1905ALNetworkingRegistrarParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Registrar2dot4", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar2dot4, NULL, BBFDM_BOTH},
{"Registrar5", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar5, NULL, BBFDM_BOTH},
{"Registrar60", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar60, NULL, BBFDM_BOTH},
{0}
};
