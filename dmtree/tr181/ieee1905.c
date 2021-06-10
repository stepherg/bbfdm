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

#include "dmentry.h"
#include "ieee1905.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.IEEE1905.AL.Interface.{i}.!UBUS:ieee1905/info//interface*/
static int browseIEEE1905ALInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *interface_obj = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("ieee1905", "info", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, interface_obj, i, 1, "interface") {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)interface_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}.!UBUS:ieee1905/info//interface[@i-1].properties*/
static int browseIEEE1905ALInterfaceVendorPropertiesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *propertie_obj = NULL, *interface = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(interface, arrobj, propertie_obj, i, 1, "properties") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)propertie_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.!UBUS:ieee1905/info//interface[@i-1].links*/
static int browseIEEE1905ALInterfaceLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *link_obj = NULL, *interface = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(interface, arrobj, link_obj, i, 1, "links") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)link_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.!UCI:ieee1905/forwarding_rule/dmmap_forwarding_rule*/
static int browseIEEE1905ALForwardingTableForwardingRuleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ieee1905", "forwarding_rule", "dmmap_forwarding_rule", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "forwardingruleinstance", "forwardingrulealias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
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
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("ieee1905", "info", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, device_obj, i, 2, "topology", "device") {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)device_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *ipv4_address = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, ipv4_address, i, 1, "ipv4_address") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv4_address, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *ipv6_address = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, ipv6_address, i, 1, "ipv6_address") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv6_address, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}.!UBUS:ieee1905/info//topology.device[@i-1].vendor_properties*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *vendor_properties = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, vendor_properties, i, 1, "vendor_properties") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)vendor_properties, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.!UBUS:ieee1905/info//topology.device[@i-1].interface*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *interface = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, interface, i, 1, "interface") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)interface, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.!UBUS:ieee1905/info//topology.device[@i-1].non1905_neighbors*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *non1905_neighbor = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, non1905_neighbor, i, 1, "non1905_neighbors") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)non1905_neighbor, inst) == DM_STOP)
			break;
	}
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
	json_object *arrobj = NULL, *ieee1905_neighbors = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, ieee1905_neighbors, i, 1, "ieee1905_neighbors") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ieee1905_neighbors, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.!UBUS:ieee1905/info//topology.device[@i-1].bridge_tuples*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *bridge_tuple = NULL, *device = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(device, arrobj, bridge_tuple, i, 1, "bridge_tuples") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bridge_tuple, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric*/
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *metric = NULL, *ieee1905_neighbors = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(ieee1905_neighbors, arrobj, metric, i, 1, "metric") {

		inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)metric, inst) == DM_STOP)
			break;
	}
	return 0;
}


/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjIEEE1905ALForwardingTableForwardingRule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	char *inst = get_last_instance_bbfdm("dmmap_forwarding_rule", "forwarding_rule", "forwardingruleinstance");
	dmuci_add_section("ieee1905", "forwarding_rule", &s);

	dmuci_add_section_bbfdm("dmmap_forwarding_rule", "forwarding_rule", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(inst, 2, dmmap, "forwardingruleinstance");
	return 0;
}

static int delObjIEEE1905ALForwardingTableForwardingRule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_forwarding_rule", "forwarding_rule", section_name((struct uci_section *)data), &dmmap_section);
		if (dmmap_section != NULL)
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
		dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections("ieee1905", "forwarding_rule", s) {
			if (found != 0) {
				get_dmmap_section_of_config_section("dmmap_forwarding_rule", "forwarding_rule", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL) {
			get_dmmap_section_of_config_section("dmmap_forwarding_rule", "forwarding_rule", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* LINKER
**************************************************************/
static int get_linker_topology_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = dmjson_get_value((json_object *)data, 1, "macaddress");
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static int ubus_ieee1905_info(const char *option, char **value)
{
	json_object *res = NULL;
	dmubus_call("ieee1905", "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, option);
	return 0;
}

static int ubus_ieee1905_info_options(const char *option1, const char *option2, char **value)
{
	json_object *res = NULL;
	dmubus_call("ieee1905", "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, option1, option2);
	return 0;
}

static char *get_datamodel_media_type(const char *media)
{
	if (!strcmp(media, "IEEE 802_3U_FAST_ETHERNET"))
		return "IEEE 802.3u";
	else if (!strcmp(media, "IEEE 802_3AB_GIGABIT_ETHERNET"))
		return "IEEE 802.3ab";
	else if (!strcmp(media, "IEEE 802_11B_2_4_GHZ"))
		return "IEEE 802.11b";
	else if (!strcmp(media, "IEEE 802_11G_2_4_GHZ"))
		return "IEEE 802.11g";
	else if (!strcmp(media, "IEEE 802_11A_5_GHZ"))
		return "IEEE 802.11a";
	else if (!strcmp(media, "IEEE 802_11N_2_4_GHZ"))
		return "IEEE 802.11n 2.4";
	else if (!strcmp(media, "IEEE 802_11N_5_GHZ"))
		return "IEEE 802.11n 5.0";
	else if (!strcmp(media, "IEEE 802_11AC_5_GHZ"))
		return "IEEE 802.11ac";
	else if (!strcmp(media, "IEEE 802_11AD_60_GHZ"))
		return "IEEE 802.11ad";
	else if (!strcmp(media, "IEEE 802_11AF_GHZ"))
		return "IEEE 802.11af";
	else if (!strcmp(media, "IEEE 1901_WAVELET"))
		return "IEEE 1901 Wavelet";
	else if (!strcmp(media, "IEEE 1901_FFT"))
		return "IEEE 1901 FFT";
	else if (!strcmp(media, "IEEE MOCA_V1_1"))
		return "MoCAv1.1";
	else
		return media;
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
	return ubus_ieee1905_info("status", value);
}

#if 0
static int get_IEEE1905AL_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905AL_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.RegistrarFreqBand!UBUS:ieee1905/info//registrar_band*/
static int get_IEEE1905AL_RegistrarFreqBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *registrar_band = NULL;
	char list_bands[64], *band = NULL;
	unsigned pos = 0, idx = 0;

	dmubus_call("ieee1905", "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");

	list_bands[0] = 0;
	dmjson_foreach_value_in_array(res, registrar_band, band, idx, 1, "registrar_band") {
		pos += snprintf(&list_bands[pos], sizeof(list_bands) - pos, "802.11 %s GHz,", (*band == '2') ? "2.4" : (*band == '5') ? "5" : "60");
	}

	if (pos)
		list_bands[pos - 1] = 0;

	*value = dmstrdup(list_bands);
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

#if 0
static int get_IEEE1905ALInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

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
	*value = get_datamodel_media_type(media);
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
		if (dm_validate_boolean(value))
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
		if (dm_validate_string(value, -1, -1, PowerState, NULL))
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
	*value = get_datamodel_media_type(media);
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
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value("ieee1905", "forwarding_table", "forwarding_enabled", b ? "1" : "0");
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "interface_list", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_InterfaceList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string_list(value, -1, -1, -1, -1, 256, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "interface_list", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACDestinationAddress!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_destination_addr*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "mac_destination_addr", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 17, NULL, MACAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "mac_destination_addr", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACDestinationAddressFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_destination_addr_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "mac_destination_addr_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "mac_destination_addr_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACSourceAddress!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_source_addr*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
        dmuci_get_value_by_section_string((struct uci_section *)data, "mac_source_addr", value);
        return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, 17, NULL, MACAddress))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "mac_source_addr", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.MACSourceAddressFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/mac_source_addr_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
        dmuci_get_value_by_section_string((struct uci_section *)data, "mac_source_addr_flag", value);
        return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "mac_source_addr_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.EtherType!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/ether_type*/
static int get_IEEE1905ALForwardingTableForwardingRule_EtherType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ether_type", "0");
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_EtherType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "ether_type", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.EtherTypeFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/ether_type_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ether_type_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "ether_type_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.Vid!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/vid*/
static int get_IEEE1905ALForwardingTableForwardingRule_Vid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "vid", "0");
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_Vid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","4095"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "vid", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.VidFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/vid_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_VidFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vid_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_VidFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "vid_flag", b ? "1" : "0");
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.PCP!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/pcp*/
static int get_IEEE1905ALForwardingTableForwardingRule_PCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "pcp", "0");
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_PCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "pcp", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.PCPFlag!UCI:dmmap_forwarding_rule/forwarding_rule,@i-1/pcp_flag*/
static int get_IEEE1905ALForwardingTableForwardingRule_PCPFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "pcp_flag", value);
	return 0;
}

static int set_IEEE1905ALForwardingTableForwardingRule_PCPFlag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section((struct uci_section *)data, "pcp_flag", b ? "1" : "0");
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
			if (dm_validate_boolean(value))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
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
	return ubus_ieee1905_info_options("topology", "num_device", value);
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
	*value = dmjson_get_value((json_object *)data, 1, "num_vendor_properties");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4AddressNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_ipv4*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_ipv4");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6AddressNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_ipv6*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_ipv6");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.InterfaceNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_interface*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_interface");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905NeighborNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_neighbor_non1905*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_NonIEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_neighbor_non1905");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905NeighborNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].num_neighbor_1905*/
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_neighbor_1905");
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
	*value = dmjson_get_value((json_object *)data, 1, "macaddress");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.IPv4Address!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].ip*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ip");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.IPv4AddressType!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].type*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4AddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "type");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.DHCPServer!UBUS:ieee1905/info//topology.device[@i-1].ipv4_address[@i-1].dhcpserver*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_DHCPServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "dhcpserver");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.MACAddress!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddress");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.IPv6Address!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].ip*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ip");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.IPv6AddressType!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].type*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "type");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.IPv6AddressOrigin!UBUS:ieee1905/info//topology.device[@i-1].ipv6_address[@i-1].dhcpserver*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressOrigin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "dhcpserver");
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
	*value = get_datamodel_media_type(media);
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

	if (!strcmp(role, "ap"))
		*value = "AP";
	else if (!strcmp(role, "sta"))
		*value = "non-AP/non-PCP STA";
	else if (!strcmp(role, "p2p_client"))
		*value = "Wi-Fi P2P Client";
	else if (!strcmp(role, "p2p_go"))
		*value = "Wi-Fi P2P Group Owner";
	else if (!strcmp(role, "pcp"))
		*value = "802.11adPCP";
	else
		*value = role;

	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.APChannelBand!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].bandwidth*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_APChannelBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val = dmjson_get_value((json_object *)data, 1, "bandwidth");
	int bw = atoi(val);

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
	*value = dmjson_get_value((json_object *)data, 1, "freq_seg0_idx");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.FrequencyIndex2!UBUS:ieee1905/info//topology.device[@i-1].interface[@i-1].freq_seg1_idx*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex2(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "freq_seg1_idx");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.LocalInterface!UBUS:ieee1905/info//topology.device[@i-1].non1905_neighbors[@i-1].interface_macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "interface_macaddress");
	adm_entry_get_linker_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.NeighborInterfaceId!UBUS:ieee1905/info//topology.device[@i-1].non1905_neighbors[@i-1].neighbors*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_NeighborInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "neighbors");
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
	char *linker = dmjson_get_value((json_object *)data, 1, "macaddress");
	adm_entry_get_linker_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.NeighborDeviceId!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].neighbor_device_id*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_NeighborDeviceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "neighbor_device_id");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.MetricNumberOfEntries!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].num_metrics*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_MetricNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_metrics");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.NeighborMACAddress!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].neighbor_macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_NeighborMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "neighbor_macaddress");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.IEEE802dot1Bridge!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].has_bridge*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_IEEE802dot1Bridge(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "has_bridge");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PacketErrors!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].tx_errors*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "tx_errors");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PacketErrorsReceived!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].rx_errors*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rx_errors");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.TransmittedPackets!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].tx_packets*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_TransmittedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "tx_packets");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PacketsReceived!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].rx_packets*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rx_packets");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.MACThroughputCapacity!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].max_macrate*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_MACThroughputCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "max_macrate");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.LinkAvailability!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].link_available*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_LinkAvailability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "link_available");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.PHYRate!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].max_phyrate*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PHYRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "max_phyrate");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.RSSI!UBUS:ieee1905/info//topology.device[@i-1].ieee1905_neighbors[@i-1].metric[@i-1].rssi*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_RSSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

/*#Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.InterfaceList!UBUS:ieee1905/info//topology.device[@i-1].bridge_tuples[@i-1].macaddress*/
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTuple_InterfaceList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "macaddress");
	adm_entry_get_linker_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.", linker, value);
	if (*value == NULL)
		*value = "";
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
		if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
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
		if (dm_validate_string(value, -1, -1, NULL, NULL))
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"AL", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALObj, tIEEE1905ALParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905Params[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Version", &DMREAD, DMT_STRING, get_IEEE1905_Version, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL. *** */
DMOBJ tIEEE1905ALObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceInst, NULL, NULL, tIEEE1905ALInterfaceObj, tIEEE1905ALInterfaceParams, NULL, BBFDM_BOTH, LIST_KEY{"InterfaceId", NULL}},
{"ForwardingTable", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALForwardingTableObj, tIEEE1905ALForwardingTableParams, NULL, BBFDM_BOTH},
{"NetworkTopology", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyObj, tIEEE1905ALNetworkTopologyParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALSecurityParams, NULL, BBFDM_BOTH},
{"NetworkingRegistrar", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkingRegistrarParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905AL_IEEE1905Id, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905AL_Status, NULL, BBFDM_BOTH},
//{"LastChange", &DMREAD, DMT_UNINT, get_IEEE1905AL_LastChange, NULL, BBFDM_BOTH},
//{"LowerLayers", &DMREAD, DMT_STRING, get_IEEE1905AL_LowerLayers, NULL, BBFDM_BOTH},
{"RegistrarFreqBand", &DMREAD, DMT_STRING, get_IEEE1905AL_RegistrarFreqBand, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905AL_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}. *** */
DMOBJ tIEEE1905ALInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"VendorProperties", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceVendorPropertiesInst, NULL, NULL, NULL, tIEEE1905ALInterfaceVendorPropertiesParams, NULL, BBFDM_BOTH},
{"Link", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceLinkInst, NULL, NULL, tIEEE1905ALInterfaceLinkObj, tIEEE1905ALInterfaceLinkParams, NULL, BBFDM_BOTH, LIST_KEY{"InterfaceId", "IEEE1905Id", NULL}},
{0}
};

DMLEAF tIEEE1905ALInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_InterfaceId, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_Status, NULL, BBFDM_BOTH},
//{"LastChange", &DMREAD, DMT_UNINT, get_IEEE1905ALInterface_LastChange, NULL, BBFDM_BOTH},
//{"LowerLayers", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_LowerLayers, NULL, BBFDM_BOTH},
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"OUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceVendorProperties_OUI, NULL, BBFDM_BOTH},
{"Information", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterfaceVendorProperties_Information, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.Link.{i}. *** */
DMOBJ tIEEE1905ALInterfaceLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Metric", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALInterfaceLinkMetricParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALInterfaceLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_InterfaceId, NULL, BBFDM_BOTH},
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_IEEE1905Id, NULL, BBFDM_BOTH},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_MediaType, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_GenericPhyOUI, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterfaceLink_GenericPhyVariant, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_GenericPhyURL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric. *** */
DMLEAF tIEEE1905ALInterfaceLinkMetricParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"ForwardingRule", &DMWRITE, addObjIEEE1905ALForwardingTableForwardingRule, delObjIEEE1905ALForwardingTableForwardingRule, NULL, browseIEEE1905ALForwardingTableForwardingRuleInst, NULL, NULL, NULL, tIEEE1905ALForwardingTableForwardingRuleParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALForwardingTableParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SetForwardingEnabled", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTable_SetForwardingEnabled, set_IEEE1905ALForwardingTable_SetForwardingEnabled, BBFDM_BOTH},
{"ForwardingRuleNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALForwardingTable_ForwardingRuleNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}. *** */
DMLEAF tIEEE1905ALForwardingTableForwardingRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
//{"ChangeLog", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyChangeLogInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyChangeLogParams, NULL, BBFDM_BOTH},
{"IEEE1905Device", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInst, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceObj, tIEEE1905ALNetworkTopologyIEEE1905DeviceParams, NULL, BBFDM_BOTH, LIST_KEY{"IEEE1905Id", NULL}},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", "IPv4Address", NULL}},
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", "IPv6Address", NULL}},
{"VendorProperties", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesParams, NULL, BBFDM_BOTH},
{"Interface", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceParams, get_linker_topology_interface, BBFDM_BOTH, LIST_KEY{"InterfaceId", NULL}},
{"NonIEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborParams, NULL, BBFDM_BOTH, LIST_KEY{"LocalInterface", "NeighborInterfaceId", NULL}},
//{"L2Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborParams, NULL, BBFDM_BOTH, (const char*[]){"LocalInterface", "NeighborInterfaceId", NULL}},
{"IEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborInst, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborObj, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborParams, NULL, BBFDM_BOTH, LIST_KEY{"LocalInterface", "NeighborDeviceId", NULL}},
{"BridgingTuple", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905Id, NULL, BBFDM_BOTH},
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_MACAddress, NULL, BBFDM_BOTH},
{"IPv4Address", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4Address, NULL, BBFDM_BOTH},
{"IPv4AddressType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4AddressType, NULL, BBFDM_BOTH},
{"DHCPServer", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_DHCPServer, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_MACAddress, NULL, BBFDM_BOTH},
{"IPv6Address", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6Address, NULL, BBFDM_BOTH},
{"IPv6AddressType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressType, NULL, BBFDM_BOTH},
{"IPv6AddressOrigin", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressOrigin, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"MessageType", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_MessageType, NULL, BBFDM_BOTH},
{"OUI", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_OUI, NULL, BBFDM_BOTH},
{"Information", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_Information, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_InterfaceId, NULL, BBFDM_BOTH},
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_LocalInterface, NULL, BBFDM_BOTH},
{"NeighborInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_NeighborInterfaceId, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_LocalInterface, NULL, BBFDM_BOTH},
//{"NeighborInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_NeighborInterfaceId, NULL, BBFDM_BOTH},
//{"BehindInterfaceIds", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_BehindInterfaceIds, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}. *** */
DMOBJ tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Metric", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricParams, NULL, BBFDM_BOTH, LIST_KEY{"NeighborMACAddress", NULL}},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_LocalInterface, NULL, BBFDM_BOTH},
{"NeighborDeviceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_NeighborDeviceId, NULL, BBFDM_BOTH},
{"MetricNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_MetricNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"NeighborMACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_NeighborMACAddress, NULL, BBFDM_BOTH},
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceList", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTuple_InterfaceList, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Security. *** */
DMLEAF tIEEE1905ALSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SetupMethod", &DMWRITE, DMT_STRING, get_IEEE1905ALSecurity_SetupMethod, set_IEEE1905ALSecurity_SetupMethod, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_IEEE1905ALSecurity_Password, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkingRegistrar. *** */
DMLEAF tIEEE1905ALNetworkingRegistrarParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Registrar2dot4", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar2dot4, NULL, BBFDM_BOTH},
{"Registrar5", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar5, NULL, BBFDM_BOTH},
{"Registrar60", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar60, NULL, BBFDM_BOTH},
{0}
};
