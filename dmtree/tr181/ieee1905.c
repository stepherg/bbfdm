/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: <Nevadita> <Chatterjee> <nevadita.chatterjee@iopsys.eu>
 */

#include "dmentry.h"
#include "ieee1905.h"

struct obj_node {
	json_object *node;
	json_object *data;
};

struct param_node {
	json_object *node;
	char *data;
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.IEEE1905.AL.Interface.{i}.!UBUS:ieee1905/interfaces//names*/
static int browseIEEE1905ALInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *result = NULL, *interfaces = NULL, *interface_id = NULL;
	char *inst = NULL, *max_inst = NULL;
	char object[256];
	int id = 0, i = 0;

	//Here  get the interface name from which the info call should be made
	dmubus_call("ieee1905", "interfaces", UBUS_ARGS{}, 0, &result);
	if (result == NULL)
		return 0;
	json_object_object_get_ex(result, "names", &interfaces);
	size_t num_interface = json_object_array_length(interfaces);
	for (i = 0; i < num_interface; i++) {
		interface_id = json_object_array_get_idx(interfaces, i);
		snprintf(object, sizeof(object), "ieee1905.al.%s", json_object_get_string(interface_id));
		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)object, inst) == DM_STOP)
			break;
	}
	return 0;
}

#if 0
static int browseIEEE1905ALInterfaceVendorPropertiesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.!UBUS:ieee1905.al.Name/link_info//Links*/
static int browseIEEE1905ALInterfaceLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *link_obj = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call((char *)prev_data, "link_info", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, link_obj, i, 1, "links") {
			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)link_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

/*#Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.!UCI:ieee1905/forwarding_rule/dmmap_forwarding_rule*/
static int browseIEEE1905ALForwardingTableForwardingRuleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ieee1905", "forwarding_rule", "dmmap_forwarding_rule", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst =  handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
				p->dmmap_section, "forwardingruleinstance", "forwardingrulealias", "dmmap_forwarding_rule", "forwarding_rule");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}


static int browseIEEE1905ALNetworkTopologyChangeLogInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *obj = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("topology", "changelog", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, obj, i, 1, "changelog") {

			inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyNonIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *arrobj = NULL, *res_self = NULL;
	char *inst = NULL, *max_inst = NULL, *obj = NULL;
	int id = 0, i = 0;

	dmubus_call("topology", "dump", UBUS_ARGS{}, 0, &res_self);
	if (res_self)
		json_object_object_get_ex(res_self, "self", &res);
	if (res) {
		dmjson_foreach_value_in_array(res, arrobj, obj, i, 1, "non1905_neighbors") {

			inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *node = NULL, *arrobj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmubus_call("topology", "dump", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, node, i, 1, "nodes") {

			inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)node, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *ipv4_param = NULL, *node = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(node, arrobj, ipv4_param, i, 1, "ipv4_params") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv4_param, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *ipv6_param = NULL, *node = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(node, arrobj, ipv6_param, i, 1, "ipv6_params") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ipv6_param, inst) == DM_STOP)
			break;
	}
	return 0;
}

#if 0
static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *interface = NULL, *node = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(node, arrobj, interface, i, 1, "interfaces") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)interface, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj, *node = (json_object *)prev_data;
	struct param_node param_st = {.node = node};
	char *inst = NULL, *max_inst = NULL, *non1905_neighbor = NULL;
	int id = 0, i = 0;

	dmjson_foreach_value_in_array(node, arrobj, non1905_neighbor, i, 1, "non1905_neighbors") {

		param_st.data = non1905_neighbor;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&param_st, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *l2_neighbor = NULL, *node = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(node, arrobj, l2_neighbor, i, 1, "l2_neighbor") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)l2_neighbor, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *neighbor = NULL, *node = (json_object *)prev_data;
	struct obj_node param_st = { .node = node };
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(node, arrobj, neighbor, i, 1, "neighbors") {

		param_st.data = neighbor;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&param_st, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *arrobj = NULL, *bridge_tuple = NULL, *node = (json_object *)prev_data;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(node, arrobj, bridge_tuple, i, 1, "bridge_tuple") {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bridge_tuple, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct obj_node *param_st = (struct obj_node *)prev_data;
	json_object *arrobj = NULL, *link_metric = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(param_st->data, arrobj, link_metric, i, 1, "link_metrics") {

		inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)link_metric, inst) == DM_STOP)
			break;
	}
	return 0;
}


/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjIEEE1905ALForwardingTableForwardingRule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_forwarding_rule");
	inst = get_last_instance_bbfdm("dmmap_forwarding_rule", "forwarding_rule", "forwardingruleinstance");
	dmuci_add_section_and_rename("ieee1905", "forwarding_rule", &s, &value);

	dmuci_add_section_bbfdm("dmmap_forwarding_rule", "forwarding_rule", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(inst, 4, dmmap, "forwardingruleinstance", "dmmap_forwarding_rule", "forwarding_rule");
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
	*linker = dmjson_get_value((json_object *)data, 1, "interface_id");
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int ubus_ieee1905_info(const char *option, char **value)
{
	json_object *res = NULL;
	dmubus_call("ieee1905", "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, option);
	return 0;
}

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

/*#Device.IEEE1905.AL.LastChange!UBUS:ieee1905/info//last_change*/
static int get_IEEE1905AL_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("last_change", value);
}

#if 0
static int get_IEEE1905AL_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.RegistrarFreqBand!UBUS:ieee1905/info//registrar_freq_band*/
static int get_IEEE1905AL_RegistrarFreqBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("registrar_freq_band", value);
}

/*#Device.IEEE1905.AL.InterfaceNumberOfEntries!UBUS:ieee1905/info//interface_num*/
static int get_IEEE1905AL_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("interface_num", value);
}

/*#Device.IEEE1905.AL.Interface.{i}.InterfaceId!UBUS:ieee1905.al.Name/info//mac*/
static int get_IEEE1905ALInterface_InterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call((char *)data, "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "mac");
	return 0;
}

#if 0
static int get_IEEE1905ALInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

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

/*#Device.IEEE1905.AL.Interface.{i}.MediaType!UBUS:ieee1905.al.Name/info//interface_type*/
static int get_IEEE1905ALInterface_MediaType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call((char *)data, "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "interface_type");
	return 0;
}

#if 0
static int get_IEEE1905ALInterface_GenericPhyOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALInterface_GenericPhyVariant(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALInterface_GenericPhyURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

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

/*#Device.IEEE1905.AL.Interface.{i}.PowerState!UBUS:ieee1905.al.Name/info//power_state*/
static int get_IEEE1905ALInterface_PowerState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call((char *)data, "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "power_state");
	return 0;
}

static int set_IEEE1905ALInterface_PowerState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		//if (dm_validate_string(value, -1, -1, PowerState, 4, NULL, 0))
		//      return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.VendorPropertiesNumberOfEntries!UBUS:ieee1905.al.Name/info//vendor_nr*/
static int get_IEEE1905ALInterface_VendorPropertiesNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call((char *)data, "info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "vendor_nr");
	return 0;
}

static int get_IEEE1905ALInterface_LinkNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *links = NULL;
	size_t num_links = 0;

	dmubus_call((char *)data, "link_info", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "links", &links);
	if (links)
		num_links = json_object_array_length(links);

	dmasprintf(value, "%d", num_links);
	return 0;
}

#if 0
static int get_IEEE1905ALInterfaceVendorProperties_OUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALInterfaceVendorProperties_Information(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.InterfaceId!UBUS:ieee1905.al.Name/link_info//Links[@i-1].interfaceid*/
static int get_IEEE1905ALInterfaceLink_InterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "interfaceid");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.IEEE1905Id!UBUS:ieee1905.al.Name/link_info//Links[@i-1].ieee1905id*/
static int get_IEEE1905ALInterfaceLink_IEEE1905Id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ieee1905id");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.MediaType!UBUS:ieee1905.al.Name/link_info//Links[@i-1].media_type*/
static int get_IEEE1905ALInterfaceLink_MediaType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "media_type");
	return 0;
}

#if 0
static int get_IEEE1905ALInterfaceLink_GenericPhyOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALInterfaceLink_GenericPhyVariant(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALInterfaceLink_GenericPhyURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.IEEE802dot1Bridge!UBUS:ieee1905.al.Name/link_info//Links[@i-1].ieee802dot1bridge*/
static int get_IEEE1905ALInterfaceLinkMetric_IEEE802dot1Bridge(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ieee802dot1bridge");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PacketErrors!UBUS:ieee1905.al.Name/link_info//Links[@i-1].packet_errors_tx*/
static int get_IEEE1905ALInterfaceLinkMetric_PacketErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "packet_errors_tx");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PacketErrorsReceived!UBUS:ieee1905.al.Name/link_info//Links[@i-1].packet_errors_rx*/
static int get_IEEE1905ALInterfaceLinkMetric_PacketErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "packet_errors_rx");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.TransmittedPackets!UBUS:ieee1905.al.Name/link_info//Links[@i-1].transmitted_packets*/
static int get_IEEE1905ALInterfaceLinkMetric_TransmittedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "transmitted_packets");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PacketsReceived!UBUS:ieee1905.al.Name/link_info//Links[@i-1].packets_received*/
static int get_IEEE1905ALInterfaceLinkMetric_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "packets_received");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.MACThroughputCapacity!UBUS:ieee1905.al.Name/link_info//Links[@i-1].mac_throughput_capacity*/
static int get_IEEE1905ALInterfaceLinkMetric_MACThroughputCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "mac_throughput_capacity");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.LinkAvailability!UBUS:ieee1905.al.Name/link_info//Links[@i-1].link_availability*/
static int get_IEEE1905ALInterfaceLinkMetric_LinkAvailability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "link_availability");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.PHYRate!UBUS:ieee1905.al.Name/link_info//Links[@i-1].phy_rate*/
static int get_IEEE1905ALInterfaceLinkMetric_PHYRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "phy_rate");
	return 0;
}

/*#Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.RSSI!UBUS:ieee1905.al.Name/link_info//Links[@i-1].rssi*/
static int get_IEEE1905ALInterfaceLinkMetric_RSSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
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
		if (dm_validate_string_list(value, -1, -1, -1, -1, 256, NULL, 0, NULL, 0))
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
		if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
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
		if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "ether_type", value);
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "vid", value);
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "pcp", value);
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


static int get_IEEE1905ALNetworkTopology_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("topology", "topology", "enabled", value);
	return 0;
}

static int set_IEEE1905ALNetworkTopology_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("topology", "topology", "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_IEEE1905ALNetworkTopology_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("topology", "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "status");
	return 0;
}

static int get_IEEE1905ALNetworkTopology_MaxChangeLogEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("topology", "topology", "maxlog", value);
	return 0;
}

static int set_IEEE1905ALNetworkTopology_MaxChangeLogEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("topology", "topology", "maxlog", value);
			break;
	}
	return 0;
}

static int get_IEEE1905ALNetworkTopology_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *obj = NULL;
	size_t num = 0;

	dmubus_call("topology", "changelog", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	json_object_object_get_ex(res, "changelog", &obj);
	if (obj) {
		num = json_object_array_length(obj);
		if (num != 0)
			dmasprintf(value, "Device.IEEE1905.AL.NetworkTopology.ChangeLog.%d", num);
	}

	return 0;
}

static int get_IEEE1905ALNetworkTopology_IEEE1905DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *obj = NULL;
	size_t num_nodes = 0;

	dmubus_call("topology", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "nodes", &obj);
	if (obj)
		num_nodes = json_object_array_length(obj);

	dmasprintf(value, "%d", num_nodes);
	return 0;
}

static int get_IEEE1905ALNetworkTopology_ChangeLogNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("topology", "changelog", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "num_changelog");
	return 0;
}

static int get_IEEE1905ALNetworkTopology_NonIEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *obj = NULL, *obj_nbr = NULL;
	size_t num_nodes = 0;

	dmubus_call("topology", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "self", &obj);
	if (obj) {
		json_object_object_get_ex(obj, "non1905_neighbors", &obj_nbr);
		if (obj_nbr != NULL)
			num_nodes = json_object_array_length(obj_nbr);
	}
	dmasprintf(value, "%d", num_nodes);
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "timestamp");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_EventType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "event_type");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_ReporterDeviceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "reporter");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_ReporterInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "reporter_interface");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_NeighborType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "is1905_neighbor");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyChangeLog_NeighborId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "neighbor");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyNonIEEE1905Neighbor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)data;
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905Id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ieee1905_macaddr");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "version");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_RegistrarFreqBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "registrar_freq_band");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_FriendlyName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "friendly_name");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "manufacturer_name");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerModel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "manufacturer_model");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_ControlURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "control_url");
	return 0;
}
#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_AssocWiFiNetworkDeviceRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_VendorPropertiesNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif
static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipv4_itfr_num");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipv6_itfr_num");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "local_interface_nbr");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_NonIEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_non1905_neighbors");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "num_neighbors");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_L2NeighborNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "l2_neighbor_num");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905Device_BridgingTupleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "bridging_tuple_num");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "mac_address");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipv4_address");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4AddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipv4_addr_type");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_DHCPServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "dhcp_addr");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "mac_address");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipv6_address");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipv6_addr_type");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressOrigin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "origin");
	return 0;
}
#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_MessageType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_OUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_Information(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_InterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "interface_id");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_MediaType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "media_type");
	return 0;
}

#if 0
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_PowerState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyVariant(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif
static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_NetworkMembership(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "network_membership");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_Role(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "role");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_APChannelBand(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ap_channel_band");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex1(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "freq_index1");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex2(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "freq_index2");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct param_node *node_val = (struct param_node *)data;
	char *linker = dmjson_get_value(node_val->node, 1, "non1905_nbr_localintf");

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIEEE1905%cAL%cNetworkTopology%cIEEE1905Device%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_NeighborInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct param_node *node_val = (struct param_node *)data;

	*value = node_val->data;
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "local_intf_id");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIEEE1905%cAL%cNetworkTopology%cIEEE1905Device%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_NeighborInterfaceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "local_nbr_id");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_BehindInterfaceIds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "behind_mac_id");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_LocalInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct obj_node *node_val = (struct obj_node *)data;
	char *linker = dmjson_get_value(node_val->node, 1, "1905_nbr_localintf");

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIEEE1905%cAL%cNetworkTopology%cIEEE1905Device%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_NeighborDeviceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct obj_node *node_val = (struct obj_node *)data;

	*value = dmjson_get_value(node_val->data, 1, "nbr_mac_id");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_MetricNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *link_metrics = NULL;
	size_t num = 0;
	const struct obj_node *node_val = (struct obj_node *)data;

	json_object_object_get_ex(node_val->data, "link_metrics", &link_metrics);
	if (link_metrics)
		num = json_object_array_length(link_metrics);

	dmasprintf(value, "%d", num);
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_NeighborMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "nbr_intf_macid");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_IEEE802dot1Bridge(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ieee_bridge");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "tx_packet_error");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rx_packet_error");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_TransmittedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "tx_packet_ok");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rx_packet_ok");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_MACThroughputCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "mac_thrput_capacity");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_LinkAvailability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "link_availability");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PHYRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "phy_rate");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_RSSI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

static int get_IEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTuple_InterfaceList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *tuple;
	char *tuple_mac = NULL, *interface = NULL;
	char list_val[512] = {0};
	int i = 0;

	dmjson_foreach_value_in_array((json_object *)data, tuple, tuple_mac, i, 1, "br_mac") {

		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIEEE1905%cAL%cNetworkTopology%cIEEE1905Device%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim, dm_delim), tuple_mac, &interface);
		if (interface == NULL)
			continue;

		if (*list_val == '\0')
			strncat(list_val, interface, strlen(interface));
		else {
			strncat(list_val, ",", 1);
			strncat(list_val, interface, strlen(interface));
		}
	}

	dmasprintf(value, "%s", list_val);
	return 0;
}

/*#Device.IEEE1905.AL.Security.SetupMethod!UCI:ieee1905/security,security/None*/
static int get_IEEE1905ALSecurity_SetupMethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("ieee1905", "security", "method", value);
	return 0;
}

static int set_IEEE1905ALSecurity_SetupMethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 3, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value("ieee1905", "security", "method", value);
		break;
	}
	return 0;
}

/*#Device.IEEE1905.AL.Security.Password!UCI:ieee1905/security,security/key*/
static int get_IEEE1905ALSecurity_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("ieee1905", "security", "key", value);
	return 0;
}

static int set_IEEE1905ALSecurity_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value("ieee1905", "security", "key", value);
		break;
	}
	return 0;
}

static int get_IEEE1905ALNetworkingRegistrar_Registrar2dot4(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("registrar2dot4", value);
}

static int get_IEEE1905ALNetworkingRegistrar_Registrar5(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("registrar5", value);
}

static int get_IEEE1905ALNetworkingRegistrar_Registrar60(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ieee1905_info("registrar60", value);
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.IEEE1905. *** */
DMOBJ tIEEE1905Obj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"AL", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALObj, tIEEE1905ALParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905Params[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Version", &DMREAD, DMT_STRING, get_IEEE1905_Version, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL. *** */
DMOBJ tIEEE1905ALObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceInst, NULL, NULL, NULL, tIEEE1905ALInterfaceObj, tIEEE1905ALInterfaceParams, NULL, BBFDM_BOTH},
{"ForwardingTable", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALForwardingTableObj, tIEEE1905ALForwardingTableParams, NULL, BBFDM_BOTH},
{"NetworkTopology", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyObj, tIEEE1905ALNetworkTopologyParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALSecurityParams, NULL, BBFDM_BOTH},
{"NetworkingRegistrar", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkingRegistrarParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905AL_IEEE1905Id, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905AL_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_IEEE1905AL_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
//{"LowerLayers", &DMREAD, DMT_STRING, get_IEEE1905AL_LowerLayers, NULL, NULL, NULL, BBFDM_BOTH},
{"RegistrarFreqBand", &DMREAD, DMT_STRING, get_IEEE1905AL_RegistrarFreqBand, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905AL_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}. *** */
DMOBJ tIEEE1905ALInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
//{"VendorProperties", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceVendorPropertiesInst, NULL, NULL, NULL, NULL, tIEEE1905ALInterfaceVendorPropertiesParams, NULL, BBFDM_BOTH},
{"Link", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALInterfaceLinkInst, NULL, NULL, NULL, tIEEE1905ALInterfaceLinkObj, tIEEE1905ALInterfaceLinkParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_InterfaceId, NULL, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"LastChange", &DMREAD, DMT_UNINT, get_IEEE1905ALInterface_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
//{"LowerLayers", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_LowerLayers, NULL, NULL, NULL, BBFDM_BOTH},
//{"InterfaceStackReference", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_InterfaceStackReference, NULL, NULL, NULL, BBFDM_BOTH},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_MediaType, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_GenericPhyOUI, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterface_GenericPhyVariant, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALInterface_GenericPhyURL, NULL, NULL, NULL, BBFDM_BOTH},
//{"SetIntfPowerStateEnabled", &DMWRITE, DMT_BOOL, get_IEEE1905ALInterface_SetIntfPowerStateEnabled, set_IEEE1905ALInterface_SetIntfPowerStateEnabled, NULL, NULL, BBFDM_BOTH},
{"PowerState", &DMWRITE, DMT_STRING, get_IEEE1905ALInterface_PowerState, set_IEEE1905ALInterface_PowerState, NULL, NULL, BBFDM_BOTH},
{"VendorPropertiesNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALInterface_VendorPropertiesNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"LinkNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALInterface_LinkNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}. *** */
DMLEAF tIEEE1905ALInterfaceVendorPropertiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"OUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceVendorProperties_OUI, NULL, NULL, NULL, BBFDM_BOTH},
//{"Information", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterfaceVendorProperties_Information, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.Link.{i}. *** */
DMOBJ tIEEE1905ALInterfaceLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Metric", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIEEE1905ALInterfaceLinkMetricParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALInterfaceLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_InterfaceId, NULL, NULL, NULL, BBFDM_BOTH},
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_IEEE1905Id, NULL, NULL, NULL, BBFDM_BOTH},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_MediaType, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_GenericPhyOUI, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALInterfaceLink_GenericPhyVariant, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALInterfaceLink_GenericPhyURL, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric. *** */
DMLEAF tIEEE1905ALInterfaceLinkMetricParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IEEE802dot1Bridge", &DMREAD, DMT_BOOL, get_IEEE1905ALInterfaceLinkMetric_IEEE802dot1Bridge, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketErrors", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PacketErrors, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketErrorsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PacketErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"TransmittedPackets", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_TransmittedPackets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"MACThroughputCapacity", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_MACThroughputCapacity, NULL, NULL, NULL, BBFDM_BOTH},
{"LinkAvailability", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_LinkAvailability, NULL, NULL, NULL, BBFDM_BOTH},
{"PHYRate", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_PHYRate, NULL, NULL, NULL, BBFDM_BOTH},
{"RSSI", &DMREAD, DMT_UNINT, get_IEEE1905ALInterfaceLinkMetric_RSSI, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.ForwardingTable. *** */
DMOBJ tIEEE1905ALForwardingTableObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"ForwardingRule", &DMWRITE, addObjIEEE1905ALForwardingTableForwardingRule, delObjIEEE1905ALForwardingTableForwardingRule, NULL, browseIEEE1905ALForwardingTableForwardingRuleInst, NULL, NULL, NULL, NULL, tIEEE1905ALForwardingTableForwardingRuleParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALForwardingTableParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"SetForwardingEnabled", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTable_SetForwardingEnabled, set_IEEE1905ALForwardingTable_SetForwardingEnabled, NULL, NULL, BBFDM_BOTH},
{"ForwardingRuleNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALForwardingTable_ForwardingRuleNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}. *** */
DMLEAF tIEEE1905ALForwardingTableForwardingRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceList", &DMWRITE, DMT_STRING, get_IEEE1905ALForwardingTableForwardingRule_InterfaceList, set_IEEE1905ALForwardingTableForwardingRule_InterfaceList, NULL, NULL, BBFDM_BOTH},
{"MACDestinationAddress", &DMWRITE, DMT_STRING, get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress, set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddress, NULL, NULL, BBFDM_BOTH},
{"MACDestinationAddressFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag, set_IEEE1905ALForwardingTableForwardingRule_MACDestinationAddressFlag, NULL, NULL, BBFDM_BOTH},
{"MACSourceAddress", &DMWRITE, DMT_STRING, get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress, set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddress, NULL, NULL, BBFDM_BOTH},
{"MACSourceAddressFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag, set_IEEE1905ALForwardingTableForwardingRule_MACSourceAddressFlag, NULL, NULL, BBFDM_BOTH},
{"EtherType", &DMWRITE, DMT_UNINT, get_IEEE1905ALForwardingTableForwardingRule_EtherType, set_IEEE1905ALForwardingTableForwardingRule_EtherType, NULL, NULL, BBFDM_BOTH},
{"EtherTypeFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag, set_IEEE1905ALForwardingTableForwardingRule_EtherTypeFlag, NULL, NULL, BBFDM_BOTH},
{"Vid", &DMWRITE, DMT_UNINT, get_IEEE1905ALForwardingTableForwardingRule_Vid, set_IEEE1905ALForwardingTableForwardingRule_Vid, NULL, NULL, BBFDM_BOTH},
{"VidFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_VidFlag, set_IEEE1905ALForwardingTableForwardingRule_VidFlag, NULL, NULL, BBFDM_BOTH},
{"PCP", &DMWRITE, DMT_UNINT, get_IEEE1905ALForwardingTableForwardingRule_PCP, set_IEEE1905ALForwardingTableForwardingRule_PCP, NULL, NULL, BBFDM_BOTH},
{"PCPFlag", &DMWRITE, DMT_BOOL, get_IEEE1905ALForwardingTableForwardingRule_PCPFlag, set_IEEE1905ALForwardingTableForwardingRule_PCPFlag, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology. *** */
DMOBJ tIEEE1905ALNetworkTopologyObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"ChangeLog", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyChangeLogInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyChangeLogParams, NULL, BBFDM_BOTH},
{"IEEE1905Device", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceObj, tIEEE1905ALNetworkTopologyIEEE1905DeviceParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"NonIEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyNonIEEE1905NeighborInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyNonIEEE1905NeighborParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IEEE1905ALNetworkTopology_Enable, set_IEEE1905ALNetworkTopology_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopology_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxChangeLogEntries", &DMWRITE, DMT_UNINT, get_IEEE1905ALNetworkTopology_MaxChangeLogEntries, set_IEEE1905ALNetworkTopology_MaxChangeLogEntries, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopology_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"IEEE1905DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopology_IEEE1905DeviceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ChangeLogNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopology_ChangeLogNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"NonIEEE1905NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopology_NonIEEE1905NeighborNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.ChangeLog.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyChangeLogParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"TimeStamp", &DMREAD, DMT_TIME, get_IEEE1905ALNetworkTopologyChangeLog_TimeStamp, NULL, NULL, NULL, BBFDM_BOTH},
{"EventType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_EventType, NULL, NULL, NULL, BBFDM_BOTH},
{"ReporterDeviceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_ReporterDeviceId, NULL, NULL, NULL, BBFDM_BOTH},
{"ReporterInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_ReporterInterfaceId, NULL, NULL, NULL, BBFDM_BOTH},
{"NeighborType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_NeighborType, NULL, NULL, NULL, BBFDM_BOTH},
{"NeighborId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyChangeLog_NeighborId, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.{CUSTOM_PREFIX}NonIEEE1905Neighbor.{i} *** */
DMLEAF tIEEE1905ALNetworkTopologyNonIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"NonIEEE1905NeighborId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyNonIEEE1905Neighbor, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}. *** */
DMOBJ tIEEE1905ALNetworkTopologyIEEE1905DeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressParams, NULL, BBFDM_BOTH},
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressParams, NULL, BBFDM_BOTH},
//{"VendorProperties", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesParams, NULL, BBFDM_BOTH},
{"Interface", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceParams, get_linker_topology_interface, BBFDM_BOTH},
{"NonIEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborParams, NULL, BBFDM_BOTH},
{"L2Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborParams, NULL, BBFDM_BOTH},
{"IEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborObj, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborParams, NULL, BBFDM_BOTH},
{"BridgingTuple", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IEEE1905Id", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905Id, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"RegistrarFreqBand", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_RegistrarFreqBand, NULL, NULL, NULL, BBFDM_BOTH},
{"FriendlyName", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_FriendlyName, NULL, NULL, NULL, BBFDM_BOTH},
{"ManufacturerName", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerName, NULL, NULL, NULL, BBFDM_BOTH},
{"ManufacturerModel", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_ManufacturerModel, NULL, NULL, NULL, BBFDM_BOTH},
{"ControlURL", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_ControlURL, NULL, NULL, NULL, BBFDM_BOTH},
//{"AssocWiFiNetworkDeviceRef", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905Device_AssocWiFiNetworkDeviceRef, NULL, NULL, NULL, BBFDM_BOTH},
//{"VendorPropertiesNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_VendorPropertiesNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv4AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_IPv6AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"NonIEEE1905NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_NonIEEE1905NeighborNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IEEE1905NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_IEEE1905NeighborNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"L2NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_L2NeighborNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"BridgingTupleNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905Device_BridgingTupleNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4Address", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4Address, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4AddressType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_IPv4AddressType, NULL, NULL, NULL, BBFDM_BOTH},
{"DHCPServer", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv4Address_DHCPServer, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6Address", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6Address, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6AddressType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressType, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6AddressOrigin", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIPv6Address_IPv6AddressOrigin, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceVendorPropertiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"MessageType", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_MessageType, NULL, NULL, NULL, BBFDM_BOTH},
//{"OUI", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_OUI, NULL, NULL, NULL, BBFDM_BOTH},
//{"Information", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceVendorProperties_Information, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_InterfaceId, NULL, NULL, NULL, BBFDM_BOTH},
{"MediaType", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_MediaType, NULL, NULL, NULL, BBFDM_BOTH},
//{"PowerState", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_PowerState, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyOUI", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyOUI, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyVariant", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyVariant, NULL, NULL, NULL, BBFDM_BOTH},
//{"GenericPhyURL", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_GenericPhyURL, NULL, NULL, NULL, BBFDM_BOTH},
{"NetworkMembership", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_NetworkMembership, NULL, NULL, NULL, BBFDM_BOTH},
{"Role", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_Role, NULL, NULL, NULL, BBFDM_BOTH},
{"APChannelBand", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_APChannelBand, NULL, NULL, NULL, BBFDM_BOTH},
{"FrequencyIndex1", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex1, NULL, NULL, NULL, BBFDM_BOTH},
{"FrequencyIndex2", &DMREAD, DMT_HEXBIN, get_IEEE1905ALNetworkTopologyIEEE1905DeviceInterface_FrequencyIndex2, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_LocalInterface, NULL, NULL, NULL, BBFDM_BOTH},
{"NeighborInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceNonIEEE1905Neighbor_NeighborInterfaceId, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.L2Neighbor.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceL2NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_LocalInterface, NULL, NULL, NULL, BBFDM_BOTH},
{"NeighborInterfaceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_NeighborInterfaceId, NULL, NULL, NULL, BBFDM_BOTH},
{"BehindInterfaceIds", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceL2Neighbor_BehindInterfaceIds, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}. *** */
DMOBJ tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Metric", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricInst, NULL, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LocalInterface", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_LocalInterface, NULL, NULL, NULL, BBFDM_BOTH},
{"NeighborDeviceId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_NeighborDeviceId, NULL, NULL, NULL, BBFDM_BOTH},
{"MetricNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905Neighbor_MetricNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetricParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"NeighborMACAddress", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_NeighborMACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"IEEE802dot1Bridge", &DMREAD, DMT_BOOL, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_IEEE802dot1Bridge, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketErrors", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrors, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketErrorsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"TransmittedPackets", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_TransmittedPackets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"MACThroughputCapacity", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_MACThroughputCapacity, NULL, NULL, NULL, BBFDM_BOTH},
{"LinkAvailability", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_LinkAvailability, NULL, NULL, NULL, BBFDM_BOTH},
{"PHYRate", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_PHYRate, NULL, NULL, NULL, BBFDM_BOTH},
{"RSSI", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopologyIEEE1905DeviceIEEE1905NeighborMetric_RSSI, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTupleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceList", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyIEEE1905DeviceBridgingTuple_InterfaceList, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.Security. *** */
DMLEAF tIEEE1905ALSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"SetupMethod", &DMWRITE, DMT_STRING, get_IEEE1905ALSecurity_SetupMethod, set_IEEE1905ALSecurity_SetupMethod, NULL, NULL, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_IEEE1905ALSecurity_Password, set_IEEE1905ALSecurity_Password, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkingRegistrar. *** */
DMLEAF tIEEE1905ALNetworkingRegistrarParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Registrar2dot4", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar2dot4, NULL, NULL, NULL, BBFDM_BOTH},
{"Registrar5", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar5, NULL, NULL, NULL, BBFDM_BOTH},
{"Registrar60", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkingRegistrar_Registrar60, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
