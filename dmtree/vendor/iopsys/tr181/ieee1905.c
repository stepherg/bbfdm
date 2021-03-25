/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "ieee1905.h"

static int browseIEEE1905ALNetworkTopologyNonIEEE1905NeighborInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *arrobj = NULL, *res_self = NULL;
	char *inst = NULL, *max_inst = NULL, *obj = NULL;
	int id = 0, i = 0;

	dmubus_call("topology", "dump", UBUS_ARGS{}, 0, &res_self);
	if (res_self)
		json_object_object_get_ex(res_self, "self", &res);
	dmjson_foreach_value_in_array(res, arrobj, obj, i, 1, "non1905_neighbors") {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)obj, inst) == DM_STOP)
			break;
	}
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
		num_nodes = (obj_nbr) ? json_object_array_length(obj_nbr) : 0;
	}
	dmasprintf(value, "%d", num_nodes);
	return 0;
}

static int get_IEEE1905ALNetworkTopologyNonIEEE1905Neighbor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)data;
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.IEEE1905.AL.NetworkTopology. *** */
DMOBJ tIOPSYS_IEEE1905ALNetworkTopologyObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{BBF_VENDOR_PREFIX"NonIEEE1905Neighbor", &DMREAD, NULL, NULL, NULL, browseIEEE1905ALNetworkTopologyNonIEEE1905NeighborInst, NULL, NULL, NULL, tIEEE1905ALNetworkTopologyNonIEEE1905NeighborParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIOPSYS_IEEE1905ALNetworkTopologyParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"NonIEEE1905NeighborNumberOfEntries", &DMREAD, DMT_UNINT, get_IEEE1905ALNetworkTopology_NonIEEE1905NeighborNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IEEE1905.AL.NetworkTopology.X_IOPSYS_EU_NonIEEE1905Neighbor.{i}. *** */
DMLEAF tIEEE1905ALNetworkTopologyNonIEEE1905NeighborParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"NonIEEE1905NeighborId", &DMREAD, DMT_STRING, get_IEEE1905ALNetworkTopologyNonIEEE1905Neighbor, NULL, BBFDM_BOTH},
{0}
};
