/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#include "atm.h"
#include "ptm.h"

struct ptm_args
{
	struct dmmap_dup *sections;
	char *device;
};

/**************************************************************************
* LINKER
***************************************************************************/
static int get_ptm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = (data && ((struct ptm_args *)data)->device) ? ((struct ptm_args *)data)->device : "";
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_ptm_link(struct ptm_args *args, struct dmmap_dup *s, char *device)
{
	args->sections = s;
	args->device = device;
	return 0;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.PTM.Link.{i}.!UCI:dsl/ptm-device/dmmap_dsl*/
static int browsePtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *device;
	struct ptm_args curr_ptm_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dsl", "ptm-device", "dmmap_dsl", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "device", &device);
		init_ptm_link(&curr_ptm_args, p, device);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "ptmlinkinstance", "ptmlinkalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ptm_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD OBJ
*************************************************************/
static int add_ptm_link(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_ptm = NULL;
	char ptm_device[16];

	snprintf(ptm_device, sizeof(ptm_device), "ptm%s", *instance);

	dmuci_set_value("dsl", ptm_device, "", "ptm-device");
	dmuci_set_value("dsl", ptm_device, "name", "PTM");
	dmuci_set_value("dsl", ptm_device, "device", ptm_device);
	dmuci_set_value("dsl", ptm_device, "enabled", "0");

	dmuci_add_section_bbfdm("dmmap_dsl", "ptm-device", &dmmap_ptm);
	dmuci_set_value_by_section(dmmap_ptm, "section_name", ptm_device);
	dmuci_set_value_by_section(dmmap_ptm, "ptmlinkinstance", *instance);
	return 0;
}

static int delete_ptm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		uci_foreach_option_cont("network", "interface", "device", ((struct ptm_args *)data)->device, s) {
			remove_device_from_interface(stmp, ((struct ptm_args *)data)->device);
		}

		dmuci_delete_by_section((((struct ptm_args *)data)->sections)->dmmap_section, NULL, NULL);
		dmuci_delete_by_section((((struct ptm_args *)data)->sections)->config_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("dsl", "ptm-device", stmp, s) {
			struct uci_section *ns = NULL;
			char *device = NULL;

			dmuci_get_value_by_section_string(s, "device", &device);
			if (DM_STRLEN(device) == 0)
				continue;

			uci_foreach_option_cont("network", "interface", "device", device, ns) {
				remove_device_from_interface(ns, device);
			}

			get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(s), &ns);
			dmuci_delete_by_section(ns, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.PTM.Link.{i}.Enable!UCI:dsl/ptm-device,@i-1/enabled*/
static int get_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct ptm_args *)data)->sections)->config_section, "enabled", "1");
	return 0;
}

static int set_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct ptm_args *)data)->sections)->config_section, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.PTM.Link.{i}.Status!SYSFS:/sys/class/net/@Name/operstate*/
static int get_ptm_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_net_device_status(((struct ptm_args *)data)->device, value);
}

/*#Device.PTM.Link.{i}.Alias!UCI:dmmap_dsl/ptm-device,@i-1/ptmlinkalias*/
static int get_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (((struct ptm_args *)data)->sections)->dmmap_section, "ptmlinkalias", instance, value);
}

static int set_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (((struct ptm_args *)data)->sections)->dmmap_section, "ptmlinkalias", instance, value);
}

/*#Device.PTM.Link.{i}.Name!UCI:dsl/ptm-device,@i-1/name*/
static int get_ptm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct ptm_args *)data)->sections)->config_section, "name", value);
	return 0;
}

static int get_ptm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct ptm_args *)data)->sections)->dmmap_section, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		char ptm_file[128] = {0};

		adm_entry_get_reference_param(ctx, "Device.FAST.Line.*.Status", "Up", value);
		if (DM_STRLEN(*value))
			return 0;

		snprintf(ptm_file, sizeof(ptm_file), "/sys/class/net/ptm%ld", DM_STRTOL(instance) - 1);
		if (folder_exists(ptm_file)) {
			adm_entry_get_reference_param(ctx, "Device.DSL.Channel.*.Name", "1", value);
			if (DM_STRLEN(*value))
				return 0;
		}

		adm_entry_get_reference_param(ctx, "Device.FAST.Line.*.Name", "1", value);

		// Store LowerLayers value
		dmuci_set_value_by_section((((struct ptm_args *)data)->sections)->dmmap_section, "LowerLayers", *value);
	} else {
		if (!adm_entry_object_exists(ctx, *value))
			*value = "";
	}

	return 0;
}

static int set_ptm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (DM_LSTRNCMP(reference.path, "Device.DSL.Channel.1", strlen("Device.DSL.Channel.1")) != 0 && DM_LSTRNCMP(reference.path, "Device.FAST.Line.1", strlen("Device.FAST.Line.1")) != 0)
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct ptm_args *)data)->sections)->dmmap_section, "LowerLayers", reference.path);
			break;
	}
	return 0;
}

static inline int ubus_ptm_stats(char **value, const char *stat_mod, void *data)
{
	json_object *res = NULL;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct ptm_args *)data)->device, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "statistics", stat_mod);
	if ((*value)[0] == '\0')
		*value = "0";
	return 0;
}

/*#Device.PTM.Link.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_ptm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ptm_stats(value, "rx_bytes", data);
}

/*#Device.PTM.Link.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_ptm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ptm_stats(value, "tx_bytes", data);
}

/*#Device.PTM.Link.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_ptm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ptm_stats(value, "rx_packets", data);
}

/*#Device.PTM.Link.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_ptm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_ptm_stats(value, "tx_packets", data);
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.PTM. *** */
DMOBJ tPTMObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Link", &DMWRITE, add_ptm_link, delete_ptm_link, NULL, browsePtmLinkInst, NULL, NULL, tPTMLinkObj, tPTMLinkParams, get_ptm_linker, BBFDM_BOTH, NULL},
{0}
};

/* *** Device.PTM.Link.{i}. *** */
DMOBJ tPTMLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPTMLinkStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tPTMLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_ptm_enable, set_ptm_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ptm_status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ptm_alias, set_ptm_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_ptm_link_name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ptm_lower_layer, set_ptm_lower_layer, BBFDM_BOTH, DM_FLAG_REFERENCE},
{0}
};

/* *** Device.PTM.Link.{i}.Stats. *** */
DMLEAF tPTMLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_ptm_stats_bytes_sent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_ptm_stats_bytes_received, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ptm_stats_pack_sent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ptm_stats_pack_received, NULL, BBFDM_BOTH},
{0}
};
