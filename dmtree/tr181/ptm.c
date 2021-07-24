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

#include "dmentry.h"
#include "atm.h"
#include "ptm.h"

struct ptm_args
{
	struct uci_section *ptm_sec;
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
static inline int init_ptm_link(struct ptm_args *args, struct uci_section *s, char *device)
{
	args->ptm_sec = s;
	args->device = device;
	return 0;
}

/**************************************************************************
* SET & GET DSL LINK PARAMETERS
***************************************************************************/
/*#Device.PTM.Link.{i}.Enable!UCI:dsl/ptm-device,@i-1/enabled*/
static int get_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct ptm_args *)data)->ptm_sec, "enabled", "1");
	return 0;
}

static int set_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct ptm_args *)data)->ptm_sec, "enabled", b ? "1" : "0");
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
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ptmlinkalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ptmlinkalias", value);
			return 0;
	}
	return 0;
}

/*#Device.PTM.Link.{i}.Name!UCI:dsl/ptm-device,@i-1/name*/
static int get_ptm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ptm_args *)data)->ptm_sec, "name", value);
	return 0;
}

static int find_lower_layer_by_dmmap_link(struct dmctx *ctx, void *data, char* dm_object, char **value)
{
	char *linker = NULL;
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ptm_ll_link", &linker);
	if (linker != NULL)
		adm_entry_get_linker_param(ctx, dm_object, linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_ptm_dsl_channel(struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ptm_file = NULL;
	struct uci_section *dmmap_section = NULL;

	dmasprintf(&ptm_file, "/sys/class/net/ptm%d", atoi(instance) - 1);
	if (folder_exists(ptm_file)) {
		*value = "Device.DSL.Channel.1";
		get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
		dmuci_set_value_by_section(dmmap_section, "ptm_ll_link", "fast_line_1");
	}

	return 0;
}

static int get_ptm_fast_line(struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	json_object *res = NULL, *line_obj = NULL;

	dmubus_call("fast", "status", UBUS_ARGS{}, 0, &res);
	if (!res)
		return 0;
	line_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "line");
	if (!line_obj)
		return 0;
	if ( strcmp(dmjson_get_value(line_obj, 1, "status"), "up") == 0) {
		*value = "Device.FAST.Line.1";
		get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
		dmuci_set_value_by_section(dmmap_section, "ptm_ll_link", "fast_line_1");
	}
	return 0;
}

static int get_ptm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_ptm_fast_line(ctx, data, instance, value);
	if (*value == NULL || (*value)[0] == '\0')
		get_ptm_dsl_channel(ctx, data, instance, value);
	if (*value == NULL || (*value)[0] == '\0')
		find_lower_layer_by_dmmap_link(ctx, data, "Device.FAST.Line.", value);
	if (*value == NULL || (*value)[0] == '\0')
		find_lower_layer_by_dmmap_link(ctx, data, "Device.DSL.Channel.", value);
	return 0;
}

static int set_ptm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (strncmp(value, "Device.DSL.Channel.1", strlen("Device.DSL.Channel.1")) != 0 && strncmp(value, "Device.FAST.Line.1", strlen("Device.FAST.Line.1")) != 0)
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
			if (strcmp(value, "Device.DSL.Channel.1") == 0)
				dmuci_set_value_by_section(dmmap_section, "ptm_ll_link", "dsl_channel_1");
			else
				dmuci_set_value_by_section(dmmap_section, "ptm_ll_link", "fast_line_1");
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

/*************************************************************
* ADD OBJ
*************************************************************/
static int add_ptm_link(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *dmmap_ptm = NULL;
	char ptm_device[16];

	char *instance = get_last_instance_bbfdm("dmmap_dsl", "ptm-device", "ptmlinkinstance");
	snprintf(ptm_device, sizeof(ptm_device), "ptm%d", instance ? atoi(instance) : 0);

	dmuci_set_value("dsl", ptm_device, "", "ptm-device");
	dmuci_set_value("dsl", ptm_device, "name", "PTM");
	dmuci_set_value("dsl", ptm_device, "device", ptm_device);
	dmuci_set_value("dsl", ptm_device, "enabled", "0");

	dmuci_add_section_bbfdm("dmmap_dsl", "ptm-device", &dmmap_ptm);
	dmuci_set_value_by_section(dmmap_ptm, "section_name", ptm_device);
	*instancepara = update_instance(instance, 2, dmmap_ptm, "ptmlinkinstance");
	return 0;
}

static int delete_ptm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_section = NULL;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
		dmuci_delete_by_section(dmmap_section, NULL, NULL);

		dmuci_delete_by_section(((struct ptm_args *)data)->ptm_sec, NULL, NULL);

		uci_foreach_option_cont("network", "interface", "device", ((struct ptm_args *)data)->device, s) {
			if (stmp && ((struct ptm_args *)data)->device != NULL)
				remove_device_from_interface(stmp, ((struct ptm_args *)data)->device);
			stmp = s;
		}
		if (stmp != NULL && ((struct ptm_args *)data)->device != NULL)
			remove_device_from_interface(stmp, ((struct ptm_args *)data)->device);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("dsl", "ptm-device", stmp, s) {
			struct uci_section *ns = NULL, *nss = NULL;
			char *device = NULL;

			dmuci_get_value_by_section_string(s, "device", &device);
			uci_foreach_option_cont("network", "interface", "device", device, ns) {
				if (nss != NULL && device != NULL)
					remove_device_from_interface(nss, device);
				nss = ns;
			}
			if (nss != NULL && device != NULL)
				remove_device_from_interface(nss, device);

			get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.PTM.Link.{i}.!UCI:dsl/ptm-device/dmmap_dsl*/
static int browsePtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *device;
	struct ptm_args curr_ptm_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dsl", "ptm-device", "dmmap_dsl", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "device", &device);
		init_ptm_link(&curr_ptm_args, p->config_section, device);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "ptmlinkinstance", "ptmlinkalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ptm_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/* *** Device.PTM. *** */
DMOBJ tPTMObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Link", &DMWRITE, add_ptm_link, delete_ptm_link, NULL, browsePtmLinkInst, NULL, NULL, tPTMLinkObj, tPTMLinkParams, get_ptm_linker, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

/* *** Device.PTM.Link.{i}. *** */
DMOBJ tPTMLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPTMLinkStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tPTMLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ptm_enable, set_ptm_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ptm_status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ptm_alias, set_ptm_alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_ptm_link_name, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ptm_lower_layer, set_ptm_lower_layer, BBFDM_BOTH},
{0}
};

/* *** Device.PTM.Link.{i}.Stats. *** */
DMLEAF tPTMLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_ptm_stats_bytes_sent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_ptm_stats_bytes_received, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ptm_stats_pack_sent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ptm_stats_pack_received, NULL, BBFDM_BOTH},
{0}
};
