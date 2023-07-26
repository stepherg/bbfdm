/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#include "atm.h"

struct atm_args
{
	struct dmmap_dup *sections;
	char *device;
};

/**************************************************************************
* LINKER
***************************************************************************/
static int get_atm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = (data && ((struct atm_args *)data)->device) ? ((struct atm_args *)data)->device : "";
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_atm_link(struct atm_args *args, struct dmmap_dup *s, char *device)
{
	args->sections = s;
	args->device = device;
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
void remove_device_from_interface(struct uci_section *interface_s, char *device)
{
	char *curr_device  = NULL;
	char new_device[64] = {0};
	unsigned pos = 0;

	if (!interface_s || !device)
		return;

	dmuci_get_value_by_section_string(interface_s, "device", &curr_device);
	if (DM_STRLEN(curr_device) == 0)
		return;

	new_device[0] = '\0';

	char *pch = NULL, *spch = NULL;
	for (pch = strtok_r(curr_device, " ", &spch); pch; pch = strtok_r(NULL, " ", &spch)) {

		if (strcmp(pch, device) == 0)
			continue;

		pos += snprintf(&new_device[pos], sizeof(new_device) - pos, "%s ", pch);
	}

	if (pos)
		new_device[pos - 1] = 0;

	dmuci_set_value_by_section(interface_s, "device", new_device);
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.ATM.Link.{i}.!UCI:dsl/atm-device/dmmap_dsl*/
static int browseAtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *device;
	struct atm_args curr_atm_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dsl", "atm-device", "dmmap_dsl", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "device", &device);
		init_atm_link(&curr_atm_args, p, device);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "atmlinkinstance", "atmlinkalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_atm_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int add_atm_link(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_atm = NULL;
	char atm_device[16];

	snprintf(atm_device, sizeof(atm_device), "atm%s", *instance);

	dmuci_set_value("dsl", atm_device, "", "atm-device");
	dmuci_set_value("dsl", atm_device, "name", "ATM");
	dmuci_set_value("dsl", atm_device, "enabled", "0");
	dmuci_set_value("dsl", atm_device, "vpi", "8");
	dmuci_set_value("dsl", atm_device, "vci", "35");
	dmuci_set_value("dsl", atm_device, "device", atm_device);

	dmuci_add_section_bbfdm("dmmap_dsl", "atm-device", &dmmap_atm);
	dmuci_set_value_by_section(dmmap_atm, "section_name", atm_device);
	dmuci_set_value_by_section(dmmap_atm, "atmlinkinstance", *instance);
	return 0;
}

static int delete_atm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			uci_foreach_option_cont("network", "interface", "device", ((struct atm_args *)data)->device, s) {
				remove_device_from_interface(stmp, ((struct atm_args *)data)->device);
			}

			dmuci_delete_by_section((((struct atm_args *)data)->sections)->dmmap_section, NULL, NULL);
			dmuci_delete_by_section((((struct atm_args *)data)->sections)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("dsl", "atm-device", stmp, s) {
				struct uci_section *ns = NULL;
				char *device = NULL;

				dmuci_get_value_by_section_string(s, "device", &device);
				if (DM_STRLEN(device) == 0)
					continue;

				uci_foreach_option_cont("network", "interface", "device", device, ns) {
					remove_device_from_interface(ns, device);
				}

				get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(s), &ns);
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
/*#Device.ATM.Link.{i}.DestinationAddress!UCI:dsl/atm-device,@i-1/vpi&UCI:dsl/atm-device,@i-1/vci*/
static int get_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vpi, *vci;

	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->config_section, "vpi", &vpi);
	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->config_section, "vci", &vci);
	dmasprintf(value, "%s/%s", vpi, vci); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int set_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *vpi = NULL, *vci = NULL, *spch;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, DestinationAddress))
				return FAULT_9007;
			return 0;
		case VALUESET:
			vpi = strtok_r(value, "/", &spch);
			if (vpi)
				vci = strtok_r(NULL, "/", &spch);
			if (vpi && vci) {
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "vpi", vpi);
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "vci", vci);
			}
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.Name!UCI:dsl/atm-device,@i-1/name*/
static int get_atm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->config_section, "name", value);
	return 0;
}

/*#Device.ATM.Link.{i}.Encapsulation!UCI:dsl/atm-device,@i-1/encapsulation*/
static int get_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encapsulation;

	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->config_section, "encapsulation", &encapsulation);

	*value = (DM_LSTRCMP(encapsulation, "vcmux") == 0) ? "VCMUX" : "LLC";
	return 0;
}

static int set_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, Encapsulation, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "encapsulation", (DM_LSTRCMP(value, "LLC") == 0) ? "llc" : "vcmux");
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.LinkType!UCI:dsl/atm-device,@i-1/link_type*/
static int get_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *link_type;

	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->config_section, "link_type", &link_type);
	if (DM_LSTRCMP(link_type, "eoa") == 0)
		*value = "EoA";
	else if (DM_LSTRCMP(link_type, "ipoa") == 0)
		*value = "IPoA";
	else if (DM_LSTRCMP(link_type, "pppoa") == 0)
		*value = "PPPoA";
	else if (DM_LSTRCMP(link_type, "cip") == 0)
		*value = "CIP";
	else
		*value = "Unconfigured";
	return 0;
}

static int set_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, LinkType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "EoA") == 0)
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "link_type", "eoa");
			else if (DM_LSTRCMP(value, "IPoA") == 0)
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "link_type", "ipoa");
			else if (DM_LSTRCMP(value, "PPPoA") == 0)
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "link_type", "pppoa");
			else if (DM_LSTRCMP(value, "CIP") == 0)
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "link_type", "cip");
			else
				dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "link_type", "");
			return 0;
	}
	return 0;
}

static int get_atm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;
	char atm_file[128];

	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->dmmap_section, "atm_ll_link", &linker);
	adm_entry_get_linker_param(ctx, "Device.DSL.Channel.", linker, value);
	if (*value != NULL && (*value)[0] != '\0')
		return 0;

	snprintf(atm_file, sizeof(atm_file), "/sys/class/net/atm%ld", DM_STRTOL(instance) - 1);
	if (folder_exists(atm_file)) {
		*value = "Device.DSL.Channel.1";
		dmuci_set_value_by_section((((struct atm_args *)data)->sections)->dmmap_section, "atm_ll_link", "dsl_channel_1");
	}
	return 0;
}

static int set_atm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (DM_LSTRNCMP(value, "Device.DSL.Channel.1", strlen("Device.DSL.Channel.1")) != 0)
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct atm_args *)data)->sections)->dmmap_section, "atm_ll_link", "dsl_channel_1");
			break;
	}
	return 0;
}

static inline int ubus_atm_stats(char **value, char *stat_mod, void *data)
{
	json_object *res = NULL;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct atm_args *)data)->device, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "statistics", stat_mod);
	if ((*value)[0] == '\0')
		*value = "0";
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_atm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "rx_bytes", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_atm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "tx_bytes", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_atm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "rx_packets", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_atm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "tx_packets", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Enable!UCI:dsl/atm-device,@i-1/enabled*/
static int get_atm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct atm_args *)data)->sections)->config_section, "enabled", "1");
	return 0;
}

static int set_atm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct atm_args *)data)->sections)->config_section, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.Status!SYSFS:/sys/class/net/@Name/operstate*/
static int get_atm_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_net_device_status(((struct atm_args *)data)->device, value);
}

/*#Device.ATM.Link.{i}.Alias!UCI:dmmap_dsl/atm-device,@i-1/atmlinkalias*/
static int get_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct atm_args *)data)->sections)->dmmap_section, "atmlinkalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct atm_args *)data)->sections)->dmmap_section, "atmlinkalias", value);
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/*** ATM. ***/
DMOBJ tATMObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Link", &DMWRITE, add_atm_link, delete_atm_link, NULL, browseAtmLinkInst, NULL, NULL, tATMLinkObj, tATMLinkParams, get_atm_linker, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.0"},
{0}
};

/*** ATM.Link. ***/
DMOBJ tATMLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tATMLinkStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tATMLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_atm_alias, set_atm_alias, BBFDM_BOTH, "2.0"},
{"Enable", &DMWRITE, DMT_BOOL, get_atm_enable, set_atm_enable, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_atm_link_name, NULL, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_atm_status, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_atm_lower_layer, set_atm_lower_layer, BBFDM_BOTH, "2.0"},
{"LinkType", &DMWRITE, DMT_STRING, get_atm_link_type, set_atm_link_type, BBFDM_BOTH, "2.0"},
{"DestinationAddress", &DMWRITE, DMT_STRING, get_atm_destination_address, set_atm_destination_address, BBFDM_BOTH, "2.0"},
{"Encapsulation", &DMWRITE, DMT_STRING, get_atm_encapsulation, set_atm_encapsulation, BBFDM_BOTH, "2.0"},
{0}
};

/*** ATM.Link.Stats. ***/
DMLEAF tATMLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_atm_stats_bytes_sent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_atm_stats_bytes_received, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_atm_stats_pack_sent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_atm_stats_pack_received, NULL, BBFDM_BOTH, "2.0"},
{0}
};
