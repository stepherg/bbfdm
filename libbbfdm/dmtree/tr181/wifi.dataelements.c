/*
 * Copyright (C) 2023 IOPSYS Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "wifi.dataelements.h"

enum set_ssid_operations {
	SET_SSID_ADD,
	SET_SSID_REMOVE,
	SET_SSID_CHANGE,
	SET_SSID_INVALID
};

typedef struct set_ssid_operate_param {
	char *ssid;
	char *enab;
	char *key;
	char *band;
	char *akm;
	char *adv;
	char *mfp;
	char *haul;
} set_ssid_param;

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static char *get_AKMs_dm_name(const char *value)
{
	if (DM_LSTRCMP(value, "sae") == 0) {
		return "sae";
	}

	if (DM_LSTRCMP(value, "sae-mixed") == 0) {
		return "psk+sae";
	}

	if (DM_LSTRCMP(value, "psk2") == 0) {
		return "psk";
	}

	if (DM_LSTRCMP(value, "dpp") == 0) {
		return "dpp";
	}

	if (DM_LSTRCMP(value, "dpp+sae") == 0) {
		return "dpp+sae";
	}

	if (DM_LSTRCMP(value, "dpp+sae-mixed") == 0) {
		return "dpp+psk+sae";
	}

	return "";
}

static char *get_AKMs_uci_name(const char *value)
{
	if (DM_LSTRCMP(value, "psk") == 0) {
		return "psk2";
	} else if(DM_LSTRCMP(value, "dpp") == 0) {
		return "dpp";
	} else if(DM_LSTRCMP(value, "sae") == 0) {
		return "sae";
	} else if(DM_LSTRCMP(value, "psk+sae") == 0) {
		return "sae-mixed";
	} else if(DM_LSTRCMP(value, "dpp+sae") == 0) {
		return "dpp+sae";
	} else if(DM_LSTRCMP(value, "dpp+psk+sae") == 0) {
		return "dpp+sae-mixed";
	}

	return "sae-mixed";
}

static char *get_mfp_dm_value_by_section(struct uci_section *sec)
{
	char *mfp = NULL;
	char *encr = NULL;
	unsigned int res = 0;

	dmuci_get_value_by_section_string(sec, "mfp", &mfp);
	if (DM_STRLEN(mfp) == 0) {
		dmuci_get_value_by_section_string(sec, "encryption", &encr);
		if (DM_LSTRCMP(encr, "psk2") == 0) {
			res = 0;
		} else if (DM_LSTRCMP(encr, "sae-mixed") == 0 || DM_LSTRCMP(encr, "sae-mixed+dpp") == 0) {
			res = 1;
		} else {
			res = 2;
		}
	} else {
		res = DM_STRTOUL(mfp);
	}

	switch (res) {
	case 0:
		return "Disabled";
	case 1:
		return "Optional";
	case 2:
		return "Required";
	}

	return "Disabled";
}

static char *get_mfp_uci_value(const char *mfp)
{
	if (DM_LSTRCMP(mfp, "Disabled") == 0)
		return "0";

	if (DM_LSTRCMP(mfp, "Optional") == 0)
		return "1";

	if (DM_LSTRCMP(mfp, "Required") == 0)
		return "2";

	return "";
}

static char *get_haultype_dm_value_by_section(struct uci_section *sec)
{
	char *type = NULL;
	dmuci_get_value_by_section_string(sec, "type", &type);

	if (DM_LSTRCMP(type, "backhaul") == 0) {
		return "Backhaul";
	}

	return "Fronthaul";
}

static char *get_haultype_uci_value(const char *value)
{
	if (DM_LSTRCMP(value, "Backhaul") == 0) {
		return "backhaul";
	}

	return "fronthaul";
}

static char *get_adv_enabled_by_section(struct uci_section *sec)
{
	char *hidden = NULL, *type = NULL;
	char *value = "0";

	dmuci_get_value_by_section_string(sec, "hidden", &hidden);
	if (DM_STRLEN(hidden) == 0) {
		dmuci_get_value_by_section_string(sec, "type", &type);
		if (DM_LSTRCMP(type, "fronthaul") == 0) {
			value = "1";
		} else {
			value = "0";
		}
	} else {
		value = (hidden[0] == '0') ? "1" : "0";
	}

	return value;
}

static int get_requested_operation(const char *req)
{
	if (DM_LSTRCMP(req, "Add") == 0)
		return SET_SSID_ADD;

	if (DM_LSTRCMP(req, "Remove") == 0)
		return SET_SSID_REMOVE;

	if (DM_LSTRCMP(req, "Change") == 0)
		return SET_SSID_CHANGE;

	return SET_SSID_INVALID;
}

static int validate_band_value(struct dmctx *ctx, char *band)
{
	char *band_list[] = {"2.4", "5", "6", "All", NULL};

	if (DM_STRLEN(band) == 0)
		return 0;

	if (bbfdm_validate_string_list(ctx, band, -1, -1, -1, -1, -1, band_list, NULL))
		return -1;

	/* if "All" is present then no other values are allowed in list */
	if (DM_STRSTR(band, "All") != NULL && DM_STRLEN(band) > 3)
		return -1;

	return 0;
}

static int validate_akms_value(struct dmctx *ctx, char *akms)
{
	char *akms_list[] = {"psk", "dpp", "sae", "psk+sae", "dpp+sae", "dpp+psk+sae", NULL};

	if (DM_STRLEN(akms) == 0)
		return 0;

	if (bbfdm_validate_string_list(ctx, akms, -1, -1, -1, -1, -1, akms_list, NULL))
		return -1;

	return 0;
}

static int validate_mfp_value(struct dmctx *ctx, char *mfp)
{
	char *mfp_list[] = {"Disabled", "Optional", "Required", NULL};

	if (DM_STRLEN(mfp) == 0)
		return 0;

	if (bbfdm_validate_string(ctx, mfp, -1, -1, mfp_list, NULL))
		return -1;

	return 0;
}

static int validate_haultype_value(struct dmctx *ctx, char *haul)
{
	char *haul_list[] = {"Fronthaul", "Backhaul", NULL};

	if (DM_STRLEN(haul) == 0)
		return 0;

	if (bbfdm_validate_string_list(ctx, haul, -1, -1, -1, -1, -1, haul_list, NULL))
		return -1;

	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
/*static int addObjWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}*/

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseWiFiDataElementsNetworkSSIDInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data *curr_data = NULL;
	char *inst = NULL, *mld_id = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("mapcontroller", "ap", "dmmap_mapcontroller", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {
		// Show the ap sections which does not have mld_id
		dmuci_get_value_by_section_string(curr_data->config_section, "mld_id", &mld_id);
		if (DM_STRLEN(mld_id) != 0)
			continue;

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "wifi_da_ssid_instance", "wifi_da_ssid_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static struct uci_section *find_device_uci_section(char *unique_key)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("mapcontroller", "node", s) {
		char *agent_id = NULL;

		dmuci_get_value_by_section_string(s, "agent_id", &agent_id);

		// Device found ==> return the current device uci section
		if (DM_STRCMP(agent_id, unique_key) == 0)
			return s;
	}

	return NULL;
}

static struct uci_section *find_radio_uci_section(char *agent_id, char *unique_key)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("mapcontroller", "radio", "agent_id", agent_id, s) {
		char *macaddr = NULL;

		dmuci_get_value_by_section_string(s, "macaddr", &macaddr);

		// Radio found ==> return the current radio uci section
		if (DM_STRCMP(macaddr, unique_key) == 0)
			return s;
	}

	return NULL;
}

static int browseWiFiDataElementsNetworkDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *data_arr = NULL, *data_obj = NULL, *res = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int i = 0, id = 0;

	dmubus_call("wifi.dataelements.collector", "dump2", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object *dev_arr = NULL, *dev_obj = NULL;
		int j = 0;

		dmjson_foreach_obj_in_array(data_obj, dev_arr, dev_obj, j, 2, "wfa-dataelements:Network", "DeviceList") {

			char *key = dmjson_get_value(dev_obj, 1, "ID");
			if (!key || *key == '\0')
				continue;

			curr_data.json_object = dev_obj;
			curr_data.config_section = find_device_uci_section(key);

			inst = handle_instance_without_section(dmctx, parent_node, ++id);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
				return 0;
		}
	}

	return 0;
}

static int browseWiFiDataElementsNetworkDeviceDefault8021QInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceSSIDtoVIDMappingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ssid_to_vid_arr = NULL, *ssid_to_vid_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, ssid_to_vid_arr, ssid_to_vid_obj, i, 1, "SSIDtoVIDMapping") {

		curr_data.json_object = ssid_to_vid_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_status_arr = NULL, *cac_status_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, cac_status_arr, cac_status_obj, i, 1, "CACStatus") {

		curr_data.json_object = cac_status_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceIEEE1905SecurityInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *ieee1905_security_arr = NULL, *ieee1905_security_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, ieee1905_security_arr, ieee1905_security_obj, i, 1, "IEEE1905Security") {

		curr_data.json_object = ieee1905_security_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}


static int browseWiFiDataElementsNetworkDeviceRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct json_object *radio_arr = NULL, *radio_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int i = 0, id = 0;

	char *agent_id = dmjson_get_value(((struct dm_data *)prev_data)->json_object, 1, "ID");

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, radio_arr, radio_obj, i, 1, "RadioList") {

		char mac[32] = {0};
		char *radio_id = dmjson_get_value(radio_obj, 1, "ID");
		char *str = base64_decode(radio_id);

		/* Cant use strlen on byte array that might genuinely include 0x00 */
		/* but to get 6 bytes, need 8 input BASE64 chars - check for that */
		if ((str != NULL) && (DM_STRLEN(radio_id) == 8))
			string_to_mac(str, 6, mac, sizeof(mac));

		if (DM_STRLEN(mac) == 0)
			continue;

		curr_data.json_object = radio_obj;
		curr_data.config_section = find_radio_uci_section(agent_id, mac);

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			return 0;
	}

	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_available_channel_arr = NULL, *cac_available_channel_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, cac_available_channel_arr, cac_available_channel_obj, i, 1, "CACAvailableChannel") {

		curr_data.json_object = cac_available_channel_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_non_occupancy_channel_arr = NULL, *cac_non_occupancy_channel_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, cac_non_occupancy_channel_arr, cac_non_occupancy_channel_obj, i, 1, "CACNonOccupancyChannel") {

		curr_data.json_object = cac_non_occupancy_channel_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_active_channel_arr = NULL, *cac_active_channel_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, cac_active_channel_arr, cac_active_channel_obj, i, 1, "CACActiveChannel") {

		curr_data.json_object = cac_active_channel_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, opclass_arr, opclass_obj, i, 1, "CurrentOperatingClassProfile") {

		curr_data.json_object = opclass_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *bss_arr = NULL, *bss_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, bss_arr, bss_obj, i, 1, "BSSList") {

		curr_data.json_object = bss_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *scanres_arr = NULL, *scanres_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, scanres_arr, scanres_obj, i, 1, "ScanResult") {

		curr_data.json_object = scanres_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*static int browseWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
*/

static int browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *unassoc_arr = NULL, *unassoc_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, unassoc_arr, unassoc_obj, i, 1, "UnassociatedSTA") {

		curr_data.json_object = unassoc_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, opclass_arr, opclass_obj, i, 2, "Capabilities", "CapableOperatingClassProfile") {

		curr_data.json_object = opclass_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *sta_obj = NULL, *sta_arr = NULL, *inst_arr = NULL, *inst_obj = NULL;
	struct dm_data curr_data = {0};
	char *sta = NULL, *inst = NULL;
	int sta_id = 0, inst_id = 0, ob = 0;

	sta = dmjson_get_value(((struct dm_data *)prev_data)->json_object, 1, "MACAddress");
	if (!DM_STRLEN(sta))
		return 0;

	dmubus_call("map.controller", "dump_steer_history", UBUS_ARGS{0}, 0, &res);

	dmjson_foreach_obj_in_array(res, sta_arr, sta_obj, sta_id, 1, "sta") {
		char *mac = dmjson_get_value(sta_obj, 1, "macaddr");

		if (DM_STRCMP(mac, sta) != 0)
			continue;

		dmjson_foreach_obj_in_array(sta_obj, inst_arr, inst_obj, inst_id, 1, "history") {

			curr_data.json_object = inst_obj;

			inst = handle_instance_without_section(dmctx, parent_node, ++ob);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
				break;
		}
		break;
	}

	return 0;
}

/*
static int browseWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *qmdescriptor_arr = NULL, *qmdescriptor_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, qmdescriptor_arr, qmdescriptor_obj, i, 1, "QMDescriptor") {

		curr_data.json_object = qmdescriptor_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}
*/

static int browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *sta_arr = NULL, *sta_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, sta_arr, sta_obj, i, 1, "STAList") {

		curr_data.json_object = sta_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_scan_arr = NULL, *opclass_scan_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, opclass_scan_arr, opclass_scan_obj, i, 1, "OpClassScan") {

		curr_data.json_object = opclass_scan_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *chscan_arr = NULL, *chscan_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, chscan_arr, chscan_obj, i, 1, "ChannelScan") {

		curr_data.json_object = chscan_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *neigh_arr = NULL, *neigh_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, neigh_arr, neigh_obj, i, 1, "NeighborBSS") {

		curr_data.json_object = neigh_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, opclass_arr, opclass_obj, i, 2, "ScanCapability", "OpClassChannels") {

		curr_data.json_object = opclass_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cacmethod_arr = NULL, *cacmethod_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, cacmethod_arr, cacmethod_obj, i, 2, "CACCapability", "CACMethod") {

		curr_data.json_object = cacmethod_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *op_class_arr = NULL, *op_class_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, op_class_arr, op_class_obj, i, 1, "OpClassChannels") {

		curr_data.json_object = op_class_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*
static int browseWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *curropclass_arr = NULL, *curropclass_obj = NULL;
	struct dm_data curr_data = {0};
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(((struct dm_data *)prev_data)->json_object, curropclass_arr, curropclass_obj, i, 2, "MultiAPDevice", "Backhaul_CurrentOperatingClassProfile") {

		curr_data.json_object = curropclass_obj;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, inst) == DM_STOP)
			break;
	}
	return 0;
}
*/

/**************************************************************************
* SET AND GET ALIAS
***************************************************************************/
static int get_WiFiDataElementsNetwork_option(char *method_name, const char *option, bool is_array, char **value)
{
	json_object *res = NULL;
	json_object *jobj = NULL;

	dmubus_call("wifi.dataelements.collector", method_name, UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "data");
	DM_ASSERT(jobj, *value = "");
	if (is_array)
		*value = dmjson_get_value_array_all(jobj, ",", 2, "wfa-dataelements:Network", option);
	else
		*value = dmjson_get_value(jobj, 2, "wfa-dataelements:Network", option);
	return 0;
}

/*#Device.WiFi.DataElements.Network.ID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.ID*/
static int get_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump2", "ID", false, value);
}

/*#Device.WiFi.DataElements.Network.TimeStamp!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.TimeStamp*/
static int get_WiFiDataElementsNetwork_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump2", "TimeStamp", false, value);
}

/*#Device.WiFi.DataElements.Network.ControllerID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.ControllerID*/
static int get_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump2", "ControllerID", false, value);
}

static int get_WiFiDataElementsNetwork_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsNetworkDeviceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_WiFiDataElementsNetwork_MSCSDisallowedStaList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump2", "MSCSDisallowedStaList", true, value);
}

static int get_WiFiDataElementsNetwork_SCSDisallowedStaList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump2", "SCSDisallowedStaList", true, value);
}

static int get_WiFiDataElementsNetwork_SSIDNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsNetworkSSIDInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "ssid", value);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_Band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "band", value);
	if (DM_STRTOUL(*value) == 2) {
		*value = "2.4";
	}

	return 0;
}

static int get_WiFiDataElementsNetworkSSID_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "enabled", "1");
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_AKMs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = NULL;
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "encryption", &res);

	*value = get_AKMs_dm_name(res);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_AdvEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_adv_enabled_by_section(((struct dm_data *)data)->config_section);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_MFP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_mfp_dm_value_by_section(((struct dm_data *)data)->config_section);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_Haul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_haultype_dm_value_by_section(((struct dm_data *)data)->config_section);
	return 0;
}

static int ubus_get_multiap_steering_summary_stats(const char *option, char **value)
{
	json_object *res = NULL;
	json_object *jobj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump2", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "data");
	DM_ASSERT(jobj, *value = "0");
	*value = dmjson_get_value(jobj, 3, "wfa-dataelements:Network", "MultiAPSteeringSummaryStats", option);
	return 0;
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_NoCandidateAPFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("NoCandidateAPFailures", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BlacklistAttempts", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistSuccesses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BlacklistSuccesses", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BlacklistFailures", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BTMAttempts", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMSuccesses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BTMSuccesses", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BTMFailures", value);
}

static int get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMQueryResponses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ubus_get_multiap_steering_summary_stats("BTMQueryResponses", value);
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDevice_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].MultiAPCapabilities*/
static int get_WiFiDataElementsNetworkDevice_MultiAPCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MultiAPCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].CollectionInterval*/
static int get_WiFiDataElementsNetworkDevice_CollectionInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CollectionInterval");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ReportUnsuccessfulAssociations!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].ReportUnsuccessfulAssociations*/
static int get_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ReportUnsuccessfulAssociations");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "report_sta_assocfails", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_MaxReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MaxReportingRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_APMetricsReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "report_metric_periodic", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_APMetricsReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "report_metric_periodic", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Manufacturer!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].Manufacturer*/
static int get_WiFiDataElementsNetworkDevice_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Manufacturer");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.SerialNumber!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].SerialNumber*/
static int get_WiFiDataElementsNetworkDevice_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SerialNumber");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_ManufacturerModel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ManufacturerModel");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.SoftwareVersion!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].SoftwareVersion*/
static int get_WiFiDataElementsNetworkDevice_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SoftwareVersion");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ExecutionEnv!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].ExecutionEnv*/
static int get_WiFiDataElementsNetworkDevice_ExecutionEnv(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ExecutionEnv");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_DSCPMap(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "DSCPMap");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.MaxPrioritizationRules!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].MaxPrioritizationRules*/
static int get_WiFiDataElementsNetworkDevice_MaxPrioritizationRules(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MaxPrioritizationRules");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.PrioritizationSupport!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].PrioritizationSupport*/
static int get_WiFiDataElementsNetworkDevice_PrioritizationSupport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "PrioritizationSupport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.MaxVIDs!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].MaxVIDs*/
static int get_WiFiDataElementsNetworkDevice_MaxVIDs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MaxVIDs");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_APMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "APMetricsWiFi6");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.CountryCode!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].CountryCode*/
static int get_WiFiDataElementsNetworkDevice_CountryCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CountryCode");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_list = NULL;
	dmuci_get_value_by_section_list(((struct dm_data *)data)->config_section, "steer_exclude", &uci_list);
	*value = dmuci_list_to_string(uci_list, ",");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length = 0;
	char **arr = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			return 0;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "steer_exclude", "");
			for (int i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct dm_data *)data)->config_section, "steer_exclude", arr[i]);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_list = NULL;
	dmuci_get_value_by_section_list(((struct dm_data *)data)->config_section, "steer_exclude_btm", &uci_list);
	*value = dmuci_list_to_string(uci_list, ",");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length = 0;
	char **arr = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			return 0;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "steer_exclude_btm", "");
			for (int i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct dm_data *)data)->config_section, "steer_exclude_btm", arr[i]);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.DFSEnable!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].DFSEnable*/
static int get_WiFiDataElementsNetworkDevice_DFSEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "DFSEnable");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ReportIndependentScans!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].ReportIndependentScans*/
static int get_WiFiDataElementsNetworkDevice_ReportIndependentScans(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ReportIndependentScans");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_ReportIndependentScans(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "report_scan", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "AssociatedSTAinAPMetricsWiFi6");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
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

static int get_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MaxUnsuccessfulAssociationReportingRate");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct dm_data *)data)->config_section)->config_section, "report_sta_assocfails_rate", value);
			return 0;
	}
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.STASteeringState!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].STASteeringState*/
static int get_WiFiDataElementsNetworkDevice_STASteeringState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "STASteeringState");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CoordinatedCACAllowed");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct dm_data *)data)->config_section)->config_section, "coordinated_cac", b ? "1" : "0");
			return 0;
	}
	return 0;
}*/

static int get_WiFiDataElementsNetworkDevice_TrafficSeparationAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("mapcontroller", "controller", "enable_ts", "0");
	return 0;
}

/*static int get_WiFiDataElementsNetworkDevice_ServicePrioritizationAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ServicePrioritizationAllowed");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].NumberOfRadios*/
static int get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "RadioNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_Default8021QNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Default8021QNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SSIDtoVIDMappingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SSIDtoVIDMappingNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_CACStatusNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CACStatusNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_IEEE1905SecurityNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "IEEE1905SecurityNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SPRuleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SPRuleNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_AnticipatedChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "AnticipatedChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_AnticipatedChannelUsageNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "AnticipatedChannelUsageNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDeviceRadio_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadio_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadio_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadio_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Transmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Transmit*/
static int get_WiFiDataElementsNetworkDeviceRadio_Transmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Transmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveSelf!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ReceiveSelf*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ReceiveSelf");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveOther!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].RecieveOther*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ReceiveOther");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.TrafficSeparationCombinedFronthaul!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].TrafficSeparationCombinedFronthaul*/
static int get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedFronthaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TrafficSeparationCombinedFronthaul");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.TrafficSeparationCombinedBackhaul!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].TrafficSeparationCombinedBackhaul*/
static int get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedBackhaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TrafficSeparationCombinedBackhaul");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dm_data *)data)->config_section)->config_section, "steer_policy", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"2"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct dm_data *)data)->config_section)->config_section, "steer_policy", value);
			return 0;
	}
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "util_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "util_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "rcpi_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"220"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "rcpi_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "report_rcpi_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"220"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "report_rcpi_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "report_rcpi_hysteresis_margin", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "report_rcpi_hysteresis_margin", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "report_util_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "report_util_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "include_sta_stats", "1");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "include_sta_stats", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "include_sta_metric", "1");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "include_sta_metric", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ChipsetVendor!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ChipsetVendor*/
static int get_WiFiDataElementsNetworkDeviceRadio_ChipsetVendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ChipsetVendor");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadio_APMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "APMetricsWiFi6");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfCurrOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CurrentOperatingClassProfileNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedSTANumberOfEntries*/
static int get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "UnassociatedSTANumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfBSS*/
static int get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BSSNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfScanRes*/
static int get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ScanResultNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_DisAllowedOpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "DisAllowedOpClassChannelsNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BackhaulSta.MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "BackhaulSta", "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "Capabilities", "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *cap = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "Capabilities", "VHTCapabilities");
	*value = (DM_STRLEN(cap)) ? cap : "AAA=";
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.NumberOfOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "Capabilities", "CapableOperatingClassProfileNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE160(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "HE160");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE8080(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "HE8080");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MCSNSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MCSNSS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "SUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "SUBeamformee");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_Beamformee80orLess(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "Beamformee80orLess");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_BeamformeeAbove80(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "BeamformeeAbove80");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "ULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "ULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MaxDLMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MaxULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MaxDLOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MaxULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_RTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "RTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MURTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MURTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MultiBSSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUEDCA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "MUEDCA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTRequestor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "TWTRequestor");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTResponder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "TWTResponder");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SpatialReuse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "SpatialReuse");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_AnticipatedChannelUsage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6APRole", "AnticipatedChannelUsage");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE160(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "HE160");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE8080(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "HE8080");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MCSNSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MCSNSS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "SUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "SUBeamformee");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_Beamformee80orLess(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "Beamformee80orLess");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_BeamformeeAbove80(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "BeamformeeAbove80");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "ULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "ULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MaxDLMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MaxULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MaxDLOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MaxULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_RTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "RTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MURTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MURTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MultiBSSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUEDCA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "MUEDCA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTRequestor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "TWTRequestor");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTResponder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "TWTResponder");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SpatialReuse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "SpatialReuse");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_AnticipatedChannelUsage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "Capabilities", "WiFi6bSTARole", "AnticipatedChannelUsage");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].Class*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.MaxTxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].MaxTxPower*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MaxTxPower");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NonOperable!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NonOperable*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all(((struct dm_data *)data)->json_object, ",", 1, "NonOperable");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NumberOfNonOperChan!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NumberOfNonOperChan*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "NumberOfNonOperChan");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Class*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Channel*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TxPower*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TxPower");
	return 0;
}
/*
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TransmitPowerLimit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TransmitPowerLimit");
	return 0;
}
*/
/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Enabled!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.LastChange!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].LastChange*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "LastChange");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesSent!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "UnicastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesReceived!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "UnicastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesSent!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MulticastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesReceived!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MulticastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesSent!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BroadcastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesReceived!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BroadcastBytesReceived");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_ByteCounterUnits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ByteCounterUnits");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Profile1bSTAsDisallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile1bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Profile1bSTAsDisallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Profile1bSTAsDisallowed");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Profile2bSTAsDisallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile2bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Profile2bSTAsDisallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Profile2bSTAsDisallowed");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_AssociationAllowanceStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "AssociationAllowanceStatus");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBE!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBE*/
/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EstServiceParametersBE");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EstServiceParametersBK");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EstServiceParametersVI");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EstServiceParametersVO");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Profile2bSTAsDisallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile2bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BackhaulUse");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.FronthaulUse!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile2bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "FronthaulUse");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.R1disallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].FronthaulUse*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_R1disallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "R1disallowed");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.R2disallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].R2disallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_R2disallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "R2disallowed");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MultiBSSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MultiBSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MultiBSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TransmittedBSSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TransmittedBSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TransmittedBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TransmittedBSSID");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all(((struct dm_data *)data)->json_object, ",", 1, "FronthaulAKMsAllowed");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, -1, AKMsAllowed, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all(((struct dm_data *)data)->json_object, ",", 1, "BackhaulAKMsAllowed");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, -1, AKMsAllowed, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
*/
/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STANumberOfEntries!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberofSTA*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "STANumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_SteeringHistoryNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_QMDescriptorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "QMDescriptorNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_ClientMAC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ClientMAC");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_DescriptorElement(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "DescriptorElement");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BlacklistAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPSteering", "BlacklistAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPSteering", "BTMAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMQueryResponses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPSteering", "BTMQueryResponses");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "VHTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "HECapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataDownlinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataDownlinkRate*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "LastDataDownlinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataUplinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataUplinkRate*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "LastDataUplinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationReceive!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationReceive*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "UtilizationReceive");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationTransmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationTransmit*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "UtilizationTransmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateDownlink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateDownlink*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EstMACDataRateDownlink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateUplink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateUplink*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EstMACDataRateUplink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].SignalStrength*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SignalStrength");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastConnectTime!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastConnectTime*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "LastConnectTime");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "PacketsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "PacketsReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ErrorsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "RetransCount");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MeasurementReport!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Measurementreport*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all(((struct dm_data *)data)->json_object, ",", 1, "Measurementreport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.NumberOfMeasureReports!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberOfMeasureReports*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "NumberOfMeasureReports");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "IPV4Address");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "IPV6Address");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Hostname*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Hostname");
	return 0;
}
/*
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CellularDataPreference");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, CellularDataPreference, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ReAssociationDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ReAssociationDelay");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadioBSSSTA_ReAssociationDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TIDQueueSizesNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TIDQueueSizesNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_NoCandidateAPFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "NoCandidateAPFailures");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BlacklistAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistSuccesses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BlacklistSuccesses");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BlacklistFailures");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BTMAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMSuccesses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BTMSuccesses");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BTMFailures");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMQueryResponses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "BTMQueryResponses");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_LastSteerTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPSTA", "SteeringSummaryStats", "LastSteerTime");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_Time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "time");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APOrigin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ap");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_TriggerEvent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *trigger = NULL;

	trigger = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "trigger");

	if (DM_STRCMP(trigger, "link_quality") == 0) {
		dmasprintf(value, "%s", "Wi-Fi Link Quality");
	} else if (DM_STRCMP(trigger, "channel_util") == 0) {
		dmasprintf(value, "%s", "Wi-Fi Channel Utilization");
	} else if (DM_STRCMP(trigger, "bk_link_util") == 0) {
		dmasprintf(value, "%s", "Backhaul Link Utilization");
	} else {
		dmasprintf(value, "%s", "Unknown");
	}

	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringApproach(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *method = NULL;

	method = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "method");

	if (DM_STRCMP(method, "btm") == 0) {
		dmasprintf(value, "%s", "BTM Request");
	} else if (DM_STRCMP(method, "assoc_ctl") == 0) {
		dmasprintf(value, "%s", "Blacklist");
	} else if (DM_STRCMP(method, "async_btm") == 0) {
		dmasprintf(value, "%s", "Async BTM Query");
	} else {
		dmasprintf(value, "%s", method);
	}

	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APDestination(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "target_ap");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringDuration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "duration");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].NumberOfOpClassScans*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClassScanNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.OperatingClass!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].OperatingClass*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OperatingClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].NumberOfChannelScans*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ChannelScanNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Channel*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NumberofNeighbors*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "NeighborBSSNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SignalStrengh*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SignalStrength");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelBandwidth!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelBandwidth*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ChannelBandwidth");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelUtilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelUtilization*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ChannelUtilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.StationCount!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].StationCount*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "StationCount");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_OnBootOnly(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "ScanCapability", "OnBootOnly");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_Impact(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "ScanCapability", "Impact");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_MinimumInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "ScanCapability", "MinimumInterval");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_OpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "ScanCapability", "OpClassChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_ChannelList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all(((struct dm_data *)data)->json_object, ",", 1, "ChannelList");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapability_CACMethodNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "CACCapability", "CACMethodNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_Method(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Method");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_NumberOfSeconds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "NumberOfSeconds");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_OpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClassChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_ChannelList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all(((struct dm_data *)data)->json_object, ",", 1, "ChannelList");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].SignalStrength*/
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SignalStrength");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_ManufacturerOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPDevice", "ManufacturerOUI");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_LastContactTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPDevice", "LastContactTime");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_AssocIEEE1905DeviceRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device_id = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ID");
	_bbfdm_get_references(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.", "IEEE1905Id", device_id, value);
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshControllerOperationMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPDevice", "EasyMeshControllerOperationMode");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshAgentOperationMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 2, "MultiAPDevice", "EasyMeshAgentOperationMode");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_LinkType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPDevice", "Backhaul", "LinkType");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPDevice", "Backhaul", "BackhaulMACAddress");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulDeviceID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPDevice", "Backhaul", "BackhaulDeviceID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPDevice", "Backhaul", "MACAddress");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 3, "MultiAPDevice", "Backhaul", "CurrentOperatingClassProfileNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Class");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TxPower");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "BytesSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "BytesReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "PacketsSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "PacketsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "ErrorsSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LinkUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "LinkUtilization");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "SignalStrength");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "LastDataDownlinkRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "LastDataUplinkRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 4, "MultiAPDevice", "Backhaul", "Stats", "TimeStamp");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceDefault8021Q_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceDefault8021Q_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			//TODO
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceDefault8021Q_PrimaryVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mapcontroller", "controller", "primary_vid", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceDefault8021Q_PrimaryVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"4095"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("mapcontroller", "controller", "primary_vid", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceDefault8021Q_DefaultPCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mapcontroller", "controller", "primary_pcp", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceDefault8021Q_DefaultPCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,"7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("mapcontroller", "controller", "primary_pcp", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "SSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_VID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "VID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "TimeStamp");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_CACAvailableChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CACAvailableChannelNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_CACNonOccupancyChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CACNonOccupancyChannelNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_CACActiveChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "CACActiveChannelNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Minutes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Minutes");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Seconds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Seconds");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Countdown(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "Countdown");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceIEEE1905Security_OnboardingProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "OnboardingProtocol");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceIEEE1905Security_IntegrityAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "IntegrityAlgorithm");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceIEEE1905Security_EncryptionAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "EncryptionAlgorithm");
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static operation_args WiFiDataElementsNetwork_SetTrafficSeparation_args = {
	.in = (const char *[]) {
		"Enable",
		"SSIDtoVIDMapping.{i}.SSID",
		"SSIDtoVIDMapping.{i}.VID",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		NULL
	}
};

struct wifi_operate_args
{
	char *arg1;
	char *arg2;
};

static int get_operate_args_WiFiDataElementsNetwork_SetTrafficSeparation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&WiFiDataElementsNetwork_SetTrafficSeparation_args;
	return 0;
}

static int operate_WiFiDataElementsNetwork_SetTrafficSeparation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
#define MAX_ARGS 16

	struct wifi_operate_args operate_args[MAX_ARGS] = {0};
	char *status = "Success";
	bool b = false;

	char *enable = dmjson_get_value((json_object *)value, 1, "Enable");
	if (!enable || *enable == '\0' || bbfdm_validate_boolean(ctx, enable)) {
		status = "Error_Invalid_Input";
		goto end;
	}

	for (int i = 0; i < MAX_ARGS; i++) {

		char ssid[32] = {0};
		char vid[32] = {0};

		snprintf(ssid, sizeof(ssid), "SSIDtoVIDMapping.%d.SSID", i+1);
		snprintf(vid, sizeof(vid), "SSIDtoVIDMapping.%d.VID", i+1);

		operate_args[i].arg1 = dmjson_get_value((json_object *)value, 1, ssid);
		operate_args[i].arg2 = dmjson_get_value((json_object *)value, 1, vid);

		// Instance number must be assigned sequentially without gaps, if one is empty then break the loop
		if (*(operate_args[i].arg1) == '\0')
			break;

		struct uci_section *s = NULL;

		uci_foreach_option_eq("mapcontroller", "ap", "ssid", operate_args[i].arg1, s) {

			// If VID is not empty then update it
			if (*(operate_args[i].arg2) != '\0')
				dmuci_set_value_by_section(s, "vid", operate_args[i].arg2);
		}
	}

	string_to_bool(enable, &b);
	dmuci_set_value("mapcontroller", "controller", "enable_ts", b ? "1" : "0");
	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;

#undef MAX_ARGS
}

static operation_args WiFiDataElementsNetwork_SetPreferredBackhauls_args = {
	.in = (const char *[]) {
		"PreferredBackhauls.{i}.BackhaulMACAddress",
		"PreferredBackhauls.{i}.bSTAMACAddress",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		NULL
	}
};

static int get_operate_args_WiFiDataElementsNetwork_SetPreferredBackhauls(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&WiFiDataElementsNetwork_SetPreferredBackhauls_args;
	return 0;
}

static int operate_WiFiDataElementsNetwork_SetPreferredBackhauls(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct wifi_operate_args operate_args[16] = {0};
	char *status = "Success";

	for (int i = 0;; i++) {

		char device_path[64] = {0};
		char backhaul_mac[64] = {0};
		char bsta_mac[64] = {0};
		char *linker = NULL;

		snprintf(device_path, sizeof(device_path), "Device.WiFi.DataElements.Network.Device.%d.", i+1);
		snprintf(backhaul_mac, sizeof(backhaul_mac), "PreferredBackHauls.%d.BackhaulMACAddress", i+1);
		snprintf(bsta_mac, sizeof(bsta_mac), "PreferredBackHauls.%d.bSTAMACAddress", i+1);

		operate_args[i].arg1 = dmjson_get_value((json_object *)value, 1, backhaul_mac);
		operate_args[i].arg2 = dmjson_get_value((json_object *)value, 1, bsta_mac);

		if (*(operate_args[i].arg1) == '\0' && *(operate_args[i].arg2) == '\0')
			break;

		if (*(operate_args[i].arg1) && bbfdm_validate_string(ctx, operate_args[i].arg1, -1, 17, NULL, MACAddress)) {
			status = "Error_Invalid_Input";
			break;
		}

		if (*(operate_args[i].arg2) && bbfdm_validate_string(ctx, operate_args[i].arg2, -1, 17, NULL, MACAddress)) {
			status = "Error_Invalid_Input";
			break;
		}

		adm_entry_get_reference_value(ctx, device_path, &linker);
		if (linker == NULL || *linker == '\0') {
			status = "Error_Invalid_Input";
			break;
		}

		struct uci_section *s = get_dup_section_in_config_opt("mapcontroller", "node", "agent_id", linker);
		if (*(operate_args[i].arg1) != '\0')
			dmuci_set_value_by_section(s, "backhaul_ul_macaddr", operate_args[i].arg1);

		if (*(operate_args[i].arg2) != '\0')
			dmuci_set_value_by_section(s, "backhaul_dl_macaddr", operate_args[i].arg2);

	}

	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

static operation_args WiFiDataElementsNetwork_SetSSID_args = {
	.in = (const char *[]) {
		"SSID",
		"Enable",
		"AddRemoveChange",
		"PassPhrase",
		"Band",
		"AKMsAllowed",
		"AdvertisementEnabled",
		"MFPConfig",
		"HaulType",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		NULL
	}
};

static int get_operate_args_WiFiDataElementsNetwork_SetSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&WiFiDataElementsNetwork_SetSSID_args;
	return 0;
}

static char *process_set_ssid_add_req(set_ssid_param *op_param)
{
	struct uci_section *s = NULL;
	bool enable = true;
	char **band_arr = NULL;
	size_t band_arr_length = 0;
	char **enc_arr = NULL;
	size_t enc_arr_length = 0;
	char **type_arr = NULL;
	size_t type_arr_length = 0;
	char *curr_ssid = NULL;
	unsigned idx = 1;

	if (op_param == NULL) {
		return "Error_Other";
	}

	if (DM_STRLEN(op_param->enab) != 0) {
		string_to_bool(op_param->enab, &enable);
	}

	if (DM_STRLEN(op_param->band) == 0 || DM_LSTRCMP(op_param->band, "All") == 0) {
		op_param->band = "2.4,5,6";
	}

	band_arr = strsplit(op_param->band, ",", &band_arr_length);

	if (DM_STRLEN(op_param->akm) != 0) {
		enc_arr = strsplit(op_param->akm, ",", &enc_arr_length);
	}

	if (DM_STRLEN(op_param->haul) != 0) {
		type_arr = strsplit(op_param->haul, ",", &type_arr_length);
	}

	if (enc_arr_length > band_arr_length || type_arr_length > band_arr_length) {
		return "Error_Invalid_Input";
	}

	/* Check if ssid is already added */
	uci_foreach_sections("mapcontroller", "ap", s) {
		dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);

		if (DM_STRCMP(curr_ssid, op_param->ssid) == 0) {
			return "Error_Invalid_Input";
		}

		idx++;
	}

	for (int i = 0; i < band_arr_length; i++) {
		char sec_name[32];
		char *encryp = NULL;
		char *haul_type = NULL;
		bool adv_enable = true;

		snprintf(sec_name, sizeof(sec_name), "ap_%c_%u", band_arr[i][0], idx+i);
		encryp = (enc_arr != NULL && i < enc_arr_length) ? get_AKMs_uci_name(enc_arr[i]) : "sae-mixed";
		haul_type = (type_arr != NULL && i < type_arr_length) ? get_haultype_uci_value(type_arr[i]) : "fronthaul";

		if (DM_STRLEN(op_param->adv) != 0) {
			string_to_bool(op_param->adv, &adv_enable);
		} else if (DM_LSTRCMP(haul_type, "backhaul") == 0) {
			adv_enable = false;
		}

		dmuci_add_section("mapcontroller", "ap", &s);
		dmuci_rename_section_by_section(s, sec_name);

		dmuci_set_value_by_section(s, "ssid", op_param->ssid);
		dmuci_set_value_by_section(s, "key", op_param->key);
		dmuci_set_value_by_section(s, "encryption", encryp);
		dmuci_set_value_by_section(s, "type", haul_type);
		dmuci_set_value_by_section(s, "enabled", (enable == true) ? "1" : "0");
		dmuci_set_value_by_section(s, "hidden", (adv_enable == true) ? "0" : "1");

		if (DM_LSTRCMP(band_arr[i], "2.4") == 0) {
			dmuci_set_value_by_section(s, "band", "2");
		} else {
			dmuci_set_value_by_section(s, "band", band_arr[i]);
		}

		if (DM_STRLEN(op_param->mfp) == 0) {
			if (DM_LSTRCMP(encryp, "psk2") == 0) {
				op_param->mfp = "Disabled";
			} else if (DM_LSTRCMP(encryp, "sae-mixed") == 0 || DM_LSTRCMP(encryp, "sae-mixed+dpp") == 0) {
				op_param->mfp = "Optional";
			} else {
				op_param->mfp = "Required";
			}
		}

		dmuci_set_value_by_section(s, "mfp", get_mfp_uci_value(op_param->mfp));
	}

	return "Success";
}

static char *process_set_ssid_remove_req(set_ssid_param *op_param)
{
	struct uci_section *s = NULL;
	char *curr_ssid = NULL;
	bool ap_deleted = false;

	if (op_param == NULL) {
		return "Error_Other";
	}

	uci_foreach_sections("mapcontroller", "ap", s) {
		dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
		if (DM_STRCMP(op_param->ssid, curr_ssid) != 0) {
			continue;
		}

		// delete this section
		dmuci_delete_by_section(s, NULL, NULL);
		ap_deleted = true;
	}

	if (ap_deleted == false) {
		return "Error_Invalid_Input";
	}

	return "Success";
}

static char *process_set_ssid_change_req(set_ssid_param *op_param)
{
	struct uci_section *s = NULL;
	char **band_arr = NULL;
	size_t band_arr_length = 0;
	char **enc_arr = NULL;
	size_t enc_arr_length = 0;
	char **type_arr = NULL;
	size_t type_arr_length = 0;
	char *curr_ssid = NULL;
	unsigned ap_count = 0;

	if (op_param == NULL) {
		return "Error_Other";
	}

	/* Check if ssid is present */
	uci_foreach_sections("mapcontroller", "ap", s) {
		dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);

		if (DM_STRCMP(curr_ssid, op_param->ssid) == 0) {
			ap_count++;
		}
	}

	if (ap_count == 0) {
		return "Error_Invalid_Input";
	}

	if (DM_STRLEN(op_param->band) != 0) {
		if (DM_LSTRCMP(op_param->band, "All") == 0) {
			op_param->band = "2.4,5,6";
		}

		band_arr = strsplit(op_param->band, ",", &band_arr_length);
	}


	if (DM_STRLEN(op_param->akm) != 0) {
		enc_arr = strsplit(op_param->akm, ",", &enc_arr_length);
	}

	if (DM_STRLEN(op_param->haul) != 0) {
		type_arr = strsplit(op_param->haul, ",", &type_arr_length);
	}

	if (band_arr_length > ap_count || enc_arr_length > ap_count || type_arr_length > ap_count) {
		return "Error_Invalid_Input";
	}

	unsigned idx = 0;
	uci_foreach_sections("mapcontroller", "ap", s) {
		dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
		if (DM_STRCMP(op_param->ssid, curr_ssid) != 0) {
			continue;
		}

		// modify this section
		bool enable = true;
		if (DM_STRLEN(op_param->enab) != 0) {
			string_to_bool(op_param->enab, &enable);
			dmuci_set_value_by_section(s, "enabled", (enable == true) ? "1" : "0");
		}

		if (DM_STRLEN(op_param->key) != 0) {
			dmuci_set_value_by_section(s, "key", op_param->key);
		}

		if (enc_arr != NULL && idx < enc_arr_length) {
			dmuci_set_value_by_section(s, "encryption", get_AKMs_uci_name(enc_arr[idx]));
		}

		if (type_arr != NULL && idx < type_arr_length) {
			dmuci_set_value_by_section(s, "type", get_haultype_uci_value(type_arr[idx]));
		}

		if (DM_STRLEN(op_param->adv) != 0) {
			bool adv_enable;
			string_to_bool(op_param->adv, &adv_enable);
			dmuci_set_value_by_section(s, "hidden", (adv_enable == true) ? "0" : "1");
		}

		if (band_arr != NULL && idx < band_arr_length) {
			if (DM_LSTRCMP(band_arr[idx], "2.4") == 0) {
				dmuci_set_value_by_section(s, "band", "2");
			} else {
				dmuci_set_value_by_section(s, "band", band_arr[idx]);
			}
		}

		if (DM_STRLEN(op_param->mfp) != 0) {
			dmuci_set_value_by_section(s, "mfp", get_mfp_uci_value(op_param->mfp));
		}

		idx++;
	}

	return "Success";
}

static int operate_WiFiDataElementsNetwork_SetSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	set_ssid_param op_param;
	char *status = NULL;

	char *add_remove_change = dmjson_get_value((json_object *)value, 1, "AddRemoveChange");
	int op = get_requested_operation(add_remove_change);

	if (op == SET_SSID_INVALID) {
		status = "Error_Invalid_Input";
		goto end;
	}

	memset(&op_param, 0, sizeof(set_ssid_param));

	op_param.ssid = dmjson_get_value((json_object *)value, 1, "SSID");
	op_param.enab = dmjson_get_value((json_object *)value, 1, "Enable");
	op_param.key = dmjson_get_value((json_object *)value, 1, "PassPhrase");
	op_param.band = dmjson_get_value((json_object *)value, 1, "Band");
	op_param.akm = dmjson_get_value((json_object *)value, 1, "AKMsAllowed");
	op_param.adv = dmjson_get_value((json_object *)value, 1, "AdvertisementEnabled");
	op_param.mfp = dmjson_get_value((json_object *)value, 1, "MFPConfig");
	op_param.haul = dmjson_get_value((json_object *)value, 1, "HaulType");

	if (DM_STRLEN(op_param.ssid) == 0 || validate_band_value(ctx, op_param.band) != 0 ||
	    validate_akms_value(ctx, op_param.akm) != 0 || validate_mfp_value(ctx, op_param.mfp) != 0 ||
	    validate_haultype_value(ctx, op_param.haul) != 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	if (DM_STRLEN(op_param.enab) != 0 && bbfdm_validate_boolean(ctx, op_param.enab) != 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	if (DM_STRLEN(op_param.adv) != 0 && bbfdm_validate_boolean(ctx, op_param.adv) != 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	switch (op) {
	case SET_SSID_ADD:
		status = process_set_ssid_add_req(&op_param);
		break;
	case SET_SSID_REMOVE:
		status = process_set_ssid_remove_req(&op_param);
		break;
	case SET_SSID_CHANGE:
		status = process_set_ssid_change_req(&op_param);
		break;
	}

	if (DM_LSTRCMP(status, "Success") != 0) {
		dmuci_revert_package("mapcontroller");
	} else {
		// Commit mapcontroller config changes
		dmuci_save_package("mapcontroller");
		dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);
	}

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

static operation_args WiFiDataElementsNetworkDevice_SetSTASteeringState_args = {
	.in = (const char *[]) {
		"Disallowed",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		NULL
	}
};

static int get_operate_args_WiFiDataElementsNetworkDevice_SetSTASteeringState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&WiFiDataElementsNetworkDevice_SetSTASteeringState_args;
	return 0;
}

static int operate_WiFiDataElementsNetworkDevice_SetSTASteeringState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *status = "Success";
	bool b = false;

	char *disallowed = dmjson_get_value((json_object *)value, 1, "Disallowed");
	if (!disallowed || *disallowed == '\0' || bbfdm_validate_boolean(ctx, disallowed)) {
		status = "Error_Invalid_Input";
		goto end;
	}

	string_to_bool(disallowed, &b);
	dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "steer_disallow", b ? "1" : "0");

	// Commit mapcontroller config changes
	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

/*
static operation_args WiFiDataElementsNetworkDevice_SetDFSState_args = {
	.in = (const char *[]) {
		"DFSEnable",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		NULL
	}
};

static int get_operate_args_WiFiDataElementsNetworkDevice_SetDFSState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&WiFiDataElementsNetworkDevice_SetDFSState_args;
	return 0;
}

static int operate_WiFiDataElementsNetworkDevice_SetDFSState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	//TODO
	return 0;
}*/

static operation_args wifidataelementsnetworkdeviceradio_channelscanrequest_args = {
    .in = (const char *[]) {
        "OpClass",
        "ChannelList",
        NULL
    },
    .out = (const char *[]) {
        "Status",
        NULL
    }
};

static int get_operate_args_WiFiDataElementsNetworkDeviceRadio_ChannelScanRequest(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsnetworkdeviceradio_channelscanrequest_args;
    return 0;
}

static int operate_WiFiDataElementsNetworkDeviceRadio_ChannelScanRequest(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *status = "Success";
	char *agent_id = NULL;
	char *macaddr = NULL;
	char *pch = NULL;
	char *spch = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "agent_id", &agent_id);
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "macaddr", &macaddr);

	if ((bbfdm_validate_string(ctx, agent_id, -1, 17, NULL, MACAddress)) ||
		(bbfdm_validate_string(ctx, macaddr, -1, 17, NULL, MACAddress))) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *channel_list = dmjson_get_value((json_object *)value, 1, "ChannelList");

	if (bbfdm_validate_unsignedInt_list(ctx, channel_list, -1, -1, -1, RANGE_ARGS{{NULL,"255"}}, 1)) {
		status = "Error_Invalid_Input";
		goto end;
	}

	struct json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "agent", json_object_new_string(agent_id));

	struct json_object *radio_array = json_object_new_array();
	json_object_array_add(radio_array, json_object_new_string(macaddr));
	json_object_object_add(in_args, "radio", radio_array);

	struct json_object *channel_array = json_object_new_array();

	for (pch = strtok_r(channel_list, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		struct json_object *val_array = json_object_new_array();
		json_object_array_add(val_array, json_object_new_int(DM_STRTOL(pch)));
		json_object_array_add(channel_array, val_array);
	}

	json_object_object_add(in_args, "channel", channel_array);

	int res = dmubus_call_blob_set("map.controller", "scan", in_args);
	if (res)
		status = "Error_Invalid_Input";

	json_object_put(in_args);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
    return 0;
}

/*static operation_args wifidataelementsnetworkdeviceradio_wifirestart_args = {
    .out = (const char *[]) {
        "Status",
        NULL
    }
};

static int get_operate_args_WiFiDataElementsNetworkDeviceRadio_WiFiRestart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsnetworkdeviceradio_wifirestart_args;
    return 0;
}

static int operate_WiFiDataElementsNetworkDeviceRadio_WiFiRestart(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
    //TODO
    return 0;
}*/

static operation_args wifidataelementsnetworkdevicemultiapdevicebackhaul_steerwifibackhaul_args = {
    .in = (const char *[]) {
        "TargetBSS",
        "Channel", // NOT used by ubus map.controller steer_backhaul
        "TimeOut",
        NULL
    },
    .out = (const char *[]) {
        "Status",
        NULL
    }
};

static int get_operate_args_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsnetworkdevicemultiapdevicebackhaul_steerwifibackhaul_args;
    return 0;
}

static int operate_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res = NULL;
	char *status = "Success";

	char *target_bbs = dmjson_get_value((json_object *)value, 1, "TargetBSS");
	char *time_out = dmjson_get_value((json_object *)value, 1, "TimeOut");
	if (DM_STRLEN(target_bbs) == 0 || DM_STRLEN(time_out) == 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *agent = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "ID");
	if (DM_STRLEN(agent) == 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	dmubus_call("map.controller", "steer_backhaul", UBUS_ARGS{{"agent", agent, String},
															{"target_bssid", target_bbs, String},
															{"timeout", time_out, Integer}}, 3, &res);

	if (res == NULL) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *res_status = dmjson_get_value((json_object *)res, 1, "status");
	if (DM_STRCMP(res_status, "ok") != 0)
		status = "Error_Other";

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

static operation_args wifidataelementsnetworkdeviceradiobssstamultiapsta_btmrequest_args = {
    .in = (const char *[]) {
        "DisassociationImminent", // NOT used by ubus map.controller steer
        "DisassociationTimer",
        "BSSTerminationDuration", // NOT used by ubus map.controller steer
        "ValidityInterval", // NOT used by ubus map.controller steer
        "SteeringTimer", // NOT used by ubus map.controller steer
        "TargetBSS",
        NULL
    },
    .out = (const char *[]) {
        "Status",
        NULL
    }
};

static int get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsnetworkdeviceradiobssstamultiapsta_btmrequest_args;
    return 0;
}

static int operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res = NULL;
	char *status = "Success";
	char buf[1024] = {0};
	char *agent = NULL;

	char *target_bbs = dmjson_get_value((json_object *)value, 1, "TargetBSS");
	char *diass_timer = dmjson_get_value((json_object *)value, 1, "DisassociationTimer");
	if (DM_STRLEN(target_bbs) == 0 || DM_STRLEN(diass_timer) == 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	DM_STRNCPY(buf, refparam, sizeof(buf));
	char *p = DM_STRSTR(buf, "Radio");
	if (p) *p = 0;

	adm_entry_get_reference_value(ctx, buf, &agent);
	if (DM_STRLEN(agent) == 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *sta = dmjson_get_value(((struct dm_data *)data)->json_object, 1, "MACAddress");
	if (DM_STRLEN(sta) == 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	dmubus_call("map.controller", "steer", UBUS_ARGS{{"agent", agent, String},
															{"sta", sta, String},
															{"target_bssid", target_bbs, String},
															{"disassoc_tmo", diass_timer, Integer}}, 4, &res);

	if (res == NULL) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *res_status = dmjson_get_value((json_object *)res, 1, "status");
	if (DM_STRCMP(res_status, "ok") != 0)
		status = "Error_Other";

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

/*************************************************************
 * EVENTS
 *************************************************************/
static event_args wifidataelementsassociationevent_associated_args = {
	.name = "wifi.dataelements.Associated",
    .param = (const char *[]) {
        "type",
        "version",
        "protocols",
        "BSSID",
        "MACAddress",
        "StatusCode",
        "HTCapabilities",
        "VHTCapabilities",
        "HECapabilities",
        "TimeStamp",
        NULL
    }
};

static int get_event_args_WiFiDataElementsAssociationEvent_Associated(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsassociationevent_associated_args;
    return 0;
}

static int event_WiFiDataElementsAssociationEvent_Associated(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case EVENT_CHECK:
			// Nothing to check
			break;
		case EVENT_RUN:
		{
			char *event_time = dmjson_get_value((json_object *)value, 1, "eventTime");
			char *bssid = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent", "AssocData", "BSSID");
			char *mac_addr = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent", "AssocData", "MACAddress");
			char *status_code = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent", "AssocData", "StatusCode");
			char *ht_cap = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent", "AssocData", "HTCapabilities");
			char *vht_cap = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent", "AssocData", "VHTCapabilities");
			char *he_cap = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent", "AssocData", "HECapabilities");

			add_list_parameter(ctx, dmstrdup("TimeStamp"), dmstrdup(event_time), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("BSSID"), dmstrdup(bssid), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MACAddress"), dmstrdup(mac_addr), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("StatusCode"), dmstrdup(status_code), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("HTCapabilities"), dmstrdup(ht_cap), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("VHTCapabilities"), dmstrdup(vht_cap), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("HECapabilities"), dmstrdup(he_cap), DMT_TYPE[DMT_STRING], NULL);
			break;
		}
	}

	return 0;
}

static event_args wifidataelementsdisassociationevent_disassociated_args = {
	.name = "wifi.dataelements.Disassociated",
    .param = (const char *[]) {
        "type",
        "version",
        "protocols",
        "BSSID",
        "MACAddress",
        "ReasonCode",
        "BytesSent",
        "BytesReceived",
        "PacketsSent",
        "PacketsReceived",
        "ErrorsSent",
        "ErrorsReceived",
        "RetransCount",
        "TimeStamp",
        NULL
    }
};

static int get_event_args_WiFiDataElementsDisassociationEvent_Disassociated(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsdisassociationevent_disassociated_args;
    return 0;
}

static int event_WiFiDataElementsDisassociationEvent_Disassociated(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case EVENT_CHECK:
			// Nothing to check
			break;
		case EVENT_RUN:
		{
			char *event_time = dmjson_get_value((json_object *)value, 1, "eventTime");
			char *bssid = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "BSSID");
			char *mac_addr = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "MACAddress");
			char *reason_code = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "ReasonCode");
			char *bytes_sent = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "BytesSent");
			char *bytes_received = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "BytesReceived");
			char *packet_sent = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "PacketsSent");
			char *packet_received = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "PacketsReceived");
			char *errors_sent = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "ErrorsSent");
			char *errors_received = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "ErrorsReceived");
			char *retrans_count = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:DisassociationEvent", "DisassocData", "RetransCount");

			add_list_parameter(ctx, dmstrdup("TimeStamp"), dmstrdup(event_time), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("BSSID"), dmstrdup(bssid), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MACAddress"), dmstrdup(mac_addr), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ReasonCode"), dmstrdup(reason_code), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("BytesSent"), dmstrdup(bytes_sent), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("BytesReceived"), dmstrdup(bytes_received), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("PacketsSent"), dmstrdup(packet_sent), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("PacketsReceived"), dmstrdup(packet_received), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ErrorsSent"), dmstrdup(errors_sent), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ErrorsReceived"), dmstrdup(errors_received), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("RetransCount"), dmstrdup(retrans_count), DMT_TYPE[DMT_STRING], NULL);
			break;
		}
	}

    return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.WiFi.DataElements. *** */
DMOBJ tWiFiDataElementsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Network", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkObj, tWiFiDataElementsNetworkParams, NULL, BBFDM_BOTH},
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH, NULL},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH, NULL},
//{"FailedConnectionEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsFailedConnectionEventParams, NULL, BBFDM_BOTH, NULL},
{0}
};

/* *** Device.WiFi.DataElements.Network. *** */
DMOBJ tWiFiDataElementsNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"SSID", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkSSIDInst, NULL, NULL, NULL, tWiFiDataElementsNetworkSSIDParams, NULL, BBFDM_BOTH, NULL},
{"MultiAPSteeringSummaryStats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkMultiAPSteeringSummaryStatsParams, NULL, BBFDM_BOTH, NULL},
{"Device", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceInst, NULL, NULL, tWiFiDataElementsNetworkDeviceObj, tWiFiDataElementsNetworkDeviceParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_ID, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_TimeStamp, NULL, BBFDM_BOTH},
{"ControllerID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_ControllerID, NULL, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetwork_DeviceNumberOfEntries, NULL, BBFDM_BOTH},
{"MSCSDisallowedStaList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_MSCSDisallowedStaList, NULL, BBFDM_BOTH},
{"SCSDisallowedStaList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_SCSDisallowedStaList, NULL, BBFDM_BOTH},
{"SSIDNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetwork_SSIDNumberOfEntries, NULL, BBFDM_BOTH},
{"SetTrafficSeparation()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetTrafficSeparation, operate_WiFiDataElementsNetwork_SetTrafficSeparation, BBFDM_USP},
//{"SetServicePrioritization()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetServicePrioritization, operate_WiFiDataElementsNetwork_SetServicePrioritization, BBFDM_USP},
{"SetPreferredBackhauls()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetPreferredBackhauls, operate_WiFiDataElementsNetwork_SetPreferredBackhauls, BBFDM_USP},
{"SetSSID()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetSSID, operate_WiFiDataElementsNetwork_SetSSID, BBFDM_USP},
//{"SetMSCSDisallowed()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetMSCSDisallowed, operate_WiFiDataElementsNetwork_SetMSCSDisallowed, BBFDM_USP},
//{"SetSCSDisallowed()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetSCSDisallowed, operate_WiFiDataElementsNetwork_SetSCSDisallowed, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.Network.SSID.{i}. *** */
DMLEAF tWiFiDataElementsNetworkSSIDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_SSID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Band", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_Band, NULL, BBFDM_BOTH},
{"Enable", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkSSID_Enable, NULL, BBFDM_BOTH},
{"AKMsAllowed", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_AKMs, NULL, BBFDM_BOTH},
{"AdvertisementEnabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkSSID_AdvEnabled, NULL, BBFDM_BOTH},
{"MFPConfig", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_MFP, NULL, BBFDM_BOTH},
{"HaulType", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_Haul, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats. *** */
DMLEAF tWiFiDataElementsNetworkMultiAPSteeringSummaryStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"NoCandidateAPFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_NoCandidateAPFailures, NULL, BBFDM_BOTH},
{"BlacklistAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistAttempts, NULL, BBFDM_BOTH},
{"BlacklistSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistSuccesses, NULL, BBFDM_BOTH},
{"BlacklistFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistFailures, NULL, BBFDM_BOTH},
{"BTMAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMAttempts, NULL, BBFDM_BOTH},
{"BTMSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMSuccesses, NULL, BBFDM_BOTH},
{"BTMFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMFailures, NULL, BBFDM_BOTH},
{"BTMQueryResponses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMQueryResponses, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Default8021Q", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceDefault8021QInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceDefault8021QParams, NULL, BBFDM_BOTH, NULL},
{"SSIDtoVIDMapping", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceSSIDtoVIDMappingInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceSSIDtoVIDMappingParams, NULL, BBFDM_BOTH, NULL},
{"CACStatus", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusInst, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusObj, tWiFiDataElementsNetworkDeviceCACStatusParams, NULL, BBFDM_BOTH, NULL},
//{"SPRule", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceSPRuleInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceSPRuleParams, NULL, BBFDM_BOTH, NULL},
{"IEEE1905Security", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceIEEE1905SecurityInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceIEEE1905SecurityParams, NULL, BBFDM_BOTH, NULL},
//{"AnticipatedChannels", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceAnticipatedChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceAnticipatedChannelsParams, NULL, BBFDM_BOTH, NULL},
//{"AnticipatedChannelUsage", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceAnticipatedChannelUsageInst, NULL, NULL, tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageObj, tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageParams, NULL, BBFDM_BOTH, NULL},
{"MultiAPDevice", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceObj, tWiFiDataElementsNetworkDeviceMultiAPDeviceParams, NULL, BBFDM_BOTH, NULL},
{"Radio", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioObj, tWiFiDataElementsNetworkDeviceRadioParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"MultiAPCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDevice_MultiAPCapabilities, NULL, BBFDM_BOTH},
{"CollectionInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_CollectionInterval, NULL, BBFDM_BOTH},
{"ReportUnsuccessfulAssociations", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations, set_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations, BBFDM_BOTH},
{"MaxReportingRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxReportingRate, NULL, BBFDM_BOTH},
{"APMetricsReportingInterval", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDevice_APMetricsReportingInterval, set_WiFiDataElementsNetworkDevice_APMetricsReportingInterval, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_Manufacturer, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_SerialNumber, NULL, BBFDM_BOTH},
// {"ManufacturerModel", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ManufacturerModel, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_SoftwareVersion, NULL, BBFDM_BOTH},
{"ExecutionEnv", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ExecutionEnv, NULL, BBFDM_BOTH},
// {"DSCPMap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDevice_DSCPMap, NULL, BBFDM_BOTH},
{"MaxPrioritizationRules", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxPrioritizationRules, NULL, BBFDM_BOTH},
{"PrioritizationSupport", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_PrioritizationSupport, NULL, BBFDM_BOTH},
{"MaxVIDs", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxVIDs, NULL, BBFDM_BOTH},
// {"APMetricsWiFi6", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_APMetricsWiFi6, NULL, BBFDM_BOTH},
{"CountryCode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_CountryCode, NULL, BBFDM_BOTH},
{"LocalSteeringDisallowedSTAList", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList, set_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList, BBFDM_BOTH},
{"BTMSteeringDisallowedSTAList", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList, set_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList, BBFDM_BOTH},
{"DFSEnable", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_DFSEnable, NULL, BBFDM_BOTH},
{"ReportIndependentScans", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_ReportIndependentScans, set_WiFiDataElementsNetworkDevice_ReportIndependentScans, BBFDM_BOTH},
// {"AssociatedSTAinAPMetricsWiFi6", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6, set_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6, BBFDM_BOTH},
// {"MaxUnsuccessfulAssociationReportingRate", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate, set_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate, BBFDM_BOTH},
{"STASteeringState", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_STASteeringState, NULL, BBFDM_BOTH},
// {"CoordinatedCACAllowed", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed, set_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed, BBFDM_BOTH},
{"TrafficSeparationAllowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_TrafficSeparationAllowed, NULL, BBFDM_BOTH},
// {"ServicePrioritizationAllowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_ServicePrioritizationAllowed, NULL, BBFDM_BOTH},
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries, NULL, BBFDM_BOTH},
{"Default8021QNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_Default8021QNumberOfEntries, NULL, BBFDM_BOTH},
{"SSIDtoVIDMappingNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_SSIDtoVIDMappingNumberOfEntries, NULL, BBFDM_BOTH},
{"CACStatusNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_CACStatusNumberOfEntries, NULL, BBFDM_BOTH},
{"IEEE1905SecurityNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_IEEE1905SecurityNumberOfEntries, NULL, BBFDM_BOTH},
{"SPRuleNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_SPRuleNumberOfEntries, NULL, BBFDM_BOTH},
{"AnticipatedChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_AnticipatedChannelsNumberOfEntries, NULL, BBFDM_BOTH},
{"AnticipatedChannelUsageNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_AnticipatedChannelUsageNumberOfEntries, NULL, BBFDM_BOTH},
{"SetSTASteeringState()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetSTASteeringState, operate_WiFiDataElementsNetworkDevice_SetSTASteeringState, BBFDM_USP},
//{"SetDFSState()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetDFSState, operate_WiFiDataElementsNetworkDevice_SetDFSState, BBFDM_USP},
//{"SetAnticipatedChannelPreference()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetAnticipatedChannelPreference, operate_WiFiDataElementsNetworkDevice_SetAnticipatedChannelPreference, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Default8021Q.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceDefault8021QParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceDefault8021Q_Enable, set_WiFiDataElementsNetworkDeviceDefault8021Q_Enable, BBFDM_BOTH},
{"PrimaryVID", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceDefault8021Q_PrimaryVID, set_WiFiDataElementsNetworkDeviceDefault8021Q_PrimaryVID, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"DefaultPCP", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceDefault8021Q_DefaultPCP, set_WiFiDataElementsNetworkDeviceDefault8021Q_DefaultPCP, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.SSIDtoVIDMapping.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceSSIDtoVIDMappingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_SSID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"VID", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_VID, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceCACStatusObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"CACAvailableChannel", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelParams, NULL, BBFDM_BOTH, NULL},
{"CACNonOccupancyChannel", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelParams, NULL, BBFDM_BOTH, NULL},
{"CACActiveChannel", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceCACStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"TimeStamp", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceCACStatus_TimeStamp, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"CACAvailableChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatus_CACAvailableChannelNumberOfEntries, NULL, BBFDM_BOTH},
{"CACNonOccupancyChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatus_CACNonOccupancyChannelNumberOfEntries, NULL, BBFDM_BOTH},
{"CACActiveChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatus_CACActiveChannelNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}.CACAvailableChannel.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_OpClass, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Channel, NULL, BBFDM_BOTH},
{"Minutes", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Minutes, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}.CACNonOccupancyChannel.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_OpClass, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Channel, NULL, BBFDM_BOTH},
{"Seconds", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Seconds, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}.CACActiveChannel.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_OpClass, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Channel, NULL, BBFDM_BOTH},
{"Countdown", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Countdown, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.SPRule.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceSPRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"ID", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSPRule_ID, NULL, BBFDM_BOTH},
//{"Precedence", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSPRule_Precedence, NULL, BBFDM_BOTH},
//{"Output", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSPRule_Output, NULL, BBFDM_BOTH},
//{"AlwaysMatch", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceSPRule_AlwaysMatch, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.IEEE1905Security.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceIEEE1905SecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OnboardingProtocol", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceIEEE1905Security_OnboardingProtocol, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"IntegrityAlgorithm", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceIEEE1905Security_IntegrityAlgorithm, NULL, BBFDM_BOTH},
{"EncryptionAlgorithm", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceIEEE1905Security_EncryptionAlgorithm, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.AnticipatedChannels.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannels_OpClass, NULL, BBFDM_BOTH},
//{"ChannelList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannels_ChannelList, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.AnticipatedChannelUsage.{i}. *** */
//DMOBJ tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"Entry", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryParams, NULL, BBFDM_BOTH, NULL},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_OpClass, NULL, BBFDM_BOTH},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_Channel, NULL, BBFDM_BOTH},
//{"ReferenceBSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_ReferenceBSSID, NULL, BBFDM_BOTH},
//{"EntryNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_EntryNumberOfEntries, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.AnticipatedChannelUsage.{i}.Entry.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"BurstStartTime", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_BurstStartTime, NULL, BBFDM_BOTH},
//{"BurstLength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_BurstLength, NULL, BBFDM_BOTH},
//{"Repetitions", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_Repetitions, NULL, BBFDM_BOTH},
//{"BurstInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_BurstInterval, NULL, BBFDM_BOTH},
//{"RUBitmask", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_RUBitmask, NULL, BBFDM_BOTH},
//{"TransmitterIdentifier", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_TransmitterIdentifier, NULL, BBFDM_BOTH},
//{"PowerLevel", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_PowerLevel, NULL, BBFDM_BOTH},
//{"ChannelUsageReason", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_ChannelUsageReason, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice. *** */
DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Backhaul", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulObj, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_ManufacturerOUI, NULL, BBFDM_BOTH},
{"LastContactTime", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDevice_LastContactTime, NULL, BBFDM_BOTH},
{"AssocIEEE1905DeviceRef", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_AssocIEEE1905DeviceRef, NULL, BBFDM_BOTH},
{"EasyMeshControllerOperationMode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshControllerOperationMode, NULL, BBFDM_BOTH},
{"EasyMeshAgentOperationMode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshAgentOperationMode, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice.Backhaul. *** */
DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, NULL},
//{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"LinkType", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_LinkType, NULL, BBFDM_BOTH},
{"BackhaulMACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulMACAddress, NULL, BBFDM_BOTH},
{"BackhaulDeviceID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulDeviceID, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_MACAddress, NULL, BBFDM_BOTH},
//{"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_CurrentOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
{"SteerWiFiBackhaul()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul, operate_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice.Backhaul.CurrentOperatingClassProfile.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Class, NULL, BBFDM_BOTH},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Channel, NULL, BBFDM_BOTH},
//{"TxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TxPower, NULL, BBFDM_BOTH},
//{"TimeStamp", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TimeStamp, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice.Backhaul.Stats. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesSent, NULL, BBFDM_BOTH},
//{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesReceived, NULL, BBFDM_BOTH},
//{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsSent, NULL, BBFDM_BOTH},
//{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsReceived, NULL, BBFDM_BOTH},
//{"ErrorsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsSent, NULL, BBFDM_BOTH},
//{"ErrorsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"LinkUtilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LinkUtilization, NULL, BBFDM_BOTH},
//{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_SignalStrength, NULL, BBFDM_BOTH},
//{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataDownlinkRate, NULL, BBFDM_BOTH},
//{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataUplinkRate, NULL, BBFDM_BOTH},
//{"TimeStamp", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_TimeStamp, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"ScanResult", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultObj, tWiFiDataElementsNetworkDeviceRadioScanResultParams, NULL, BBFDM_BOTH, NULL},
{"BackhaulSta", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams, NULL, BBFDM_BOTH, NULL},
{"ScanCapability", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanCapabilityObj, tWiFiDataElementsNetworkDeviceRadioScanCapabilityParams, NULL, BBFDM_BOTH, NULL},
{"CACCapability", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCACCapabilityObj, tWiFiDataElementsNetworkDeviceRadioCACCapabilityParams, NULL, BBFDM_BOTH, NULL},
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj, tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams, NULL, BBFDM_BOTH, NULL},
{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, NULL},
//{"DisAllowedOpClassChannels", &DMWRITE, addObjWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels, delObjWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels, NULL, browseWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsParams, NULL, BBFDM_BOTH, NULL},
//{"SpatialReuse", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioSpatialReuseParams, NULL, BBFDM_BOTH, NULL},
{"BSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSObj, tWiFiDataElementsNetworkDeviceRadioBSSParams, NULL, BBFDM_BOTH, NULL},
{"UnassociatedSTA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams, NULL, BBFDM_BOTH, NULL},
//{"MultiAPRadio", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioMultiAPRadioParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ID", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadio_ID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_Enabled, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Noise, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Utilization, NULL, BBFDM_BOTH},
{"Transmit", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Transmit, NULL, BBFDM_BOTH},
{"ReceiveSelf", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf, NULL, BBFDM_BOTH},
{"ReceiveOther", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther, NULL, BBFDM_BOTH},
{"TrafficSeparationCombinedFronthaul", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedFronthaul, NULL, BBFDM_BOTH},
{"TrafficSeparationCombinedBackhaul", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedBackhaul, NULL, BBFDM_BOTH},
// {"SteeringPolicy", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy, set_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy, BBFDM_BOTH},
{"ChannelUtilizationThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold, set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold, BBFDM_BOTH},
{"RCPISteeringThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold, set_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold, BBFDM_BOTH},
{"STAReportingRCPIThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold, set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold, BBFDM_BOTH},
{"STAReportingRCPIHysteresisMarginOverride", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride, set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride, BBFDM_BOTH},
{"ChannelUtilizationReportingThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold, set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold, BBFDM_BOTH},
{"AssociatedSTATrafficStatsInclusionPolicy", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy, set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy, BBFDM_BOTH},
{"AssociatedSTALinkMetricsInclusionPolicy", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy, set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy, BBFDM_BOTH},
{"ChipsetVendor", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadio_ChipsetVendor, NULL, BBFDM_BOTH},
// {"APMetricsWiFi6", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_APMetricsWiFi6, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
{"UnassociatedSTANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries, NULL, BBFDM_BOTH},
{"BSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries, NULL, BBFDM_BOTH},
{"ScanResultNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries, NULL, BBFDM_BOTH},
{"DisAllowedOpClassChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_DisAllowedOpClassChannelsNumberOfEntries, NULL, BBFDM_BOTH},
{"ChannelScanRequest()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_ChannelScanRequest, operate_WiFiDataElementsNetworkDeviceRadio_ChannelScanRequest, BBFDM_USP},
//{"RadioEnable()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_RadioEnable, operate_WiFiDataElementsNetworkDeviceRadio_RadioEnable, BBFDM_USP},
//{"SetTxPowerLimit()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_SetTxPowerLimit, operate_WiFiDataElementsNetworkDeviceRadio_SetTxPowerLimit, BBFDM_USP},
//{"SetSpatialReuse()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_SetSpatialReuse, operate_WiFiDataElementsNetworkDeviceRadio_SetSpatialReuse, BBFDM_USP},
//{"WiFiRestart()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_WiFiRestart, operate_WiFiDataElementsNetworkDeviceRadio_WiFiRestart, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"OpClassScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp, NULL, BBFDM_BOTH},
{"OpClassScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"ChannelScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OperatingClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ChannelScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"NeighborBSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise, NULL, BBFDM_BOTH},
{"NeighborBSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength, NULL, BBFDM_BOTH},
{"ChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth, NULL, BBFDM_BOTH},
{"ChannelUtilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization, NULL, BBFDM_BOTH},
{"StationCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanCapability. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanCapabilityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"OpClassChannels", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OnBootOnly", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioScanCapability_OnBootOnly, NULL, BBFDM_BOTH},
{"Impact", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapability_Impact, NULL, BBFDM_BOTH},
{"MinimumInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapability_MinimumInterval, NULL, BBFDM_BOTH},
{"OpClassChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapability_OpClassChannelsNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanCapability.OpClassChannels.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_OpClass, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ChannelList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_ChannelList, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CACCapability. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"CACMethod", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodObj, tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"CACMethodNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapability_CACMethodNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CACCapability.CACMethod.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"OpClassChannels", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Method", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_Method, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"NumberOfSeconds", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_NumberOfSeconds, NULL, BBFDM_BOTH},
{"OpClassChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_OpClassChannelsNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CACCapability.CACMethod.{i}.OpClassChannels.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_OpClass, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ChannelList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_ChannelList, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"WiFi6APRole", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRoleParams, NULL, BBFDM_BOTH, NULL},
{"WiFi6bSTARole", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARoleParams, NULL, BBFDM_BOTH, NULL},
//{"AKMFrontHaul", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulParams, NULL, BBFDM_BOTH, NULL},
//{"AKMBackhaul", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulParams, NULL, BBFDM_BOTH, NULL},
{"CapableOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities, NULL, BBFDM_BOTH},
{"CapableOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
//{"AKMFrontHaulNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_AKMFrontHaulNumberOfEntries, NULL, BBFDM_BOTH},
//{"AKMBackhaulNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_AKMBackhaulNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.WiFi6APRole. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRoleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE160, NULL, BBFDM_BOTH},
{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE8080, NULL, BBFDM_BOTH},
{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MCSNSS, NULL, BBFDM_BOTH},
{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformer, NULL, BBFDM_BOTH},
{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformee, NULL, BBFDM_BOTH},
{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUBeamformer, NULL, BBFDM_BOTH},
{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_Beamformee80orLess, NULL, BBFDM_BOTH},
{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_BeamformeeAbove80, NULL, BBFDM_BOTH},
{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULMUMIMO, NULL, BBFDM_BOTH},
{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULOFDMA, NULL, BBFDM_BOTH},
{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLMUMIMO, NULL, BBFDM_BOTH},
{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULMUMIMO, NULL, BBFDM_BOTH},
{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLOFDMA, NULL, BBFDM_BOTH},
{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULOFDMA, NULL, BBFDM_BOTH},
{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_RTS, NULL, BBFDM_BOTH},
{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MURTS, NULL, BBFDM_BOTH},
{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MultiBSSID, NULL, BBFDM_BOTH},
{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUEDCA, NULL, BBFDM_BOTH},
{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTRequestor, NULL, BBFDM_BOTH},
{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTResponder, NULL, BBFDM_BOTH},
{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SpatialReuse, NULL, BBFDM_BOTH},
{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_AnticipatedChannelUsage, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.WiFi6bSTARole. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARoleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE160, NULL, BBFDM_BOTH},
{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE8080, NULL, BBFDM_BOTH},
{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MCSNSS, NULL, BBFDM_BOTH},
{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformer, NULL, BBFDM_BOTH},
{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformee, NULL, BBFDM_BOTH},
{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUBeamformer, NULL, BBFDM_BOTH},
{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_Beamformee80orLess, NULL, BBFDM_BOTH},
{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_BeamformeeAbove80, NULL, BBFDM_BOTH},
{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULMUMIMO, NULL, BBFDM_BOTH},
{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULOFDMA, NULL, BBFDM_BOTH},
{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLMUMIMO, NULL, BBFDM_BOTH},
{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULMUMIMO, NULL, BBFDM_BOTH},
{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLOFDMA, NULL, BBFDM_BOTH},
{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULOFDMA, NULL, BBFDM_BOTH},
{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_RTS, NULL, BBFDM_BOTH},
{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MURTS, NULL, BBFDM_BOTH},
{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MultiBSSID, NULL, BBFDM_BOTH},
{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUEDCA, NULL, BBFDM_BOTH},
{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTRequestor, NULL, BBFDM_BOTH},
{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTResponder, NULL, BBFDM_BOTH},
{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SpatialReuse, NULL, BBFDM_BOTH},
{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_AnticipatedChannelUsage, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.AKMFrontHaul.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OUI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaul_OUI, NULL, BBFDM_BOTH},
//{"Type", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaul_Type, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.AKMBackhaul.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OUI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaul_OUI, NULL, BBFDM_BOTH},
//{"Type", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaul_Type, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"MaxTxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower, NULL, BBFDM_BOTH},
{"NonOperable", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable, NULL, BBFDM_BOTH},
{"NumberOfNonOperChan", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel, NULL, BBFDM_BOTH},
{"TxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower, NULL, BBFDM_BOTH},
// {"TransmitPowerLimit", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TransmitPowerLimit, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.DisAllowedOpClassChannels.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_Enable, set_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_Enable, BBFDM_BOTH},
//{"OpClass", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_OpClass, set_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_OpClass, BBFDM_BOTH},
//{"ChannelList", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_ChannelList, set_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_ChannelList, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.SpatialReuse. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioSpatialReuseParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"PartialBSSColor", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_PartialBSSColor, NULL, BBFDM_BOTH},
//{"BSSColor", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_BSSColor, NULL, BBFDM_BOTH},
//{"HESIGASpatialReuseValue15Allowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_HESIGASpatialReuseValue15Allowed, NULL, BBFDM_BOTH},
//{"SRGInformationValid", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGInformationValid, NULL, BBFDM_BOTH},
//{"NonSRGOffsetValid", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_NonSRGOffsetValid, NULL, BBFDM_BOTH},
//{"PSRDisallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_PSRDisallowed, NULL, BBFDM_BOTH},
//{"NonSRGOBSSPDMaxOffset", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_NonSRGOBSSPDMaxOffset, NULL, BBFDM_BOTH},
//{"SRGOBSSPDMinOffset", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGOBSSPDMinOffset, NULL, BBFDM_BOTH},
//{"SRGOBSSPDMaxOffset", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGOBSSPDMaxOffset, NULL, BBFDM_BOTH},
//{"SRGBSSColorBitmap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGBSSColorBitmap, NULL, BBFDM_BOTH},
//{"SRGPartialBSSIDBitmap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGPartialBSSIDBitmap, NULL, BBFDM_BOTH},
//{"NeighborBSSColorInUseBitmap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_NeighborBSSColorInUseBitmap, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
// {"QMDescriptor", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorParams, NULL, BBFDM_BOTH, NULL},
{"MultiAPSteering", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSMultiAPSteeringParams, NULL, BBFDM_BOTH, NULL},
{"STA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAObj, tWiFiDataElementsNetworkDeviceRadioBSSSTAParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_SSID, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp, NULL, BBFDM_BOTH},
{"UnicastBytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent, NULL, BBFDM_BOTH},
{"UnicastBytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived, NULL, BBFDM_BOTH},
{"MulticastBytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent, NULL, BBFDM_BOTH},
{"MulticastBytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived, NULL, BBFDM_BOTH},
{"BroadcastBytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent, NULL, BBFDM_BOTH},
{"BroadcastBytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived, NULL, BBFDM_BOTH},
// {"ByteCounterUnits", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_ByteCounterUnits, NULL, BBFDM_BOTH},
{"Profile1bSTAsDisallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Profile1bSTAsDisallowed, NULL, BBFDM_BOTH},
{"Profile2bSTAsDisallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Profile2bSTAsDisallowed, NULL, BBFDM_BOTH},
// {"AssociationAllowanceStatus", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_AssociationAllowanceStatus, NULL, BBFDM_BOTH},
// {"EstServiceParametersBE", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE, NULL, BBFDM_BOTH},
// {"EstServiceParametersBK", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK, NULL, BBFDM_BOTH},
// {"EstServiceParametersVI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI, NULL, BBFDM_BOTH},
// {"EstServiceParametersVO", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO, NULL, BBFDM_BOTH},
{"BackhaulUse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulUse, NULL, BBFDM_BOTH},
{"FronthaulUse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulUse, NULL, BBFDM_BOTH},
{"R1disallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_R1disallowed, NULL, BBFDM_BOTH},
{"R2disallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_R2disallowed, NULL, BBFDM_BOTH},
{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_MultiBSSID, NULL, BBFDM_BOTH},
{"TransmittedBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_TransmittedBSSID, NULL, BBFDM_BOTH},
// {"FronthaulAKMsAllowed", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed, set_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed, BBFDM_BOTH},
// {"BackhaulAKMsAllowed", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulAKMsAllowed, set_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulAKMsAllowed, BBFDM_BOTH},
{"STANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries, NULL, BBFDM_BOTH},
// {"QMDescriptorNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_QMDescriptorNumberOfEntries, NULL, BBFDM_BOTH},
//{"SetQMDescriptors()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSS_SetQMDescriptors, operate_WiFiDataElementsNetworkDeviceRadioBSS_SetQMDescriptors, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.QMDescriptor.{i}. *** */
// DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
// {"ClientMAC", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_ClientMAC, NULL, BBFDM_BOTH},
// {"DescriptorElement", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_DescriptorElement, NULL, BBFDM_BOTH},
// {0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MultiAPSteering. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSMultiAPSteeringParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BlacklistAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BlacklistAttempts, NULL, BBFDM_BOTH},
{"BTMAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMAttempts, NULL, BBFDM_BOTH},
{"BTMQueryResponses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMQueryResponses, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSSTAObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"MultiAPSTA", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAObj, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAParams, NULL, BBFDM_BOTH, NULL},
//{"WiFi6Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6CapabilitiesParams, NULL, BBFDM_BOTH, NULL},
//{"TIDQueueSizes", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities, NULL, BBFDM_BOTH},
//{"ClientCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ClientCapabilities, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate, NULL, BBFDM_BOTH},
{"UtilizationReceive", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive, NULL, BBFDM_BOTH},
{"UtilizationTransmit", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit, NULL, BBFDM_BOTH},
{"EstMACDataRateDownlink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink, NULL, BBFDM_BOTH},
{"EstMACDataRateUplink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength, NULL, BBFDM_BOTH},
{"LastConnectTime", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount, NULL, BBFDM_BOTH},
{"MeasurementReport", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport, NULL, BBFDM_BOTH},
{"NumberOfMeasureReports", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports, NULL, BBFDM_BOTH},
{"IPV4Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address, NULL, BBFDM_BOTH},
{"IPV6Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address, NULL, BBFDM_BOTH},
{"Hostname", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname, NULL, BBFDM_BOTH},
// {"CellularDataPreference", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference, set_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference, BBFDM_BOTH},
// {"ReAssociationDelay", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ReAssociationDelay, set_WiFiDataElementsNetworkDeviceRadioBSSSTA_ReAssociationDelay, BBFDM_BOTH},
{"TIDQueueSizesNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TIDQueueSizesNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MultiAPSTA. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"SteeringSummaryStats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStatsParams, NULL, BBFDM_BOTH, NULL},
{"SteeringHistory", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"AssociationTime", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_AssociationTime, NULL, BBFDM_BOTH},
//{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Noise, NULL, BBFDM_BOTH},
{"SteeringHistoryNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_SteeringHistoryNumberOfEntries, NULL, BBFDM_BOTH},
//{"Disassociate()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Disassociate, operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Disassociate, BBFDM_USP},
{"BTMRequest()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest, operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MultiAPSTA.SteeringSummaryStats. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"NoCandidateAPFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_NoCandidateAPFailures, NULL, BBFDM_BOTH},
{"BlacklistAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistAttempts, NULL, BBFDM_BOTH},
{"BlacklistSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistSuccesses, NULL, BBFDM_BOTH},
{"BlacklistFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistFailures, NULL, BBFDM_BOTH},
{"BTMAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMAttempts, NULL, BBFDM_BOTH},
{"BTMSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMSuccesses, NULL, BBFDM_BOTH},
{"BTMFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMFailures, NULL, BBFDM_BOTH},
{"BTMQueryResponses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMQueryResponses, NULL, BBFDM_BOTH},
{"LastSteerTime", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_LastSteerTime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MultiAPSTA.SteeringHistory.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Time", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_Time, NULL, BBFDM_BOTH},
{"APOrigin", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APOrigin, NULL, BBFDM_BOTH},
{"TriggerEvent", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_TriggerEvent, NULL, BBFDM_BOTH},
{"SteeringApproach", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringApproach, NULL, BBFDM_BOTH},
{"APDestination", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APDestination, NULL, BBFDM_BOTH},
{"SteeringDuration", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringDuration, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.WiFi6Capabilities. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6CapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_HE160, NULL, BBFDM_BOTH},
//{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_HE8080, NULL, BBFDM_BOTH},
//{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MCSNSS, NULL, BBFDM_BOTH},
//{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_SUBeamformer, NULL, BBFDM_BOTH},
//{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_SUBeamformee, NULL, BBFDM_BOTH},
//{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MUBeamformer, NULL, BBFDM_BOTH},
//{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_Beamformee80orLess, NULL, BBFDM_BOTH},
//{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_BeamformeeAbove80, NULL, BBFDM_BOTH},
//{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_ULMUMIMO, NULL, BBFDM_BOTH},
//{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_ULOFDMA, NULL, BBFDM_BOTH},
//{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxDLMUMIMO, NULL, BBFDM_BOTH},
//{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxULMUMIMO, NULL, BBFDM_BOTH},
//{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxDLOFDMA, NULL, BBFDM_BOTH},
//{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxULOFDMA, NULL, BBFDM_BOTH},
//{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_RTS, NULL, BBFDM_BOTH},
//{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MURTS, NULL, BBFDM_BOTH},
//{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MultiBSSID, NULL, BBFDM_BOTH},
//{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MUEDCA, NULL, BBFDM_BOTH},
//{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_TWTRequestor, NULL, BBFDM_BOTH},
//{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_TWTResponder, NULL, BBFDM_BOTH},
//{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_SpatialReuse, NULL, BBFDM_BOTH},
//{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_AnticipatedChannelUsage, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TIDQueueSizes.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"TID", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizes_TID, NULL, BBFDM_BOTH},
//{"Size", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizes_Size, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.MultiAPRadio. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioMultiAPRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"RadarDetections", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_RadarDetections, NULL, BBFDM_BOTH},
//{"FullScan()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_FullScan, operate_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_FullScan, BBFDM_USP},
//{"ChannelScan()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_ChannelScan, operate_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_ChannelScan, BBFDM_USP},
//{0}
//};

/* *** Device.WiFi.DataElements.AssociationEvent. *** */
DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Associated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsAssociationEvent_Associated, event_WiFiDataElementsAssociationEvent_Associated, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent. *** */
DMLEAF tWiFiDataElementsDisassociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Disassociated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsDisassociationEvent_Disassociated, event_WiFiDataElementsDisassociationEvent_Disassociated, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.FailedConnectionEvent. *** */
//DMLEAF tWiFiDataElementsFailedConnectionEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"FailedConnection!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsFailedConnectionEvent_FailedConnection, NULL, BBFDM_USP},
//{0}
//};
