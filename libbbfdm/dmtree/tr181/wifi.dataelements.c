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

static int get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value) __attribute__ ((unused));
static int get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value) __attribute__ ((unused));

struct wifi_data_element_args
{
	struct json_object *dump_obj;
	struct json_object *dump_fallback;
	struct uci_section *uci_s;
};

struct wifi_event_args
{
	struct json_object *event_obj;
	char *event_time;
};

struct wifi_ap_fronthaul_args
{
	struct uci_section *uci_s;
	char *band_list;
};

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static bool is_ssid_exists(const char *sec_name, const char *ssid, char **band_list)
{
	struct uci_section *s = NULL;
	char *curr_ssid = NULL;
	char buf[256] = {0};
	unsigned pos = 0;

	*band_list = NULL;

	if (DM_STRLEN(sec_name) == 0 || DM_STRLEN(ssid) == 0)
		return false;

	uci_foreach_option_eq("mapcontroller", "ap", "type", "fronthaul", s) {
		struct uci_section *dmmap_s = NULL;
		char *ap_inst = NULL;

		// skip the disabled fronthaul interfaces
		char *enabled = NULL;
		dmuci_get_value_by_section_string(s, "enabled", &enabled);
		if (DM_STRLEN(enabled)) {
			bool b = false;

			string_to_bool(enabled, &b);
			if (b == false)
				continue;
		}

		dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
		if (DM_STRLEN(curr_ssid) == 0 ||
			DM_STRCMP(curr_ssid, ssid) != 0)
			continue;

		if ((dmmap_s = get_dup_section_in_dmmap("dmmap_mapcontroller", "ap", section_name(s))) != NULL) {
			dmuci_get_value_by_section_string(dmmap_s, "wifi_da_ssid_instance", &ap_inst);

			if (strcmp(sec_name, section_name(s)) != 0 && DM_STRLEN(ap_inst) != 0)
				return true;
		}

		// Update band list
		char *band = NULL;
		dmuci_get_value_by_section_string(s, "band", &band);
		pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", (!DM_LSTRCMP(band, "2")) ? "2.4" : (!DM_LSTRCMP(band, "5")) ? "5" : "6");
	}

	if (pos)
		buf[pos - 1] = 0;

	*band_list = dmstrdup(buf);
	return false;
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
	struct wifi_ap_fronthaul_args curr_wifi_ap_fronthaul_args = {0};
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	char *band_list = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("mapcontroller", "ap", "dmmap_mapcontroller", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *type = NULL;
		char *enabled = NULL;
		char *ssid = NULL;
		bool b = false;

		dmuci_get_value_by_section_string(p->config_section, "type", &type);
		if (DM_LSTRCMP(type, "fronthaul") != 0)
			continue;

		// skip the disabled fronthaul interfaces
		dmuci_get_value_by_section_string(p->config_section, "enabled", &enabled);
		if (DM_STRLEN(enabled)) {
			string_to_bool(enabled, &b);
			if (b == false)
				continue;
		}

		dmuci_get_value_by_section_string(p->config_section, "ssid", &ssid);
		if (DM_STRLEN(ssid) == 0)
			continue;

		if (is_ssid_exists(section_name(p->config_section), ssid, &band_list))
			continue;

		curr_wifi_ap_fronthaul_args.uci_s = p->config_section;
		curr_wifi_ap_fronthaul_args.band_list = band_list;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "wifi_da_ssid_instance", "wifi_da_ssid_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_ap_fronthaul_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static json_object *find_device_json_object(const char *unique_key)
{
	json_object *data_arr = NULL;
	json_object *data_obj = NULL;
	json_object *res = NULL;
	int i = 0;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object *dev_arr = NULL;
		json_object *dev_obj = NULL;
		int j = 0;

		dmjson_foreach_obj_in_array(data_obj, dev_arr, dev_obj, j, 2, "wfa-dataelements:Network", "DeviceList") {

			char *id = dmjson_get_value(dev_obj, 1, "ID");
			if (DM_STRCASECMP(unique_key, id) == 0)
				return dev_obj;
		}
	}

	return NULL;
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

	// Device not found ==> create a new device uci section
	char node_name[32];

	snprintf(node_name, sizeof(node_name), "node_%s", unique_key);
	remove_char(node_name, ':');

	dmuci_add_section("mapcontroller", "node", &s);
	dmuci_rename_section_by_section(s, node_name);
	dmuci_set_value_by_section(s, "agent_id", unique_key);
	return s;
}

static json_object *find_radio_json_object(json_object *device_obj, const char *unique_key)
{
	json_object *radio_arr = NULL;
	json_object *radio_obj = NULL;
	int i = 0;

	dmjson_foreach_obj_in_array(device_obj, radio_arr, radio_obj, i, 1, "RadioList") {

		char mac[32] = {0};
		char *id = dmjson_get_value(radio_obj, 1, "ID");
		char *str = base64_decode(id);

		/* Cant use strlen on byte array that might genuinely include 0x00 */
		/* but to get 6 bytes, need 8 input BASE64 chars - check for that */
		if ((str != NULL) && (DM_STRLEN(id) == 8)) {
			string_to_mac(str, 6, mac, sizeof(mac));
			if (DM_STRCMP(unique_key, mac) == 0)
				return radio_obj;
		}
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

	// Radio not found ==> create a new radio uci section
	char radio_name[64];

	snprintf(radio_name, sizeof(radio_name), "radio_%s", unique_key);
	remove_char(radio_name, ':');

	dmuci_add_section("mapcontroller", "radio", &s);
	dmuci_rename_section_by_section(s, radio_name);
	dmuci_set_value_by_section(s, "agent_id", agent_id);
	dmuci_set_value_by_section(s, "macaddr", unique_key);
	return s;
}

static int browseWiFiDataElementsNetworkDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_data_element_args wifi_da_device_args = {0};
	json_object *data_arr = NULL;
	json_object *data_obj = NULL;
	json_object *res = NULL;
	char *inst = NULL;
	int i = 0, id = 0;

	dmubus_call("wifi.dataelements.collector", "dump2", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object *dev_arr = NULL;
		json_object *dev_obj = NULL;
		int j = 0;

		dmjson_foreach_obj_in_array(data_obj, dev_arr, dev_obj, j, 2, "wfa-dataelements:Network", "DeviceList") {

			char *key = dmjson_get_value(dev_obj, 1, "ID");
			if (!key || *key == '\0')
				continue;

			wifi_da_device_args.dump_obj = dev_obj;
			wifi_da_device_args.dump_fallback = find_device_json_object(key);
			wifi_da_device_args.uci_s = find_device_uci_section(key);

			inst = handle_instance_without_section(dmctx, parent_node, ++id);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&wifi_da_device_args, inst) == DM_STOP)
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
	json_object *wifi_da_device_dump2 = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *ssid_to_vid_arr = NULL, *ssid_to_vid_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_device_dump2, ssid_to_vid_arr, ssid_to_vid_obj, i, 1, "SSIDtoVIDMapping") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ssid_to_vid_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_device_dump2 = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *cac_status_arr = NULL, *cac_status_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_device_dump2, cac_status_arr, cac_status_obj, i, 1, "CACStatus") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)cac_status_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceIEEE1905SecurityInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_device_dump2 = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *ieee1905_security_arr = NULL, *ieee1905_security_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_device_dump2, ieee1905_security_arr, ieee1905_security_obj, i, 1, "IEEE1905Security") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)ieee1905_security_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}


static int browseWiFiDataElementsNetworkDeviceRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_data_element_args *wifi_da_device = (struct wifi_data_element_args *)prev_data;
	struct wifi_data_element_args wifi_da_radio_args = {0};
	struct json_object *radio_arr = NULL, *radio_obj = NULL;
	char *inst = NULL;
	int i = 0, id = 0;

	char *agent_id = dmjson_get_value(wifi_da_device->dump_obj, 1, "ID");

	dmjson_foreach_obj_in_array(wifi_da_device->dump_obj, radio_arr, radio_obj, i, 1, "RadioList") {

		char mac[32] = {0};
		char *radio_id = dmjson_get_value(radio_obj, 1, "ID");
		char *str = base64_decode(radio_id);

		/* Cant use strlen on byte array that might genuinely include 0x00 */
		/* but to get 6 bytes, need 8 input BASE64 chars - check for that */
		if ((str != NULL) && (DM_STRLEN(radio_id) == 8))
			string_to_mac(str, 6, mac, sizeof(mac));

		if (DM_STRLEN(mac) == 0)
			continue;

		wifi_da_radio_args.dump_obj = radio_obj;
		wifi_da_radio_args.dump_fallback = find_radio_json_object(wifi_da_device->dump_fallback, mac);
		wifi_da_radio_args.uci_s = find_radio_uci_section(agent_id, mac);

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&wifi_da_radio_args, inst) == DM_STOP)
			return 0;
	}

	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_available_channel_arr = NULL, *cac_available_channel_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, cac_available_channel_arr, cac_available_channel_obj, i, 1, "CACAvailableChannel") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)cac_available_channel_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_non_occupancy_channel_arr = NULL, *cac_non_occupancy_channel_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, cac_non_occupancy_channel_arr, cac_non_occupancy_channel_obj, i, 1, "CACNonOccupancyChannel") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)cac_non_occupancy_channel_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cac_active_channel_arr = NULL, *cac_active_channel_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, cac_active_channel_arr, cac_active_channel_obj, i, 1, "CACActiveChannel") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)cac_active_channel_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_fallback;
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, opclass_arr, opclass_obj, i, 1, "CurrentOperatingClasses") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *bss_arr = NULL, *bss_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, bss_arr, bss_obj, i, 1, "BSSList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bss_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *scanres_arr = NULL, *scanres_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, scanres_arr, scanres_obj, i, 1, "ScanResultList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)scanres_obj, inst) == DM_STOP)
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
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *unassoc_arr = NULL, *unassoc_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, unassoc_arr, unassoc_obj, i, 1, "UnassociatedStaList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)unassoc_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_fallback;
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, opclass_arr, opclass_obj, i, 2, "Capabilities", "OperatingClasses") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*
static int browseWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *qmdescriptor_arr = NULL, *qmdescriptor_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, qmdescriptor_arr, qmdescriptor_obj, i, 1, "QMDescriptor") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)qmdescriptor_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}
*/

static int browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *sta_arr = NULL, *sta_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, sta_arr, sta_obj, i, 1, "STAList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)sta_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_scan_arr = NULL, *opclass_scan_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, opclass_scan_arr, opclass_scan_obj, i, 1, "OpClassScanList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_scan_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *chscan_arr = NULL, *chscan_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, chscan_arr, chscan_obj, i, 1, "ChannelScanList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)chscan_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *neigh_arr = NULL, *neigh_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, neigh_arr, neigh_obj, i, 1, "NeighborList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)neigh_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, opclass_arr, opclass_obj, i, 1, "OpClassChannels") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *cacmethod_arr = NULL, *cacmethod_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, cacmethod_arr, cacmethod_obj, i, 2, "CACCapability", "CACMethod") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)cacmethod_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *cacmethod_obj = (json_object *)prev_data;
	json_object *op_class_arr = NULL, *op_class_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(cacmethod_obj, op_class_arr, op_class_obj, i, 1, "OpClassChannels") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)op_class_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*
static int browseWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_device = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *curropclass_arr = NULL, *curropclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_device, curropclass_arr, curropclass_obj, i, 2, "MultiAPDevice", "Backhaul_CurrentOperatingClassProfile") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curropclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}
*/

static int browseWiFiDataElementsAssociationEventAssociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_event_args curr_wifi_event_args = {0};
	json_object *res = NULL, *notify_arr = NULL, *notify_obj = NULL, *assoc_ev = NULL, *assoc_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("wifi.dataelements.collector", "event", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array_reverse(res, notify_arr, notify_obj, i, 1, "notification") {
		curr_wifi_event_args.event_time = dmjson_get_value(notify_obj, 1, "eventTime");
		if (json_object_object_get_ex(notify_obj, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_obj)) {
				curr_wifi_event_args.event_obj = assoc_obj;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_event_args, inst) == DM_STOP)
					break;
			}
		}
	}
	return 0;
}

static int browseWiFiDataElementsDisassociationEventDisassociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_event_args curr_wifi_event_args = {0};
	json_object *res = NULL, *notify_arr = NULL, *notify_obj = NULL, *disassoc_ev = NULL, *disassoc_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("wifi.dataelements.collector", "event", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array_reverse(res, notify_arr, notify_obj, i, 1, "notification") {
		curr_wifi_event_args.event_time = dmjson_get_value(notify_obj, 1, "eventTime");
		if (json_object_object_get_ex(notify_obj, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_obj)) {
				curr_wifi_event_args.event_obj = disassoc_obj;
				inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_event_args, inst) == DM_STOP)
					break;
			}
		}
	}
	return 0;
}

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

/*#Device.WiFi.DataElements.Network.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ID*/
static int get_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump", "ID", false, value);
}

/*#Device.WiFi.DataElements.Network.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.TimeStamp*/
static int get_WiFiDataElementsNetwork_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump", "TimeStamp", false, value);
}

/*#Device.WiFi.DataElements.Network.ControllerID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ControllerID*/
static int get_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump", "ControllerID", false, value);
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
	struct wifi_ap_fronthaul_args *args = (struct wifi_ap_fronthaul_args *)data;

	dmuci_get_value_by_section_string(args->uci_s, "ssid", value);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_Band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_ap_fronthaul_args *data_args = (struct wifi_ap_fronthaul_args *)data;

	*value = (data_args && data_args->band_list) ? data_args->band_list : "";
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
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].MultiAPCapabilities*/
static int get_WiFiDataElementsNetworkDevice_MultiAPCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "MultiAPCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].CollectionInterval*/
static int get_WiFiDataElementsNetworkDevice_CollectionInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "CollectionInterval");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ReportUnsuccessfulAssociations!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].ReportUnsuccessfulAssociations*/
static int get_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ReportUnsuccessfulAssociations");
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "report_sta_assocfails", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_MaxReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "MaxReportingRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_APMetricsReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "report_metric_periodic", value);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "report_metric_periodic", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Manufacturer!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].Manufacturer*/
static int get_WiFiDataElementsNetworkDevice_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "Manufacturer");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.SerialNumber!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].SerialNumber*/
static int get_WiFiDataElementsNetworkDevice_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "SerialNumber");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_ManufacturerModel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ManufacturerModel");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.SoftwareVersion!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].SoftwareVersion*/
static int get_WiFiDataElementsNetworkDevice_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "SoftwareVersion");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ExecutionEnv!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].ExecutionEnv*/
static int get_WiFiDataElementsNetworkDevice_ExecutionEnv(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ExecutionEnv");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_DSCPMap(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "DSCPMap");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.MaxPrioritizationRules!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].MaxPrioritizationRules*/
static int get_WiFiDataElementsNetworkDevice_MaxPrioritizationRules(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "MaxPrioritizationRules");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.PrioritizationSupport!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].PrioritizationSupport*/
static int get_WiFiDataElementsNetworkDevice_PrioritizationSupport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "PrioritizationSupport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.MaxVIDs!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].MaxVIDs*/
static int get_WiFiDataElementsNetworkDevice_MaxVIDs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "MaxVIDs");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_APMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "APMetricsWiFi6");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.CountryCode!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].CountryCode*/
static int get_WiFiDataElementsNetworkDevice_CountryCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "CountryCode");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_list = NULL;
	dmuci_get_value_by_section_list(((struct wifi_data_element_args *)data)->uci_s, "steer_exclude", &uci_list);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "steer_exclude", "");
			for (int i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "steer_exclude", arr[i]);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_list = NULL;
	dmuci_get_value_by_section_list(((struct wifi_data_element_args *)data)->uci_s, "steer_exclude_btm", &uci_list);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "steer_exclude_btm", "");
			for (int i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "steer_exclude_btm", arr[i]);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.DFSEnable!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].DFSEnable*/
static int get_WiFiDataElementsNetworkDevice_DFSEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "DFSEnable");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ReportIndependentScans!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].ReportIndependentScans*/
static int get_WiFiDataElementsNetworkDevice_ReportIndependentScans(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ReportIndependentScans");
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "report_scan", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "AssociatedSTAinAPMetricsWiFi6");
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
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "MaxUnsuccessfulAssociationReportingRate");
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
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_sta_assocfails_rate", value);
			return 0;
	}
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.STASteeringState!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].STASteeringState*/
static int get_WiFiDataElementsNetworkDevice_STASteeringState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "STASteeringState");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "CoordinatedCACAllowed");
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
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "coordinated_cac", b ? "1" : "0");
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
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ServicePrioritizationAllowed");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].NumberOfRadios*/
static int get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "RadioNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_Default8021QNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "Default8021QNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SSIDtoVIDMappingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "SSIDtoVIDMappingNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_CACStatusNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "CACStatusNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_IEEE1905SecurityNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "IEEE1905SecurityNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SPRuleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "SPRuleNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_AnticipatedChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "AnticipatedChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_AnticipatedChannelUsageNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "AnticipatedChannelUsageNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDeviceRadio_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadio_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadio_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadio_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Transmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Transmit*/
static int get_WiFiDataElementsNetworkDeviceRadio_Transmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "Transmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveSelf!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ReceiveSelf*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ReceiveSelf");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveOther!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].RecieveOther*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ReceiveOther");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.TrafficSeparationCombinedFronthaul!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].TrafficSeparationCombinedFronthaul*/
static int get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedFronthaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "TrafficSeparationCombinedFronthaul");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.TrafficSeparationCombinedBackhaul!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].TrafficSeparationCombinedBackhaul*/
static int get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedBackhaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "TrafficSeparationCombinedBackhaul");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_policy", value);
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
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_policy", value);
			return 0;
	}
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "util_threshold", value);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "util_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "rcpi_threshold", value);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "rcpi_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "report_rcpi_threshold", value);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "report_rcpi_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "report_rcpi_hysteresis_margin", value);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "report_rcpi_hysteresis_margin", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "report_util_threshold", value);
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "report_util_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_data_element_args *)data)->uci_s, "include_sta_stats", "1");
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "include_sta_stats", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_data_element_args *)data)->uci_s, "include_sta_metric", "1");
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
			dmuci_set_value_by_section(((struct wifi_data_element_args *)data)->uci_s, "include_sta_metric", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ChipsetVendor!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ChipsetVendor*/
static int get_WiFiDataElementsNetworkDeviceRadio_ChipsetVendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ChipsetVendor");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadio_APMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "APMetricsWiFi6");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfCurrOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_fallback, 1, "NumberOfCurrOpClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedSTANumberOfEntries*/
static int get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "UnassociatedSTANumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfBSS*/
static int get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "BSSNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfScanRes*/
static int get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ScanResultNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_DisAllowedOpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "DisAllowedOpClassChannelsNumberOfEntries");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BackhaulSta.MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "BackhaulSta", "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_fallback, 2, "Capabilities", "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *cap = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_fallback, 2, "Capabilities", "VHTCapabilities");
	*value = (DM_STRLEN(cap)) ? cap : "AAA=";
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *cap = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_fallback, 2, "Capabilities", "HECapabilities");
	*value = (DM_STRLEN(cap)) ? cap : "AAAAAA==";
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.NumberOfOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_fallback, 2, "Capabilities", "NumberOfOpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE160(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "HE160");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE8080(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "HE8080");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MCSNSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MCSNSS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "SUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "SUBeamformee");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_Beamformee80orLess(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "Beamformee80orLess");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_BeamformeeAbove80(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "BeamformeeAbove80");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "ULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "ULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MaxDLMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MaxULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MaxDLOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MaxULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_RTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "RTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MURTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MURTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MultiBSSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUEDCA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "MUEDCA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTRequestor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "TWTRequestor");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTResponder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "TWTResponder");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SpatialReuse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "SpatialReuse");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_AnticipatedChannelUsage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6APRole", "AnticipatedChannelUsage");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE160(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "HE160");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE8080(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "HE8080");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MCSNSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MCSNSS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "SUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "SUBeamformee");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MUBeamformer");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_Beamformee80orLess(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "Beamformee80orLess");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_BeamformeeAbove80(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "BeamformeeAbove80");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "ULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "ULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MaxDLMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MaxULMUMIMO");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MaxDLOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MaxULOFDMA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_RTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "RTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MURTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MURTS");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MultiBSSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUEDCA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "MUEDCA");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTRequestor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "TWTRequestor");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTResponder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "TWTResponder");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SpatialReuse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "SpatialReuse");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_AnticipatedChannelUsage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "Capabilities", "WiFi6bSTARole", "AnticipatedChannelUsage");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].Class*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.MaxTxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].MaxTxPower*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MaxTxPower");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NonOperable!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NonOperable*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NonOperable");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NumberOfNonOperChan!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NumberOfNonOperChan*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfNonOperChan");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Class*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Channel*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TxPower*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TxPower");
	return 0;
}
/*
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TransmitPowerLimit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TransmitPowerLimit");
	return 0;
}
*/
/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Enabled!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.LastChange!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].LastChange*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastChange");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesSent!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesReceived!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesSent!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesReceived!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesSent!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesReceived!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesReceived");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_ByteCounterUnits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ByteCounterUnits");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Profile1bSTAsDisallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile1bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Profile1bSTAsDisallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Profile1bSTAsDisallowed");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Profile2bSTAsDisallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile2bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Profile2bSTAsDisallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Profile2bSTAsDisallowed");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_AssociationAllowanceStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "AssociationAllowanceStatus");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBE!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBE*/
/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBE");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBK");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVI");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVO");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Profile2bSTAsDisallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile2bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BackhaulUse");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.FronthaulUse!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Profile2bSTAsDisallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "FronthaulUse");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.R1disallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].FronthaulUse*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_R1disallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "R1disallowed");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.R2disallowed!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].R2disallowed*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_R2disallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "R2disallowed");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MultiBSSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MultiBSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MultiBSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TransmittedBSSID!UBUS:wifi.dataelements.collector/dump2//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TransmittedBSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TransmittedBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TransmittedBSSID");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "FronthaulAKMsAllowed");
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
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "BackhaulAKMsAllowed");
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
	*value = dmjson_get_value((json_object *)data, 1, "NumberofSTA");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_QMDescriptorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "QMDescriptorNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_ClientMAC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ClientMAC");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_DescriptorElement(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "DescriptorElement");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BlacklistAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "MultiAPSteering", "BlacklistAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "MultiAPSteering", "BTMAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMQueryResponses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "MultiAPSteering", "BTMQueryResponses");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "VHTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "HECapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataDownlinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataDownlinkRate*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastDataDownlinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataUplinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataUplinkRate*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastDataUplinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationReceive!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationReceive*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UtilizationReceive");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationTransmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationTransmit*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UtilizationTransmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateDownlink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateDownlink*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstMACDataRateDownlink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateUplink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateUplink*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstMACDataRateUplink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].SignalStrength*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastConnectTime!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastConnectTime*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastConnectTime");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "PacketsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "PacketsReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ErrorsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "RetransCount");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MeasurementReport!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Measurementreport*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "Measurementreport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.NumberOfMeasureReports!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberOfMeasureReports*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfMeasureReports");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "IPV4Address");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "IPV6Address");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Hostname*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Hostname");
	return 0;
}
/*
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CellularDataPreference");
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
	*value = dmjson_get_value((json_object *)data, 1, "ReAssociationDelay");
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
	*value = dmjson_get_value((json_object *)data, 1, "TIDQueueSizesNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_NoCandidateAPFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "NoCandidateAPFailures");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BlacklistAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistSuccesses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BlacklistSuccesses");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BlacklistFailures");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMAttempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BTMAttempts");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMSuccesses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BTMSuccesses");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BTMFailures");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMQueryResponses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "BTMQueryResponses");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_LastSteerTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "SteeringSummaryStats", "LastSteerTime");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].NumberOfOpClassScans*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfOpClassScans");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.OperatingClass!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].OperatingClass*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OperatingClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].NumberOfChannelScans*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfChannelScans");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Channel*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NumberofNeighbors*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberofNeighbors");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SignalStrengh*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrengh");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelBandwidth!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelBandwidth*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ChannelBandwidth");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelUtilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelUtilization*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ChannelUtilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.StationCount!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].StationCount*/
static int get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "StationCount");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_OnBootOnly(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OnBootOnly");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_Impact(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Impact");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_MinimumInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MinimumInterval");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_OpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClassChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_ChannelList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "ChannelList");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapability_CACMethodNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "CACCapability", "CACMethodNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_Method(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Method");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_NumberOfSeconds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfSeconds");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_OpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClassChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_ChannelList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "ChannelList");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].SignalStrength*/
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_ManufacturerOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "MultiAPDevice", "ManufacturerOUI");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_LastContactTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "MultiAPDevice", "LastContactTime");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_AssocIEEE1905DeviceRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device_id = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "ID");
	adm_entry_get_reference_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.*.IEEE1905Id", device_id, value);
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshControllerOperationMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "MultiAPDevice", "EasyMeshControllerOperationMode");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshAgentOperationMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "MultiAPDevice", "EasyMeshAgentOperationMode");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_LinkType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "MultiAPDevice", "Backhaul", "LinkType");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "MultiAPDevice", "Backhaul", "BackhaulMACAddress");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulDeviceID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "MultiAPDevice", "Backhaul", "BackhaulDeviceID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "MultiAPDevice", "Backhaul", "MACAddress");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 3, "MultiAPDevice", "Backhaul", "CurrentOperatingClassProfileNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TxPower");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "BytesSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "BytesReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "PacketsSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "PacketsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "ErrorsSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LinkUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "LinkUtilization");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "SignalStrength");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "LastDataDownlinkRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "LastDataUplinkRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "TimeStamp");
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
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_VID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "VID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_CACAvailableChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CACAvailableChannelNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_CACNonOccupancyChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CACNonOccupancyChannelNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatus_CACActiveChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CACActiveChannelNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Minutes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Minutes");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Seconds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Seconds");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OpClass");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Countdown(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Countdown");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceIEEE1905Security_OnboardingProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OnboardingProtocol");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceIEEE1905Security_IntegrityAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "IntegrityAlgorithm");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceIEEE1905Security_EncryptionAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EncryptionAlgorithm");
	return 0;
}

static int get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsAssociationEventAssociationEventDataInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "BSSID");
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "MACAddress");
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "StatusCode");
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "HTCapabilities");
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "VHTCapabilities");
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "HECapabilities");
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct wifi_event_args *)data)->event_time;
	return 0;
}

/*
static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_HE160(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_HE8080(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MCSNSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SUBeamformee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MUBeamformer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_Beamformee80orLess(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_BeamformeeAbove80(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_ULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_ULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxDLMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxULMUMIMO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxDLOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxULOFDMA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_RTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MURTS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MUEDCA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_TWTRequestor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_TWTResponder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SpatialReuse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_AnticipatedChannelUsage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
*/

static int get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsDisassociationEventDisassociationEventDataInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "BSSID");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "MACAddress");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "ReasonCode");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "BytesSent");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "BytesReceived");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "PacketsSent");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "PacketsReceived");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "ErrorsSent");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_event_args *)data)->event_obj, 1, "RetransCount");
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct wifi_event_args *)data)->event_time;
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
		"AddRemove",
		"PassPhrase",
		"Band",
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

static int operate_WiFiDataElementsNetwork_SetSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *status = "Success";
	char *curr_ssid = NULL, *curr_band = NULL;
	char *pch = NULL, *spch = NULL;
	bool ssid_exist = false, b = false;
	char band_list[64] = {0};

	char *add_remove = dmjson_get_value((json_object *)value, 1, "AddRemove");
	if (!add_remove || *add_remove == '\0' || bbfdm_validate_boolean(ctx, add_remove)) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *ssid = dmjson_get_value((json_object *)value, 1, "SSID");
	char *key = dmjson_get_value((json_object *)value, 1, "PassPhrase");
	char *band = dmjson_get_value((json_object *)value, 1, "Band");
	if (DM_STRLEN(ssid) == 0 || DM_STRLEN(band) == 0) {
		status = "Error_Invalid_Input";
		goto end;
	}

	// Check band list
	DM_STRNCPY(band_list, band, sizeof(band_list));
	for (pch = strtok_r(band_list, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		if (DM_STRCMP(pch, "2.4") != 0 && DM_STRCMP(pch, "5") != 0 && DM_STRCMP(pch, "6") != 0) {
			status = "Error_Invalid_Input";
			goto end;
		}
	}

	DM_STRNCPY(band_list, band, sizeof(band_list));
	string_to_bool(add_remove, &b);

	if (b) {
		// Add this SSID

		for (pch = strtok_r(band_list, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
			ssid_exist = false;

			uci_foreach_option_eq("mapcontroller", "ap", "type", "fronthaul", s) {
				dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
				dmuci_get_value_by_section_string(s, "band", &curr_band);
				if (DM_STRCMP(curr_ssid, ssid) == 0 && DM_STRNCMP(curr_band, pch, 1) == 0) {
					dmuci_set_value_by_section(s, "enabled", "1");
					if (*key) dmuci_set_value_by_section(s, "key", key);
					ssid_exist = true;
					break;
				}
			}

			if (!ssid_exist) {
				char sec_name[32];
				unsigned idx = 1;

				uci_foreach_sections("mapcontroller", "ap", s)
					idx++;

				snprintf(sec_name, sizeof(sec_name), "ap_%s_%u", (*pch == '2') ? "2" : pch, idx);

				dmuci_add_section("mapcontroller", "ap", &s);
				dmuci_rename_section_by_section(s, sec_name);
				dmuci_set_value_by_section(s, "ssid", ssid);
				dmuci_set_value_by_section(s, "key", key);
				// TR181-2.16 does not have option to configure encryption mode, so use the sae as default encryption
				dmuci_set_value_by_section(s, "encryption", "sae-mixed");
				dmuci_set_value_by_section(s, "type", "fronthaul");
				dmuci_set_value_by_section(s, "band", (*pch == '2') ? "2" : pch);
				dmuci_set_value_by_section(s, "enabled", "1");
			}
		}
	} else {
		// Remove each band in the list linked to this SSID

		for (pch = strtok_r(band_list, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
			ssid_exist = false;

			uci_foreach_option_eq("mapcontroller", "ap", "type", "fronthaul", s) {
				dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
				dmuci_get_value_by_section_string(s, "band", &curr_band);
				if (DM_STRCMP(curr_ssid, ssid) == 0 && DM_STRNCMP(curr_band, pch, 1) == 0) {
					dmuci_set_value_by_section(s, "enabled", "0");
					ssid_exist = true;
					break;
				}
			}

			if (!ssid_exist) {
				status = "Error_Invalid_Input";
				dmuci_revert_package("mapcontroller");
				goto end;
			}
		}
	}

	// Commit dmmap_mapcontroller changes
	uci_path_foreach_sections(bbfdm, "dmmap_mapcontroller", "ap", s) {
		dmuci_delete_by_section(s, "wifi_da_ssid_instance", NULL);
	}

	dmuci_commit_package_bbfdm("dmmap_mapcontroller");

	// Commit mapcontroller config changes
	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

/*
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
	dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_disallow", b ? "1" : "0");
	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return 0;
}

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

	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "agent_id", &agent_id);
	dmuci_get_value_by_section_string(((struct wifi_data_element_args *)data)->uci_s, "macaddr", &macaddr);

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

/*************************************************************
 * EVENTS
 *************************************************************/
static event_args wifidataelementsassociationevent_associated_args = {
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

static event_args wifidataelementsdisassociationevent_disassociated_args = {
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

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.WiFi.DataElements. *** */
DMOBJ tWiFiDataElementsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Network", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkObj, tWiFiDataElementsNetworkParams, NULL, BBFDM_BOTH},
#ifdef BBFDM_WIFI_DATAELEMENTS_ASSOCIATION_EVENT_DATA
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventObj, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH, NULL},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventObj, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH, NULL},
#else
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH, NULL},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH, NULL},
#endif
//{"FailedConnectionEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsFailedConnectionEventObj, tWiFiDataElementsFailedConnectionEventParams, NULL, BBFDM_BOTH, NULL},
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
//{"SetSTASteeringState()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetSTASteeringState, operate_WiFiDataElementsNetworkDevice_SetSTASteeringState, BBFDM_USP},
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
// {"ManufacturerOUI", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_ManufacturerOUI, NULL, BBFDM_BOTH},
// {"LastContactTime", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDevice_LastContactTime, NULL, BBFDM_BOTH},
{"AssocIEEE1905DeviceRef", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_AssocIEEE1905DeviceRef, NULL, BBFDM_BOTH},
// {"EasyMeshControllerOperationMode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshControllerOperationMode, NULL, BBFDM_BOTH},
// {"EasyMeshAgentOperationMode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshAgentOperationMode, NULL, BBFDM_BOTH},
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
//{"SteerWiFiBackhaul()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul, operate_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul, BBFDM_USP},
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
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities, NULL, BBFDM_BOTH},
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
//{"SteeringHistory", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"AssociationTime", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_AssociationTime, NULL, BBFDM_BOTH},
//{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Noise, NULL, BBFDM_BOTH},
//{"SteeringHistoryNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_SteeringHistoryNumberOfEntries, NULL, BBFDM_BOTH},
//{"Disassociate()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Disassociate, operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Disassociate, BBFDM_USP},
//{"BTMRequest()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest, operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest, BBFDM_USP},
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
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Time", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_Time, NULL, BBFDM_BOTH},
//{"APOrigin", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APOrigin, NULL, BBFDM_BOTH},
//{"TriggerEvent", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_TriggerEvent, NULL, BBFDM_BOTH},
//{"SteeringApproach", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringApproach, NULL, BBFDM_BOTH},
//{"APDestination", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APDestination, NULL, BBFDM_BOTH},
//{"SteeringDuration", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringDuration, NULL, BBFDM_BOTH},
//{0}
//};

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
DMOBJ tWiFiDataElementsAssociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"AssociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsAssociationEventAssociationEventDataInst, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataObj, tWiFiDataElementsAssociationEventAssociationEventDataParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
#ifdef BBFDM_WIFI_DATAELEMENTS_ASSOCIATION_EVENT_DATA
{"AssociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries, NULL, BBFDM_BOTH},
#endif
{"Associated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsAssociationEvent_Associated, NULL, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}. *** */
DMOBJ tWiFiDataElementsAssociationEventAssociationEventDataObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"WiFi6Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataWiFi6CapabilitiesParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_BSSID, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress, NULL, BBFDM_BOTH},
{"StatusCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}.WiFi6Capabilities. *** */
//DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataWiFi6CapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_HE160, NULL, BBFDM_BOTH},
//{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_HE8080, NULL, BBFDM_BOTH},
//{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MCSNSS, NULL, BBFDM_BOTH},
//{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SUBeamformer, NULL, BBFDM_BOTH},
//{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SUBeamformee, NULL, BBFDM_BOTH},
//{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MUBeamformer, NULL, BBFDM_BOTH},
//{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_Beamformee80orLess, NULL, BBFDM_BOTH},
//{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_BeamformeeAbove80, NULL, BBFDM_BOTH},
//{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_ULMUMIMO, NULL, BBFDM_BOTH},
//{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_ULOFDMA, NULL, BBFDM_BOTH},
//{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxDLMUMIMO, NULL, BBFDM_BOTH},
//{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxULMUMIMO, NULL, BBFDM_BOTH},
//{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxDLOFDMA, NULL, BBFDM_BOTH},
//{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxULOFDMA, NULL, BBFDM_BOTH},
//{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_RTS, NULL, BBFDM_BOTH},
//{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MURTS, NULL, BBFDM_BOTH},
//{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MultiBSSID, NULL, BBFDM_BOTH},
//{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MUEDCA, NULL, BBFDM_BOTH},
//{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_TWTRequestor, NULL, BBFDM_BOTH},
//{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_TWTResponder, NULL, BBFDM_BOTH},
//{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SpatialReuse, NULL, BBFDM_BOTH},
//{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_AnticipatedChannelUsage, NULL, BBFDM_BOTH},
//{0}
//};

/* *** Device.WiFi.DataElements.DisassociationEvent. *** */
DMOBJ tWiFiDataElementsDisassociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DisassociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsDisassociationEventDisassociationEventDataInst, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventDisassociationEventDataParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tWiFiDataElementsDisassociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
#ifdef BBFDM_WIFI_DATAELEMENTS_ASSOCIATION_EVENT_DATA
{"DisassociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries, NULL, BBFDM_BOTH},
#endif
{"Disassociated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsDisassociationEvent_Disassociated, NULL, BBFDM_USP},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress, NULL, BBFDM_BOTH},
{"ReasonCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.FailedConnectionEvent. *** */
//DMOBJ tWiFiDataElementsFailedConnectionEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"FailedConnectionEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsFailedConnectionEventFailedConnectionEventDataInst, NULL, NULL, NULL, tWiFiDataElementsFailedConnectionEventFailedConnectionEventDataParams, NULL, BBFDM_BOTH, NULL},
//{0}
//};

//DMLEAF tWiFiDataElementsFailedConnectionEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"FailedConnectionEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsFailedConnectionEvent_FailedConnectionEventDataNumberOfEntries, NULL, BBFDM_BOTH},
//{"FailedConnection!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsFailedConnectionEvent_FailedConnection, NULL, BBFDM_USP},
//{0}
//};

/* *** Device.WiFi.DataElements.FailedConnectionEvent.FailedConnectionEventData.{i}. *** */
//DMLEAF tWiFiDataElementsFailedConnectionEventFailedConnectionEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_MACAddress, NULL, BBFDM_BOTH},
//{"StatusCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_StatusCode, NULL, BBFDM_BOTH},
//{"ReasonCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_ReasonCode, NULL, BBFDM_BOTH},
//{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_TimeStamp, NULL, BBFDM_BOTH},
//{0}
//};
