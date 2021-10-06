/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	Author: Saurabh Verma <saurabh.verma@iopsys.eu>
 *
 */

#include "dmentry.h"
#include "wifi.h"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_Wifi_Radio(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = (data && (((struct wifi_radio_args *)data)->sections)->config_section) ? section_name((((struct wifi_radio_args *)data)->sections)->config_section) : "";
	return 0;
}

static int get_linker_Wifi_Ssid(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = (data && ((struct wifi_ssid_args *)data)->ifname) ? ((struct wifi_ssid_args *)data)->ifname : "";
	return 0;
}

static int get_linker_associated_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? dmjson_get_value((json_object *)data, 1, "macaddr") : "";
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_wifi_radio(struct wifi_radio_args *args, struct dmmap_dup *s)
{
	args->sections = s;
	return 0;
}

static inline int init_wifi_ssid(struct wifi_ssid_args *args, struct dmmap_dup *s, char *wiface, char *linker)
{
	args->sections = s;
	args->ifname = wiface;
	args->linker = linker;
	return 0;
}

static inline int init_wifi_acp(struct wifi_acp_args *args, struct dmmap_dup *s, char *wiface)
{
	args->sections = s;
	args->ifname = wiface;
	return 0;
}

static inline int init_wifi_enp(struct wifi_enp_args *args, struct dmmap_dup *s, char *wiface)
{
	args->sections = s;
	args->ifname = wiface;
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static char *get_radio_option_nocache(const struct wifi_radio_args *args, char *option)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->sections->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);

	return (res) ? dmjson_get_value(res, 1, option) : "";
}

static char *get_data_model_mode(const char *ubus_mode)
{
	if (strcmp(ubus_mode, "WEP64") == 0)
		return "WEP-64";
	else if (strcmp(ubus_mode, "WEP128") == 0)
		return "WEP-128";
	else if (strcmp(ubus_mode, "WPAPSK") == 0)
		return "WPA-Personal";
	else if (strcmp(ubus_mode, "WPA2PSK") == 0)
		return "WPA2-Personal";
	else if (strcmp(ubus_mode, "WPA3PSK") == 0)
		return "WPA3-Personal";
	else if (strcmp(ubus_mode, "WPAPSK+WPA2PSK") == 0)
		return "WPA-WPA2-Personal";
	else if (strcmp(ubus_mode, "WPA2PSK+WPA3PSK") == 0)
		return "WPA3-Personal-Transition";
	else if (strcmp(ubus_mode, "WPA") == 0)
		return "WPA-Enterprise";
	else if (strcmp(ubus_mode, "WPA2") == 0)
		return "WPA2-Enterprise";
	else if (strcmp(ubus_mode, "WPA3") == 0)
		return "WPA3-Enterprise";
	else if (strcmp(ubus_mode, "WPA+WPA2") == 0)
		return "WPA-WPA2-Enterprise";
	else
		return "None";
}

static int get_supported_modes(const char *ubus_method, const char *ifname, char **value)
{
	char *dm_default_modes_supported = "None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA3-Personal,WPA-WPA2-Personal,WPA3-Personal-Transition,WPA-Enterprise,WPA2-Enterprise,WPA3-Enterprise,WPA-WPA2-Enterprise";
	char *dm_wifi_driver_modes_supported = "NONE,WEP64,WEP128,WPAPSK,WPA2PSK,WPA3PSK,WPAPSK+WPA2PSK,WPA2PSK+WPA3PSK,WPA,WPA2,WPA3,WPA+WPA2";
	json_object *res = NULL, *supported_modes = NULL;
	char list_modes[256], object[32], *mode = NULL;
	unsigned pos = 0, idx = 0;

	snprintf(object, sizeof(object), "%s.%s", ubus_method, ifname);
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = dm_default_modes_supported);

	list_modes[0] = 0;
	dmjson_foreach_value_in_array(res, supported_modes, mode, idx, 1, "supp_security") {
		if (!strstr(dm_wifi_driver_modes_supported, mode))
			continue;

		pos += snprintf(&list_modes[pos], sizeof(list_modes) - pos, "%s,", get_data_model_mode(mode));
	}

	/* cut tailing ',' */
	if (pos)
		list_modes[pos - 1] = 0;

	*value = (*list_modes != '\0') ? dmstrdup(list_modes) : dm_default_modes_supported;

	return 0;
}

static char *get_security_mode(struct uci_section *section)
{
	char *encryption = NULL;

	dmuci_get_value_by_section_string(section, "encryption", &encryption);
	if (!encryption || *encryption == '\0')
		return "None";

	if (strstr(encryption, "wep")) {
		char *key_index = NULL, *key = NULL;

		dmuci_get_value_by_section_string(section, "key", &key_index);
		if (key_index && (*key_index) > '0' && (*key_index) < '5' && *(key_index+1) == '\0') {
			char buf[16];

			snprintf(buf, sizeof(buf), "key%s", key_index);
			dmuci_get_value_by_section_string(section, buf, &key);
		}
		return (key && strlen(key) == 10) ? "WEP-64" : "WEP-128";
	}
	else if (strncmp(encryption, "psk-mixed", 9) == 0)
		return "WPA-WPA2-Personal";
	else if (strncmp(encryption, "psk2", 4) == 0)
		return "WPA2-Personal";
	else if (strncmp(encryption, "psk", 3) == 0)
		return "WPA-Personal";
	else if (strcmp(encryption, "sae") == 0)
		return "WPA3-Personal";
	else if (strcmp(encryption, "sae-mixed") == 0)
		return "WPA3-Personal-Transition";
	else if (strncmp(encryption, "wpa-mixed", 9) == 0)
		return "WPA-WPA2-Enterprise";
	else if (strncmp(encryption, "wpa2", 4) == 0)
		return "WPA2-Enterprise";
	else if (strncmp(encryption, "wpa3", 4) == 0)
		return "WPA3-Enterprise";
	else if (strncmp(encryption, "wpa", 3) == 0)
		return "WPA-Enterprise";
	else
		return "None";
}

static void reset_wlan(struct uci_section *s)
{
	dmuci_delete_by_section(s, "wpa_group_rekey", NULL);
	dmuci_delete_by_section(s, "wps", NULL);
	dmuci_delete_by_section(s, "key", NULL);
	dmuci_delete_by_section(s, "key1", NULL);
	dmuci_delete_by_section(s, "key2", NULL);
	dmuci_delete_by_section(s, "key3", NULL);
	dmuci_delete_by_section(s, "key4", NULL);
	dmuci_delete_by_section(s, "auth_server", NULL);
	dmuci_delete_by_section(s, "auth_port", NULL);
	dmuci_delete_by_section(s, "auth_secret", NULL);
}

static void generate_wep_key(const char *passphrase, char *buf, size_t len)
{
	unsigned pos = 0, i;

	for (i = 0; i < len/2; i++) {
		pos += snprintf(buf + pos, len - pos, "%02X", passphrase[i]);
	}
}

static char *get_default_wpa_key()
{
	char *wpakey;
	db_get_value_string("hw", "board", "wpa_key", &wpakey);
	return wpakey;
}

static void wifi_start_scan(const char *radio)
{
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", radio);
	dmubus_call_set(object, "scan", UBUS_ARGS{}, 0);
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_wifi_iface(char *inst_name, char **instance)
{
	struct uci_section *s = NULL, *dmmap_wifi = NULL;
	char ssid[32] = {0}, s_name[32] = {0};

	snprintf(ssid, sizeof(ssid), "iopsys_%s", *instance);
	snprintf(s_name, sizeof(s_name), "wlan_%s", *instance);

	dmuci_add_section("wireless", "wifi-iface", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_wifi, "ifname", ssid);
	dmuci_set_value_by_section(dmmap_wifi, inst_name, *instance);
	return 0;
}

static int add_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	return add_wifi_iface("ssidinstance", instance);
}

static int add_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	return add_wifi_iface("ap_instance", instance);
}

static int delete_wifi_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((((struct wifi_ssid_args *)data)->sections)->dmmap_section, NULL, NULL);
			dmuci_delete_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("wireless", "wifi-iface", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int addObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *endpoint_sec = NULL, *dmmap_sec = NULL;

	dmuci_add_section("wireless", "wifi-iface", &endpoint_sec);
	dmuci_set_value_by_section(endpoint_sec, "disabled", "1");
	dmuci_set_value_by_section(endpoint_sec, "device", "wl2"); // Should be removed after fixing Device.WiFi.EndPoint.{i}. object
	dmuci_set_value_by_section(endpoint_sec, "mode", "sta");
	dmuci_set_value_by_section(endpoint_sec, "network", "lan");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(endpoint_sec));
	dmuci_set_value_by_section(dmmap_sec, "endpointinstance", *instance);
	return 0;
}

static int delObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "endpointinstance", "");
		dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "mode", "");
		break;
	case DEL_ALL:
		uci_foreach_sections("wireless", "wifi-iface", s) {
			struct uci_section *dmmap_section = NULL;
			char *mode;

			dmuci_get_value_by_section_string(s, "mode", &mode);
			if (strcmp(mode, "sta") != 0)
				continue;

			dmuci_set_value_by_section(s, "mode", "");

			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(s), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "endpointinstance", "");
		}
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.WiFi.Radio.{i}.!UCI:wireless/wifi-device/dmmap_wireless*/
static int browseWifiRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct wifi_radio_args curr_wifi_radio_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-device", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_wifi_radio(&curr_wifi_radio_args, p);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "radioinstance", "radioalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_radio_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.SSID.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWifiSsidInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *ifname = NULL, *linker = NULL;
	struct wifi_ssid_args curr_wifi_ssid_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "device", &linker);
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);

		if (ifname && *ifname == '\0')
			dmuci_get_value_by_section_string(p->dmmap_section, "ifname", &ifname);

		init_wifi_ssid(&curr_wifi_ssid_args, p, ifname, linker);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "ssidinstance", "ssidalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_ssid_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWifiAccessPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *ifname, *mode = NULL;
	struct wifi_acp_args curr_wifi_acp_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if ((strlen(mode)>0 || mode[0] != '\0') && strcmp(mode, "ap") != 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);

		if (ifname && *ifname == '\0')
			dmuci_get_value_by_section_string(p->dmmap_section, "ifname", &ifname);

		init_wifi_acp(&curr_wifi_acp_args, p, ifname);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "ap_instance", "ap_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_acp_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWiFiEndPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *ifname, *mode = NULL;
	struct wifi_enp_args curr_wifi_enp_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if (strcmp(mode, "sta") != 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_wifi_enp(&curr_wifi_enp_args, p, ifname);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "endpointinstance", "endpointalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_enp_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseWiFiEndPointProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ep_instance = NULL;
	struct wifi_enp_args *ep_args = (struct wifi_enp_args *)prev_data;

	dmuci_get_value_by_section_string(ep_args->sections->dmmap_section, "endpointinstance", &ep_instance);
	struct uci_section *s = is_dmmap_section_exist_eq("dmmap_wireless", "ep_profile", "ep_key", ep_instance);
	if (!s)
		dmuci_add_section_bbfdm("dmmap_wireless", "ep_profile", &s);
	dmuci_set_value_by_section_bbfdm(s, "ep_key", ep_instance);

	handle_instance(dmctx, parent_node, s, "ep_profile_instance", "ep_profile_alias");

	DM_LINK_INST_OBJ(dmctx, parent_node, ep_args->sections->config_section, "1");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.!UBUS:wifi.radio.@Name/scanresults//accesspoints*/
static int browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	json_object *res = NULL, *accesspoints = NULL, *arrobj = NULL;
	char object[32], *inst = NULL;
	int id = 0, i = 0;

	uci_foreach_sections("wireless", "wifi-device", s) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(s));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		dmjson_foreach_obj_in_array(res, arrobj, accesspoints, i, 1, "accesspoints") {
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)accesspoints, inst) == DM_STOP)
				return 0;
		}
	}
	return 0;
}

static int browse_wifi_associated_device(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *stations = NULL, *arrobj = NULL;
	char object[32], *inst = NULL;
	int id = 0, i = 0;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)prev_data)->ifname);
	dmubus_call(object, "stations", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, stations, i, 1, "stations") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)stations, inst) == DM_STOP)
			return 0;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int i = 0, j = 0, id = 0;
	char *inst = NULL;
	json_object *res = NULL, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;
	json_object *dev_arr = NULL, *dev_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		dmjson_foreach_obj_in_array(net_obj, dev_arr, dev_obj, j, 1, "DeviceList") {
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dev_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *radio_arr = NULL, *radio_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, radio_arr, radio_obj, i, 1, "RadioList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)radio_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, opclass_arr, opclass_obj, i, 1, "CurrentOperatingClasses") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *bss_arr = NULL, *bss_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, bss_arr, bss_obj, i, 1, "BSSList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bss_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioScanResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *scanres_arr = NULL, *scanres_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, scanres_arr, scanres_obj, i, 1, "ScanResultList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)scanres_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *unassoc_arr = NULL, *unassoc_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, unassoc_arr, unassoc_obj, i, 1, "UnassociatedStaList") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)unassoc_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *caps_obj = NULL, *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	json_object_object_get_ex((json_object *)prev_data, "Capabilites", &caps_obj);
	dmjson_foreach_obj_in_array(caps_obj, opclass_arr, opclass_obj, i, 1, "OperatingClasses") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

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

static int browseWiFiDataElementsAssociationEventAssociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *notify_arr = NULL, *notify_obj = NULL, *assoc_ev = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("wifi.dataelements.collector", "event", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, notify_arr, notify_obj, i, 1, "notification") {
		if (json_object_object_get_ex(notify_obj, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)notify_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseWiFiDataElementsDisassociationEventDisassociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *notify_arr = NULL, *notify_obj = NULL, *disassoc_ev = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("wifi.dataelements.collector", "event", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, notify_arr, notify_obj, i, 1, "notification") {
		if (json_object_object_get_ex(notify_obj, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)notify_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.RadioNumberOfEntries!UCI:wireless/wifi-device/*/
static int get_WiFi_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWifiRadioInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.WiFi.SSIDNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_SSIDNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWifiSsidInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.WiFi.AccessPointNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_AccessPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWifiAccessPointInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.WiFi.EndPointNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_EndPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiEndPointInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.WiFi.SSID.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
/*#Device.WiFi.AccessPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_wifi_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "Down" : "Up";
	return 0;
}


/*#Device.WiFi.SSID.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
static int get_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->config_section, "ssid", value);
	return 0;
}

static int set_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, "ssid", value);
			return 0;
	}
	return 0;
}

static int get_wlan_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name((((struct wifi_ssid_args *)data)->sections)->config_section));
	return 0;
}

/*#Device.WiFi.SSID.{i}.MACAddress!SYSFS:/sys/class/net/@Name/address*/
static int get_WiFiSSID_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_net_device_sysfs(((struct wifi_ssid_args *)data)->ifname, "address", value);
}

/*#Device.WiFi.Radio.{i}.Enable!UCI:wireless/wifi-device,@i-1/disabled*/
static int get_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.Status!UCI:wireless/wifi-device,@i-1/disabled*/
static int get_radio_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "Down" : "Up";
	return 0;
}

static int get_WiFiRadio_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_WiFiRadio_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_WiFiRadio_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	return 0;
}

static int get_WiFiRadio_AutoChannelSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod!UCI:wireless/wifi-device,@i-1/acs_refresh_period*/
static int get_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "acs_refresh_period", "0");
	return 0;
}

static int set_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "acs_refresh_period", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxSupportedAssociations!UCI:wireless/wifi-device,@i-1/maxassoc*/
static int get_WiFiRadio_MaxSupportedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "maxassoc", "32");
	return 0;
}

/*#Device.WiFi.Radio.{i}.FragmentationThreshold!UCI:wireless/wifi-device,@i-1/frag_threshold*/
static int get_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "frag_threshold", "2346");
	return 0;
}

static int set_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "frag_threshold", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RTSThreshold!UCI:wireless/wifi-device,@i-1/rts_threshold*/
static int get_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "rts_threshold", "2347");
	return 0;
}

static int set_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "rts_threshold", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.BeaconPeriod!UCI:wireless/wifi-device,@i-1/beacon_int*/
static int get_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "beacon_int", "100");
	return 0;
}

static int set_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "beacon_int", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.DTIMPeriod!UCI:wireless/wifi-device,@i-1/dtim_period*/
static int get_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "dtim_period", "2");
	return 0;
}

static int set_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "dtim_period", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingChannelBandwidth!UCI:wireless/wifi-device,@i-1/htmode*/
static int get_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *htmode = NULL;

	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", &htmode);

	if (htmode && *htmode) {
		int freq;

		sscanf(htmode, "%*[A-Z]%d", &freq);
		dmasprintf(value, "%dMHz", !strcmp(htmode, "NOHT") ? 20 : freq);
	} else {
		*value = "Auto";
	}

	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths!UBUS:wifi.radio.@Name/status//supp_channels[0].bandwidth*/
static int get_WiFiRadio_SupportedOperatingChannelBandwidths(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL, *arrobj = NULL;
	char bandwidth_list[128], object[32];
	int i = 0, pos = 0;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "Auto");

	bandwidth_list[0] = 0;
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		char *bandwidth = dmjson_get_value(supp_channels, 1, "bandwidth");
		if (bandwidth && !strstr(bandwidth_list, !strcmp(bandwidth, "8080") ? "80+80" : !strcmp(bandwidth, "80") ? ",80MHz" : bandwidth)) {
			pos += snprintf(&bandwidth_list[pos], sizeof(bandwidth_list) - pos, "%sMHz,", !strcmp(bandwidth, "8080") ? "80+80" : bandwidth);
		}
	}

	if (pos)
		bandwidth_list[pos - 1] = 0;

	*value = dmstrdup(bandwidth_list);
	return 0;
}

static int set_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_bandwidths = NULL;
	char *curr_htmode = NULL;
	char htmode[32];
	int freq;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedOperatingChannelBandwidth, NULL))
				return FAULT_9007;

			// Get the list of all supported operating channel bandwidths
			get_WiFiRadio_SupportedOperatingChannelBandwidths(refparam, ctx, data, instance, &supported_bandwidths);

			// Check if the input value is a valid channel bandwidth value
			if (!value_exits_in_str_list(supported_bandwidths, ",", value))
				return FAULT_9007;

			break;
		case VALUESET:
			sscanf(value, "%d", &freq);

			dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", &curr_htmode);

			if (strncmp(curr_htmode, "VHT", 3) == 0)
				snprintf(htmode, sizeof(htmode), "VHT%d", freq);
			else if (strncmp(curr_htmode, "HT", 2) == 0 && (freq == 20 || freq == 40))
				snprintf(htmode, sizeof(htmode), "HT%d", freq);
			else
				snprintf(htmode, sizeof(htmode), "HE%d", freq);

			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", htmode);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.PreambleType!UCI:wireless/wifi-device,@i-1/short_preamble*/
static int get_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "short_preamble", value);
	*value = ((*value)[0] == '1') ? "short" : "long";
	return 0;
}

static int set_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, PreambleType, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "short_preamble", (strcmp(value, "short") == 0) ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiRadio_IEEE80211hSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.IEEE80211hEnabled!UCI:wireless/wifi-device,@i-1/doth*/
static int get_WiFiRadio_IEEE80211hEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "doth", "0");
	return 0;
}

static int set_WiFiRadio_IEEE80211hEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "doth", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.TransmitPower!UCI:wireless/wifi-device,@i-1/txpower*/
static int get_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_radio_args *)data)->sections)->config_section, "txpower", "100");
	return 0;
}

static int set_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","100"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "txpower", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RegulatoryDomain!UCI:wireless/wifi-device,@i-1/country*/
static int get_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *conf_country, *dmmap_contry = NULL;

	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "country", &conf_country);
	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->dmmap_section, "country", &dmmap_contry);

	dmasprintf(value, "%s%c", conf_country, (dmmap_contry && *dmmap_contry) ? dmmap_contry[2] : ' ');
	return 0;
}

static int set_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, 3, 3, NULL, RegulatoryDomain))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->dmmap_section, "country", value);
			value[2] = '\0';
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "country", value);
			break;
	}
	return 0;
}

static int set_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","255"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "channel", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelEnable!UCI:wireless/wifi-device,@i-1/channel*/
static int get_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0')
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				value = "auto";
			else
				value = get_radio_option_nocache(data, "channel");

			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "channel", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.SSIDAdvertisementEnabled!UCI:wireless/wifi-iface,@i-1/hidden*/
static int get_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->config_section, "hidden", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, "hidden", b ? "0" : "1");
			return 0;

	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WMMEnable!UCI:wireless/wifi-device,@i-1/wmm*/
static int get_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "wmm", "1");
	return 0;
}

static int set_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wmm", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MACAddressControlEnabled!UCI:wireless/wifi-iface,@i-1/macfilter*/
static int get_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *macfilter;

	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "macfilter", &macfilter);
	if (macfilter[0] == 0 || strcmp(macfilter, "deny") == 0 || strcmp(macfilter, "disable") == 0)
		*value = "false";
	else
		*value = "true";
	return 0;
}

static int get_WiFiAccessPoint_WMMCapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MaxAllowedAssociations!UCI:wireless/wifi-iface,@i-1/maxassoc*/
static int get_WiFiAccessPoint_MaxAllowedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "maxassoc", "32");
	return 0;
}

static int set_WiFiAccessPoint_MaxAllowedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "maxassoc", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.IsolationEnable!UCI:wireless/wifi-iface,@i-1/isolate*/
static int get_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "isolate", "0");
	return 0;
}

static int set_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "isolate", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AllowedMACAddress!UCI:wireless/wifi-iface,@i-1/maclist*/
static int get_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val = NULL;
	dmuci_get_value_by_section_list((((struct wifi_acp_args *)data)->sections)->config_section, "maclist", &val);
	*value = dmuci_list_to_string(val, ",");
	return 0;
}

static int set_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length;
	int i;
	char **arr;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "maclist", "");
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "maclist", arr[i]);
			break;
	}
	return 0;
}

static int get_WiFiAccessPoint_UAPSDCapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "macfilter", b ? "allow" : "disable");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.UAPSDEnable!UCI:wireless/wifi-iface,@i-1/wmm_apsd*/
static int get_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "wmm_apsd", "0");
	return 0;
}

static int set_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wmm_apsd", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_access_point_security_supported_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_supported_modes("wifi.ap", ((struct wifi_acp_args *)data)->ifname, value);
}

static bool is_different_group(const char *mode1, const char *mode2)
{
	int i, g1 = 0, g2 =0;
	char *security_modes[3] = {
		"WEP-64, WEP-128",
		"WPA-Personal, WPA2-Personal, WPA3-Personal, WPA-WPA2-Personal, WPA3-Personal-Transition",
		"WPA-Enterprise, WPA2-Enterprise, WPA3-Enterprise, WPA-WPA2-Enterprise"};

	for (i = 0; i < 3; i++) {
		if (strstr(security_modes[i], mode1)) {
			g1 = i;
		}

		if (strstr(security_modes[i], mode2)) {
			g2 = i;
		}
	}

	return (g1 != g2);

}

static void set_security_mode(struct uci_section *section, char *value)
{
	char *wpa_key = NULL;
	char *mode = get_security_mode(section);

	// Use default key only in case the key is not set
	dmuci_get_value_by_section_string(section, "key", &wpa_key);
	if (strlen(wpa_key) == 0)
		wpa_key = get_default_wpa_key();

	if (mode && strcmp(value, mode) != 0) {
		// Only reset the wlan key section if its belongs to different group
		if (is_different_group(value, mode))
			reset_wlan(section);

		if (strcmp(value, "None") == 0) {
			dmuci_set_value_by_section(section, "encryption", "none");
		} else if (strcmp(value, "WEP-64") == 0) {
			char key[16], buf[11];
			int i;

			generate_wep_key("iopsys", buf, sizeof(buf));
			for (i = 0; i < 4; i++) {
				snprintf(key, sizeof(key), "key%d", i + 1);
				dmuci_set_value_by_section(section, key, buf);
			}
			dmuci_set_value_by_section(section, "encryption", "wep-open");
			dmuci_set_value_by_section(section, "key", "1");
		} else if (strcmp(value, "WEP-128") == 0) {
			char key[16], buf[27];
			int i;

			generate_wep_key("iopsys_wep128", buf, sizeof(buf));
			for (i = 0; i < 4; i++) {
				snprintf(key, sizeof(key), "key%d", i + 1);
				dmuci_set_value_by_section(section, key, buf);
			}
			dmuci_set_value_by_section(section, "encryption", "wep-open");
			dmuci_set_value_by_section(section, "key", "1");
		} else if (strcmp(value, "WPA-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "psk");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
		} else if (strcmp(value, "WPA-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa");
			dmuci_set_value_by_section(section, "auth_port", "1812");
		} else if (strcmp(value, "WPA2-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "psk2");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(section, "wps", "1");
		} else if (strcmp(value, "WPA2-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa2");
			dmuci_set_value_by_section(section, "auth_port", "1812");
		} else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "psk-mixed");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(section, "wps", "1");
		} else if (strcmp(value, "WPA-WPA2-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa-mixed");
			dmuci_set_value_by_section(section, "auth_port", "1812");
		} else if (strcmp(value, "WPA3-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "sae");
			dmuci_set_value_by_section(section, "key", wpa_key);
		} else if (strcmp(value, "WPA3-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa3");
			dmuci_set_value_by_section(section, "auth_port", "1812");
		} else if (strcmp(value, "WPA3-Personal-Transition") == 0) {
			dmuci_set_value_by_section(section, "encryption", "sae-mixed");
			dmuci_set_value_by_section(section, "key", wpa_key);
		}
	}
}

/*#Device.WiFi.AccessPoint.{i}.Security.ModeEnabled!UCI:wireless/wifi-iface,@i-1/encryption&UCI:wireless/wifi-iface,@i-1/encryption*/
static int get_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_security_mode((((struct wifi_acp_args *)data)->sections)->config_section);
	return 0;
}

static int set_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_modes = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;

			// Get the list of all supported security modes
			get_access_point_security_supported_modes(refparam, ctx, data, instance, &supported_modes);

			// Check if the input value is a valid security mode
			if (!value_exits_in_str_list(supported_modes, ",", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			set_security_mode((((struct wifi_acp_args *)data)->sections)->config_section, value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_wepkey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"5","5"},{"13","13"}}, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "wep")) {
				char *key_index = NULL, buf[16];

				dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "key", &key_index);
				snprintf(buf, sizeof(buf),"key%s", key_index ? key_index : "1");
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, buf, value);
			}
			return 0;
	}
	return 0;
}

static int set_access_point_security_shared_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"32"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "psk"))
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_passphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, 8, 63, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "psk"))
				set_access_point_security_shared_key(refparam, ctx, data, instance, value, action);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval!UCI:wireless/wifi-iface,@i-1/wpa_group_rekey*/
static int get_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "wpa_group_rekey", "0");
	return 0;
}

static int set_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (!strstr(encryption, "wep") && strcmp(encryption, "none") != 0)
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wpa_group_rekey", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.SAEPassphrase!UCI:wireless/wifi-iface,@i-1/key*/
static int set_WiFiAccessPointSecurity_SAEPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "sae"))
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr!UCI:wireless/wifi-iface,@i-1/auth_server*/
static int get_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "auth_server", value);
	return 0;
}

static int set_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "wpa"))
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "auth_server", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort!UCI:wireless/wifi-iface,@i-1/auth_port*/
static int get_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "auth_port", "1812");
	return 0;
}

static int set_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "wpa"))
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "auth_port", value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_radius_secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (strstr(encryption, "wpa"))
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "auth_secret", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.MFPConfig!UCI:wireless/wifi-iface,@i-1/ieee80211w*/
static int get_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "ieee80211w", value);

	if (*value[0] == '1')
		*value = "Optional";
	else if (*value[0] == '2')
		*value = "Required";
	else
		*value = "Disabled";
	return 0;
}

static int set_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[2];

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, MFPConfig, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcmp(value, "Disabled") == 0)
				buf[0] = '0';
			else if (strcmp(value, "Optional") == 0)
				buf[0] = '1';
			else if (strcmp(value, "Required") == 0)
				buf[0] = '2';
			buf[1] = 0;
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "ieee80211w", buf);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "wps", "0");
	return 0;
}

static int set_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wps", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiAccessPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton,Label,PIN";
	return 0;
}

static int get_wps_config_methods_enabled(struct uci_section *section, char **value)
{
	char *pushbut = NULL, *label = NULL, *pin = NULL;
	char buf[32] = {0};

	dmuci_get_value_by_section_string(section, "wps_pushbutton", &pushbut);
	dmuci_get_value_by_section_string(section, "wps_label", &label);
	dmuci_get_value_by_section_string(section, "wps_pin", &pin);

	if (*pushbut && strcmp(pushbut, "1") == 0)
		strcpy(buf, "PushButton");

	if (*label && strcmp(label, "1") == 0) {
		if (*buf)
			strcat(buf, ",");

		strcat(buf, "Label");
	}

	if (*pin && strcmp(pin, "1") == 0) {
		if (*buf)
			strcat(buf, ",");

		strcat(buf, "PIN");
	}

	*value = dmstrdup(buf);
	return 0;
}

static void set_wps_config_methods_enabled(struct uci_section *section, char *value)
{
	char *token = NULL, *saveptr = NULL;
	bool pushbut = false, label = false, pin = false;

	char *wps_list = dmstrdup(value);
	for (token = strtok_r(wps_list, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {

		if (strcmp(token, "PushButton") == 0)
			pushbut = true;

		if (strcmp(token, "Label") == 0)
			label = true;

		if (strcmp(token, "PIN") == 0)
			pin = true;
	}
	dmfree(wps_list);

	dmuci_set_value_by_section(section, "wps_pushbutton", pushbut ? "1" : "0");
	dmuci_set_value_by_section(section, "wps_label", label ? "1" : "0");
	dmuci_set_value_by_section(section, "wps_pin", pin ? "1" : "0");
}

static int get_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_wps_config_methods_enabled((((struct wifi_acp_args *)data)->sections)->config_section, value);
}

static int set_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			set_wps_config_methods_enabled((((struct wifi_acp_args *)data)->sections)->config_section, value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiAccessPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "wps", &wps_status);
	*value = (wps_status[0] == '1') ? "Configured" : "Disabled";
	return 0;
}

static int set_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 8, NULL, PIN))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wps_pin", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerIPAddr!UCI:wireless/wifi-iface,@i-1/acct_server*/
static int get_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "acct_server", value);
	return 0;
}

static int set_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "acct_server", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerPort!UCI:wireless/wifi-iface,@i-1/acct_port*/
static int get_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "acct_port", "1813");
	return 0;
}

static int set_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "acct_port", value);
			break;
	}
	return 0;
}

static int set_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "acct_secret", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_enp_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_WiFiEndPoint_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_enp_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/endpointalias*/
static int get_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_enp_args *)data)->sections)->dmmap_section, "endpointalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->dmmap_section, "endpointalias", value);
			return 0;
	}
	return 0;
}

static int get_WiFiEndPoint_SSIDReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", ((struct wifi_enp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_WiFiEndPointSecurity_ModesSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_supported_modes("wifi.backhaul", ((struct wifi_enp_args *)data)->ifname, value);
}

static int get_WiFiEndPointProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_WiFiEndPointProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_WiFiEndPointProfile_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Active";
	return 0;
}

static int get_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL, *dm = NULL;
	char *epinst = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
	get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
	dmuci_get_value_by_section_string(dm, "ep_profile_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL, *dm = NULL;
	char *epinst = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
			dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
			get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
			dmuci_set_value_by_section_bbfdm(dm, "ep_profile_alias", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
static int get_WiFiEndPointProfile_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section*)data, "ssid", value);
	return 0;
}

static int set_WiFiEndPointProfile_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section*)data, "ssid", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.Security.ModeEnabled!UCI:wireless/wifi-iface,@i-1/encryption*/
static int get_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_security_mode((struct uci_section *)data);
	return 0;
}

static int set_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_modes = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;

			// Get the list of all supported security modes
			get_WiFiEndPointSecurity_ModesSupported(refparam, ctx, data, instance, &supported_modes);

			// Check if the input value is a valid security mode
			if (!value_exits_in_str_list(supported_modes, ",", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			set_security_mode((struct uci_section *)data, value);
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_WEPKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"5","5"},{"13","13"}}, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strstr(encryption, "wep")) {
				char *key_index = NULL, buf[16];

				dmuci_get_value_by_section_string((struct uci_section*)data, "key", &key_index);
				snprintf(buf, sizeof(buf),"key%s", key_index ? key_index : "1");
				dmuci_set_value_by_section((struct uci_section*)data, buf, value);
			}
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_PreSharedKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"32"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strstr(encryption, "psk"))
				dmuci_set_value_by_section((struct uci_section*)data, "key", value);
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_KeyPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, 8, 63, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strstr(encryption, "psk"))
				set_WiFiEndPointProfileSecurity_PreSharedKey(refparam, ctx, data, instance, value, action);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.Security.SAEPassphrase!UCI:wireless/wifi-iface,@i-1/key*/
static int set_WiFiEndPointProfileSecurity_SAEPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strstr(encryption, "sae"))
				dmuci_set_value_by_section((struct uci_section*)data, "key", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.Security.MFPConfig!UCI:wireless/wifi-iface,@i-1/ieee80211w*/
static int get_WiFiEndPointProfileSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section*)data, "ieee80211w", value);
	if(*value[0] == 0 || *value[0] == '0')
		*value = "Disabled";
	else if (strcmp(*value, "1") == 0)
		*value = "Optional";
	else if (strcmp(*value, "2") == 0)
		*value = "Required";
	return 0;
}

static int set_WiFiEndPointProfileSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, MFPConfig, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcmp(value, "Disabled") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "0");
			else if (strcmp(value, "Optional") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "1");
			else if (strcmp(value, "Required") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "2");
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_enp_args *)data)->sections)->config_section, "wps", "0");
	return 0;
}

static int set_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "wps", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiEndPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton,Label,PIN";
	return 0;
}

static int get_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_wps_config_methods_enabled((((struct wifi_enp_args *)data)->sections)->config_section, value);
}

static int set_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			set_wps_config_methods_enabled((((struct wifi_enp_args *)data)->sections)->config_section, value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiEndPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string((((struct wifi_enp_args *)data)->sections)->config_section, "wps", &wps_status);
	*value = (wps_status[0] == '1') ? "Configured" : "Disabled";
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.PIN!UCI:wireless/wifi-iface,@i-1/wps_pin*/
static int get_WiFiEndPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int set_WiFiEndPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"4","4"},{"8","8"}}, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "wps_pin", value);
			break;
	}
	return 0;
}

/**************************************************************************
* SET AND GET ALIAS
***************************************************************************/
/*#Device.WiFi.Radio.{i}.Alias!UCI:dmmap_wireless/wifi-device,@i-1/radioalias*/
static int get_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->dmmap_section, "radioalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->dmmap_section, "radioalias", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/ssidalias*/
static int get_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->dmmap_section, "ssidalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_ssid_args *)data)->sections)->dmmap_section, "ssidalias", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/ap_alias*/
static int get_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->dmmap_section, "ap_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->dmmap_section, "ap_alias", value);
			return 0;
	}
	return 0;
}

static int get_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (data && ((struct wifi_ssid_args *)data)->linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", ((struct wifi_ssid_args *)data)->linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *ssid_linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &ssid_linker);
			if (ssid_linker && *ssid_linker) {
				dmuci_set_value_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, "device", ssid_linker);
				dmfree(ssid_linker);
			}
			return 0;
	}
	return 0;
}

static int get_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", ((struct wifi_acp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (*value == '\0')
				break;

			adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", ((struct wifi_acp_args *)data)->ifname, &linker);
			if (strncmp(value, "Device.WiFi.SSID.", 17) != 0 || (linker && strcmp(value, linker) != 0))
				return FAULT_9007;

			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int set_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				uci_foreach_sections("wireless", "wifi-device", ss)
					wifi_start_scan(section_name(ss));

				dmubus_call_set("tr069", "inform", UBUS_ARGS{{"event", "8 DIAGNOSTICS COMPLETE", String}}, 1);
			}
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.BSSID!UBUS:wifi.ap.@Name/status//bssid*/
static int get_wlan_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_ssid_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "bssid");
	return 0;
}

static int ssid_read_ubus(const struct wifi_ssid_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.ap.%s", args->ifname);
	dmubus_call(object, "stats", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

static int radio_read_ubus(const struct wifi_radio_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->sections->config_section));
	dmubus_call(object, "stats", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.BytesSent!UBUS:wifi.radio.@Name/stats//tx_bytes*/
static int get_WiFiRadioStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_bytes", value);
}

/*#Device.WiFi.Radio.{i}.Stats.BytesReceived!UBUS:wifi.radio.@Name/stats//rx_bytes*/
static int get_WiFiRadioStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_bytes", value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsSent!UBUS:wifi.radio.@Name/stats//tx_packets*/
static int get_WiFiRadioStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsReceived!UBUS:wifi.radio.@Name/stats//rx_packets*/
static int get_WiFiRadioStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsSent!UBUS:wifi.radio.@Name/stats//tx_error_packets*/
static int get_WiFiRadioStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_error_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsReceived!UBUS:wifi.radio.@Name/stats//rx_error_packets*/
static int get_WiFiRadioStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_error_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent!UBUS:wifi.radio.@Name/stats//tx_dropped_packets*/
static int get_WiFiRadioStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_dropped_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.radio.@Name/stats//rx_dropped_packets*/
static int get_WiFiRadioStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_dropped_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.FCSErrorCount!UBUS:wifi.radio.@Name/stats//rx_fcs_error_packets*/
static int get_WiFiRadioStats_FCSErrorCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_fcs_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stats//tx_bytes*/
static int get_WiFiSSIDStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_bytes", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stats//rx_bytes*/
static int get_WiFiSSIDStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_bytes", value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stats//tx_packets*/
static int get_WiFiSSIDStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stats//rx_packets*/
static int get_WiFiSSIDStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stats//tx_error_packets*/
static int get_WiFiSSIDStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsReceived!UBUS:wifi.ap.@Name/stats//rx_error_packets*/
static int get_WiFiSSIDStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent!UBUS:wifi.ap.@Name/stats//tx_dropped_packets*/
static int get_WiFiSSIDStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_dropped_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_dropped_packets*/
static int get_WiFiSSIDStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_dropped_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_unicast_packets*/
static int get_WiFiSSIDStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_unicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unicast_packets*/
static int get_WiFiSSIDStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_unicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_multicast_packets*/
static int get_WiFiSSIDStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_multicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_multicast_packets*/
static int get_WiFiSSIDStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_multicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_broadcast_packets*/
static int get_WiFiSSIDStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_broadcast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_broadcast_packets*/
static int get_WiFiSSIDStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_broadcast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_packets*/
static int get_WiFiSSIDStats_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retrans_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.FailedRetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_fail_packets*/
static int get_WiFiSSIDStats_FailedRetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retrans_fail_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetryCount!UBUS:wifi.ap.@Name/stats//tx_retry_packets*/
static int get_WiFiSSIDStats_RetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retry_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MultipleRetryCount!UBUS:wifi.ap.@Name/stats//tx_multi_retry_packets*/
static int get_WiFiSSIDStats_MultipleRetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_multi_retry_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ACKFailureCount!UBUS:wifi.ap.@Name/stats//ack_fail_packets*/
static int get_WiFiSSIDStats_ACKFailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "ack_fail_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.AggregatedPacketCount!UBUS:wifi.ap.@Name/stats//aggregate_packets*/
static int get_WiFiSSIDStats_AggregatedPacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "aggregate_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unknown_packets*/
static int get_WiFiSSIDStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_unknown_packets", value);
}

static int get_WiFiAccessPointAssociatedDevice_Active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Noise!UBUS:wifi.ap.@Name/stations//stations[i-1].noise*/
static int get_WiFiAccessPointAssociatedDevice_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "noise");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.MACAddress!UBUS:wifi.ap.@Name/stations//stations[i-1].macaddr*/
static int get_WiFiAccessPointAssociatedDevice_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddr");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataDownlinkRate!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_rate_latest.rate*/
static int get_WiFiAccessPointAssociatedDevice_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *rate_mbps = dmjson_get_value((json_object *)data, 3, "stats", "rx_rate_latest", "rate");
	unsigned int rate_kbps = (rate_mbps && *rate_mbps != '\0') ? atoi(rate_mbps) * 1000 : 1000;

	dmasprintf(value, "%u", rate_kbps);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataUplinkRate!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_rate_latest.rate*/
static int get_WiFiAccessPointAssociatedDevice_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *rate_mbps = dmjson_get_value((json_object *)data, 3, "stats", "tx_rate_latest", "rate");
	unsigned int rate_kbps = (rate_mbps && *rate_mbps != '\0') ? atoi(rate_mbps) * 1000 : 1000;

	dmasprintf(value, "%u", rate_kbps);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.SignalStrength!UBUS:wifi.ap.@Name/stations//stations[i-1].rssi*/
static int get_WiFiAccessPointAssociatedDevice_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.AssociationTime!UBUS:wifi.ap.@Name/stations//stations[i-1].in_network*/
static int get_WiFiAccessPointAssociatedDevice_AssociationTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0001-01-01T00:00:00Z";

	char *in_network = dmjson_get_value((json_object *)data, 1, "in_network");
	if (in_network && *in_network != '\0' && atoi(in_network) > 0) {
		time_t t_time = time(NULL) - atoi(in_network);
		if (gmtime(&t_time) == NULL)
			return -1;

		char utc_time[32] = {0};

		if (strftime(utc_time, sizeof(utc_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t_time)) == 0)
			return -1;

		*value = dmstrdup(utc_time);
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_total_bytes*/
static int get_access_point_associative_device_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_total_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_data_bytes*/
static int get_access_point_associative_device_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_data_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_total_pkts*/
static int get_access_point_associative_device_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_total_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_data_pkts*/
static int get_access_point_associative_device_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_data_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_failures*/
static int get_access_point_associative_device_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_failures");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_pkts_retries*/
static int get_access_point_associative_device_statistics_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_pkts_retries");
	return 0;
}


/*#Device.WiFi.AccessPoint.{i}.Status!UBUS:wifi.ap.@Name/status//status*/
static int get_wifi_access_point_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char object[32], *status = NULL, *iface;

	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->config_section, "device", &iface);
	snprintf(object, sizeof(object), "wifi.ap.%s", iface);
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, status = "Error_Misconfigured");
	status = dmjson_get_value(res, 1, "status");

	if (strcmp(status, "running") == 0 || strcmp(status, "up") == 0)
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxBitRate!UBUS:wifi.radio.@Name/status//maxrate*/
static int get_radio_max_bit_rate (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "maxrate");
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedFrequencyBands!UBUS:wifi.radio.@Name/status//supp_bands*/
static int get_radio_supported_frequency_bands(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "2.4GHz,5GHz");
	*value = dmjson_get_value_array_all(res, ",", 1, "supp_bands");
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/status//band*/
static int get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "band");
	return 0;
}

static int set_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_frequency_bands = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedFrequencyBands, NULL))
				return FAULT_9007;

			// Get the list of all supported frequency bands
			get_radio_supported_frequency_bands(refparam, ctx, data, instance, &supported_frequency_bands);

			// Check if the input value is a supported band value
			if (!value_exits_in_str_list(supported_frequency_bands, ",", value))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "hwmode", (!strcmp(value, "5GHz") ? "11a" :"11g"));
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.ChannelsInUse!UCI:wireless/wifi-device,@i-1/channel*/
static int get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0') {
		char object[32];
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
		dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
		DM_ASSERT(res, *value = "1");
		*value = dmjson_get_value(res, 1, "channel");
	}
	return 0;
}

static int get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss = NULL;
	json_object *res = NULL, *neighboring_wifi_obj = NULL;
	char object[32];

	*value = "None";
	uci_foreach_sections("wireless", "wifi-device", ss) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(ss));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		DM_ASSERT(res, *value = "None");
		neighboring_wifi_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "accesspoints");
		if (neighboring_wifi_obj) {
			*value = "Complete";
			break;
		} else
			*value = "None";
	}
	return 0;
}

static int get_neighboring_wifi_diagnostics_result_number_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWifiNeighboringWiFiDiagnosticResultInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].ssid*/
static int get_neighboring_wifi_diagnostics_result_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ssid");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BSSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].bssid*/
static int get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "bssid");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Channel!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].channel*/
static int get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "channel");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SignalStrength!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].rssi*/
static int get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].band*/
static int get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "band");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Noise!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].noise*/
static int get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "noise");
	return 0;
}

/*#Device.WiFi.Radio.{i}.PossibleChannels!UBUS:wifi.radio.@Name/status//supp_channels[0].channels*/
static int get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL, *arrobj = NULL;
	char object[32], *cur_opclass = NULL;
	int i = 0;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	cur_opclass = dmjson_get_value(res, 1, "opclass");
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		char *opclass = dmjson_get_value(supp_channels, 1, "opclass");
		if (opclass && strcmp(opclass, cur_opclass) != 0)
			continue;

		*value = dmjson_get_value_array_all(supp_channels, ",", 1, "channels");
		break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth!UBUS:wifi.radio.@Name/status//bandwidth*/
static int get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "20MHz");
	dmasprintf(value, "%sMHz", dmjson_get_value(res, 1, "bandwidth"));
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedStandards!UBUS:wifi.radio.@Name/status//standard*/
static int get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *freq = get_radio_option_nocache(data, "band");
	*value = (freq && *freq == '5') ? "a,n,ac,ax" : "b,g,n,ax";
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingStandards!UBUS:wifi.radio.@Name/status//standard*/
static int get_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char standard_list[16] = { 0, 0 };
	char object[16];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "n,ax");
	char *standard = dmjson_get_value(res, 1, "standard");
	if (strstr(standard, "802.11")) {
		DM_STRNCPY(standard_list, standard + strlen("802.11"), sizeof(standard_list));
		replace_char(standard_list, '/', ',');
	}

	*value = dmstrdup(standard_list);
	return 0;
}

static int set_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_standards = NULL;
	char *curr_htmode = NULL;
	char *pch, *spch, *band;
	char htmode[8];
	char hwmode[8];
	int freq = 20;

	switch (action) {
			case VALUECHECK:
				if (dm_validate_string_list(value, -1, -1, -1, -1, -1, SupportedStandards, NULL))
					return FAULT_9007;

				// Get the list of all supported standards
				get_radio_supported_standard(refparam, ctx, data, instance, &supported_standards);

				// Check if the input value is a valid standard value
				for (pch = strtok_r(value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
					if (!value_exits_in_str_list(supported_standards, ",", pch))
						return FAULT_9007;
				}

				break;
			case VALUESET:
				dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", &curr_htmode);

				if (curr_htmode && *curr_htmode) {
					sscanf(curr_htmode, "%*[A-Z]%d", &freq);
					freq = !strcmp(curr_htmode, "NOHT") ? 20 : freq;
				}

				band = get_radio_option_nocache(data, "band");

				if (strcmp(band, "5GHz") == 0) {
					if (strstr(value, "ax"))
						snprintf(htmode, sizeof(htmode), "HE%d", freq);
					else if (strstr(value, "ac"))
						snprintf(htmode, sizeof(htmode), "VHT%d", freq);
					else if (strstr(value, "n"))
						snprintf(htmode, sizeof(htmode), "HT%d", (freq != 20 && freq != 40) ? 20 : freq);
					else
						snprintf(htmode, sizeof(htmode), "NOHT");

					snprintf(hwmode, sizeof(hwmode), "11a");
				} else {
					if (strstr(value, "ax")) {
						snprintf(htmode, sizeof(htmode), "HE%d", freq);
						snprintf(hwmode, sizeof(hwmode), "11g");
					} else if (strstr(value, "n")) {
						snprintf(htmode, sizeof(htmode), "HT%d", (freq != 20 && freq != 40) ? 20 : freq);
						snprintf(hwmode, sizeof(hwmode), "11g");
					} else if (strstr(value, "g")) {
						snprintf(htmode, sizeof(htmode), "NOHT");
						snprintf(hwmode, sizeof(hwmode), "11g");
					} else {
						snprintf(htmode, sizeof(htmode), "NOHT");
						snprintf(hwmode, sizeof(hwmode), "11b");
					}
				}

				dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "hwmode", hwmode);
				dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", htmode);
				break;
		}
		return 0;
}

static int get_access_point_total_associations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *assoclist = NULL, *arrobj = NULL;
	char object[32];
	int i = 0, entries = 0;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)data)->ifname);
	dmubus_call(object, "assoclist", UBUS_ARGS{}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, assoclist, i, 1, "assoclist") {
		entries++;
	}
	dmasprintf(value, "%d", entries);
	return 0;
}

static int get_WiFiDataElementsNetwork_option(const char *option, char **value)
{
	int i = 0;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, option);
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ID*/
static int get_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("ID", value);
}

static int set_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.TimeStamp*/
static int get_WiFiDataElementsNetwork_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("TimeStamp", value);
}

/*#Device.WiFi.DataElements.Network.ControllerID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ControllerID*/
static int get_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("ControllerID", value);
}

static int set_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.DeviceNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.NumberOfDevices*/
static int get_WiFiDataElementsNetwork_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i = 0;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "NumberOfDevices");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDevice_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ID");
	return 0;
}

#if 0
static int get_WiFiDataElementsNetworkDevice_MultiAPCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].CollectionInterval*/
static int get_WiFiDataElementsNetworkDevice_CollectionInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CollectionInterval");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].NumberOfRadios*/
static int get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfRadios");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ID*/
static int get_WiFiDataElementsNetworkDeviceRadio_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadio_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Noise*/
static int get_WiFiDataElementsNetworkDeviceRadio_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Utilization*/
static int get_WiFiDataElementsNetworkDeviceRadio_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Transmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Transmit*/
static int get_WiFiDataElementsNetworkDeviceRadio_Transmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Transmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveSelf!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ReceiveSelf*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ReceiveSelf");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveOther!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].RecieveOther*/
static int get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "RecieveOther");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfCurrOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfCurrOpClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfUnassocSta*/
static int get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfUnassocSta");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfBSS*/
static int get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfBSS");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfScanRes*/
static int get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int num_scanres = 0;
	json_object *scanres_arr = NULL;

	json_object_object_get_ex((json_object *)data, "ScanResultList", &scanres_arr);
	num_scanres = (scanres_arr) ? json_object_array_length(scanres_arr) : 0;

	dmasprintf(value, "%d", num_scanres);
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BackhaulSta.MACAddress*/
static int get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *backsta_obj = NULL;

	if (data) {
		json_object_object_get_ex((json_object *)data, "BackhaulSta", &backsta_obj);
		*value = (backsta_obj) ? dmjson_get_value(backsta_obj, 1, "MACAddress") : "";
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	*value = (caps_obj) ? dmjson_get_value(caps_obj, 1, "HTCapabilities") : "";

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	*value = (caps_obj) ? dmjson_get_value(caps_obj, 1, "VHTCapabilities") : "";

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	*value = (caps_obj) ? dmjson_get_value(caps_obj, 1, "HECapabilities") : "";

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.NumberOfOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	*value = (caps_obj) ? dmjson_get_value(caps_obj, 1, "NumberOfOpClass") : "0";

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

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BSSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].SSID*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Enabled*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.LastChange!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].LastChange*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastChange");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TimeStamp*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesSent*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesReceived*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBE!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBE*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBE");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBK!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBK*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBK");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersVI!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersVI*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVI");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersVO!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersVO*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVO");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberofSTA*/
static int get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberofSTA");
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

#if 0
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MeasurementReport!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Measurementreport*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Measurementreport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.NumberOfMeasureReports!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberOfMeasureReports*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfMeasureReports");
	return 0;
}

#if 0
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Hostname*/
static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Hostname");
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

static int get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsAssociationEventAssociationEventDataInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL, *assoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_data))
				*value = dmjson_get_value(assoc_data, 1, "BSSID");
		}
	}
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL, *assoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_data))
				*value = dmjson_get_value(assoc_data, 1, "MACAddress");
		}
	}
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL, *assoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_data))
				*value = dmjson_get_value(assoc_data, 1, "StatusCode");
		}
	}
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL, *assoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_data))
				*value = dmjson_get_value(assoc_data, 1, "HTCapabilities");
		}
	}
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL, *assoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_data))
				*value = dmjson_get_value(assoc_data, 1, "VHTCapabilities");
		}
	}
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL, *assoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			if (json_object_object_get_ex(assoc_ev, "AssocData", &assoc_data))
				*value = dmjson_get_value(assoc_data, 1, "HECapabilities");
		}
	}
	return 0;
}

static int get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *assoc_ev = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:AssociationEvent", &assoc_ev)) {
			*value = dmjson_get_value((json_object *)data, 1, "eventTime");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseWiFiDataElementsDisassociationEventDisassociationEventDataInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "BSSID");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "MACAddress");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "ReasonCode");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "BytesSent");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "BytesReceived");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "PacketsSent");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "PacketsReceived");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "ErrorsSent");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "ErrorsReceived");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL, *disassoc_data = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			if (json_object_object_get_ex(disassoc_ev, "DisassocData", &disassoc_data))
				*value = dmjson_get_value(disassoc_data, 1, "RetransCount");
		}
	}
	return 0;
}

static int get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *disassoc_ev = NULL;

	if (data) {
		if (json_object_object_get_ex((json_object *)data, "wfa-dataelements:DisassociationEvent", &disassoc_ev)) {
			*value = dmjson_get_value((json_object *)data, 1, "eventTime");
		}
	}
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_WiFi_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return !dmcmd_no_wait("/sbin/wifi", 2, "reload", "&") ? CMD_SUCCESS : CMD_FAIL;
}

static operation_args neighboring_wifi_diagnostic_args = {
	.out = (const char *[]) {
		"Status",
		"Result.{i}.Radio",
		"Result.{i}.SSID",
		"Result.{i}.BSSID",
		"Result.{i}.Mode",
		"Result.{i}.Channel",
		"Result.{i}.SignalStrength",
		"Result.{i}.SecurityModeEnabled",
		"Result.{i}.EncryptionMode",
		"Result.{i}.OperatingFrequencyBand",
		"Result.{i}.SupportedStandards",
		"Result.{i}.OperatingStandards",
		"Result.{i}.OperatingChannelBandwidth",
		"Result.{i}.BeaconPeriod",
		"Result.{i}.Noise",
		"Result.{i}.BasicDataTransferRates",
		"Result.{i}.SupportedDataTransferRates",
		"Result.{i}.DTIMPeriod",
		NULL
	}
};

static int get_operate_args_WiFi_NeighboringWiFiDiagnostic(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&neighboring_wifi_diagnostic_args;
	return 0;
}

static int operate_WiFi_NeighboringWiFiDiagnostic(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res = NULL;

	dmubus_call("wifi", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		json_object *radios = NULL, *arrobj = NULL;
		int i = 0;

		dmjson_foreach_obj_in_array(res, arrobj, radios, i, 1, "radios") {
			json_object *scan_res = NULL, *obj = NULL;
			char object[32] = {0};
			char *ssid[2] = {0};
			char *bssid[2] = {0};
			char *noise[2] = {0};
			char *channel[2] = {0};
			char *frequency[2] = {0};
			char *signal_strength[2] = {0};

			char *radio_name = dmjson_get_value(radios, 1, "name");
			snprintf(object, sizeof(object), "wifi.radio.%s", radio_name);
			dmubus_call_set(object, "scan", UBUS_ARGS{}, 0);
			sleep(2); // Wait for results to get populated in scanresults
			dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &scan_res);

			if (!scan_res)
				continue;

			if (!json_object_object_get_ex(scan_res,"accesspoints", &obj))
				continue;

			uint8_t len = obj ? json_object_array_length(obj) : 0;
			for (uint8_t j = 0; j < len; j++ ) {
				json_object *array_obj = json_object_array_get_idx(obj, j);
				ssid[1] = dmjson_get_value(array_obj, 1, "ssid");
				bssid[1] = dmjson_get_value(array_obj, 1, "bssid");
				channel[1] = dmjson_get_value(array_obj, 1, "channel");
				frequency[1] = dmjson_get_value(array_obj, 1, "band");
				signal_strength[1] = dmjson_get_value(array_obj, 1, "rssi");
				noise[1] = dmjson_get_value(array_obj, 1, "noise");

				dmasprintf(&ssid[0], "Result.%d.SSID", j);
				dmasprintf(&bssid[0], "Result.%d.BSSID", j);
				dmasprintf(&channel[0], "Result.%d.Channel", j);
				dmasprintf(&frequency[0], "Result.%d.OperatingFrequencyBand", j);
				dmasprintf(&signal_strength[0], "Result.%d.SignalStrength", j);
				dmasprintf(&noise[0], "Result.%d.Noise", j);

				add_list_parameter(ctx, ssid[0], ssid[1], DMT_TYPE[DMT_STRING], NULL);
				add_list_parameter(ctx, bssid[0], bssid[1], DMT_TYPE[DMT_STRING], NULL);
				add_list_parameter(ctx, channel[0], channel[1], DMT_TYPE[DMT_UNINT], NULL);
				add_list_parameter(ctx, frequency[0], frequency[1], DMT_TYPE[DMT_STRING], NULL);
				add_list_parameter(ctx, signal_strength[0], signal_strength[1], DMT_TYPE[DMT_INT], NULL);
				add_list_parameter(ctx, noise[0], noise[1], DMT_TYPE[DMT_INT], NULL);
			}
		}
	}

	return CMD_SUCCESS;
}

static int operate_WiFiAccessPointSecurity_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", "psk");
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", get_default_wpa_key());
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wps", "1");
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wps_pushbutton", "1");

	return CMD_SUCCESS;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.WiFi. *** */
DMOBJ tWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DataElements", &DMREAD, NULL, NULL, "ubus:wifi.dataelements.collector", NULL, NULL, NULL, tWiFiDataElementsObj, NULL, NULL, BBFDM_BOTH},
{"Radio", &DMREAD, NULL, NULL, NULL, browseWifiRadioInst, NULL, NULL, tWiFiRadioObj, tWiFiRadioParams, get_linker_Wifi_Radio, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"SSID", &DMWRITE, add_wifi_ssid, delete_wifi_iface, NULL, browseWifiSsidInst, NULL, NULL, tWiFiSSIDObj, tWiFiSSIDParams, get_linker_Wifi_Ssid, BBFDM_BOTH, LIST_KEY{"Name", "Alias", "BSSID", NULL}},
{"AccessPoint", &DMWRITE, add_wifi_accesspoint, delete_wifi_iface, NULL, browseWifiAccessPointInst, NULL, NULL, tWiFiAccessPointObj, tWiFiAccessPointParams, NULL, BBFDM_BOTH, LIST_KEY{"SSIDReference", "Alias", NULL}},
{"NeighboringWiFiDiagnostic", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticObj, tWiFiNeighboringWiFiDiagnosticParams, NULL, BBFDM_BOTH},
{"EndPoint", &DMWRITE, addObjWiFiEndPoint, delObjWiFiEndPoint, NULL, browseWiFiEndPointInst, NULL, NULL, tWiFiEndPointObj, tWiFiEndPointParams, NULL, BBFDM_BOTH, LIST_KEY{"SSIDReference", "Alias", NULL}},
{0}
};

DMLEAF tWiFiParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_RadioNumberOfEntries, NULL, BBFDM_BOTH},
{"SSIDNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_SSIDNumberOfEntries, NULL, BBFDM_BOTH},
{"AccessPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_AccessPointNumberOfEntries, NULL, BBFDM_BOTH},
{"EndPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_EndPointNumberOfEntries, NULL, BBFDM_BOTH},
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_WiFi_Reset, BBFDM_USP},
{"NeighboringWiFiDiagnostic()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFi_NeighboringWiFiDiagnostic, operate_WiFi_NeighboringWiFiDiagnostic, BBFDM_USP},
{0}
};

/* *** Device.WiFi.Radio.{i}. *** */
DMOBJ tWiFiRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiRadioStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_radio_alias, set_radio_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_radio_enable, set_radio_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_radio_status, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_WiFiRadio_LowerLayers, set_WiFiRadio_LowerLayers, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_WiFiRadio_Name, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMREAD, DMT_UNINT, get_radio_max_bit_rate, NULL, BBFDM_BOTH},
{"SupportedFrequencyBands", &DMREAD, DMT_STRING, get_radio_supported_frequency_bands, NULL, BBFDM_BOTH},
{"OperatingFrequencyBand", &DMWRITE, DMT_STRING, get_radio_frequency, set_radio_frequency, BBFDM_BOTH},
{"SupportedStandards", &DMREAD, DMT_STRING, get_radio_supported_standard, NULL, BBFDM_BOTH},
{"OperatingStandards", &DMWRITE, DMT_STRING, get_radio_operating_standard, set_radio_operating_standard, BBFDM_BOTH},
{"ChannelsInUse", &DMREAD, DMT_STRING, get_radio_channel, NULL, BBFDM_BOTH},
{"Channel", &DMWRITE, DMT_UNINT, get_radio_channel, set_radio_channel, BBFDM_BOTH},
{"AutoChannelEnable", &DMWRITE, DMT_BOOL, get_radio_auto_channel_enable, set_radio_auto_channel_enable, BBFDM_BOTH},
{"PossibleChannels", &DMREAD, DMT_STRING, get_radio_possible_channels, NULL, BBFDM_BOTH},
{"AutoChannelSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_AutoChannelSupported, NULL, BBFDM_BOTH},
{"AutoChannelRefreshPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_AutoChannelRefreshPeriod, set_WiFiRadio_AutoChannelRefreshPeriod, BBFDM_BOTH},
{"MaxSupportedAssociations", &DMREAD, DMT_UNINT, get_WiFiRadio_MaxSupportedAssociations, NULL, BBFDM_BOTH},
{"FragmentationThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_FragmentationThreshold, set_WiFiRadio_FragmentationThreshold, BBFDM_BOTH},
{"RTSThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_RTSThreshold, set_WiFiRadio_RTSThreshold, BBFDM_BOTH},
{"BeaconPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_BeaconPeriod, set_WiFiRadio_BeaconPeriod, BBFDM_BOTH},
{"DTIMPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_DTIMPeriod, set_WiFiRadio_DTIMPeriod, BBFDM_BOTH},
{"SupportedOperatingChannelBandwidths", &DMREAD, DMT_STRING, get_WiFiRadio_SupportedOperatingChannelBandwidths, NULL, BBFDM_BOTH},
{"OperatingChannelBandwidth", &DMWRITE, DMT_STRING, get_WiFiRadio_OperatingChannelBandwidth, set_WiFiRadio_OperatingChannelBandwidth, BBFDM_BOTH},
{"CurrentOperatingChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiRadio_CurrentOperatingChannelBandwidth, NULL, BBFDM_BOTH},
{"PreambleType", &DMWRITE, DMT_STRING, get_WiFiRadio_PreambleType, set_WiFiRadio_PreambleType, BBFDM_BOTH},
{"IEEE80211hSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_IEEE80211hSupported, NULL, BBFDM_BOTH},
{"IEEE80211hEnabled", &DMWRITE, DMT_BOOL, get_WiFiRadio_IEEE80211hEnabled, set_WiFiRadio_IEEE80211hEnabled, BBFDM_BOTH},
{"TransmitPower", &DMWRITE, DMT_INT, get_WiFiRadio_TransmitPower, set_WiFiRadio_TransmitPower, BBFDM_BOTH},
{"RegulatoryDomain", &DMWRITE, DMT_STRING, get_WiFiRadio_RegulatoryDomain, set_WiFiRadio_RegulatoryDomain, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.Radio.{i}.Stats. *** */
DMLEAF tWiFiRadioStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiRadioStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiRadioStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_WiFiRadioStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiRadioStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"FCSErrorCount", &DMREAD, DMT_UNINT, get_WiFiRadioStats_FCSErrorCount, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic. *** */
DMOBJ tWiFiNeighboringWiFiDiagnosticObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Result", &DMREAD, NULL, NULL, NULL, browseWifiNeighboringWiFiDiagnosticResultInst, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tWiFiNeighboringWiFiDiagnosticParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_neighboring_wifi_diagnostics_diagnostics_state, set_neighboring_wifi_diagnostics_diagnostics_state, BBFDM_CWMP},
{"ResultNumberOfEntries", &DMREAD, DMT_UNINT, get_neighboring_wifi_diagnostics_result_number_entries, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}. *** */
DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SSID", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_ssid, NULL, BBFDM_CWMP},
{"BSSID", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_bssid, NULL, BBFDM_CWMP},
{"Channel", &DMREAD, DMT_UNINT, get_neighboring_wifi_diagnostics_result_channel, NULL, BBFDM_CWMP},
{"SignalStrength", &DMREAD, DMT_INT, get_neighboring_wifi_diagnostics_result_signal_strength, NULL, BBFDM_CWMP},
{"OperatingFrequencyBand", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_operating_frequency_band, NULL, BBFDM_CWMP},
{"Noise", &DMREAD, DMT_INT, get_neighboring_wifi_diagnostics_result_noise, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.SSID.{i}. *** */
DMOBJ tWiFiSSIDObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiSSIDStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiSSIDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_ssid_alias, set_ssid_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_wifi_enable, set_wifi_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_wifi_status, NULL, BBFDM_BOTH},
{"SSID", &DMWRITE, DMT_STRING, get_wlan_ssid, set_wlan_ssid, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING,  get_wlan_name, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ssid_lower_layer, set_ssid_lower_layer, BBFDM_BOTH},
{"BSSID", &DMREAD, DMT_STRING, get_wlan_bssid, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiSSID_MACAddress, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.SSID.{i}.Stats. *** */
DMLEAF tWiFiSSIDStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ErrorsSent, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_RetransCount, NULL, BBFDM_BOTH},
{"FailedRetransCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_FailedRetransCount, NULL, BBFDM_BOTH},
{"RetryCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_RetryCount, NULL, BBFDM_BOTH},
{"MultipleRetryCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_MultipleRetryCount, NULL, BBFDM_BOTH},
{"ACKFailureCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ACKFailureCount, NULL, BBFDM_BOTH},
{"AggregatedPacketCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_AggregatedPacketCount, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}. *** */
DMOBJ tWiFiAccessPointObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Security", &DMWRITE, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointSecurityParams, NULL, BBFDM_BOTH},
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_wifi_associated_device, NULL, NULL, tWiFiAccessPointAssociatedDeviceObj, tWiFiAccessPointAssociatedDeviceParams, get_linker_associated_device, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointWPSParams, NULL, BBFDM_BOTH},
{"Accounting", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAccountingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_access_point_alias, set_access_point_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL,  get_wifi_enable, set_wifi_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_wifi_access_point_status, NULL, BBFDM_BOTH},
{"SSIDReference", &DMWRITE, DMT_STRING, get_ap_ssid_ref, set_ap_ssid_ref, BBFDM_BOTH},
{"SSIDAdvertisementEnabled", &DMWRITE, DMT_BOOL, get_wlan_ssid_advertisement_enable, set_wlan_ssid_advertisement_enable, BBFDM_BOTH},
{"WMMEnable", &DMWRITE, DMT_BOOL, get_wmm_enabled, set_wmm_enabled, BBFDM_BOTH},
{"UAPSDEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_UAPSDEnable, set_WiFiAccessPoint_UAPSDEnable, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_access_point_total_associations, NULL, BBFDM_BOTH},
{"MACAddressControlEnabled", &DMWRITE, DMT_BOOL, get_access_point_control_enable, set_access_point_control_enable, BBFDM_BOTH},
{"UAPSDCapability", &DMREAD, DMT_BOOL, get_WiFiAccessPoint_UAPSDCapability, NULL, BBFDM_BOTH},
{"WMMCapability", &DMREAD, DMT_BOOL, get_WiFiAccessPoint_WMMCapability, NULL, BBFDM_BOTH},
{"MaxAllowedAssociations", &DMWRITE, DMT_UNINT, get_WiFiAccessPoint_MaxAllowedAssociations, set_WiFiAccessPoint_MaxAllowedAssociations, BBFDM_BOTH},
{"IsolationEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_IsolationEnable, set_WiFiAccessPoint_IsolationEnable, BBFDM_BOTH},
{"AllowedMACAddress", &DMWRITE, DMT_STRING, get_WiFiAccessPoint_AllowedMACAddress, set_WiFiAccessPoint_AllowedMACAddress, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.Security. *** */
DMLEAF tWiFiAccessPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ModesSupported", &DMREAD, DMT_STRING, get_access_point_security_supported_modes, NULL, BBFDM_BOTH},
{"ModeEnabled", &DMWRITE, DMT_STRING, get_access_point_security_modes, set_access_point_security_modes, BBFDM_BOTH},
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_wepkey, BBFDM_BOTH},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_shared_key, BBFDM_BOTH},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_passphrase, BBFDM_BOTH},
{"RekeyingInterval", &DMWRITE, DMT_UNINT, get_access_point_security_rekey_interval, set_access_point_security_rekey_interval, BBFDM_BOTH},
{"SAEPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointSecurity_SAEPassphrase, BBFDM_BOTH},
{"RadiusServerIPAddr", &DMWRITE, DMT_STRING, get_access_point_security_radius_ip_address, set_access_point_security_radius_ip_address, BBFDM_BOTH},
{"RadiusServerPort", &DMWRITE, DMT_UNINT, get_access_point_security_radius_server_port, set_access_point_security_radius_server_port, BBFDM_BOTH},
{"RadiusSecret", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_radius_secret, BBFDM_BOTH},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiAccessPointSecurity_MFPConfig, set_WiFiAccessPointSecurity_MFPConfig, BBFDM_BOTH},
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_WiFiAccessPointSecurity_Reset, BBFDM_USP},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.WPS. *** */
DMLEAF tWiFiAccessPointWPSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiAccessPointWPS_Enable, set_WiFiAccessPointWPS_Enable, BBFDM_BOTH},
{"ConfigMethodsSupported", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_ConfigMethodsSupported, NULL, BBFDM_BOTH},
{"ConfigMethodsEnabled", &DMWRITE, DMT_STRING, get_WiFiAccessPointWPS_ConfigMethodsEnabled, set_WiFiAccessPointWPS_ConfigMethodsEnabled, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Status, NULL, BBFDM_BOTH},
//{"Version", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Version, NULL, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointWPS_PIN, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}. *** */
DMOBJ tWiFiAccessPointAssociatedDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAssociatedDeviceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointAssociatedDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Active", &DMREAD, DMT_BOOL, get_WiFiAccessPointAssociatedDevice_Active, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_INT, get_WiFiAccessPointAssociatedDevice_Noise, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiAccessPointAssociatedDevice_MACAddress, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_LastDataDownlinkRate, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_LastDataUplinkRate, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_INT, get_WiFiAccessPointAssociatedDevice_SignalStrength, NULL, BBFDM_BOTH},
//{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_Retransmissions, NULL, BBFDM_BOTH},
{"AssociationTime", &DMREAD, DMT_TIME, get_WiFiAccessPointAssociatedDevice_AssociationTime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats. *** */
DMLEAF tWiFiAccessPointAssociatedDeviceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_tx_bytes, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_rx_bytes, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_tx_packets, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_rx_packets, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_tx_errors, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_retrans_count, NULL, BBFDM_BOTH},
//{"FailedRetransCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_failed_retrans_count, NULL, BBFDM_BOTH},
//{"RetryCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_retry_count, NULL, BBFDM_BOTH},
//{"MultipleRetryCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_multiple_retry_count, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.Accounting. *** */
DMLEAF tWiFiAccessPointAccountingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_WiFiAccessPointAccounting_Enable, set_WiFiAccessPointAccounting_Enable, BBFDM_BOTH},
{"ServerIPAddr", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_ServerIPAddr, set_WiFiAccessPointAccounting_ServerIPAddr, BBFDM_BOTH},
//{"SecondaryServerIPAddr", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondaryServerIPAddr, set_WiFiAccessPointAccounting_SecondaryServerIPAddr, BBFDM_BOTH},
{"ServerPort", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_ServerPort, set_WiFiAccessPointAccounting_ServerPort, BBFDM_BOTH},
//{"SecondaryServerPort", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_SecondaryServerPort, set_WiFiAccessPointAccounting_SecondaryServerPort, BBFDM_BOTH},
{"Secret", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointAccounting_Secret, BBFDM_BOTH},
//{"SecondarySecret", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondarySecret, set_WiFiAccessPointAccounting_SecondarySecret, BBFDM_BOTH},
//{"InterimInterval", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_InterimInterval, set_WiFiAccessPointAccounting_InterimInterval, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}. *** */
DMOBJ tWiFiEndPointObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointSecurityParams, NULL, BBFDM_BOTH},
{"Profile", &DMREAD, NULL, NULL, NULL, browseWiFiEndPointProfileInst, NULL, NULL, tWiFiEndPointProfileObj, tWiFiEndPointProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "SSID", "Location", "Priority", NULL}},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointWPSParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiEndPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPoint_Enable, set_WiFiEndPoint_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPoint_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPoint_Alias, set_WiFiEndPoint_Alias, BBFDM_BOTH},
//{"ProfileReference", &DMWRITE, DMT_STRING, get_WiFiEndPoint_ProfileReference, set_WiFiEndPoint_ProfileReference, BBFDM_BOTH},
{"SSIDReference", &DMREAD, DMT_STRING, get_WiFiEndPoint_SSIDReference, NULL, BBFDM_BOTH},
//{"ProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiEndPoint_ProfileNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Security. *** */
DMLEAF tWiFiEndPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ModesSupported", &DMREAD, DMT_STRING, get_WiFiEndPointSecurity_ModesSupported, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}. *** */
DMOBJ tWiFiEndPointProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointProfileSecurityParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiEndPointProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointProfile_Enable, set_WiFiEndPointProfile_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointProfile_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Alias, set_WiFiEndPointProfile_Alias, BBFDM_BOTH},
{"SSID", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_SSID, set_WiFiEndPointProfile_SSID, BBFDM_BOTH},
//{"Location", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Location, set_WiFiEndPointProfile_Location, BBFDM_BOTH},
//{"Priority", &DMWRITE, DMT_UNINT, get_WiFiEndPointProfile_Priority, set_WiFiEndPointProfile_Priority, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}.Security. *** */
DMLEAF tWiFiEndPointProfileSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ModeEnabled", &DMWRITE, DMT_STRING, get_WiFiEndPointProfileSecurity_ModeEnabled, set_WiFiEndPointProfileSecurity_ModeEnabled, BBFDM_BOTH},
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_WiFiEndPointProfileSecurity_WEPKey, BBFDM_BOTH},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_WiFiEndPointProfileSecurity_PreSharedKey, BBFDM_BOTH},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiEndPointProfileSecurity_KeyPassphrase, BBFDM_BOTH},
{"SAEPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiEndPointProfileSecurity_SAEPassphrase, BBFDM_BOTH},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiEndPointProfileSecurity_MFPConfig, set_WiFiEndPointProfileSecurity_MFPConfig, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.WPS. *** */
DMLEAF tWiFiEndPointWPSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointWPS_Enable, set_WiFiEndPointWPS_Enable, BBFDM_BOTH},
{"ConfigMethodsSupported", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_ConfigMethodsSupported, NULL, BBFDM_BOTH},
{"ConfigMethodsEnabled", &DMWRITE, DMT_STRING, get_WiFiEndPointWPS_ConfigMethodsEnabled, set_WiFiEndPointWPS_ConfigMethodsEnabled, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Status, NULL, BBFDM_BOTH},
//{"Version", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Version, NULL, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_UNINT, get_WiFiEndPointWPS_PIN, set_WiFiEndPointWPS_PIN, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements. *** */
DMOBJ tWiFiDataElementsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Network", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkObj, tWiFiDataElementsNetworkParams, NULL, BBFDM_BOTH},
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventObj, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventObj, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network. *** */
DMOBJ tWiFiDataElementsNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceInst, NULL, NULL, tWiFiDataElementsNetworkDeviceObj, tWiFiDataElementsNetworkDeviceParams, NULL, BBFDM_BOTH, LIST_KEY{"ID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ID", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetwork_ID, set_WiFiDataElementsNetwork_ID, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_TimeStamp, NULL, BBFDM_BOTH},
{"ControllerID", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetwork_ControllerID, set_WiFiDataElementsNetwork_ControllerID, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetwork_DeviceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Radio", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioObj, tWiFiDataElementsNetworkDeviceRadioParams, NULL, BBFDM_BOTH, LIST_KEY{"ID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ID, NULL, BBFDM_BOTH},
//{"MultiAPCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDevice_MultiAPCapabilities, NULL, BBFDM_BOTH},
{"CollectionInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_CollectionInterval, NULL, BBFDM_BOTH},
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"BackhaulSta", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams, NULL, BBFDM_BOTH},
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj, tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}},
{"BSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSObj, tWiFiDataElementsNetworkDeviceRadioBSSParams, NULL, BBFDM_BOTH, LIST_KEY{"BSSID", NULL}},
{"ScanResult", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultObj, tWiFiDataElementsNetworkDeviceRadioScanResultParams, NULL, BBFDM_BOTH},
{"UnassociatedSTA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ID", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadio_ID, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_Enabled, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Noise, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Utilization, NULL, BBFDM_BOTH},
{"Transmit", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Transmit, NULL, BBFDM_BOTH},
{"ReceiveSelf", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf, NULL, BBFDM_BOTH},
{"ReceiveOther", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
{"UnassociatedSTANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries, NULL, BBFDM_BOTH},
{"BSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries, NULL, BBFDM_BOTH},
{"ScanResultNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"CapableOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities, NULL, BBFDM_BOTH},
{"CapableOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class, NULL, BBFDM_BOTH},
{"MaxTxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower, NULL, BBFDM_BOTH},
{"NonOperable", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable, NULL, BBFDM_BOTH},
{"NumberOfNonOperChan", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class, NULL, BBFDM_BOTH},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel, NULL, BBFDM_BOTH},
{"TxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"STA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID, NULL, BBFDM_BOTH},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_SSID, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp, NULL, BBFDM_BOTH},
{"UnicastBytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent, NULL, BBFDM_BOTH},
{"UnicastBytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived, NULL, BBFDM_BOTH},
{"MulticastBytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent, NULL, BBFDM_BOTH},
{"MulticastBytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived, NULL, BBFDM_BOTH},
{"BroadcastBytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent, NULL, BBFDM_BOTH},
{"BroadcastBytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived, NULL, BBFDM_BOTH},
{"EstServiceParametersBE", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE, NULL, BBFDM_BOTH},
{"EstServiceParametersBK", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK, NULL, BBFDM_BOTH},
{"EstServiceParametersVI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI, NULL, BBFDM_BOTH},
{"EstServiceParametersVO", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO, NULL, BBFDM_BOTH},
{"STANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate, NULL, BBFDM_BOTH},
{"UtilizationReceive", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive, NULL, BBFDM_BOTH},
{"UtilizationTransmit", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit, NULL, BBFDM_BOTH},
{"EstMACDataRateDownlink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink, NULL, BBFDM_BOTH},
{"EstMACDataRateUplink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength, NULL, BBFDM_BOTH},
{"LastConnectTime", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived, NULL, BBFDM_BOTH},
//{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount, NULL, BBFDM_BOTH},
{"MeasurementReport", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport, NULL, BBFDM_BOTH},
{"NumberOfMeasureReports", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports, NULL, BBFDM_BOTH},
//{"IPV4Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address, NULL, BBFDM_BOTH},
//{"IPV6Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address, NULL, BBFDM_BOTH},
{"Hostname", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"OpClassScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams, NULL, BBFDM_BOTH, LIST_KEY{"OperatingClass", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp, NULL, BBFDM_BOTH},
{"OpClassScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"ChannelScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams, NULL, BBFDM_BOTH, LIST_KEY{"Channel", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"OperatingClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass, NULL, BBFDM_BOTH},
{"ChannelScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"NeighborBSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams, NULL, BBFDM_BOTH, LIST_KEY{"BSSID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise, NULL, BBFDM_BOTH},
{"NeighborBSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID, NULL, BBFDM_BOTH},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength, NULL, BBFDM_BOTH},
{"ChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth, NULL, BBFDM_BOTH},
{"ChannelUtilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization, NULL, BBFDM_BOTH},
{"StationCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent. *** */
DMOBJ tWiFiDataElementsAssociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"AssociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsAssociationEventAssociationEventDataInst, NULL, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"AssociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_BSSID, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress, NULL, BBFDM_BOTH},
{"StatusCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent. *** */
DMOBJ tWiFiDataElementsDisassociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DisassociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsDisassociationEventDisassociationEventDataInst, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventDisassociationEventDataParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsDisassociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DisassociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress, NULL, BBFDM_BOTH},
{"ReasonCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp, NULL, BBFDM_BOTH},
{0}
};
