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

#include "wifi.h"

struct wifi_radio_args
{
	struct dmmap_dup *sections;
};

struct wifi_ssid_args
{
	struct dmmap_dup *sections;
	char *ifname;
	char *linker;
};

struct wifi_acp_args
{
	struct dmmap_dup *sections;
	char *ifname;
};

struct wifi_enp_args
{
	struct dmmap_dup *sections;
	char *ifname;
};

struct wifi_data_element_args
{
	struct dmmap_dup *uci_s;
	struct json_object *dump_obj;
	struct json_object *dump2_obj;
};

struct wifi_event_args
{
	struct json_object *event_obj;
	char *event_time;
};


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

static int get_linker_Wifi_AccessPoint(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = (data && ((struct wifi_acp_args *)data)->ifname) ? ((struct wifi_acp_args *)data)->ifname : "";
	return 0;
}

static int get_linker_associated_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? dmjson_get_value((json_object *)data, 1, "macaddr") : "";
	return 0;
}

static int get_linker_wfdata_Device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? section_name((((struct wifi_data_element_args *)data)->uci_s)->config_section) : "";
	return 0;
}

static int get_linker_wfdata_BSS_STA(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? dmjson_get_value((json_object *)data, 1, "MACAddress") : "";
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
static char *get_radio_option_nocache(const char *device_name, char *option)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", device_name);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);

	return (res) ? dmjson_get_value(res, 1, option) : "";
}

static char *get_data_model_mode(const char *ubus_mode)
{
	if (DM_LSTRCMP(ubus_mode, "WEP64") == 0)
		return "WEP-64";
	else if (DM_LSTRCMP(ubus_mode, "WEP128") == 0)
		return "WEP-128";
	else if (DM_LSTRCMP(ubus_mode, "WPAPSK") == 0)
		return "WPA-Personal";
	else if (DM_LSTRCMP(ubus_mode, "WPA2PSK") == 0)
		return "WPA2-Personal";
	else if (DM_LSTRCMP(ubus_mode, "WPA3PSK") == 0)
		return "WPA3-Personal";
	else if (DM_LSTRCMP(ubus_mode, "WPAPSK+WPA2PSK") == 0)
		return "WPA-WPA2-Personal";
	else if (DM_LSTRCMP(ubus_mode, "WPA2PSK+WPA3PSK") == 0)
		return "WPA3-Personal-Transition";
	else if (DM_LSTRCMP(ubus_mode, "WPA") == 0)
		return "WPA-Enterprise";
	else if (DM_LSTRCMP(ubus_mode, "WPA2") == 0)
		return "WPA2-Enterprise";
	else if (DM_LSTRCMP(ubus_mode, "WPA3") == 0)
		return "WPA3-Enterprise";
	else if (DM_LSTRCMP(ubus_mode, "WPA+WPA2") == 0)
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = dm_default_modes_supported);

	list_modes[0] = 0;
	dmjson_foreach_value_in_array(res, supported_modes, mode, idx, 1, "supp_security") {
		if (!DM_STRSTR(dm_wifi_driver_modes_supported, mode))
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
	char *ptrch = NULL;

	dmuci_get_value_by_section_string(section, "encryption", &encryption);
	if (!encryption || *encryption == '\0')
		return "None";

	/*Here the encryption type and the cipher are seperated*/
	ptrch  = DM_STRCHR(encryption, '+');
	if (ptrch)
		*ptrch = '\0';

	if (DM_LSTRSTR(encryption, "wep")) {
		char *key_index = NULL, *key = NULL;

		dmuci_get_value_by_section_string(section, "key", &key_index);
		if (key_index && (*key_index) > '0' && (*key_index) < '5' && *(key_index+1) == '\0') {
			char buf[16];

			snprintf(buf, sizeof(buf), "key%s", key_index);
			dmuci_get_value_by_section_string(section, buf, &key);
		}
		return (key && DM_STRLEN(key) == 10) ? "WEP-64" : "WEP-128";
	}
	else if (DM_LSTRNCMP(encryption, "psk-mixed", 9) == 0)
		return "WPA-WPA2-Personal";
	else if (DM_LSTRNCMP(encryption, "psk2", 4) == 0)
		return "WPA2-Personal";
	else if (DM_LSTRNCMP(encryption, "psk", 3) == 0)
		return "WPA-Personal";
	else if (DM_LSTRCMP(encryption, "sae") == 0)
		return "WPA3-Personal";
	else if (DM_LSTRCMP(encryption, "sae-mixed") == 0)
		return "WPA3-Personal-Transition";
	else if (DM_LSTRNCMP(encryption, "wpa-mixed", 9) == 0)
		return "WPA-WPA2-Enterprise";
	else if (DM_LSTRNCMP(encryption, "wpa2", 4) == 0)
		return "WPA2-Enterprise";
	else if (DM_LSTRNCMP(encryption, "wpa3", 4) == 0)
		return "WPA3-Enterprise";
	else if (DM_LSTRNCMP(encryption, "wpa", 3) == 0)
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
	dmubus_call_set(object, "scan", UBUS_ARGS{0}, 0);
}

struct uci_section *find_mapcontroller_ssid_section(struct uci_section *wireless_ssid_s)
{
	struct uci_section *s = NULL;
	char *multi_ap = NULL;
	char *device = NULL;
	char *ssid = NULL;
	char *band = NULL;

	if (!file_exists("/etc/config/mapcontroller"))
		return NULL;

	dmuci_get_value_by_section_string(wireless_ssid_s, "multi_ap", &multi_ap);
	if (DM_LSTRCMP(multi_ap, "2") != 0)
		return NULL;

	dmuci_get_value_by_section_string(wireless_ssid_s, "ssid", &ssid);
	dmuci_get_value_by_section_string(wireless_ssid_s, "device", &device);
	band = get_radio_option_nocache(device, "band");

	uci_foreach_option_eq("mapcontroller", "ap", "type", "fronthaul", s) {
		char *curr_ssid = NULL;
		char *curr_band = NULL;

		dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
		dmuci_get_value_by_section_string(s, "band", &curr_band);

		if (DM_STRCMP(curr_ssid, ssid) == 0 &&
			curr_band[0] == band[0]) {
			return s;
		}
	}

	return NULL;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_wifi = NULL;
	char ssid[32] = {0}, s_name[32] = {0};

	snprintf(ssid, sizeof(ssid), "iopsys_ssid_%s", *instance);
	snprintf(s_name, sizeof(s_name), "wlan_ssid_%s", *instance);

	dmuci_add_section("wireless", "wifi-iface", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_wifi, "ssid_added_by_user", "1");
	dmuci_set_value_by_section(dmmap_wifi, "ifname", ssid);
	dmuci_set_value_by_section(dmmap_wifi, "ssidinstance", *instance);
	return 0;
}

static int delete_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *ssid_s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((((struct wifi_ssid_args *)data)->sections)->dmmap_section, NULL, NULL);
			dmuci_delete_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("wireless", "wifi-iface", stmp, ssid_s) {
				struct uci_section *dmmap_section = NULL;
				char *added_by_user;

				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ssid_s), &dmmap_section);
				dmuci_get_value_by_section_string(dmmap_section, "ap_added_by_user", &added_by_user);
				if (DM_LSTRCMP(added_by_user, "1") == 0)
					continue;

				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(ssid_s, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int add_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_wifi = NULL;
	char ssid[32] = {0}, s_name[32] = {0};

	snprintf(ssid, sizeof(ssid), "iopsys_ap_%s", *instance);
	snprintf(s_name, sizeof(s_name), "wlan_ap_%s", *instance);

	dmuci_add_section("wireless", "wifi-iface", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_wifi, "ap_added_by_user", "1");
	dmuci_set_value_by_section(dmmap_wifi, "ap_instance", *instance);
	return 0;
}

static int delete_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *ap_s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((((struct wifi_ssid_args *)data)->sections)->dmmap_section, NULL, NULL);
			dmuci_delete_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("wireless", "wifi-iface", stmp, ap_s) {
				struct uci_section *dmmap_section = NULL;
				char *added_by_user;

				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ap_s), &dmmap_section);
				dmuci_get_value_by_section_string(dmmap_section, "ssid_added_by_user", &added_by_user);
				if (DM_LSTRCMP(added_by_user, "1") == 0)
					continue;

				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(ap_s, NULL, NULL);
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
			if (DM_LSTRCMP(mode, "sta") != 0)
				continue;

			dmuci_set_value_by_section(s, "mode", "");

			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(s), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "endpointinstance", "");
		}
	}
	return 0;
}

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

		if (*ifname == '\0') {
			char *added_by_user;

			dmuci_get_value_by_section_string(p->dmmap_section, "ap_added_by_user", &added_by_user);
			if (DM_LSTRCMP(added_by_user, "1") == 0)
				continue;

			dmuci_get_value_by_section_string(p->dmmap_section, "ifname", &ifname);
		}

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
	struct wifi_acp_args curr_wifi_acp_args = {0};
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *mode, *ifname, *added_by_user;

		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if (DM_LSTRCMP(mode, "ap") != 0)
			continue;

		dmuci_get_value_by_section_string(p->dmmap_section, "ssid_added_by_user", &added_by_user);
		if (DM_LSTRCMP(added_by_user, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		if (*ifname == '\0')
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
		if (DM_LSTRCMP(mode, "sta") != 0)
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

	DM_LINK_INST_OBJ(dmctx, parent_node, ep_args->sections->config_section, "1");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.!UBUS:wifi.radio.@Name/scanresults//accesspoints*/
static int browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	json_object *res = NULL, *accesspoints = NULL, *arrobj = NULL;
	char object[32], *inst = NULL;
	int id = 0, i;

	uci_foreach_sections("wireless", "wifi-device", s) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(s));
		dmubus_call(object, "scanresults", UBUS_ARGS{0}, 0, &res);
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
	dmubus_call(object, "stations", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, stations, i, 1, "stations") {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)stations, inst) == DM_STOP)
			return 0;
	}
	return 0;
}

static int browseWiFiDataElementsNetworkSSIDInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("mapcontroller", "ap", "dmmap_mapcontroller", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *type = NULL;
		char *enabled = NULL;
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

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "wifi_da_ssid_instance", "wifi_da_ssid_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static json_object *find_device_object(char *method_name, const char *unique_key)
{
	json_object *data_arr = NULL;
	json_object *data_obj = NULL;
	json_object *res = NULL;
	int i = 0;

	dmubus_call("wifi.dataelements.collector", method_name, UBUS_ARGS{0}, 0, &res);
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

static json_object *find_radio_object(json_object *device_obj, const char *unique_key)
{
	json_object *radio_arr = NULL;
	json_object *radio_obj = NULL;
	int i = 0;

	dmjson_foreach_obj_in_array(device_obj, radio_arr, radio_obj, i, 1, "RadioList") {

		char mac[32] = {0};
		char *id = dmjson_get_value(radio_obj, 1, "ID");
		char *str = base64_decode(id);
		string_to_mac(str, DM_STRLEN(str), mac, sizeof(mac));
		if (DM_STRCMP(unique_key, mac) == 0)
			return radio_obj;
	}

	return NULL;
}

static int browseWiFiDataElementsNetworkDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_data_element_args wifi_da_device_args = {0};
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("mapcontroller", "node", "dmmap_mapcontroller", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *key = NULL;

		dmuci_get_value_by_section_string(p->config_section, "agent_id", &key);
		if (!key || *key == '\0')
			continue;

		wifi_da_device_args.uci_s = p;
		wifi_da_device_args.dump_obj = find_device_object("dump", key);
		wifi_da_device_args.dump2_obj = find_device_object("dump2", key);

		if (wifi_da_device_args.dump_obj == NULL && wifi_da_device_args.dump2_obj == NULL)
			continue;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "wifi_da_device_instance", "wifi_da_device_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&wifi_da_device_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceDefault8021QInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceSSIDtoVIDMappingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_device_dump2 = ((struct wifi_data_element_args *)prev_data)->dump2_obj;
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

static int browseWiFiDataElementsNetworkDeviceRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_data_element_args *wifi_da_device = (struct wifi_data_element_args *)prev_data;
	struct wifi_data_element_args wifi_da_radio_args = {0};
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *agent_id = NULL;
	LIST_HEAD(dup_list);

	dmuci_get_value_by_section_string(wifi_da_device->uci_s->config_section, "agent_id", &agent_id);

	synchronize_specific_config_sections_with_dmmap_eq("mapcontroller", "radio", "dmmap_mapcontroller", "agent_id", agent_id, &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *key = NULL;

		dmuci_get_value_by_section_string(p->config_section, "macaddr", &key);
		if (!key || *key == '\0')
			continue;

		wifi_da_radio_args.uci_s = p;
		wifi_da_radio_args.dump_obj = find_radio_object(wifi_da_device->dump_obj, key);
		wifi_da_radio_args.dump2_obj = find_radio_object(wifi_da_device->dump2_obj, key);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "wifi_da_device_instance", "wifi_da_device_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&wifi_da_radio_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
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
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump2_obj;
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
*/

static int browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump_obj;
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array(wifi_da_radio, opclass_arr, opclass_obj, i, 2, "Capabilites", "OperatingClasses") {
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

/*
static int browseWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump2_obj;
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
	json_object *wifi_da_radio = ((struct wifi_data_element_args *)prev_data)->dump2_obj;
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

static int browseWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *wifi_da_device = ((struct wifi_data_element_args *)prev_data)->dump2_obj;
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
	struct uci_section *map_ssid_s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			// mapcontroller config: Update the corresponding fronthaul ssid section if exist
			map_ssid_s = find_mapcontroller_ssid_section((((struct wifi_ssid_args *)data)->sections)->config_section);
			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "ssid", value);

			// wireless config: Update ssid option
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
	struct uci_section *s = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//Here need to loop the iface and match the section name then add the dtim_period on each section
			//as this param is read by mac80211.sh script and is overwriten as 2 if not written in all section
			//of radio
			uci_foreach_option_eq("wireless", "wifi-iface", "device", section_name((((struct wifi_radio_args *)data)->sections)->config_section), s) {
				char *mode;

				dmuci_get_value_by_section_string(s, "mode", &mode);

				if (DM_LSTRCMP(mode, "ap") != 0)
					continue;

				dmuci_set_value_by_section(s, "dtim_period", value);
			}

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
		dmasprintf(value, "%dMHz", !DM_LSTRCMP(htmode, "NOHT") ? 20 : freq);
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "Auto");

	bandwidth_list[0] = 0;
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		char *bandwidth = dmjson_get_value(supp_channels, 1, "bandwidth");
		if (bandwidth && !strstr(bandwidth_list, !DM_LSTRCMP(bandwidth, "8080") ? "80+80" : !DM_LSTRCMP(bandwidth, "80") ? ",80MHz" : bandwidth)) {
			pos += snprintf(&bandwidth_list[pos], sizeof(bandwidth_list) - pos, "%sMHz,", !DM_LSTRCMP(bandwidth, "8080") ? "80+80" : bandwidth);
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

			if (DM_LSTRNCMP(curr_htmode, "VHT", 3) == 0)
				snprintf(htmode, sizeof(htmode), "VHT%d", freq);
			else if (DM_LSTRNCMP(curr_htmode, "HT", 2) == 0 && (freq == 20 || freq == 40))
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
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "short_preamble", (DM_LSTRCMP(value, "short") == 0) ? "1" : "0");
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
	if (DM_LSTRCMP(*value, "auto") == 0 || (*value)[0] == '\0')
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
				value = get_radio_option_nocache(section_name((((struct wifi_radio_args *)data)->sections)->config_section), "channel");

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
	if (macfilter[0] == 0 || DM_LSTRCMP(macfilter, "deny") == 0 || DM_LSTRCMP(macfilter, "disable") == 0)
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
		if (DM_STRSTR(security_modes[i], mode1)) {
			g1 = i;
		}

		if (DM_STRSTR(security_modes[i], mode2)) {
			g2 = i;
		}
	}

	return (g1 != g2);

}

static void set_security_mode(struct uci_section *section, char *value, bool is_endpoint)
{
	struct uci_section *map_ssid_s = NULL;
	char *wpa_key = NULL;
	char *mode = get_security_mode(section);

	// mapcontroller config: find the corresponding fronthaul ssid section if exist
	if (!is_endpoint)
		map_ssid_s = find_mapcontroller_ssid_section(section);

	// Use default key only in case the key is not set
	dmuci_get_value_by_section_string(section, "key", &wpa_key);
	if (DM_STRLEN(wpa_key) == 0)
		wpa_key = get_default_wpa_key();

	if (mode && DM_STRCMP(value, mode) != 0) {
		// Only reset the wlan key section if its belongs to different group
		if (is_different_group(value, mode))
			reset_wlan(section);
		dmuci_set_value_by_section(section, "ieee80211w", "0");

		if (DM_LSTRCMP(value, "None") == 0) {
			dmuci_set_value_by_section(section, "encryption", "none");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "none");
		} else if (DM_LSTRCMP(value, "WEP-64") == 0) {
			char key[16], buf[11];
			int i;

			generate_wep_key("iopsys", buf, sizeof(buf));
			for (i = 0; i < 4; i++) {
				snprintf(key, sizeof(key), "key%d", i + 1);
				dmuci_set_value_by_section(section, key, buf);
			}
			dmuci_set_value_by_section(section, "encryption", "wep-open");
			dmuci_set_value_by_section(section, "key", "1");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "none");
		} else if (DM_LSTRCMP(value, "WEP-128") == 0) {
			char key[16], buf[27];
			int i;

			generate_wep_key("iopsys_wep128", buf, sizeof(buf));
			for (i = 0; i < 4; i++) {
				snprintf(key, sizeof(key), "key%d", i + 1);
				dmuci_set_value_by_section(section, key, buf);
			}
			dmuci_set_value_by_section(section, "encryption", "wep-open");
			dmuci_set_value_by_section(section, "key", "1");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "none");
		} else if (DM_LSTRCMP(value, "WPA-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "psk");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "psk");
			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa");
			dmuci_set_value_by_section(section, "auth_port", "1812");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "wpa");
		} else if (DM_LSTRCMP(value, "WPA2-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "psk2");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(section, "wps", "1");
			dmuci_set_value_by_section(section, "ieee80211w", "1");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "psk2");
			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA2-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa2");
			dmuci_set_value_by_section(section, "auth_port", "1812");
			dmuci_set_value_by_section(section, "ieee80211w", "1");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "wpa2");
		} else if (DM_LSTRCMP(value, "WPA-WPA2-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "psk-mixed");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(section, "wps", "1");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "psk-mixed");
			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA-WPA2-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa-mixed");
			dmuci_set_value_by_section(section, "auth_port", "1812");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "wpa-mixed");
		} else if (DM_LSTRCMP(value, "WPA3-Personal") == 0) {
			dmuci_set_value_by_section(section, "encryption", "sae");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "ieee80211w", "2");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "sae");
			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA3-Enterprise") == 0) {
			dmuci_set_value_by_section(section, "encryption", "wpa3");
			dmuci_set_value_by_section(section, "auth_port", "1812");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "wpa");
		} else if (DM_LSTRCMP(value, "WPA3-Personal-Transition") == 0) {
			dmuci_set_value_by_section(section, "encryption", "sae-mixed");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "ieee80211w", "1");

			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "encryption", "sae-mixed");
			if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", wpa_key);
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
			set_security_mode((((struct wifi_acp_args *)data)->sections)->config_section, value, false);
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
			if (DM_LSTRSTR(encryption, "wep")) {
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
	struct uci_section *map_ssid_s = NULL;
	char *encryption = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"32"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (DM_LSTRSTR(encryption, "psk")) {
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", value);

				// mapcontroller config: Update the corresponding fronthaul ssid section if exist
				map_ssid_s = find_mapcontroller_ssid_section((((struct wifi_acp_args *)data)->sections)->config_section);
				if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", value);
			}

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
			if (DM_LSTRSTR(encryption, "psk"))
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
			if (!DM_LSTRSTR(encryption, "wep") && DM_LSTRCMP(encryption, "none") != 0)
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wpa_group_rekey", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.SAEPassphrase!UCI:wireless/wifi-iface,@i-1/key*/
static int set_WiFiAccessPointSecurity_SAEPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *map_ssid_s = NULL;
	char *encryption = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (DM_LSTRSTR(encryption, "sae")) {
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", value);

				// mapcontroller config: Update the corresponding fronthaul ssid section if exist
				map_ssid_s = find_mapcontroller_ssid_section((((struct wifi_acp_args *)data)->sections)->config_section);
				if (map_ssid_s) dmuci_set_value_by_section(map_ssid_s, "key", value);
			}
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
			if (DM_LSTRSTR(encryption, "wpa"))
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
			if (DM_LSTRSTR(encryption, "wpa"))
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
			if (DM_LSTRSTR(encryption, "wpa"))
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

static void get_cipher(char *encryption, bool *aes, bool *sae, bool *tkip)
{
	char *token = NULL, *saveptr = NULL;

	for (token = strtok_r(encryption, "+", &saveptr); token; token = strtok_r(NULL, "+", &saveptr)) {

		if (DM_LSTRCMP(token, "aes") == 0)
			*aes = true;

		if (DM_LSTRCMP(token, "sae") == 0)
			*sae = true;

		if (DM_LSTRCMP(token, "tkip") == 0)
			*tkip = true;
	}
}


static int validate_mfp_config(struct uci_section *section, const char *value)
{
	char *encryption = NULL;
	char *mode = NULL;

	bool aes = false, sae = false, tkip = false;

	if (!value || *value == '\0')
		return -1;

	mode = get_security_mode(section);
	if (!mode || *mode == '\0')
		return -1;

	dmuci_get_value_by_section_string(section, "encryption", &encryption);
	if (!encryption || *encryption == '\0')
		return -1;

	/*Here we get which cipher is true*/
	get_cipher(encryption, &aes, &sae, &tkip);

	if ((DM_LSTRCMP(mode, "WPA3-Personal")) == 0) {
		if ((sae == true || aes == true) && (tkip == false) && (DM_LSTRCMP(value, "Required") == 0))
			return 0;
		else
			return -1;
	} else if (DM_LSTRCMP(mode, "WPA2-Personal") == 0) {
		if ((aes == true) && (tkip == false) && (DM_LSTRCMP(value, "Optional") == 0))
			return 0;
		else
			return -1;

	} else if (DM_LSTRCMP(mode, "WPA3-Personal-Transition") == 0) {
		if ((sae == true || aes == true) && (tkip == false) && (DM_LSTRCMP(value, "Optional") == 0))
			return 0;
		else
			return -1;
	} else if (DM_LSTRCMP(value, "Disabled") == 0)
		return 0;
	else
		return -1;
}

static int set_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[2];

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, MFPConfig, NULL))
				return FAULT_9007;

			/*Here we also need to validate the encyption algo whether the MFP can be set*/
			if (validate_mfp_config((((struct wifi_acp_args *)data)->sections)->config_section, value))
				return FAULT_9007;

			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "Disabled") == 0)
				buf[0] = '0';
			else if (DM_LSTRCMP(value, "Optional") == 0)
				buf[0] = '1';
			else if (DM_LSTRCMP(value, "Required") == 0)
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

	if (*pushbut && DM_LSTRCMP(pushbut, "1") == 0)
		DM_STRNCPY(buf, "PushButton", sizeof(buf));

	if (*label && DM_LSTRCMP(label, "1") == 0) {
		if (*buf)
			strcat(buf, ",");

		strcat(buf, "Label");
	}

	if (*pin && DM_LSTRCMP(pin, "1") == 0) {
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

		if (DM_LSTRCMP(token, "PushButton") == 0)
			pushbut = true;

		if (DM_LSTRCMP(token, "Label") == 0)
			label = true;

		if (DM_LSTRCMP(token, "PIN") == 0)
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

static operation_args WiFiAccessPointWPSInitiateWPSPBC_args = {
	.out = (const char *[]) {
		"Status",
		NULL
	}
};

static int get_operate_args_WiFiAccessPointWPS_InitiateWPSPBC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&WiFiAccessPointWPSInitiateWPSPBC_args;
	return 0;
}

static int operate_WiFiAccessPointWPS_InitiateWPSPBC(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *status = "Success";
	char object[256];
	char *ifname = ((struct wifi_acp_args *)data)->ifname;
	int ubus_ret = 0;

	if (ifname == NULL)
		return CMD_FAIL;

	snprintf(object, sizeof(object), "hostapd.%s", ifname);
	ubus_ret = dmubus_call_set(object, "wps_start", UBUS_ARGS{0}, 0);
	if (ubus_ret != 0)
		status = "Error_Not_Ready";

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return CMD_SUCCESS;
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
	adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", ((struct wifi_enp_args *)data)->ifname, value);
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

static int get_dmmap_wireless_section(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value, char *section_name)
{
	struct uci_section *dmmap_section = NULL, *dm = NULL;
	char *epinst = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
	get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
	dmuci_get_value_by_section_string(dm, section_name, value);
	return 0;
}

static int set_dmmap_wireless_section(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action, char *section_name)
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
			dmuci_set_value_by_section_bbfdm(dm, section_name, value);
			break;
	}
	return 0;
}

static int get_WiFiEndPointProfile_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_dmmap_wireless_section(refparam, ctx, data, instance, value, "ep_location");
}

static int set_WiFiEndPointProfile_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_dmmap_wireless_section(refparam, ctx, data, instance, value, action, "ep_location");
}

static int get_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_dmmap_wireless_section(refparam, ctx, data, instance, value, "ep_profile_alias");
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_dmmap_wireless_section(refparam, ctx, data, instance, value, action, "ep_profile_alias");
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
			set_security_mode((struct uci_section *)data, value, true);
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
			if (DM_LSTRSTR(encryption, "wep")) {
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
			if (DM_LSTRSTR(encryption, "psk"))
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
			if (DM_LSTRSTR(encryption, "psk"))
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
			if (DM_LSTRSTR(encryption, "sae"))
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
	else if (DM_LSTRCMP(*value, "1") == 0)
		*value = "Optional";
	else if (DM_LSTRCMP(*value, "2") == 0)
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
			if (DM_LSTRCMP(value, "Disabled") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "0");
			else if (DM_LSTRCMP(value, "Optional") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "1");
			else if (DM_LSTRCMP(value, "Required") == 0)
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
	adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", ((struct wifi_ssid_args *)data)->linker, value);
	return 0;
}

static int set_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.WiFi.Radio.", NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section((((struct wifi_ssid_args *)data)->sections)->config_section, "device", linker ? linker : "");
			return 0;
	}
	return 0;
}

static int get_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", ((struct wifi_acp_args *)data)->ifname, value);
	return 0;
}

static int set_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.WiFi.SSID.", NULL};
	struct uci_section *s = NULL, *ssid_dmmap_s = NULL;
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			if ((((struct wifi_acp_args *)data)->ifname)[0] != '\0' || *value == '\0')
				break;

			adm_entry_get_linker_value(ctx, value, &linker);

			uci_foreach_sections("wireless", "wifi-iface", s) {
				struct uci_section *dmmap_section = NULL;
				char *ifname;

				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(s), &dmmap_section);
				dmuci_get_value_by_section_string(s, "ifname", &ifname);
				if (DM_STRCMP(ifname, linker) == 0) {
					ssid_dmmap_s = dmmap_section;
					break;
				}

				dmuci_get_value_by_section_string(dmmap_section, "ifname", &ifname);
				if (DM_STRCMP(ifname, linker) == 0) {
					ssid_dmmap_s = dmmap_section;
					break;
				}
			}

			if (ssid_dmmap_s != NULL) {
				dmuci_set_value_by_section(ssid_dmmap_s, "ap_instance", instance);
				dmuci_delete_by_section(ssid_dmmap_s, "ssid_added_by_user", NULL);
				dmuci_delete_by_section((((struct wifi_acp_args *)data)->sections)->config_section, NULL, NULL);
				dmuci_delete_by_section((((struct wifi_acp_args *)data)->sections)->dmmap_section, NULL, NULL);
			}

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
			if (DM_LSTRCMP(value, "Requested") == 0) {
				// cppcheck-suppress unknownMacro
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "bssid");
	return 0;
}

static int ssid_read_ubus(const struct wifi_ssid_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.ap.%s", args->ifname);
	dmubus_call(object, "stats", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

static int radio_read_ubus(const struct wifi_radio_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->sections->config_section));
	dmubus_call(object, "stats", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.Noise!UBUS:wifi.radio.@Name/status//noise*/
static int get_WiFiRadioStats_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "255");
	*value = dmjson_get_value(res, 1, "noise");
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
	float rate_kbps = (rate_mbps && *rate_mbps != '\0') ? atof(rate_mbps) * 1000 : 1000;

	dmasprintf(value, "%u", (unsigned int)rate_kbps);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataUplinkRate!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_rate_latest.rate*/
static int get_WiFiAccessPointAssociatedDevice_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *rate_mbps = dmjson_get_value((json_object *)data, 3, "stats", "tx_rate_latest", "rate");
	float rate_kbps = (rate_mbps && *rate_mbps != '\0') ? atof(rate_mbps) * 1000 : 1000;

	dmasprintf(value, "%u", (unsigned int)rate_kbps);
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
	if (in_network && *in_network != '\0' && DM_STRTOL(in_network) > 0) {
		time_t t_time = time(NULL) - DM_STRTOL(in_network);
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
	json_object *res = NULL;
	char object[32], *status = NULL, *iface;

	dmuci_get_value_by_section_string((((struct wifi_ssid_args *)data)->sections)->config_section, "device", &iface);
	snprintf(object, sizeof(object), "wifi.ap.%s", iface);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "Error_Misconfigured");
	status = dmjson_get_value(res, 1, "status");

	if (DM_LSTRCMP(status, "running") == 0 || DM_LSTRCMP(status, "up") == 0)
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
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
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "hwmode", (!DM_LSTRCMP(value, "5GHz") ? "11a" :"11g"));
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.ChannelsInUse!UCI:wireless/wifi-device,@i-1/channel*/
static int get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char object[32];
	json_object *res = NULL;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "channel");

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
		dmubus_call(object, "scanresults", UBUS_ARGS{0}, 0, &res);
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	cur_opclass = dmjson_get_value(res, 1, "opclass");
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		char *opclass = dmjson_get_value(supp_channels, 1, "opclass");
		if (opclass && DM_STRCMP(opclass, cur_opclass) != 0)
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
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "20MHz");
	dmasprintf(value, "%sMHz", dmjson_get_value(res, 1, "bandwidth"));
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedStandards!UBUS:wifi.radio.@Name/status//supp_std*/
static int get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_std_arr = NULL;
	char list_supp_std[16], object[16];
	char *supp_std = NULL;
	unsigned pos = 0, idx = 0;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "n,ax");

	list_supp_std[0] = 0;
	dmjson_foreach_value_in_array(res, supp_std_arr, supp_std, idx, 1, "supp_std") { // supp_std has as value 11xx
		pos += snprintf(&list_supp_std[pos], sizeof(list_supp_std) - pos, "%s,", supp_std + 2);
	}

	if (pos)
		list_supp_std[pos - 1] = 0;

	*value = dmstrdup(list_supp_std);
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingStandards!UBUS:wifi.radio.@Name/status//standard*/
static int get_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char standard_list[16] = { 0, 0 };
	char object[16];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "n,ax");
	char *standard = dmjson_get_value(res, 1, "standard");
	if (DM_LSTRSTR(standard, "802.11")) {
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
	char buf[16];
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
				snprintf(buf, sizeof(buf), "%s", value);
				for (pch = strtok_r(buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
					if (!value_exits_in_str_list(supported_standards, ",", pch))
						return FAULT_9007;
				}

				break;
			case VALUESET:
				dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", &curr_htmode);

				if (curr_htmode && *curr_htmode) {
					sscanf(curr_htmode, "%*[A-Z]%d", &freq);
					freq = !DM_LSTRCMP(curr_htmode, "NOHT") ? 20 : freq;
				}

				band = get_radio_option_nocache(section_name((((struct wifi_radio_args *)data)->sections)->config_section), "band");

				if (DM_LSTRCMP(band, "5GHz") == 0) {
					if (DM_LSTRSTR(value, "ax"))
						snprintf(htmode, sizeof(htmode), "HE%d", freq);
					else if (DM_LSTRSTR(value, "ac"))
						snprintf(htmode, sizeof(htmode), "VHT%d", freq);
					else if (DM_LSTRSTR(value, "n"))
						snprintf(htmode, sizeof(htmode), "HT%d", (freq != 20 && freq != 40) ? 20 : freq);
					else
						snprintf(htmode, sizeof(htmode), "NOHT");

					snprintf(hwmode, sizeof(hwmode), "11a");
				} else {
					if (DM_LSTRSTR(value, "ax")) {
						snprintf(htmode, sizeof(htmode), "HE%d", freq);
						snprintf(hwmode, sizeof(hwmode), "11g");
					} else if (DM_LSTRSTR(value, "n")) {
						snprintf(htmode, sizeof(htmode), "HT%d", (freq != 20 && freq != 40) ? 20 : freq);
						snprintf(hwmode, sizeof(hwmode), "11g");
					} else if (DM_LSTRSTR(value, "g")) {
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
	dmubus_call(object, "assoclist", UBUS_ARGS{0}, 0, &res);
	dmjson_foreach_obj_in_array(res, arrobj, assoclist, i, 1, "assoclist") {
		entries++;
	}
	dmasprintf(value, "%d", entries);
	return 0;
}

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

/*
static int get_WiFiDataElementsNetwork_MSCSDisallowedStaList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_WiFiDataElementsNetwork_option("dump2", "MSCSDisallowedStaList", true, value);
}
*/

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
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ssid", value);
	return 0;
}

static int get_WiFiDataElementsNetworkSSID_Band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *band = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "band", &band);
	*value = (!DM_LSTRCMP(band, "2")) ? "2.4" : (!DM_LSTRCMP(band, "5")) ? "5" : "6";
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
/*
static int get_WiFiDataElementsNetworkDevice_MultiAPCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "MultiAPCapabilities");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].CollectionInterval*/
static int get_WiFiDataElementsNetworkDevice_CollectionInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "CollectionInterval");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_sta_assocfails", "1");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_sta_assocfails", b ? "1" : "0");
			return 0;
	}
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDevice_MaxReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "MaxReportingRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_APMetricsReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_metric_periodic", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_APMetricsReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_metric_periodic", value);
			return 0;
	}
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "Manufacturer");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "SerialNumber");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_ManufacturerModel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ManufacturerModel");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "SoftwareVersion");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_ExecutionEnv(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ExecutionEnv");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_DSCPMap(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "DSCPMap");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_MaxPrioritizationRules(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "MaxPrioritizationRules");
	return 0;
}
*/

/*
static int get_WiFiDataElementsNetworkDevice_PrioritizationSupport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "PrioritizationSupport");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_MaxVIDs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "MaxVIDs");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_APMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "APMetricsWiFi6");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_CountryCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "CountryCode");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_list = NULL;
	dmuci_get_value_by_section_list((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_exclude", &uci_list);
	*value = dmuci_list_to_string(uci_list, ",");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length = 0;
	char **arr = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			return 0;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_exclude", "");
			for (int i = 0; i < length; i++)
				dmuci_add_list_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_exclude", arr[i]);
			return 0;
	}
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_list = NULL;
	dmuci_get_value_by_section_list((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_exclude_btm", &uci_list);
	*value = dmuci_list_to_string(uci_list, ",");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length = 0;
	char **arr = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			return 0;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_exclude_btm", "");
			for (int i = 0; i < length; i++)
				dmuci_add_list_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_exclude_btm", arr[i]);
			return 0;
	}
	return 0;
}
/*
static int get_WiFiDataElementsNetworkDevice_DFSEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "DFSEnable");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDevice_ReportIndependentScans(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ReportIndependentScans");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_ReportIndependentScans(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_scan", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "AssociatedSTAinAPMetricsWiFi6");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
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

static int get_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "MaxUnsuccessfulAssociationReportingRate");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_sta_assocfails_rate", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_STASteeringState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "STASteeringState");
	return 0;
}
*/

/*
static int get_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "CoordinatedCACAllowed");
	return 0;
}

static int set_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
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
	*value = dmuci_get_option_value_fallback_def("mapcontroller", "controller", "enable_ts", "1");
	return 0;
}

/*static int get_WiFiDataElementsNetworkDevice_ServicePrioritizationAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ServicePrioritizationAllowed");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].NumberOfRadios*/
static int get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "NumberOfRadios");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_Default8021QNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "Default8021QNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SSIDtoVIDMappingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "SSIDtoVIDMappingNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_CACStatusNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "CACStatusNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_IEEE1905SecurityNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "IEEE1905SecurityNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_SPRuleNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "SPRuleNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_AnticipatedChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "AnticipatedChannelsNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDevice_AnticipatedChannelUsageNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "AnticipatedChannelUsageNumberOfEntries");
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
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "RecieveOther");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedFronthaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "TrafficSeparationCombinedFronthaul");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedBackhaul(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "TrafficSeparationCombinedBackhaul");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_policy", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"2"}}, 1))
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
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "util_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "util_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "rcpi_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"220"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "rcpi_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_rcpi_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"220"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_rcpi_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_rcpi_hysteresis_margin", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_rcpi_hysteresis_margin", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_util_threshold", value);
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "report_util_threshold", value);
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_data_element_args *)data)->uci_s)->config_section, "include_sta_stats", "1");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "include_sta_stats", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_data_element_args *)data)->uci_s)->config_section, "include_sta_metric", "1");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "include_sta_metric", b ? "1" : "0");
			return 0;
	}
	return 0;
}
/*
static int get_WiFiDataElementsNetworkDeviceRadio_ChipsetVendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ChipsetVendor");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_APMetricsWiFi6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "APMetricsWiFi6");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfCurrOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "NumberOfCurrOpClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfUnassocSta*/
/*
static int get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "NumberOfUnassocSta");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfBSS*/
static int get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 1, "NumberOfBSS");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfScanRes*/
static int get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ScanResultNumberOfEntries");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadio_DisAllowedOpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "DisAllowedOpClassChannelsNumberOfEntries");
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
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "Capabilites", "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.VHTCapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *cap = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "Capabilites", "VHTCapabilities");
	*value = (DM_STRLEN(cap)) ? cap : "AAA=";
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HECapabilities*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *cap = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "Capabilites", "HECapabilities");
	*value = (DM_STRLEN(cap)) ? cap : "AAAAAA==";
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.NumberOfOpClass*/
static int get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump_obj, 2, "Capabilites", "NumberOfOpClass");
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
/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastChange");
	return 0;
}
*/

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

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_ByteCounterUnits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ByteCounterUnits");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadioBSS_Profile1bSTAsDisallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Profile1bSTAsDisallowed");
	return 0;
}

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

static int get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BackhaulUse");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "FronthaulUse");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_R1disallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "R1disallowed");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_R2disallowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "R2disallowed");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceRadioBSS_MultiBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MultiBSSID");
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceRadioBSS_TransmittedBSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TransmittedBSSID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value_array_all((json_object *)data, ",", 1, "FronthaulAKMsAllowed");
	return 0;
}

static int set_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, AKMsAllowed, NULL))
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
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, AKMsAllowed, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
*/
/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberofSTA*/
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
//static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
//{
//	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
//	return 0;
//}

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
//static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
//{
//	*value = dmjson_get_value((json_object *)data, 1, "UtilizationReceive");
//	return 0;
//}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationTransmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationTransmit*/
//static int get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
//{
//	*value = dmjson_get_value((json_object *)data, 1, "UtilizationTransmit");
//	return 0;
//}

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

/*
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
*/

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
			if (dm_validate_string(value, -1, -1, CellularDataPreference, NULL))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
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

/*static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_OnBootOnly(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_Impact(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_MinimumInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapability_OpClassChannelsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_OpClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_ChannelList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceRadioCACCapability_CACMethodNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 2, "CACCapability", "CACMethodNumberOfEntries");
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
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].MACAddress*/
/*
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}
*/

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].SignalStrength*/
/*
static int get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}
*/

/*
static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_ManufacturerOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 2, "MultiAPDevice", "ManufacturerOUI");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_LastContactTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 2, "MultiAPDevice", "LastContactTime");
	return 0;
}
*/

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_AssocIEEE1905DeviceRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device_id = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 1, "ID");
	adm_entry_get_linker_param(ctx, "Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.", device_id, value);
	return 0;
}

/*
static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshControllerOperationMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 2, "MultiAPDevice", "EasyMeshControllerOperationMode");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshAgentOperationMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 2, "MultiAPDevice", "EasyMeshAgentOperationMode");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_LinkType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 3, "MultiAPDevice", "Backhaul", "LinkType");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 3, "MultiAPDevice", "Backhaul", "BackhaulMACAddress");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulDeviceID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 3, "MultiAPDevice", "Backhaul", "BackhaulDeviceID");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 3, "MultiAPDevice", "Backhaul", "MACAddress");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 3, "MultiAPDevice", "Backhaul", "CurrentOperatingClassProfileNumberOfEntries");
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
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "BytesSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "BytesReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "PacketsSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "PacketsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "ErrorsSent");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "ErrorsReceived");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LinkUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "LinkUtilization");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "SignalStrength");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "LastDataDownlinkRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "LastDataUplinkRate");
	return 0;
}

static int get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct wifi_data_element_args *)data)->dump2_obj, 4, "MultiAPDevice", "Backhaul", "Stats", "TimeStamp");
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
			if (dm_validate_boolean(value))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"4095"}}, 1))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"7"}}, 1))
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
static int operate_WiFi_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return !dmcmd_no_wait("/sbin/wifi", 1, "reload") ? CMD_SUCCESS : CMD_FAIL;
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

	dmubus_call("wifi", "status", UBUS_ARGS{0}, 0, &res);
	if (res) {
		json_object *radios = NULL, *arrobj = NULL;
		int i = 0;
		uint8_t index = 1;

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
			if (!DM_STRLEN(radio_name))
				continue;

			snprintf(object, sizeof(object), "wifi.radio.%s", radio_name);

			struct blob_buf bb;
			memset(&bb, 0, sizeof(struct blob_buf));
			blob_buf_init(&bb, 0);
			blobmsg_add_string(&bb, "radio", radio_name);
			blobmsg_add_string(&bb, "action", "scan_finished");

			dmubus_call_set(object, "scan", UBUS_ARGS{0}, 0);

			dmubus_register_event_blocking("wifi.radio", 30, bb.head);
			blob_buf_free(&bb);

			dmubus_call(object, "scanresults", UBUS_ARGS{0}, 0, &scan_res);

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

				dmasprintf(&ssid[0], "Result.%d.SSID", index);
				dmasprintf(&bssid[0], "Result.%d.BSSID", index);
				dmasprintf(&channel[0], "Result.%d.Channel", index);
				dmasprintf(&frequency[0], "Result.%d.OperatingFrequencyBand", index);
				dmasprintf(&signal_strength[0], "Result.%d.SignalStrength", index);
				dmasprintf(&noise[0], "Result.%d.Noise", index);

				add_list_parameter(ctx, ssid[0], ssid[1], DMT_TYPE[DMT_STRING], NULL);
				add_list_parameter(ctx, bssid[0], bssid[1], DMT_TYPE[DMT_STRING], NULL);
				add_list_parameter(ctx, channel[0], channel[1], DMT_TYPE[DMT_UNINT], NULL);
				add_list_parameter(ctx, frequency[0], frequency[1], DMT_TYPE[DMT_STRING], NULL);
				add_list_parameter(ctx, signal_strength[0], signal_strength[1], DMT_TYPE[DMT_INT], NULL);
				add_list_parameter(ctx, noise[0], noise[1], DMT_TYPE[DMT_INT], NULL);
				index++;
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
	if (!enable || *enable == '\0' || dm_validate_boolean(enable)) {
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
	return CMD_SUCCESS;

#undef MAX_ARGS
}
/*
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

		if (*(operate_args[i].arg1) && dm_validate_string(operate_args[i].arg1, -1, 17, NULL, MACAddress)) {
			status = "Error_Invalid_Input";
			break;
		}

		if (*(operate_args[i].arg2) && dm_validate_string(operate_args[i].arg2, -1, 17, NULL, MACAddress)) {
			status = "Error_Invalid_Input";
			break;
		}

		adm_entry_get_linker_value(ctx, device_path, &linker);
		if (linker == NULL || *linker == '\0') {
			status = "Error_Invalid_Input";
			break;
		}

		struct uci_section *s = get_origin_section_from_config("mapcontroller", "node", linker);
		if (*(operate_args[i].arg1) != '\0')
			dmuci_set_value_by_section(s, "backhaul_ul_macaddr", operate_args[i].arg1);

		if (*(operate_args[i].arg2) != '\0')
			dmuci_set_value_by_section(s, "backhaul_dl_macaddr", operate_args[i].arg2);

	}

	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return CMD_SUCCESS;
}
*/

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
	struct uci_section *s = NULL, *stmp = NULL;
	char *status = "Success";
	char *curr_ssid = NULL;
	char *curr_band = NULL;
	bool ssid_exist = false, b = false;

	char *add_remove = dmjson_get_value((json_object *)value, 1, "AddRemove");
	if (!add_remove || *add_remove == '\0' || dm_validate_boolean(add_remove)) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *ssid = dmjson_get_value((json_object *)value, 1, "SSID");
	char *key = dmjson_get_value((json_object *)value, 1, "PassPhrase");
	char *band = dmjson_get_value((json_object *)value, 1, "Band");
	if (!ssid || *ssid == '\0' || !band || *band == '\0') {
		status = "Error_Invalid_Input";
		goto end;
	}

	string_to_bool(add_remove, &b);

	if (b) {
		// Add this SSID
		uci_foreach_option_eq("mapcontroller", "ap", "type", "fronthaul", s) {
			dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
			dmuci_get_value_by_section_string(s, "band", &curr_band);
			if (DM_STRCMP(curr_ssid, ssid) == 0 && DM_STRNCMP(curr_band, band, 1) == 0) {
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

			snprintf(sec_name, sizeof(sec_name), "ap_%s_%u", (*band == '5') ? "5" : (*band == '6') ? "6" : "2", idx);

			dmuci_add_section("mapcontroller", "ap", &s);
			dmuci_rename_section_by_section(s, sec_name);
			dmuci_set_value_by_section(s, "ssid", ssid);
			dmuci_set_value_by_section(s, "key", key);
			dmuci_set_value_by_section(s, "type", "fronthaul");
			dmuci_set_value_by_section(s, "band", (*band == '5') ? "5" : (*band == '6') ? "6" : "2");
			dmuci_set_value_by_section(s, "enabled", "1");
		}

	} else {
		// Remove this SSID
		uci_foreach_option_eq_safe("mapcontroller", "ap", "type", "fronthaul", stmp, s) {
			dmuci_get_value_by_section_string(s, "ssid", &curr_ssid);
			dmuci_get_value_by_section_string(s, "band", &curr_band);
			if (DM_STRCMP(curr_ssid, ssid) == 0 && DM_STRNCMP(curr_band, band, 1) == 0) {
				dmuci_set_value_by_section(s, "enabled", "0");
				ssid_exist = true;
				break;
			}
		}

		if (!ssid_exist)
			status = "Error_Invalid_Input";
	}

	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return CMD_SUCCESS;
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
	if (!disallowed || *disallowed == '\0' || dm_validate_boolean(disallowed)) {
		status = "Error_Invalid_Input";
		goto end;
	}

	string_to_bool(disallowed, &b);
	dmuci_set_value_by_section((((struct wifi_data_element_args *)data)->uci_s)->config_section, "steer_disallow", b ? "1" : "0");
	dmuci_save_package("mapcontroller");
	dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", "mapcontroller", String}}, 1);

end:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	return CMD_SUCCESS;
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
	return CMD_SUCCESS;
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

	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "agent_id", &agent_id);
	dmuci_get_value_by_section_string((((struct wifi_data_element_args *)data)->uci_s)->config_section, "macaddr", &macaddr);

	if ((dm_validate_string(agent_id, -1, 17, NULL, MACAddress)) ||
		(dm_validate_string(macaddr, -1, 17, NULL, MACAddress))) {
		status = "Error_Invalid_Input";
		goto end;
	}

	char *channel_list = dmjson_get_value((json_object *)value, 1, "ChannelList");

	if (dm_validate_unsignedInt_list(channel_list, -1, -1, -1, RANGE_ARGS{{NULL,"255"}}, 1)) {
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
    return CMD_SUCCESS;
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
    return CMD_SUCCESS;
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
/* *** Device.WiFi. *** */
DMOBJ tWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DataElements", &DMREAD, NULL, NULL, "file:/etc/init.d/decollector", NULL, NULL, NULL, tWiFiDataElementsObj, NULL, NULL, BBFDM_BOTH, NULL, "2.13"},
{"Radio", &DMREAD, NULL, NULL, "file:/etc/config/wireless", browseWifiRadioInst, NULL, NULL, tWiFiRadioObj, tWiFiRadioParams, get_linker_Wifi_Radio, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.0"},
{"SSID", &DMWRITE, add_wifi_ssid, delete_wifi_ssid, "file:/etc/config/wireless", browseWifiSsidInst, NULL, NULL, tWiFiSSIDObj, tWiFiSSIDParams, get_linker_Wifi_Ssid, BBFDM_BOTH, LIST_KEY{"Name", "Alias", "BSSID", NULL}, "2.0"},
{"AccessPoint", &DMWRITE, add_wifi_accesspoint, delete_wifi_accesspoint, "file:/etc/config/wireless", browseWifiAccessPointInst, NULL, NULL, tWiFiAccessPointObj, tWiFiAccessPointParams, get_linker_Wifi_AccessPoint, BBFDM_BOTH, LIST_KEY{"SSIDReference", "Alias", NULL}, "2.0"},
{"NeighboringWiFiDiagnostic", &DMREAD, NULL, NULL, "file:/etc/config/wireless", NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticObj, tWiFiNeighboringWiFiDiagnosticParams, NULL, BBFDM_BOTH, NULL, "2.7"},
{"EndPoint", &DMWRITE, addObjWiFiEndPoint, delObjWiFiEndPoint, "file:/etc/config/wireless", browseWiFiEndPointInst, NULL, NULL, tWiFiEndPointObj, tWiFiEndPointParams, NULL, BBFDM_BOTH, LIST_KEY{"SSIDReference", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tWiFiParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_RadioNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"SSIDNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_SSIDNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"AccessPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_AccessPointNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"EndPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_EndPointNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_WiFi_Reset, BBFDM_USP, "2.12"},
{"NeighboringWiFiDiagnostic()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFi_NeighboringWiFiDiagnostic, operate_WiFi_NeighboringWiFiDiagnostic, BBFDM_USP, "2.12"},
{0}
};

/* *** Device.WiFi.Radio.{i}. *** */
DMOBJ tWiFiRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiRadioStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tWiFiRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_radio_alias, set_radio_alias, BBFDM_BOTH, "2.0"},
{"Enable", &DMWRITE, DMT_BOOL, get_radio_enable, set_radio_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_radio_status, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_WiFiRadio_LowerLayers, set_WiFiRadio_LowerLayers, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_WiFiRadio_Name, NULL, BBFDM_BOTH, "2.0"},
{"MaxBitRate", &DMREAD, DMT_UNINT, get_radio_max_bit_rate, NULL, BBFDM_BOTH, "2.0"},
{"SupportedFrequencyBands", &DMREAD, DMT_STRING, get_radio_supported_frequency_bands, NULL, BBFDM_BOTH, "2.0"},
{"OperatingFrequencyBand", &DMWRITE, DMT_STRING, get_radio_frequency, set_radio_frequency, BBFDM_BOTH, "2.0"},
{"SupportedStandards", &DMREAD, DMT_STRING, get_radio_supported_standard, NULL, BBFDM_BOTH, "2.0"},
{"OperatingStandards", &DMWRITE, DMT_STRING, get_radio_operating_standard, set_radio_operating_standard, BBFDM_BOTH, "2.0"},
{"ChannelsInUse", &DMREAD, DMT_STRING, get_radio_channel, NULL, BBFDM_BOTH, "2.0"},
{"Channel", &DMWRITE, DMT_UNINT, get_radio_channel, set_radio_channel, BBFDM_BOTH, "2.0"},
{"AutoChannelEnable", &DMWRITE, DMT_BOOL, get_radio_auto_channel_enable, set_radio_auto_channel_enable, BBFDM_BOTH, "2.0"},
{"PossibleChannels", &DMREAD, DMT_STRING, get_radio_possible_channels, NULL, BBFDM_BOTH, "2.0"},
{"AutoChannelSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_AutoChannelSupported, NULL, BBFDM_BOTH, "2.0"},
{"AutoChannelRefreshPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_AutoChannelRefreshPeriod, set_WiFiRadio_AutoChannelRefreshPeriod, BBFDM_BOTH, "2.0"},
{"MaxSupportedAssociations", &DMREAD, DMT_UNINT, get_WiFiRadio_MaxSupportedAssociations, NULL, BBFDM_BOTH, "2.12"},
{"FragmentationThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_FragmentationThreshold, set_WiFiRadio_FragmentationThreshold, BBFDM_BOTH, "2.8"},
{"RTSThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_RTSThreshold, set_WiFiRadio_RTSThreshold, BBFDM_BOTH, "2.8"},
{"BeaconPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_BeaconPeriod, set_WiFiRadio_BeaconPeriod, BBFDM_BOTH, "2.8"},
{"DTIMPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_DTIMPeriod, set_WiFiRadio_DTIMPeriod, BBFDM_BOTH, "2.8"},
{"SupportedOperatingChannelBandwidths", &DMREAD, DMT_STRING, get_WiFiRadio_SupportedOperatingChannelBandwidths, NULL, BBFDM_BOTH, "2.12"},
{"OperatingChannelBandwidth", &DMWRITE, DMT_STRING, get_WiFiRadio_OperatingChannelBandwidth, set_WiFiRadio_OperatingChannelBandwidth, BBFDM_BOTH, "2.0"},
{"CurrentOperatingChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiRadio_CurrentOperatingChannelBandwidth, NULL, BBFDM_BOTH, "2.11"},
{"PreambleType", &DMWRITE, DMT_STRING, get_WiFiRadio_PreambleType, set_WiFiRadio_PreambleType, BBFDM_BOTH, "2.8"},
{"IEEE80211hSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_IEEE80211hSupported, NULL, BBFDM_BOTH, "2.0"},
{"IEEE80211hEnabled", &DMWRITE, DMT_BOOL, get_WiFiRadio_IEEE80211hEnabled, set_WiFiRadio_IEEE80211hEnabled, BBFDM_BOTH, "2.0"},
{"TransmitPower", &DMWRITE, DMT_INT, get_WiFiRadio_TransmitPower, set_WiFiRadio_TransmitPower, BBFDM_BOTH, "2.0"},
{"RegulatoryDomain", &DMWRITE, DMT_STRING, get_WiFiRadio_RegulatoryDomain, set_WiFiRadio_RegulatoryDomain, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.WiFi.Radio.{i}.Stats. *** */
DMLEAF tWiFiRadioStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Noise", &DMREAD, DMT_INT, get_WiFiRadioStats_Noise, NULL, BBFDM_BOTH, "2.8"},
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_BytesSent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_BytesReceived, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_PacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiRadioStats_PacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiRadioStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiRadioStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_WiFiRadioStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiRadioStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"FCSErrorCount", &DMREAD, DMT_UNINT, get_WiFiRadioStats_FCSErrorCount, NULL, BBFDM_BOTH, "2.7"},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic. *** */
DMOBJ tWiFiNeighboringWiFiDiagnosticObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Result", &DMREAD, NULL, NULL, NULL, browseWifiNeighboringWiFiDiagnosticResultInst, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticResultParams, NULL, BBFDM_CWMP, NULL, "2.7"},
{0}
};

DMLEAF tWiFiNeighboringWiFiDiagnosticParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_neighboring_wifi_diagnostics_diagnostics_state, set_neighboring_wifi_diagnostics_diagnostics_state, BBFDM_CWMP, "2.7"},
{"ResultNumberOfEntries", &DMREAD, DMT_UNINT, get_neighboring_wifi_diagnostics_result_number_entries, NULL, BBFDM_CWMP, "2."},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}. *** */
DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SSID", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_ssid, NULL, BBFDM_CWMP, "2.7"},
{"BSSID", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_bssid, NULL, BBFDM_CWMP, "2.7"},
{"Channel", &DMREAD, DMT_UNINT, get_neighboring_wifi_diagnostics_result_channel, NULL, BBFDM_CWMP, "2.7"},
{"SignalStrength", &DMREAD, DMT_INT, get_neighboring_wifi_diagnostics_result_signal_strength, NULL, BBFDM_CWMP, "2.7"},
{"OperatingFrequencyBand", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_operating_frequency_band, NULL, BBFDM_CWMP, "2.7"},
{"Noise", &DMREAD, DMT_INT, get_neighboring_wifi_diagnostics_result_noise, NULL, BBFDM_CWMP, "2.7"},
{0}
};

/* *** Device.WiFi.SSID.{i}. *** */
DMOBJ tWiFiSSIDObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiSSIDStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tWiFiSSIDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_ssid_alias, set_ssid_alias, BBFDM_BOTH, "2.0"},
{"Enable", &DMWRITE, DMT_BOOL, get_wifi_enable, set_wifi_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_wifi_status, NULL, BBFDM_BOTH, "2.0"},
{"SSID", &DMWRITE, DMT_STRING, get_wlan_ssid, set_wlan_ssid, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING,  get_wlan_name, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ssid_lower_layer, set_ssid_lower_layer, BBFDM_BOTH, "2.0"},
{"BSSID", &DMREAD, DMT_STRING, get_wlan_bssid, NULL, BBFDM_BOTH, "2.0"},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiSSID_MACAddress, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.WiFi.SSID.{i}.Stats. *** */
DMLEAF tWiFiSSIDStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BytesSent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BytesReceived, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_PacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_PacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_RetransCount, NULL, BBFDM_BOTH, "2.7"},
{"FailedRetransCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_FailedRetransCount, NULL, BBFDM_BOTH, "2.7"},
{"RetryCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_RetryCount, NULL, BBFDM_BOTH, "2.7"},
{"MultipleRetryCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_MultipleRetryCount, NULL, BBFDM_BOTH, "2.7"},
{"ACKFailureCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ACKFailureCount, NULL, BBFDM_BOTH, "2.7"},
{"AggregatedPacketCount", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_AggregatedPacketCount, NULL, BBFDM_BOTH, "2.7"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_UnicastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_UnicastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_MulticastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_MulticastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BroadcastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiSSIDStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}. *** */
DMOBJ tWiFiAccessPointObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointSecurityParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_wifi_associated_device, NULL, NULL, tWiFiAccessPointAssociatedDeviceObj, tWiFiAccessPointAssociatedDeviceParams, get_linker_associated_device, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}, "2.0"},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointWPSParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Accounting", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAccountingParams, NULL, BBFDM_BOTH, NULL, "2.5"},
{0}
};

DMLEAF tWiFiAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_access_point_alias, set_access_point_alias, BBFDM_BOTH, "2.0"},
{"Enable", &DMWRITE, DMT_BOOL,  get_wifi_enable, set_wifi_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_wifi_access_point_status, NULL, BBFDM_BOTH, "2.0"},
{"SSIDReference", &DMWRITE, DMT_STRING, get_ap_ssid_ref, set_ap_ssid_ref, BBFDM_BOTH, "2.0"},
{"SSIDAdvertisementEnabled", &DMWRITE, DMT_BOOL, get_wlan_ssid_advertisement_enable, set_wlan_ssid_advertisement_enable, BBFDM_BOTH, "2.0"},
{"WMMEnable", &DMWRITE, DMT_BOOL, get_wmm_enabled, set_wmm_enabled, BBFDM_BOTH, "2.0"},
{"UAPSDEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_UAPSDEnable, set_WiFiAccessPoint_UAPSDEnable, BBFDM_BOTH, "2.0"},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_access_point_total_associations, NULL, BBFDM_BOTH, "2.0"},
{"MACAddressControlEnabled", &DMWRITE, DMT_BOOL, get_access_point_control_enable, set_access_point_control_enable, BBFDM_BOTH, "2.9"},
{"UAPSDCapability", &DMREAD, DMT_BOOL, get_WiFiAccessPoint_UAPSDCapability, NULL, BBFDM_BOTH, "2.0"},
{"WMMCapability", &DMREAD, DMT_BOOL, get_WiFiAccessPoint_WMMCapability, NULL, BBFDM_BOTH, "2.0"},
{"MaxAllowedAssociations", &DMWRITE, DMT_UNINT, get_WiFiAccessPoint_MaxAllowedAssociations, set_WiFiAccessPoint_MaxAllowedAssociations, BBFDM_BOTH, "2.12"},
{"IsolationEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_IsolationEnable, set_WiFiAccessPoint_IsolationEnable, BBFDM_BOTH, "2.4"},
{"AllowedMACAddress", &DMWRITE, DMT_STRING, get_WiFiAccessPoint_AllowedMACAddress, set_WiFiAccessPoint_AllowedMACAddress, BBFDM_BOTH, "2.9"},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.Security. *** */
DMLEAF tWiFiAccessPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ModesSupported", &DMREAD, DMT_STRING, get_access_point_security_supported_modes, NULL, BBFDM_BOTH, "2.0"},
{"ModeEnabled", &DMWRITE, DMT_STRING, get_access_point_security_modes, set_access_point_security_modes, BBFDM_BOTH, "2.0"},
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_wepkey, BBFDM_BOTH, "2.0"},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_shared_key, BBFDM_BOTH, "2.0"},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_passphrase, BBFDM_BOTH, "2.0"},
{"RekeyingInterval", &DMWRITE, DMT_UNINT, get_access_point_security_rekey_interval, set_access_point_security_rekey_interval, BBFDM_BOTH, "2.0"},
{"SAEPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointSecurity_SAEPassphrase, BBFDM_BOTH, "2.0"},
{"RadiusServerIPAddr", &DMWRITE, DMT_STRING, get_access_point_security_radius_ip_address, set_access_point_security_radius_ip_address, BBFDM_BOTH, "2.0"},
{"RadiusServerPort", &DMWRITE, DMT_UNINT, get_access_point_security_radius_server_port, set_access_point_security_radius_server_port, BBFDM_BOTH, "2.0"},
{"RadiusSecret", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_radius_secret, BBFDM_BOTH, "2.0"},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiAccessPointSecurity_MFPConfig, set_WiFiAccessPointSecurity_MFPConfig, BBFDM_BOTH, "2.11"},
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_WiFiAccessPointSecurity_Reset, BBFDM_USP, "2.12"},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.WPS. *** */
DMLEAF tWiFiAccessPointWPSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiAccessPointWPS_Enable, set_WiFiAccessPointWPS_Enable, BBFDM_BOTH, "2.0"},
{"ConfigMethodsSupported", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_ConfigMethodsSupported, NULL, BBFDM_BOTH, "2.0"},
{"ConfigMethodsEnabled", &DMWRITE, DMT_STRING, get_WiFiAccessPointWPS_ConfigMethodsEnabled, set_WiFiAccessPointWPS_ConfigMethodsEnabled, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Status, NULL, BBFDM_BOTH, "2.11"},
//{"Version", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Version, NULL, BBFDM_BOTH, "2.11"},
{"PIN", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointWPS_PIN, BBFDM_BOTH, "2.11"},
{"InitiateWPSPBC()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiAccessPointWPS_InitiateWPSPBC, operate_WiFiAccessPointWPS_InitiateWPSPBC, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}. *** */
DMOBJ tWiFiAccessPointAssociatedDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAssociatedDeviceStatsParams, NULL, BBFDM_BOTH, NULL, "2.8"},
{0}
};

DMLEAF tWiFiAccessPointAssociatedDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Active", &DMREAD, DMT_BOOL, get_WiFiAccessPointAssociatedDevice_Active, NULL, BBFDM_BOTH, "2.0"},
{"Noise", &DMREAD, DMT_INT, get_WiFiAccessPointAssociatedDevice_Noise, NULL, BBFDM_BOTH, "2.12"},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiAccessPointAssociatedDevice_MACAddress, NULL, BBFDM_BOTH, "2.0"},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_LastDataDownlinkRate, NULL, BBFDM_BOTH, "2.0"},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_LastDataUplinkRate, NULL, BBFDM_BOTH, "2.0"},
{"SignalStrength", &DMREAD, DMT_INT, get_WiFiAccessPointAssociatedDevice_SignalStrength, NULL, BBFDM_BOTH, "2.0"},
//{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_Retransmissions, NULL, BBFDM_BOTH, "2.0"},
{"AssociationTime", &DMREAD, DMT_TIME, get_WiFiAccessPointAssociatedDevice_AssociationTime, NULL, BBFDM_BOTH, "2.12"},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats. *** */
DMLEAF tWiFiAccessPointAssociatedDeviceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_tx_bytes, NULL, BBFDM_BOTH, "2.8"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_rx_bytes, NULL, BBFDM_BOTH, "2.8"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_tx_packets, NULL, BBFDM_BOTH, "2.8"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_access_point_associative_device_statistics_rx_packets, NULL, BBFDM_BOTH, "2.8"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_tx_errors, NULL, BBFDM_BOTH, "2.8"},
{"RetransCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_retrans_count, NULL, BBFDM_BOTH, "2.8"},
//{"FailedRetransCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_failed_retrans_count, NULL, BBFDM_BOTH, "2.8"},
//{"RetryCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_retry_count, NULL, BBFDM_BOTH, "2.8"},
//{"MultipleRetryCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_multiple_retry_count, NULL, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.Accounting. *** */
DMLEAF tWiFiAccessPointAccountingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_WiFiAccessPointAccounting_Enable, set_WiFiAccessPointAccounting_Enable, BBFDM_BOTH, "2.5"},
{"ServerIPAddr", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_ServerIPAddr, set_WiFiAccessPointAccounting_ServerIPAddr, BBFDM_BOTH, "2.5"},
//{"SecondaryServerIPAddr", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondaryServerIPAddr, set_WiFiAccessPointAccounting_SecondaryServerIPAddr, BBFDM_BOTH, "2.5"},
{"ServerPort", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_ServerPort, set_WiFiAccessPointAccounting_ServerPort, BBFDM_BOTH, "2.5"},
//{"SecondaryServerPort", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_SecondaryServerPort, set_WiFiAccessPointAccounting_SecondaryServerPort, BBFDM_BOTH, "2.5"},
{"Secret", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointAccounting_Secret, BBFDM_BOTH, "2.5"},
//{"SecondarySecret", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondarySecret, set_WiFiAccessPointAccounting_SecondarySecret, BBFDM_BOTH, "2.5"},
//{"InterimInterval", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_InterimInterval, set_WiFiAccessPointAccounting_InterimInterval, BBFDM_BOTH, "2.5"},
{0}
};

/* *** Device.WiFi.EndPoint.{i}. *** */
DMOBJ tWiFiEndPointObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointSecurityParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Profile", &DMREAD, NULL, NULL, NULL, browseWiFiEndPointProfileInst, NULL, NULL, tWiFiEndPointProfileObj, tWiFiEndPointProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "SSID", "Location", "Priority", NULL}, "2.0"},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointWPSParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tWiFiEndPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPoint_Enable, set_WiFiEndPoint_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPoint_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPoint_Alias, set_WiFiEndPoint_Alias, BBFDM_BOTH, "2.0"},
//{"ProfileReference", &DMWRITE, DMT_STRING, get_WiFiEndPoint_ProfileReference, set_WiFiEndPoint_ProfileReference, BBFDM_BOTH, "2.0"},
{"SSIDReference", &DMREAD, DMT_STRING, get_WiFiEndPoint_SSIDReference, NULL, BBFDM_BOTH, "2.0"},
//{"ProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiEndPoint_ProfileNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Security. *** */
DMLEAF tWiFiEndPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ModesSupported", &DMREAD, DMT_STRING, get_WiFiEndPointSecurity_ModesSupported, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}. *** */
DMOBJ tWiFiEndPointProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointProfileSecurityParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tWiFiEndPointProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointProfile_Enable, set_WiFiEndPointProfile_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointProfile_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Alias, set_WiFiEndPointProfile_Alias, BBFDM_BOTH, "2.0"},
{"SSID", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_SSID, set_WiFiEndPointProfile_SSID, BBFDM_BOTH, "2.0"},
{"Location", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Location, set_WiFiEndPointProfile_Location, BBFDM_BOTH, "2.0"},
//{"Priority", &DMWRITE, DMT_UNINT, get_WiFiEndPointProfile_Priority, set_WiFiEndPointProfile_Priority, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}.Security. *** */
DMLEAF tWiFiEndPointProfileSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ModeEnabled", &DMWRITE, DMT_STRING, get_WiFiEndPointProfileSecurity_ModeEnabled, set_WiFiEndPointProfileSecurity_ModeEnabled, BBFDM_BOTH, "2.0"},
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_WiFiEndPointProfileSecurity_WEPKey, BBFDM_BOTH, "2.0"},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_WiFiEndPointProfileSecurity_PreSharedKey, BBFDM_BOTH, "2.0"},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiEndPointProfileSecurity_KeyPassphrase, BBFDM_BOTH, "2.0"},
{"SAEPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiEndPointProfileSecurity_SAEPassphrase, BBFDM_BOTH, "2.13"},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiEndPointProfileSecurity_MFPConfig, set_WiFiEndPointProfileSecurity_MFPConfig, BBFDM_BOTH, "2.11"},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.WPS. *** */
DMLEAF tWiFiEndPointWPSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointWPS_Enable, set_WiFiEndPointWPS_Enable, BBFDM_BOTH, "2.0"},
{"ConfigMethodsSupported", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_ConfigMethodsSupported, NULL, BBFDM_BOTH, "2.0"},
{"ConfigMethodsEnabled", &DMWRITE, DMT_STRING, get_WiFiEndPointWPS_ConfigMethodsEnabled, set_WiFiEndPointWPS_ConfigMethodsEnabled, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Status, NULL, BBFDM_BOTH, "2.11"},
//{"Version", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Version, NULL, BBFDM_BOTH, "2.11"},
{"PIN", &DMWRITE, DMT_UNINT, get_WiFiEndPointWPS_PIN, set_WiFiEndPointWPS_PIN, BBFDM_BOTH, "2.11"},
{0}
};

/* *** Device.WiFi.DataElements. *** */
DMOBJ tWiFiDataElementsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Network", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkObj, tWiFiDataElementsNetworkParams, NULL, BBFDM_BOTH, NULL, "2.13"},
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventObj, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH, NULL, "2.13"},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventObj, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH, NULL, "2.13"},
//{"FailedConnectionEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsFailedConnectionEventObj, tWiFiDataElementsFailedConnectionEventParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network. *** */
DMOBJ tWiFiDataElementsNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"SSID", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkSSIDInst, NULL, NULL, NULL, tWiFiDataElementsNetworkSSIDParams, NULL, BBFDM_BOTH, LIST_KEY{"SSID", NULL}, "2.15"},
{"MultiAPSteeringSummaryStats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkMultiAPSteeringSummaryStatsParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{"Device", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceInst, NULL, NULL, tWiFiDataElementsNetworkDeviceObj, tWiFiDataElementsNetworkDeviceParams, get_linker_wfdata_Device, BBFDM_BOTH, LIST_KEY{"ID", NULL}, "2.13"},
{0}
};

DMLEAF tWiFiDataElementsNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_ID, NULL, BBFDM_BOTH, "2.13"},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_TimeStamp, NULL, BBFDM_BOTH, "2.13"},
{"ControllerID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_ControllerID, NULL, BBFDM_BOTH, "2.13"},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetwork_DeviceNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
// {"MSCSDisallowedStaList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_MSCSDisallowedStaList, NULL, BBFDM_BOTH, "2.15"},
{"SCSDisallowedStaList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetwork_SCSDisallowedStaList, NULL, BBFDM_BOTH, "2.15"},
{"SSIDNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetwork_SSIDNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
{"SetTrafficSeparation()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetTrafficSeparation, operate_WiFiDataElementsNetwork_SetTrafficSeparation, BBFDM_USP, "2.15"},
//{"SetServicePrioritization()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetServicePrioritization, operate_WiFiDataElementsNetwork_SetServicePrioritization, BBFDM_USP, "2.15"},
// {"SetPreferredBackhauls()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetPreferredBackhauls, operate_WiFiDataElementsNetwork_SetPreferredBackhauls, BBFDM_USP, "2.15"},
{"SetSSID()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetSSID, operate_WiFiDataElementsNetwork_SetSSID, BBFDM_USP, "2.15"},
//{"SetMSCSDisallowed()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetMSCSDisallowed, operate_WiFiDataElementsNetwork_SetMSCSDisallowed, BBFDM_USP, "2.15"},
//{"SetSCSDisallowed()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetwork_SetSCSDisallowed, operate_WiFiDataElementsNetwork_SetSCSDisallowed, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.SSID.{i}. *** */
DMLEAF tWiFiDataElementsNetworkSSIDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_SSID, NULL, BBFDM_BOTH, "2.15"},
{"Band", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkSSID_Band, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.MultiAPSteeringSummaryStats. *** */
DMLEAF tWiFiDataElementsNetworkMultiAPSteeringSummaryStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"NoCandidateAPFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_NoCandidateAPFailures, NULL, BBFDM_BOTH, "2.15"},
{"BlacklistAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistAttempts, NULL, BBFDM_BOTH, "2.15"},
{"BlacklistSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistSuccesses, NULL, BBFDM_BOTH, "2.15"},
{"BlacklistFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BlacklistFailures, NULL, BBFDM_BOTH, "2.15"},
{"BTMAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMAttempts, NULL, BBFDM_BOTH, "2.15"},
{"BTMSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMSuccesses, NULL, BBFDM_BOTH, "2.15"},
{"BTMFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMFailures, NULL, BBFDM_BOTH, "2.15"},
{"BTMQueryResponses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkMultiAPSteeringSummaryStats_BTMQueryResponses, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Default8021Q", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceDefault8021QInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceDefault8021QParams, NULL, BBFDM_BOTH, LIST_KEY{"PrimaryVID", NULL}, "2.15"},
{"SSIDtoVIDMapping", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceSSIDtoVIDMappingInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceSSIDtoVIDMappingParams, NULL, BBFDM_BOTH, LIST_KEY{"SSID", NULL}, "2.15"},
//{"CACStatus", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusInst, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusObj, tWiFiDataElementsNetworkDeviceCACStatusParams, NULL, BBFDM_BOTH, LIST_KEY{"TimeStamp", NULL}, "2.15"},
//{"SPRule", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceSPRuleInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceSPRuleParams, NULL, BBFDM_BOTH, LIST_KEY{"ID", NULL}, "2.15"},
//{"IEEE1905Security", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceIEEE1905SecurityInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceIEEE1905SecurityParams, NULL, BBFDM_BOTH, LIST_KEY{"OnboardingProtocol", NULL}, "2.15"},
//{"AnticipatedChannels", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceAnticipatedChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceAnticipatedChannelsParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{"AnticipatedChannelUsage", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceAnticipatedChannelUsageInst, NULL, NULL, tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageObj, tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
{"MultiAPDevice", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceObj, tWiFiDataElementsNetworkDeviceMultiAPDeviceParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{"Radio", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioObj, tWiFiDataElementsNetworkDeviceRadioParams, NULL, BBFDM_BOTH, LIST_KEY{"ID", NULL}, "2.13"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ID, NULL, BBFDM_BOTH, "2.13"},
// {"MultiAPCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDevice_MultiAPCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"CollectionInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_CollectionInterval, NULL, BBFDM_BOTH, "2.13"},
// {"ReportUnsuccessfulAssociations", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations, set_WiFiDataElementsNetworkDevice_ReportUnsuccessfulAssociations, BBFDM_BOTH, "2.15"},
{"MaxReportingRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxReportingRate, NULL, BBFDM_BOTH, "2.15"},
{"APMetricsReportingInterval", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDevice_APMetricsReportingInterval, set_WiFiDataElementsNetworkDevice_APMetricsReportingInterval, BBFDM_BOTH, "2.15"},
// {"Manufacturer", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_Manufacturer, NULL, BBFDM_BOTH, "2.15"},
// {"SerialNumber", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_SerialNumber, NULL, BBFDM_BOTH, "2.15"},
// {"ManufacturerModel", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ManufacturerModel, NULL, BBFDM_BOTH, "2.15"},
// {"SoftwareVersion", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_SoftwareVersion, NULL, BBFDM_BOTH, "2.15"},
// {"ExecutionEnv", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_ExecutionEnv, NULL, BBFDM_BOTH, "2.15"},
// {"DSCPMap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDevice_DSCPMap, NULL, BBFDM_BOTH, "2.15"},
// {"MaxPrioritizationRules", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxPrioritizationRules, NULL, BBFDM_BOTH, "2.15"},
// {"PrioritizationSupport", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_PrioritizationSupport, NULL, BBFDM_BOTH, "2.15"},
// {"MaxVIDs", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxVIDs, NULL, BBFDM_BOTH, "2.15"},
// {"APMetricsWiFi6", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_APMetricsWiFi6, NULL, BBFDM_BOTH, "2.15"},
// {"CountryCode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDevice_CountryCode, NULL, BBFDM_BOTH, "2.15"},
// {"LocalSteeringDisallowedSTAList", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList, set_WiFiDataElementsNetworkDevice_LocalSteeringDisallowedSTAList, BBFDM_BOTH, "2.15"},
{"BTMSteeringDisallowedSTAList", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList, set_WiFiDataElementsNetworkDevice_BTMSteeringDisallowedSTAList, BBFDM_BOTH, "2.15"},
// {"DFSEnable", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_DFSEnable, NULL, BBFDM_BOTH, "2.15"},
{"ReportIndependentScans", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_ReportIndependentScans, set_WiFiDataElementsNetworkDevice_ReportIndependentScans, BBFDM_BOTH, "2.15"},
// {"AssociatedSTAinAPMetricsWiFi6", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6, set_WiFiDataElementsNetworkDevice_AssociatedSTAinAPMetricsWiFi6, BBFDM_BOTH, "2.15"},
// {"MaxUnsuccessfulAssociationReportingRate", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate, set_WiFiDataElementsNetworkDevice_MaxUnsuccessfulAssociationReportingRate, BBFDM_BOTH, "2.15"},
// {"STASteeringState", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_STASteeringState, NULL, BBFDM_BOTH, "2.15"},
// {"CoordinatedCACAllowed", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed, set_WiFiDataElementsNetworkDevice_CoordinatedCACAllowed, BBFDM_BOTH, "2.15"},
{"TrafficSeparationAllowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_TrafficSeparationAllowed, NULL, BBFDM_BOTH, "2.15"},
// {"ServicePrioritizationAllowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDevice_ServicePrioritizationAllowed, NULL, BBFDM_BOTH, "2.15"},
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"Default8021QNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_Default8021QNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"SSIDtoVIDMappingNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_SSIDtoVIDMappingNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"CACStatusNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_CACStatusNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"IEEE1905SecurityNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_IEEE1905SecurityNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"SPRuleNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_SPRuleNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"AnticipatedChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_AnticipatedChannelsNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"AnticipatedChannelUsageNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDevice_AnticipatedChannelUsageNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
// {"SetSTASteeringState()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetSTASteeringState, operate_WiFiDataElementsNetworkDevice_SetSTASteeringState, BBFDM_USP, "2.15"},
//{"SetDFSState()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetDFSState, operate_WiFiDataElementsNetworkDevice_SetDFSState, BBFDM_USP, "2.15"},
//{"SetAnticipatedChannelPreference()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDevice_SetAnticipatedChannelPreference, operate_WiFiDataElementsNetworkDevice_SetAnticipatedChannelPreference, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Default8021Q.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceDefault8021QParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceDefault8021Q_Enable, set_WiFiDataElementsNetworkDeviceDefault8021Q_Enable, BBFDM_BOTH, "2.15"},
{"PrimaryVID", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceDefault8021Q_PrimaryVID, set_WiFiDataElementsNetworkDeviceDefault8021Q_PrimaryVID, BBFDM_BOTH, "2.15"},
{"DefaultPCP", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceDefault8021Q_DefaultPCP, set_WiFiDataElementsNetworkDeviceDefault8021Q_DefaultPCP, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.SSIDtoVIDMapping.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceSSIDtoVIDMappingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_SSID, NULL, BBFDM_BOTH, "2.15"},
{"VID", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSSIDtoVIDMapping_VID, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}. *** */
//DMOBJ tWiFiDataElementsNetworkDeviceCACStatusObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"CACAvailableChannel", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{"CACNonOccupancyChannel", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{"CACActiveChannel", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceCACStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"TimeStamp", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceCACStatus_TimeStamp, NULL, BBFDM_BOTH, "2.15"},
//{"CACAvailableChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatus_CACAvailableChannelNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{"CACNonOccupancyChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatus_CACNonOccupancyChannelNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{"CACActiveChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatus_CACActiveChannelNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}.CACAvailableChannel.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACAvailableChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Channel, NULL, BBFDM_BOTH, "2.15"},
//{"Minutes", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACAvailableChannel_Minutes, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}.CACNonOccupancyChannel.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Channel, NULL, BBFDM_BOTH, "2.15"},
//{"Seconds", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACNonOccupancyChannel_Seconds, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.CACStatus.{i}.CACActiveChannel.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceCACStatusCACActiveChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Channel, NULL, BBFDM_BOTH, "2.15"},
//{"Countdown", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceCACStatusCACActiveChannel_Countdown, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.SPRule.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceSPRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"ID", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSPRule_ID, NULL, BBFDM_BOTH, "2.15"},
//{"Precedence", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSPRule_Precedence, NULL, BBFDM_BOTH, "2.15"},
//{"Output", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceSPRule_Output, NULL, BBFDM_BOTH, "2.15"},
//{"AlwaysMatch", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceSPRule_AlwaysMatch, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.IEEE1905Security.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceIEEE1905SecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OnboardingProtocol", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceIEEE1905Security_OnboardingProtocol, NULL, BBFDM_BOTH, "2.15"},
//{"IntegrityAlgorithm", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceIEEE1905Security_IntegrityAlgorithm, NULL, BBFDM_BOTH, "2.15"},
//{"EncryptionAlgorithm", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceIEEE1905Security_EncryptionAlgorithm, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.AnticipatedChannels.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannels_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"ChannelList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannels_ChannelList, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.AnticipatedChannelUsage.{i}. *** */
//DMOBJ tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"Entry", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryParams, NULL, BBFDM_BOTH, LIST_KEY{"BurstStartTime", NULL}, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_Channel, NULL, BBFDM_BOTH, "2.15"},
//{"ReferenceBSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_ReferenceBSSID, NULL, BBFDM_BOTH, "2.15"},
//{"EntryNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsage_EntryNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.AnticipatedChannelUsage.{i}.Entry.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntryParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"BurstStartTime", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_BurstStartTime, NULL, BBFDM_BOTH, "2.15"},
//{"BurstLength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_BurstLength, NULL, BBFDM_BOTH, "2.15"},
//{"Repetitions", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_Repetitions, NULL, BBFDM_BOTH, "2.15"},
//{"BurstInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_BurstInterval, NULL, BBFDM_BOTH, "2.15"},
//{"RUBitmask", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_RUBitmask, NULL, BBFDM_BOTH, "2.15"},
//{"TransmitterIdentifier", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_TransmitterIdentifier, NULL, BBFDM_BOTH, "2.15"},
//{"PowerLevel", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_PowerLevel, NULL, BBFDM_BOTH, "2.15"},
//{"ChannelUsageReason", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceAnticipatedChannelUsageEntry_ChannelUsageReason, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice. *** */
DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
// {"Backhaul", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulObj, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
// {"ManufacturerOUI", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_ManufacturerOUI, NULL, BBFDM_BOTH, "2.15"},
// {"LastContactTime", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDevice_LastContactTime, NULL, BBFDM_BOTH, "2.15"},
{"AssocIEEE1905DeviceRef", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_AssocIEEE1905DeviceRef, NULL, BBFDM_BOTH, "2.15"},
// {"EasyMeshControllerOperationMode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshControllerOperationMode, NULL, BBFDM_BOTH, "2.15"},
// {"EasyMeshAgentOperationMode", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDevice_EasyMeshAgentOperationMode, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice.Backhaul. *** */
// DMOBJ tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}, "2.15"},
//{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStatsParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
// {"LinkType", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_LinkType, NULL, BBFDM_BOTH, "2.15"},
// {"BackhaulMACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulMACAddress, NULL, BBFDM_BOTH, "2.15"},
// {"BackhaulDeviceID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_BackhaulDeviceID, NULL, BBFDM_BOTH, "2.15"},
// {"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_MACAddress, NULL, BBFDM_BOTH, "2.15"},
// {"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_CurrentOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{"SteerWiFiBackhaul()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul, operate_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaul_SteerWiFiBackhaul, BBFDM_USP, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice.Backhaul.CurrentOperatingClassProfile.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Class, NULL, BBFDM_BOTH, "2.15"},
//{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_Channel, NULL, BBFDM_BOTH, "2.15"},
//{"TxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TxPower, NULL, BBFDM_BOTH, "2.15"},
//{"TimeStamp", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulCurrentOperatingClassProfile_TimeStamp, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.MultiAPDevice.Backhaul.Stats. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesSent, NULL, BBFDM_BOTH, "2.15"},
//{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_BytesReceived, NULL, BBFDM_BOTH, "2.15"},
//{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsSent, NULL, BBFDM_BOTH, "2.15"},
//{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_PacketsReceived, NULL, BBFDM_BOTH, "2.15"},
//{"ErrorsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsSent, NULL, BBFDM_BOTH, "2.15"},
//{"ErrorsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.15"},
//{"LinkUtilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LinkUtilization, NULL, BBFDM_BOTH, "2.15"},
//{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_SignalStrength, NULL, BBFDM_BOTH, "2.15"},
//{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataDownlinkRate, NULL, BBFDM_BOTH, "2.15"},
//{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_LastDataUplinkRate, NULL, BBFDM_BOTH, "2.15"},
//{"TimeStamp", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceMultiAPDeviceBackhaulStats_TimeStamp, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"ScanResult", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultObj, tWiFiDataElementsNetworkDeviceRadioScanResultParams, NULL, BBFDM_BOTH, NULL, "2.14"},
{"BackhaulSta", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams, NULL, BBFDM_BOTH, NULL, "2.13"},
//{"ScanCapability", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanCapabilityObj, tWiFiDataElementsNetworkDeviceRadioScanCapabilityParams, NULL, BBFDM_BOTH, NULL, "2.15"},
// {"CACCapability", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCACCapabilityObj, tWiFiDataElementsNetworkDeviceRadioCACCapabilityParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj, tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams, NULL, BBFDM_BOTH, NULL, "2.13"},
{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}, "2.13"},
//{"DisAllowedOpClassChannels", &DMWRITE, addObjWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels, delObjWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels, NULL, browseWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{"SpatialReuse", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioSpatialReuseParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{"BSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSObj, tWiFiDataElementsNetworkDeviceRadioBSSParams, NULL, BBFDM_BOTH, LIST_KEY{"BSSID", NULL}, "2.13"},
// {"UnassociatedSTA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}, "2.13"},
//{"MultiAPRadio", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioMultiAPRadioParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ID", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadio_ID, NULL, BBFDM_BOTH, "2.13"},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_Enabled, NULL, BBFDM_BOTH, "2.13"},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Noise, NULL, BBFDM_BOTH, "2.13"},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Utilization, NULL, BBFDM_BOTH, "2.13"},
{"Transmit", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_Transmit, NULL, BBFDM_BOTH, "2.13"},
{"ReceiveSelf", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf, NULL, BBFDM_BOTH, "2.13"},
{"ReceiveOther", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther, NULL, BBFDM_BOTH, "2.13"},
// {"TrafficSeparationCombinedFronthaul", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedFronthaul, NULL, BBFDM_BOTH, "2.15"},
// {"TrafficSeparationCombinedBackhaul", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_TrafficSeparationCombinedBackhaul, NULL, BBFDM_BOTH, "2.15"},
// {"SteeringPolicy", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy, set_WiFiDataElementsNetworkDeviceRadio_SteeringPolicy, BBFDM_BOTH, "2.15"},
{"ChannelUtilizationThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold, set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationThreshold, BBFDM_BOTH, "2.15"},
{"RCPISteeringThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold, set_WiFiDataElementsNetworkDeviceRadio_RCPISteeringThreshold, BBFDM_BOTH, "2.15"},
{"STAReportingRCPIThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold, set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIThreshold, BBFDM_BOTH, "2.15"},
{"STAReportingRCPIHysteresisMarginOverride", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride, set_WiFiDataElementsNetworkDeviceRadio_STAReportingRCPIHysteresisMarginOverride, BBFDM_BOTH, "2.15"},
{"ChannelUtilizationReportingThreshold", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold, set_WiFiDataElementsNetworkDeviceRadio_ChannelUtilizationReportingThreshold, BBFDM_BOTH, "2.15"},
{"AssociatedSTATrafficStatsInclusionPolicy", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy, set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTATrafficStatsInclusionPolicy, BBFDM_BOTH, "2.15"},
{"AssociatedSTALinkMetricsInclusionPolicy", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy, set_WiFiDataElementsNetworkDeviceRadio_AssociatedSTALinkMetricsInclusionPolicy, BBFDM_BOTH, "2.15"},
// {"ChipsetVendor", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadio_ChipsetVendor, NULL, BBFDM_BOTH, "2.15"},
// {"APMetricsWiFi6", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadio_APMetricsWiFi6, NULL, BBFDM_BOTH, "2.15"},
{"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
// {"UnassociatedSTANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"BSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"ScanResultNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"DisAllowedOpClassChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadio_DisAllowedOpClassChannelsNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
{"ChannelScanRequest()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_ChannelScanRequest, operate_WiFiDataElementsNetworkDeviceRadio_ChannelScanRequest, BBFDM_USP, "2.15"},
//{"RadioEnable()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_RadioEnable, operate_WiFiDataElementsNetworkDeviceRadio_RadioEnable, BBFDM_USP, "2.15"},
//{"SetTxPowerLimit()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_SetTxPowerLimit, operate_WiFiDataElementsNetworkDeviceRadio_SetTxPowerLimit, BBFDM_USP, "2.15"},
//{"SetSpatialReuse()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_SetSpatialReuse, operate_WiFiDataElementsNetworkDeviceRadio_SetSpatialReuse, BBFDM_USP, "2.15"},
//{"WiFiRestart()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadio_WiFiRestart, operate_WiFiDataElementsNetworkDeviceRadio_WiFiRestart, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"OpClassScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams, NULL, BBFDM_BOTH, LIST_KEY{"OperatingClass", NULL}, "2.14"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp, NULL, BBFDM_BOTH, "2.14"},
{"OpClassScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries, NULL, BBFDM_BOTH, "2.14"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"ChannelScan", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams, NULL, BBFDM_BOTH, LIST_KEY{"Channel", NULL}, "2.14"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"OperatingClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass, NULL, BBFDM_BOTH, "2.14"},
{"ChannelScanNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries, NULL, BBFDM_BOTH, "2.14"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"NeighborBSS", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams, NULL, BBFDM_BOTH, LIST_KEY{"BSSID", NULL}, "2.14"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel, NULL, BBFDM_BOTH, "2.14"},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp, NULL, BBFDM_BOTH, "2.14"},
{"Utilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization, NULL, BBFDM_BOTH, "2.14"},
{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise, NULL, BBFDM_BOTH, "2.14"},
{"NeighborBSSNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries, NULL, BBFDM_BOTH, "2.14"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID, NULL, BBFDM_BOTH, "2.14"},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID, NULL, BBFDM_BOTH, "2.14"},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength, NULL, BBFDM_BOTH, "2.14"},
{"ChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth, NULL, BBFDM_BOTH, "2.14"},
{"ChannelUtilization", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization, NULL, BBFDM_BOTH, "2.14"},
{"StationCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount, NULL, BBFDM_BOTH, "2.14"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress, NULL, BBFDM_BOTH, "2.13"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanCapability. *** */
//DMOBJ tWiFiDataElementsNetworkDeviceRadioScanCapabilityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"OpClassChannels", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OnBootOnly", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioScanCapability_OnBootOnly, NULL, BBFDM_BOTH, "2.15"},
//{"Impact", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapability_Impact, NULL, BBFDM_BOTH, "2.15"},
//{"MinimumInterval", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapability_MinimumInterval, NULL, BBFDM_BOTH, "2.15"},
//{"OpClassChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapability_OpClassChannelsNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanCapability.OpClassChannels.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"ChannelList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioScanCapabilityOpClassChannels_ChannelList, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CACCapability. *** */
// DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
// {"CACMethod", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodObj, tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodParams, NULL, BBFDM_BOTH, LIST_KEY{"Method", NULL}, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"CACMethodNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapability_CACMethodNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CACCapability.CACMethod.{i}. *** */
// DMOBJ tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"OpClassChannels", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsParams, NULL, BBFDM_BOTH, LIST_KEY{"OpClass", NULL}, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Method", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_Method, NULL, BBFDM_BOTH, "2.15"},
//{"NumberOfSeconds", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_NumberOfSeconds, NULL, BBFDM_BOTH, "2.15"},
//{"OpClassChannelsNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethod_OpClassChannelsNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CACCapability.CACMethod.{i}.OpClassChannels.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OpClass", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_OpClass, NULL, BBFDM_BOTH, "2.15"},
//{"ChannelList", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCACCapabilityCACMethodOpClassChannels_ChannelList, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"WiFi6APRole", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRoleParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{"WiFi6bSTARole", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARoleParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{"AKMFrontHaul", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulParams, NULL, BBFDM_BOTH, LIST_KEY{"OUI", NULL}, "2.15"},
//{"AKMBackhaul", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulParams, NULL, BBFDM_BOTH, LIST_KEY{"OUI", NULL}, "2.15"},
{"CapableOperatingClassProfile", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}, "2.13"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities, NULL, BBFDM_BOTH, "2.13"},
{"CapableOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
//{"AKMFrontHaulNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_AKMFrontHaulNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{"AKMBackhaulNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilities_AKMBackhaulNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.WiFi6APRole. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRoleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE160, NULL, BBFDM_BOTH, "2.15"},
//{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_HE8080, NULL, BBFDM_BOTH, "2.15"},
//{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MCSNSS, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SUBeamformee, NULL, BBFDM_BOTH, "2.15"},
//{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_Beamformee80orLess, NULL, BBFDM_BOTH, "2.15"},
//{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_BeamformeeAbove80, NULL, BBFDM_BOTH, "2.15"},
//{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_ULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxDLOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MaxULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_RTS, NULL, BBFDM_BOTH, "2.15"},
//{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MURTS, NULL, BBFDM_BOTH, "2.15"},
//{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MultiBSSID, NULL, BBFDM_BOTH, "2.15"},
//{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_MUEDCA, NULL, BBFDM_BOTH, "2.15"},
//{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTRequestor, NULL, BBFDM_BOTH, "2.15"},
//{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_TWTResponder, NULL, BBFDM_BOTH, "2.15"},
//{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_SpatialReuse, NULL, BBFDM_BOTH, "2.15"},
//{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6APRole_AnticipatedChannelUsage, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.WiFi6bSTARole. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARoleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE160, NULL, BBFDM_BOTH, "2.15"},
//{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_HE8080, NULL, BBFDM_BOTH, "2.15"},
//{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MCSNSS, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SUBeamformee, NULL, BBFDM_BOTH, "2.15"},
//{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_Beamformee80orLess, NULL, BBFDM_BOTH, "2.15"},
//{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_BeamformeeAbove80, NULL, BBFDM_BOTH, "2.15"},
//{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_ULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxDLOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MaxULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_RTS, NULL, BBFDM_BOTH, "2.15"},
//{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MURTS, NULL, BBFDM_BOTH, "2.15"},
//{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MultiBSSID, NULL, BBFDM_BOTH, "2.15"},
//{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_MUEDCA, NULL, BBFDM_BOTH, "2.15"},
//{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTRequestor, NULL, BBFDM_BOTH, "2.15"},
//{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_TWTResponder, NULL, BBFDM_BOTH, "2.15"},
//{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_SpatialReuse, NULL, BBFDM_BOTH, "2.15"},
//{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesWiFi6bSTARole_AnticipatedChannelUsage, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.AKMFrontHaul.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaulParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OUI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaul_OUI, NULL, BBFDM_BOTH, "2.15"},
//{"Type", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMFrontHaul_Type, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.AKMBackhaul.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaulParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"OUI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaul_OUI, NULL, BBFDM_BOTH, "2.15"},
//{"Type", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesAKMBackhaul_Type, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class, NULL, BBFDM_BOTH, "2.13"},
{"MaxTxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower, NULL, BBFDM_BOTH, "2.13"},
{"NonOperable", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable, NULL, BBFDM_BOTH, "2.13"},
{"NumberOfNonOperChan", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan, NULL, BBFDM_BOTH, "2.13"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Class", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class, NULL, BBFDM_BOTH, "2.13"},
{"Channel", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel, NULL, BBFDM_BOTH, "2.13"},
{"TxPower", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower, NULL, BBFDM_BOTH, "2.13"},
// {"TransmitPowerLimit", &DMREAD, DMT_INT, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TransmitPowerLimit, NULL, BBFDM_BOTH, "2.15"},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp, NULL, BBFDM_BOTH, "2.13"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.DisAllowedOpClassChannels.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannelsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Enable", &DMWRITE, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_Enable, set_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_Enable, BBFDM_BOTH, "2.15"},
//{"OpClass", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_OpClass, set_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_OpClass, BBFDM_BOTH, "2.15"},
//{"ChannelList", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_ChannelList, set_WiFiDataElementsNetworkDeviceRadioDisAllowedOpClassChannels_ChannelList, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.SpatialReuse. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioSpatialReuseParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"PartialBSSColor", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_PartialBSSColor, NULL, BBFDM_BOTH, "2.15"},
//{"BSSColor", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_BSSColor, NULL, BBFDM_BOTH, "2.15"},
//{"HESIGASpatialReuseValue15Allowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_HESIGASpatialReuseValue15Allowed, NULL, BBFDM_BOTH, "2.15"},
//{"SRGInformationValid", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGInformationValid, NULL, BBFDM_BOTH, "2.15"},
//{"NonSRGOffsetValid", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_NonSRGOffsetValid, NULL, BBFDM_BOTH, "2.15"},
//{"PSRDisallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_PSRDisallowed, NULL, BBFDM_BOTH, "2.15"},
//{"NonSRGOBSSPDMaxOffset", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_NonSRGOBSSPDMaxOffset, NULL, BBFDM_BOTH, "2.15"},
//{"SRGOBSSPDMinOffset", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGOBSSPDMinOffset, NULL, BBFDM_BOTH, "2.15"},
//{"SRGOBSSPDMaxOffset", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGOBSSPDMaxOffset, NULL, BBFDM_BOTH, "2.15"},
//{"SRGBSSColorBitmap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGBSSColorBitmap, NULL, BBFDM_BOTH, "2.15"},
//{"SRGPartialBSSIDBitmap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_SRGPartialBSSIDBitmap, NULL, BBFDM_BOTH, "2.15"},
//{"NeighborBSSColorInUseBitmap", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioSpatialReuse_NeighborBSSColorInUseBitmap, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
// {"QMDescriptor", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorParams, NULL, BBFDM_BOTH, LIST_KEY{"ClientMAC", NULL}, "2.15"},
{"MultiAPSteering", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSMultiAPSteeringParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{"STA", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAObj, tWiFiDataElementsNetworkDeviceRadioBSSSTAParams, get_linker_wfdata_BSS_STA, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}, "2.13"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID, NULL, BBFDM_BOTH, "2.13"},
{"SSID", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_SSID, NULL, BBFDM_BOTH, "2.13"},
{"Enabled", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled, NULL, BBFDM_BOTH, "2.13"},
// {"LastChange", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange, NULL, BBFDM_BOTH, "2.13"},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp, NULL, BBFDM_BOTH, "2.13"},
{"UnicastBytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent, NULL, BBFDM_BOTH, "2.13"},
{"UnicastBytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived, NULL, BBFDM_BOTH, "2.13"},
{"MulticastBytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent, NULL, BBFDM_BOTH, "2.13"},
{"MulticastBytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived, NULL, BBFDM_BOTH, "2.13"},
{"BroadcastBytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent, NULL, BBFDM_BOTH, "2.13"},
{"BroadcastBytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived, NULL, BBFDM_BOTH, "2.13"},
// {"ByteCounterUnits", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_ByteCounterUnits, NULL, BBFDM_BOTH, "2.15"},
{"Profile1bSTAsDisallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Profile1bSTAsDisallowed, NULL, BBFDM_BOTH, "2.15"},
{"Profile2bSTAsDisallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_Profile2bSTAsDisallowed, NULL, BBFDM_BOTH, "2.15"},
// {"AssociationAllowanceStatus", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_AssociationAllowanceStatus, NULL, BBFDM_BOTH, "2.15"},
// {"EstServiceParametersBE", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE, NULL, BBFDM_BOTH, "2.13"},
// {"EstServiceParametersBK", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK, NULL, BBFDM_BOTH, "2.13"},
// {"EstServiceParametersVI", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI, NULL, BBFDM_BOTH, "2.13"},
// {"EstServiceParametersVO", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO, NULL, BBFDM_BOTH, "2.13"},
// {"BackhaulUse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulUse, NULL, BBFDM_BOTH, "2.15"},
// {"FronthaulUse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulUse, NULL, BBFDM_BOTH, "2.15"},
// {"R1disallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_R1disallowed, NULL, BBFDM_BOTH, "2.15"},
// {"R2disallowed", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_R2disallowed, NULL, BBFDM_BOTH, "2.15"},
{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_MultiBSSID, NULL, BBFDM_BOTH, "2.15"},
// {"TransmittedBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSS_TransmittedBSSID, NULL, BBFDM_BOTH, "2.15"},
// {"FronthaulAKMsAllowed", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed, set_WiFiDataElementsNetworkDeviceRadioBSS_FronthaulAKMsAllowed, BBFDM_BOTH, "2.15"},
// {"BackhaulAKMsAllowed", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulAKMsAllowed, set_WiFiDataElementsNetworkDeviceRadioBSS_BackhaulAKMsAllowed, BBFDM_BOTH, "2.15"},
{"STANumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
// {"QMDescriptorNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSS_QMDescriptorNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
//{"SetQMDescriptors()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSS_SetQMDescriptors, operate_WiFiDataElementsNetworkDeviceRadioBSS_SetQMDescriptors, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.QMDescriptor.{i}. *** */
// DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSQMDescriptorParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
// {"ClientMAC", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_ClientMAC, NULL, BBFDM_BOTH, "2.15"},
// {"DescriptorElement", &DMREAD, DMT_HEXBIN, get_WiFiDataElementsNetworkDeviceRadioBSSQMDescriptor_DescriptorElement, NULL, BBFDM_BOTH, "2.15"},
// {0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MultiAPSteering. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSMultiAPSteeringParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BlacklistAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BlacklistAttempts, NULL, BBFDM_BOTH, "2.15"},
{"BTMAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMAttempts, NULL, BBFDM_BOTH, "2.15"},
{"BTMQueryResponses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSMultiAPSteering_BTMQueryResponses, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSSTAObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"MultiAPSTA", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAObj, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{"WiFi6Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6CapabilitiesParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{"TIDQueueSizes", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesParams, NULL, BBFDM_BOTH, LIST_KEY{"TID", NULL}, "2.15"},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress, NULL, BBFDM_BOTH, "2.13"},
// {"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp, NULL, BBFDM_BOTH, "2.13"},
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities, NULL, BBFDM_BOTH, "2.13"},
//{"ClientCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ClientCapabilities, NULL, BBFDM_BOTH, "2.15"},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate, NULL, BBFDM_BOTH, "2.13"},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate, NULL, BBFDM_BOTH, "2.13"},
// {"UtilizationReceive", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive, NULL, BBFDM_BOTH, "2.13"},
// {"UtilizationTransmit", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit, NULL, BBFDM_BOTH, "2.13"},
{"EstMACDataRateDownlink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink, NULL, BBFDM_BOTH, "2.13"},
{"EstMACDataRateUplink", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink, NULL, BBFDM_BOTH, "2.13"},
{"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength, NULL, BBFDM_BOTH, "2.13"},
{"LastConnectTime", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime, NULL, BBFDM_BOTH, "2.13"},
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent, NULL, BBFDM_BOTH, "2.13"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived, NULL, BBFDM_BOTH, "2.13"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent, NULL, BBFDM_BOTH, "2.13"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived, NULL, BBFDM_BOTH, "2.13"},
{"ErrorsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent, NULL, BBFDM_BOTH, "2.13"},
{"ErrorsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived, NULL, BBFDM_BOTH, "2.13"},
{"RetransCount", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount, NULL, BBFDM_BOTH, "2.13"},
{"MeasurementReport", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport, NULL, BBFDM_BOTH, "2.13"},
{"NumberOfMeasureReports", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports, NULL, BBFDM_BOTH, "2.13"},
// {"IPV4Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address, NULL, BBFDM_BOTH, "2.13"},
// {"IPV6Address", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address, NULL, BBFDM_BOTH, "2.13"},
{"Hostname", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname, NULL, BBFDM_BOTH, "2.13"},
// {"CellularDataPreference", &DMWRITE, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference, set_WiFiDataElementsNetworkDeviceRadioBSSSTA_CellularDataPreference, BBFDM_BOTH, "2.15"},
// {"ReAssociationDelay", &DMWRITE, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ReAssociationDelay, set_WiFiDataElementsNetworkDeviceRadioBSSSTA_ReAssociationDelay, BBFDM_BOTH, "2.15"},
{"TIDQueueSizesNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TIDQueueSizesNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MultiAPSTA. *** */
//DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"SteeringSummaryStats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStatsParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{"SteeringHistory", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryInst, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams, NULL, BBFDM_BOTH, LIST_KEY{"Time", "APOrigin", "APDestination", NULL}, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"AssociationTime", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_AssociationTime, NULL, BBFDM_BOTH, "2.15"},
//{"Noise", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Noise, NULL, BBFDM_BOTH, "2.15"},
//{"SteeringHistoryNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_SteeringHistoryNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{"Disassociate()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Disassociate, operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_Disassociate, BBFDM_USP, "2.15"},
//{"BTMRequest()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest, operate_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTA_BTMRequest, BBFDM_USP, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MultiAPSTA.SteeringSummaryStats. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"NoCandidateAPFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_NoCandidateAPFailures, NULL, BBFDM_BOTH, "2.15"},
//{"BlacklistAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistAttempts, NULL, BBFDM_BOTH, "2.15"},
//{"BlacklistSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistSuccesses, NULL, BBFDM_BOTH, "2.15"},
//{"BlacklistFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BlacklistFailures, NULL, BBFDM_BOTH, "2.15"},
//{"BTMAttempts", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMAttempts, NULL, BBFDM_BOTH, "2.15"},
//{"BTMSuccesses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMSuccesses, NULL, BBFDM_BOTH, "2.15"},
//{"BTMFailures", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMFailures, NULL, BBFDM_BOTH, "2.15"},
//{"BTMQueryResponses", &DMREAD, DMT_UNLONG, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_BTMQueryResponses, NULL, BBFDM_BOTH, "2.15"},
//{"LastSteerTime", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringSummaryStats_LastSteerTime, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MultiAPSTA.SteeringHistory.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistoryParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"Time", &DMREAD, DMT_TIME, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_Time, NULL, BBFDM_BOTH, "2.15"},
//{"APOrigin", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APOrigin, NULL, BBFDM_BOTH, "2.15"},
//{"TriggerEvent", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_TriggerEvent, NULL, BBFDM_BOTH, "2.15"},
//{"SteeringApproach", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringApproach, NULL, BBFDM_BOTH, "2.15"},
//{"APDestination", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_APDestination, NULL, BBFDM_BOTH, "2.15"},
//{"SteeringDuration", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAMultiAPSTASteeringHistory_SteeringDuration, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.WiFi6Capabilities. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6CapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_HE160, NULL, BBFDM_BOTH, "2.15"},
//{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_HE8080, NULL, BBFDM_BOTH, "2.15"},
//{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MCSNSS, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_SUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_SUBeamformee, NULL, BBFDM_BOTH, "2.15"},
//{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_Beamformee80orLess, NULL, BBFDM_BOTH, "2.15"},
//{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_BeamformeeAbove80, NULL, BBFDM_BOTH, "2.15"},
//{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_ULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_ULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxDLMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxDLOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MaxULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_RTS, NULL, BBFDM_BOTH, "2.15"},
//{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MURTS, NULL, BBFDM_BOTH, "2.15"},
//{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MultiBSSID, NULL, BBFDM_BOTH, "2.15"},
//{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_MUEDCA, NULL, BBFDM_BOTH, "2.15"},
//{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_TWTRequestor, NULL, BBFDM_BOTH, "2.15"},
//{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_TWTResponder, NULL, BBFDM_BOTH, "2.15"},
//{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_SpatialReuse, NULL, BBFDM_BOTH, "2.15"},
//{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsNetworkDeviceRadioBSSSTAWiFi6Capabilities_AnticipatedChannelUsage, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TIDQueueSizes.{i}. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"TID", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizes_TID, NULL, BBFDM_BOTH, "2.15"},
//{"Size", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioBSSSTATIDQueueSizes_Size, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}. *** */
// DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
// {"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress, NULL, BBFDM_BOTH, "2.13"},
// {"SignalStrength", &DMREAD, DMT_UNINT, get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength, NULL, BBFDM_BOTH, "2.13"},
// {0}
//};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.MultiAPRadio. *** */
//DMLEAF tWiFiDataElementsNetworkDeviceRadioMultiAPRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"RadarDetections", &DMREAD, DMT_STRING, get_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_RadarDetections, NULL, BBFDM_BOTH, "2.15"},
//{"FullScan()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_FullScan, operate_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_FullScan, BBFDM_USP, "2.15"},
//{"ChannelScan()", &DMASYNC, DMT_COMMAND, get_operate_args_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_ChannelScan, operate_WiFiDataElementsNetworkDeviceRadioMultiAPRadio_ChannelScan, BBFDM_USP, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.AssociationEvent. *** */
DMOBJ tWiFiDataElementsAssociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"AssociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsAssociationEventAssociationEventDataInst, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataObj, tWiFiDataElementsAssociationEventAssociationEventDataParams, NULL, BBFDM_BOTH, NULL, "2.13"},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"AssociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"Associated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsAssociationEvent_Associated, NULL, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}. *** */
DMOBJ tWiFiDataElementsAssociationEventAssociationEventDataObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"WiFi6Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataWiFi6CapabilitiesParams, NULL, BBFDM_BOTH, NULL, "2.15"},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_BSSID, NULL, BBFDM_BOTH, "2.13"},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress, NULL, BBFDM_BOTH, "2.13"},
{"StatusCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode, NULL, BBFDM_BOTH, "2.13"},
{"HTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"VHTCapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities, NULL, BBFDM_BOTH, "2.13"},
{"HECapabilities", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities, NULL, BBFDM_BOTH, "2.13"},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp, NULL, BBFDM_BOTH, "2.13"},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}.WiFi6Capabilities. *** */
//DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataWiFi6CapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"HE160", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_HE160, NULL, BBFDM_BOTH, "2.15"},
//{"HE8080", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_HE8080, NULL, BBFDM_BOTH, "2.15"},
//{"MCSNSS", &DMREAD, DMT_BASE64, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MCSNSS, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"SUBeamformee", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SUBeamformee, NULL, BBFDM_BOTH, "2.15"},
//{"MUBeamformer", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MUBeamformer, NULL, BBFDM_BOTH, "2.15"},
//{"Beamformee80orLess", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_Beamformee80orLess, NULL, BBFDM_BOTH, "2.15"},
//{"BeamformeeAbove80", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_BeamformeeAbove80, NULL, BBFDM_BOTH, "2.15"},
//{"ULMUMIMO", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_ULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"ULOFDMA", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_ULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxDLMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULMUMIMO", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxULMUMIMO, NULL, BBFDM_BOTH, "2.15"},
//{"MaxDLOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxDLOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"MaxULOFDMA", &DMREAD, DMT_UNINT, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MaxULOFDMA, NULL, BBFDM_BOTH, "2.15"},
//{"RTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_RTS, NULL, BBFDM_BOTH, "2.15"},
//{"MURTS", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MURTS, NULL, BBFDM_BOTH, "2.15"},
//{"MultiBSSID", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MultiBSSID, NULL, BBFDM_BOTH, "2.15"},
//{"MUEDCA", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_MUEDCA, NULL, BBFDM_BOTH, "2.15"},
//{"TWTRequestor", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_TWTRequestor, NULL, BBFDM_BOTH, "2.15"},
//{"TWTResponder", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_TWTResponder, NULL, BBFDM_BOTH, "2.15"},
//{"SpatialReuse", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_SpatialReuse, NULL, BBFDM_BOTH, "2.15"},
//{"AnticipatedChannelUsage", &DMREAD, DMT_BOOL, get_WiFiDataElementsAssociationEventAssociationEventDataWiFi6Capabilities_AnticipatedChannelUsage, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.DisassociationEvent. *** */
DMOBJ tWiFiDataElementsDisassociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DisassociationEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsDisassociationEventDisassociationEventDataInst, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventDisassociationEventDataParams, NULL, BBFDM_BOTH, NULL, "2.13"},
{0}
};

DMLEAF tWiFiDataElementsDisassociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"DisassociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries, NULL, BBFDM_BOTH, "2.13"},
{"Disassociated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsDisassociationEvent_Disassociated, NULL, BBFDM_USP, "2.15"},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BSSID", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID, NULL, BBFDM_BOTH, "2.13"},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress, NULL, BBFDM_BOTH, "2.13"},
{"ReasonCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode, NULL, BBFDM_BOTH, "2.13"},
{"BytesSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent, NULL, BBFDM_BOTH, "2.13"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived, NULL, BBFDM_BOTH, "2.13"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent, NULL, BBFDM_BOTH, "2.13"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived, NULL, BBFDM_BOTH, "2.13"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent, NULL, BBFDM_BOTH, "2.13"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived, NULL, BBFDM_BOTH, "2.13"},
{"RetransCount", &DMREAD, DMT_UNINT, get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount, NULL, BBFDM_BOTH, "2.13"},
{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp, NULL, BBFDM_BOTH, "2.13"},
{0}
};

/* *** Device.WiFi.DataElements.FailedConnectionEvent. *** */
//DMOBJ tWiFiDataElementsFailedConnectionEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
//{"FailedConnectionEventData", &DMREAD, NULL, NULL, NULL, browseWiFiDataElementsFailedConnectionEventFailedConnectionEventDataInst, NULL, NULL, NULL, tWiFiDataElementsFailedConnectionEventFailedConnectionEventDataParams, NULL, BBFDM_BOTH, NULL, "2.15"},
//{0}
//};

//DMLEAF tWiFiDataElementsFailedConnectionEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"FailedConnectionEventDataNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiDataElementsFailedConnectionEvent_FailedConnectionEventDataNumberOfEntries, NULL, BBFDM_BOTH, "2.15"},
//{"FailedConnection!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsFailedConnectionEvent_FailedConnection, NULL, BBFDM_USP, "2.15"},
//{0}
//};

/* *** Device.WiFi.DataElements.FailedConnectionEvent.FailedConnectionEventData.{i}. *** */
//DMLEAF tWiFiDataElementsFailedConnectionEventFailedConnectionEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
//{"MACAddress", &DMREAD, DMT_STRING, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_MACAddress, NULL, BBFDM_BOTH, "2.15"},
//{"StatusCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_StatusCode, NULL, BBFDM_BOTH, "2.15"},
//{"ReasonCode", &DMREAD, DMT_UNINT, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_ReasonCode, NULL, BBFDM_BOTH, "2.15"},
//{"TimeStamp", &DMREAD, DMT_STRING, get_WiFiDataElementsFailedConnectionEventFailedConnectionEventData_TimeStamp, NULL, BBFDM_BOTH, "2.15"},
//{0}
//};
