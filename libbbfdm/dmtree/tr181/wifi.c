/*
 * Copyright (C) 2023 IOPSYS Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *	Author: Saurabh Verma <saurabh.verma@iopsys.eu>
 *
 */

#include "wifi.h"

#ifdef BBF_WIFI_DATAELEMENTS
#include "wifi.dataelements.h"
#endif

#define MAX_POWER_INDEX 64
#define UBUS_OBJ_LEN 32

struct wifi_radio_args
{
	struct dmmap_dup *sections;
	int transmit_power[MAX_POWER_INDEX];
	int power_count;
};

struct wifi_ssid_args
{
	struct uci_section *config_s;
	struct uci_section *dmmap_s;
	char *ifname;
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

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_wifi_radio(struct wifi_radio_args *args, struct dmmap_dup *s)
{
	char *device = NULL;
	json_object *res = NULL, *arrobj = NULL, *power = NULL;
	int i = 0, j = 0, ind = 0;

	args->sections = s;
	device = section_name(s->config_section);
	if (DM_STRLEN(device) == 0)
		return 0;

	dmubus_call("iwinfo", "txpowerlist", UBUS_ARGS{{"device", device, String}}, 1, &res);
	dmjson_foreach_obj_in_array(res, arrobj, power, i, 1, "results") {
		char *dbm = dmjson_get_value(power, 1, "dbm");
		if (!dbm)
			continue;
		int power = (int)strtod(dbm, NULL);
		if (ind < MAX_POWER_INDEX) {
			args->transmit_power[ind] = power;
			ind++;
		}
	}

	args->power_count = ind;
	/* sort the power list */
	for (i = 0; i < ind; i++)  {
		for (j = i + 1; j < ind; j++) {
			if (args->transmit_power[i] > args->transmit_power[j]) {
				int tmp =  args->transmit_power[i];
				args->transmit_power[i] = args->transmit_power[j];
				args->transmit_power[j] = tmp;
			}
		}
	}

	return 0;
}

static inline int init_wifi_ssid(struct wifi_ssid_args *args, struct uci_section *config_s, struct uci_section *dmmap_s, char *ifname)
{
	args->config_s = config_s;
	args->dmmap_s = dmmap_s;
	args->ifname = ifname;
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
	char object[UBUS_OBJ_LEN];

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

static struct uci_section *find_mapcontroller_section(struct uci_section *wireless_s)
{
	struct uci_section *s = NULL;
	char *device = NULL;
	char *ssid = NULL;
	char *band = NULL;

	if (!file_exists("/etc/config/mapcontroller") || !wireless_s)
		return NULL;

	dmuci_get_value_by_section_string(wireless_s, "ssid", &ssid);
	dmuci_get_value_by_section_string(wireless_s, "device", &device);
	band = get_radio_option_nocache(device, "band");

	uci_foreach_sections("mapcontroller", "ap", s) {
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
	struct uci_section *dmmap = NULL;
	char ssid[32] = {0}, ifname[32] = {0};

	snprintf(ssid, sizeof(ssid), "ssid_%s", *instance);
	snprintf(ifname, sizeof(ifname), "wl%s", *instance);

	dmuci_add_section_bbfdm("dmmap_wireless", "ssid", &dmmap);
	dmuci_set_value_by_section(dmmap, "enabled", "0");
	dmuci_set_value_by_section(dmmap, "ifname", ifname);
	dmuci_set_value_by_section(dmmap, "ssid", ssid);
	dmuci_set_value_by_section(dmmap, "name", ssid);
	dmuci_set_value_by_section(dmmap, "added_by_user", "1");
	dmuci_set_value_by_section(dmmap, "ssid_instance", *instance);
	return 0;
}

static int delete_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *ssid_s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			if (((struct wifi_ssid_args *)data)->config_s) {
				dmuci_delete_by_section(((struct wifi_ssid_args *)data)->config_s, "device", NULL);
				dmuci_delete_by_section(((struct wifi_ssid_args *)data)->config_s, "ifname", NULL);
				dmuci_delete_by_section(((struct wifi_ssid_args *)data)->config_s, "ssid", NULL);
			}

			dmuci_delete_by_section(((struct wifi_ssid_args *)data)->dmmap_s, NULL, NULL);
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_wireless", "ssid", stmp, ssid_s) {
				struct uci_section *s = NULL;
				char *ifname = NULL;

				dmuci_get_value_by_section_string(ssid_s, "ifname", &ifname);

				s = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", ifname);
				if (s) {
					dmuci_delete_by_section(s, "device", NULL);
					dmuci_delete_by_section(s, "ifname", NULL);
					dmuci_delete_by_section(s, "ssid", NULL);
				}

				dmuci_delete_by_section(ssid_s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int add_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_wifi = NULL;
	char s_name[32] = {0};

	snprintf(s_name, sizeof(s_name), "wlan_ap_%s", *instance);

	dmuci_add_section("wireless", "wifi-iface", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "disabled", "1");
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_wifi, "ap_instance", *instance);
	return 0;
}

static int delete_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *ap_s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((((struct wifi_acp_args *)data)->sections)->dmmap_section, NULL, NULL);
			dmuci_delete_by_section((((struct wifi_acp_args *)data)->sections)->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("wireless", "wifi-iface", stmp, ap_s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ap_s), &dmmap_section);
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

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.WiFi.Radio.{i}.!UCI:wireless/wifi-device/dmmap_wireless*/
static int browseWifiRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct wifi_radio_args curr_wifi_radio_args;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	memset(&curr_wifi_radio_args, 0, sizeof(struct wifi_radio_args));

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

static void dmmap_synchronizeWiFiSSID(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;
	char *user_s = NULL, *ifname = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_wireless", "ssid", stmp, s) {

		// section added by user ==> skip it
		dmuci_get_value_by_section_string(s, "added_by_user", &user_s);
		if (DM_LSTRCMP(user_s, "1") == 0)
			continue;

		// check config section ==> if it exists then skip it
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		ss = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", ifname);
		if (ss)
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_sections("wireless", "wifi-iface", s) {
		char *disabled = NULL, *ssid = NULL, *device = NULL;

		// if ifname is empty ==> skip it
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (DM_STRLEN(ifname) == 0)
			continue;

		// if dmmap section exits ==> skip it
		ss = get_dup_section_in_dmmap_opt("dmmap_wireless", "ssid", "ifname", ifname);
		if (ss)
			continue;

		dmuci_get_value_by_section_string(s, "disabled", &disabled);
		dmuci_get_value_by_section_string(s, "ssid", &ssid);
		dmuci_get_value_by_section_string(s, "device", &device);

		dmuci_add_section_bbfdm("dmmap_wireless", "ssid", &ss);
		dmuci_set_value_by_section(ss, "enabled", DM_STRLEN(disabled) ? ((*disabled == '1') ? "0" : "1") : "1");
		dmuci_set_value_by_section(ss, "ifname", ifname);
		dmuci_set_value_by_section(ss, "ssid", ssid);
		dmuci_set_value_by_section(ss, "device", device);
		dmuci_set_value_by_section(ss, "name", section_name(s));
	}
}

/*#Device.WiFi.SSID.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWifiSsidInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_ssid_args curr_wifi_ssid_args = {0};
	struct uci_section *dmmap_s = NULL;
	char *inst = NULL;

	dmmap_synchronizeWiFiSSID(dmctx, parent_node, prev_data, prev_instance);

	uci_path_foreach_sections(bbfdm, "dmmap_wireless", "ssid", dmmap_s) {
		struct uci_section *config_s = NULL;
		char *ifname = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "ifname", &ifname);

		config_s = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", ifname);

		init_wifi_ssid(&curr_wifi_ssid_args, config_s, dmmap_s, ifname);

		inst = handle_instance(dmctx, parent_node, dmmap_s, "ssid_instance", "ssid_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_ssid_args, inst) == DM_STOP)
			break;
	}
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
		char *mode = NULL, *ifname = NULL;

		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if (DM_LSTRCMP(mode, "ap") != 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);

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
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_wifi_neighboring", "result", s) {
		inst = handle_instance(dmctx, parent_node, s, "wifineighbor_instance", "wifineighbor_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
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

static int get_wifi_ssid_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->dmmap_s, "enabled", value);
	return 0;
}

static int set_wifi_ssid_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *map_s = NULL;
	char *multi_ap = NULL;
	bool b;

	map_s = find_mapcontroller_section(((struct wifi_ssid_args *)data)->config_s);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->config_s, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			string_to_bool(value, &b);

			// wireless config: Update disabled option
			if (((struct wifi_ssid_args *)data)->config_s)
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->config_s, "disabled", b ? "0" : "1");

			// mapcontroller config: Update the corresponding ap section if exists
			if (map_s)
				dmuci_set_value_by_section(map_s, "enabled", b ? "1" : "0");

			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->dmmap_s, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_wifi_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname = NULL;

	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->dmmap_s, "ifname", &ifname);
	return get_net_device_status(ifname, value);
}

/*#Device.WiFi.SSID.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
static int get_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->dmmap_s, "ssid", value);
	return 0;
}

static int set_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *map_s = NULL;
	char *multi_ap = NULL;

	map_s = find_mapcontroller_section(((struct wifi_ssid_args *)data)->config_s);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 32, NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->config_s, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			// wireless config: Update ssid option
			if (((struct wifi_ssid_args *)data)->config_s)
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->config_s, "ssid", value);

			// mapcontroller config: Update the corresponding ap section if exists
			if (map_s)
				dmuci_set_value_by_section(map_s, "ssid", value);

			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->dmmap_s, "ssid", value);
			return 0;
	}
	return 0;
}

static int get_wlan_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->dmmap_s, "name", value);
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

static int get_radio_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.wireless", "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "Down");

	char *isup = dmjson_get_value(res, 2, section_name((((struct wifi_radio_args *)data)->sections)->config_section), "up");
	*value = (DM_STRCMP(isup, "false") == 0) ? "Down" : "Up";
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
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
	char bandwidth_list[128], object[UBUS_OBJ_LEN];
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
			if (bbfdm_validate_string(ctx, value, -1, -1, SupportedOperatingChannelBandwidth, NULL))
				return FAULT_9007;

			// Get the list of all supported operating channel bandwidths
			get_WiFiRadio_SupportedOperatingChannelBandwidths(refparam, ctx, data, instance, &supported_bandwidths);

			// Check if the input value is a valid channel bandwidth value
			if (!value_exits_in_str_list(supported_bandwidths, ",", value)) {
				bbfdm_set_fault_message(ctx, "'%s' bandwidth is not supported by this radio. Possible bandwidths are [%s].", value, supported_bandwidths);
				return FAULT_9007;
			}

			break;
		case VALUESET:
			sscanf(value, "%d", &freq);

			dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "htmode", &curr_htmode);

			if (DM_LSTRNCMP(curr_htmode, "EHT", 3) == 0)
				snprintf(htmode, sizeof(htmode), "EHT%d", freq);
			else if (DM_LSTRNCMP(curr_htmode, "VHT", 3) == 0)
				snprintf(htmode, sizeof(htmode), "VHT%d", freq);
			else if (DM_LSTRNCMP(curr_htmode, "HT", 2) == 0)
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
			if (bbfdm_validate_string(ctx, value, -1, -1, PreambleType, NULL))
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "doth", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiRadio_TransmitPowerSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i = 0, len = 0;
	char supported_list[125] = {0};
	int space_left = sizeof(supported_list);

	snprintf(supported_list, sizeof(supported_list), "-1,");
	space_left = space_left - 3;

	struct wifi_radio_args *args = (struct wifi_radio_args *)data;

	if (args->power_count <= 0)
		goto end;

	int max_power = args->transmit_power[args->power_count - 1];

	for (i = 0; i < args->power_count; i++) {
		int percent = ceil((double)(args->transmit_power[i] * 100) / max_power);
		char strval[4] = {0};
		snprintf(strval, sizeof(strval), "%d", percent);

		if (space_left >= strlen(strval) + 1) {
			snprintf(supported_list + strlen(supported_list), space_left, "%s,", strval);
			space_left = space_left - (strlen(strval) + 1);
		}
	}

end:
	len = strlen(supported_list);
	if ((len > 0) && (supported_list[len -1] == ','))
		supported_list[len - 1] = '\0';

	*value = dmstrdup(supported_list);
	return 0;
}

static int get_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_radio_args *args = (struct wifi_radio_args *)data;
	char *config = dmuci_get_value_by_section_fallback_def((args->sections)->config_section, "txpower", "-1");
	if (DM_STRCMP(config, "-1") == 0) {
		*value = "-1";
		return 0;
	}

	if (args->power_count <= 0)
		return 0;

	int max_power = args->transmit_power[args->power_count - 1];
	int dbm = (int)strtod(config, NULL);
	int percent = ceil((double)(dbm * 100) / max_power);

	dmasprintf(value, "%d", percent);

	return 0;
}

static int set_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_list = NULL;
	bool found = false;
	struct wifi_radio_args *args = (struct wifi_radio_args *)data;

	switch (action)	{
		case VALUECHECK:
			get_WiFiRadio_TransmitPowerSupported(refparam, ctx, data, instance, &supported_list);
			if (!supported_list)
				return FAULT_9007;

			/* check if requested value is present in supported list */
			char *token;
			char *rest= supported_list;
			while ((token = strtok_r(rest, ",", &rest))) {
				if (DM_STRCMP(value, token) == 0) {
					found = true;
					break;
				}
			}

			if (found == false)
				return FAULT_9007;

			break;
		case VALUESET:
			if (DM_STRCMP(value, "-1") == 0) {
				dmuci_set_value_by_section((args->sections)->config_section, "txpower", "");
				break;
			}

			if (args->power_count <= 0)
				break;

			int max_power = args->transmit_power[args->power_count - 1];
			int req_val = (int)strtod(value, NULL);
			int percent = (int)round((max_power * req_val) / 100);

			char str_val[10] = {0};
			snprintf(str_val, sizeof(str_val), "%d", percent);
			dmuci_set_value_by_section((args->sections)->config_section, "txpower", str_val);
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
			if (bbfdm_validate_string(ctx, value, 2, 3, NULL, RegulatoryDomain))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->dmmap_section, "country", value);

			// uci only support country code, so strip I/O from value before setting
			if (DM_STRLEN(value) == 3)
				value[2] = '\0';

			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "country", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.PossibleChannels!UBUS:wifi.radio.@Name/status//supp_channels[0].channels*/
static int get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL, *arrobj = NULL;
	char object[UBUS_OBJ_LEN], *cur_opclass = NULL;
	int i = 0;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	cur_opclass = dmjson_get_value(res, 1, "opclass");
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		char *opclass = dmjson_get_value(supp_channels, 1, "opclass");
		if (DM_STRCMP(opclass, cur_opclass) != 0)
			continue;

		*value = dmjson_get_value_array_all(supp_channels, ",", 1, "channels");
		break;
	}
	return 0;
}

static int get_radio_channels_in_use(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_radio_option_nocache(section_name((((struct wifi_radio_args *)data)->sections)->config_section), "channel");
	return 0;
}

static int get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *channel = NULL;

	dmuci_get_value_by_section_string((((struct wifi_radio_args *)data)->sections)->config_section, "channel", &channel);

	if (DM_LSTRCMP(channel, "auto") == 0 || DM_STRLEN(channel) == 0)
		channel = get_radio_option_nocache(section_name((((struct wifi_radio_args *)data)->sections)->config_section), "channel");

	*value = channel;
	return 0;
}

static int set_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *supported_channels = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","255"}}, 1))
				return FAULT_9007;

			// Get the list of all supported channels
			get_radio_possible_channels(refparam, ctx, data, instance, &supported_channels);

			// Check if the input value is a valid channel
			if (!value_exits_in_str_list(supported_channels, ",", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "channel", value);
			return 0;
	}
	return 0;
}

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
			if (bbfdm_validate_boolean(ctx, value))
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

/*#Device.WiFi.AccessPoint.{i}.SSIDAdvertisementEnabled!UCI:wireless/wifi-iface,@i-1/hidden*/
static int get_wlan_ap_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "hidden", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_wlan_ap_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "hidden", b ? "0" : "1");
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, 17, NULL, MACAddress))
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_boolean(ctx, value))
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

static void set_security_mode(struct uci_section *wireless_s, struct uci_section *map_s, char *value)
{
	char *wpa_key = NULL;
	char *mode = get_security_mode(wireless_s);

	// Use default key only in case the key is not set
	dmuci_get_value_by_section_string(wireless_s, "key", &wpa_key);
	if (DM_STRLEN(wpa_key) == 0)
		wpa_key = get_default_wpa_key();

	if (mode && DM_STRCMP(value, mode) != 0) {
		// Only reset the wlan key section if its belongs to different group
		if (is_different_group(value, mode))
			reset_wlan(wireless_s);
		dmuci_set_value_by_section(wireless_s, "ieee80211w", "0");

		if (DM_LSTRCMP(value, "None") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "none");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "none");
		} else if (DM_LSTRCMP(value, "WEP-64") == 0) {
			char key[16], buf[11];
			int i;

			generate_wep_key("iopsys", buf, sizeof(buf));
			for (i = 0; i < 4; i++) {
				snprintf(key, sizeof(key), "key%d", i + 1);
				dmuci_set_value_by_section(wireless_s, key, buf);
			}
			dmuci_set_value_by_section(wireless_s, "encryption", "wep-open");
			dmuci_set_value_by_section(wireless_s, "key", "1");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "none");
		} else if (DM_LSTRCMP(value, "WEP-128") == 0) {
			char key[16], buf[27];
			int i;

			generate_wep_key("iopsys_wep128", buf, sizeof(buf));
			for (i = 0; i < 4; i++) {
				snprintf(key, sizeof(key), "key%d", i + 1);
				dmuci_set_value_by_section(wireless_s, key, buf);
			}
			dmuci_set_value_by_section(wireless_s, "encryption", "wep-open");
			dmuci_set_value_by_section(wireless_s, "key", "1");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "none");
		} else if (DM_LSTRCMP(value, "WPA-Personal") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "psk");
			dmuci_set_value_by_section(wireless_s, "key", wpa_key);
			dmuci_set_value_by_section(wireless_s, "wpa_group_rekey", "3600");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "psk");
			if (map_s) dmuci_set_value_by_section(map_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA-Enterprise") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "wpa");
			dmuci_set_value_by_section(wireless_s, "auth_port", "1812");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "wpa");
		} else if (DM_LSTRCMP(value, "WPA2-Personal") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "psk2");
			dmuci_set_value_by_section(wireless_s, "key", wpa_key);
			dmuci_set_value_by_section(wireless_s, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(wireless_s, "wps_pushbutton", "1");
			dmuci_set_value_by_section(wireless_s, "ieee80211w", "1");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "psk2");
			if (map_s) dmuci_set_value_by_section(map_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA2-Enterprise") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "wpa2");
			dmuci_set_value_by_section(wireless_s, "auth_port", "1812");
			dmuci_set_value_by_section(wireless_s, "ieee80211w", "1");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "wpa2");
		} else if (DM_LSTRCMP(value, "WPA-WPA2-Personal") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "psk-mixed");
			dmuci_set_value_by_section(wireless_s, "key", wpa_key);
			dmuci_set_value_by_section(wireless_s, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(wireless_s, "wps_pushbutton", "1");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "psk-mixed");
			if (map_s) dmuci_set_value_by_section(map_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA-WPA2-Enterprise") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "wpa-mixed");
			dmuci_set_value_by_section(wireless_s, "auth_port", "1812");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "wpa-mixed");
		} else if (DM_LSTRCMP(value, "WPA3-Personal") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "sae");
			dmuci_set_value_by_section(wireless_s, "key", wpa_key);
			dmuci_set_value_by_section(wireless_s, "ieee80211w", "2");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "sae");
			if (map_s) dmuci_set_value_by_section(map_s, "key", wpa_key);
		} else if (DM_LSTRCMP(value, "WPA3-Enterprise") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "wpa3");
			dmuci_set_value_by_section(wireless_s, "auth_port", "1812");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "wpa");
		} else if (DM_LSTRCMP(value, "WPA3-Personal-Transition") == 0) {
			dmuci_set_value_by_section(wireless_s, "encryption", "sae-mixed");
			dmuci_set_value_by_section(wireless_s, "key", wpa_key);
			dmuci_set_value_by_section(wireless_s, "ieee80211w", "1");

			if (map_s) dmuci_set_value_by_section(map_s, "encryption", "sae-mixed");
			if (map_s) dmuci_set_value_by_section(map_s, "key", wpa_key);
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
	struct uci_section *map_s = NULL;
	char *supported_modes = NULL;
	char *multi_ap = NULL;

	map_s = find_mapcontroller_section((((struct wifi_acp_args *)data)->sections)->config_section);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;

			// Get the list of all supported security modes
			get_access_point_security_supported_modes(refparam, ctx, data, instance, &supported_modes);

			// Check if the input value is a valid security mode
			if (!value_exits_in_str_list(supported_modes, ",", value))
				return FAULT_9007;

			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			set_security_mode((((struct wifi_acp_args *)data)->sections)->config_section, map_s, value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_wepkey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *map_s = NULL;
	char *encryption;
	char *multi_ap = NULL;

	map_s = find_mapcontroller_section((((struct wifi_acp_args *)data)->sections)->config_section);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{"5","5"},{"13","13"}}, 2))
				return FAULT_9007;

			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (DM_LSTRSTR(encryption, "wep")) {
				char *key_index = NULL, buf[16];

				dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "key", &key_index);
				snprintf(buf, sizeof(buf),"key%s", key_index ? key_index : "1");

				// wireless config: Update key option
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, buf, value);

				// mapcontroller config: Update the corresponding ap section if exists
				if (map_s)
					dmuci_set_value_by_section(map_s, buf, value);
			}
			return 0;
	}
	return 0;
}

static int set_access_point_security_shared_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *map_s = NULL;
	char *encryption = NULL;
	char *multi_ap = NULL;

	map_s = find_mapcontroller_section((((struct wifi_acp_args *)data)->sections)->config_section);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{NULL,"32"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (DM_LSTRSTR(encryption, "psk")) {

				// wireless config: Update key option
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", value);

				// mapcontroller config: Update the corresponding ap section if exists
				if (map_s)
					dmuci_set_value_by_section(map_s, "key", value);
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
			if (bbfdm_validate_string(ctx, value, 8, 63, NULL, NULL))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
	struct uci_section *map_s = NULL;
	char *encryption = NULL;
	char *multi_ap = NULL;

	map_s = find_mapcontroller_section((((struct wifi_acp_args *)data)->sections)->config_section);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", &encryption);
			if (DM_LSTRSTR(encryption, "sae")) {

				// wireless config: Update key option
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", value);

				// mapcontroller config: Update the corresponding ap section if exists
				if (map_s)
					dmuci_set_value_by_section(map_s, "key", value);
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
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPAddress))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, MFPConfig, NULL))
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

/*#Device.WiFi.AccessPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps_pushbutton*/
static int get_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_acp_args *)data)->sections)->config_section, "wps_pushbutton", "0");
	return 0;
}

static int set_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wps_pushbutton", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiAccessPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton";
	return 0;
}

static int get_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton";
	return 0;
}

static int set_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (DM_STRCMP(value, "PushButton") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			// Don't do anything since we only support 'PushButton'
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps_pushbutton*/
static int get_WiFiAccessPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "wps_pushbutton", &wps_status);
	*value = (wps_status[0] == '1') ? "Configured" : "Disabled";
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
		return USP_FAULT_COMMAND_FAILURE;

	snprintf(object, sizeof(object), "hostapd.%s", ifname);
	ubus_ret = dmubus_call_set(object, "wps_start", UBUS_ARGS{0}, 0);
	if (ubus_ret != 0)
		status = "Error_Not_Ready";

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
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
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPAddress))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

static int get_WiFiEndPoint_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname = NULL;

	dmuci_get_value_by_section_string((((struct wifi_enp_args *)data)->sections)->config_section, "ifname", &ifname);
	return get_net_device_status(ifname, value);
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
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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

static int get_WiFiEndPointStats_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.backhaul.%s", ((struct wifi_enp_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 3, "stats", "rx_rate_latest", "rate");
	return 0;
}

static int get_WiFiEndPointStats_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.backhaul.%s", ((struct wifi_enp_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 3, "stats", "tx_rate_latest", "rate");
	return 0;
}

static int get_WiFiEndPointStats_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.backhaul.%s", ((struct wifi_enp_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "rssi");
	return 0;
}

static int get_WiFiEndPointStats_Retransmissions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.backhaul.%s", ((struct wifi_enp_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "stats", "tx_pkts_retries");
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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
			if (bbfdm_validate_string(ctx, value, -1, 32, NULL, NULL))
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
	struct uci_section *map_s = NULL;
	char *supported_modes = NULL;
	char *multi_ap = NULL;

	map_s = find_mapcontroller_section((((struct wifi_acp_args *)data)->sections)->config_section);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;

			// Get the list of all supported security modes
			get_WiFiEndPointSecurity_ModesSupported(refparam, ctx, data, instance, &supported_modes);

			// Check if the input value is a valid security mode
			if (!value_exits_in_str_list(supported_modes, ",", value))
				return FAULT_9007;

			dmuci_get_value_by_section_string((struct uci_section *)data, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			set_security_mode((struct uci_section *)data, map_s, value);
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_WEPKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{"5","5"},{"13","13"}}, 2))
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
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{NULL,"32"}}, 1))
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
			if (bbfdm_validate_string(ctx, value, 8, 63, NULL, NULL))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, MFPConfig, NULL))
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

/*#Device.WiFi.EndPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps_pushbutton*/
static int get_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct wifi_enp_args *)data)->sections)->config_section, "wps_pushbutton", "0");
	return 0;
}

static int set_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct wifi_enp_args *)data)->sections)->config_section, "wps_pushbutton", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiEndPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton";
	return 0;
}

static int get_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton";
	return 0;
}

static int set_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (DM_STRCMP(value, "PushButton") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			// Don't do anything since we only support 'PushButton'
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps_pushbutton*/
static int get_WiFiEndPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string((((struct wifi_enp_args *)data)->sections)->config_section, "wps_pushbutton", &wps_status);
	*value = (wps_status[0] == '1') ? "Configured" : "Disabled";
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
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->dmmap_s, "ssid_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->dmmap_s, "ssid_alias", value);
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
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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
	char *device = NULL;

	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->dmmap_s, "device", &device);
	adm_entry_get_linker_param(ctx, "Device.WiFi.Radio.", device, value);
	return 0;
}

static int set_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.WiFi.Radio.", NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->dmmap_s, "device", linker ? linker : "");

			if (((struct wifi_ssid_args *)data)->config_s)
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->config_s, "device", linker ? linker : "");
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
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);

			if (linker) {
				struct uci_section *ss = NULL;
				char *device = NULL, *ssid = NULL, *enabled = NULL;

				ss = get_dup_section_in_dmmap_opt("dmmap_wireless", "ssid", "ifname", linker);

				dmuci_get_value_by_section_string(ss, "device", &device);
				dmuci_get_value_by_section_string(ss, "ssid", &ssid);
				dmuci_get_value_by_section_string(ss, "enabled", &enabled);

				bool b = dmuci_string_to_boolean(enabled);

				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "device", device);
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "ssid", ssid);
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");

				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "ifname", linker);
			} else {
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "ifname", "");
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "ssid", "");
				dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "device", "");
			}
			break;
	}
	return 0;
}

static int set_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (file_exists("/etc/bbfdm/dmmap/dmmap_wifi_neighboring"))
				remove("/etc/bbfdm/dmmap/dmmap_wifi_neighboring");

			dmuci_add_section_bbfdm("dmmap_wifi_neighboring", "diagnostic_status", &s);
			dmuci_set_value_by_section(s, "DiagnosticsState", value);
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
	char object[UBUS_OBJ_LEN];

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
	char object[UBUS_OBJ_LEN];

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

/*#Device.WiFi.AccessPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_access_point_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "disabled", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_access_point_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *map_s = NULL;
	char *multi_ap = NULL;
	bool b;

	map_s = find_mapcontroller_section((((struct wifi_acp_args *)data)->sections)->config_section);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			dmuci_get_value_by_section_string((((struct wifi_acp_args *)data)->sections)->config_section, "multi_ap", &multi_ap);
			if (DM_STRLEN(multi_ap) && !map_s)
				return FAULT_9007;

			return 0;
		case VALUESET:
			string_to_bool(value, &b);

			// wireless config: Update disabled option
			dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "disabled", b ? "0" : "1");

			// mapcontroller config: Update the corresponding ap section if exists
			if (map_s)
				dmuci_set_value_by_section(map_s, "enabled", b ? "1" : "0");

			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Status!UBUS:wifi.ap.@Name/status//status*/
static int get_wifi_access_point_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32], *status = NULL;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "Disabled");
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
	char object[UBUS_OBJ_LEN];

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
	char object[UBUS_OBJ_LEN];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name((((struct wifi_radio_args *)data)->sections)->config_section));
	dmubus_call(object, "status", UBUS_ARGS{0}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value_array_all(res, ",", 1, "supp_bands");
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/status//band*/
static int get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[UBUS_OBJ_LEN];

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
			if (bbfdm_validate_string(ctx, value, -1, -1, SupportedFrequencyBands, NULL))
				return FAULT_9007;

			// Get the list of all supported frequency bands
			get_radio_supported_frequency_bands(refparam, ctx, data, instance, &supported_frequency_bands);

			// Check if the input value is a supported band value
			if (!value_exits_in_str_list(supported_frequency_bands, ",", value)) {
				bbfdm_set_fault_message(ctx, "'%s' band is not supported by this radio. Possible bands are [%s].", value, supported_frequency_bands);
				return FAULT_9007;
			}

			break;
		case VALUESET:
			dmuci_set_value_by_section((((struct wifi_radio_args *)data)->sections)->config_section, "band", (value[0] == '6') ? "6g" : (value[0] == '5') ? "5g" : "2g");
			break;
	}
	return 0;
}

static int get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_bbfdm("dmmap_wifi_neighboring", "@diagnostic_status[0]", "DiagnosticsState", value);
	if ((*value)[0] == '\0')
		*value = "None";
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
	dmuci_get_value_by_section_string((struct uci_section *)data, "ssid", value);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BSSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].bssid*/
static int get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "bssid", value);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Channel!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].channel*/
static int get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "channel", value);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SignalStrength!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].rssi*/
static int get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rssi", value);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].band*/
static int get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "band", value);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Noise!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].noise*/
static int get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "noise", value);
	return 0;
}

/*#Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth!UBUS:wifi.radio.@Name/status//bandwidth*/
static int get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[UBUS_OBJ_LEN];

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
	char list_supp_std[32], object[UBUS_OBJ_LEN];
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
	char standard_list[32] = {0};
	char object[UBUS_OBJ_LEN] = {0};

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
	char *bandwidth = NULL;
	char *pch, *spch;
	char buf[16], htmode[8];

	switch (action) {
			case VALUECHECK:
				if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, -1, SupportedStandards, NULL))
					return FAULT_9007;

				// Get the list of all supported standards
				get_radio_supported_standard(refparam, ctx, data, instance, &supported_standards);

				// Check if the input value is a valid standard value
				snprintf(buf, sizeof(buf), "%s", value);
				for (pch = strtok_r(buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
					if (!value_exits_in_str_list(supported_standards, ",", pch)) {
						bbfdm_set_fault_message(ctx, "'%s' standard is not supported by this radio. Possible standards are [%s].", pch, supported_standards);
						return FAULT_9007;
					}
				}

				break;
			case VALUESET:
				bandwidth = get_radio_option_nocache(section_name((((struct wifi_radio_args *)data)->sections)->config_section), "bandwidth");
				if (DM_STRLEN(bandwidth) == 0)
					bandwidth = "20";

				if (DM_LSTRSTR(value, "be"))
					snprintf(htmode, sizeof(htmode), "EHT%s", bandwidth);
				else if (DM_LSTRSTR(value, "ax"))
					snprintf(htmode, sizeof(htmode), "HE%s", bandwidth);
				else if (DM_LSTRSTR(value, "ac"))
					snprintf(htmode, sizeof(htmode), "VHT%s", bandwidth);
				else if (DM_LSTRSTR(value, "n"))
					snprintf(htmode, sizeof(htmode), "HT%s", bandwidth);
				else
					snprintf(htmode, sizeof(htmode), "NOHT");

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


/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_WiFi_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return !dmcmd_no_wait("/sbin/wifi", 1, "reload") ? 0 : USP_FAULT_COMMAND_FAILURE;
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
			char object[UBUS_OBJ_LEN] = {0};
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

				if (ctx->dm_type != BBFDM_USP) {
					struct uci_section *dmmap_s = NULL;
					dmuci_add_section_bbfdm("dmmap_wifi_neighboring", "result", &dmmap_s);
					dmuci_set_value_by_section(dmmap_s, "ssid", ssid[1]);
					dmuci_set_value_by_section(dmmap_s, "bssid", bssid[1]);
					dmuci_set_value_by_section(dmmap_s, "channel", channel[1]);
					dmuci_set_value_by_section(dmmap_s, "rssi", signal_strength[1]);
					dmuci_set_value_by_section(dmmap_s, "band", frequency[1]);
					dmuci_set_value_by_section(dmmap_s, "noise", noise[1]);
				}

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

		if (ctx->dm_type != BBFDM_USP) {
			dmuci_set_value_bbfdm("dmmap_wifi_neighboring", "@diagnostic_status[0]", "DiagnosticsState", "Complete");
			dmuci_commit_package_bbfdm("dmmap_wifi_neighboring");
		}
	}

	return 0;
}

static int operate_WiFiAccessPointSecurity_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "encryption", "psk");
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "key", get_default_wpa_key());
	dmuci_set_value_by_section((((struct wifi_acp_args *)data)->sections)->config_section, "wps_pushbutton", "1");

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.WiFi. *** */
DMOBJ tWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
#ifdef BBF_WIFI_DATAELEMENTS
{"DataElements", &DMREAD, NULL, NULL, "file:/etc/init.d/decollector", NULL, NULL, NULL, tWiFiDataElementsObj, NULL, NULL, BBFDM_BOTH, NULL, "2.13"},
#endif
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
{"ChannelsInUse", &DMREAD, DMT_STRING, get_radio_channels_in_use, NULL, BBFDM_BOTH, "2.0"},
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
{"TransmitPowerSupported", &DMREAD, DMT_STRING, get_WiFiRadio_TransmitPowerSupported, NULL, BBFDM_BOTH, "2.0"},
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
{"Enable", &DMWRITE, DMT_BOOL, get_wifi_ssid_enable, set_wifi_ssid_enable, BBFDM_BOTH, "2.0"},
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
{"Enable", &DMWRITE, DMT_BOOL,  get_access_point_enable, set_access_point_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_wifi_access_point_status, NULL, BBFDM_BOTH, "2.0"},
{"SSIDReference", &DMWRITE, DMT_STRING, get_ap_ssid_ref, set_ap_ssid_ref, BBFDM_BOTH, "2.0"},
{"SSIDAdvertisementEnabled", &DMWRITE, DMT_BOOL, get_wlan_ap_advertisement_enable, set_wlan_ap_advertisement_enable, BBFDM_BOTH, "2.0"},
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
//{"PIN", &DMWRITE, DMT_STRING, get_empty, set_WiFiAccessPointWPS_PIN, BBFDM_BOTH, "2.11"},
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
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
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

/* *** Device.WiFi.EndPoint.{i}.Stats. *** */
DMLEAF tWiFiEndPointStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataDownlinkRate, NULL, BBFDM_BOTH, "2.0"},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataUplinkRate, NULL, BBFDM_BOTH, "2.0"},
{"SignalStrength", &DMREAD, DMT_INT, get_WiFiEndPointStats_SignalStrength, NULL, BBFDM_BOTH, "2.0"},
{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_Retransmissions, NULL, BBFDM_BOTH, "2.0"},
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
//{"PIN", &DMWRITE, DMT_UNINT, get_WiFiEndPointWPS_PIN, set_WiFiEndPointWPS_PIN, BBFDM_BOTH, "2.11"},
{0}
};
