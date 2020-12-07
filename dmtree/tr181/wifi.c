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
#include "wepkey.h"
#include "wifi.h"
#include "os.h"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_Wifi_Radio(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct wifi_radio_args *)data)->wifi_radio_sec)
		*linker = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
	else
		*linker = "";
	return 0;
}

static int get_linker_Wifi_Ssid(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct wifi_ssid_args *)data)->ifname)
		*linker = ((struct wifi_ssid_args *)data)->ifname;
	else
		*linker = "";
	return 0;
}

static int get_linker_associated_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data)
		*linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	else
		*linker = "";
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_wifi_radio(struct wifi_radio_args *args, struct uci_section *s)
{
	args->wifi_radio_sec = s;
	return 0;
}

static inline int init_wifi_ssid(struct wifi_ssid_args *args, struct uci_section *s, char *wiface, char *linker)
{
	args->wifi_ssid_sec = s;
	args->ifname = wiface;
	args->linker = linker;
	return 0;
}

static inline int init_wifi_acp(struct wifi_acp_args *args, struct uci_section *s, char *wiface)
{
	args->wifi_acp_sec = s;
	args->ifname = wiface;
	return 0;
}

static inline int init_wifi_enp(struct wifi_enp_args *args, struct uci_section *s, char *wiface)
{
	args->wifi_enp_sec = s;
	args->ifname = wiface;
	return 0;
}
/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.RadioNumberOfEntries!UCI:wireless/wifi-device/*/
static int get_WiFi_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;

	uci_foreach_sections("wireless", "wifi-device", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.SSIDNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_SSIDNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.AccessPointNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_AccessPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;
	char *mode = NULL;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		dmuci_get_value_by_section_string(s, "mode", &mode);
		if ((strlen(mode) > 0 || mode[0] != '\0') && strcmp(mode, "ap") != 0)
			continue;
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.EndPointNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_EndPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;
	char *mode = NULL;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		dmuci_get_value_by_section_string(s, "mode", &mode);
		if (strcmp(mode, "wet") == 0 || strcmp(mode, "sta") == 0)
			nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.SSID.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
/*#Device.WiFi.AccessPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", value);
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
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_wifi_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", value);
	*value = ((*value)[0] == '1') ? "Down" : "Up";
	return 0;
}


/*#Device.WiFi.SSID.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
static int get_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "ssid", value);
	return 0;
}

static int set_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "ssid", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.MACAddress!UBUS:network.device/status/name,@Name/macaddr*/
static int get_WiFiSSID_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "macaddr");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Enable!UCI:wireless/wifi-device,@i-1/disabled*/
static int get_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", value);
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.Status!UCI:wireless/wifi-device,@i-1/disabled*/
static int get_radio_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", value);
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
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_WiFiRadio_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	return 0;
}

static int set_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *freq;

	switch (action) {
			case VALUECHECK:
				if (dm_validate_string_list(value, -1, -1, -1, -1, -1, SupportedStandards, 6, NULL, 0))
					return FAULT_9007;
				return 0;
			case VALUESET:
				freq = os__get_radio_frequency_nocache(data);
				if (strcmp(freq, "5GHz") == 0) {
					 if (strcmp(value, "n") == 0)
						value = "11n"; 
					 else if (strcmp(value, "ac") == 0)
						value = "11ac";
				} else {
					if (strcmp(value, "b") == 0)
						value = "11b";
					else if (strcmp(value, "b,g") == 0 || strcmp(value, "g,b") == 0)
						value = "11bg";
					else if (strcmp(value, "g") == 0)
						value = "11g";
					 else if (strcmp(value, "n") == 0)
						value = "11n";
				}
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "hwmode", value);
				return 0;
		}
		return 0;
}

static int get_WiFiRadio_AutoChannelSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod!UCI:wireless/wifi-device,@i-1/acs_refresh_time*/
static int get_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "acs_refresh_time", "3600");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "acs_refresh_time", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxSupportedAssociations!UCI:wireless/wifi-device,@i-1/maxassoc*/
static int get_WiFiRadio_MaxSupportedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "maxassoc", "32");
	return 0;
}

/*#Device.WiFi.Radio.{i}.FragmentationThreshold!UCI:wireless/wifi-device,@i-1/frag_threshold*/
static int get_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "frag_threshold", "2346");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "frag_threshold", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RTSThreshold!UCI:wireless/wifi-device,@i-1/rts_threshold*/
static int get_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "rts_threshold", "2347");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "rts_threshold", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.BeaconPeriod!UCI:wireless/wifi-device,@i-1/beacon_int*/
static int get_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "beacon_int", "100");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "beacon_int", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.DTIMPeriod!UCI:wireless/wifi-device,@i-1/dtim_period*/
static int get_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "dtim_period", "2");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "dtim_period", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingChannelBandwidth!UCI:wireless/wifi-device,@i-1/htmode*/
static int get_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "htmode", value);
	if(*value[0] == '\0') {
		*value = "";
		return 0;
	}
	if (strncmp(*value, "NOHT", 4) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "HT20", 4) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "HT40", 4) == 0)
		*value = "40MHz";
	else if (strncmp(*value, "VHT20", 5) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "VHT40", 5) == 0)
		*value = "40MHz";
	else if (strncmp(*value, "VHT80", 5) == 0)
		*value = "80MHz";
	else if (strncmp(*value, "VHT160", 6) == 0)
		*value = "160MHz";
	else if (strncmp(*value, "HE20", 4) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "HE40", 4) == 0)
		*value = "40MHz";
	else if (strncmp(*value, "HE80", 4) == 0)
		*value = "80MHz";
	else if (strncmp(*value, "HE160", 5) == 0)
		*value = "160MHz";

	return 0;
}

static int set_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[6];
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedOperatingChannelBandwidth, 6, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			sscanf(value,"%[^M]", buf);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "bandwidth", buf);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.PreambleType!UCI:wireless/wifi-device,@i-1/short_preamble*/
static int get_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", value);
	*value = ((*value)[0] == '1') ? "short" : "long";
	return 0;
}

static int set_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, PreambleType, 3, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", (strcmp(value, "short") == 0) ? "1" : "0");
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
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", "0");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.TransmitPower!UCI:wireless/wifi-device,@i-1/txpower*/
static int get_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_radio_args *)data)->wifi_radio_sec, "txpower", "100");
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "txpower", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RegulatoryDomain!UCI:wireless/wifi-device,@i-1/country*/
static int get_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	char *conf_country, *dmmap_contry = NULL;

	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", &conf_country);

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "country", &dmmap_contry);

	dmasprintf(value, "%s%c", conf_country, (dmmap_contry && *dmmap_contry) ? dmmap_contry[2] : ' ');
	return 0;
}

static int set_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, 3, 3, NULL, 0, RegulatoryDomain, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "country", value);
			value[2] = '\0';
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", value);
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
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelEnable!UCI:wireless/wifi-device,@i-1/channel*/
static int get_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
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
				value = os__get_radio_channel_nocache(data);

			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
			return 0;
	}
	return 0;
}

/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.SSID.{i}.SSIDAdvertisementEnabled!UCI:wireless/wifi-iface,@i-1/hidden*/
static int get_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", value);
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
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", b ? "0" : "1");
			return 0;

	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WMMEnable!UCI:wireless/wifi-device,@i-1/wmm*/
static int get_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm", "1");
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MACAddressControlEnabled!UCI:wireless/wifi-iface,@i-1/macfilter*/
static int get_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *macfilter;

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", &macfilter);
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
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "maxassoc", "32");
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "maxassoc", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.IsolationEnable!UCI:wireless/wifi-iface,@i-1/isolate*/
static int get_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", "0");
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AllowedMACAddress!UCI:wireless/wifi-iface,@i-1/maclist*/
static int get_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val;
	dmuci_get_value_by_section_list(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", &val);
	if (val)
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
			if (dm_validate_string_list(value, -1, -1, -1, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", "");
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", arr[i]);
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", b ? "allow" : "disable");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.UAPSDEnable!UCI:wireless/wifi-iface,@i-1/wmm_apsd*/
static int get_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm_apsd", "0");
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm_apsd", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_access_point_security_supported_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise";
	return 0;
}

static void get_security_mode(char **value, char *encryption)
{
	if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0)
		*value = "WEP-64";
	else if (strcmp(encryption, "psk") == 0)
		*value = "WPA-Personal";
	else if (strcmp(encryption, "wpa") == 0)
		*value = "WPA-Enterprise";
	else if (strcmp(encryption, "psk2") == 0)
		*value = "WPA2-Personal";
	else if (strcmp(encryption, "wpa2") == 0)
		*value = "WPA2-Enterprise";
	else if (strcmp(encryption, "mixed-psk") == 0)
		*value = "WPA-WPA2-Personal";
	else if (strcmp(encryption, "wpa-mixed") == 0 || strcmp(encryption, "mixed-wpa") == 0)
		*value = "WPA-WPA2-Enterprise";
	else
		*value = "None";
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

static void set_security_mode(struct uci_section *section, char *value)
{
	char *encryption, *mode;

	dmuci_get_value_by_section_string(section, "encryption", &encryption);
	get_security_mode(&mode, encryption);

	if (strcmp(value, mode) != 0) {
		if (strcmp(value, "None") == 0) {
			reset_wlan(section);
			dmuci_set_value_by_section(section, "encryption", "none");
		}
		else if (strcmp(value, "WEP-64") == 0 || strcmp(value, "WEP-128") == 0) {
			reset_wlan(section);
			dmuci_set_value_by_section(section, "encryption", "wep-open");
			char *option, strk64[4][11];
			wepkey64("iopsys", strk64);
			int i;
			for (i = 0; i < 4; i++) {
				dmasprintf(&option, "key%d", i + 1);
				dmuci_set_value_by_section(section, option, strk64[i]);
				dmfree(option);
			}
			dmuci_set_value_by_section(section, "key", "1");
		}
		else if (strcmp(value, "WPA-Personal") == 0) {
			reset_wlan(section);
			char *wpa_key = os__get_default_wpa_key();
			dmuci_set_value_by_section(section, "encryption", "psk");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
		}
		else if (strcmp(value, "WPA-Enterprise") == 0) {
			reset_wlan(section);
			dmuci_set_value_by_section(section, "encryption", "wpa");
			dmuci_set_value_by_section(section, "auth_server", "");
			dmuci_set_value_by_section(section, "auth_port", "1812");
			dmuci_set_value_by_section(section, "auth_secret", "");
		}
		else if (strcmp(value, "WPA2-Personal") == 0) {
			reset_wlan(section);
			char *wpa_key = os__get_default_wpa_key();
			dmuci_set_value_by_section(section, "encryption", "psk2");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(section, "wps", "1");
		}
		else if (strcmp(value, "WPA2-Enterprise") == 0) {
			reset_wlan(section);
			dmuci_set_value_by_section(section, "encryption", "wpa2");
			dmuci_set_value_by_section(section, "auth_server", "");
			dmuci_set_value_by_section(section, "auth_port", "1812");
			dmuci_set_value_by_section(section, "auth_secret", "");
		}
		else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
			reset_wlan(section);
			char *wpa_key = os__get_default_wpa_key();
			dmuci_set_value_by_section(section, "encryption", "mixed-psk");
			dmuci_set_value_by_section(section, "key", wpa_key);
			dmuci_set_value_by_section(section, "wpa_group_rekey", "3600");
			dmuci_set_value_by_section(section, "wps", "1");
		}
		else if (strcmp(value, "WPA-WPA2-Enterprise") == 0) {
			reset_wlan(section);
			dmuci_set_value_by_section(section, "encryption", "wpa-mixed");
			dmuci_set_value_by_section(section, "auth_server", "");
			dmuci_set_value_by_section(section, "auth_port", "1812");
			dmuci_set_value_by_section(section, "auth_secret", "");
		}
	}
}

/*#Device.WiFi.AccessPoint.{i}.Security.ModeEnabled!UCI:wireless/wifi-iface,@i-1/encryption&UCI:wireless/wifi-iface,@i-1/encryption*/
static int get_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encryption;

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
	if (*encryption == '\0')
		*value = "None";
	else
		get_security_mode(value, encryption);
	return 0;
}

static int set_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			set_security_mode(((struct wifi_acp_args *)data)->wifi_acp_sec, value);
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
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 ) {
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", value);
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
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 )
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_passphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, 8, 63, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 )
				set_access_point_security_shared_key(refparam, ctx, data, instance, value, action);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval!UCI:wireless/wifi-iface,@i-1/wpa_group_rekey*/
static int get_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", "0");
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
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") != 0 && strcmp(encryption, "wep-shared") != 0 && strcmp(encryption, "none") != 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr!UCI:wireless/wifi-iface,@i-1/auth_server*/
static int get_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", value);
	return 0;
}

static int set_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort!UCI:wireless/wifi-iface,@i-1/auth_port*/
static int get_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", "1812");
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
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_radius_secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_secret", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.MFPConfig!UCI:wireless/wifi-iface,@i-1/ieee80211w*/
static int get_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211w", value);

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
			if (dm_validate_string(value, -1, -1, MFPConfig, 3, NULL, 0))
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211w", buf);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "0");
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", b ? "1" : "0");
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
	char *wps_list = NULL, *token, *saveptr;
	bool pushbut = false, label = false, pin = false;

	wps_list = dmstrdup(value);
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
	return get_wps_config_methods_enabled(((struct wifi_acp_args *)data)->wifi_acp_sec, value);
}

static int set_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			set_wps_config_methods_enabled(((struct wifi_acp_args *)data)->wifi_acp_sec, value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiAccessPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", &wps_status);
	*value = (wps_status[0] == '1') ? "Configured" : "Disabled";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.PIN!UCI:wireless/wifi-iface,@i-1/wps_pin*/
static int get_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps_pin", value);
	return 0;
}

static int set_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 8, NULL, 0, PIN, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps_pin", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerIPAddr!UCI:wireless/wifi-iface,@i-1/acct_server*/
static int get_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_server", value);
	return 0;
}

static int set_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_server", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerPort!UCI:wireless/wifi-iface,@i-1/acct_port*/
static int get_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_port", "1813");
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
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_port", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.Secret!UCI:wireless/wifi-iface,@i-1/acct_secret*/
static int get_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_secret", value);
	return 0;
}

static int set_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_secret", value);
			break;
	}
	return 0;
}

static int set_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedFrequencyBands, 2, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "hwmode", (!strcmp(value, "5GHz") ? "11a" :"11g"));
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", value);
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
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_WiFiEndPoint_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", value);
	*value = ((*value)[0] == '1') ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/endpointalias*/
static int get_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_enp_args *)data)->wifi_enp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_enp_args *)data)->wifi_enp_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "endpointalias", value);
			return 0;
	}
	return 0;
}

static int get_WiFiEndPoint_SSIDReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_enp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
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
	char *encryption;

	dmuci_get_value_by_section_string((struct uci_section *)data, "encryption", &encryption);
	if (*encryption == '\0')
		*value = "None";
	else
		get_security_mode(value, encryption);
	return 0;
}

static int set_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
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
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 ) {
				dmuci_set_value_by_section((struct uci_section*)data, "key", value);
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
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 ) {
				dmuci_set_value_by_section((struct uci_section*)data, "key", value);
			}
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_KeyPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, 8, 63, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 ) {
				set_WiFiEndPointProfileSecurity_PreSharedKey(refparam, ctx, data, instance, value, action);
			}
			return 0;
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
			if (dm_validate_string(value, -1, -1, MFPConfig, 3, NULL, 0))
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
	*value = dmuci_get_value_by_section_fallback_def(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", "0");
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
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", b ? "1" : "0");
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
	return get_wps_config_methods_enabled(((struct wifi_enp_args *)data)->wifi_enp_sec, value);
}

static int set_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			set_wps_config_methods_enabled(((struct wifi_enp_args *)data)->wifi_enp_sec, value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiEndPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", &wps_status);
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
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", value);
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
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "radioalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "radioalias", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/ssidalias*/
static int get_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ssidalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ssidalias", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/ap_alias*/
static int get_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_acp_args *)data)->wifi_acp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ap_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_acp_args *)data)->wifi_acp_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ap_alias", value);
			return 0;
	}
	return 0;
}
/*************************************************************
* GET & SET LOWER LAYER
**************************************************************/
static int get_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (data && ((struct wifi_ssid_args *)data)->linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_ssid_args *)data)->linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_acp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_wifi = NULL;
	char ssid[32] = {0};

	char *inst = get_last_instance_bbfdm("dmmap_wireless", "wifi-iface", "ssidinstance");
	snprintf(ssid, sizeof(ssid), "iopsys_%d", inst ? (atoi(inst)+1) : 1);

	dmuci_add_section("wireless", "wifi-iface", &s);
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");
	dmuci_set_value_by_section(s, "disabled", "0");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", section_name(s));
	*instance = update_instance(inst, 2, dmmap_wifi, "ssidinstance");
	return 0;
}

static int delete_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("wireless", "wifi-iface", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int add_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_wifi = NULL;
	char ssid[32] = {0};

	char *inst = get_last_instance_bbfdm("dmmap_wireless", "wifi-iface", "ap_instance");
	snprintf(ssid, sizeof(ssid), "iopsys_%d", inst ? (atoi(inst)+1) : 1);

	dmuci_add_section("wireless", "wifi-iface", &s);
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");
	dmuci_set_value_by_section(s, "disabled", "0");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", section_name(s));
	*instance = update_instance(inst, 2, dmmap_wifi, "ap_instance");
	return 0;
}

static int delete_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("wireless", "wifi-iface", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int addObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *instancepara, *instancepara1, *instancepara2;
	struct uci_section *endpoint_sec = NULL, *dmmap_sec = NULL;

	instancepara1 = get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "wet")?get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "wet"):"0";
	instancepara2 = get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "sta")?get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "sta"):"0";
	instancepara = atoi(instancepara1)>atoi(instancepara2)?dmstrdup(instancepara1):dmstrdup(instancepara2);

	dmuci_add_section("wireless", "wifi-iface", &endpoint_sec);
	dmuci_set_value_by_section(endpoint_sec, "device", "wl1");
	dmuci_set_value_by_section(endpoint_sec, "mode", "wet");
	dmuci_set_value_by_section(endpoint_sec, "network", "lan");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(endpoint_sec));
	*instance = update_instance(instancepara, 2, dmmap_sec, "endpointinstance");
	return 0;
}

static int delObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
		dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "endpointinstance", "");
		dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "mode", "");
		break;
	case DEL_ALL:
		uci_foreach_sections("wireless", "wifi-iface", s) {

			char *mode;
			dmuci_get_value_by_section_string(s, "mode", &mode);
			if (strcmp(mode, "sta") != 0 && strcmp(mode, "wet") != 0)
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
	char *inst = NULL, *max_inst = NULL;
	struct wifi_radio_args curr_wifi_radio_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-device", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_wifi_radio(&curr_wifi_radio_args, p->config_section);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "radioinstance", "radioalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_radio_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.SSID.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWifiSsidInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *ifname, *linker;
	struct wifi_ssid_args curr_wifi_ssid_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "device", &linker);
#ifdef GENERIC_OPENWRT
		ifname = get_device_from_wifi_iface(linker, section_name(p->config_section));
#else
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
#endif
		init_wifi_ssid(&curr_wifi_ssid_args, p->config_section, ifname, linker);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "ssidinstance", "ssidalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_ssid_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWifiAccessPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *ifname, *max_inst = NULL, *mode = NULL;
	struct wifi_acp_args curr_wifi_acp_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if ((strlen(mode)>0 || mode[0] != '\0') && strcmp(mode, "ap") != 0)
			continue;
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_wifi_acp(&curr_wifi_acp_args, p->config_section, ifname);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "ap_instance", "ap_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_acp_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWiFiEndPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *ifname, *max_inst = NULL, *mode= NULL;
	struct wifi_enp_args curr_wifi_enp_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if(strcmp(mode, "wet")!=0 && strcmp(mode, "sta")!=0)
			continue;
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_wifi_enp(&curr_wifi_enp_args, p->config_section, ifname);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "endpointinstance", "endpointalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_enp_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseWiFiEndPointProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *max_inst = NULL, *ep_instance;
	struct wifi_enp_args *ep_args = (struct wifi_enp_args *)prev_data;
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ep_args->wifi_enp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &ep_instance);
	s = is_dmmap_section_exist_eq("dmmap_wireless", "ep_profile", "ep_key", ep_instance);
	if (!s)
		dmuci_add_section_bbfdm("dmmap_wireless", "ep_profile", &s);
	dmuci_set_value_by_section_bbfdm(s, "ep_key", ep_instance);

	handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 3,
			s, "ep_profile_instance", "ep_profile_alias");

	DM_LINK_INST_OBJ(dmctx, parent_node, ep_args->wifi_enp_sec, "1");
	return 0;
}

int set_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				uci_foreach_sections("wireless", "wifi-device", ss)
					os__wifi_start_scan(section_name(ss));

				dmubus_call_set("tr069", "inform", UBUS_ARGS{{"event", "8 DIAGNOSTICS COMPLETE", String}}, 1);
			}
			return 0;
	}
	return 0;
}

/* *** Device.WiFi. *** */
DMOBJ tWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DataElements", &DMREAD, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsObj, NULL, NULL, BBFDM_BOTH},
{"Radio", &DMREAD, NULL, NULL, NULL, browseWifiRadioInst, NULL, tWiFiRadioObj, tWiFiRadioParams, get_linker_Wifi_Radio, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"SSID", &DMWRITE, add_wifi_ssid, delete_wifi_ssid, NULL, browseWifiSsidInst, NULL, tWiFiSSIDObj, tWiFiSSIDParams, get_linker_Wifi_Ssid, BBFDM_BOTH, LIST_KEY{"Name", "Alias", "BSSID", NULL}},
{"AccessPoint", &DMWRITE, add_wifi_accesspoint, delete_wifi_accesspoint, NULL, browseWifiAccessPointInst, NULL, tWiFiAccessPointObj, tWiFiAccessPointParams, NULL, BBFDM_BOTH, LIST_KEY{"SSIDReference", "Alias", NULL}},
{"NeighboringWiFiDiagnostic", &DMREAD, NULL, NULL, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticObj, tWiFiNeighboringWiFiDiagnosticParams, NULL, BBFDM_BOTH},
{"EndPoint", &DMWRITE, addObjWiFiEndPoint, delObjWiFiEndPoint, NULL, browseWiFiEndPointInst, NULL, tWiFiEndPointObj, tWiFiEndPointParams, NULL, BBFDM_BOTH, LIST_KEY{"SSIDReference", "Alias", NULL}},
{0}
};

DMLEAF tWiFiParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_RadioNumberOfEntries, NULL, BBFDM_BOTH},
{"SSIDNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_SSIDNumberOfEntries, NULL, BBFDM_BOTH},
{"AccessPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_AccessPointNumberOfEntries, NULL, BBFDM_BOTH},
{"EndPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_EndPointNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.Radio.{i}. *** */
DMOBJ tWiFiRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiRadioStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_radio_alias, set_radio_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_radio_enable, set_radio_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_radio_status, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_WiFiRadio_LowerLayers, set_WiFiRadio_LowerLayers, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_WiFiRadio_Name, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMREAD, DMT_UNINT, os__get_radio_max_bit_rate, NULL, BBFDM_BOTH},
{"OperatingFrequencyBand", &DMWRITE, DMT_STRING, os__get_radio_frequency, set_radio_frequency, BBFDM_BOTH},
{"SupportedFrequencyBands", &DMREAD, DMT_STRING, os__get_radio_supported_frequency_bands, NULL, BBFDM_BOTH},
{"SupportedStandards", &DMREAD, DMT_STRING, os__get_radio_supported_standard, NULL, BBFDM_BOTH},
{"OperatingStandards", &DMWRITE, DMT_STRING, os_get_radio_operating_standard, set_radio_operating_standard, BBFDM_BOTH},
{"ChannelsInUse", &DMREAD, DMT_STRING, os__get_radio_channel, NULL, BBFDM_BOTH},
{"Channel", &DMWRITE, DMT_UNINT, os__get_radio_channel, set_radio_channel, BBFDM_BOTH},
{"AutoChannelEnable", &DMWRITE, DMT_BOOL, get_radio_auto_channel_enable, set_radio_auto_channel_enable, BBFDM_BOTH},
{"PossibleChannels", &DMREAD, DMT_STRING, os__get_radio_possible_channels, NULL, BBFDM_BOTH},
{"AutoChannelSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_AutoChannelSupported, NULL, BBFDM_BOTH},
{"AutoChannelRefreshPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_AutoChannelRefreshPeriod, set_WiFiRadio_AutoChannelRefreshPeriod, BBFDM_BOTH},
{"MaxSupportedAssociations", &DMREAD, DMT_UNINT, get_WiFiRadio_MaxSupportedAssociations, NULL, BBFDM_BOTH},
{"FragmentationThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_FragmentationThreshold, set_WiFiRadio_FragmentationThreshold, BBFDM_BOTH},
{"RTSThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_RTSThreshold, set_WiFiRadio_RTSThreshold, BBFDM_BOTH},
{"BeaconPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_BeaconPeriod, set_WiFiRadio_BeaconPeriod, BBFDM_BOTH},
{"DTIMPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_DTIMPeriod, set_WiFiRadio_DTIMPeriod, BBFDM_BOTH},
{"SupportedOperatingChannelBandwidths", &DMREAD, DMT_STRING, os__get_WiFiRadio_SupportedOperatingChannelBandwidths, NULL, BBFDM_BOTH},
{"OperatingChannelBandwidth", &DMWRITE, DMT_STRING, get_WiFiRadio_OperatingChannelBandwidth, set_WiFiRadio_OperatingChannelBandwidth, BBFDM_BOTH},
{"CurrentOperatingChannelBandwidth", &DMREAD, DMT_STRING, os__get_WiFiRadio_CurrentOperatingChannelBandwidth, NULL, BBFDM_BOTH},
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
{"BytesSent", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"FCSErrorCount", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_FCSErrorCount, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic. *** */
DMOBJ tWiFiNeighboringWiFiDiagnosticObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Result", &DMREAD, NULL, NULL, NULL, os__browseWifiNeighboringWiFiDiagnosticResultInst, NULL, NULL, tWiFiNeighboringWiFiDiagnosticResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tWiFiNeighboringWiFiDiagnosticParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, os__get_neighboring_wifi_diagnostics_diagnostics_state, set_neighboring_wifi_diagnostics_diagnostics_state, BBFDM_CWMP},
{"ResultNumberOfEntries", &DMREAD, DMT_UNINT, os__get_neighboring_wifi_diagnostics_result_number_entries, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}. *** */
DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SSID", &DMREAD, DMT_STRING, os__get_neighboring_wifi_diagnostics_result_ssid, NULL, BBFDM_CWMP},
{"BSSID", &DMREAD, DMT_STRING, os__get_neighboring_wifi_diagnostics_result_bssid, NULL, BBFDM_CWMP},
{"Channel", &DMREAD, DMT_UNINT, os__get_neighboring_wifi_diagnostics_result_channel, NULL, BBFDM_CWMP},
{"SignalStrength", &DMREAD, DMT_INT, os__get_neighboring_wifi_diagnostics_result_signal_strength, NULL, BBFDM_CWMP},
{"OperatingFrequencyBand", &DMREAD, DMT_STRING, os__get_neighboring_wifi_diagnostics_result_operating_frequency_band, NULL, BBFDM_CWMP},
{"Noise", &DMREAD, DMT_INT, os__get_neighboring_wifi_diagnostics_result_noise, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.SSID.{i}. *** */
DMOBJ tWiFiSSIDObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiSSIDStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiSSIDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_ssid_alias, set_ssid_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_wifi_enable, set_wifi_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_wifi_status, NULL, BBFDM_BOTH},
{"SSID", &DMWRITE, DMT_STRING, get_wlan_ssid, set_wlan_ssid, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING,  get_wlan_ssid, set_wlan_ssid, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ssid_lower_layer, set_ssid_lower_layer, BBFDM_BOTH},
{"BSSID", &DMREAD, DMT_STRING, os__get_wlan_bssid, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiSSID_MACAddress, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.SSID.{i}.Stats. *** */
DMLEAF tWiFiSSIDStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_ErrorsSent, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_RetransCount, NULL, BBFDM_BOTH},
{"FailedRetransCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_FailedRetransCount, NULL, BBFDM_BOTH},
{"RetryCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_RetryCount, NULL, BBFDM_BOTH},
{"MultipleRetryCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_MultipleRetryCount, NULL, BBFDM_BOTH},
{"ACKFailureCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_ACKFailureCount, NULL, BBFDM_BOTH},
{"AggregatedPacketCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_AggregatedPacketCount, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}. *** */
DMOBJ tWiFiAccessPointObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Security", &DMWRITE, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointSecurityParams, NULL, BBFDM_BOTH},
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, os__browse_wifi_associated_device, NULL, tWiFiAccessPointAssociatedDeviceObj, tWiFiAccessPointAssociatedDeviceParams, get_linker_associated_device, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointWPSParams, NULL, BBFDM_BOTH},
{"Accounting", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAccountingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_access_point_alias, set_access_point_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL,  get_wifi_enable, set_wifi_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_wifi_access_point_status, NULL, BBFDM_BOTH},
{"SSIDReference", &DMREAD, DMT_STRING, get_ap_ssid_ref, NULL, BBFDM_BOTH},
{"SSIDAdvertisementEnabled", &DMWRITE, DMT_BOOL, get_wlan_ssid_advertisement_enable, set_wlan_ssid_advertisement_enable, BBFDM_BOTH},
{"WMMEnable", &DMWRITE, DMT_BOOL, get_wmm_enabled, set_wmm_enabled, BBFDM_BOTH},
{"UAPSDEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_UAPSDEnable, set_WiFiAccessPoint_UAPSDEnable, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, os__get_access_point_total_associations, NULL, BBFDM_BOTH},
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
{"ModeEnabled", &DMWRITE, DMT_STRING ,get_access_point_security_modes, set_access_point_security_modes, BBFDM_BOTH},
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_wepkey, BBFDM_BOTH},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_shared_key, BBFDM_BOTH},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_passphrase, BBFDM_BOTH},
{"RekeyingInterval", &DMWRITE, DMT_UNINT, get_access_point_security_rekey_interval, set_access_point_security_rekey_interval, BBFDM_BOTH},
{"RadiusServerIPAddr", &DMWRITE, DMT_STRING, get_access_point_security_radius_ip_address, set_access_point_security_radius_ip_address, BBFDM_BOTH},
{"RadiusServerPort", &DMWRITE, DMT_UNINT, get_access_point_security_radius_server_port, set_access_point_security_radius_server_port, BBFDM_BOTH},
{"RadiusSecret", &DMWRITE, DMT_STRING,get_empty, set_access_point_security_radius_secret, BBFDM_BOTH},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiAccessPointSecurity_MFPConfig, set_WiFiAccessPointSecurity_MFPConfig, BBFDM_BOTH},
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
{"PIN", &DMWRITE, DMT_STRING, get_WiFiAccessPointWPS_PIN, set_WiFiAccessPointWPS_PIN, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}. *** */
DMOBJ tWiFiAccessPointAssociatedDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAssociatedDeviceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointAssociatedDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Active", &DMREAD, DMT_BOOL, os__get_WiFiAccessPointAssociatedDevice_Active, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_INT, os__get_WiFiAccessPointAssociatedDevice_Noise, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING , os__get_WiFiAccessPointAssociatedDevice_MACAddress, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, os__get_WiFiAccessPointAssociatedDevice_LastDataDownlinkRate, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, os__get_WiFiAccessPointAssociatedDevice_LastDataUplinkRate, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_INT, os__get_WiFiAccessPointAssociatedDevice_SignalStrength, NULL, BBFDM_BOTH},
//{"Retransmissions", &DMREAD, DMT_UNINT, os__get_WiFiAccessPointAssociatedDevice_Retransmissions, NULL, BBFDM_BOTH},
{"AssociationTime", &DMREAD, DMT_TIME, os__get_WiFiAccessPointAssociatedDevice_AssociationTime, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats. *** */
DMLEAF tWiFiAccessPointAssociatedDeviceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_tx_bytes, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_rx_bytes, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_tx_packets, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_rx_packets, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_tx_errors, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_retrans_count, NULL, BBFDM_BOTH},
//{"FailedRetransCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_failed_retrans_count, NULL, BBFDM_BOTH},
//{"RetryCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_retry_count, NULL, BBFDM_BOTH},
//{"MultipleRetryCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_multiple_retry_count, NULL, BBFDM_BOTH},
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
{"Secret", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_Secret, set_WiFiAccessPointAccounting_Secret, BBFDM_BOTH},
//{"SecondarySecret", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondarySecret, set_WiFiAccessPointAccounting_SecondarySecret, BBFDM_BOTH},
//{"InterimInterval", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_InterimInterval, set_WiFiAccessPointAccounting_InterimInterval, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}. *** */
DMOBJ tWiFiEndPointObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointStatsParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointSecurityParams, NULL, BBFDM_BOTH},
{"Profile", &DMREAD, NULL, NULL, NULL, browseWiFiEndPointProfileInst, NULL, tWiFiEndPointProfileObj, tWiFiEndPointProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "SSID", "Location", "Priority", NULL}},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointWPSParams, NULL, BBFDM_BOTH},
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

/* *** Device.WiFi.EndPoint.{i}.Stats. *** */
DMLEAF tWiFiEndPointStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataDownlinkRate, NULL, BBFDM_BOTH},
//{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataUplinkRate, NULL, BBFDM_BOTH},
//{"SignalStrength", &DMREAD, DMT_INT, get_WiFiEndPointStats_SignalStrength, NULL, BBFDM_BOTH},
//{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_Retransmissions, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Security. *** */
DMLEAF tWiFiEndPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"ModesSupported", &DMREAD, DMT_STRING, get_WiFiEndPointSecurity_ModesSupported, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}. *** */
DMOBJ tWiFiEndPointProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointProfileSecurityParams, NULL, BBFDM_BOTH},
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Network", &DMREAD, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkObj, tWiFiDataElementsNetworkParams, NULL, BBFDM_BOTH},
{"AssociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsAssociationEventObj, tWiFiDataElementsAssociationEventParams, NULL, BBFDM_BOTH},
{"DisassociationEvent", &DMREAD, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsDisassociationEventObj, tWiFiDataElementsDisassociationEventParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network. *** */
DMOBJ tWiFiDataElementsNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Device", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceInst, NULL, tWiFiDataElementsNetworkDeviceObj, tWiFiDataElementsNetworkDeviceParams, NULL, BBFDM_BOTH, LIST_KEY{"ID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ID", &DMWRITE, DMT_STRING, os__get_WiFiDataElementsNetwork_ID, os__set_WiFiDataElementsNetwork_ID, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetwork_TimeStamp, NULL, BBFDM_BOTH},
{"ControllerID", &DMWRITE, DMT_STRING, os__get_WiFiDataElementsNetwork_ControllerID, os__set_WiFiDataElementsNetwork_ControllerID, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetwork_DeviceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Radio", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioInst, NULL, tWiFiDataElementsNetworkDeviceRadioObj, tWiFiDataElementsNetworkDeviceRadioParams, NULL, BBFDM_BOTH, LIST_KEY{"ID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDevice_ID, NULL, BBFDM_BOTH},
//{"MultiAPCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDevice_MultiAPCapabilities, NULL, BBFDM_BOTH},
{"CollectionInterval", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDevice_CollectionInterval, NULL, BBFDM_BOTH},
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"BackhaulSta", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams, NULL, BBFDM_BOTH},
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj, tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfile", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}},
{"BSS", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioBSSInst, NULL, tWiFiDataElementsNetworkDeviceRadioBSSObj, tWiFiDataElementsNetworkDeviceRadioBSSParams, NULL, BBFDM_BOTH, LIST_KEY{"BSSID", NULL}},
{"ScanResult", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioScanResultInst, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultObj, tWiFiDataElementsNetworkDeviceRadioScanResultParams, NULL, BBFDM_BOTH},
{"UnassociatedSTA", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ID", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadio_ID, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, os__get_WiFiDataElementsNetworkDeviceRadio_Enabled, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_Noise, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_Utilization, NULL, BBFDM_BOTH},
{"Transmit", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_Transmit, NULL, BBFDM_BOTH},
{"ReceiveSelf", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf, NULL, BBFDM_BOTH},
{"ReceiveOther", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther, NULL, BBFDM_BOTH},
{"CurrentOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
{"UnassociatedSTANumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries, NULL, BBFDM_BOTH},
{"BSSNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries, NULL, BBFDM_BOTH},
{"ScanResultNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBackhaulStaParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"CapableOperatingClassProfile", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Class", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"HTCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities, NULL, BBFDM_BOTH},
{"CapableOperatingClassProfileNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Class", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class, NULL, BBFDM_BOTH},
{"MaxTxPower", &DMREAD, DMT_INT, os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower, NULL, BBFDM_BOTH},
{"NonOperable", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable, NULL, BBFDM_BOTH},
{"NumberOfNonOperChan", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Class", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class, NULL, BBFDM_BOTH},
{"Channel", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel, NULL, BBFDM_BOTH},
{"TxPower", &DMREAD, DMT_INT, os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioBSSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"STA", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioBSSSTAParams, NULL, BBFDM_BOTH, LIST_KEY{"MACAddress", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID, NULL, BBFDM_BOTH},
{"SSID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSS_SSID, NULL, BBFDM_BOTH},
{"Enabled", &DMREAD, DMT_BOOL, os__get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp, NULL, BBFDM_BOTH},
{"UnicastBytesSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent, NULL, BBFDM_BOTH},
{"UnicastBytesReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived, NULL, BBFDM_BOTH},
{"MulticastBytesSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent, NULL, BBFDM_BOTH},
{"MulticastBytesReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived, NULL, BBFDM_BOTH},
{"BroadcastBytesSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent, NULL, BBFDM_BOTH},
{"BroadcastBytesReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived, NULL, BBFDM_BOTH},
{"EstServiceParametersBE", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE, NULL, BBFDM_BOTH},
{"EstServiceParametersBK", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK, NULL, BBFDM_BOTH},
{"EstServiceParametersVI", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI, NULL, BBFDM_BOTH},
{"EstServiceParametersVO", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO, NULL, BBFDM_BOTH},
{"STANumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioBSSSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp, NULL, BBFDM_BOTH},
{"HTCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities, NULL, BBFDM_BOTH},
{"VHTCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities, NULL, BBFDM_BOTH},
{"HECapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate, NULL, BBFDM_BOTH},
{"UtilizationReceive", &DMREAD, DMT_UNLONG, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive, NULL, BBFDM_BOTH},
{"UtilizationTransmit", &DMREAD, DMT_UNLONG, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit, NULL, BBFDM_BOTH},
{"EstMACDataRateDownlink", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink, NULL, BBFDM_BOTH},
{"EstMACDataRateUplink", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength, NULL, BBFDM_BOTH},
{"LastConnectTime", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived, NULL, BBFDM_BOTH},
//{"RetransCount", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount, NULL, BBFDM_BOTH},
{"MeasurementReport", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport, NULL, BBFDM_BOTH},
{"NumberOfMeasureReports", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports, NULL, BBFDM_BOTH},
//{"IPV4Address", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address, NULL, BBFDM_BOTH},
//{"IPV6Address", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address, NULL, BBFDM_BOTH},
{"Hostname", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"OpClassScan", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams, NULL, BBFDM_BOTH, LIST_KEY{"OperatingClass", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp, NULL, BBFDM_BOTH},
{"OpClassScanNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"ChannelScan", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams, NULL, BBFDM_BOTH, LIST_KEY{"Channel", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"OperatingClass", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass, NULL, BBFDM_BOTH},
{"ChannelScanNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}. *** */
DMOBJ tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"NeighborBSS", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst, NULL, NULL, tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams, NULL, BBFDM_BOTH, LIST_KEY{"BSSID", NULL}},
{0}
};

DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Channel", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel, NULL, BBFDM_BOTH},
{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp, NULL, BBFDM_BOTH},
{"Utilization", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise, NULL, BBFDM_BOTH},
{"NeighborBSSNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BSSID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID, NULL, BBFDM_BOTH},
{"SSID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength, NULL, BBFDM_BOTH},
{"ChannelBandwidth", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth, NULL, BBFDM_BOTH},
{"ChannelUtilization", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization, NULL, BBFDM_BOTH},
{"StationCount", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}. *** */
DMLEAF tWiFiDataElementsNetworkDeviceRadioUnassociatedSTAParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MACAddress", &DMREAD, DMT_STRING, os__get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent. *** */
DMOBJ tWiFiDataElementsAssociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
//{"AssociationEventData", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsAssociationEventAssociationEventDataInst, NULL, NULL, tWiFiDataElementsAssociationEventAssociationEventDataParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"AssociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.AssociationEvent.AssociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsAssociationEventAssociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"BSSID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsAssociationEventAssociationEventData_BSSID, NULL, BBFDM_BOTH},
//{"MACAddress", &DMREAD, DMT_STRING, os__get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress, NULL, BBFDM_BOTH},
//{"StatusCode", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode, NULL, BBFDM_BOTH},
//{"HTCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities, NULL, BBFDM_BOTH},
//{"VHTCapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities, NULL, BBFDM_BOTH},
//{"HECapabilities", &DMREAD, DMT_BASE64, os__get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities, NULL, BBFDM_BOTH},
//{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent. *** */
DMOBJ tWiFiDataElementsDisassociationEventObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
//{"DisassociationEventData", &DMREAD, NULL, NULL, NULL, os__browseWiFiDataElementsDisassociationEventDisassociationEventDataInst, NULL, NULL, tWiFiDataElementsDisassociationEventDisassociationEventDataParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiDataElementsDisassociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"DisassociationEventDataNumberOfEntries", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.DataElements.DisassociationEvent.DisassociationEventData.{i}. *** */
DMLEAF tWiFiDataElementsDisassociationEventDisassociationEventDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"BSSID", &DMREAD, DMT_STRING, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID, NULL, BBFDM_BOTH},
//{"MACAddress", &DMREAD, DMT_STRING, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress, NULL, BBFDM_BOTH},
//{"ReasonCode", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode, NULL, BBFDM_BOTH},
//{"BytesSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent, NULL, BBFDM_BOTH},
//{"BytesReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived, NULL, BBFDM_BOTH},
//{"PacketsSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent, NULL, BBFDM_BOTH},
//{"PacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived, NULL, BBFDM_BOTH},
//{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent, NULL, BBFDM_BOTH},
//{"ErrorsReceived", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived, NULL, BBFDM_BOTH},
//{"RetransCount", &DMREAD, DMT_UNINT, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount, NULL, BBFDM_BOTH},
//{"TimeStamp", &DMREAD, DMT_STRING, os__get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp, NULL, BBFDM_BOTH},
{0}
};
