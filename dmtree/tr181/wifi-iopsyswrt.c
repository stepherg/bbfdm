/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	Author: Saurabh Verma <saurabh.verma@iopsys.eu>
 *
 */

#include "os.h"

/*#Device.WiFi.SSID.{i}.BSSID!UBUS:wifi.ap.@Name/status//bssid*/
int os__get_wlan_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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
	if (!res) {
		*value = "0";
		return 0;
	}
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

static int radio_read_ubus(const struct wifi_radio_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->wifi_radio_sec));
	dmubus_call(object, "stats", UBUS_ARGS{}, 0, &res);
	if (!res) {
		*value = "0";
		return 0;
	}
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.BytesSent!UBUS:wifi.radio.@Name/stats//tx_bytes*/
int os__get_WiFiRadioStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_bytes", value);
}

/*#Device.WiFi.Radio.{i}.Stats.BytesReceived!UBUS:wifi.radio.@Name/stats//rx_bytes*/
int os__get_WiFiRadioStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_bytes", value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsSent!UBUS:wifi.radio.@Name/stats//tx_packets*/
int os__get_WiFiRadioStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsReceived!UBUS:wifi.radio.@Name/stats//rx_packets*/
int os__get_WiFiRadioStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsSent!UBUS:wifi.radio.@Name/stats//tx_error_packets*/
int os__get_WiFiRadioStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_error_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsReceived!UBUS:wifi.radio.@Name/stats//rx_error_packets*/
int os__get_WiFiRadioStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_error_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent!UBUS:wifi.radio.@Name/stats//tx_dropped_packets*/
int os__get_WiFiRadioStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_dropped_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.radio.@Name/stats//rx_dropped_packets*/
int os__get_WiFiRadioStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_dropped_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.FCSErrorCount!UBUS:wifi.radio.@Name/stats//rx_fcs_error_packets*/
int os__get_WiFiRadioStats_FCSErrorCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_fcs_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stats//tx_bytes*/
int os__get_WiFiSSIDStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_bytes", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stats//rx_bytes*/
int os__get_WiFiSSIDStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_bytes", value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stats//tx_packets*/
int os__get_WiFiSSIDStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stats//rx_packets*/
int os__get_WiFiSSIDStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stats//tx_error_packets*/
int os__get_WiFiSSIDStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsReceived!UBUS:wifi.ap.@Name/stats//rx_error_packets*/
int os__get_WiFiSSIDStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent!UBUS:wifi.ap.@Name/stats//tx_dropped_packets*/
int os__get_WiFiSSIDStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_dropped_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_dropped_packets*/
int os__get_WiFiSSIDStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_dropped_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_unicast_packets*/
int os__get_WiFiSSIDStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_unicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unicast_packets*/
int os__get_WiFiSSIDStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_unicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_multicast_packets*/
int os__get_WiFiSSIDStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_multicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_multicast_packets*/
int os__get_WiFiSSIDStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_multicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_broadcast_packets*/
int os__get_WiFiSSIDStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_broadcast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_broadcast_packets*/
int os__get_WiFiSSIDStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_broadcast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_packets*/
int os__get_WiFiSSIDStats_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retrans_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.FailedRetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_fail_packets*/
int os__get_WiFiSSIDStats_FailedRetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retrans_fail_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetryCount!UBUS:wifi.ap.@Name/stats//tx_retry_packets*/
int os__get_WiFiSSIDStats_RetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retry_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MultipleRetryCount!UBUS:wifi.ap.@Name/stats//tx_multi_retry_packets*/
int os__get_WiFiSSIDStats_MultipleRetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_multi_retry_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ACKFailureCount!UBUS:wifi.ap.@Name/stats//ack_fail_packets*/
int os__get_WiFiSSIDStats_ACKFailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "ack_fail_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.AggregatedPacketCount!UBUS:wifi.ap.@Name/stats//aggregate_packets*/
int os__get_WiFiSSIDStats_AggregatedPacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "aggregate_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unknown_packets*/
int os__get_WiFiSSIDStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_unknown_packets", value);
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_total_bytes*/
int os__get_access_point_associative_device_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_total_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_data_bytes*/
int os__get_access_point_associative_device_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_data_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_total_pkts*/
int os__get_access_point_associative_device_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_total_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_data_pkts*/
int os__get_access_point_associative_device_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_data_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_failures*/
int os__get_access_point_associative_device_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_failures");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_pkts_retries*/
int os__get_access_point_associative_device_statistics_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_pkts_retries");
	return 0;
}


/*#Device.WiFi.AccessPoint.{i}.Status!UBUS:wifi.ap.@Name/status//status*/
int os_get_wifi_access_point_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char object[32], *status = NULL, *iface;

	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", &iface);
	snprintf(object, sizeof(object), "wifi.ap.%s", iface);
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, status = "");
	status = dmjson_get_value(res, 1, "status");

	if (strcmp(status, "running") == 0 || strcmp(status, "up") == 0)
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxBitRate!UBUS:wifi.radio.@Name/status//maxrate*/
int os__get_radio_max_bit_rate (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "maxrate");
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/status//band*/
int os__get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "band");
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedFrequencyBands!UBUS:wifi.radio.@Name/status//supp_bands*/
int os__get_radio_supported_frequency_bands(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value_array_all(res, DELIMITOR, 1, "supp_bands");
	return 0;
}

/*#Device.WiFi.Radio.{i}.ChannelsInUse!UCI:wireless/wifi-device,@i-1/channel*/
int os__get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0') {
		char object[32];
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
		dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
		DM_ASSERT(res, *value = "");
		*value = dmjson_get_value(res, 1, "channel");
	}
	return 0;
}

char * os__get_radio_channel_nocache(const struct wifi_radio_args *args)
{
	char object[32];
	char *value = "";
	json_object *res;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	if (res)
		value = dmjson_get_value(res, 1, "channel");

	return value;
}

char * os__get_radio_frequency_nocache(const struct wifi_radio_args *args)
{
	char object[32];
	json_object *res;
	char *freq = "";

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	if (res)
		freq = dmjson_get_value(res, 1, "band");

	return freq;
}

int os__get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	json_object *res = NULL, *neighboring_wifi_obj = NULL;
	char object[32];

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

int os__get_neighboring_wifi_diagnostics_result_number_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	json_object *res = NULL, *accesspoints = NULL;
	size_t entries = 0, result = 0;
	char object[32];
	*value = "0";

	uci_foreach_sections("wireless", "wifi-device", ss) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(ss));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		if (res) {
			json_object_object_get_ex(res, "accesspoints", &accesspoints);
			if (accesspoints)
				entries = json_object_array_length(accesspoints);
		}
		result = result + entries;
		entries = 0;
	}
	dmasprintf(value, "%d", result); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

void os__wifi_start_scan(const char *radio)
{
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", radio);
	dmubus_call_set(object, "scan", UBUS_ARGS{}, 0);
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].ssid*/
int os__get_neighboring_wifi_diagnostics_result_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ssid");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BSSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].bssid*/
int os__get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "bssid");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Channel!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].channel*/
int os__get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "channel");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SignalStrength!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].rssi*/
int os__get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].band*/
int os__get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "band");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Noise!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].noise*/
int os__get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "noise");
	return 0;
}

/*#Device.WiFi.Radio.{i}.PossibleChannels!UBUS:wifi.radio.@Name/status//supp_channels[0].channels*/
int os__get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL, *arrobj = NULL;
	char object[32], *cur_opclass = NULL;
	int i = 0;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	cur_opclass = dmjson_get_value(res, 1, "opclass");
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		char *opclass = dmjson_get_value(supp_channels, 1, "opclass");
		if (opclass && strcmp(opclass, cur_opclass) != 0)
			continue;

		*value = dmjson_get_value_array_all(supp_channels, DELIMITOR, 1, "channels");
		break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths!UBUS:wifi.radio.@Name/status//supp_channels[0].bandwidth*/
int os__get_WiFiRadio_SupportedOperatingChannelBandwidths(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL, *arrobj = NULL;
	char object[32], *bandwidth = NULL, *bandwidth_list = "";
	int i = 0;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, arrobj, supp_channels, i, 1, "supp_channels") {
		bandwidth = dmjson_get_value(supp_channels, 1, "bandwidth");
		if (bandwidth && !strstr(bandwidth_list, !strcmp(bandwidth, "8080") ? "80+80" : !strcmp(bandwidth, "80") ? ",80MHz" : bandwidth)) {
			if (*bandwidth_list == '\0')
				dmasprintf(&bandwidth_list, "%sMHz", !strcmp(bandwidth, "8080") ? "80+80" : bandwidth);
			else {
				char *tmp = dmstrdup(bandwidth_list);
				dmfree(bandwidth_list);
				dmasprintf(&bandwidth_list, "%s,%sMHz", tmp, !strcmp(bandwidth, "8080") ? "80+80" : bandwidth);
				dmfree(tmp);
			}
		}
	}
	*value = bandwidth_list;
	return 0;
}

/*#Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth!UBUS:wifi.radio.@Name/status//bandwidth*/
int os__get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char object[32], *bandwidth = NULL;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	bandwidth = dmjson_get_value(res, 1, "bandwidth");
	if (bandwidth)
		dmasprintf(value, "%sMHz", bandwidth);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.!UBUS:wifi.radio.@Name/scanresults//accesspoints*/
int os__browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *ss;
	json_object *res = NULL, *accesspoints = NULL, *arrobj = NULL;
	char object[32], *inst, *max_inst = NULL;
	int id = 0, i = 0;

	uci_foreach_sections("wireless", "wifi-device", ss) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(ss));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		if (res) {
			dmjson_foreach_obj_in_array(res, arrobj, accesspoints, i, 1, "accesspoints") {
				inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)accesspoints, inst) == DM_STOP)
					return 0;
			}
		}
	}
	return 0;
}

static int get_radio_standards(struct uci_section *section, char **value)
{
	json_object *res;
	char object[32], *standard = NULL;
	char **standards = NULL, *str_append = NULL;
	int i;
	size_t length;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(section));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");

	standard = dmjson_get_value(res, 1, "standard");
	standards = strsplit(standard, "/", &length);

	for (i = 0; i < length; i++) {
		if (strstr(standards[i], "802.11") == standards[i])
			str_append = dmstrdup(strstr(standards[i], "802.11") + strlen("802.11"));
		else
			str_append = dmstrdup(standards[i]);
		if (strlen(*value) == 0){
			dmasprintf(value, "%s", str_append);
			continue;
		}
		dmasprintf(value, "%s,%s", *value, str_append);
		FREE(str_append);
	}

	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedStandards!UBUS:wifi.radio.@Name/status//standard*/
int os__get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_radio_standards(((struct wifi_radio_args *)data)->wifi_radio_sec, value);
}

/*#Device.WiFi.Radio.{i}.OperatingStandards!UBUS:wifi.radio.@Name/status//standard*/
int os_get_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_radio_standards(((struct wifi_radio_args *)data)->wifi_radio_sec, value);
}

int os__get_access_point_total_associations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *assoclist = NULL, *arrobj = NULL;
	char object[32];
	int i = 0, entries = 0;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)data)->ifname);
	dmubus_call(object, "assoclist", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, assoclist, i, 1, "assoclist") {
			entries++;
		}
	}
	dmasprintf(value, "%d", entries);
	return 0;
}

int os__browse_wifi_associated_device(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *stations = NULL, *arrobj = NULL;
	char object[32], *inst, *max_inst = NULL;
	int id = 0, i = 0;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)prev_data)->ifname);
	dmubus_call(object, "stations", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, stations, i, 1, "stations") {
			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)stations, inst) == DM_STOP)
				return 0;
		}
	}
	return 0;
}

char * os__get_default_wpa_key()
{
	char *wpakey;
	db_get_value_string("hw", "board", "wpa_key", &wpakey);
	return wpakey;
}

/**************************************************************************
 * *** Device.WiFi.DataElements. *** *
 ***************************************************************************/

/*#Device.WiFi.DataElements.Network.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ID*/
int os__get_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "ID");
	}
	return 0;
}

int os__set_WiFiDataElementsNetwork_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.TimeStamp!UBUS:wifi.dataelements.collector/dump//description*/
int os__get_WiFiDataElementsNetwork_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "TimeStamp");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.ControllerID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.ControllerID*/
int os__get_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "ControllerID");
	}
	return 0;
}

int os__set_WiFiDataElementsNetwork_ControllerID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.DeviceNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[@i-1].wfa-dataelements:Network.NumberOfDevices*/
int os__get_WiFiDataElementsNetwork_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int i;
	json_object *res, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
		json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
		*value = dmjson_get_value(net_obj, 1, "NumberOfDevices");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].ID*/
int os__get_WiFiDataElementsNetworkDevice_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ID");
	return 0;
}

#if 0
int os__get_WiFiDataElementsNetworkDevice_MultiAPCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.WiFi.DataElements.Network.Device.{i}.CollectionInterval!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].CollectionInterval*/
int os__get_WiFiDataElementsNetworkDevice_CollectionInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "CollectionInterval");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.RadioNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].NumberOfRadios*/
int os__get_WiFiDataElementsNetworkDevice_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfRadios");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ID*/
int os__get_WiFiDataElementsNetworkDeviceRadio_ID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Enabled*/
int os__get_WiFiDataElementsNetworkDeviceRadio_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Noise*/
int os__get_WiFiDataElementsNetworkDeviceRadio_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Utilization*/
int os__get_WiFiDataElementsNetworkDeviceRadio_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Transmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Transmit*/
int os__get_WiFiDataElementsNetworkDeviceRadio_Transmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Transmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveSelf!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].ReceiveSelf*/
int os__get_WiFiDataElementsNetworkDeviceRadio_ReceiveSelf(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ReceiveSelf");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ReceiveOther!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].RecieveOther*/
int os__get_WiFiDataElementsNetworkDeviceRadio_ReceiveOther(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "RecieveOther");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfCurrOpClass*/
int os__get_WiFiDataElementsNetworkDeviceRadio_CurrentOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfCurrOpClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfUnassocSta*/
int os__get_WiFiDataElementsNetworkDeviceRadio_UnassociatedSTANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfUnassocSta");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfBSS*/
int os__get_WiFiDataElementsNetworkDeviceRadio_BSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfBSS");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResultNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].NumberOfScanRes*/
int os__get_WiFiDataElementsNetworkDeviceRadio_ScanResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int num_scanres = 0;
	json_object *scanres_arr = NULL;

	json_object_object_get_ex((json_object *)data, "ScanResultList", &scanres_arr);
	if (scanres_arr)
		num_scanres = json_object_array_length(scanres_arr);

	dmasprintf(value, "%d", num_scanres);
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BackhaulSta.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BackhaulSta.MACAddress*/
int os__get_WiFiDataElementsNetworkDeviceRadioBackhaulSta_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *backsta_obj = NULL;

	if (data) {
		json_object_object_get_ex((json_object *)data, "BackhaulSta", &backsta_obj);
		if (backsta_obj)
			*value = dmjson_get_value(backsta_obj, 1, "MACAddress");
	}
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HTCapabilities*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "HTCapabilities");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.VHTCapabilities*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "VHTCapabilities");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.HECapabilities*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "HECapabilities");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfileNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.NumberOfOpClass*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilities_CapableOperatingClassProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *caps_obj = NULL;

	json_object_object_get_ex((json_object *)data, "Capabilites", &caps_obj);
	if (caps_obj)
		*value = dmjson_get_value(caps_obj, 1, "NumberOfOpClass");

	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].Class*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.MaxTxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].MaxTxPower*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_MaxTxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MaxTxPower");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NonOperable!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NonOperable*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NonOperable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NonOperable");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.Capabilities.CapableOperatingClassProfile.{i}.NumberOfNonOperChan!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].Capabilites.OperatingClasses[@i-1].NumberOfNonOperChan*/
int os__get_WiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfile_NumberOfNonOperChan(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfNonOperChan");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Class!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Class*/
int os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Class(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Class");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].Channel*/
int os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TxPower!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TxPower*/
int os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TxPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TxPower");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.CurrentOperatingClassProfile.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].CurrentOperatingClasses[@i-1].TimeStamp*/
int os__get_WiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfile_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BSSID*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].SSID*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.Enabled!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].Enabled*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_Enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Enabled");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.LastChange!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].LastChange*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastChange");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].TimeStamp*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesSent*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.UnicastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].UnicastBytesReceived*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_UnicastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UnicastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesSent*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.MulticastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].MulticastBytesReceived*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_MulticastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MulticastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesSent*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.BroadcastBytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].BroadcastBytesReceived*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_BroadcastBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BroadcastBytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBE!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBE*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBE");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersBK!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersBK*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersBK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersBK");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersVI!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersVI*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVI");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.EstServiceParametersVO!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].EstServiceParametersVO*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_EstServiceParametersVO(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstServiceParametersVO");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STANumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberofSTA*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSS_STANumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberofSTA");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].MACAddress*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].TimeStamp*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HTCapabilities*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "HTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.VHTCapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].VHTCapabilities*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "VHTCapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.HECapabilities!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].HECapabilities*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "HECapabilities");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataDownlinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataDownlinkRate*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastDataDownlinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastDataUplinkRate!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastDataUplinkRate*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastDataUplinkRate");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationReceive!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationReceive*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationReceive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UtilizationReceive");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.UtilizationTransmit!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].UtilizationTransmit*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_UtilizationTransmit(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "UtilizationTransmit");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateDownlink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateDownlink*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateDownlink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstMACDataRateDownlink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.EstMACDataRateUplink!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].EstMACDataRateUplink*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_EstMACDataRateUplink(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "EstMACDataRateUplink");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].SignalStrength*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.LastConnectTime!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].LastConnectTime*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_LastConnectTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "LastConnectTime");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesSent*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BytesSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.BytesReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].BytesReceived*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BytesReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsSent*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "PacketsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.PacketsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].PacketsReceived*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "PacketsReceived");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsSent!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsSent*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ErrorsSent");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.ErrorsReceived!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].ErrorsReceived*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ErrorsReceived");
	return 0;
}

#if 0
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.MeasurementReport!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Measurementreport*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_MeasurementReport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Measurementreport");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.NumberOfMeasureReports!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].NumberOfMeasureReports*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_NumberOfMeasureReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfMeasureReports");
	return 0;
}

#if 0
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_IPV6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.BSS.{i}.STA.{i}.Hostname!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].STAList[@i-1].Hostname*/
int os__get_WiFiDataElementsNetworkDeviceRadioBSSSTA_Hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Hostname");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].TimeStamp*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResult_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].NumberOfOpClassScans*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResult_OpClassScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfOpClassScans");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.OperatingClass!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].OperatingClass*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_OperatingClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "OperatingClass");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScanNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].NumberOfChannelScans*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScan_ChannelScanNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberOfChannelScans");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Channel!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Channel*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Channel");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.TimeStamp!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].TimeStamp*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "TimeStamp");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Utilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Utilization*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Utilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Utilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.Noise!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].Noise*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "Noise");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSSNumberOfEntries!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NumberofNeighbors*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScan_NeighborBSSNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "NumberofNeighbors");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.BSSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].BSSID*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "BSSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SSID!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SSID*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SSID");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].SignalStrengh*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrengh");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelBandwidth!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelBandwidth*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ChannelBandwidth");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.ChannelUtilization!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].ChannelUtilization*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_ChannelUtilization(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ChannelUtilization");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.ScanResult.{i}.OpClassScan.{i}.ChannelScan.{i}.NeighborBSS.{i}.StationCount!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].BSSList[@i-1].ScanResultList[@i-1].OpClassScanList[@i-1].ChannelScanList[@i-1].NeighborList[@i-1].StationCount*/
int os__get_WiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSS_StationCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "StationCount");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.MACAddress!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].MACAddress*/
int os__get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "MACAddress");
	return 0;
}

/*#Device.WiFi.DataElements.Network.Device.{i}.Radio.{i}.UnassociatedSTA.{i}.SignalStrength!UBUS:wifi.dataelements.collector/dump//data[0].wfa-dataelements:Network.DeviceList[@i-1].RadioList[@i-1].UnassociatedStaList[@i-1].SignalStrength*/
int os__get_WiFiDataElementsNetworkDeviceRadioUnassociatedSTA_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "SignalStrength");
	return 0;
}

#if 0
int os__get_WiFiDataElementsAssociationEvent_AssociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_StatusCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_HTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_VHTCapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_HECapabilities(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsAssociationEventAssociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEvent_DisassociationEventDataNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_BSSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_ReasonCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os__get_WiFiDataElementsDisassociationEventDisassociationEventData_TimeStamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*************************************************************
 * ENTRY METHOD
 **************************************************************/
int os__browseWiFiDataElementsNetworkDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int i, j, id = 0;
	char *inst = NULL, *max_inst = NULL;
	json_object *res = NULL, *data_arr = NULL, *data_obj = NULL, *net_obj = NULL;
	json_object *dev_arr = NULL, *dev_obj = NULL;

	dmubus_call("wifi.dataelements.collector", "dump", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, data_arr, data_obj, i, 1, "data") {
			json_object_object_get_ex(data_obj, "wfa-dataelements:Network", &net_obj);
			dmjson_foreach_obj_in_array(net_obj, dev_arr, dev_obj, j, 1, "DeviceList") {
				inst = handle_update_instance(1, dmctx, &max_inst, update_instance_without_section, 1, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dev_obj, inst) == DM_STOP)
					break;
			}
		}
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *radio_arr = NULL, *radio_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, radio_arr, radio_obj, i, 1, "RadioList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)radio_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioCurrentOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, opclass_arr, opclass_obj, i, 1, "CurrentOperatingClasses") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *bss_arr = NULL, *bss_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, bss_arr, bss_obj, i, 1, "BSSList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)bss_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioScanResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *scanres_arr = NULL, *scanres_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, scanres_arr, scanres_obj, i, 1, "ScanResultList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)scanres_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioUnassociatedSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *unassoc_arr = NULL, *unassoc_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, unassoc_arr, unassoc_obj, i, 1, "UnassociatedStaList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)unassoc_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioCapabilitiesCapableOperatingClassProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *caps_obj = NULL, *opclass_arr = NULL, *opclass_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	json_object_object_get_ex((json_object *)prev_data, "Capabilites", &caps_obj);
	if (caps_obj) {
		dmjson_foreach_obj_in_array(caps_obj, opclass_arr, opclass_obj, i, 1, "OperatingClasses") {
			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioBSSSTAInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *sta_arr = NULL, *sta_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, sta_arr, sta_obj, i, 1, "STAList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)sta_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *opclass_scan_arr = NULL, *opclass_scan_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, opclass_scan_arr, opclass_scan_obj, i, 1, "OpClassScanList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)opclass_scan_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *chscan_arr = NULL, *chscan_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, chscan_arr, chscan_obj, i, 1, "ChannelScanList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)chscan_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

int os__browseWiFiDataElementsNetworkDeviceRadioScanResultOpClassScanChannelScanNeighborBSSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *neigh_arr = NULL, *neigh_obj = NULL;
	char *inst = NULL, *max_inst = NULL;
	int id = 0, i = 0;

	dmjson_foreach_obj_in_array((json_object *)prev_data, neigh_arr, neigh_obj, i, 1, "NeighborList") {
		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)neigh_obj, inst) == DM_STOP)
			break;
	}
	return 0;
}

#if 0
int os__browseWiFiDataElementsAssociationEventAssociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

int os__browseWiFiDataElementsDisassociationEventDisassociationEventDataInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif
