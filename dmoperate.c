/*
 * dmoperate.c: Operate handler for uspd
 *
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Yashvardhan <y.yashvardhan@iopsys.eu>
 * Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmoperate.h"

#define GLOB_EXPR "[=><]+"

static uint8_t wifi_neighbor_count = 0;
struct op_cmd *dynamic_operate = NULL;

static const char *fw_image_activate_in[] = {
	"TimeWindow.1.Start",
	"TimeWindow.2.Start",
	"TimeWindow.3.Start",
	"TimeWindow.4.Start",
	"TimeWindow.5.Start",
};

static void bbf_init(struct dmctx *dm_ctx, char *path)
{
	unsigned int instance = INSTANCE_MODE_NUMBER;

	if (match(path, "[[]+")) {
		if (!match(path, GLOB_EXPR))
			instance = INSTANCE_MODE_ALIAS;
	}
	dm_ctx_init_sub(dm_ctx, instance);
}

static void bbf_cleanup(struct dmctx *dm_ctx)
{
	dm_ctx_clean_sub(dm_ctx);
}

static bool bbf_get(int operation, char *path, struct dmctx *dm_ctx)
{
	int fault = 0;

	switch(operation) {
		case CMD_GET_NAME:
			fault = dm_entry_param_method(dm_ctx, CMD_GET_NAME, path, "true", NULL);
			break;
		case CMD_GET_VALUE:
			fault = dm_entry_param_method(dm_ctx, CMD_GET_VALUE, path, NULL, NULL);
			break;
		default:
			return false;
	}

	if (dm_ctx->list_fault_param.next != &dm_ctx->list_fault_param) {
		return false;
	}
	if (fault) {
		return false;
	}
	return true;
}

static bool bbf_set_value(char *path, char *value)
{
	int fault = 0, res;
	struct dmctx dm_ctx = {0};
	struct dmctx *p_dmctx = &dm_ctx;

	bbf_init(&dm_ctx, path);

	fault = dm_entry_param_method(&dm_ctx, CMD_SET_VALUE, path, value, NULL);

	if (!fault) {
		fault = dm_entry_apply(&dm_ctx, CMD_SET_VALUE, "", NULL);
	}

	if (p_dmctx->list_fault_param.next != &p_dmctx->list_fault_param) {
		res = FAIL;
	}

	if (fault)
		res = FAIL;
	else
		res = SUCCESS;

	bbf_cleanup(&dm_ctx);
	return res;
}

static char *bbf_get_value_by_id(char *id)
{
	struct dmctx dm_ctx = {0};
	struct dm_parameter *n = NULL;
	char *value = NULL;

	bbf_init(&dm_ctx, id);
	if (bbf_get(CMD_GET_VALUE, id, &dm_ctx)) {
			list_for_each_entry(n, &dm_ctx.list_parameter, list) {
				value = dmstrdup(n->data);
				break;
			}
	}
	bbf_cleanup(&dm_ctx);
	return value;
}

char *get_param_val_from_op_cmd(char *op_cmd, const char *param)
{
	char node[256] = {'\0'};

	// Trim action from operation command
	// For eg: trim Reset from Device.IP.Interface.*.Reset
	char *ret = strrchr(op_cmd, '.');
	strncpy(node, op_cmd, ret - op_cmd +1);

	// Append param name to the trimmed path
	strncat(node, param, sizeof(node) - strlen(node));

	// Get parameter value
	return bbf_get_value_by_id(node);
}

static opr_ret_t reboot_device(struct dmctx *dmctx, char *path, json_object *input)
{
	if (0 == dmubus_call_set(SYSTEM_UBUS_PATH, "reboot", UBUS_ARGS{}, 0))
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t factory_reset(struct dmctx *dmctx, char *path, json_object *input)
{
	if (0 == dmcmd_no_wait("/sbin/defaultreset", 0))
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t network_interface_reset(struct dmctx *dmctx, char *path, json_object *input)
{
	char cmd[NAME_MAX] = NETWORK_INTERFACE_UBUS_PATH;
	bool status = false;

	snprintf(cmd + strlen(cmd), NAME_MAX - strlen(cmd), "%s", ".");
	char *zone = get_param_val_from_op_cmd(path, "Name");
	if (zone) {
		strncat(cmd, zone, NAME_MAX - strlen(cmd));
		dmfree(zone);
	} else {
		return FAIL;
	}
	if (0 == dmubus_call_set(cmd, "down", UBUS_ARGS{}, 0))
		status = true;

	if (0 == dmubus_call_set(cmd, "up", UBUS_ARGS{}, 0))
		status &= true;

	if (status)
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t wireless_reset(struct dmctx *dmctx, char *path, json_object *input)
{
	if (0 == dmcmd_no_wait("/sbin/wifi", 2, "reload", "&"))
		return SUCCESS;
	else
		return FAIL;
}

struct wifi_security_params reset_params[] = {
	{"", "ModeEnabled", ""},
	{"", "PreSharedKey", ""},
	{"", "KeyPassphrase", ""}
};

static opr_ret_t ap_security_reset(struct dmctx *dmctx, char *path, json_object *input)
{
	char *wpakey = NULL;
	char node[255] = {'\0'};
	int i, len = 0;

	char *ret = strrchr(path, '.');
	strncpy(node, path, ret - path +1);

	len = ARRAY_SIZE(reset_params);

	for (i = 0; i < len; i++) {
		DM_STRNCPY(reset_params[i].node, node, sizeof(reset_params[i].node));
		strncat(reset_params[i].node, reset_params[i].param, 255 - strlen(reset_params[i].node));
	}
	const char *mode_enabled = "WPA2-Personal";

	// Default mode - WPA2-Personal
	DM_STRNCPY(reset_params[0].value, mode_enabled, sizeof(reset_params[0].value));

	// Get Default wpakey
	db_get_value_string("hw", "board", "wpa_key", &wpakey);

	// PreSharedKey and KeyPassphrase are kept same
	DM_STRNCPY(reset_params[1].value, wpakey, sizeof(reset_params[1].value));
	DM_STRNCPY(reset_params[2].value, wpakey, sizeof(reset_params[2].value));

	for (i = 0; i < len; i++) {
		bbf_set_value(reset_params[i].node, reset_params[i].value);
	}
	return SUCCESS;
}

static opr_ret_t dhcp_client_renew(struct dmctx *dmctx, char *path, json_object *input)
{
	if (SUCCESS == bbf_set_value(path, "true"))
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t vendor_conf_backup(struct dmctx *dmctx, char *path, json_object *input)
{
	struct file_server fserver = {0};
	char obj_path[256] = {'\0'};
	char command[32] = {'\0'};

	char *ret = strrchr(path, '.');
	strncpy(obj_path, path, ret - path +1);
	DM_STRNCPY(command, ret+1, sizeof(command));

	char *vcf_name = get_param_val_from_op_cmd(path, "Name");
	if (!vcf_name)
		return FAIL;

	fserver.url = dmjson_get_value(input, 1, "URL");
	if (fserver.url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	fserver.user = dmjson_get_value(input, 1, "Username");
	fserver.pass = dmjson_get_value(input, 1, "Password");

	int res = bbf_config_backup(fserver.url, fserver.user, fserver.pass, vcf_name, command, obj_path);
	dmfree(vcf_name);

	return res ? FAIL : SUCCESS;
}

static opr_ret_t vendor_conf_restore(struct dmctx *dmctx, char *path, json_object *input)
{
	struct file_server fserver = {0};
	char obj_path[256] = {'\0'};
	char command[32] = {'\0'};

	char *ret = strrchr(path, '.');
	strncpy(obj_path, path, ret - path +1);
	DM_STRNCPY(command, ret+1, sizeof(command));

	fserver.url = dmjson_get_value(input, 1, "URL");
	if (fserver.url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	fserver.user = dmjson_get_value(input, 1, "Username");
	fserver.pass = dmjson_get_value(input, 1, "Password");
	fserver.file_size = dmjson_get_value(input, 1, "FileSize");
	fserver.checksum_algorithm = dmjson_get_value(input, 1, "CheckSumAlgorithm");
	fserver.checksum = dmjson_get_value(input, 1, "CheckSum");

	int res = bbf_config_restore(fserver.url, fserver.user, fserver.pass, fserver.file_size, fserver.checksum_algorithm, fserver.checksum, command, obj_path);

	return res ? FAIL : SUCCESS;
}

static void fill_wireless_scan_results(struct dmctx *dmctx, char *radio)
{
	json_object *res = NULL, *obj = NULL;
	struct neighboring_wiFi_diagnostic neighboring = {0};
	char object[32], *ssid, *bssid, *channel, *frequency, *signal_stregth, *noise;

	snprintf(object, sizeof(object), "wifi.radio.%s", radio);
	dmubus_call_set(object, "scan", UBUS_ARGS{}, 0);
	sleep(2); // Wait for results to get populated in scanresults
	dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);

	if (!res)
		return;

	if (!json_object_object_get_ex(res,"accesspoints", &obj))
		return;

	uint8_t len = obj ? json_object_array_length(obj) : 0;
	for (uint8_t j = 0; j < len; j++ ) {
		wifi_neighbor_count++;
		json_object *array_obj = json_object_array_get_idx(obj, j);
		neighboring.ssid = dmjson_get_value(array_obj, 1, "ssid");
		neighboring.bssid = dmjson_get_value(array_obj, 1, "bssid");
		neighboring.channel = dmjson_get_value(array_obj, 1, "channel");
		neighboring.frequency = dmjson_get_value(array_obj, 1, "band");
		neighboring.signal_strength = dmjson_get_value(array_obj, 1, "rssi");
		neighboring.noise = dmjson_get_value(array_obj, 1, "noise");

		dmasprintf(&ssid, "Result.%d.SSID", wifi_neighbor_count);
		dmasprintf(&bssid, "Result.%d.BSSID", wifi_neighbor_count);
		dmasprintf(&channel, "Result.%d.Channel", wifi_neighbor_count);
		dmasprintf(&frequency, "Result.%d.OperatingFrequencyBand", wifi_neighbor_count);
		dmasprintf(&signal_stregth, "Result.%d.SignalStrength", wifi_neighbor_count);
		dmasprintf(&noise, "Result.%d.Noise", wifi_neighbor_count);

		add_list_parameter(dmctx, ssid, neighboring.ssid, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, bssid, neighboring.bssid, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, channel, neighboring.channel, DMT_TYPE[DMT_UNINT], NULL);
		add_list_parameter(dmctx, frequency, neighboring.frequency, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, signal_stregth, neighboring.signal_strength, DMT_TYPE[DMT_INT], NULL);
		add_list_parameter(dmctx, noise, neighboring.noise, DMT_TYPE[DMT_INT], NULL);
	}
}

static opr_ret_t fetch_neighboring_wifi_diagnostic(struct dmctx *dmctx, char *path, json_object *input)
{
	json_object *res = NULL, *radios = NULL, *arrobj = NULL;

	dmubus_call("wifi", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		int j = 0;

		dmjson_foreach_obj_in_array(res, arrobj, radios, j, 1, "radios") {
			fill_wireless_scan_results(dmctx, dmjson_get_value(radios, 1, "name"));
		}
	}
	wifi_neighbor_count = 0;
	return SUCCESS;
}

static opr_ret_t ip_diagnostics_ipping(struct dmctx *dmctx, char *path, json_object *input)
{
	struct ipping_diagnostics ipping = {0};

	init_diagnostics_operation("ipping", IPPING_PATH);

	ipping.host = dmjson_get_value(input, 1, "Host");
	if (ipping.host[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	ipping.interface = dmjson_get_value(input, 1, "Interface");
	ipping.proto = dmjson_get_value(input, 1, "ProtocolVersion");
	ipping.nbofrepetition = dmjson_get_value(input, 1, "NumberOfRepetitions");
	ipping.timeout = dmjson_get_value(input, 1, "Timeout");
	ipping.datablocksize = dmjson_get_value(input, 1, "DataBlockSize");
	ipping.dscp = dmjson_get_value(input, 1, "DSCP");

	set_diagnostics_option("ipping", "Host", ipping.host);
	set_diagnostics_interface_option(dmctx, "ipping", ipping.interface);
	set_diagnostics_option("ipping", "ProtocolVersion", ipping.proto);
	set_diagnostics_option("ipping", "NumberOfRepetitions", ipping.nbofrepetition);
	set_diagnostics_option("ipping", "Timeout", ipping.timeout);
	set_diagnostics_option("ipping", "DataBlockSize", ipping.datablocksize);
	set_diagnostics_option("ipping", "DSCP", ipping.dscp);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, IPPING_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	ipping.success_count = get_diagnostics_option("ipping", "SuccessCount");
	ipping.failure_count = get_diagnostics_option("ipping", "FailureCount");
	ipping.average_response_time = get_diagnostics_option("ipping", "AverageResponseTime");
	ipping.minimum_response_time = get_diagnostics_option("ipping", "MinimumResponseTime");
	ipping.maximum_response_time = get_diagnostics_option("ipping", "MaximumResponseTime");
	ipping.average_response_time_detailed = get_diagnostics_option("ipping", "AverageResponseTimeDetailed");
	ipping.minimum_response_time_detailed = get_diagnostics_option("ipping", "MinimumResponseTimeDetailed");
	ipping.maximum_response_time_detailed = get_diagnostics_option("ipping", "MaximumResponseTimeDetailed");

	add_list_parameter(dmctx, dmstrdup("SuccessCount"), ipping.success_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("FailureCount"), ipping.failure_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("AverageResponseTime"), ipping.average_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MinimumResponseTime"), ipping.minimum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MaximumResponseTime"), ipping.maximum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("AverageResponseTimeDetailed"), ipping.average_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MinimumResponseTimeDetailed"), ipping.minimum_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MaximumResponseTimeDetailed"), ipping.maximum_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_traceroute(struct dmctx *dmctx, char *path, json_object *input)
{
	struct traceroute_diagnostics traceroute = {0};
	struct uci_section *s = NULL;
	char *host, *host_address, *errorcode, *rttimes;
	int i = 1;

	init_diagnostics_operation("traceroute", TRACEROUTE_PATH);

	traceroute.host = dmjson_get_value(input, 1, "Host");
	if (traceroute.host[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	traceroute.interface = dmjson_get_value(input, 1, "Interface");
	traceroute.proto = dmjson_get_value(input, 1, "ProtocolVersion");
	traceroute.nboftries = dmjson_get_value(input, 1, "NumberOfTries");
	traceroute.timeout = dmjson_get_value(input, 1, "Timeout");
	traceroute.datablocksize = dmjson_get_value(input, 1, "DataBlockSize");
	traceroute.dscp = dmjson_get_value(input, 1, "DSCP");
	traceroute.maxhops = dmjson_get_value(input, 1, "MaxHopCount");

	set_diagnostics_option("traceroute", "Host", traceroute.host);
	set_diagnostics_interface_option(dmctx, "traceroute", traceroute.interface);
	set_diagnostics_option("traceroute", "ProtocolVersion", traceroute.proto);
	set_diagnostics_option("traceroute", "NumberOfTries", traceroute.nboftries);
	set_diagnostics_option("traceroute", "Timeout", traceroute.timeout);
	set_diagnostics_option("traceroute", "DataBlockSize", traceroute.datablocksize);
	set_diagnostics_option("traceroute", "DSCP", traceroute.dscp);
	set_diagnostics_option("traceroute", "MaxHops", traceroute.maxhops);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, TRACEROUTE_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	traceroute.response_time = get_diagnostics_option("traceroute", "ResponseTime");
	add_list_parameter(dmctx, dmstrdup("ResponseTime"), traceroute.response_time, DMT_TYPE[DMT_UNINT], NULL);

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "RouteHops", s) {
		dmasprintf(&host, "RouteHops.%d.Host", i);
		dmasprintf(&host_address, "RouteHops.%d.HostAddress", i);
		dmasprintf(&errorcode, "RouteHops.%d.ErrorCode", i);
		dmasprintf(&rttimes, "RouteHops.%d.RTTimes", i);

		dmuci_get_value_by_section_string(s, "host", &traceroute.host_name);
		dmuci_get_value_by_section_string(s, "ip", &traceroute.host_address);
		dmuci_get_value_by_section_string(s, "time", &traceroute.rttimes);

		add_list_parameter(dmctx, host, traceroute.host_name, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, host_address, traceroute.host_address, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, errorcode, "0", DMT_TYPE[DMT_UNINT], NULL);
		add_list_parameter(dmctx, rttimes, traceroute.rttimes, DMT_TYPE[DMT_STRING], NULL);
		i++;
	}

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_download(struct dmctx *dmctx, char *path, json_object *input)
{
	struct download_diagnostics download = {0};

	init_diagnostics_operation("download", DOWNLOAD_DIAGNOSTIC_PATH);

	download.download_url = dmjson_get_value(input, 1, "DownloadURL");
	if (download.download_url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	download.interface = dmjson_get_value(input, 1, "Interface");
	download.dscp = dmjson_get_value(input, 1, "DSCP");
	download.ethernet_priority = dmjson_get_value(input, 1, "EthernetPriority");
	download.proto = dmjson_get_value(input, 1, "ProtocolVersion");
	download.num_of_connections = dmjson_get_value(input, 1, "NumberOfConnections");
	download.enable_per_connection_results = dmjson_get_value(input, 1, "EnablePerConnectionResults");

	set_diagnostics_option("download", "url", download.download_url);
	set_diagnostics_interface_option(dmctx, "download", download.interface);
	set_diagnostics_option("download", "DSCP", download.dscp);
	set_diagnostics_option("download", "ethernetpriority", download.ethernet_priority);
	set_diagnostics_option("download", "ProtocolVersion", download.proto);
	set_diagnostics_option("download", "NumberOfConnections", download.num_of_connections);
	set_diagnostics_option("download", "EnablePerConnection", download.enable_per_connection_results);

	if (start_upload_download_diagnostic(DOWNLOAD_DIAGNOSTIC) == -1)
		return FAIL;

	download.romtime = get_diagnostics_option("download", "ROMtime");
	download.bomtime = get_diagnostics_option("download", "BOMtime");
	download.eomtime = get_diagnostics_option("download", "EOMtime");
	download.test_bytes_received = get_diagnostics_option("download", "TestBytesReceived");
	download.total_bytes_received = get_diagnostics_option("download", "TotalBytesReceived");
	download.total_bytes_sent = get_diagnostics_option("download", "TotalBytesSent");
	download.test_bytes_received_under_full_loading = get_diagnostics_option("download", "TestBytesReceived");
	download.total_bytes_received_under_full_loading = get_diagnostics_option("download", "TotalBytesReceived");
	download.total_bytes_sent_under_full_loading = get_diagnostics_option("download", "TotalBytesSent");
	download.period_of_full_loading = get_diagnostics_option("download", "PeriodOfFullLoading");
	download.tcp_open_request_time = get_diagnostics_option("download", "TCPOpenRequestTime");
	download.tcp_open_response_time = get_diagnostics_option("download", "TCPOpenResponseTime");

	add_list_parameter(dmctx, dmstrdup("ROMTime"), download.romtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("BOMTime"), download.bomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("EOMTime"), download.eomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("TestBytesReceived"), download.test_bytes_received, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesReceived"), download.total_bytes_received, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesSent"), download.total_bytes_sent, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TestBytesReceivedUnderFullLoading"), download.test_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesReceivedUnderFullLoading"), download.total_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesSentUnderFullLoading"), download.total_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("PeriodOfFullLoading"), download.period_of_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TCPOpenRequestTime"), download.tcp_open_request_time, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("TCPOpenResponseTime"), download.tcp_open_response_time, DMT_TYPE[DMT_TIME], NULL);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_upload(struct dmctx *dmctx, char *path, json_object *input)
{
	struct upload_diagnostics upload = {0};

	init_diagnostics_operation("upload", UPLOAD_DIAGNOSTIC_PATH);

	upload.upload_url = dmjson_get_value(input, 1, "UploadURL");
	if (upload.upload_url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	upload.test_file_length = dmjson_get_value(input, 1, "TestFileLength");
	if (upload.test_file_length[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	upload.interface = dmjson_get_value(input, 1, "Interface");
	upload.dscp = dmjson_get_value(input, 1, "DSCP");
	upload.ethernet_priority = dmjson_get_value(input, 1, "EthernetPriority");
	upload.proto = dmjson_get_value(input, 1, "ProtocolVersion");
	upload.num_of_connections = dmjson_get_value(input, 1, "NumberOfConnections");
	upload.enable_per_connection_results = dmjson_get_value(input, 1, "EnablePerConnectionResults");

	set_diagnostics_option("upload", "url", upload.upload_url);
	set_diagnostics_option("upload", "TestFileLength", upload.test_file_length);
	set_diagnostics_interface_option(dmctx, "upload", upload.interface);
	set_diagnostics_option("upload", "DSCP", upload.dscp);
	set_diagnostics_option("upload", "ethernetpriority", upload.ethernet_priority);
	set_diagnostics_option("upload", "ProtocolVersion", upload.proto);
	set_diagnostics_option("upload", "NumberOfConnections", upload.num_of_connections);
	set_diagnostics_option("upload", "EnablePerConnection", upload.enable_per_connection_results);

	if (start_upload_download_diagnostic(UPLOAD_DIAGNOSTIC) == -1)
		return FAIL;

	upload.romtime = get_diagnostics_option("upload", "ROMtime");
	upload.bomtime = get_diagnostics_option("upload", "BOMtime");
	upload.eomtime = get_diagnostics_option("upload", "EOMtime");
	upload.test_bytes_sent = get_diagnostics_option("upload", "TestBytesSent");
	upload.total_bytes_received = get_diagnostics_option("upload", "TotalBytesReceived");
	upload.total_bytes_sent = get_diagnostics_option("upload", "TotalBytesSent");
	upload.test_bytes_sent_under_full_loading = get_diagnostics_option("upload", "TestBytesSent");
	upload.total_bytes_received_under_full_loading = get_diagnostics_option("upload", "TotalBytesReceived");
	upload.total_bytes_sent_under_full_loading = get_diagnostics_option("upload", "TotalBytesSent");
	upload.period_of_full_loading = get_diagnostics_option("upload", "PeriodOfFullLoading");
	upload.tcp_open_request_time = get_diagnostics_option("upload", "TCPOpenRequestTime");
	upload.tcp_open_response_time = get_diagnostics_option("upload", "TCPOpenResponseTime");

	add_list_parameter(dmctx, dmstrdup("ROMTime"), upload.romtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("BOMTime"), upload.bomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("EOMTime"), upload.eomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("TestBytesSent"), upload.test_bytes_sent, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesReceived"), upload.total_bytes_received, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesSent"), upload.total_bytes_sent, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TestBytesSentUnderFullLoading"), upload.test_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesReceivedUnderFullLoading"), upload.total_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TotalBytesSentUnderFullLoading"), upload.total_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("PeriodOfFullLoading"), upload.period_of_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("TCPOpenRequestTime"), upload.tcp_open_request_time, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(dmctx, dmstrdup("TCPOpenResponseTime"), upload.tcp_open_response_time, DMT_TYPE[DMT_TIME], NULL);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_udpecho(struct dmctx *dmctx, char *path, json_object *input)
{
	struct udpecho_diagnostics udpecho = {0};

	init_diagnostics_operation("udpechodiag", UDPECHO_PATH);

	udpecho.host = dmjson_get_value(input, 1, "Host");
	if (udpecho.host[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	udpecho.port = dmjson_get_value(input, 1, "Port");
	if (udpecho.port[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	udpecho.interface = dmjson_get_value(input, 1, "Interface");
	udpecho.proto = dmjson_get_value(input, 1, "ProtocolVersion");
	udpecho.nbofrepetition = dmjson_get_value(input, 1, "NumberOfRepetitions");
	udpecho.timeout = dmjson_get_value(input, 1, "Timeout");
	udpecho.datablocksize = dmjson_get_value(input, 1, "DataBlockSize");
	udpecho.dscp = dmjson_get_value(input, 1, "DSCP");
	udpecho.inter_transmission_time = dmjson_get_value(input, 1, "InterTransmissionTime");

	set_diagnostics_option("udpechodiag", "Host", udpecho.host);
	set_diagnostics_option("udpechodiag", "port", udpecho.port);
	set_diagnostics_interface_option(dmctx, "udpechodiag", udpecho.interface);
	set_diagnostics_option("udpechodiag", "ProtocolVersion", udpecho.proto);
	set_diagnostics_option("udpechodiag", "NumberOfRepetitions", udpecho.nbofrepetition);
	set_diagnostics_option("udpechodiag", "Timeout", udpecho.timeout);
	set_diagnostics_option("udpechodiag", "DataBlockSize", udpecho.datablocksize);
	set_diagnostics_option("udpechodiag", "DSCP", udpecho.dscp);
	set_diagnostics_option("udpechodiag", "InterTransmissionTime", udpecho.inter_transmission_time);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, UDPECHO_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	udpecho.success_count = get_diagnostics_option("udpechodiag", "SuccessCount");
	udpecho.failure_count = get_diagnostics_option("udpechodiag", "FailureCount");
	udpecho.average_response_time = get_diagnostics_option("udpechodiag", "AverageResponseTime");
	udpecho.minimum_response_time = get_diagnostics_option("udpechodiag", "MinimumResponseTime");
	udpecho.maximum_response_time = get_diagnostics_option("udpechodiag", "MaximumResponseTime");

	add_list_parameter(dmctx, dmstrdup("SuccessCount"), udpecho.success_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("FailureCount"), udpecho.failure_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("AverageResponseTime"), udpecho.average_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MinimumResponseTime"), udpecho.minimum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MaximumResponseTime"), udpecho.maximum_response_time, DMT_TYPE[DMT_UNINT], NULL);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_serverselection(struct dmctx *dmctx, char *path, json_object *input)
{
	struct serverselection_diagnostics serverselection = {0};

	init_diagnostics_operation("serverselection", SERVERSELECTION_PATH);

	serverselection.hostlist = dmjson_get_value(input, 1, "HostList");
	if (serverselection.hostlist[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	serverselection.port = dmjson_get_value(input, 1, "Port");
	serverselection.proto = dmjson_get_value(input, 1, "Protocol");
	if (strcmp(serverselection.proto, "ICMP")) {
		if (serverselection.port[0] == '\0')
			return UBUS_INVALID_ARGUMENTS;
	}
	serverselection.protocol_version = dmjson_get_value(input, 1, "ProtocolVersion");
	serverselection.interface = dmjson_get_value(input, 1, "Interface");
	serverselection.nbofrepetition = dmjson_get_value(input, 1, "NumberOfRepetitions");
	serverselection.timeout = dmjson_get_value(input, 1, "Timeout");

	set_diagnostics_option("serverselection", "HostList", serverselection.hostlist);
	set_diagnostics_interface_option(dmctx, "serverselection", serverselection.interface);
	set_diagnostics_option("serverselection", "ProtocolVersion", serverselection.protocol_version);
	set_diagnostics_option("serverselection", "NumberOfRepetitions", serverselection.nbofrepetition);
	set_diagnostics_option("serverselection", "port", serverselection.port);
	set_diagnostics_option("serverselection", "Protocol", serverselection.proto);
	set_diagnostics_option("serverselection", "Timeout", serverselection.timeout);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, SERVERSELECTION_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	serverselection.fasthost = get_diagnostics_option("serverselection", "FastestHost");
	serverselection.average_response_time = get_diagnostics_option("serverselection", "AverageResponseTime");
	serverselection.minimum_response_time = get_diagnostics_option("serverselection", "MinimumResponseTime");
	serverselection.maximum_response_time = get_diagnostics_option("serverselection", "MaximumResponseTime");

	add_list_parameter(dmctx, dmstrdup("FastestHost"), serverselection.fasthost, DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(dmctx, dmstrdup("AverageResponseTime"), serverselection.average_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MinimumResponseTime"), serverselection.minimum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(dmctx, dmstrdup("MaximumResponseTime"), serverselection.maximum_response_time, DMT_TYPE[DMT_UNINT], NULL);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_nslookup(struct dmctx *dmctx, char *path, json_object *input)
{
	struct nslookup_diagnostics nslookup = {0};
	struct uci_section *s = NULL;
	char *status, *answertype, *hostname, *ipaddress, *dnsserverip, *responsetime;
	int i = 1;

	init_diagnostics_operation("nslookup", NSLOOKUP_PATH);

	nslookup.hostname = dmjson_get_value(input, 1, "HostName");
	if (nslookup.hostname[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	nslookup.interface = dmjson_get_value(input, 1, "Interface");
	nslookup.dnsserver = dmjson_get_value(input, 1, "DNSServer");
	nslookup.timeout = dmjson_get_value(input, 1, "Timeout");
	nslookup.nbofrepetition = dmjson_get_value(input, 1, "NumberOfRepetitions");

	set_diagnostics_option("nslookup", "HostName", nslookup.hostname);
	set_diagnostics_interface_option(dmctx, "nslookup", nslookup.interface);
	set_diagnostics_option("nslookup", "DNSServer", nslookup.dnsserver);
	set_diagnostics_option("nslookup", "Timeout", nslookup.timeout);
	set_diagnostics_option("nslookup", "NumberOfRepetitions", nslookup.nbofrepetition);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, NSLOOKUP_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	nslookup.success_count = get_diagnostics_option("nslookup", "SuccessCount");
	char *param_success_count = dmstrdup("SuccessCount");
	add_list_parameter(dmctx, param_success_count, nslookup.success_count, DMT_TYPE[DMT_UNINT], NULL);

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "NSLookupResult", s) {
		dmasprintf(&status, "Result.%d.Status", i);
		dmasprintf(&answertype, "Result.%d.AnswerType", i);
		dmasprintf(&hostname, "Result.%d.HostNameReturned", i);
		dmasprintf(&ipaddress, "Result.%d.IPAddresses", i);
		dmasprintf(&dnsserverip, "Result.%d.DNSServerIP", i);
		dmasprintf(&responsetime, "Result.%d.ResponseTime", i);

		dmuci_get_value_by_section_string(s, "Status", &nslookup.status);
		dmuci_get_value_by_section_string(s, "AnswerType", &nslookup.answer_type);
		dmuci_get_value_by_section_string(s, "HostNameReturned", &nslookup.hostname_returned);
		dmuci_get_value_by_section_string(s, "IPAddresses", &nslookup.ip_addresses);
		dmuci_get_value_by_section_string(s, "DNSServerIP", &nslookup.dns_server_ip);
		dmuci_get_value_by_section_string(s, "ResponseTime", &nslookup.response_time);

		add_list_parameter(dmctx, status, nslookup.status, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, answertype, nslookup.answer_type, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, hostname, nslookup.hostname_returned, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, ipaddress, nslookup.ip_addresses, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, dnsserverip, nslookup.dns_server_ip, DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(dmctx, responsetime, nslookup.response_time, DMT_TYPE[DMT_UNINT], NULL);
		i++;
	}

	return SUCCESS;
}

static opr_ret_t firmware_image_download(struct dmctx *dmctx, char *path, json_object *input)
{
	char obj_path[256] = {'\0'};
	char command[32] = {'\0'};
	char *bank_id = NULL;
	char *linker = NULL;

	char *ret = strrchr(path, '.');
	strncpy(obj_path, path, ret - path +1);
	DM_STRNCPY(command, ret+1, sizeof(command));

	adm_entry_get_linker_value(dmctx, obj_path, &linker);
	if (linker && *linker) {
		bank_id = strchr(linker, ':');
		if (!bank_id)
			return FAIL;
	} else {
		return FAIL;
	}

	char *url = dmjson_get_value(input, 1, "URL");
	char *auto_activate = dmjson_get_value(input, 1, "AutoActivate");
	if (url[0] == '\0' || auto_activate[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	char *username = dmjson_get_value(input, 1, "Username");
	char *password = dmjson_get_value(input, 1, "Password");
	char *file_size = dmjson_get_value(input, 1, "FileSize");
	char *checksum_algorithm = dmjson_get_value(input, 1, "CheckSumAlgorithm");
	char *checksum = dmjson_get_value(input, 1, "CheckSum");

	int res = bbf_fw_image_download(url, auto_activate, username, password, file_size, checksum_algorithm, checksum, bank_id+1, command, obj_path);

	return res ? FAIL : SUCCESS;
}

static opr_ret_t firmware_image_activate(struct dmctx *dmctx, char *path, json_object *input)
{
	struct activate_image active_images[MAX_TIME_WINDOW] = {0};
	char fwimage_path[256] = {'\0'};
	char *bank_id = NULL;
	char *linker = NULL;

	char *ret = strrchr(path, '.');
	strncpy(fwimage_path, path, ret - path +1);

	adm_entry_get_linker_value(dmctx, fwimage_path, &linker);
	if (linker && *linker) {
		bank_id = strchr(linker, ':');
		if (!bank_id)
			return FAIL;
	} else {
		return FAIL;
	}

	for (int i = 0; i < ARRAY_SIZE(fw_image_activate_in); i++)
		active_images[i].start_time = dmjson_get_value(input, 1, fw_image_activate_in[i]);

	int res = bbf_fw_image_activate(bank_id+1, active_images);

	return res ? FAIL : SUCCESS;
}

static int get_index_of_available_dynamic_operate(struct op_cmd *operate)
{
	int idx = 0;
	for (; (operate && operate->name); operate++) {
		idx++;
	}
	return idx;
}

int add_dynamic_operate(char *path, operation operate, char *type, operation_args args)
{
	if (dynamic_operate == NULL) {
		dynamic_operate = calloc(2, sizeof(struct op_cmd));
		dynamic_operate[0].name = path;
		dynamic_operate[0].opt = operate;
		dynamic_operate[0].type = type;
		dynamic_operate[0].args = args;
	} else {
		int idx = get_index_of_available_dynamic_operate(dynamic_operate);
		struct op_cmd *new_dynamic_operate = realloc(dynamic_operate, (idx + 2) * sizeof(struct op_cmd));
		if (new_dynamic_operate == NULL)
			FREE(dynamic_operate);
		else
			dynamic_operate = new_dynamic_operate;
		memset(dynamic_operate + (idx + 1), 0, sizeof(struct op_cmd));
		dynamic_operate[idx].name = path;
		dynamic_operate[idx].opt = operate;
		dynamic_operate[idx].type = type;
		dynamic_operate[idx].args = args;
	}
	return 0;
}

static const struct op_cmd operate_helper[] = {
	{
		"Device.Reboot", reboot_device, "sync"
	},
	{
		"Device.FactoryReset", factory_reset, "sync"
	},
	{
		"Device.IP.Interface.*.Reset", network_interface_reset, "sync"
	},
	{
		"Device.PPP.Interface.*.Reset", network_interface_reset, "sync"
	},
	{
		"Device.WiFi.Reset", wireless_reset, "sync"
	},
	{
		"Device.WiFi.AccessPoint.*.Security.Reset", ap_security_reset, "sync"
	},
	{
		"Device.DHCPv4.Client.*.Renew", dhcp_client_renew, "sync"
	},
	{
		"Device.DHCPv6.Client.*.Renew", dhcp_client_renew, "sync"
	},
	{
		"Device.DeviceInfo.VendorConfigFile.*.Backup", vendor_conf_backup, "async",
		{
			.in = (const char *[]) {
				"URL",
				"Username",
				"Password",
				NULL
			}
		}
	},
	{
		"Device.DeviceInfo.VendorConfigFile.*.Restore", vendor_conf_restore, "async",
		{
			.in = (const char *[]) {
				"URL",
				"Username",
				"Password",
				"FileSize",
				"TargetFileName",
				"CheckSumAlgorithm",
				"CheckSum",
				NULL
			}
		}
	},
	{
		"Device.DeviceInfo.FirmwareImage.*.Download", firmware_image_download, "async",
		{
			.in = (const char *[]) {
				"URL",
				"AutoActivate",
				"Username",
				"Password",
				"FileSize",
				"CheckSumAlgorithm",
				"CheckSum",
				NULL
			}
		}
	},
	{
		"Device.DeviceInfo.FirmwareImage.*.Activate", firmware_image_activate, "async",
		{
			.in = (const char *[]) {
				"TimeWindow.{i}.Start",
				"TimeWindow.{i}.End",
				"TimeWindow.{i}.Mode",
				"TimeWindow.{i}.UserMessage",
				"TimeWindow.{i}.MaxRetries",
				NULL
			}
		}
	},
	{
		"Device.WiFi.NeighboringWiFiDiagnostic", fetch_neighboring_wifi_diagnostic, "async",
		{
			.out = (const char *[]) {
				"Status",
				NULL
			}
		}
	},
	{
		"Device.IP.Diagnostics.IPPing", ip_diagnostics_ipping, "async",
		{
			.in = (const char *[]) {
				"Interface",
				"ProtocolVersion",
				"Host",
				"NumberOfRepetitions",
				"Timeout",
				"DataBlockSize",
				"DSCP",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"IPAddressUsed",
				"SuccessCount",
				"FailureCount",
				"AverageResponseTime",
				"MinimumResponseTime",
				"MaximumResponseTime",
				"AverageResponseTimeDetailed",
				"MinimumResponseTimeDetailed",
				"MaximumResponseTimeDetailed",
				NULL
			}
		}
	},
	{
		"Device.IP.Diagnostics.TraceRoute", ip_diagnostics_traceroute, "async",
		{
			.in = (const char *[]) {
				"Interface",
				"ProtocolVersion",
				"Host",
				"NumberOfTries",
				"Timeout",
				"DataBlockSize",
				"DSCP",
				"MaxHopCount",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"IPAddressUsed",
				"ResponseTime",
				NULL
			}
		}
	},
	{
		"Device.IP.Diagnostics.DownloadDiagnostics", ip_diagnostics_download, "async",
		{
			.in = (const char *[]) {
				"Interface",
				"DownloadURL",
				"DSCP",
				"EthernetPriority",
				"TimeBasedTestDuration",
				"TimeBasedTestMeasurementInterval",
				"TimeBasedTestMeasurementOffset",
				"ProtocolVersion",
				"NumberOfConnections",
				"EnablePerConnectionResults",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"IPAddressUsed",
				"ROMTime",
				"BOMTime",
				"EOMTime",
				"TestBytesReceived",
				"TotalBytesReceived",
				"TotalBytesSent",
				"TestBytesReceivedUnderFullLoading",
				"TotalBytesReceivedUnderFullLoading",
				"TotalBytesSentUnderFullLoading",
				"PeriodOfFullLoading",
				"TCPOpenRequestTime",
				"TCPOpenResponseTime",
				NULL
			}
		}
	},
	{
		"Device.IP.Diagnostics.UploadDiagnostics", ip_diagnostics_upload, "async",
		{
			.in = (const char *[]) {
				"Interface",
				"UploadURL",
				"DSCP",
				"EthernetPriority",
				"TestFileLength",
				"TimeBasedTestDuration",
				"TimeBasedTestMeasurementInterval",
				"TimeBasedTestMeasurementOffset",
				"ProtocolVersion",
				"NumberOfConnections",
				"EnablePerConnectionResults",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"IPAddressUsed",
				"ROMTime",
				"BOMTime",
				"EOMTime",
				"TestBytesSent",
				"TotalBytesReceived",
				"TotalBytesSent",
				"TestBytesSentUnderFullLoading",
				"TotalBytesReceivedUnderFullLoading",
				"TotalBytesSentUnderFullLoading",
				"PeriodOfFullLoading",
				"TCPOpenRequestTime",
				"TCPOpenResponseTime",
				NULL
			}
		}
	},
	{
		"Device.IP.Diagnostics.UDPEchoDiagnostics", ip_diagnostics_udpecho, "async",
		{
			.in = (const char *[]) {
				"Interface",
				"Host",
				"Port",
				"NumberOfRepetitions",
				"Timeout",
				"DataBlockSize",
				"DSCP",
				"InterTransmissionTime",
				"ProtocolVersion",
				"EnableIndividualPacketResults",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"IPAddressUsed",
				"SuccessCount",
				"FailureCount",
				"AverageResponseTime",
				"MinimumResponseTime",
				"MaximumResponseTime",
				NULL
			}
		}
	},
	{
		"Device.IP.Diagnostics.ServerSelectionDiagnostics", ip_diagnostics_serverselection, "async",
		{
			.in = (const char *[]) {
				"Interface",
				"ProtocolVersion",
				"Protocol",
				"HostList",
				"NumberOfRepetitions",
				"Timeout",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"FastestHost",
				"MinimumResponseTime",
				"AverageResponseTime",
				"MaximumResponseTime",
				"IPAddressUsed",
				NULL
			}
		}
	},
	{
		"Device.DNS.Diagnostics.NSLookupDiagnostics", ip_diagnostics_nslookup, "async",
		{
			.in = (const char *[]) {
				"HostName",
				"Interface",
				"DNSServer",
				"Timeout",
				"NumberOfRepetitions",
				NULL
			},
			.out = (const char *[]) {
				"Status",
				"AnswerType",
				"HostNameReturned",
				"IPAddresses",
				"DNSServerIP",
				"ResponseTime",
				NULL
			}
		}
	},
};

void operate_list_cmds(struct dmctx *dmctx)
{
	char *param, *type;
	const operation_args *args;
	const size_t n = ARRAY_SIZE(operate_helper);
	size_t i;
	struct op_cmd *save_pointer = NULL;

	if (dynamic_operate)
		save_pointer = dynamic_operate;

	for(i = 0; i < n; i++) {
		param = dmstrdup(operate_helper[i].name);
		type = (char *)operate_helper[i].type;
		args = &operate_helper[i].args;
		add_list_parameter(dmctx, param, (char *)args, type, NULL);
	}

	for (; (dynamic_operate && dynamic_operate->name); dynamic_operate++) {
		param = dmstrdup(dynamic_operate->name);
		type = (char *)dynamic_operate->type;
		args = &dynamic_operate->args;
		add_list_parameter(dmctx, param, (char *)args, type, NULL);
	}

	if (save_pointer)
		dynamic_operate = save_pointer;
}

static opr_ret_t do_operate(struct dmctx *dmctx, char *path, operation func, const char *input)
{
	json_object *j_input;
	opr_ret_t rc;

	if (input)
		j_input = json_tokener_parse(input);
	else
		j_input = NULL;

	rc = func(dmctx, path, j_input);
	json_object_put(j_input);
	return rc;
}

opr_ret_t operate_on_node(struct dmctx *dmctx, char *path, char *input)
{
	struct op_cmd *save_pointer = NULL;
	const struct op_cmd *op = NULL;
	const size_t n = ARRAY_SIZE(operate_helper);
	size_t i;

	if (dynamic_operate)
		save_pointer = dynamic_operate;

	for (i = 0; i < n; i++) {
		op = &operate_helper[i];

		if (match(path, op->name))
			return do_operate(dmctx, path, op->opt, input);
	}

	for (; (dynamic_operate && dynamic_operate->name); dynamic_operate++) {
		if (match(path, dynamic_operate->name)) {
			opr_ret_t res = do_operate(dmctx, path, dynamic_operate->opt, input);
			if (save_pointer) dynamic_operate = save_pointer;
			return res;
		}
	}

	if (save_pointer)
		dynamic_operate = save_pointer;

	return CMD_NOT_FOUND;
}
