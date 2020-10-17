/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "dmdiagnostics.h"
#include "dmbbfcommon.h"
#include "diagnostics.h"

static int get_diag_enable_true(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*
 * *** Device.IP.Diagnostics.IPPing. ***
 */

static int get_ip_ping_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "DiagnosticState", "None");
	return 0;
}

static int set_ip_ping_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				IPPING_STOP
				set_diagnostics_option("ipping", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_IPPING_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_ip_ping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("ipping", "interface");
	return 0;
}

static int set_ip_ping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "interface", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_protocolversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "ProtocolVersion", "Any");
	return 0;
}

static int set_ip_ping_protocolversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("ipping", "Host");
	return 0;
}

static int set_ip_ping_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "Host", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_repetition_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "NumberOfRepetitions", "3");
	return 0;
}

static int set_ip_ping_repetition_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "Timeout", "1000");
	return 0;
}

static int set_ip_ping_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_block_size(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "DataBlockSize", "64");
	return 0;
}

static int set_ip_ping_block_size(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "DataBlockSize", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "DSCP", "0");
	return 0;
}

static int set_ip_ping_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			set_diagnostics_option("ipping", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_success_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "SuccessCount", "0");
	return 0;
}

static int get_ip_ping_failure_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "FailureCount", "0");
	return 0;
}

static int get_ip_ping_average_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "AverageResponseTime", "0");
	return 0;
}

static int get_ip_ping_min_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "MinimumResponseTime", "0");
	return 0;
}

static int get_ip_ping_max_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "MaximumResponseTime", "0");
	return 0;
}

static int get_ip_ping_AverageResponseTimeDetailed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "AverageResponseTimeDetailed", "0");
	return 0;
}

static int get_ip_ping_MinimumResponseTimeDetailed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "MinimumResponseTimeDetailed", "0");
	return 0;
}

static int get_ip_ping_MaximumResponseTimeDetailed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("ipping", "MaximumResponseTimeDetailed", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.TraceRoute. ***
 */

static int get_IPDiagnosticsTraceRoute_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				TRACEROUTE_STOP
				set_diagnostics_option("traceroute", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_TRACEROUTE_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("traceroute", "interface");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("traceroute", "Host");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "Host", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_NumberOfTries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "NumberOfTries", "3");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_NumberOfTries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","3"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "NumberOfTries", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "Timeout", "5000");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "DataBlockSize", "38");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "DataBlockSize", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_MaxHopCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "MaxHops", "30");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_MaxHopCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","64"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			set_diagnostics_option("traceroute", "MaxHops", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_ResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "ResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsTraceRoute_RouteHopsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("traceroute", "NumberOfHops", "0");
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "host", value);
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_HostAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip", value);
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_ErrorCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_RTTimes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "time", value);
	return 0;
}

/*
 * *** Device.IP.Diagnostics.DownloadDiagnostics. ***
 */

static int get_IPDiagnosticsDownloadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				DOWNLOAD_DIAGNOSTIC_STOP
				set_diagnostics_option("download", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_DOWNLOAD_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("download", "interface");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char interface[256] = {0}, *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			append_dot_to_string(interface, value, sizeof(interface));
			adm_entry_get_linker_value(ctx, interface, &linker);
			if (linker) {
				json_object *res = NULL;
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", linker, String}}, 1, &res);
				if (!res) return 0;
				char *device = dmjson_get_value(res, 1, "device");
				if (device && *device) {
					DOWNLOAD_DIAGNOSTIC_STOP
					set_diagnostics_option("download", "interface", linker);
					set_diagnostics_option("download", "device", device);
				}
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DownloadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("download", "url");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_DownloadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("download", "url", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DownloadTransports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,FTP";
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DownloadDiagnosticMaxConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("download", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "ethernetpriority", "0");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("download", "ethernetpriority", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("download", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "NumberOfConnections", "1");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("download", "NumberOfConnections", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "ROMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "BOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "EOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TestBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TestBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TestBytesReceivedUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TestBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceivedUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesSentUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_PeriodOfFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "PeriodOfFullLoading", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TCPOpenRequestTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TCPOpenResponseTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_PerConnectionResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	char *tmp = get_diagnostics_option("download", "EnablePerConnection");
	string_to_bool(tmp, &b);
	*value = (b) ? "1" : "0";
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "EnablePerConnection", "0");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("download", "EnablePerConnection", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "ROMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "BOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "EOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TestBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TestBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TCPOpenRequestTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "TCPOpenResponseTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.UploadDiagnostics. ***
 */

static int get_IPDiagnosticsUploadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				UPLOAD_DIAGNOSTIC_STOP
				set_diagnostics_option("upload", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_UPLOAD_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("upload", "interface");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char interface[256] = {0}, *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			append_dot_to_string(interface, value, sizeof(interface));
			adm_entry_get_linker_value(ctx, interface, &linker);
			if (linker) {
				json_object *res = NULL;
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", linker, String}}, 1, &res);
				if (!res) return 0;
				char *device = dmjson_get_value(res, 1, "device");
				if (device && *device) {
					UPLOAD_DIAGNOSTIC_STOP
					set_diagnostics_option("upload", "interface", linker);
					set_diagnostics_option("upload", "device", device);
				}
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_UploadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("upload", "url");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_UploadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "url", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_UploadTransports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,FTP";
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "ethernetpriority", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "ethernetpriority", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TestFileLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TestFileLength", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_TestFileLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "TestFileLength", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "NumberOfConnections", "1");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "NumberOfConnections", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "ROMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "BOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "EOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TestBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TestBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TestBytesSentUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TestBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesReceivedUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesSentUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_PeriodOfFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload","PeriodOfFullLoading", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TCPOpenRequestTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TCPOpenResponseTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_PerConnectionResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	char *tmp = get_diagnostics_option("upload", "EnablePerConnection");
	string_to_bool(tmp, &b);
	*value = (b) ? "1" : "0";
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "EnablePerConnection", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			set_diagnostics_option("upload", "EnablePerConnection", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "ROMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "BOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "EOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TestBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TestBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TotalBytesSent", "0");
	return 0;

}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TCPOpenRequestTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "TCPOpenResponseTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.UDPEchoDiagnostics. ***
 */

static int get_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				UDPECHO_STOP;
				set_diagnostics_option("udpechodiag", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_UDPECHO_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("udpechodiag", "Interface");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "Interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("udpechodiag", "Host");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "Host", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "port", "1");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "port", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "NumberOfRepetitions", "1");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "Timeout", "5000");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "DataBlockSize", "24");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "DataBlockSize", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "InterTransmissionTime", "1000");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "InterTransmissionTime", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			set_diagnostics_option("udpechodiag", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_SuccessCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "SuccessCount", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_FailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "FailureCount", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_AverageResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "AverageResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_MinimumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "MinimumResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_MaximumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "MaximumResponseTime", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.ServerSelectionDiagnostics. ***
 */

static int get_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				SERVERSELECTION_STOP
				set_diagnostics_option("serverselection", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_SERVERSELECTION_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("serverselection", "interface");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			set_diagnostics_option("serverselection", "interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			set_diagnostics_option("serverselection", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "Protocol", "ICMP");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ServerSelectionProtocol, 2, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			set_diagnostics_option("serverselection", "Protocol", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "port", "1");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP;
			set_diagnostics_option("serverselection", "port", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_HostList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("serverselection", "HostList");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_HostList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 10, -1, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			set_diagnostics_option("serverselection", "HostList", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "NumberOfRepetitions", "3");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			set_diagnostics_option("serverselection", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "Timeout", "1000");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			set_diagnostics_option("serverselection", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_FastestHost(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("serverselection", "FastestHost");
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_MinimumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "MinimumResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_AverageResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "AverageResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_MaximumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("serverselection", "MaximumResponseTime", "0");
	return 0;
}

static int browseIPDiagnosticsTraceRouteRouteHopsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst, *max_inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "RouteHops", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
				   (void *)s, "routehop_instance", "routehop_alias", DMMAP_DIAGNOSTIGS, "RouteHops");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPDiagnosticsDownloadDiagnosticsPerConnectionResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst, *max_inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "DownloadPerConnection", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
				   (void *)s, "perconnection_instance", "perconnection_alias", DMMAP_DIAGNOSTIGS, "DownloadPerConnection");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPDiagnosticsUploadDiagnosticsPerConnectionResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst, *max_inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "UploadPerConnection", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
				   (void *)s, "perconnection_instance", "perconnection_alias", DMMAP_DIAGNOSTIGS, "UploadPerConnection");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

/* *** Device.IP.Diagnostics. *** */
DMOBJ tIPDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPPing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsIPPingParams, NULL, BBFDM_CWMP},
{"TraceRoute", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsTraceRouteObj, tIPDiagnosticsTraceRouteParams, NULL, BBFDM_CWMP},
{"DownloadDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsDownloadDiagnosticsObj, tIPDiagnosticsDownloadDiagnosticsParams, NULL, BBFDM_CWMP},
{"UploadDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUploadDiagnosticsObj, tIPDiagnosticsUploadDiagnosticsParams, NULL, BBFDM_CWMP},
{"UDPEchoDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUDPEchoDiagnosticsParams, NULL, BBFDM_CWMP},
{"ServerSelectionDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsServerSelectionDiagnosticsParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IPv4PingSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6PingSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4TraceRouteSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6TraceRouteSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4DownloadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6DownloadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4UploadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6UploadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4UDPEchoDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6UDPEchoDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4ServerSelectionDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6ServerSelectionDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Diagnostics.IPPing. *** */
DMLEAF tIPDiagnosticsIPPingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_ip_ping_diagnostics_state, set_ip_ping_diagnostics_state, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_ip_ping_interface, set_ip_ping_interface, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_ip_ping_protocolversion, set_ip_ping_protocolversion, NULL, NULL, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_ip_ping_host, set_ip_ping_host, NULL, NULL, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_ip_ping_repetition_number, set_ip_ping_repetition_number, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_ip_ping_timeout, set_ip_ping_timeout, NULL, NULL, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_ip_ping_block_size, set_ip_ping_block_size, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_ip_ping_DSCP, set_ip_ping_DSCP, NULL, NULL, BBFDM_CWMP},
{"SuccessCount", &DMREAD, DMT_UNINT, get_ip_ping_success_count, NULL, NULL, NULL, BBFDM_CWMP},
{"FailureCount", &DMREAD, DMT_UNINT, get_ip_ping_failure_count, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_average_response_time, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_min_response_time, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_max_response_time, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_AverageResponseTimeDetailed, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_MinimumResponseTimeDetailed, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_MaximumResponseTimeDetailed, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.TraceRoute. *** */
DMOBJ tIPDiagnosticsTraceRouteObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"RouteHops", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsTraceRouteRouteHopsInst, NULL, NULL, NULL, NULL, tIPDiagnosticsTraceRouteRouteHopsParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsTraceRouteParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_DiagnosticsState, set_IPDiagnosticsTraceRoute_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_Interface, set_IPDiagnosticsTraceRoute_Interface, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_ProtocolVersion, set_IPDiagnosticsTraceRoute_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_Host, set_IPDiagnosticsTraceRoute_Host, NULL, NULL, BBFDM_CWMP},
{"NumberOfTries", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_NumberOfTries, set_IPDiagnosticsTraceRoute_NumberOfTries, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_Timeout, set_IPDiagnosticsTraceRoute_Timeout, NULL, NULL, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_DataBlockSize, set_IPDiagnosticsTraceRoute_DataBlockSize, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_DSCP, set_IPDiagnosticsTraceRoute_DSCP, NULL, NULL, BBFDM_CWMP},
{"MaxHopCount", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_MaxHopCount, set_IPDiagnosticsTraceRoute_MaxHopCount, NULL, NULL, BBFDM_CWMP},
{"ResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRoute_ResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"RouteHopsNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRoute_RouteHopsNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.TraceRoute.RouteHops.{i}. *** */
DMLEAF tIPDiagnosticsTraceRouteRouteHopsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Host", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_Host, NULL, NULL, NULL, BBFDM_CWMP},
{"HostAddress", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_HostAddress, NULL, NULL, NULL, BBFDM_CWMP},
{"ErrorCode", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRouteRouteHops_ErrorCode, NULL, NULL, NULL, BBFDM_CWMP},
{"RTTimes", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_RTTimes, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.DownloadDiagnostics. *** */
DMOBJ tIPDiagnosticsDownloadDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PerConnectionResult", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsDownloadDiagnosticsPerConnectionResultInst, NULL, NULL, NULL, NULL, tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsDownloadDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DiagnosticsState, set_IPDiagnosticsDownloadDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_Interface, set_IPDiagnosticsDownloadDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"DownloadURL", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DownloadURL, set_IPDiagnosticsDownloadDiagnostics_DownloadURL, NULL, NULL, BBFDM_CWMP},
{"DownloadTransports", &DMREAD, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DownloadTransports, NULL, NULL, NULL, BBFDM_CWMP},
{"DownloadDiagnosticMaxConnections", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_DownloadDiagnosticMaxConnections, NULL, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_DSCP, set_IPDiagnosticsDownloadDiagnostics_DSCP, NULL, NULL, BBFDM_CWMP},
{"EthernetPriority", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_EthernetPriority, set_IPDiagnosticsDownloadDiagnostics_EthernetPriority, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_ProtocolVersion, set_IPDiagnosticsDownloadDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"NumberOfConnections", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_NumberOfConnections, set_IPDiagnosticsDownloadDiagnostics_NumberOfConnections, NULL, NULL, BBFDM_CWMP},
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TestBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TestBytesReceivedUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceivedUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesSentUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"PeriodOfFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_PeriodOfFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"PerConnectionResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_PerConnectionResultNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{"EnablePerConnectionResults", &DMWRITE, DMT_BOOL, get_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults, set_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.DownloadDiagnostics.PerConnectionResult.{i}. *** */
DMLEAF tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TestBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UploadDiagnostics. *** */
DMOBJ tIPDiagnosticsUploadDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PerConnectionResult", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsUploadDiagnosticsPerConnectionResultInst, NULL, NULL, NULL, NULL, tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsUploadDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_DiagnosticsState, set_IPDiagnosticsUploadDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_Interface, set_IPDiagnosticsUploadDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"UploadURL", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_UploadURL, set_IPDiagnosticsUploadDiagnostics_UploadURL, NULL, NULL, BBFDM_CWMP},
{"UploadTransports", &DMREAD, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_UploadTransports, NULL, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_DSCP, set_IPDiagnosticsUploadDiagnostics_DSCP, NULL, NULL, BBFDM_CWMP},
{"EthernetPriority", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_EthernetPriority, set_IPDiagnosticsUploadDiagnostics_EthernetPriority, NULL, NULL, BBFDM_CWMP},
{"TestFileLength", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestFileLength, set_IPDiagnosticsUploadDiagnostics_TestFileLength, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_ProtocolVersion, set_IPDiagnosticsUploadDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"NumberOfConnections", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_NumberOfConnections, set_IPDiagnosticsUploadDiagnostics_NumberOfConnections, NULL, NULL, BBFDM_CWMP},
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestBytesSentUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesReceivedUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesSentUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"PeriodOfFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_PeriodOfFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"PerConnectionResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_PerConnectionResultNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{"EnablePerConnectionResults", &DMWRITE, DMT_BOOL, get_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults, set_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UploadDiagnostics.PerConnectionResult.{i}. *** */
DMLEAF tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TestBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UDPEchoDiagnostics. *** */
DMLEAF tIPDiagnosticsUDPEchoDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState, set_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_Interface, set_IPDiagnosticsUDPEchoDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_Host, set_IPDiagnosticsUDPEchoDiagnostics_Host, NULL, NULL, BBFDM_CWMP},
{"Port", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_Port, set_IPDiagnosticsUDPEchoDiagnostics_Port, NULL, NULL, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions, set_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_Timeout, set_IPDiagnosticsUDPEchoDiagnostics_Timeout, NULL, NULL, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize, set_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_DSCP, set_IPDiagnosticsUDPEchoDiagnostics_DSCP, NULL, NULL, BBFDM_CWMP},
{"InterTransmissionTime", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime, set_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion, set_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"SuccessCount", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_SuccessCount, NULL, NULL, NULL, BBFDM_CWMP},
{"FailureCount", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_FailureCount, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_AverageResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_MinimumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_MaximumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.ServerSelectionDiagnostics. *** */
DMLEAF tIPDiagnosticsServerSelectionDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState, set_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_Interface, set_IPDiagnosticsServerSelectionDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion, set_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"Protocol", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_Protocol, set_IPDiagnosticsServerSelectionDiagnostics_Protocol, NULL, NULL, BBFDM_CWMP},
{CUSTOM_PREFIX"Port", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_Port, set_IPDiagnosticsServerSelectionDiagnostics_Port, NULL, NULL, BBFDM_CWMP},
{"HostList", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_HostList, set_IPDiagnosticsServerSelectionDiagnostics_HostList, NULL, NULL, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions, set_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_Timeout, set_IPDiagnosticsServerSelectionDiagnostics_Timeout, NULL, NULL, BBFDM_CWMP},
{"FastestHost", &DMREAD, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_FastestHost, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_MinimumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_AverageResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_MaximumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};
