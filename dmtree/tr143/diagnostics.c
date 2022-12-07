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

#include "dmdiagnostics.h"
#include "dmbbfcommon.h"
#include "diagnostics.h"

#define TRACEROUTE_DIAGNOSTIC_PATH "/usr/share/bbfdm/traceroute"
#define DOWNLOAD_DIAGNOSTIC_PATH "/usr/share/bbfdm/download"
#define UPLOAD_DIAGNOSTIC_PATH "/usr/share/bbfdm/upload"

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static int get_diag_enable_true(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				set_diagnostics_option("ipping", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_IPPING_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_ip_ping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("ipping", "interface");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_ip_ping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("ipping");
			set_diagnostics_interface_option(ctx, "ipping", value);
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
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("ipping");
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("ipping");
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
			reset_diagnostic_state("ipping");
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
			reset_diagnostic_state("ipping");
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
			reset_diagnostic_state("ipping");
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
			reset_diagnostic_state("ipping");
			set_diagnostics_option("ipping", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPPing_IPAddressUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("ipping", "IPAddressUsed");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				set_diagnostics_option("traceroute", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_TRACEROUTE_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("traceroute", "interface");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("traceroute");
			set_diagnostics_interface_option(ctx, "traceroute", value);
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
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("traceroute");
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("traceroute");
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
			reset_diagnostic_state("traceroute");
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
			reset_diagnostic_state("traceroute");
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
			reset_diagnostic_state("traceroute");
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
			reset_diagnostic_state("traceroute");
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
			reset_diagnostic_state("traceroute");
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

static int get_IPDiagnosticsTraceRoute_IPAddressUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("traceroute", "IPAddressUsed");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
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
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("download");
			set_diagnostics_interface_option(ctx, "download", value);
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("download");
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
			reset_diagnostic_state("download");
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
			reset_diagnostic_state("download");
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
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("download");
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
			reset_diagnostic_state("download");
			set_diagnostics_option("download", "NumberOfConnections", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_IPAddressUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("download", "IPAddressUsed");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "ROMTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "BOMTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("download", "EOMTime", "0001-01-01T00:00:00.000000Z");
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
			reset_diagnostic_state("download");
			set_diagnostics_option("download", "EnablePerConnection", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ROMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "BOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "EOMtime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TestBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TestBytesReceived", "0");
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
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TCPOpenRequestTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TCPOpenResponseTime", "0001-01-01T00:00:00.000000Z");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
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
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("upload");
			set_diagnostics_interface_option(ctx, "upload", value);
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("upload");
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
			reset_diagnostic_state("upload");
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
			reset_diagnostic_state("upload");
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
			reset_diagnostic_state("upload");
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
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("upload");
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
			reset_diagnostic_state("upload");
			set_diagnostics_option("upload", "NumberOfConnections", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_IPAddressUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("upload", "IPAddressUsed");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "ROMTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "BOMTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("upload", "EOMTime", "0001-01-01T00:00:00.000000Z");
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
			reset_diagnostic_state("upload");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				set_diagnostics_option("udpechodiag", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_UDPECHO_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("udpechodiag", "interface");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("udpechodiag");
			set_diagnostics_interface_option(ctx, "udpechodiag", value);
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("udpechodiag");
			set_diagnostics_option("udpechodiag", "Host", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("udpechodiag", "port", "7");
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
			reset_diagnostic_state("udpechodiag");
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
			reset_diagnostic_state("udpechodiag");
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
			reset_diagnostic_state("udpechodiag");
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
			reset_diagnostic_state("udpechodiag");
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
			reset_diagnostic_state("udpechodiag");
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
			reset_diagnostic_state("udpechodiag");
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
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("udpechodiag");
			set_diagnostics_option("udpechodiag", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_IPAddressUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("udpechodiag", "IPAddressUsed");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				set_diagnostics_option("serverselection", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_SERVERSELECTION_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("serverselection", "interface");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("serverselection");
			set_diagnostics_interface_option(ctx, "serverselection", value);
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
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("serverselection");
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
			if (dm_validate_string(value, -1, -1, ServerSelectionProtocol, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("serverselection");
			set_diagnostics_option("serverselection", "Protocol", value);
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
			if (dm_validate_string_list(value, -1, 10, -1, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("serverselection");
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
			reset_diagnostic_state("serverselection");
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
			reset_diagnostic_state("serverselection");
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

static int get_IPDiagnosticsServerSelectionDiagnostics_IPAddressUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("serverselection", "IPAddressUsed");
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseIPDiagnosticsTraceRouteRouteHopsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "RouteHops", s) {
		inst = handle_instance(dmctx, parent_node, s, "routehop_instance", "routehop_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPDiagnosticsDownloadDiagnosticsPerConnectionResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "DownloadPerConnection", s) {
		inst = handle_instance(dmctx, parent_node, s, "perconnection_instance", "perconnection_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPDiagnosticsUploadDiagnosticsPerConnectionResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "UploadPerConnection", s) {
		inst = handle_instance(dmctx, parent_node, s, "perconnection_instance", "perconnection_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static operation_args ip_diagnostics_ipping_args = {
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
};

static int get_operate_args_IPDiagnostics_IPPing(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_ipping_args;
	return 0;
}

static int operate_IPDiagnostics_IPPing(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res = NULL;

	char *ipping_host = dmjson_get_value((json_object *)value, 1, "Host");
	if (ipping_host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;
	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *ipping_interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *ipping_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *ipping_nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");
	char *ipping_timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *ipping_datablocksize = dmjson_get_value((json_object *)value, 1, "DataBlockSize");
	char *ipping_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *proto = (bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto";

	dmubus_call_blocking("bbf.diag", "ipping",
			UBUS_ARGS{
				{"host", ipping_host, String},
				{"iface", ipping_interface, String},
				{"ip_proto", ipping_proto, String},
				{"nbr_of_rep", ipping_nbofrepetition, String},
				{"timeout", ipping_timeout, String},
				{"data_size", ipping_datablocksize, String},
				{"dscp", ipping_dscp, String},
				{"proto", proto, String}
			},
			8, &res);

	if (res == NULL)
		return CMD_FAIL;

	char *ipping_status = dmjson_get_value(res, 1, "Status");
	char *ipping_ip_address_used = dmjson_get_value(res, 1, "IPAddressUsed");
	char *ipping_success_count = dmjson_get_value(res, 1, "SuccessCount");
	char *ipping_failure_count = dmjson_get_value(res, 1, "FailureCount");
	char *ipping_average_response_time = dmjson_get_value(res, 1, "AverageResponseTime");
	char *ipping_minimum_response_time = dmjson_get_value(res, 1, "MinimumResponseTime");
	char *ipping_maximum_response_time = dmjson_get_value(res, 1, "MaximumResponseTime");
	char *ipping_average_response_time_detailed = dmjson_get_value(res, 1, "AverageResponseTimeDetailed");
	char *ipping_minimum_response_time_detailed = dmjson_get_value(res, 1, "MinimumResponseTimeDetailed");
	char *ipping_maximum_response_time_detailed = dmjson_get_value(res, 1, "MaximumResponseTimeDetailed");

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(ipping_status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("IPAddressUsed"), dmstrdup(ipping_ip_address_used), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("SuccessCount"), dmstrdup(ipping_success_count), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("FailureCount"), dmstrdup(ipping_failure_count), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTime"), dmstrdup(ipping_average_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), dmstrdup(ipping_minimum_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), dmstrdup(ipping_maximum_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTimeDetailed"), dmstrdup(ipping_average_response_time_detailed), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTimeDetailed"), dmstrdup(ipping_minimum_response_time_detailed), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTimeDetailed"), dmstrdup(ipping_maximum_response_time_detailed), DMT_TYPE[DMT_UNINT], NULL);

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

static operation_args ip_diagnostics_trace_route_args = {
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
		"RouteHops.{i}.Host",
		"RouteHops.{i}.HostAddress",
		"RouteHops.{i}.ErrorCode",
		"RouteHops.{i}.RTTimes",
		NULL
	}
};

static int get_operate_args_IPDiagnostics_TraceRoute(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_trace_route_args;
	return 0;
}

static int operate_IPDiagnostics_TraceRoute(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *arr_route_hops = NULL, *route_hops_obj = NULL;
	char *route_hops_host[2] = {0};
	char *route_hops_host_address[2] = {0};
	char *route_hops_rttimes[2] = {0};
	char *route_hops_errorcode = NULL;
	char input[2048] = {0};
	char output[2048] = {0};
	char cmd[2096] = {0};
	int idx = 0;

	char *host = dmjson_get_value((json_object *)value, 1, "Host");
	if (host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *ip_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *nboftries = dmjson_get_value((json_object *)value, 1, "NumberOfTries");
	char *timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *datablocksize = dmjson_get_value((json_object *)value, 1, "DataBlockSize");
	char *dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *maxhops = dmjson_get_value((json_object *)value, 1, "MaxHopCount");

	snprintf(input, sizeof(input), "'{\"host\": \"%s\",\"iface\":\"%s\",\"ip_proto\":\"%s\",\"nbr_of_tries\":\"%s\",\"timeout\":\"%s\",\"data_size\":\"%s\",\"dscp\":\"%s\",\"max_hop_cnt\":\"%s\",\"proto\":\"%s\"}'",
									host,
									interface,
									ip_proto,
									nboftries,
									timeout,
									datablocksize,
									dscp,
									maxhops,
									(bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto");

	snprintf(cmd, sizeof(cmd), "sh %s %s", TRACEROUTE_DIAGNOSTIC_PATH, input);

	FILE *pp = popen(cmd, "r");
	if (pp != NULL) {
		fgets(output, sizeof(output) , pp);
		pclose(pp);
	} else {
		return CMD_FAIL;
	}

	json_object *res = (DM_STRLEN(output)) ? json_tokener_parse(output) : NULL;

	if (res == NULL)
		return CMD_FAIL;

	char *status = dmjson_get_value(res, 1, "Status");
	char *ip_address_used = dmjson_get_value(res, 1, "IPAddressUsed");
	char *response_time = dmjson_get_value(res, 1, "ResponseTime");
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("IPAddressUsed"), dmstrdup(ip_address_used), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("ResponseTime"), dmstrdup(response_time), DMT_TYPE[DMT_UNINT], NULL);

	dmjson_foreach_obj_in_array(res, arr_route_hops, route_hops_obj, idx, 1, "RouteHops") {
		int i = idx + 1;

		dmasprintf(&route_hops_host[0], "RouteHops.%d.Host", i);
		dmasprintf(&route_hops_host_address[0], "RouteHops.%d.HostAddress", i);
		dmasprintf(&route_hops_rttimes[0], "RouteHops.%d.RTTimes", i);
		dmasprintf(&route_hops_errorcode, "RouteHops.%d.ErrorCode", i);

		route_hops_host[1] = dmjson_get_value(route_hops_obj, 1, "Host");
		route_hops_host_address[1] = dmjson_get_value(route_hops_obj, 1, "HostAddress");
		route_hops_rttimes[1] = dmjson_get_value(route_hops_obj, 1, "RTTimes");

		add_list_parameter(ctx, route_hops_host[0], dmstrdup(route_hops_host[1]), DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, route_hops_host_address[0], dmstrdup(route_hops_host_address[1]), DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, route_hops_rttimes[0], dmstrdup(route_hops_rttimes[1]), DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, route_hops_errorcode, "0", DMT_TYPE[DMT_UNINT], NULL);
	}

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

static operation_args ip_diagnostics_download_args = {
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
		"PerConnectionResult.{i}.ROMTime",
		"PerConnectionResult.{i}.BOMTime",
		"PerConnectionResult.{i}.EOMTime",
		"PerConnectionResult.{i}.TestBytesReceived",
		"PerConnectionResult.{i}.TotalBytesReceived",
		"PerConnectionResult.{i}.TotalBytesSent",
		"PerConnectionResult.{i}.TCPOpenRequestTime",
		"PerConnectionResult.{i}.TCPOpenResponseTime",
		"IncrementalResult.{i}.TestBytesReceived",
		"IncrementalResult.{i}.TotalBytesReceived",
		"IncrementalResult.{i}.TotalBytesSent",
		"IncrementalResult.{i}.StartTime",
		"IncrementalResult.{i}.EndTime",
		NULL
	}
};

static int get_operate_args_IPDiagnostics_DownloadDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_download_args;
	return 0;
}

static int operate_IPDiagnostics_DownloadDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char input[2048] = {0};
	char output[2048] = {0};
	char cmd[2096] = {0};
	char *download_url = dmjson_get_value((json_object *)value, 1, "DownloadURL");

	if (download_url[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	if (strncmp(download_url, HTTP_URI, strlen(HTTP_URI)) != 0 &&
		strncmp(download_url, FTP_URI, strlen(FTP_URI)) != 0 &&
		strchr(download_url,'@') != NULL)
		return CMD_INVALID_ARGUMENTS;

	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *download_interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *download_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *download_ethernet_priority = dmjson_get_value((json_object *)value, 1, "EthernetPriority");
	char *download_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *download_num_of_connections = dmjson_get_value((json_object *)value, 1, "NumberOfConnections");
	char *download_enable_per_connection_results = dmjson_get_value((json_object *)value, 1, "EnablePerConnectionResults");

	snprintf(input, sizeof(input), "'{\"url\": \"%s\",\"iface\":\"%s\",\"dscp\":\"%s\",\"eth_prio\":\"%s\",\"ip_proto\":\"%s\",\"num_of_con\":\"%s\",\"enable_per_con\":\"%s\",\"proto\":\"%s\"}'",
									download_url,
									download_interface,
									download_dscp,
									download_ethernet_priority,
									download_proto,
									download_num_of_connections,
									download_enable_per_connection_results,
									(bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto");

	snprintf(cmd, sizeof(cmd), "sh %s %s", DOWNLOAD_DIAGNOSTIC_PATH, input);

	FILE *pp = popen(cmd, "r");
	if (pp != NULL) {
		fgets(output, sizeof(output) , pp);
		pclose(pp);
	} else {
		return CMD_FAIL;
	}

	json_object *res = (DM_STRLEN(output)) ? json_tokener_parse(output) : NULL;

	if (res == NULL)
		return CMD_FAIL;

	char *status = dmjson_get_value(res, 1, "Status");
	char *ip_address_used = dmjson_get_value(res, 1, "IPAddressUsed");
	char *rom_time = dmjson_get_value(res, 1, "ROMTime");
	char *bom_time = dmjson_get_value(res, 1, "BOMTime");
	char *eom_time = dmjson_get_value(res, 1, "EOMTime");
	char *test_bytes_received = dmjson_get_value(res, 1, "TestBytesReceived");
	char *total_bytes_received = dmjson_get_value(res, 1, "TotalBytesReceived");
	char *total_bytes_sent = dmjson_get_value(res, 1, "TotalBytesSent");
	char *period_of_full_loading = dmjson_get_value(res, 1, "PeriodOfFullLoading");
	char *tcp_open_request_time = dmjson_get_value(res, 1, "TCPOpenRequestTime");
	char *tcp_open_response_time = dmjson_get_value(res, 1, "TCPOpenResponseTime");

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("IPAddressUsed"), dmstrdup(ip_address_used), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("ROMTime"), rom_time[0] != 0 ? dmstrdup(rom_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("BOMTime"), bom_time[0] != 0 ? dmstrdup(bom_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("EOMTime"), eom_time[0] != 0 ? dmstrdup(eom_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesReceived"), dmstrdup(test_bytes_received), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceived"), dmstrdup(total_bytes_received), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSent"), dmstrdup(total_bytes_sent), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesReceivedUnderFullLoading"), dmstrdup(test_bytes_received), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceivedUnderFullLoading"), dmstrdup(total_bytes_received), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSentUnderFullLoading"), dmstrdup(total_bytes_sent), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("PeriodOfFullLoading"), dmstrdup(period_of_full_loading), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenRequestTime"), tcp_open_request_time[0] != 0 ? dmstrdup(tcp_open_request_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenResponseTime"), tcp_open_response_time[0] != 0 ? dmstrdup(tcp_open_response_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

static operation_args ip_diagnostics_upload_args = {
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
		"PerConnectionResult.{i}.ROMTime",
		"PerConnectionResult.{i}.BOMTime",
		"PerConnectionResult.{i}.EOMTime",
		"PerConnectionResult.{i}.TestBytesSent",
		"PerConnectionResult.{i}.TotalBytesReceived",
		"PerConnectionResult.{i}.TotalBytesSent",
		"PerConnectionResult.{i}.TCPOpenRequestTime",
		"PerConnectionResult.{i}.TCPOpenResponseTime",
		"IncrementalResult.{i}.TestBytesSent",
		"IncrementalResult.{i}.TotalBytesReceived",
		"IncrementalResult.{i}.TotalBytesSent",
		"IncrementalResult.{i}.StartTime",
		"IncrementalResult.{i}.EndTime",
		NULL
	}
};

static int get_operate_args_IPDiagnostics_UploadDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_upload_args;
	return 0;
}

static int operate_IPDiagnostics_UploadDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char input[2048] = {0};
	char output[2048] = {0};
	char cmd[2096] = {0};
	char *upload_url = dmjson_get_value((json_object *)value, 1, "UploadURL");

	if (upload_url[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	if (strncmp(upload_url, HTTP_URI, strlen(HTTP_URI)) != 0 &&
		strncmp(upload_url, FTP_URI, strlen(FTP_URI)) != 0 &&
		strchr(upload_url,'@') != NULL)
		return CMD_INVALID_ARGUMENTS;

	char *upload_test_file_length = dmjson_get_value((json_object *)value, 1, "TestFileLength");
	if (upload_test_file_length[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *upload_interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *upload_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *upload_ethernet_priority = dmjson_get_value((json_object *)value, 1, "EthernetPriority");
	char *upload_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *upload_num_of_connections = dmjson_get_value((json_object *)value, 1, "NumberOfConnections");
	char *upload_enable_per_connection_results = dmjson_get_value((json_object *)value, 1, "EnablePerConnectionResults");

	snprintf(input, sizeof(input), "'{\"url\": \"%s\",\"iface\":\"%s\",\"dscp\":\"%s\",\"eth_prio\":\"%s\",\"file_length\":\"%s\",\"ip_proto\":\"%s\",\"num_of_con\":\"%s\",\"enable_per_con\":\"%s\",\"proto\":\"%s\"}'",
			upload_url,
									upload_interface,
									upload_dscp,
									upload_ethernet_priority,
									upload_test_file_length,
									upload_proto,
									upload_num_of_connections,
									upload_enable_per_connection_results,
									(bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto");

	snprintf(cmd, sizeof(cmd), "sh %s %s", UPLOAD_DIAGNOSTIC_PATH, input);

	FILE *pp = popen(cmd, "r");
	if (pp != NULL) {
		fgets(output, sizeof(output) , pp);
		pclose(pp);
	} else {
		return CMD_FAIL;
	}

	json_object *res = (DM_STRLEN(output)) ? json_tokener_parse(output) : NULL;

	if (res == NULL)
		return CMD_FAIL;

	char *upload_status = dmjson_get_value(res, 1, "Status");
	char *upload_ip_address_used = dmjson_get_value(res, 1, "IPAddressUsed");
	char *upload_rom_time = dmjson_get_value(res, 1, "ROMTime");
	char *upload_bom_time = dmjson_get_value(res, 1, "BOMTime");
	char *upload_eom_time = dmjson_get_value(res, 1, "EOMTime");
	char *upload_test_bytes_sent = dmjson_get_value(res, 1, "TestBytesSent");
	char *upload_total_bytes_received = dmjson_get_value(res, 1, "TotalBytesReceived");
	char *upload_total_bytes_sent = dmjson_get_value(res, 1, "TotalBytesSent");
	char *upload_period_of_full_loading = dmjson_get_value(res, 1, "PeriodOfFullLoading");
	char *upload_tcp_open_request_time = dmjson_get_value(res, 1, "TCPOpenRequestTime");
	char *upload_tcp_open_response_time = dmjson_get_value(res, 1, "TCPOpenResponseTime");

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(upload_status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("IPAddressUsed"), dmstrdup(upload_ip_address_used), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("ROMTime"), upload_rom_time[0] != 0 ? dmstrdup(upload_rom_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("BOMTime"), upload_bom_time[0] != 0 ? dmstrdup(upload_bom_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("EOMTime"), upload_eom_time[0] != 0 ? dmstrdup(upload_eom_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesSent"), dmstrdup(upload_test_bytes_sent), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceived"), dmstrdup(upload_total_bytes_received), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSent"), dmstrdup(upload_total_bytes_sent), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesSentUnderFullLoading"), dmstrdup(upload_test_bytes_sent), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceivedUnderFullLoading"), dmstrdup(upload_total_bytes_received), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSentUnderFullLoading"), dmstrdup(upload_total_bytes_sent), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("PeriodOfFullLoading"), dmstrdup(upload_period_of_full_loading), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenRequestTime"), upload_tcp_open_request_time[0] != 0 ? dmstrdup(upload_tcp_open_request_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenResponseTime"), upload_tcp_open_response_time[0] != 0 ? dmstrdup(upload_tcp_open_response_time) : "0001-01-01T00:00:00.000000Z", DMT_TYPE[DMT_TIME], NULL);

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

static operation_args ip_diagnostics_udpecho_args = {
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
		"IndividualPacketResult.{i}.PacketSuccess",
		"IndividualPacketResult.{i}.PacketSendTime",
		"IndividualPacketResult.{i}.PacketReceiveTime",
		"IndividualPacketResult.{i}.TestGenSN",
		"IndividualPacketResult.{i}.TestRespSN",
		"IndividualPacketResult.{i}.TestRespRcvTimeStamp",
		"IndividualPacketResult.{i}.TestRespReplyTimeStamp",
		"IndividualPacketResult.{i}.TestRespReplyFailureCount",
		NULL
	}
};

static int get_operate_args_IPDiagnostics_UDPEchoDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_udpecho_args;
	return 0;
}

static int operate_IPDiagnostics_UDPEchoDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res = NULL;

	char *udpecho_host = dmjson_get_value((json_object *)value, 1, "Host");
	if (udpecho_host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *udpecho_port = dmjson_get_value((json_object *)value, 1, "Port");
	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *udpecho_interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *udpecho_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *udpecho_nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");
	char *udpecho_timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *udpecho_datablocksize = dmjson_get_value((json_object *)value, 1, "DataBlockSize");
	char *udpecho_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *udpecho_inter_transmission_time = dmjson_get_value((json_object *)value, 1, "InterTransmissionTime");
	char *proto = (bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto";

	dmubus_call_blocking("bbf.diag", "udpecho",
			UBUS_ARGS{
				{"host", udpecho_host, String},
				{"port", udpecho_port, String},
				{"iface", udpecho_interface, String},
				{"ip_proto", udpecho_proto, String},
				{"nbr_of_rep", udpecho_nbofrepetition, String},
				{"timeout", udpecho_timeout, String},
				{"data_size", udpecho_datablocksize, String},
				{"dscp", udpecho_dscp, String},
				{"inter_trans_time", udpecho_inter_transmission_time, String},
				{"proto", proto, String}
			},
			10, &res);

	if (res == NULL)
		return CMD_FAIL;

	char *status = dmjson_get_value(res, 1, "Status");
	char *ip_address_used = dmjson_get_value(res, 1, "IPAddressUsed");
	char *udpecho_success_count = dmjson_get_value(res, 1, "SuccessCount");
	char *udpecho_failure_count = dmjson_get_value(res, 1, "FailureCount");
	char *udpecho_average_response_time = dmjson_get_value(res, 1, "AverageResponseTime");
	char *udpecho_minimum_response_time = dmjson_get_value(res, 1, "MinimumResponseTime");
	char *udpecho_maximum_response_time = dmjson_get_value(res, 1, "MaximumResponseTime");

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("IPAddressUsed"), dmstrdup(ip_address_used), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("SuccessCount"), dmstrdup(udpecho_success_count), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("FailureCount"), dmstrdup(udpecho_failure_count), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTime"), dmstrdup(udpecho_average_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), dmstrdup(udpecho_minimum_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), dmstrdup(udpecho_maximum_response_time), DMT_TYPE[DMT_UNINT], NULL);

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

static operation_args ip_diagnostics_server_selection_args = {
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
};

static int get_operate_args_IPDiagnostics_ServerSelectionDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_server_selection_args;
	return 0;
}

static int operate_IPDiagnostics_ServerSelectionDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res = NULL;

	char *hostlist = dmjson_get_value((json_object *)value, 1, "HostList");
	if (hostlist[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *port = dmjson_get_value((json_object *)value, 1, "Port");
	char *protocol_used = dmjson_get_value((json_object *)value, 1, "Protocol");
	char *protocol_version = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");
	char *timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *proto = (bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto";

	dmubus_call_blocking("bbf.diag", "serverselection",
			UBUS_ARGS{
				{"hostlist", hostlist, String},
				{"port", port, String},
				{"iface", interface, String},
				{"ip_proto", protocol_version, String},
				{"nbr_of_rep", nbofrepetition, String},
				{"timeout", timeout, String},
				{"protocol_used", protocol_used, String},
				{"proto", proto, String}
			},
			8, &res);

	if (res == NULL)
		return CMD_FAIL;

	char *status = dmjson_get_value(res, 1, "Status");
	char *fasthost = dmjson_get_value(res, 1, "FastestHost");
	char *average_response_time = dmjson_get_value(res, 1, "AverageResponseTime");
	char *minimum_response_time = dmjson_get_value(res, 1, "MinimumResponseTime");
	char *maximum_response_time = dmjson_get_value(res, 1, "MaximumResponseTime");
	char *ip_address_used = dmjson_get_value(res, 1, "IPAddressUsed");

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("FastestHost"), dmstrdup(fasthost), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTime"), dmstrdup(average_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), dmstrdup(minimum_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), dmstrdup(maximum_response_time), DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("IPAddressUsed"), dmstrdup(ip_address_used), DMT_TYPE[DMT_STRING], NULL);

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.IP.Diagnostics. *** */
DMOBJ tIPDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPPing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsIPPingParams, NULL, BBFDM_CWMP},
{"TraceRoute", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsTraceRouteObj, tIPDiagnosticsTraceRouteParams, NULL, BBFDM_CWMP},
{"DownloadDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsDownloadDiagnosticsObj, tIPDiagnosticsDownloadDiagnosticsParams, NULL, BBFDM_CWMP},
{"UploadDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUploadDiagnosticsObj, tIPDiagnosticsUploadDiagnosticsParams, NULL, BBFDM_CWMP},
{"UDPEchoDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUDPEchoDiagnosticsParams, NULL, BBFDM_CWMP},
{"ServerSelectionDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsServerSelectionDiagnosticsParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IPv4PingSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv6PingSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv4TraceRouteSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv6TraceRouteSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv4DownloadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv6DownloadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv4UploadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv6UploadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true,  NULL, BBFDM_BOTH},
{"IPv4UDPEchoDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv6UDPEchoDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv4ServerSelectionDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPv6ServerSelectionDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, BBFDM_BOTH},
{"IPPing()", &DMASYNC, DMT_COMMAND, get_operate_args_IPDiagnostics_IPPing, operate_IPDiagnostics_IPPing, BBFDM_USP},
{"TraceRoute()", &DMASYNC, DMT_COMMAND, get_operate_args_IPDiagnostics_TraceRoute, operate_IPDiagnostics_TraceRoute, BBFDM_USP},
{"DownloadDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_IPDiagnostics_DownloadDiagnostics, operate_IPDiagnostics_DownloadDiagnostics, BBFDM_USP},
{"UploadDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_IPDiagnostics_UploadDiagnostics, operate_IPDiagnostics_UploadDiagnostics, BBFDM_USP},
{"UDPEchoDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_IPDiagnostics_UDPEchoDiagnostics, operate_IPDiagnostics_UDPEchoDiagnostics, BBFDM_USP},
{"ServerSelectionDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_IPDiagnostics_ServerSelectionDiagnostics, operate_IPDiagnostics_ServerSelectionDiagnostics, BBFDM_USP},
{0}
};

/* *** Device.IP.Diagnostics.IPPing. *** */
DMLEAF tIPDiagnosticsIPPingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_ip_ping_diagnostics_state, set_ip_ping_diagnostics_state, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_ip_ping_interface, set_ip_ping_interface, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_ip_ping_protocolversion, set_ip_ping_protocolversion, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_ip_ping_host, set_ip_ping_host, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_ip_ping_repetition_number, set_ip_ping_repetition_number, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_ip_ping_timeout, set_ip_ping_timeout, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_ip_ping_block_size, set_ip_ping_block_size, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_ip_ping_DSCP, set_ip_ping_DSCP, BBFDM_CWMP},
{"IPAddressUsed", &DMREAD, DMT_STRING, get_IPDiagnosticsIPPing_IPAddressUsed, NULL, BBFDM_CWMP},
{"SuccessCount", &DMREAD, DMT_UNINT, get_ip_ping_success_count, NULL, BBFDM_CWMP},
{"FailureCount", &DMREAD, DMT_UNINT, get_ip_ping_failure_count, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_average_response_time, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_min_response_time, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_max_response_time, NULL, BBFDM_CWMP},
{"AverageResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_AverageResponseTimeDetailed, NULL, BBFDM_CWMP},
{"MinimumResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_MinimumResponseTimeDetailed, NULL, BBFDM_CWMP},
{"MaximumResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_MaximumResponseTimeDetailed, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.TraceRoute. *** */
DMOBJ tIPDiagnosticsTraceRouteObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"RouteHops", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsTraceRouteRouteHopsInst, NULL, NULL, NULL, tIPDiagnosticsTraceRouteRouteHopsParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsTraceRouteParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_DiagnosticsState, set_IPDiagnosticsTraceRoute_DiagnosticsState, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_Interface, set_IPDiagnosticsTraceRoute_Interface, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_ProtocolVersion, set_IPDiagnosticsTraceRoute_ProtocolVersion, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_Host, set_IPDiagnosticsTraceRoute_Host, BBFDM_CWMP},
{"NumberOfTries", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_NumberOfTries, set_IPDiagnosticsTraceRoute_NumberOfTries, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_Timeout, set_IPDiagnosticsTraceRoute_Timeout, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_DataBlockSize, set_IPDiagnosticsTraceRoute_DataBlockSize, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_DSCP, set_IPDiagnosticsTraceRoute_DSCP, BBFDM_CWMP},
{"MaxHopCount", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_MaxHopCount, set_IPDiagnosticsTraceRoute_MaxHopCount, BBFDM_CWMP},
{"ResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRoute_ResponseTime, NULL, BBFDM_CWMP},
{"IPAddressUsed", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRoute_IPAddressUsed, NULL, BBFDM_CWMP},
{"RouteHopsNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRoute_RouteHopsNumberOfEntries, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.TraceRoute.RouteHops.{i}. *** */
DMLEAF tIPDiagnosticsTraceRouteRouteHopsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Host", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_Host, NULL, BBFDM_CWMP},
{"HostAddress", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_HostAddress, NULL, BBFDM_CWMP},
{"ErrorCode", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRouteRouteHops_ErrorCode, NULL, BBFDM_CWMP},
{"RTTimes", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_RTTimes, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.DownloadDiagnostics. *** */
DMOBJ tIPDiagnosticsDownloadDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PerConnectionResult", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsDownloadDiagnosticsPerConnectionResultInst, NULL, NULL, NULL, tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsDownloadDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DiagnosticsState, set_IPDiagnosticsDownloadDiagnostics_DiagnosticsState, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_Interface, set_IPDiagnosticsDownloadDiagnostics_Interface, BBFDM_CWMP},
{"DownloadURL", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DownloadURL, set_IPDiagnosticsDownloadDiagnostics_DownloadURL, BBFDM_CWMP},
{"DownloadTransports", &DMREAD, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DownloadTransports, NULL, BBFDM_CWMP},
{"DownloadDiagnosticMaxConnections", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_DownloadDiagnosticMaxConnections,NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_DSCP, set_IPDiagnosticsDownloadDiagnostics_DSCP, BBFDM_CWMP},
{"EthernetPriority", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_EthernetPriority, set_IPDiagnosticsDownloadDiagnostics_EthernetPriority, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_ProtocolVersion, set_IPDiagnosticsDownloadDiagnostics_ProtocolVersion, BBFDM_CWMP},
{"NumberOfConnections", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_NumberOfConnections, set_IPDiagnosticsDownloadDiagnostics_NumberOfConnections, BBFDM_CWMP},
{"IPAddressUsed", &DMREAD, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_IPAddressUsed, NULL, BBFDM_CWMP},
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_ROMTime, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_BOMTime, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_EOMTime, NULL, BBFDM_CWMP},
{"TestBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TestBytesReceived, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceived, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesSent, NULL, BBFDM_CWMP},
{"TestBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TestBytesReceivedUnderFullLoading, NULL, BBFDM_CWMP},
{"TotalBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceivedUnderFullLoading, NULL, BBFDM_CWMP},
{"TotalBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesSentUnderFullLoading, NULL, BBFDM_CWMP},
{"PeriodOfFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_PeriodOfFullLoading, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_TCPOpenRequestTime, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_TCPOpenResponseTime, NULL, BBFDM_CWMP},
{"PerConnectionResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_PerConnectionResultNumberOfEntries, NULL, BBFDM_CWMP},
{"EnablePerConnectionResults", &DMWRITE, DMT_BOOL, get_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults, set_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.DownloadDiagnostics.PerConnectionResult.{i}. *** */
DMLEAF tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_ROMTime, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_BOMTime, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_EOMTime, NULL, BBFDM_CWMP},
{"TestBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TestBytesReceived, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesReceived, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesSent, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenRequestTime, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenResponseTime, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UploadDiagnostics. *** */
DMOBJ tIPDiagnosticsUploadDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PerConnectionResult", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsUploadDiagnosticsPerConnectionResultInst, NULL, NULL, NULL, tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsUploadDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_DiagnosticsState, set_IPDiagnosticsUploadDiagnostics_DiagnosticsState, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_Interface, set_IPDiagnosticsUploadDiagnostics_Interface, BBFDM_CWMP},
{"UploadURL", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_UploadURL, set_IPDiagnosticsUploadDiagnostics_UploadURL, BBFDM_CWMP},
{"UploadTransports", &DMREAD, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_UploadTransports, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_DSCP, set_IPDiagnosticsUploadDiagnostics_DSCP, BBFDM_CWMP},
{"EthernetPriority", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_EthernetPriority, set_IPDiagnosticsUploadDiagnostics_EthernetPriority, BBFDM_CWMP},
{"TestFileLength", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestFileLength, set_IPDiagnosticsUploadDiagnostics_TestFileLength, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_ProtocolVersion, set_IPDiagnosticsUploadDiagnostics_ProtocolVersion, BBFDM_CWMP},
{"NumberOfConnections", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_NumberOfConnections, set_IPDiagnosticsUploadDiagnostics_NumberOfConnections, BBFDM_CWMP},
{"IPAddressUsed", &DMREAD, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_IPAddressUsed, NULL, BBFDM_CWMP},
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_ROMTime, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_BOMTime, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_EOMTime, NULL, BBFDM_CWMP},
{"TestBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestBytesSent, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesReceived, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesSent, NULL, BBFDM_CWMP},
{"TestBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestBytesSentUnderFullLoading, NULL, BBFDM_CWMP},
{"TotalBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesReceivedUnderFullLoading, NULL, BBFDM_CWMP},
{"TotalBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesSentUnderFullLoading, NULL, BBFDM_CWMP},
{"PeriodOfFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_PeriodOfFullLoading, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_TCPOpenRequestTime, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_TCPOpenResponseTime, NULL, BBFDM_CWMP},
{"PerConnectionResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_PerConnectionResultNumberOfEntries, NULL, BBFDM_CWMP},
{"EnablePerConnectionResults", &DMWRITE, DMT_BOOL, get_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults, set_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UploadDiagnostics.PerConnectionResult.{i}. *** */
DMLEAF tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_ROMTime, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_BOMTime, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_EOMTime, NULL, BBFDM_CWMP},
{"TestBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TestBytesSent, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesReceived, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesSent, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenRequestTime, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenResponseTime, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UDPEchoDiagnostics. *** */
DMLEAF tIPDiagnosticsUDPEchoDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState, set_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_Interface, set_IPDiagnosticsUDPEchoDiagnostics_Interface, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_Host, set_IPDiagnosticsUDPEchoDiagnostics_Host, BBFDM_CWMP},
{"Port", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_Port, set_IPDiagnosticsUDPEchoDiagnostics_Port, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions, set_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_Timeout, set_IPDiagnosticsUDPEchoDiagnostics_Timeout, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize, set_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_DSCP, set_IPDiagnosticsUDPEchoDiagnostics_DSCP, BBFDM_CWMP},
{"InterTransmissionTime", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime, set_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion, set_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion, BBFDM_CWMP},
{"IPAddressUsed", &DMREAD, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_IPAddressUsed, NULL, BBFDM_CWMP},
{"SuccessCount", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_SuccessCount, NULL, BBFDM_CWMP},
{"FailureCount", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_FailureCount, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_AverageResponseTime, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_MinimumResponseTime, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_MaximumResponseTime, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.ServerSelectionDiagnostics. *** */
DMLEAF tIPDiagnosticsServerSelectionDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState, set_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_Interface, set_IPDiagnosticsServerSelectionDiagnostics_Interface, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion, set_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion, BBFDM_CWMP},
{"Protocol", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_Protocol, set_IPDiagnosticsServerSelectionDiagnostics_Protocol, BBFDM_CWMP},
{"HostList", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_HostList, set_IPDiagnosticsServerSelectionDiagnostics_HostList, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions, set_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_Timeout, set_IPDiagnosticsServerSelectionDiagnostics_Timeout, BBFDM_CWMP},
{"FastestHost", &DMREAD, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_FastestHost, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_MinimumResponseTime, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_AverageResponseTime, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_MaximumResponseTime, NULL, BBFDM_CWMP},
{"IPAddressUsed", &DMREAD, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_IPAddressUsed, NULL, BBFDM_CWMP},
{0}
};
