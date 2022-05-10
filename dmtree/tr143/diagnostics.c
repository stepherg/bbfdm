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
			IPPING_STOP
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
			IPPING_STOP
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
			IPPING_STOP
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
			IPPING_STOP
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
			IPPING_STOP
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
			IPPING_STOP
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
			IPPING_STOP
			reset_diagnostic_state("ipping");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			TRACEROUTE_STOP
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
			DOWNLOAD_DIAGNOSTIC_STOP
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
			DOWNLOAD_DIAGNOSTIC_STOP
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
			DOWNLOAD_DIAGNOSTIC_STOP
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
			DOWNLOAD_DIAGNOSTIC_STOP
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
			DOWNLOAD_DIAGNOSTIC_STOP
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
			DOWNLOAD_DIAGNOSTIC_STOP
			reset_diagnostic_state("download");
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
			reset_diagnostic_state("download");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
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
			UPLOAD_DIAGNOSTIC_STOP
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
			UPLOAD_DIAGNOSTIC_STOP
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
			UPLOAD_DIAGNOSTIC_STOP
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
			UPLOAD_DIAGNOSTIC_STOP
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
			UPLOAD_DIAGNOSTIC_STOP
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
			UPLOAD_DIAGNOSTIC_STOP
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
			UPLOAD_DIAGNOSTIC_STOP
			reset_diagnostic_state("upload");
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
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
			UDPECHO_STOP;
			reset_diagnostic_state("udpechodiag");
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
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
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
			SERVERSELECTION_STOP
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
			SERVERSELECTION_STOP
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
			SERVERSELECTION_STOP
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
			SERVERSELECTION_STOP
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
			SERVERSELECTION_STOP
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
			SERVERSELECTION_STOP
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
	init_diagnostics_operation("ipping", IPPING_PATH);

	char *ipping_host = dmjson_get_value((json_object *)value, 1, "Host");
	if (ipping_host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;
	char *ipping_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *ipping_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *ipping_nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");
	char *ipping_timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *ipping_datablocksize = dmjson_get_value((json_object *)value, 1, "DataBlockSize");
	char *ipping_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");

	set_diagnostics_option("ipping", "Host", ipping_host);
	set_diagnostics_interface_option(ctx, "ipping", ipping_interface);
	set_diagnostics_option("ipping", "ProtocolVersion", ipping_proto);
	set_diagnostics_option("ipping", "NumberOfRepetitions", ipping_nbofrepetition);
	set_diagnostics_option("ipping", "Timeout", ipping_timeout);
	set_diagnostics_option("ipping", "DataBlockSize", ipping_datablocksize);
	set_diagnostics_option("ipping", "DSCP", ipping_dscp);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, IPPING_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	char *ipping_success_count = get_diagnostics_option("ipping", "SuccessCount");
	char *ipping_failure_count = get_diagnostics_option("ipping", "FailureCount");
	char *ipping_average_response_time = get_diagnostics_option("ipping", "AverageResponseTime");
	char *ipping_minimum_response_time = get_diagnostics_option("ipping", "MinimumResponseTime");
	char *ipping_maximum_response_time = get_diagnostics_option("ipping", "MaximumResponseTime");
	char *ipping_average_response_time_detailed = get_diagnostics_option("ipping", "AverageResponseTimeDetailed");
	char *ipping_minimum_response_time_detailed = get_diagnostics_option("ipping", "MinimumResponseTimeDetailed");
	char *ipping_maximum_response_time_detailed = get_diagnostics_option("ipping", "MaximumResponseTimeDetailed");

	add_list_parameter(ctx, dmstrdup("SuccessCount"), ipping_success_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("FailureCount"), ipping_failure_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTime"), ipping_average_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), ipping_minimum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), ipping_maximum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTimeDetailed"), ipping_average_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTimeDetailed"), ipping_minimum_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTimeDetailed"), ipping_maximum_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL);

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
	struct uci_section *s = NULL;
	char *route_hops_host[2] = {0};
	char *route_hops_host_address[2] = {0};
	char *route_hops_rttimes[2] = {0};
	char *route_hops_errorcode = NULL;
	int i = 1;

	init_diagnostics_operation("traceroute", TRACEROUTE_PATH);

	char *host = dmjson_get_value((json_object *)value, 1, "Host");
	if (host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *nboftries = dmjson_get_value((json_object *)value, 1, "NumberOfTries");
	char *timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *datablocksize = dmjson_get_value((json_object *)value, 1, "DataBlockSize");
	char *dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *maxhops = dmjson_get_value((json_object *)value, 1, "MaxHopCount");

	set_diagnostics_option("traceroute", "Host", host);
	set_diagnostics_interface_option(ctx, "traceroute", interface);
	set_diagnostics_option("traceroute", "ProtocolVersion", proto);
	set_diagnostics_option("traceroute", "NumberOfTries", nboftries);
	set_diagnostics_option("traceroute", "Timeout", timeout);
	set_diagnostics_option("traceroute", "DataBlockSize", datablocksize);
	set_diagnostics_option("traceroute", "DSCP", dscp);
	set_diagnostics_option("traceroute", "MaxHops", maxhops);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, TRACEROUTE_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	char *response_time = get_diagnostics_option("traceroute", "ResponseTime");
	add_list_parameter(ctx, dmstrdup("ResponseTime"), response_time, DMT_TYPE[DMT_UNINT], NULL);

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "RouteHops", s) {
		dmasprintf(&route_hops_host[0], "RouteHops.%d.Host", i);
		dmasprintf(&route_hops_host_address[0], "RouteHops.%d.HostAddress", i);
		dmasprintf(&route_hops_rttimes[0], "RouteHops.%d.RTTimes", i);
		dmasprintf(&route_hops_errorcode, "RouteHops.%d.ErrorCode", i);

		dmuci_get_value_by_section_string(s, "host", &route_hops_host[1]);
		dmuci_get_value_by_section_string(s, "ip", &route_hops_host_address[1]);
		dmuci_get_value_by_section_string(s, "time", &route_hops_rttimes[1]);

		add_list_parameter(ctx, route_hops_host[0], route_hops_host[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, route_hops_host_address[0], route_hops_host_address[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, route_hops_rttimes[0], route_hops_rttimes[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, route_hops_errorcode, "0", DMT_TYPE[DMT_UNINT], NULL);
		i++;
	}

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
	init_diagnostics_operation("download", DOWNLOAD_DIAGNOSTIC_PATH);

	char *download_url = dmjson_get_value((json_object *)value, 1, "DownloadURL");
	if (download_url[0] == '\0')
		return CMD_INVALID_ARGUMENTS;
	char *download_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *download_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *download_ethernet_priority = dmjson_get_value((json_object *)value, 1, "EthernetPriority");
	char *download_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *download_num_of_connections = dmjson_get_value((json_object *)value, 1, "NumberOfConnections");
	char *download_enable_per_connection_results = dmjson_get_value((json_object *)value, 1, "EnablePerConnectionResults");

	set_diagnostics_option("download", "url", download_url);
	set_diagnostics_interface_option(ctx, "download", download_interface);
	set_diagnostics_option("download", "DSCP", download_dscp);
	set_diagnostics_option("download", "ethernetpriority", download_ethernet_priority);
	set_diagnostics_option("download", "ProtocolVersion", download_proto);
	set_diagnostics_option("download", "NumberOfConnections", download_num_of_connections);
	set_diagnostics_option("download", "EnablePerConnection", download_enable_per_connection_results);

	if (start_upload_download_diagnostic(DOWNLOAD_DIAGNOSTIC) == -1)
		return CMD_FAIL;

	char *romtime = get_diagnostics_option("download", "ROMtime");
	char *bomtime = get_diagnostics_option("download", "BOMtime");
	char *eomtime = get_diagnostics_option("download", "EOMtime");
	char *test_bytes_received = get_diagnostics_option("download", "TestBytesReceived");
	char *total_bytes_received = get_diagnostics_option("download", "TotalBytesReceived");
	char *total_bytes_sent = get_diagnostics_option("download", "TotalBytesSent");
	char *test_bytes_received_under_full_loading = get_diagnostics_option("download", "TestBytesReceived");
	char *total_bytes_received_under_full_loading = get_diagnostics_option("download", "TotalBytesReceived");
	char *total_bytes_sent_under_full_loading = get_diagnostics_option("download", "TotalBytesSent");
	char *period_of_full_loading = get_diagnostics_option("download", "PeriodOfFullLoading");
	char *tcp_open_request_time = get_diagnostics_option("download", "TCPOpenRequestTime");
	char *tcp_open_response_time = get_diagnostics_option("download", "TCPOpenResponseTime");

	add_list_parameter(ctx, dmstrdup("ROMTime"), romtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("BOMTime"), bomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("EOMTime"), eomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesReceived"), test_bytes_received, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceived"), total_bytes_received, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSent"), total_bytes_sent, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesReceivedUnderFullLoading"), test_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceivedUnderFullLoading"), total_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSentUnderFullLoading"), total_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("PeriodOfFullLoading"), period_of_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenRequestTime"), tcp_open_request_time, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenResponseTime"), tcp_open_response_time, DMT_TYPE[DMT_TIME], NULL);

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
	init_diagnostics_operation("upload", UPLOAD_DIAGNOSTIC_PATH);

	char *upload_url = dmjson_get_value((json_object *)value, 1, "UploadURL");
	if (upload_url[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *upload_test_file_length = dmjson_get_value((json_object *)value, 1, "TestFileLength");
	if (upload_test_file_length[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *upload_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *upload_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *upload_ethernet_priority = dmjson_get_value((json_object *)value, 1, "EthernetPriority");
	char *upload_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *upload_num_of_connections = dmjson_get_value((json_object *)value, 1, "NumberOfConnections");
	char *upload_enable_per_connection_results = dmjson_get_value((json_object *)value, 1, "EnablePerConnectionResults");

	set_diagnostics_option("upload", "url", upload_url);
	set_diagnostics_option("upload", "TestFileLength", upload_test_file_length);
	set_diagnostics_interface_option(ctx, "upload", upload_interface);
	set_diagnostics_option("upload", "DSCP", upload_dscp);
	set_diagnostics_option("upload", "ethernetpriority", upload_ethernet_priority);
	set_diagnostics_option("upload", "ProtocolVersion", upload_proto);
	set_diagnostics_option("upload", "NumberOfConnections", upload_num_of_connections);
	set_diagnostics_option("upload", "EnablePerConnection", upload_enable_per_connection_results);

	if (start_upload_download_diagnostic(UPLOAD_DIAGNOSTIC) == -1)
		return CMD_FAIL;

	char *upload_romtime = get_diagnostics_option("upload", "ROMtime");
	char *upload_bomtime = get_diagnostics_option("upload", "BOMtime");
	char *upload_eomtime = get_diagnostics_option("upload", "EOMtime");
	char *upload_test_bytes_sent = get_diagnostics_option("upload", "TestBytesSent");
	char *upload_total_bytes_received = get_diagnostics_option("upload", "TotalBytesReceived");
	char *upload_total_bytes_sent = get_diagnostics_option("upload", "TotalBytesSent");
	char *upload_test_bytes_sent_under_full_loading = get_diagnostics_option("upload", "TestBytesSent");
	char *upload_total_bytes_received_under_full_loading = get_diagnostics_option("upload", "TotalBytesReceived");
	char *upload_total_bytes_sent_under_full_loading = get_diagnostics_option("upload", "TotalBytesSent");
	char *upload_period_of_full_loading = get_diagnostics_option("upload", "PeriodOfFullLoading");
	char *upload_tcp_open_request_time = get_diagnostics_option("upload", "TCPOpenRequestTime");
	char *upload_tcp_open_response_time = get_diagnostics_option("upload", "TCPOpenResponseTime");

	add_list_parameter(ctx, dmstrdup("ROMTime"), upload_romtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("BOMTime"), upload_bomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("EOMTime"), upload_eomtime, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesSent"), upload_test_bytes_sent, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceived"), upload_total_bytes_received, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSent"), upload_total_bytes_sent, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TestBytesSentUnderFullLoading"), upload_test_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesReceivedUnderFullLoading"), upload_total_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TotalBytesSentUnderFullLoading"), upload_total_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("PeriodOfFullLoading"), upload_period_of_full_loading, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenRequestTime"), upload_tcp_open_request_time, DMT_TYPE[DMT_TIME], NULL);
	add_list_parameter(ctx, dmstrdup("TCPOpenResponseTime"), upload_tcp_open_response_time, DMT_TYPE[DMT_TIME], NULL);

	return CMD_SUCCESS;
}

static operation_args ip_diagnostics_udpecho_args = {
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
};

static int get_operate_args_IPDiagnostics_UDPEchoDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_udpecho_args;
	return 0;
}

static int operate_IPDiagnostics_UDPEchoDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	init_diagnostics_operation("udpechodiag", UDPECHO_PATH);

	char *udpecho_host = dmjson_get_value((json_object *)value, 1, "Host");
	if (udpecho_host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *udpecho_port = dmjson_get_value((json_object *)value, 1, "Port");
	char *udpecho_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *udpecho_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *udpecho_nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");
	char *udpecho_timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *udpecho_datablocksize = dmjson_get_value((json_object *)value, 1, "DataBlockSize");
	char *udpecho_dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	char *udpecho_inter_transmission_time = dmjson_get_value((json_object *)value, 1, "InterTransmissionTime");

	set_diagnostics_option("udpechodiag", "Host", udpecho_host);
	set_diagnostics_option("udpechodiag", "port", udpecho_port);
	set_diagnostics_interface_option(ctx, "udpechodiag", udpecho_interface);
	set_diagnostics_option("udpechodiag", "ProtocolVersion", udpecho_proto);
	set_diagnostics_option("udpechodiag", "NumberOfRepetitions", udpecho_nbofrepetition);
	set_diagnostics_option("udpechodiag", "Timeout", udpecho_timeout);
	set_diagnostics_option("udpechodiag", "DataBlockSize", udpecho_datablocksize);
	set_diagnostics_option("udpechodiag", "DSCP", udpecho_dscp);
	set_diagnostics_option("udpechodiag", "InterTransmissionTime", udpecho_inter_transmission_time);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, UDPECHO_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	char *udpecho_success_count = get_diagnostics_option("udpechodiag", "SuccessCount");
	char *udpecho_failure_count = get_diagnostics_option("udpechodiag", "FailureCount");
	char *udpecho_average_response_time = get_diagnostics_option("udpechodiag", "AverageResponseTime");
	char *udpecho_minimum_response_time = get_diagnostics_option("udpechodiag", "MinimumResponseTime");
	char *udpecho_maximum_response_time = get_diagnostics_option("udpechodiag", "MaximumResponseTime");

	add_list_parameter(ctx, dmstrdup("SuccessCount"), udpecho_success_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("FailureCount"), udpecho_failure_count, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTime"), udpecho_average_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), udpecho_minimum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), udpecho_maximum_response_time, DMT_TYPE[DMT_UNINT], NULL);

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
	init_diagnostics_operation("serverselection", SERVERSELECTION_PATH);

	char *hostlist = dmjson_get_value((json_object *)value, 1, "HostList");
	if (hostlist[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *port = dmjson_get_value((json_object *)value, 1, "Port");
	char *proto = dmjson_get_value((json_object *)value, 1, "Protocol");
	char *protocol_version = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	char *interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");
	char *timeout = dmjson_get_value((json_object *)value, 1, "Timeout");

	set_diagnostics_option("serverselection", "HostList", hostlist);
	set_diagnostics_interface_option(ctx, "serverselection", interface);
	set_diagnostics_option("serverselection", "ProtocolVersion", protocol_version);
	set_diagnostics_option("serverselection", "NumberOfRepetitions", nbofrepetition);
	set_diagnostics_option("serverselection", "port", port);
	set_diagnostics_option("serverselection", "Protocol", proto);
	set_diagnostics_option("serverselection", "Timeout", timeout);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, SERVERSELECTION_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	char *fasthost = get_diagnostics_option("serverselection", "FastestHost");
	char *average_response_time = get_diagnostics_option("serverselection", "AverageResponseTime");
	char *minimum_response_time = get_diagnostics_option("serverselection", "MinimumResponseTime");
	char *maximum_response_time = get_diagnostics_option("serverselection", "MaximumResponseTime");

	add_list_parameter(ctx, dmstrdup("FastestHost"), fasthost, DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("AverageResponseTime"), average_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), minimum_response_time, DMT_TYPE[DMT_UNINT], NULL);
	add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), maximum_response_time, DMT_TYPE[DMT_UNINT], NULL);

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
{0}
};
