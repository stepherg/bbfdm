/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 *
 */

#include "dmdiagnostics.h"
#include "dmbbfcommon.h"
#include "iplayercap.h"

#define IPLAYER_CAP_DIAGNOSTIC_PATH "/usr/share/bbfdm/iplayercap"

/*
 * *** Device.IP.Diagnostics.IPLayerCapacityMetrics. ***
 */
static int browseIPLayerCapacityModalResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "modalresult", s) {
		inst = handle_instance(dmctx, parent_node, s, "modal_instance", "modal_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPLayerCapacityIncrementalResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "incrementalresult", s) {
		inst = handle_instance(dmctx, parent_node, s, "incremental_instance", "incremental_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}


static int get_IPDiagnosticsIPLayerCapacity_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("iplayercapacity", "DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				set_diagnostics_option("iplayercapacity", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_IPLAYERCAPACITY_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

int get_IPDiagnosticsIPLayerCapacity_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "7.5.1";
	return 0;
}

int get_IPDiagnosticsIPLayerCapacity_MaxConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int get_IPDiagnosticsIPLayerCapacity_MaxIncrementalResult(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "3600";
	return 0;
}

int get_IPDiagnosticsIPLayerCapacity_ControlProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "9";
	return 0;
}

int get_IPDiagnosticsIPLayerCapacity_SupportedMetrics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "IPLR,Sampled_RTT,IPDV,IPRR,RIPR";
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("iplayercapacity", "interface");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_interface_option(ctx, "iplayercapacity", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_Role(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "Role");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_Role(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, IPLayerCapacityRole, NULL))
				return FAULT_9007;

			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "Role", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "Host");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "Host", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "Port");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "Port", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_JumboFramesPermitted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "JumboFramesPermitted");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_JumboFramesPermitted(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			string_to_bool(value, &b);
			set_diagnostics_option("iplayercapacity", "JumboFramesPermitted", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "DSCP");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "ProtocolVersion");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_UDPPayloadContent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "UDPPayloadContent");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_UDPPayloadContent(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, UDPPayloadContent, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "UDPPayloadContent", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TestType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "TestType");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_TestType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, IPLayerCapacityTestType, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "TestType", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_IPDVEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "IPDVEnable");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_IPDVEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			string_to_bool(value, &b);
			set_diagnostics_option("iplayercapacity", "IPDVEnable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_StartSendingRateIndex(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "StartSendingRateIndex");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_StartSendingRateIndex(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			/* As per TR max should be 11108 but udpst supports 1108 */
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","1108"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "StartSendingRateIndex", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_NumberFirstModeTestSubIntervals(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "NumberFirstModeTestSubIntervals");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_NumberFirstModeTestSubIntervals(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","100"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "NumberFirstModeTestSubIntervals", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_NumberTestSubIntervals(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "NumberTestSubIntervals");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_NumberTestSubIntervals(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			/* As per TR max should be 100 and (NumberTestSubIntervals * TestSubInterval) <= 60 sec
			 * since supported min value of TestSubInterval by udpst is 1 sec, so can be supported
			 * upto 60 value
			 */
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","60"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "NumberTestSubIntervals", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TestSubInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "TestSubInterval");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_TestSubInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			/* As per DM min should be 100 but udpst supports min 1000 */
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1000","6000"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "TestSubInterval", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_StatusFeedbackInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "StatusFeedbackInterval");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_StatusFeedbackInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"5","250"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "StatusFeedbackInterval", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_SeqErrThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "SeqErrThresh");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_SeqErrThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","100"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "SeqErrThresh", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ReordDupIgnoreEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "ReordDupIgnoreEnable");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_ReordDupIgnoreEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			string_to_bool(value, &b);
			set_diagnostics_option("iplayercapacity", "ReordDupIgnoreEnable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_LowerThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "LowerThresh");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_LowerThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"5","250"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "LowerThresh", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_UpperThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "UpperThresh");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_UpperThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"5","250"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "UpperThresh", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_HighSpeedDelta(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "HighSpeedDelta");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_HighSpeedDelta(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"2", NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "HighSpeedDelta", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_RateAdjAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "RateAdjAlgorithm");
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_RateAdjAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, RateAdjAlgorithm, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "RateAdjAlgorithm", value);
			return 0;
	}
	return 0;
}

static int set_IPDiagnosticsIPLayerCapacity_SlowAdjThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"2",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			reset_diagnostic_state("iplayercapacity");
			set_diagnostics_option("iplayercapacity", "SlowAdjThresh", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_SlowAdjThresh(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "SlowAdjThresh");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("iplayercapacity", "BOMTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("iplayercapacity", "EOMTime", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TmaxUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "TmaxUsed");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TestInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "TestInterval");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MaxIPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MaxIPLayerCapacity");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TimeOfMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("iplayercapacity", "TimeOfMax", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MaxETHCapacityNoFCS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MaxETHCapacityNoFCS");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MaxETHCapacityWithFCS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MaxETHCapacityWithFCS");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MaxETHCapacityWithFCSVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MaxETHCapacityWithFCSVLAN");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_LossRatioAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "LossRatioAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_RTTRangeAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "RTTRangeAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_PDVRangeAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "PDVRangeAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MinOnewayDelayAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MinOnewayDelayAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ReorderedRatioAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "ReorderedRatioAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ReplicatedRatioAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "ReplicatedRatioAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_InterfaceEthMbpsAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "InterfaceEthMbpsAtMax");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_IPLayerCapacitySummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "IPLayerCapacitySummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_LossRatioSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "LossRatioSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_RTTRangeSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "RTTRangeSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_PDVRangeSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "PDVRangeSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MinOnewayDelaySummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MinOnewayDelaySummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_MinRTTSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "MinRTTSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ReorderedRatioSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "ReorderedRatioSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ReplicatedRatioSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "ReplicatedRatioSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_InterfaceEthMbpsSummary(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "InterfaceEthMbpsSummary");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TmaxRTTUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "TmaxRTTUsed");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_TimestampResolutionUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("iplayercapacity", "TimestampResolutionUsed");
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_IncrementalResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPLayerCapacityIncrementalResultInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPDiagnosticsIPLayerCapacity_ModalResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPLayerCapacityModalResultInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPLayerCapacityModal_MaxIPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "MaxIPLayerCapacity", value);
	return 0;
}

static int get_IPLayerCapacityModal_TimeOfMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TimeOfMax", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPLayerCapacityModal_MaxETHCapacityNoFCS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "MaxETHCapacityNoFCS", value);
	return 0;
}

static int get_IPLayerCapacityModal_MaxETHCapacityWithFCS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "MaxETHCapacityWithFCS", value);
	return 0;
}

static int get_IPLayerCapacityModal_MaxETHCapacityWithFCSVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "MaxETHCapacityWithFCSVLAN", value);
	return 0;
}

static int get_IPLayerCapacityModal_LossRatioAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "LossRatioAtMax", value);
	return 0;
}

static int get_IPLayerCapacityModal_RTTRangeAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "RTTRangeAtMax", value);
	return 0;
}

static int get_IPLayerCapacityModal_PDVRangeAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "PDVRangeAtMax", value);
	return 0;
}

static int get_IPLayerCapacityModal_MinOnewayDelayAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "MinOnewayDelayAtMax", value);
	return 0;
}

static int get_IPLayerCapacityModal_ReorderedRatioAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ReorderedRatioAtMax", value);
	return 0;
}

static int get_IPLayerCapacityModal_ReplicatedRatioAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ReplicatedRatioAtMax", value);
	return 0;
}

static int get_IPLayerCapacityModal_InterfaceEthMbpsAtMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "InterfaceEthMbpsAtMax", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_IPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "IPLayerCapacity", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_TimeOfSubInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "TimeOfSubInterval", "0001-01-01T00:00:00.000000Z");
	return 0;
}

static int get_IPLayerCapacityIncremental_LossRatio(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "LossRatio", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_RTTRange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "RTTRange", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_PDVRange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "PDVRange", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_MinOnewayDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "MinOnewayDelay", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_ReorderedRatio(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ReorderedRatio", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_ReplicatedRatio(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ReplicatedRatio", value);
	return 0;
}

static int get_IPLayerCapacityIncremental_InterfaceEthMbps(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "InterfaceEthMbps", value);
	return 0;
}

static operation_args ip_diagnostics_iplayercapacity_args = {
	.in = (const char *[]) {
		"Interface",
		"Role",
		"Host",
		"Port",
		"JumboFramesPermitted",
		"DSCP",
		"ProtocolVersion",
		"UDPPayloadContent",
		"TestType",
		"IPDVEnable",
		"StartSendingRateIndex",
		"NumberTestSubIntervals",
		"NumberFirstModeTestSubIntervals",
		"TestSubInterval",
		"StatusFeedbackInterval",
		"SeqErrThresh",
		"ReordDupIgnoreEnable",
		"LowerThresh",
		"UpperThresh",
		"HighSpeedDelta",
		"SlowAdjThresh",
		"RateAdjAlgorithm",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		"BOMTime",
		"EOMTime",
		"TmaxUsed",
		"TestInterval",
		"MaxIPLayerCapacity",
		"TimeOfMax",
		"MaxETHCapacityNoFCS",
		"MaxETHCapacityWithFCS",
		"MaxETHCapacityWithFCSVLAN",
		"LossRatioAtMax",
		"RTTRangeAtMax",
		"PDVRangeAtMax",
		"MinOnewayDelayAtMax",
		"ReorderedRatioAtMax",
		"ReplicatedRatioAtMax",
		"InterfaceEthMbpsAtMax",
		"IPLayerCapacitySummary",
		"LossRatioSummary",
		"RTTRangeSummary",
		"PDVRangeSummary",
		"MinOnewayDelaySummary",
		"MinRTTSummary",
		"ReorderedRatioSummary",
		"ReplicatedRatioSummary",
		"InterfaceEthMbpsSummary",
		"TmaxRTTUsed",
		"TimestampResolutionUsed",
		"ModalResult.{i}.MaxIPLayerCapacity",
		"ModalResult.{i}.TimeOfMax",
		"ModalResult.{i}.MaxETHCapacityNoFCS",
		"ModalResult.{i}.MaxETHCapacityWithFCS",
		"ModalResult.{i}.MaxETHCapacityWithFCSVLAN",
		"ModalResult.{i}.LossRatioAtMax",
		"ModalResult.{i}.RTTRangeAtMax",
		"ModalResult.{i}.PDVRangeAtMax",
		"ModalResult.{i}.MinOnewayDelayAtMax",
		"ModalResult.{i}.ReorderedRatioAtMax",
		"ModalResult.{i}.ReplicatedRatioAtMax",
		"ModalResult.{i}.InterfaceEthMbpsAtMax",
		"IncrementalResult.{i}.IPLayerCapacity",
		"IncrementalResult.{i}.TimeOfSubInterval",
		"IncrementalResult.{i}.LossRatio",
		"IncrementalResult.{i}.RTTRange",
		"IncrementalResult.{i}.PDVRange",
		"IncrementalResult.{i}.MinOnewayDelay",
		"IncrementalResult.{i}.ReorderedRatio",
		"IncrementalResult.{i}.ReplicatedRatio",
		"IncrementalResult.{i}.InterfaceEthMbps",
		NULL
	}
};

int get_operate_args_IPDiagnostics_IPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&ip_diagnostics_iplayercapacity_args;
	return 0;
}

int operate_IPDiagnostics_IPLayerCapacity(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char input[4096] = {0};
	char output[40000] = {0};
	char cmd[5120] = {0};
	unsigned int idx = 0;

	char *host = dmjson_get_value((json_object *)value, 1, "Host");
	if (host[0] == '\0')
		return CMD_INVALID_ARGUMENTS;

	char *ip_interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *interface = get_diagnostics_interface_option(ctx, ip_interface);
	char *role = dmjson_get_value((json_object *)value, 1, "Role");
	if (role[0] != '\0' && dm_validate_string(role, -1, -1, IPLayerCapacityRole, NULL))
		return CMD_INVALID_ARGUMENTS;

	char *port = dmjson_get_value((json_object *)value, 1, "Port");
	if (port[0] != '\0' && dm_validate_unsignedInt(port, RANGE_ARGS{{"1","65535"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *jumbo = dmjson_get_value((json_object *)value, 1, "JumboFramesPermitted");
	bool jumbo_en = false;
	string_to_bool(jumbo, &jumbo_en);

	char *dscp = dmjson_get_value((json_object *)value, 1, "DSCP");
	if (dscp[0] != '\0' && dm_validate_unsignedInt(dscp, RANGE_ARGS{{"0","63"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *ip_proto = dmjson_get_value((json_object *)value, 1, "ProtocolVersion");
	if (ip_proto[0] != '\0' && dm_validate_string(ip_proto, -1, -1, ProtocolVersion, NULL))
		return CMD_INVALID_ARGUMENTS;

	char *content = dmjson_get_value((json_object *)value, 1, "UDPPayloadContent");
	if (content[0] != '\0' && dm_validate_string(content, -1, -1, UDPPayloadContent, NULL))
		return CMD_INVALID_ARGUMENTS;

	char *test_type = dmjson_get_value((json_object *)value, 1, "TestType");
	if (test_type[0] != '\0' && dm_validate_string(test_type, -1, -1, IPLayerCapacityTestType, NULL))
		return CMD_INVALID_ARGUMENTS;

	char *ipdv = dmjson_get_value((json_object *)value, 1, "IPDVEnable");
	bool ipdv_en = false;
	string_to_bool(ipdv, &ipdv_en);

	char *start_rate = dmjson_get_value((json_object *)value, 1, "StartSendingRateIndex");
	if (start_rate[0] != '\0' && dm_validate_unsignedInt(start_rate, RANGE_ARGS{{"0","1108"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *num_interval = dmjson_get_value((json_object *)value, 1, "NumberTestSubIntervals");
	if (num_interval[0] != '\0' && dm_validate_unsignedInt(num_interval, RANGE_ARGS{{"1","60"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *mode_test = dmjson_get_value((json_object *)value, 1, "NumberFirstModeTestSubIntervals");
	if (mode_test[0] != '\0' && dm_validate_unsignedInt(mode_test, RANGE_ARGS{{"0","100"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *sub_interval = dmjson_get_value((json_object *)value, 1, "TestSubInterval");
	if (sub_interval[0] != '\0' && dm_validate_unsignedInt(sub_interval, RANGE_ARGS{{"1000","6000"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *feed_interval = dmjson_get_value((json_object *)value, 1, "StatusFeedbackInterval");
	if (feed_interval[0] != '\0' && dm_validate_unsignedInt(feed_interval, RANGE_ARGS{{"5","250"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *seq_err = dmjson_get_value((json_object *)value, 1, "SeqErrThresh");
	if (seq_err[0] != '\0' && dm_validate_unsignedInt(seq_err, RANGE_ARGS{{"0","100"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *dup_ignore = dmjson_get_value((json_object *)value, 1, "ReordDupIgnoreEnable");
	bool dup_ignore_en = false;
	string_to_bool(dup_ignore, &dup_ignore_en);

	char *low_thresh = dmjson_get_value((json_object *)value, 1, "LowerThresh");
	if (low_thresh[0] != '\0' && dm_validate_unsignedInt(low_thresh, RANGE_ARGS{{"5","250"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *up_thresh = dmjson_get_value((json_object *)value, 1, "UpperThresh");
	if (up_thresh[0] != '\0' && dm_validate_unsignedInt(up_thresh, RANGE_ARGS{{"5","250"}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *speed_delta = dmjson_get_value((json_object *)value, 1, "HighSpeedDelta");
	if (speed_delta[0] != '\0' && dm_validate_unsignedInt(speed_delta, RANGE_ARGS{{"2", NULL}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *slow_adj = dmjson_get_value((json_object *)value, 1, "SlowAdjThresh");
	if (slow_adj[0] != '\0' && dm_validate_unsignedInt(slow_adj, RANGE_ARGS{{"2", NULL}}, 1))
		return CMD_INVALID_ARGUMENTS;

	char *rate_adj = dmjson_get_value((json_object *)value, 1, "RateAdjAlgorithm");
	if (rate_adj[0] != '\0' && dm_validate_string(rate_adj, -1, -1, RateAdjAlgorithm, NULL))
		return CMD_INVALID_ARGUMENTS;

	snprintf(input, sizeof(input), "'{\"host\": \"%s\",\"interface\":\"%s\",\"role\":\"%s\",\"port\":\"%s\",\"jumbo_frames\":\"%s\",\"proto_ver\":\"%s\",\"udp_content\":\"%s\",\"test_type\":\"%s\",\"ipdv_enable\":\"%s\",\"DSCP\":\"%s\",\"rate_index\":\"%s\",\"mode_subintervals\":\"%s\",\"test_subinterval\":\"%s\",\"feedback_interval\":\"%s\",\"seq_err_thresh\":\"%s\",\"dup_ignore\":\"%s\",\"lower_thresh\":\"%s\",\"upper_thresh\":\"%s\",\"high_speed_delta\":\"%s\",\"algorithm\":\"%s\",\"slow_adj_thresh\":\"%s\",\"num_interval\":\"%s\",\"proto\":\"%s\"}'",
					host, interface, role, port, DM_STRLEN(jumbo) > 0 ? (jumbo_en ? "1" : "0") : "\0",
					ip_proto, content, test_type, DM_STRLEN(ipdv) > 0 ? (ipdv_en ? "1" : "0") : "\0",
					dscp, start_rate, mode_test, sub_interval, feed_interval, seq_err,
					DM_STRLEN(dup_ignore) > 0 ? (dup_ignore_en ? "1" : "0") : "\0", low_thresh, up_thresh,
					speed_delta, rate_adj, slow_adj, num_interval, (bbfdatamodel_type == BBFDM_USP) ? "usp" : "both_proto");

	snprintf(cmd, sizeof(cmd), "sh %s %s", IPLAYER_CAP_DIAGNOSTIC_PATH, input);

	FILE *pp = popen(cmd, "r");
	if (pp != NULL) {
		fgets(output, sizeof(output), pp);
		pclose(pp);
	} else {
		return CMD_FAIL;
	}

	json_object *res = (DM_STRLEN(output)) ? json_tokener_parse(output) : NULL;

	if (res == NULL) {
		return CMD_FAIL;
	}

	char *status = NULL;
	char *err = dmjson_get_value(res, 1, "ErrorStatus");
	if (DM_STRCMP(err, "0") != 0)
		status = "Error_Internal";
	else
		status = "Complete";

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);

	json_object *jobj = dmjson_get_obj(res, 1, "Output");
	if (jobj) {
		char *BOMTime = dmjson_get_value(jobj, 1, "BOMTime");
		char *EOMTime = dmjson_get_value(jobj, 1, "EOMTime");
		char *TmaxUsed = dmjson_get_value(jobj, 1, "TmaxUsed");
		char *TestInterval = dmjson_get_value(jobj, 1, "TestInterval");
		char *TmaxRTTUsed = dmjson_get_value(jobj, 1, "TmaxRTTUsed");
		char *TimestampResolutionUsed = dmjson_get_value(jobj, 1, "TimestampResolutionUsed");

		add_list_parameter(ctx, dmstrdup("BOMTime"), dmstrdup(BOMTime), DMT_TYPE[DMT_TIME], NULL);
		add_list_parameter(ctx, dmstrdup("EOMTime"), dmstrdup(EOMTime), DMT_TYPE[DMT_TIME], NULL);
		add_list_parameter(ctx, dmstrdup("TmaxUsed"), dmstrdup(TmaxUsed), DMT_TYPE[DMT_UNINT], NULL);
		add_list_parameter(ctx, dmstrdup("TestInterval"), dmstrdup(TestInterval), DMT_TYPE[DMT_UNINT], NULL);
		add_list_parameter(ctx, dmstrdup("TmaxRTTUsed"), dmstrdup(TmaxRTTUsed), DMT_TYPE[DMT_UNINT], NULL);
		add_list_parameter(ctx, dmstrdup("TimestampResolutionUsed"), dmstrdup(TimestampResolutionUsed), DMT_TYPE[DMT_UNINT], NULL);

		json_object *atmax = dmjson_get_obj(jobj, 1, "AtMax");
		if (atmax) {
			char *MaxIPLayerCapacity = dmjson_get_value(atmax, 1, "MaxIPLayerCapacity");
			char *TimeOfMax = dmjson_get_value(atmax, 1, "TimeOfMax");
			char *MaxETHCapacityNoFCS = dmjson_get_value(atmax, 1, "MaxETHCapacityNoFCS");
			char *MaxETHCapacityWithFCS = dmjson_get_value(atmax, 1, "MaxETHCapacityWithFCS");
			char *MaxETHCapacityWithFCSVLAN = dmjson_get_value(atmax, 1, "MaxETHCapacityWithFCSVLAN");
			char *LossRatioAtMax = dmjson_get_value(atmax, 1, "LossRatioAtMax");
			char *RTTRangeAtMax = dmjson_get_value(atmax, 1, "RTTRangeAtMax");
			char *PDVRangeAtMax = dmjson_get_value(atmax, 1, "PDVRangeAtMax");
			char *MinOnewayDelayAtMax = dmjson_get_value(atmax, 1, "MinOnewayDelayAtMax");
			char *ReorderedRatioAtMax = dmjson_get_value(atmax, 1, "ReorderedRatioAtMax");
			char *ReplicatedRatioAtMax = dmjson_get_value(atmax, 1, "ReplicatedRatioAtMax");
			char *InterfaceEthMbpsAtMax = dmjson_get_value(atmax, 1, "InterfaceEthMbps");

			add_list_parameter(ctx, dmstrdup("MaxIPLayerCapacity"), dmstrdup(MaxIPLayerCapacity), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("TimeOfMax"), dmstrdup(TimeOfMax), DMT_TYPE[DMT_TIME], NULL);
			add_list_parameter(ctx, dmstrdup("MaxETHCapacityNoFCS"), dmstrdup(MaxETHCapacityNoFCS), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MaxETHCapacityWithFCS"), dmstrdup(MaxETHCapacityWithFCS), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MaxETHCapacityWithFCSVLAN"), dmstrdup(MaxETHCapacityWithFCSVLAN), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("LossRatioAtMax"), dmstrdup(LossRatioAtMax), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("RTTRangeAtMax"), dmstrdup(RTTRangeAtMax), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("PDVRangeAtMax"), dmstrdup(PDVRangeAtMax), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MinOnewayDelayAtMax"), dmstrdup(MinOnewayDelayAtMax), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ReorderedRatioAtMax"), dmstrdup(ReorderedRatioAtMax), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ReplicatedRatioAtMax"), dmstrdup(ReplicatedRatioAtMax), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("InterfaceEthMbpsAtMax"), dmstrdup(InterfaceEthMbpsAtMax), DMT_TYPE[DMT_STRING], NULL);
		}

		json_object *sum = dmjson_get_obj(jobj, 1, "Summary");
		if (sum) {
			char *IPLayerCapacitySummary = dmjson_get_value(sum, 1, "IPLayerCapacitySummary");
			char *LossRatioSummary = dmjson_get_value(sum, 1, "LossRatioSummary");
			char *RTTRangeSummary = dmjson_get_value(sum, 1, "RTTRangeSummary");
			char *PDVRangeSummary = dmjson_get_value(sum, 1, "PDVRangeSummary");
			char *MinOnewayDelaySummary = dmjson_get_value(sum, 1, "MinOnewayDelaySummary");
			char *MinRTTSummary = dmjson_get_value(sum, 1, "MinRTTSummary");
			char *ReorderedRatioSummary = dmjson_get_value(sum, 1, "ReorderedRatioSummary");
			char *ReplicatedRatioSummary = dmjson_get_value(sum, 1, "ReplicatedRatioSummary");
			char *InterfaceEthMbpsSummary = dmjson_get_value(sum, 1, "InterfaceEthMbps");

			add_list_parameter(ctx, dmstrdup("IPLayerCapacitySummary"), dmstrdup(IPLayerCapacitySummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("LossRatioSummary"), dmstrdup(LossRatioSummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("RTTRangeSummary"), dmstrdup(RTTRangeSummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("PDVRangeSummary"), dmstrdup(PDVRangeSummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MinOnewayDelaySummary"), dmstrdup(MinOnewayDelaySummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("MinRTTSummary"), dmstrdup(MinRTTSummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ReorderedRatioSummary"), dmstrdup(ReorderedRatioSummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("ReplicatedRatioSummary"), dmstrdup(ReplicatedRatioSummary), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, dmstrdup("InterfaceEthMbpsSummary"), dmstrdup(InterfaceEthMbpsSummary), DMT_TYPE[DMT_STRING], NULL);
		}

		json_object *arrobj = NULL, *modal = NULL;
		dmjson_foreach_obj_in_array(jobj, arrobj, modal, idx, 1, "ModalResult") {
			unsigned int i = idx + 1;
			char *MaxIPLayerCapacity[2] = {0};
			char *TimeOfMax[2] = {0};
			char *MaxETHCapacityNoFCS[2] = {0};
			char *MaxETHCapacityWithFCS[2] = {0};
			char *MaxETHCapacityWithFCSVLAN[2] = {0};
			char *LossRatioAtMax[2] = {0};
			char *RTTRangeAtMax[2] = {0};
			char *PDVRangeAtMax[2] = {0};
			char *MinOnewayDelayAtMax[2] = {0};
			char *ReorderedRatioAtMax[2] = {0};
			char *ReplicatedRatioAtMax[2] = {0};
			char *InterfaceEthMbpsAtMax[2] = {0};

			MaxIPLayerCapacity[1] = dmjson_get_value(modal, 1, "MaxIPLayerCapacity");
			dmasprintf(&MaxIPLayerCapacity[0], "ModalResult.%u.MaxIPLayerCapacity", i);
			
			TimeOfMax[1] = dmjson_get_value(modal, 1, "TimeOfMax");
			dmasprintf(&TimeOfMax[0], "ModalResult.%u.TimeOfMax", i);

			MaxETHCapacityNoFCS[1] = dmjson_get_value(modal, 1, "MaxETHCapacityNoFCS");
			dmasprintf(&MaxETHCapacityNoFCS[0], "ModalResult.%u.MaxETHCapacityNoFCS", i);

			MaxETHCapacityWithFCS[1] = dmjson_get_value(modal, 1, "MaxETHCapacityWithFCS");
			dmasprintf(&MaxETHCapacityWithFCS[0], "ModalResult.%u.MaxETHCapacityWithFCS", i);

			MaxETHCapacityWithFCSVLAN[1] = dmjson_get_value(modal, 1, "MaxETHCapacityWithFCSVLAN");
			dmasprintf(&MaxETHCapacityWithFCSVLAN[0], "ModalResult.%u.MaxETHCapacityWithFCSVLAN", i);

			LossRatioAtMax[1] = dmjson_get_value(modal, 1, "LossRatioAtMax");
			dmasprintf(&LossRatioAtMax[0], "ModalResult.%u.LossRatioAtMax", i);

			RTTRangeAtMax[1] = dmjson_get_value(modal, 1, "RTTRangeAtMax");
			dmasprintf(&RTTRangeAtMax[0], "ModalResult.%u.RTTRangeAtMax", i);

			PDVRangeAtMax[1] = dmjson_get_value(modal, 1, "PDVRangeAtMax");
			dmasprintf(&PDVRangeAtMax[0], "ModalResult.%u.PDVRangeAtMax", i);

			MinOnewayDelayAtMax[1] = dmjson_get_value(modal, 1, "MinOnewayDelayAtMax");
			dmasprintf(&MinOnewayDelayAtMax[0], "ModalResult.%u.MinOnewayDelayAtMax", i);

			ReorderedRatioAtMax[1] = dmjson_get_value(modal, 1, "ReorderedRatioAtMax");
			dmasprintf(&ReorderedRatioAtMax[0], "ModalResult.%u.ReorderedRatioAtMax", i);

			ReplicatedRatioAtMax[1] = dmjson_get_value(modal, 1, "ReplicatedRatioAtMax");
			dmasprintf(&ReplicatedRatioAtMax[0], "ModalResult.%u.ReplicatedRatioAtMax", i);

			InterfaceEthMbpsAtMax[1] = dmjson_get_value(modal, 1, "InterfaceEthMbps");
			dmasprintf(&InterfaceEthMbpsAtMax[0], "ModalResult.%u.InterfaceEthMbpsAtMax", i);

			add_list_parameter(ctx, MaxIPLayerCapacity[0], dmstrdup(MaxIPLayerCapacity[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, TimeOfMax[0], dmstrdup(TimeOfMax[1]), DMT_TYPE[DMT_TIME], NULL);
			add_list_parameter(ctx, MaxETHCapacityNoFCS[0], dmstrdup(MaxETHCapacityNoFCS[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, MaxETHCapacityWithFCS[0], dmstrdup(MaxETHCapacityWithFCS[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, MaxETHCapacityWithFCSVLAN[0], dmstrdup(MaxETHCapacityWithFCSVLAN[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, LossRatioAtMax[0], dmstrdup(LossRatioAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, RTTRangeAtMax[0], dmstrdup(RTTRangeAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, PDVRangeAtMax[0], dmstrdup(PDVRangeAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, MinOnewayDelayAtMax[0], dmstrdup(MinOnewayDelayAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, ReorderedRatioAtMax[0], dmstrdup(ReorderedRatioAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, ReplicatedRatioAtMax[0], dmstrdup(ReplicatedRatioAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, InterfaceEthMbpsAtMax[0], dmstrdup(InterfaceEthMbpsAtMax[1]), DMT_TYPE[DMT_STRING], NULL);
		}

		idx = 0;
		json_object *arrob = NULL, *incremental = NULL;
		dmjson_foreach_obj_in_array(jobj, arrob, incremental, idx, 1, "IncrementalResult") {
			unsigned int i = idx + 1;
			char *IPLayerCapacity[2] = {0};
			char *TimeOfSubInterval[2] = {0};
			char *LossRatio[2] = {0};
			char *RTTRange[2] = {0};
			char *PDVRange[2] = {0};
			char *MinOnewayDelay[2] = {0};
			char *ReorderedRatio[2] = {0};
			char *ReplicatedRatio[2] = {0};
			char *InterfaceEthMbps[2] = {0};

			IPLayerCapacity[1] = dmjson_get_value(incremental, 1, "IPLayerCapacity");
			dmasprintf(&IPLayerCapacity[0], "IncrementalResult.%u.IPLayerCapacity", i);

			TimeOfSubInterval[1] = dmjson_get_value(incremental, 1, "TimeOfSubInterval");
			dmasprintf(&TimeOfSubInterval[0], "IncrementalResult.%u.TimeOfSubInterval", i);

			LossRatio[1] = dmjson_get_value(incremental, 1, "LossRatio");
			dmasprintf(&LossRatio[0], "IncrementalResult.%u.LossRatio", i);

			RTTRange[1] = dmjson_get_value(incremental, 1, "RTTRange");
			dmasprintf(&RTTRange[0], "IncrementalResult.%u.RTTRange", i);

			PDVRange[1] = dmjson_get_value(incremental, 1, "PDVRange");
			dmasprintf(&PDVRange[0], "IncrementalResult.%u.PDVRange", i);

			MinOnewayDelay[1] = dmjson_get_value(incremental, 1, "MinOnewayDelay");
			dmasprintf(&MinOnewayDelay[0], "IncrementalResult.%u.MinOnewayDelay", i);

			ReorderedRatio[1] = dmjson_get_value(incremental, 1, "ReorderedRatio");
			dmasprintf(&ReorderedRatio[0], "IncrementalResult.%u.ReorderedRatio", i);

			ReplicatedRatio[1] = dmjson_get_value(incremental, 1, "ReplicatedRatio");
			dmasprintf(&ReplicatedRatio[0], "IncrementalResult.%u.ReplicatedRatio", i);

			InterfaceEthMbps[1] = dmjson_get_value(incremental, 1, "InterfaceEthMbps");
			dmasprintf(&InterfaceEthMbps[0], "IncrementalResult.%u.InterfaceEthMbps", i);

			add_list_parameter(ctx, IPLayerCapacity[0], dmstrdup(IPLayerCapacity[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, TimeOfSubInterval[0], dmstrdup(TimeOfSubInterval[1]), DMT_TYPE[DMT_TIME], NULL);
			add_list_parameter(ctx, LossRatio[0], dmstrdup(LossRatio[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, RTTRange[0], dmstrdup(RTTRange[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, PDVRange[0], dmstrdup(PDVRange[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, MinOnewayDelay[0], dmstrdup(MinOnewayDelay[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, ReorderedRatio[0], dmstrdup(ReorderedRatio[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, ReplicatedRatio[0], dmstrdup(ReplicatedRatio[1]), DMT_TYPE[DMT_STRING], NULL);
			add_list_parameter(ctx, InterfaceEthMbps[0], dmstrdup(InterfaceEthMbps[1]), DMT_TYPE[DMT_STRING], NULL);
		}
	}

	if (res != NULL)
		json_object_put(res);

	return CMD_SUCCESS;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/

/* *** Device.IP.Diagnostics.IPLayerCapacityMetrics. *** */
DMOBJ tIPLayerCapacityObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"ModalResult", &DMREAD, NULL, NULL, NULL, browseIPLayerCapacityModalResultInst, NULL, NULL, NULL, tIPLayerCapacityModalResultParams, NULL, BBFDM_CWMP},
{"IncrementalResult", &DMREAD, NULL, NULL, NULL, browseIPLayerCapacityIncrementalResultInst, NULL, NULL, NULL, tIPLayerCapacityIncrementalResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPLayerCapacityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_DiagnosticsState, set_IPDiagnosticsIPLayerCapacity_DiagnosticsState, BBFDM_CWMP},
{"IPLayerMaxConnections", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_MaxConnections, NULL, BBFDM_CWMP},
{"IPLayerMaxIncrementalResult", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_MaxIncrementalResult, NULL, BBFDM_CWMP},
{"IPLayerCapSupportedSoftwareVersion", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_SoftwareVersion, NULL, BBFDM_CWMP},
{"IPLayerCapSupportedControlProtocolVersion", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_ControlProtocolVersion, NULL, BBFDM_CWMP},
{"IPLayerCapSupportedMetrics", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_SupportedMetrics, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_Interface, set_IPDiagnosticsIPLayerCapacity_Interface, BBFDM_CWMP},
{"Role", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_Role, set_IPDiagnosticsIPLayerCapacity_Role, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_Host, set_IPDiagnosticsIPLayerCapacity_Host, BBFDM_CWMP},
{"Port", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_Port, set_IPDiagnosticsIPLayerCapacity_Port, BBFDM_CWMP},
{"JumboFramesPermitted", &DMWRITE, DMT_BOOL, get_IPDiagnosticsIPLayerCapacity_JumboFramesPermitted, set_IPDiagnosticsIPLayerCapacity_JumboFramesPermitted, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_DSCP, set_IPDiagnosticsIPLayerCapacity_DSCP, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_ProtocolVersion, set_IPDiagnosticsIPLayerCapacity_ProtocolVersion, BBFDM_CWMP},
{"UDPPayloadContent", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_UDPPayloadContent, set_IPDiagnosticsIPLayerCapacity_UDPPayloadContent, BBFDM_CWMP},
{"TestType", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_TestType, set_IPDiagnosticsIPLayerCapacity_TestType, BBFDM_CWMP},
{"IPDVEnable", &DMWRITE, DMT_BOOL, get_IPDiagnosticsIPLayerCapacity_IPDVEnable, set_IPDiagnosticsIPLayerCapacity_IPDVEnable, BBFDM_CWMP},
{"StartSendingRateIndex", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_StartSendingRateIndex, set_IPDiagnosticsIPLayerCapacity_StartSendingRateIndex, BBFDM_CWMP},
{"NumberTestSubIntervals", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_NumberTestSubIntervals, set_IPDiagnosticsIPLayerCapacity_NumberTestSubIntervals, BBFDM_CWMP},
{"NumberFirstModeTestSubIntervals", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_NumberFirstModeTestSubIntervals, set_IPDiagnosticsIPLayerCapacity_NumberFirstModeTestSubIntervals, BBFDM_CWMP},
{"TestSubInterval", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_TestSubInterval, set_IPDiagnosticsIPLayerCapacity_TestSubInterval, BBFDM_CWMP},
{"StatusFeedbackInterval", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_StatusFeedbackInterval, set_IPDiagnosticsIPLayerCapacity_StatusFeedbackInterval, BBFDM_CWMP},
{"SeqErrThresh", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_SeqErrThresh, set_IPDiagnosticsIPLayerCapacity_SeqErrThresh, BBFDM_CWMP},
{"ReordDupIgnoreEnable", &DMWRITE, DMT_BOOL, get_IPDiagnosticsIPLayerCapacity_ReordDupIgnoreEnable, set_IPDiagnosticsIPLayerCapacity_ReordDupIgnoreEnable, BBFDM_CWMP},
{"LowerThresh", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_LowerThresh, set_IPDiagnosticsIPLayerCapacity_LowerThresh, BBFDM_CWMP},
{"UpperThresh", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_UpperThresh, set_IPDiagnosticsIPLayerCapacity_UpperThresh, BBFDM_CWMP},
{"HighSpeedDelta", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_HighSpeedDelta, set_IPDiagnosticsIPLayerCapacity_HighSpeedDelta, BBFDM_CWMP},
{"RateAdjAlgorithm", &DMWRITE, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_RateAdjAlgorithm, set_IPDiagnosticsIPLayerCapacity_RateAdjAlgorithm, BBFDM_CWMP},
{"SlowAdjThresh", &DMWRITE, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_SlowAdjThresh, set_IPDiagnosticsIPLayerCapacity_SlowAdjThresh, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsIPLayerCapacity_BOMTime, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsIPLayerCapacity_EOMTime, NULL, BBFDM_CWMP},
{"TmaxUsed", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_TmaxUsed, NULL, BBFDM_CWMP},
{"TestInterval", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_TestInterval, NULL, BBFDM_CWMP},
{"MaxIPLayerCapacity", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MaxIPLayerCapacity, NULL, BBFDM_CWMP},
{"TimeOfMax", &DMREAD, DMT_TIME, get_IPDiagnosticsIPLayerCapacity_TimeOfMax, NULL, BBFDM_CWMP},
{"MaxETHCapacityNoFCS", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MaxETHCapacityNoFCS, NULL, BBFDM_CWMP},
{"MaxETHCapacityWithFCS", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MaxETHCapacityWithFCS, NULL, BBFDM_CWMP},
{"MaxETHCapacityWithFCSVLAN", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MaxETHCapacityWithFCSVLAN, NULL, BBFDM_CWMP},
{"LossRatioAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_LossRatioAtMax, NULL, BBFDM_CWMP},
{"RTTRangeAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_RTTRangeAtMax, NULL, BBFDM_CWMP},
{"PDVRangeAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_PDVRangeAtMax, NULL, BBFDM_CWMP},
{"MinOnewayDelayAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MinOnewayDelayAtMax, NULL, BBFDM_CWMP},
{"ReorderedRatioAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_ReorderedRatioAtMax, NULL, BBFDM_CWMP},
{"ReplicatedRatioAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_ReplicatedRatioAtMax, NULL, BBFDM_CWMP},
{"InterfaceEthMbpsAtMax", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_InterfaceEthMbpsAtMax, NULL, BBFDM_CWMP},
{"IPLayerCapacitySummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_IPLayerCapacitySummary, NULL, BBFDM_CWMP},
{"LossRatioSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_LossRatioSummary, NULL, BBFDM_CWMP},
{"RTTRangeSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_RTTRangeSummary, NULL, BBFDM_CWMP},
{"PDVRangeSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_PDVRangeSummary, NULL, BBFDM_CWMP},
{"MinOnewayDelaySummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MinOnewayDelaySummary, NULL, BBFDM_CWMP},
{"MinRTTSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_MinRTTSummary, NULL, BBFDM_CWMP},
{"ReorderedRatioSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_ReorderedRatioSummary, NULL, BBFDM_CWMP},
{"ReplicatedRatioSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_ReplicatedRatioSummary, NULL, BBFDM_CWMP},
{"InterfaceEthMbpsSummary", &DMREAD, DMT_STRING, get_IPDiagnosticsIPLayerCapacity_InterfaceEthMbpsSummary, NULL, BBFDM_CWMP},
{"IncrementalResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_IncrementalResultNumberOfEntries, NULL, BBFDM_CWMP},
{"ModalResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_ModalResultNumberOfEntries, NULL, BBFDM_CWMP},
{"TmaxRTTUsed", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_TmaxRTTUsed, NULL, BBFDM_CWMP},
{"TimestampResolutionUsed", &DMREAD, DMT_UNINT, get_IPDiagnosticsIPLayerCapacity_TimestampResolutionUsed, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPLayerCapacityModalResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"MaxIPLayerCapacity", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_MaxIPLayerCapacity, NULL, BBFDM_CWMP},
{"TimeOfMax", &DMREAD, DMT_TIME, get_IPLayerCapacityModal_TimeOfMax, NULL, BBFDM_CWMP},
{"MaxETHCapacityNoFCS", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_MaxETHCapacityNoFCS, NULL, BBFDM_CWMP},
{"MaxETHCapacityWithFCS", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_MaxETHCapacityWithFCS, NULL, BBFDM_CWMP},
{"MaxETHCapacityWithFCSVLAN", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_MaxETHCapacityWithFCSVLAN, NULL, BBFDM_CWMP},
{"LossRatioAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_LossRatioAtMax, NULL, BBFDM_CWMP},
{"RTTRangeAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_RTTRangeAtMax, NULL, BBFDM_CWMP},
{"PDVRangeAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_PDVRangeAtMax, NULL, BBFDM_CWMP},
{"MinOnewayDelayAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_MinOnewayDelayAtMax, NULL, BBFDM_CWMP},
{"ReorderedRatioAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_ReorderedRatioAtMax, NULL, BBFDM_CWMP},
{"ReplicatedRatioAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_ReplicatedRatioAtMax, NULL, BBFDM_CWMP},
{"InterfaceEthMbpsAtMax", &DMREAD, DMT_STRING, get_IPLayerCapacityModal_InterfaceEthMbpsAtMax, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPLayerCapacityIncrementalResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IPLayerCapacity", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_IPLayerCapacity, NULL, BBFDM_CWMP},
{"TimeOfSubInterval", &DMREAD, DMT_TIME, get_IPLayerCapacityIncremental_TimeOfSubInterval, NULL, BBFDM_CWMP},
{"LossRatio", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_LossRatio, NULL, BBFDM_CWMP},
{"RTTRange", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_RTTRange, NULL, BBFDM_CWMP},
{"PDVRange", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_PDVRange, NULL, BBFDM_CWMP},
{"MinOnewayDelay", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_MinOnewayDelay, NULL, BBFDM_CWMP},
{"ReorderedRatio", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_ReorderedRatio, NULL, BBFDM_CWMP},
{"ReplicatedRatio", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_ReplicatedRatio, NULL, BBFDM_CWMP},
{"InterfaceEthMbps", &DMREAD, DMT_STRING, get_IPLayerCapacityIncremental_InterfaceEthMbps, NULL, BBFDM_CWMP},
{0}
};

