/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 *
 */

#include "packetcapture.h"

#define PACKET_CAPTURE_DIAGNOSTIC_PATH BBFDM_SCRIPTS_PATH"/packetcapture"

/*************************************************************
 * ENTRY METHODS
 ************************************************************/
static int browsePacketCaptureResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;
	int id = 0;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "packetcapture", s) {
		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static void stop_packetcapture_diagnostics(void)
{
	char cmd[256] = {0};

	snprintf(cmd, sizeof(cmd), "sh %s '{\"proto\":\"both_proto\",\"cancel\":\"1\"}'", PACKET_CAPTURE_DIAGNOSTIC_PATH);
	system(cmd);
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static operation_args packetCapture_args = {
	.in = (const char *[]) {
		"Interface",
		"Format",
		"Duration",
		"PacketCount",
		"FileTarget",
		"FilterExpression",
		"Username",
		"Password",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		"PacketCaptureResult.{i}.FileLocation",
		"PacketCaptureResult.{i}.StartTime",
		"PacketCaptureResult.{i}.EndTime",
		"PacketCaptureResult.{i}.Count",
		NULL
	}
};

int get_operate_args_packetCapture(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&packetCapture_args;
	return 0;
}

int operate_Device_packetCapture(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_format[] = {"libpcap", NULL};
	char input[4096] = {0};
	char cmd[5096] = {0};
	char output[5096] = {0};
	char time_start[32] = {0};
	char time_stop[32] = {0};

	char *intf = dmjson_get_value((json_object *)value, 1, "Interface");
	if (intf[0] != '\0') {
		intf = diagnostics_get_interface_name(ctx, intf);
		if (DM_STRLEN(intf) == 0)
			return USP_FAULT_INVALID_ARGUMENT;
	}

	char *format = dmjson_get_value((json_object *)value, 1, "Format");
	if (format[0] != '\0' && bbfdm_validate_string(ctx, format, -1, -1, allowed_format, NULL))
		return USP_FAULT_INVALID_ARGUMENT;

	char *duration = dmjson_get_value((json_object *)value, 1, "Duration");
	if (duration[0] != '\0') {
		if (bbfdm_validate_unsignedInt(ctx, duration, RANGE_ARGS{{"1", NULL}}, 1))
			return USP_FAULT_INVALID_ARGUMENT;
	} else
		duration = "1";

	char *pack_count = dmjson_get_value((json_object *)value, 1, "PacketCount");
	if (pack_count[0] != '\0') {
		if (bbfdm_validate_unsignedInt(ctx, pack_count, RANGE_ARGS{{0, NULL}}, 1))
			return USP_FAULT_INVALID_ARGUMENT;
	} else
		pack_count = "0";

	char *file_target = dmjson_get_value((json_object *)value, 1, "FileTarget");
	if (file_target[0] != '\0' && bbfdm_validate_string(ctx, file_target, -1, 2048, NULL, NULL))
		return USP_FAULT_INVALID_ARGUMENT;

	char *expr = dmjson_get_value((json_object *)value, 1, "FilterExpression");
	if (expr[0] != '\0' && bbfdm_validate_string(ctx, expr, -1, 256, NULL, NULL))
		return USP_FAULT_INVALID_ARGUMENT;

	char *user = dmjson_get_value((json_object *)value, 1, "Username");
	if (user[0] != '\0' && bbfdm_validate_string(ctx, user, -1, 256, NULL, NULL))
		return USP_FAULT_INVALID_ARGUMENT;

	char *pass = dmjson_get_value((json_object *)value, 1, "Password");
	if (pass[0] != '\0' && bbfdm_validate_string(ctx, pass, -1, 256, NULL, NULL))
		return USP_FAULT_INVALID_ARGUMENT;

	snprintf(input, sizeof(input), "'{\"interface\":\"%s\", \"format\":\"%s\", \"duration\":\"%s\", \"packet_count\":\"%s\", \"file_target\":\"%s\", \"expression\":\"%s\", \"username\":\"%s\", \"password\":\"%s\", \"proto\":\"%s\"}'",
		intf, format, duration, pack_count, file_target, expr, user, pass, (ctx->dm_type == BBFDM_USP) ? "usp" : "both_proto");

	snprintf(cmd, sizeof(cmd), "sh %s %s", PACKET_CAPTURE_DIAGNOSTIC_PATH, input);

	if (run_cmd(cmd, output, sizeof(output)) != 0) {
		bbfdm_set_fault_message(ctx, "PacketCapture: 'sh %s {input}' command failed to run", PACKET_CAPTURE_DIAGNOSTIC_PATH);
		return USP_FAULT_COMMAND_FAILURE;
	}

	json_object *res = (DM_STRLEN(output)) ? json_tokener_parse(output) : NULL;

	if (res == NULL) {
		bbfdm_set_fault_message(ctx, "PacketCapture: there is no output from '%s' script", PACKET_CAPTURE_DIAGNOSTIC_PATH);
		return USP_FAULT_COMMAND_FAILURE;
	}

	char *status = dmjson_get_value(res, 1, "Status");
	char *file_loc = dmjson_get_value(res, 1, "FileLocation");
	char *count = dmjson_get_value(res, 1, "Count");
	char *start_time = dmjson_get_value(res, 1, "StartTime");
	char *end_time = dmjson_get_value(res, 1, "EndTime");

	time_t s_time = strtoul(start_time, NULL, 10);
	time_t e_time = strtoul(end_time, NULL, 10);

	strftime(time_start, sizeof(time_start), "%Y-%m-%dT%H:%M:%SZ", gmtime(&s_time));
	strftime(time_stop, sizeof(time_stop), "%Y-%m-%dT%H:%M:%SZ", gmtime(&e_time));

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup(status), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("PacketCaptureResult.1.FileLocation"), dmstrdup(file_loc), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("PacketCaptureResult.1.StartTime"), dmstrdup(time_start), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("PacketCaptureResult.1.EndTime"), dmstrdup(time_stop), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("PacketCaptureResult.1.Count"), dmstrdup(count), DMT_TYPE[DMT_UNINT], NULL);

	json_object_put(res);

	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_PacketCapture_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val = diagnostics_get_option_fallback_def("packetcapture", "DiagnosticState", "None");
	if (DM_STRSTR(val, "Requested") != NULL)
		*value = dmstrdup("Requested");
	else
		*value = dmstrdup(val);

	return 0;
}

static int set_PacketCapture_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				diagnostics_set_option("packetcapture", "DiagnosticState", value);
			} else if (DM_LSTRCMP(value, "Canceled") == 0) {
				diagnostics_set_option("packetcapture", "DiagnosticState", "None");
				stop_packetcapture_diagnostics();
			}
	}
	return 0;
}

static int get_PacketCapture_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = diagnostics_get_option("packetcapture", "Interface");
	_bbfdm_get_references(ctx, "Device.IP.Interface.", "Name", linker, value);
	return 0;
}

static int set_PacketCapture_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbfdm_get_reference_linker(ctx, value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "Interface", reference.value);
	}
	return 0;
}

static int get_PacketCapture_Format(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = diagnostics_get_option("packetcapture", "Format");
	return 0;
}

static int set_PacketCapture_Format(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_format[] = {"libpcap", NULL};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, allowed_format, NULL))
				return FAULT_9007;

			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "Format", value);
	}
	return 0;
}

static int get_PacketCapture_Duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = diagnostics_get_option_fallback_def("packetcapture", "Duration", "1");
	return 0;
}

static int set_PacketCapture_Duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1", NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "Duration", value);
	}
	return 0;
}

static int get_PacketCapture_PacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = diagnostics_get_option_fallback_def("packetcapture", "PacketCount", "0");
	return 0;
}

static int set_PacketCapture_PacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "PacketCount", value);
	}
	return 0;
}

static int get_PacketCapture_FileTarget(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = diagnostics_get_option("packetcapture", "FileTarget");
	return 0;
}

static int set_PacketCapture_FileTarget(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 2048, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "FileTarget", value);
	}
	return 0;
}

static int get_PacketCapture_FilterExpression(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = diagnostics_get_option("packetcapture", "FilterExpression");
	return 0;
}

static int set_PacketCapture_FilterExpression(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "FilterExpression", value);
	}
	return 0;
}

static int get_PacketCapture_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = diagnostics_get_option("packetcapture", "Username");
	return 0;
}

static int set_PacketCapture_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "Username", value);
	}
	return 0;
}

static int get_PacketCapture_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_PacketCapture_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			diagnostics_reset_state("packetcapture");
			stop_packetcapture_diagnostics();
			diagnostics_set_option("packetcapture", "Password", value);
	}
	return 0;
}

static int get_PacketCapture_ResultNumInstance(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browsePacketCaptureResultInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_PacketCaptureResult_FileLocation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "FileLocation", value);
	return 0;
}

static int get_PacketCaptureResult_StartTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *time = NULL;
	time_t tm;
	char time_start[32] = {0};

	dmuci_get_value_by_section_string((struct uci_section *)data, "StartTime", &time);
	tm = strtoul(time, NULL, 10);
	strftime(time_start, sizeof(time_start), "%Y-%m-%dT%H:%M:%SZ", gmtime(&tm));

	*value = dmstrdup(time_start);
	return 0;
}

static int get_PacketCaptureResult_EndTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *time = NULL;
	time_t tm;
	char time_end[32] = {0};

	dmuci_get_value_by_section_string((struct uci_section *)data, "EndTime", &time);
	tm = strtoul(time, NULL, 10);
	strftime(time_end, sizeof(time_end), "%Y-%m-%dT%H:%M:%SZ", gmtime(&tm));

	*value = dmstrdup(time_end);
	return 0;
}

static int get_PacketCaptureResult_Count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "Count", value);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
DMOBJ tPacketCaptureObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PacketCaptureResult", &DMREAD, NULL, NULL, NULL, browsePacketCaptureResultInst, NULL, NULL, NULL, tPacketCaptureResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tPacketCaptureParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_PacketCapture_DiagnosticsState, set_PacketCapture_DiagnosticsState, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_PacketCapture_Interface, set_PacketCapture_Interface, BBFDM_CWMP, DM_FLAG_REFERENCE},
{"Format", &DMWRITE, DMT_STRING, get_PacketCapture_Format, set_PacketCapture_Format, BBFDM_CWMP},
{"Duration", &DMWRITE, DMT_UNINT, get_PacketCapture_Duration, set_PacketCapture_Duration, BBFDM_CWMP},
{"PacketCount", &DMWRITE, DMT_UNINT, get_PacketCapture_PacketCount, set_PacketCapture_PacketCount, BBFDM_CWMP},
{"FileTarget", &DMWRITE, DMT_STRING, get_PacketCapture_FileTarget, set_PacketCapture_FileTarget, BBFDM_CWMP},
{"FilterExpression", &DMWRITE, DMT_STRING, get_PacketCapture_FilterExpression, set_PacketCapture_FilterExpression, BBFDM_CWMP},
{"Username", &DMWRITE, DMT_STRING, get_PacketCapture_Username, set_PacketCapture_Username, BBFDM_CWMP},
{"Password", &DMWRITE, DMT_STRING, get_PacketCapture_Password, set_PacketCapture_Password, BBFDM_CWMP},
{"PacketCaptureResultNumberOfEntries", &DMREAD, DMT_UNINT, get_PacketCapture_ResultNumInstance, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tPacketCaptureResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"FileLocation", &DMREAD, DMT_STRING, get_PacketCaptureResult_FileLocation, NULL, BBFDM_CWMP},
{"StartTime", &DMREAD, DMT_TIME, get_PacketCaptureResult_StartTime, NULL, BBFDM_CWMP},
{"EndTime", &DMREAD, DMT_TIME, get_PacketCaptureResult_EndTime, NULL, BBFDM_CWMP},
{"Count", &DMREAD, DMT_UNINT, get_PacketCaptureResult_Count, NULL, BBFDM_CWMP},
{0}
};
