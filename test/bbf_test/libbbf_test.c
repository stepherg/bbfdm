/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include <libbbfdm-api/dmbbf.h>
#include <libbbfdm-api/dmcommon.h>
#include <libbbfdm-api/dmuci.h>
#include <libbbfdm-api/dmubus.h>
#include <libbbfdm-api/dmjson.h>

#include "libbbf_test.h"

/* ********** DynamicObj ********** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.", tDynamicDeviceObj, tDynamicDeviceParams},
{0}
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseX_IOPSYS_EU_EventTESTInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;

	for (int i = 0; i < 2; i++) {

		inst = handle_instance_without_section(dmctx, parent_node, i + 1);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, NULL, inst) == DM_STOP)
			break;
	}

	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_X_IOPSYS_EU_Syslog_ServerIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("system", "@system[0]", "log_ip", value);
	return 0;
}

static int set_X_IOPSYS_EU_Syslog_ServerIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:			
			return 0;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "log_ip", value);
			return 0;
	}
	return 0;
}
	
static int get_X_IOPSYS_EU_Syslog_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("system", "@system[0]", "log_port", "514");
	return 0;
}

static int set_X_IOPSYS_EU_Syslog_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:			
			return 0;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "log_port", value);
			return 0;
	}
	return 0;
}

static int get_X_IOPSYS_EU_Syslog_ConsoleLogLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("system", "@system[0]", "conloglevel", "7");
	return 0;
}

static int set_X_IOPSYS_EU_Syslog_ConsoleLogLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:			
			return 0;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "conloglevel", value);
			return 0;
	}
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_Device_X_IOPSYS_EU_Reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return !dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0) ? 0 : USP_FAULT_COMMAND_FAILURE;
}

static operation_args x_iopsys_eu_ping_test_run_args = {
	.in = (const char *[]) {
		"Host",
		NULL
	},
	.out = (const char *[]) {
		"AverageResponseTime",
		"MinimumResponseTime",
		"MaximumResponseTime",
		NULL
	}
};

static int get_operate_args_XIOPSYSEUPingTEST_Run(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&x_iopsys_eu_ping_test_run_args;
	return 0;
}

static int operate_DeviceXIOPSYSEUPingTEST_Run(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *p, *min = NULL, *avg = NULL, *max = NULL, command[512];
	FILE *log = NULL;

	char *host = dmjson_get_value((json_object *)value, 1, "Host");
	if(host[0] == '\0')
		return USP_FAULT_INVALID_ARGUMENT;

	snprintf(command, sizeof(command), "ping -c 1 -W 1 %s", host);

	if ((log = popen(command, "r"))) { /* Flawfinder: ignore */
		char line[512] = {0};

		while (fgets(line, sizeof(line), log) != NULL) {
			if (DM_STRSTR(line, "rtt")) {
				strtok_r(line, "=", &min);
				strtok_r(min ? min+1 : "", "/", &avg);
				fill_blob_param(&ctx->bb, "MinimumResponseTime", min ? min + 1 : "", "xsd:unsignedInt", 0);
				strtok_r(avg, "/", &max);
				fill_blob_param(&ctx->bb, "AverageResponseTime", avg ? avg : "", "xsd:unsignedInt", 0);
				strtok_r(max, "/", &p);
				fill_blob_param(&ctx->bb, "MaximumResponseTime", max ? max : "", "xsd:unsignedInt", 0);
				break;
			}
		}
		pclose(log);
	}
	return 0;
}

/*************************************************************
 * EVENTS
 *************************************************************/
static event_args boot_event_args = {
	.name = "",
	.param = (const char *[]) {
		"CommandKey",
		"Cause",
		"FirmwareUpdated",
		"ParameterMap",
		NULL
	}
};

static int get_event_args_XIOPSYSEU_Boot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&boot_event_args;
	return 0;
}

static event_args test_event_args = {
	.name = "bbf.test",
	.param = (const char *[]) {
		"CommandKey",
		"Status",
		NULL
	}
};

static int get_event_args_XIOPSYSEUEventTEST_Test(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&test_event_args;
	return 0;
}

static int event_XIOPSYSEUEventTEST_Test(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case EVENT_CHECK:
		{
			char *test_instance = dmjson_get_value((json_object *)value, 1, "instance");
			if (DM_STRCMP(test_instance, instance) != 0)
				return USP_FAULT_INVALID_PATH_SYNTAX;
			break;
		}
		case EVENT_RUN:
		{
			char *command_key = dmjson_get_value((json_object *)value, 1, "command_key");
			char *status = dmjson_get_value((json_object *)value, 1, "status");

			fill_blob_param(&ctx->bb, "CommandKey", command_key, DMT_TYPE[DMT_STRING], 0);
			fill_blob_param(&ctx->bb, "Status", status, DMT_TYPE[DMT_STRING], 0);
			break;
		}
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device. *** */
DMOBJ tDynamicDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"X_IOPSYS_EU_Syslog", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, tX_IOPSYS_EU_SyslogParam, NULL, BBFDM_BOTH},
{"X_IOPSYS_EU_PingTEST", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tX_IOPSYS_EU_PingTESTParam, NULL, BBFDM_BOTH},
{"X_IOPSYS_EU_EventTEST", &DMREAD, NULL, NULL, NULL, browseX_IOPSYS_EU_EventTESTInst, NULL, NULL, NULL, tX_IOPSYS_EU_EventTESTParam, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDynamicDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"X_IOPSYS_EU_Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_X_IOPSYS_EU_Reboot, BBFDM_USP},
{"X_IOPSYS_EU_Boot!", &DMREAD, DMT_EVENT, get_event_args_XIOPSYSEU_Boot, NULL, BBFDM_USP},
{"X_IOPSYS_EU_WakeUp!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP},
{0}
};

/*** Device.X_IOPSYS_EU_Syslog. ***/
DMLEAF tX_IOPSYS_EU_SyslogParam[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ServerIPAddress", &DMWRITE, DMT_STRING, get_X_IOPSYS_EU_Syslog_ServerIPAddress, set_X_IOPSYS_EU_Syslog_ServerIPAddress, BBFDM_BOTH},
{"ServerPort", &DMWRITE, DMT_UNINT, get_X_IOPSYS_EU_Syslog_ServerPort, set_X_IOPSYS_EU_Syslog_ServerPort, BBFDM_BOTH},
{"ConsoleLogLevel", &DMWRITE, DMT_UNINT, get_X_IOPSYS_EU_Syslog_ConsoleLogLevel, set_X_IOPSYS_EU_Syslog_ConsoleLogLevel, BBFDM_BOTH},
{0}
};

/*** Device.X_IOPSYS_EU_PingTEST. ***/
DMLEAF tX_IOPSYS_EU_PingTESTParam[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Run()", &DMASYNC, DMT_COMMAND, get_operate_args_XIOPSYSEUPingTEST_Run, operate_DeviceXIOPSYSEUPingTEST_Run, BBFDM_USP},
{0}
};

/*** Device.X_IOPSYS_EU_EventTEST. ***/
DMLEAF tX_IOPSYS_EU_EventTESTParam[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Test!", &DMREAD, DMT_EVENT, get_event_args_XIOPSYSEUEventTEST_Test, event_XIOPSYSEUEventTEST_Test, BBFDM_USP},
{0}
};

