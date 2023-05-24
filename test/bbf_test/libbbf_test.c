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
	return !dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0) ? 0 : bbfdm_FAULT_COMMAND_FAILURE;
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
		return bbfdm_FAULT_INVALID_ARGUMENT;

	snprintf(command, sizeof(command), "ping -c 1 -W 1 %s", host);

	if ((log = popen(command, "r"))) { /* Flawfinder: ignore */
		char line[512] = {0};

		while (fgets(line, sizeof(line), log) != NULL) {
			if (DM_STRSTR(line, "rtt")) {
				strtok_r(line, "=", &min);
				strtok_r(min ? min+1 : "", "/", &avg);
				add_list_parameter(ctx, dmstrdup("MinimumResponseTime"), dmstrdup(min ? min+1 : ""), "xsd:unsignedInt", NULL);
				strtok_r(avg, "/", &max);
				add_list_parameter(ctx, dmstrdup("AverageResponseTime"), dmstrdup(avg ? avg : ""), "xsd:unsignedInt", NULL);
				strtok_r(max, "/", &p);
				add_list_parameter(ctx, dmstrdup("MaximumResponseTime"), dmstrdup(max ? max : ""), "xsd:unsignedInt", NULL);
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

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device. *** */
DMOBJ tDynamicDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"X_IOPSYS_EU_Syslog", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, tX_IOPSYS_EU_SyslogParam, NULL, BBFDM_BOTH},
{"X_IOPSYS_EU_PingTEST", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tX_IOPSYS_EU_PingTESTParam, NULL, BBFDM_BOTH},
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
