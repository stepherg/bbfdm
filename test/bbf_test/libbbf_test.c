/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmcommon.h>
#include <libbbf_api/dmuci.h>
#include <libbbf_api/dmubus.h>
#include <libbbf_api/dmjson.h>

#include "libbbf_test.h"

/* ********** DynamicObj ********** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.ManagementServer.", tDynamicManagementServerObj, tDynamicManagementServerParams},
{"Device.", tDynamicDeviceObj, tDynamicDeviceParams},
{0}
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseManagementServerInformParameterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("cwmp", "inform_extra", "dmmap_cwmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "inform_instance", "inform_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjManagementServerInformParameter(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;

	dmuci_add_section("cwmp", "inform_extra", &s);

	dmuci_add_section_bbfdm("dmmap_cwmp", "inform_extra", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_s, "inform_instance", *instance);
	return 0;
}

static int delObjManagementServerInformParameter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("cwmp", "inform_extra", stmp, s) {
				struct uci_section *dmmap_s = NULL;

				get_dmmap_section_of_config_section("dmmap_cwmp", "inform_extra", section_name(s), &dmmap_s);
				dmuci_delete_by_section(dmmap_s, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ManagementServer_EnableCWMP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "enabled", "1");
	return 0;
}

static int set_ManagementServer_EnableCWMP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp", "acs", "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ManagementServerInformParameter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "1");
	return 0;
}

static int set_ManagementServerInformParameter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ManagementServerInformParameter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_cwmp", "inform_extra", section_name(((struct dmmap_dup *)data)->config_section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "inform_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ManagementServerInformParameter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_cwmp", "inform_extra", section_name(((struct dmmap_dup *)data)->config_section), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "inform_alias", value);
			break;
	}
	return 0;
}

static int get_ManagementServerInformParameter_ParameterName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "parameter", value);
	return 0;
}

static int set_ManagementServerInformParameter_ParameterName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "parameter", value);
			break;
	}
	return 0;
}

static int get_ManagementServerInformParameter_EventList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "events", value);
	return 0;
}

static int set_ManagementServerInformParameter_EventList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "events", value);
			break;
	}
	return 0;
}

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
	return !dmubus_call_set("system", "reboot", UBUS_ARGS{0}, 0) ? CMD_SUCCESS : CMD_FAIL;
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
		return CMD_INVALID_ARGUMENTS;

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
	return CMD_SUCCESS;
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
/* *** Device.ManagementServer. *** */
DMOBJ tDynamicManagementServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"InformParameter", &DMWRITE, addObjManagementServerInformParameter, delObjManagementServerInformParameter, NULL, browseManagementServerInformParameterInst, NULL, NULL, NULL, tManagementServerInformParameterParams, NULL, BBFDM_CWMP, LIST_KEY{"Alias", "ParameterName", NULL}},
{0}
};

DMLEAF tDynamicManagementServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"EnableCWMP", &DMWRITE, DMT_BOOL, get_ManagementServer_EnableCWMP, set_ManagementServer_EnableCWMP, BBFDM_CWMP},
{0}
};

/* *** Device.ManagementServer.InformParameter.{i}. *** */
DMLEAF tManagementServerInformParameterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ManagementServerInformParameter_Enable, set_ManagementServerInformParameter_Enable, BBFDM_CWMP},
{"Alias", &DMWRITE, DMT_STRING, get_ManagementServerInformParameter_Alias, set_ManagementServerInformParameter_Alias, BBFDM_CWMP},
{"ParameterName", &DMWRITE, DMT_STRING, get_ManagementServerInformParameter_ParameterName, set_ManagementServerInformParameter_ParameterName, BBFDM_CWMP},
{"EventList", &DMWRITE, DMT_STRING, get_ManagementServerInformParameter_EventList, set_ManagementServerInformParameter_EventList, BBFDM_CWMP},
{0}
};

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
