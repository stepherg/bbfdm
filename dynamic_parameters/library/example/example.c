/*
 * Copyright (C) 2020 iopsys Software Solutions AB
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
#include "example.h"

/* ********** RootDynamicObj ********** */
LIB_MAP_OBJ tRootDynamicObj[] = {
/* parentobj, nextobject */
{"Device.IP.Diagnostics.", tdynamicIPDiagnosticsObj},
{0}
};

/* ********** RootDynamicOperate ********** */
LIB_MAP_OPERATE tRootDynamicOperate[] = {
/* pathname, operation, type */
{"Device.BBKSpeedTest", dynamicDeviceOperate, "async"},
{0}
};

/*************************************************************
 * GET & SET PARAM
/*************************************************************/
static int execute_bbk_speedtest()
{
	json_object *res;
	char *latency, *download, *upload = NULL;

	dmubus_call("bbk", "start", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmuci_set_value_bbfdm("dmmap_diagnostics", "bbkspeedtest", "DiagnosticState", "Complete");
		latency = dmjson_get_value(res, 1, "latency");
		if (latency != NULL && strlen(latency) > 0)
			dmuci_set_value_bbfdm("dmmap_diagnostics", "bbkspeedtest", "Latency", latency);
		download = dmjson_get_value(res, 1, "download");
		if (download != NULL && strlen(latency) > 0)
			dmuci_set_value_bbfdm("dmmap_diagnostics", "bbkspeedtest", "Download", download);
		upload=dmjson_get_value(res, 1, "upload");
		if (upload != NULL && strlen(upload) > 0)
			dmuci_set_value_bbfdm("dmmap_diagnostics", "bbkspeedtest", "Upload", upload);
	}
	return 0;
}

static char *bbk_speedtest_get(char *option, char *default_value)
{
	char *value;
	dmuci_get_option_value_string_bbfdm("dmmap_diagnostics", "bbkspeedtest", option, &value);
	return (*value != '\0') ? value : default_value;
}

void bbk_speedtest_set(char *option, char *value)
{
	struct uci_section *section = NULL;

	check_create_dmmap_package("dmmap_diagnostics");
	section = dmuci_walk_section_bbfdm("dmmap_diagnostics", "bbkspeedtest", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
	if (!section)
		dmuci_set_value_bbfdm("dmmap_diagnostics", "bbkspeedtest", "", "bbkspeedtest");

	dmuci_set_value_bbfdm("dmmap_diagnostics", "bbkspeedtest", option, value);
}

static int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("DiagnosticState", "None");
	return 0;
}

static int setdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				bbk_speedtest_set("DiagnosticState", value);
				execute_bbk_speedtest();
			}
			break;
	}
	return 0;
}

static int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Latency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("Latency", "0");
	return 0;
}

static int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Download(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("Download", "0");
	return 0;
}

static int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Upload(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("Upload", "0");
	return 0;
}

/*************************************************************
 * OPERATE
/*************************************************************/
opr_ret_t dynamicDeviceOperate(struct dmctx *dmctx, char *path, json_object *input)
{
	json_object *ubus_res = NULL;

	dmubus_call("bbk", "start", UBUS_ARGS{}, 0, &ubus_res);

	char *param_latency = (char *) dmjson_get_value(ubus_res, 1, "latency");
	char *param_download = (char *) dmjson_get_value(ubus_res, 1, "download");
	char *param_upload = (char *) dmjson_get_value(ubus_res, 1, "upload");

	add_list_paramameter(dmctx, dmstrdup("Latency"), param_latency, "string", NULL, 0);
	add_list_paramameter(dmctx, dmstrdup("Download"), param_download, "string", NULL, 0);
	add_list_paramameter(dmctx, dmstrdup("Upload"), param_upload, "string", NULL, 0);

	return SUCCESS;
}

/* *** Device.IP.Diagnostics. *** */
DMOBJ tdynamicIPDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"X_IOPSYS_EU_BBKSpeedTest", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tdynamicIPDiagnosticsX_IOPSYS_EU_BBKSpeedTestParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Diagnostics.X_IOPSYS_EU_BBKSpeedTest. *** */
DMLEAF tdynamicIPDiagnosticsX_IOPSYS_EU_BBKSpeedTestParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState, setdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState, BBFDM_BOTH},
{"Latency", &DMREAD, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Latency, NULL, BBFDM_BOTH},
{"Download", &DMREAD, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Download, NULL, BBFDM_BOTH},
{"Upload", &DMREAD, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Upload, NULL, BBFDM_BOTH},
{0}
};

