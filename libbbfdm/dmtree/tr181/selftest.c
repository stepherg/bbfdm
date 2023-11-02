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

#include <sys/stat.h>

#include "dmcommon.h"
#include "selftest.h"

#define DIAG_BIN "/usr/sbin/self-diagnostics"

static char *get_selftest_log_instance(struct dmctx *ctx)
{
	char *file_name = NULL;
	char *path = NULL;

	struct uci_section *s = get_origin_section_from_config("system", "system", "self_test_log");
	if (s == NULL)
		goto err;

	dmuci_get_value_by_section_string(s, "log_file", &file_name);
	if (DM_STRLEN(file_name) == 0)
		goto err;

	adm_entry_get_reference_param(ctx, "Device.DeviceInfo.VendorLogFile.*.Name", file_name, &path);

err:
	return dmstrdup(path ? path : "");
}

/*************************************************************
* OPERATE COMMAND
**************************************************************/
static operation_args device_self_test_args = {
	.out = (const char *[]) {
		"Status",
		"Results",
		NULL
	}
};

int get_operate_args_SelfTest(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&device_self_test_args;
	return 0;
}

int operate_Device_SelfTest(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char cmd[512] = {0};
	char output[512] = {0};

	snprintf(cmd, sizeof(cmd), "sh %s", DIAG_BIN);

	FILE *pp = popen(cmd, "r");
	if (pp != NULL) {
		fgets(output, sizeof(output), pp);
		pclose(pp);
	} else {
		goto err;
	}

	// truncate the new line char from end
	remove_new_line(output);

	if (!file_exists(output))
		goto err;

	/* Add in vendor log */
	struct uci_section *s = get_origin_section_from_config("system", "system", "self_test_log");
	if (s == NULL) {
		dmuci_add_section("system", "system", &s);
		dmuci_rename_section_by_section(s, "self_test_log");
	}

	dmuci_set_value_by_section(s, "log_file", output);
	dmuci_commit_package("system");

	/* Get self test log instance */
	char *result = get_selftest_log_instance(ctx);

	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup("Complete"), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("Results"), result, DMT_TYPE[DMT_STRING], NULL);

	if (ctx->dm_type != BBFDM_USP) {
		set_diagnostics_option("selftest", "DiagnosticState", "Complete");
		dmuci_commit_package_bbfdm(DMMAP_DIAGNOSTIGS);
	}

	return 0;

err:
	add_list_parameter(ctx, dmstrdup("Status"), dmstrdup("Error_Internal"), DMT_TYPE[DMT_STRING], NULL);
	if (ctx->dm_type != BBFDM_USP) {
		set_diagnostics_option("selftest", "DiagnosticState", "Error");
		dmuci_commit_package_bbfdm(DMMAP_DIAGNOSTIGS);
	}

	return USP_FAULT_COMMAND_FAILURE;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_SelfTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("selftest", "DiagnosticState", "None");
	return 0;
}

static int set_SelfTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0)
				set_diagnostics_option("selftest", "DiagnosticState", value);
	}
	return 0;
}

static int get_SelfTest_Results(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_selftest_log_instance(ctx);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
DMLEAF tSelfTestParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_SelfTest_DiagnosticsState, set_SelfTest_DiagnosticsState, BBFDM_CWMP},
{"Results", &DMREAD, DMT_STRING, get_SelfTest_Results, NULL, BBFDM_CWMP},
{0}
};
