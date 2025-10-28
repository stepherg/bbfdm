/*
 * Copyright (C) 2019-2024 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#include "device.h"
#include "lanconfigsecurity.h"
#include "security.h"
#include "schedules.h"

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static void _exec_reboot(const void *arg1, void *arg2)
{
	struct bbfdm_ctx d_ctx = {0};
	struct blob_buf bb = {0};

	bbfdm_init_ctx(&d_ctx);
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	// Set last_reboot_cause to 'RemoteReboot' because the upcoming reboot will be initiated by USP Operate
	bbfdm_uci_set(&d_ctx, "sysmngr", "reboots", "last_reboot_cause", "RemoteReboot");
	bbfdm_uci_commit_package(&d_ctx, "sysmngr");
	sleep(3);

	bbfdm_ubus_invoke_sync(&d_ctx, "rpc-sys", "reboot", bb.head, 5000, NULL, NULL);
	sleep(30); // Wait for reboot to happen

	BBF_ERR("Reboot call failed with rpc-sys, trying again with system");
	bbfdm_ubus_invoke_sync(&d_ctx, "system", "reboot", bb.head, 5000, NULL, NULL);
	sleep(30); // Wait for reboot

	BBF_ERR("Reboot call failed!!!");

	// Set last_reboot_cause to empty because there is a problem in the system reboot
	bbfdm_uci_set(&d_ctx, "sysmngr", "reboots", "last_reboot_cause", "");
	bbfdm_uci_commit_package(&d_ctx, "sysmngr");
	bbfdm_free_ctx(&d_ctx);
	blob_buf_free(&bb);
}

static void _exec_factoryreset(const void *arg1, void *arg2)
{
	struct bbfdm_ctx d_ctx = {0};
	struct blob_buf bb = {0};

	bbfdm_init_ctx(&d_ctx);
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	sleep(2);
	bbfdm_ubus_invoke_sync(&d_ctx, "rpc-sys", "factory", bb.head, 5000, NULL, NULL);
	sleep(5); // Wait for reboot to happen

	BBF_ERR("FactoryReset via rpc-sys failed, trying defaultreset");
	bbfdm_free_ctx(&d_ctx);
	blob_buf_free(&bb);

	dmcmd_no_wait("/sbin/defaultreset", 0);
	sleep(5); // Wait for reboot to happen
	BBF_ERR("FactoryReset call failed!!!");
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Device_RootDataModelVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup("2.19");
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_Device_Reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = bbfdm_task_fork(_exec_reboot, NULL, NULL, NULL);
	if (res) bbfdm_set_fault_message(ctx, "Reboot: ubus 'system reboot' method doesn't exist");
	return !res ? 0 : USP_FAULT_COMMAND_FAILURE;
}

static int operate_Device_FactoryReset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = bbfdm_task_fork(_exec_factoryreset, NULL, NULL, NULL);
	if (res) bbfdm_set_fault_message(ctx, "FactoryReset: '/sbin/defaultreset' command doesn't exist");
	return !res ? 0 : USP_FAULT_COMMAND_FAILURE;
}

/*************************************************************
* Init & Clean Module
**************************************************************/
int init_core_module(void *data)
{
	struct dmctx bbf_ctx = {0};

	bbf_ctx_init(&bbf_ctx, NULL);
	dmmap_synchronizeSchedulesSchedule(&bbf_ctx);
	bbf_ctx_clean(&bbf_ctx);

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** BBFDM *** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.", tDMRootObj, tDMRootParams, init_core_module, NULL},
{0}
};

/* *** Device. *** */
DMOBJ tDMRootObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH},
{"Schedules", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSchedulesObj, tSchedulesParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tDMRootParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, BBFDM_BOTH},
{"Reboot()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_Reboot, BBFDM_USP},
{"FactoryReset()", &DMSYNC, DMT_COMMAND, NULL, operate_Device_FactoryReset, BBFDM_USP},
//{"Boot!", &DMREAD, DMT_EVENT, NULL, NULL, BBFDM_USP},
{0}
};

