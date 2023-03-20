/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 */

/* This file is used for validating USPD max msg len using libbbf APIs */

#include <stdlib.h>
#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmcommon.h>

#ifndef DEF_IPC_DATA_LEN
#define DEF_IPC_DATA_LEN (1024 * 1024 - 128)
#endif

/*************************************************************
* GET PARAM
**************************************************************/
static int get_X_IOPSYS_EU_testUSPDParam_TestText(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ptr = (char *)calloc(1, DEF_IPC_DATA_LEN);
	if (ptr == NULL) {
		*value = "";
		return 0;
	}
	memset(ptr, 'a', DEF_IPC_DATA_LEN - 1);
	dmasprintf(value, ptr);
	free(ptr);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/*** Device. ***/
DMLEAF tX_IOPSYS_EU_testUSPDParam[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"X_IOPSYS_EU_TestText", &DMREAD, DMT_STRING, get_X_IOPSYS_EU_testUSPDParam_TestText, NULL, BBFDM_BOTH},
{0}
};

/* ********** DynamicObj ********** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.", NULL, tX_IOPSYS_EU_testUSPDParam},
{0}
};
