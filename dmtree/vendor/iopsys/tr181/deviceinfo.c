/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "deviceinfo.h"

static int get_base_mac_addr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "BaseMACAddress", value);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMLEAF tIOPSYS_DeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"BaseMACAddress", &DMREAD, DMT_STRING, get_base_mac_addr, NULL, BBFDM_BOTH},
{0}
};
