/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "wifi.h"

static int get_multi_ap_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *multi_ap = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "multi_ap", &multi_ap);

	if (DM_STRCMP(multi_ap, "1") == 0)
		*value = "Backhaul";
	else if (DM_STRCMP(multi_ap, "2") == 0)
		*value = "Fronthaul";
	else if (DM_STRCMP(multi_ap, "3") == 0)
		*value = "Combined";
	else
		*value = "None";

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMLEAF tIOPSYS_WiFiAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"MultiAPMode", &DMREAD, DMT_STRING, get_multi_ap_mode, NULL, BBFDM_BOTH},
{0}
};
