/*
 * Copyright (C) 2021 Iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 */

#include "servicesvoiceservicedect.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int get_ServicesVoiceServiceDECTPortable_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipui = dmjson_get_value((json_object *)data, 1, "ipui");
	char *id = dmjson_get_value((json_object *)data, 1, "id");

	dmuci_get_option_value_string("dect", ipui, "name", value);
	if ((*value)[0] == '\0') {
		if (strlen(id))
			dmasprintf(value, "DECT%s", id);
		else
			dmasprintf(value, "DECT%s", instance);
	}

	return 0;
}

static int set_ServicesVoiceServiceDECTPortable_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *ipui = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			ipui = dmjson_get_value((json_object *)data, 1, "ipui");
			if ((s = get_origin_section_from_config("dect", "handset", ipui)) == NULL) {
				dmuci_add_section("dect", "handset", &s);
				dmuci_rename_section_by_section(s, ipui);
			}

			dmuci_set_value_by_section(s, "name", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.DECT.Portable.{i}. *** */
DMLEAF tIOPSYS_VoiceServiceDECTPortableParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"Name", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceDECTPortable_Name, set_ServicesVoiceServiceDECTPortable_Name, BBFDM_BOTH},
{0}
};

