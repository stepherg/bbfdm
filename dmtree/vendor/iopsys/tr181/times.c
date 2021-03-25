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

#include "dmentry.h"
#include "times.h"

static int get_local_time_zone_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("system", "@system[0]", "zonename", value);
	return 0;
}

static int get_time_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *iface = NULL;

	dmuci_get_option_value_string("system", "ntp", "interface", &iface);
	if (*iface == '\0' || strlen(iface) == 0)
		return 0;
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", iface, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_time_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *iface = NULL;

	switch (action) {
		case VALUECHECK:
			adm_entry_get_linker_value(ctx, value, &iface);
			if (iface == NULL ||  iface[0] == '\0')
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &iface);
			dmuci_set_value("system", "ntp", "interface", iface);
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMLEAF tIOPSYS_TimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"LocalTimeZoneName", &DMREAD, DMT_STRING, get_local_time_zone_name, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"SourceInterface", &DMWRITE, DMT_STRING, get_time_source_interface, set_time_source_interface, BBFDM_BOTH},
{0}
};
