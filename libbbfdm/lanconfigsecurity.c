/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "lanconfigsecurity.h"

/*#Device.LANConfigSecurity.ConfigPassword!UCI:users/user,user/password*/
static int get_LANConfigSecurity_ConfigPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("users", "user", "password", value);
	return 0;
}

static int set_LANConfigSecurity_ConfigPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value("users", "user", "password", value);
		break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMLEAF tLANConfigSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ConfigPassword", &DMWRITE, DMT_STRING, get_LANConfigSecurity_ConfigPassword, set_LANConfigSecurity_ConfigPassword, BBFDM_BOTH, DM_FLAG_SECURE},
{0}
};
