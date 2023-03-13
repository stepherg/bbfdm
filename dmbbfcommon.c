/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "dmbbfcommon.h"

int set_bbfdatamodel_type(int bbf_type)
{
	bbfdatamodel_type = bbf_type;
	return 0;
}

int get_bbfdatamodel_type(void)
{
	return bbfdatamodel_type;
}

int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value)
{
	return dmuci_lookup_ptr(ctx, ptr, package, section, option, value);
}

void bbf_uci_commit_bbfdm(void)
{
	dmuci_init_bbfdm();
	dmuci_commit_bbfdm();
	dmuci_exit_bbfdm();
}

void bbf_uci_revert_bbfdm(void)
{
	dmuci_init_bbfdm();
	dmuci_revert_bbfdm();
	dmuci_exit_bbfdm();
}

void del_list_fault_param(struct param_fault *param_fault)
{
	bbf_api_del_list_fault_param(param_fault);
}

int get_dm_type(char *dm_str)
{
	if (dm_str == NULL)
		return DMT_STRING;

	if (DM_STRCMP(dm_str, DMT_TYPE[DMT_STRING]) == 0)
		return DMT_STRING;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_UNINT]) == 0)
		return DMT_UNINT;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_INT]) == 0)
		return DMT_INT;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_UNLONG]) == 0)
		return DMT_UNLONG;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_LONG]) == 0)
		return DMT_LONG;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_BOOL]) == 0)
		return DMT_BOOL;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_TIME]) == 0)
		return DMT_TIME;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_HEXBIN]) == 0)
		return DMT_HEXBIN;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_BASE64]) == 0)
		return DMT_BASE64;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_COMMAND]) == 0)
		return DMT_COMMAND;
	else if (DM_STRCMP(dm_str, DMT_TYPE[DMT_EVENT]) == 0)
		return DMT_EVENT;
	else
		return DMT_STRING;

	return DMT_STRING;
}
