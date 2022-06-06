/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *    Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DMBBFCOMMON_H__
#define __DMBBFCOMMON_H__

#include "libbbf_api/dmcommon.h"
#include "dmentry.h"

void bbf_uci_commit_bbfdm(void);
void bbf_uci_revert_bbfdm(void);
int set_bbfdatamodel_type(int bbf_type);
int get_bbfdatamodel_type(void);
void del_list_fault_param(struct param_fault *param_fault);

void bbf_set_end_session_flag (struct dmctx *ctx, unsigned int flag);
int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value);
int get_dm_type(char *dm_str);

#endif //__DMBBFCOMMON_H__
