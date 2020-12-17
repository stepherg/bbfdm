/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DMENTRY_H__
#define __DMENTRY_H__

#include <libbbf_api/dmcommon.h>

extern struct list_head head_package_change;

enum ctx_init_enum {
	CTX_INIT_ALL,
	CTX_INIT_SUB
};

int dm_ctx_init(struct dmctx *ctx, unsigned int instance_mode);
int dm_ctx_init_sub(struct dmctx *ctx, unsigned int instance_mode);
int dm_entry_param_method(struct dmctx *ctx, int cmd, char *inparam, char *arg1, char *arg2);
int dm_entry_apply(struct dmctx *ctx, int cmd, char *arg1, char *arg2);
int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value);
int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value);
int dm_entry_restart_services(void);
int dm_entry_revert_changes(void);
int usp_fault_map(int fault);
int dm_ctx_clean(struct dmctx *ctx);
int dm_ctx_clean_sub(struct dmctx *ctx);
int load_dynamic_arrays(struct dmctx *ctx);
int free_dynamic_arrays(void);
int dmentry_get_parameter_leaf_value(struct dmctx *ctx, char *inparam);
void dm_ctx_init_list_parameter(struct dmctx *ctx);
void dm_ctx_clean_list_parameter(struct dmctx *ctx);

#endif
