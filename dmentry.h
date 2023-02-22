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

#include "libbbf_api/dmcommon.h"

extern struct list_head head_package_change;
extern struct list_head main_memhead;
enum ctx_init_enum {
	CTX_INIT_ALL,
	CTX_INIT_SUB
};

typedef enum {
	ALL_SCHEMA,
	PARAM_ONLY,
	EVENT_ONLY,
	COMMAND_ONLY
} schema_type_t;

int dm_ctx_init(struct dmctx *ctx, unsigned int instance_mode);
int dm_ctx_init_sub(struct dmctx *ctx, unsigned int instance_mode);
int dm_ctx_init_entry(struct dmctx *ctx, DMOBJ tEntryObj[], unsigned int instance_mode);
int dm_entry_param_method(struct dmctx *ctx, int cmd, char *inparam, char *arg1, char *arg2);
int dm_entry_apply(struct dmctx *ctx, int cmd);
int dm_entry_restart_services(void);
int dm_entry_manage_services(struct blob_buf *bb, bool restart);
int dm_entry_revert_changes(void);
int usp_fault_map(int fault);
int dm_ctx_clean(struct dmctx *ctx);
int dm_ctx_clean_sub(struct dmctx *ctx);
int dm_get_supported_dm(struct dmctx *ctx, char *path, bool first_level, schema_type_t schema_type);
void dm_config_ubus(struct ubus_context *ctx);
int dm_ctx_init_cache(int time);
void bbf_dm_cleanup(void);

/**
 * @brief dm_debug_browse_path
 *
 * Debug API to get the last datamodel access object by datamodel browse
 * function.
 *
 * @param buff Memory address to store the last access object, ownership
 *  of the address belongs to caller.
 * @param len maximum size of buffer.
 *
 * @return 0, on success and -1, in case of error.
 *
 * @note This is debug API, mostly be useful in debugging in last datamodel
 * object illegal access.
 */
int dm_debug_browse_path(char *buff, size_t len);
void dm_cleanup_dynamic_entry(DMOBJ *root);

#endif
