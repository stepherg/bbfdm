/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DMENTRY_H__
#define __DMENTRY_H__

extern struct list_head global_memhead;

void bbf_ctx_init(struct dmctx *ctx, DMOBJ *tEntryObj,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE *tVendorExtensionExclude);
void bbf_ctx_clean(struct dmctx *ctx);

void bbf_ctx_init_sub(struct dmctx *ctx, DMOBJ *tEntryObj,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE *tVendorExtensionExclude);
void bbf_ctx_clean_sub(struct dmctx *ctx);

int bbf_fault_map(unsigned int dm_type, int fault);

int bbf_entry_method(struct dmctx *ctx, int cmd);

void bbf_global_clean(DMOBJ *dm_entryobj);
int dm_entry_validate_allowed_objects(struct dmctx *ctx, char *value, char *objects[]);

int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value);
int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value);

void bbf_entry_restart_services(struct blob_buf *bb, bool restart_services);
void bbf_entry_revert_changes(struct blob_buf *bb);


/**
 * @brief bbf_debug_browse_path
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
int bbf_debug_browse_path(char *buff, size_t len);

#endif //__DMENTRY_H__
