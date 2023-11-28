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

void bbf_ctx_init(struct dmctx *ctx, DMOBJ *tEntryObj,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE *tVendorExtensionExclude);
void bbf_ctx_clean(struct dmctx *ctx);

void bbf_ctx_init_sub(struct dmctx *ctx, DMOBJ *tEntryObj,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE *tVendorExtensionExclude);
void bbf_ctx_clean_sub(struct dmctx *ctx);

int bbf_fault_map(struct dmctx *ctx, int fault);

int bbf_entry_method(struct dmctx *ctx, int cmd);

void bbf_global_init(DMOBJ *dm_entryobj, DM_MAP_VENDOR *dm_VendorExtension[], DM_MAP_VENDOR_EXCLUDE *dm_VendorExtensionExclude, const char *plugin_path);
void bbf_global_clean(DMOBJ *dm_entryobj);

int dm_entry_validate_allowed_objects(struct dmctx *ctx, char *value, char *objects[]);
int dm_entry_validate_external_linker_allowed_objects(struct dmctx *ctx, char *value, char *objects[]);
int dm_validate_allowed_objects(struct dmctx *ctx, struct dm_reference *reference, char *objects[]);

bool adm_entry_object_exists(struct dmctx *ctx, char *param);

int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value);
int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value);

void bbf_entry_restart_services(struct blob_buf *bb, bool restart_services);
void bbf_entry_revert_changes(struct blob_buf *bb);

void get_list_of_registered_service(struct list_head *srvlist, struct blob_buf *bb);
bool load_service(DMOBJ *main_dm, struct list_head *srv_list, char *srv_name, char *srv_parent_dm, char *srv_obj);
void free_services_from_list(struct list_head *clist);

int handle_transaction_of_registered_service(struct ubus_context *ctx, struct blob_buf *trans_bb, struct list_head *srvlist,
		const char *trans_cmd, int trans_id, uint32_t max_timeout, bool service_restart);

#endif //__DMENTRY_H__
