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

void bbf_ctx_init(struct dmctx *ctx, DMOBJ *tEntryObj);
void bbf_ctx_clean(struct dmctx *ctx);

void bbf_ctx_init_sub(struct dmctx *ctx, DMOBJ *tEntryObj);
void bbf_ctx_clean_sub(struct dmctx *ctx);

int bbf_fault_map(struct dmctx *ctx, int fault);

int bbf_entry_method(struct dmctx *ctx, int cmd);

void bbf_global_init(DMOBJ *dm_entryobj, const char *plugin_path);
void bbf_global_clean(DMOBJ *dm_entryobj);

int dm_validate_allowed_objects(struct dmctx *ctx, struct dm_reference *reference, char *objects[]);

bool adm_entry_object_exists(struct dmctx *ctx, const char *param); // To be removed later

void bbf_entry_services(unsigned int proto, bool is_commit, bool reload_required);

#endif //__DMENTRY_H__
