/*
 * plugin.h: Plugin file bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#ifndef PLUGIN_H

int bbfdm_load_internal_plugin(struct bbfdm_context *bbfdm_ctx, DM_MAP_OBJ *Dynamic_Obj, bbfdm_config_t *config, DMOBJ **main_entry);
int bbfdm_load_external_plugin(struct bbfdm_context *bbfdm_ctx, void **lib_handle, bbfdm_config_t *config, DMOBJ **main_entry);

int bbfdm_load_dotso_plugin(struct bbfdm_context *bbfdm_ctx, void **lib_handle, const char *file_path, bbfdm_config_t *config, DMOBJ **main_entry);
int bbfdm_free_dotso_plugin(struct bbfdm_context *bbfdm_ctx, void *lib_handle);

int bbfdm_load_json_plugin(struct list_head *json_plugin, struct list_head *json_list, struct list_head *json_memhead,
		const char *file_path, bbfdm_config_t *config, DMOBJ **main_entry);
int bbfdm_free_json_plugin(void);

#endif /* PLUGIN_H */
