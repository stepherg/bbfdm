/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#include "dmapi.h"
#include "dmplugin.h"

#ifdef BBFDM_ENABLE_JSON_PLUGIN
#include "plugin/json_plugin.h"
static char json_hash[64] = {0};
#endif /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
#include "plugin/dotso_plugin.h"
static char library_hash[64] = {0};
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
#include "plugin/vendor_plugin.h"
#endif

static bool first_boot = false;

extern struct list_head global_memhead;

#if defined(BBFDM_ENABLE_JSON_PLUGIN) || defined(BBFDM_ENABLE_DOTSO_PLUGIN)
static char *get_folder_path(bool json_path)
{
	if (json_path) {
#ifdef BBFDM_ENABLE_JSON_PLUGIN
		return JSON_FOLDER_PATH;
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */
	} else {
#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
		return LIBRARY_FOLDER_PATH;
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */
	}

	return NULL;
}

static int get_stats_folder(bool json_path, int *count, unsigned long *size)
{
	const char *path = get_folder_path(json_path);
	if (path == NULL)
		return 0;

	if (folder_exists(path)) {
		struct dirent *entry = NULL;
		struct stat stats;
		int file_count = 0;
		unsigned long file_size = 0;
		char buf[512] = {0};

		DIR *dirp = opendir(path);
		while ((entry = readdir(dirp)) != NULL) {
			if ((entry->d_type == DT_REG) && (strstr(entry->d_name, json_path ? ".json" : ".so"))) {
				file_count++;
				snprintf(buf, sizeof(buf), "%s/%s", path, entry->d_name);
				if (!stat(buf, &stats))
					file_size += stats.st_size;
			}
		}

		if (dirp)
			closedir(dirp);

		*count = file_count;
		*size = file_size;
		return 1;
	}
	return 0;
}

static bool check_stats_folder(bool json_path)
{
	int count = 0;
	unsigned long size = 0;
	char buf[64] = {0};

	if (!get_stats_folder(json_path, &count, &size))
		return false;

	snprintf(buf, sizeof(buf), "count:%d,size:%lu", count, size);

	if (json_path) {
#ifdef BBFDM_ENABLE_JSON_PLUGIN
		if (DM_STRCMP(buf, json_hash) != 0) {
			DM_STRNCPY(json_hash, buf, sizeof(json_hash));
			return true;
		}
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */
	} else {
#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
		if (DM_STRCMP(buf, library_hash) != 0) {
			DM_STRNCPY(library_hash, buf, sizeof(library_hash));
			return true;
		}
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */
	}

	return false;
}
#endif  /* (BBFDM_ENABLE_JSON_PLUGIN || BBFDM_ENABLE_DOTSO_PLUGIN) */

static void load_services(struct dmctx *ctx)
{
	json_object *service = NULL;

	if (!ctx->services_obj)
		return;

	size_t nbre_services = json_object_array_length(ctx->services_obj);

	for (size_t i = 0; i < nbre_services; i++) {
		service = json_object_array_get_idx(ctx->services_obj, i);

		char *obj_mount = dmjson_get_value(service, 1, "obj_mount");
		if (DM_STRLEN(obj_mount) == 0)
			continue;

		char *obj_name = dmjson_get_value(service, 1, "obj_name");
		if (DM_STRLEN(obj_name) == 0)
			continue;

		char *ubus_obj = dmjson_get_value(service, 1, "ubus_obj");
		if (DM_STRLEN(ubus_obj) == 0)
			continue;

		DMOBJ *dm_entryobj = NULL;
		bool obj_exists = find_entry_obj(ctx->dm_entryobj, obj_mount, &dm_entryobj);
		if (obj_exists == false || !dm_entryobj)
			continue;

		if (dm_entryobj->nextdynamicobj == NULL) {
			dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
			dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
			dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
			dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
			dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].idx_type = INDX_SERVICE_MOUNT;
		}

		if (dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj == NULL) {
			dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj = calloc(2, sizeof(DMOBJ *));
		}

		if (dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] == NULL) {
			dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] = dm_dynamic_calloc(&global_memhead, 2, sizeof(struct dm_obj_s));
			((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[0]).obj = dm_dynamic_strdup(&global_memhead, obj_name);
			((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[0]).checkdep = dm_dynamic_strdup(&global_memhead, ubus_obj);
		} else {
			int idx = get_entry_idx(dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0]);
			dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] = dm_dynamic_realloc(&global_memhead, dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
			memset(dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
			((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[idx]).obj = dm_dynamic_strdup(&global_memhead, obj_name);
			((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[idx]).checkdep = dm_dynamic_strdup(&global_memhead, ubus_obj);
		}
	}
}

static void free_specific_dynamic_node(DMOBJ *entryobj, int indx)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + indx;
			FREE(next_dyn_array->nextobj);
		}

		if (entryobj->dynamicleaf) {
			struct dm_dynamic_leaf *next_dyn_array = entryobj->dynamicleaf + indx;
			FREE(next_dyn_array->nextleaf);
		}

		if (entryobj->nextobj)
			free_specific_dynamic_node(entryobj->nextobj, indx);
	}
}

static void free_all_dynamic_nodes(DMOBJ *entryobj)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + i;
				FREE(next_dyn_array->nextobj);
			}
			FREE(entryobj->nextdynamicobj);
		}

		if (entryobj->dynamicleaf) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_leaf *next_dyn_array = entryobj->dynamicleaf + i;
				FREE(next_dyn_array->nextleaf);
			}
			FREE(entryobj->dynamicleaf);
		}

		if (entryobj->nextobj)
			free_all_dynamic_nodes(entryobj->nextobj);
	}
}

static int plugin_obj_match(char *in_param, struct dmnode *node)
{
	if (node->matched)
		return 0;

	if (DM_STRSTR(node->current_object, in_param) == node->current_object) {
		node->matched++;
		return 0;
	}

	if (DM_STRSTR(in_param, node->current_object) == in_param)
		return 0;

	return FAULT_9005;
}

static void dm_check_dynamic_obj(DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, DMOBJ **root_entry, bool *obj_found);
static void dm_check_dynamic_obj_entry(DMNODE *parent_node, DMOBJ *entryobj, char *parent_obj, char *full_obj, DMOBJ **root_entry, bool *obj_found)
{
	DMNODE node = {0};
	node.obj = entryobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level;
	node.matched = parent_node->matched;

	dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);
	if (DM_STRCMP(node.current_object, full_obj) == 0) {
		*root_entry = entryobj;
		*obj_found = true;
		return;
	}

	int err = plugin_obj_match(full_obj, &node);
	if (err)
		return;

	if (entryobj->nextobj || entryobj->nextdynamicobj)
		dm_check_dynamic_obj(&node, entryobj->nextobj, full_obj, root_entry, obj_found);
}

static void dm_check_dynamic_obj(DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, DMOBJ **root_entry, bool *obj_found)
{
	char *parent_obj = parent_node->current_object;

	for (; (entryobj && entryobj->obj); entryobj++) {
		dm_check_dynamic_obj_entry(parent_node, entryobj, parent_obj, full_obj, root_entry, obj_found);
		if (*obj_found == true)
			return;
	}

	if (parent_node->obj) {
		if (parent_node->obj->nextdynamicobj) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX - 1; i++) {
				struct dm_dynamic_obj *next_dyn_array = parent_node->obj->nextdynamicobj + i;
				if (next_dyn_array->nextobj) {
					for (int j = 0; next_dyn_array->nextobj[j]; j++) {
						DMOBJ *jentryobj = next_dyn_array->nextobj[j];
						for (; (jentryobj && jentryobj->obj); jentryobj++) {
							dm_check_dynamic_obj_entry(parent_node, jentryobj, parent_obj, full_obj, root_entry, obj_found);
							if (*obj_found == true)
								return;
						}
					}
				}
			}
		}
	}
}

bool find_entry_obj(DMOBJ *root_entry, char *in_param, DMOBJ **entryobj)
{
	if (!root_entry || !in_param || !entryobj)
		return false;

	DMNODE node = {.current_object = ""};
	bool obj_found = false;

	char *obj_path = replace_str(in_param, ".{i}.", ".");
	dm_check_dynamic_obj(&node, root_entry, obj_path, entryobj, &obj_found);
	FREE(obj_path);

	return (obj_found && *entryobj) ? true : false;
}

void dm_exclude_obj(DMOBJ *entryobj, DMNODE *parent_node, char *obj_path)
{
	char *parent_obj = parent_node->current_object;

	for (; (entryobj && entryobj->obj); entryobj++) {
		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);
		if (DM_STRCMP(node.current_object, obj_path) == 0) {
			entryobj->bbfdm_type = BBFDM_NONE;
			return;
		}

		int err = plugin_obj_match(obj_path, &node);
		if (err)
			continue;

		if (entryobj->nextobj)
			dm_exclude_obj(entryobj->nextobj, &node, obj_path);
	}
}

int get_entry_idx(DMOBJ *entryobj)
{
	int idx = 0;

	for (; (entryobj && entryobj->obj); entryobj++)
		idx++;

	return idx;
}

int get_obj_idx(DMOBJ **entryobj)
{
	int idx = 0;

	for (int i = 0; entryobj[i]; i++)
		idx++;

	return idx;
}

int get_leaf_idx(DMLEAF **entryleaf)
{
	int idx = 0;

	for (int i = 0; entryleaf[i]; i++)
		idx++;

	return idx;
}

void load_plugins(struct dmctx *ctx)
{
	if (ctx->enable_plugins) {
#ifdef BBFDM_ENABLE_JSON_PLUGIN
	// Load dynamic objects and parameters exposed via JSON file plugin
	if (check_stats_folder(true)) {
		free_json_plugins();
		free_specific_dynamic_node(ctx->dm_entryobj, INDX_JSON_MOUNT);
		load_json_plugins(ctx);
	}
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
	// Load dynamic objects and parameters exposed via a dotso plugin
	if (check_stats_folder(false)) {
		free_dotso_plugins();
		free_specific_dynamic_node(ctx->dm_entryobj, INDX_LIBRARY_MOUNT);
		load_dotso_plugins(ctx);
	}
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
	// Load objects and parameters exposed via vendor extension plugin
	if (first_boot == false) {
		free_specific_dynamic_node(ctx->dm_entryobj, INDX_VENDOR_MOUNT);
		load_vendor_dynamic_arrays(ctx);
	}
#endif /* BBF_VENDOR_EXTENSION */
	}

	if (first_boot == false) {
		// Load main objects exposed via services section
		free_specific_dynamic_node(ctx->dm_entryobj, INDX_SERVICE_MOUNT);
		load_services(ctx);
	}

	first_boot = true;
}

void free_plugins(DMOBJ *dm_entryobj)
{
	free_all_dynamic_nodes(dm_entryobj);

#ifdef BBFDM_ENABLE_JSON_PLUGIN
	free_json_plugins();
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
	free_dotso_plugins();
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */
}
