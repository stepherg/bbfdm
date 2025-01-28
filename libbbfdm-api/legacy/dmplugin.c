/*
 * Copyright (C) 2023-2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#include "dmapi.h"
#include "dmplugin.h"

#include "plugin/json_plugin.h"
#include "plugin/dotso_plugin.h"

static void free_all_dynamic_nodes(DMOBJ *entryobj)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + i;

				if (next_dyn_array->nextobj) {
					for (int j = 0; next_dyn_array->nextobj[j]; j++) {
						DMOBJ *jentryobj = next_dyn_array->nextobj[j];
						if (jentryobj)
							free_all_dynamic_nodes(jentryobj);
					}
				}

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

static int plugin_obj_match(const char *in_param, struct dmnode *node)
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

static void dm_check_dynamic_obj(struct list_head *mem_list, DMNODE *parent_node, DMOBJ *entryobj, const char *full_obj, DMOBJ **root_entry);
static void dm_check_dynamic_obj_entry(struct list_head *mem_list, DMNODE *parent_node, DMOBJ *entryobj, const char *parent_obj, const char *full_obj, DMOBJ **root_entry)
{
	DMNODE node = {0};
	node.obj = entryobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level;
	node.matched = parent_node->matched;

	dm_dynamic_asprintf(mem_list, &(node.current_object), "%s%s.", parent_obj, entryobj->obj);
	if (DM_STRCMP(node.current_object, full_obj) == 0) {
		*root_entry = entryobj;
		return;
	}

	int err = plugin_obj_match(full_obj, &node);
	if (err)
		return;

	if (entryobj->nextobj || entryobj->nextdynamicobj)
		dm_check_dynamic_obj(mem_list, &node, entryobj->nextobj, full_obj, root_entry);
}

static void dm_check_dynamic_obj(struct list_head *mem_list, DMNODE *parent_node, DMOBJ *entryobj, const char *full_obj, DMOBJ **root_entry)
{
	char *parent_obj = parent_node->current_object;

	for (; (entryobj && entryobj->obj); entryobj++) {
		dm_check_dynamic_obj_entry(mem_list, parent_node, entryobj, parent_obj, full_obj, root_entry);
		if (*root_entry != NULL)
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
							dm_check_dynamic_obj_entry(mem_list, parent_node, jentryobj, parent_obj, full_obj, root_entry);
							if (*root_entry != NULL)
								return;
						}
					}
				}
			}
		}
	}
}

DMOBJ *find_entry_obj(DMOBJ *entryobj, const char *obj_path)
{
	if (!entryobj || !obj_path)
		return NULL;

	DMNODE node = {.current_object = ""};
	DMOBJ *obj = NULL;
	LIST_HEAD(local_mem);

	char in_obj[1024] = {0};
	replace_str(obj_path, ".{i}.", ".", in_obj, sizeof(in_obj));
	if (strlen(in_obj) == 0)
		return NULL;

	dm_check_dynamic_obj(&local_mem, &node, entryobj, in_obj, &obj);

	dm_dynamic_cleanmem(&local_mem);

	return obj;
}

void disable_entry_obj(DMOBJ *entryobj, const char *obj_path, const char *parent_obj, const char *plugin_path)
{
	if (!entryobj || !plugin_path || DM_STRLEN(obj_path) == 0)
		return;

	char obj_name[256] = {0};
	replace_str(obj_path, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX, obj_name, sizeof(obj_name));
	if (strlen(obj_name) == 0)
		return;

	DMOBJ *nextobj = entryobj->nextobj;

	for (; (nextobj && nextobj->obj); nextobj++) {

		if (DM_STRCMP(nextobj->obj, obj_name) == 0) {
			BBF_INFO("## Excluding [%s%s.] from the core tree and the same object will be exposed again using (%s) ##", parent_obj, obj_name, plugin_path);
			nextobj->bbfdm_type = BBFDM_NONE;
			return;
		}
	}
}

void disable_entry_leaf(DMOBJ *entryobj, const char *leaf_path, const char *parent_obj, const char *plugin_path)
{
	if (!entryobj || !plugin_path || DM_STRLEN(leaf_path) == 0)
		return;

	char leaf_name[256] = {0};
	replace_str(leaf_path, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX, leaf_name, sizeof(leaf_name));
	if (strlen(leaf_name) == 0)
		return;

	DMLEAF *leaf = entryobj->leaf;

	for (; (leaf && leaf->parameter); leaf++) {

		if (DM_STRCMP(leaf->parameter, leaf_name) == 0) {
			BBF_INFO("## Excluding [%s%s] from the core tree and the same parameter will be exposed again using (%s) ##", parent_obj, leaf_name, plugin_path);
			leaf->bbfdm_type = BBFDM_NONE;
			return;
		}
	}
}

int get_entry_obj_idx(DMOBJ *entryobj)
{
	int idx = 0;

	for (; (entryobj && entryobj->obj); entryobj++)
		idx++;

	return idx;
}

int get_entry_leaf_idx(DMLEAF *entryleaf)
{
	int idx = 0;

	for (; (entryleaf && entryleaf->parameter); entryleaf++)
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

static int filter(const struct dirent *entry)
{
	return entry->d_name[0] != '.';
}

static int compare(const struct dirent **a, const struct dirent **b)
{
	return strcasecmp((*a)->d_name, (*b)->d_name);
}

void load_plugins(DMOBJ *dm_entryobj, const char *plugin_path)
{
	struct dirent **namelist;

	if (DM_STRLEN(plugin_path) == 0) // If empty, return without further action
		return;

	if (!folder_exists(plugin_path)) {
		BBF_ERR("Folder plugin (%s) doesn't exist", plugin_path);
		return;
	}

	int num_files = scandir(plugin_path, &namelist, filter, compare);

	for (int i = 0; i < num_files; i++) {
		char file_path[512] = {0};

		snprintf(file_path, sizeof(file_path), "%s/%s", plugin_path, namelist[i]->d_name);

		if (DM_LSTRSTR(namelist[i]->d_name, ".json")) {
			load_json_plugins(dm_entryobj, file_path);
		} else if (DM_LSTRSTR(namelist[i]->d_name, ".so")) {
			load_dotso_plugins(dm_entryobj, file_path);
		}

		FREE(namelist[i]);
	}

	FREE(namelist);
}

void free_plugins(DMOBJ *dm_entryobj)
{
	free_all_dynamic_nodes(dm_entryobj);

	free_json_plugins();
	free_dotso_plugins();
}
