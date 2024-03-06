/*
 * plugin.c: Plugin file bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "common.h"

#include "plugin/json_plugin.h"

extern struct list_head global_memhead;

static uint8_t find_number_of_objects(DM_MAP_OBJ *dynamic_obj)
{
	if (!dynamic_obj)
		return 0;

	uint8_t len = 0;

	while (dynamic_obj[len].path)
		len++;

	return len;
}


int load_dotso_plugin(void **lib_handle, const char *file_path, DMOBJ **main_entry)
{
	if (!lib_handle || !file_path || !strlen(file_path) || !main_entry)
		return -1;

	void *handle = dlopen(file_path, RTLD_NOW|RTLD_LOCAL);
	if (!handle) {
		ERR("Plugin failed [%s]\n", dlerror());
		return -1;
	}

	*lib_handle = handle;

	//Dynamic Object
	DM_MAP_OBJ *dynamic_obj = NULL;
	*(void **) (&dynamic_obj) = dlsym(handle, "tDynamicObj");
	if (dynamic_obj) {
		uint8_t obj_num = find_number_of_objects(dynamic_obj);
		if (obj_num == 0) {
			ERR("No Object defined in the required DotSo Plugin\n");
			return -1;
		}

		DMOBJ *dm_entryobj = (DMOBJ *)dm_dynamic_calloc(&global_memhead, obj_num + 1, sizeof(DMOBJ));
		if (dm_entryobj == NULL) {
			ERR("No Memory exists\n");
			return -1;
		}

		for (int i = 0; dynamic_obj[i].path; i++) {
			char *node_obj = dm_dynamic_strdup(&global_memhead, dynamic_obj[i].path);
			unsigned int len = strlen(node_obj);

			if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[len-1] != '.') {
				ERR("Object (%s) not valid\n", node_obj);
				return -1;
			}

			node_obj[len-1] = 0;

			dm_entryobj[i].obj = node_obj;
			dm_entryobj[i].permission = &DMREAD;
			dm_entryobj[i].nextobj = dynamic_obj[i].root_obj;
			dm_entryobj[i].leaf = dynamic_obj[i].root_leaf;
			dm_entryobj[i].bbfdm_type = BBFDM_BOTH;
		}

		*main_entry = dm_entryobj;
	} else {
		ERR("Main entry not available");
		return -1;
	}

	return 0;
}

int free_dotso_plugin(void *lib_handle)
{
	if (lib_handle)
		dlclose(lib_handle);

	return 0;
}

int load_json_plugin(struct list_head *json_plugin, struct list_head *json_list, struct list_head *json_memhead, const char *file_path, DMOBJ **main_entry)
{
	DMOBJ *dm_entryobj = NULL;
	int json_plugin_version = JSON_VERSION_0;
	uint8_t idx = 0;

	if (!file_path || !strlen(file_path) || !main_entry)
		return -1;

	json_object *json_obj = json_object_from_file(file_path);
	if (!json_obj)
		return -1;

	save_loaded_json_files(json_plugin, json_obj);

	json_object_object_foreach(json_obj, key, jobj) {
		char node_obj[1024] = {0};

		if (strcmp(key, "json_plugin_version") == 0) {
			json_plugin_version = get_json_plugin_version(jobj);
			continue;
		}

		replace_str(key, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX, node_obj, sizeof(node_obj));
		if (strlen(node_obj) == 0) {
			ERR("ERROR: Can't get the node object\n");
			return -1;
		}

		if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[strlen(node_obj) - 1] != '.') {
			ERR("ERROR: Object (%s) not valid\n", node_obj);
			return -1;
		}

		char obj_prefix[1024] = {0};
		json_plugin_find_prefix_obj(node_obj, obj_prefix, sizeof(obj_prefix));

		int obj_prefix_len = strlen(obj_prefix);
		if (obj_prefix_len == 0) {
			ERR("ERROR: Obj prefix is empty for (%s) Object\n", node_obj);
			return -1;
		}

		// Remove '.' from object prefix
		if (obj_prefix[obj_prefix_len - 1] == '.')
			obj_prefix[obj_prefix_len - 1] = 0;

		dm_entryobj = (DMOBJ *)dm_dynamic_realloc(json_memhead, dm_entryobj, (idx + 2) * sizeof(DMOBJ));
		if (dm_entryobj == NULL) {
			ERR("ERROR: No Memory exists\n");
			return -1;
		}

		memset(&dm_entryobj[idx + 1], 0, sizeof(DMOBJ));

		dm_entryobj[idx].obj = dm_dynamic_strdup(json_memhead, obj_prefix);
		dm_entryobj[idx].permission = &DMREAD;
		dm_entryobj[idx].nextobj = (DMOBJ *)dm_dynamic_calloc(json_memhead, 2, sizeof(DMOBJ));
		dm_entryobj[idx].leaf = NULL;
		dm_entryobj[idx].bbfdm_type = BBFDM_BOTH;

		parse_obj(node_obj, jobj, dm_entryobj[idx].nextobj, 0, json_plugin_version, json_list);

		idx++;
	}

	*main_entry = dm_entryobj;
	return 0;
}

int free_json_plugin(void)
{
	return free_json_plugins();
}
