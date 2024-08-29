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

static LIST_HEAD(plugin_mem);

static uint8_t find_number_of_objects(DM_MAP_OBJ *dynamic_obj)
{
	if (!dynamic_obj)
		return 0;

	uint8_t len = 0;

	while (dynamic_obj[len].path)
		len++;

	return len;
}

static void fill_dotso_micro_service_out_args(bbfdm_config_t *config, DMOBJ *entryobj, char *parent_dm, int *idx)
{
	char ms_name[128] = {0};

	if (!config || !entryobj || !parent_dm || !idx || *idx >= MAX_OBJS)
		return;

	strncpyt(config->out_parent_dm, parent_dm, sizeof(config->out_parent_dm));

	for (; (entryobj && entryobj->obj); entryobj++) {

		if (*idx >= MAX_OBJS)
			break;

		strncpyt(config->out_objects[(*idx)++], entryobj->obj, sizeof(config->out_objects[0]));

		int len = DM_STRLEN(ms_name);
		if (len == 0) {
			snprintf(ms_name, sizeof(ms_name), "%s.%s", config->out_root_obj, entryobj->obj);
		} else {
			snprintf(ms_name + len, sizeof(ms_name) - len, "_%s", entryobj->obj);
		}
	}

	if (DM_STRLEN(config->out_name) == 0)
		strncpyt(config->out_name, ms_name, sizeof(config->out_name));
}

int load_dotso_plugin(void **lib_handle, const char *file_path, bbfdm_config_t *config, DMOBJ **main_entry)
{
	if (!lib_handle || !file_path || !strlen(file_path) || !main_entry) {
		BBF_ERR("Input validation failed\n");
		return -1;
	}

	dm_dynamic_initmem(&plugin_mem);
	DM_MAP_OBJ *dynamic_obj = NULL;

	if (strcmp(file_path, "internal_dm.so") == 0) {
		dynamic_obj = INTERNAL_ROOT_TREE;
	} else {
		void *handle = dlopen(file_path, RTLD_NOW|RTLD_LOCAL);
		if (!handle) {
			BBF_ERR("Plugin failed [%s]\n", dlerror());
			return -1;
		}

		*lib_handle = handle;

		//Dynamic Object
		*(void **) (&dynamic_obj) = dlsym(handle, "tDynamicObj");
	}

	if (dynamic_obj) {
		uint8_t obj_num = find_number_of_objects(dynamic_obj);
		if (obj_num == 0) {
			BBF_ERR("No Object defined in the required DotSo Plugin\n");
			return -1;
		}

		DMOBJ *dm_entryobj = (DMOBJ *)dm_dynamic_calloc(&plugin_mem, obj_num + 1, sizeof(DMOBJ));
		if (dm_entryobj == NULL) {
			BBF_ERR("No Memory exists\n");
			return -1;
		}

		int out_obj_idx = 0;

		for (int i = 0; dynamic_obj[i].path; i++) {
			char *node_obj = dm_dynamic_strdup(&plugin_mem, dynamic_obj[i].path);
			unsigned int len = strlen(node_obj);

			if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[len-1] != '.') {
				BBF_ERR("Object (%s) not valid\n", node_obj);
				return -1;
			}

			// Fill out arguments if it is running as micro-service
			if (dm_is_micro_service() == true)
				fill_dotso_micro_service_out_args(config, dynamic_obj[i].root_obj, node_obj, &out_obj_idx);

			node_obj[len-1] = 0;

			dm_entryobj[i].obj = node_obj;
			dm_entryobj[i].permission = &DMREAD;
			dm_entryobj[i].nextobj = dynamic_obj[i].root_obj;
			dm_entryobj[i].leaf = dynamic_obj[i].root_leaf;
			dm_entryobj[i].bbfdm_type = BBFDM_BOTH;
		}

		*main_entry = dm_entryobj;
	} else {
		BBF_ERR("Main entry not available");
		return -1;
	}

	return 0;
}

int free_dotso_plugin(void *lib_handle)
{
	if (lib_handle)
		dlclose(lib_handle);

	dm_dynamic_cleanmem(&plugin_mem);
	return 0;
}

static void fill_json_micro_service_out_args(bbfdm_config_t *config, char *parent_dm, char *obj, int idx, char *ms_name, size_t ms_name_len)
{
	if (!config || !obj || idx >= MAX_OBJS)
		return;

	strncpyt(config->out_parent_dm, parent_dm, sizeof(config->out_parent_dm));
	strncpyt(config->out_objects[idx], obj, sizeof(config->out_objects[idx]));

	int len = DM_STRLEN(ms_name);
	if (len == 0) {
		snprintf(ms_name, ms_name_len, "%s.%s", config->out_root_obj, obj);
	} else {
		snprintf(ms_name + len, ms_name_len - len, "_%s", obj);
	}
}

int load_json_plugin(struct list_head *json_plugin, struct list_head *json_list, struct list_head *json_memhead,
		const char *file_path, bbfdm_config_t *config, DMOBJ **main_entry)
{
	DMOBJ *dm_entryobj = NULL;
	int json_plugin_version = JSON_VERSION_0;
	char ms_name[128] = {0};
	uint8_t idx = 0;

	if (!file_path || !strlen(file_path) || !main_entry) {
		BBF_ERR("Entry validation failed ...");
		return -1;
	}

	json_object *json_obj = json_object_from_file(file_path);
	if (!json_obj) {
		BBF_ERR("Failed to parse json file (%s)", file_path);
		return -1;
	}

	save_loaded_json_files(json_plugin, json_obj);

	json_object_object_foreach(json_obj, key, jobj) {
		char node_obj[1024] = {0};

		if (strcmp(key, "json_plugin_version") == 0) {
			json_plugin_version = get_json_plugin_version(jobj);
			continue;
		}

		replace_str(key, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX, node_obj, sizeof(node_obj));
		if (strlen(node_obj) == 0) {
			BBF_ERR("ERROR: Can't get the node object\n");
			return -1;
		}

		if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[strlen(node_obj) - 1] != '.') {
			BBF_ERR("ERROR: Object (%s) not valid\n", node_obj);
			return -1;
		}

		char obj_prefix[1024] = {0};
		json_plugin_find_prefix_obj(node_obj, obj_prefix, sizeof(obj_prefix));

		int obj_prefix_len = strlen(obj_prefix);
		if (obj_prefix_len == 0) {
			BBF_ERR("ERROR: Obj prefix is empty for (%s) Object\n", node_obj);
			return -1;
		}

		char obj_name[64] = {0};
		json_plugin_find_current_obj(node_obj, obj_name, sizeof(obj_name));
		if (strlen(obj_name) == 0) {
			BBF_ERR("ERROR: Obj name is empty for (%s) Object\n", node_obj);
			return -1;
		}

		// Fill out arguments if it is running as micro-service
		if (dm_is_micro_service() == true)
			fill_json_micro_service_out_args(config, obj_prefix, obj_name, idx, ms_name, sizeof(ms_name));

		// Remove '.' from object prefix
		if (obj_prefix[obj_prefix_len - 1] == '.')
			obj_prefix[obj_prefix_len - 1] = 0;

		dm_entryobj = (DMOBJ *)dm_dynamic_realloc(json_memhead, dm_entryobj, (idx + 2) * sizeof(DMOBJ));
		if (dm_entryobj == NULL) {
			BBF_ERR("ERROR: No Memory exists\n");
			return -1;
		}

		if (idx == 0) {
			memset(&dm_entryobj[idx], 0, sizeof(DMOBJ));
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

	if (DM_STRLEN(config->out_name) == 0)
		strncpyt(config->out_name, ms_name, sizeof(config->out_name));

	*main_entry = dm_entryobj;
	return 0;
}

int free_json_plugin(void)
{
	return free_json_plugins();
}
