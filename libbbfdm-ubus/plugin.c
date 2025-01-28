/*
 * plugin.c: Plugin file bbfdmd
 *
 * Copyright (C) 2023-2025 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "common.h"
#include "get_helper.h"

#include "libbbfdm-api/legacy/plugin/json_plugin.h"

extern struct list_head loaded_json_files;
extern struct list_head json_list;
extern struct list_head json_memhead;

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

int bbfdm_load_internal_plugin(struct bbfdm_context *bbfdm_ctx, DM_MAP_OBJ *dynamic_obj, DMOBJ **main_entry)
{
	if (!dynamic_obj || !main_entry) {
		BBF_ERR("Input validation failed");
		return -1;
	}

	uint8_t obj_num = find_number_of_objects(dynamic_obj);
	if (obj_num == 0) {
		BBF_ERR("No Object defined in the required DotSo Plugin\n");
		return -1;
	}

	dm_dynamic_initmem(&plugin_mem);

	DMOBJ *dm_entryobj = (DMOBJ *)dm_dynamic_calloc(&plugin_mem, obj_num + 1, sizeof(DMOBJ));
	if (dm_entryobj == NULL) {
		BBF_ERR("No Memory exists\n");
		return -1;
	}

	for (int i = 0; dynamic_obj[i].path; i++) {
		char *node_obj = dm_dynamic_strdup(&plugin_mem, dynamic_obj[i].path);
		unsigned int len = strlen(node_obj);

		if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[len-1] != '.') {
			BBF_ERR("Object (%s) not valid\n", node_obj);
			return -1;
		}

		if (dynamic_obj[i].root_obj != NULL) {
			struct dm_obj_s *entryobj = dynamic_obj[i].root_obj;
			for (; (entryobj && entryobj->obj); entryobj++) {
				char path[MAX_DM_PATH] = {0};
				snprintf(path, sizeof(path), "%s%s.", node_obj, entryobj->obj);
				add_path_list(path, &bbfdm_ctx->obj_list);
			}
		}

		node_obj[len-1] = 0;

		dm_entryobj[i].obj = node_obj;
		dm_entryobj[i].permission = &DMREAD;
		dm_entryobj[i].nextobj = dynamic_obj[i].root_obj;
		dm_entryobj[i].leaf = dynamic_obj[i].root_leaf;
		dm_entryobj[i].bbfdm_type = BBFDM_BOTH;

		if (dynamic_obj[i].init_module)
			dynamic_obj[i].init_module(bbfdm_ctx);
	}

	*main_entry = dm_entryobj;
	return 0;
}

int bbfdm_load_dotso_plugin(struct bbfdm_context *bbfdm_ctx, void **lib_handle, const char *file_path, DMOBJ **main_entry)
{
	if (!lib_handle || !file_path || !strlen(file_path) || !main_entry) {
		BBF_ERR("Input validation failed");
		return -1;
	}

	DM_MAP_OBJ *dynamic_obj = NULL;

	void *handle = dlopen(file_path, RTLD_NOW|RTLD_LOCAL);
	if (!handle) {
		BBF_ERR("Plugin failed [%s]\n", dlerror());
		return -1;
	}

	*lib_handle = handle;

	//Dynamic Object
	*(void **) (&dynamic_obj) = dlsym(handle, "tDynamicObj");

	return bbfdm_load_internal_plugin(bbfdm_ctx, dynamic_obj, main_entry);
}

int bbfdm_free_dotso_plugin(struct bbfdm_context *bbfdm_ctx, void **lib_handle)
{
	if (*lib_handle) {
		DM_MAP_OBJ *dynamic_obj = NULL;

		//Dynamic Object
		*(void **) (&dynamic_obj) = dlsym(*lib_handle, "tDynamicObj");

		if (dynamic_obj) {
			// Clean module
			for (int i = 0; dynamic_obj[i].path; i++) {
				if (dynamic_obj[i].clean_module)
					dynamic_obj[i].clean_module(bbfdm_ctx);
			}
		}

		dlclose(*lib_handle);
		*lib_handle = NULL;
	}

	dm_dynamic_cleanmem(&plugin_mem);
	return 0;
}

static int bbfdm_load_json_plugin(struct bbfdm_context *bbfdm_ctx, struct list_head *json_plugin, struct list_head *json_list,
		struct list_head *json_memhead, const char *file_path, DMOBJ **main_entry)
{
	DMOBJ *dm_entryobj = NULL;
	int json_plugin_version = JSON_VERSION_0;
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

		if (key == NULL)
			continue;

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

		char obj_prefix[512] = {0};
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

		char path[MAX_DM_PATH] = {0};
		snprintf(path, sizeof(path), "%s%s.", obj_prefix, obj_name);
		add_path_list(path, &bbfdm_ctx->obj_list);

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

	*main_entry = dm_entryobj;
	return 0;
}

int bbfdm_free_json_plugin(void)
{
	return free_json_plugins();
}

int bbfdm_load_external_plugin(struct bbfdm_context *bbfdm_ctx, void **lib_handle, DMOBJ **main_entry)
{
	char file_path[128] = {0};
	int err = -1;

	snprintf(file_path, sizeof(file_path), "%s", bbfdm_ctx->config.in_name);

	if (DM_STRLEN(file_path) == 0) {
		BBF_ERR("Input type/name not supported or defined");
		return -1;
	}

	char *ext = strrchr(file_path, '.');
	if (ext == NULL) {
		BBF_ERR("Input file without extension");
	} else if (strcasecmp(ext, ".json") == 0) {
		BBF_INFO("Loading JSON plugin %s", file_path);
		err = bbfdm_load_json_plugin(bbfdm_ctx, &loaded_json_files, &json_list, &json_memhead, file_path, main_entry);
	} else if (strcasecmp(ext, ".so") == 0) {
		BBF_INFO("Loading DotSo plugin %s", file_path);
		err = bbfdm_load_dotso_plugin(bbfdm_ctx, lib_handle, file_path, main_entry);
	} else {
		BBF_ERR("Input type %s not supported", ext);
	}

	return err;
}
