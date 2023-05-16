/*
 * plugin.c: Plugin file bbfdmd
 *
 * Copyright (C) 2023 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "common.h"
#include "libbbfdm-api/dmapi.h"
#include "libbbfdm-api/plugin/json_plugin.h"

extern struct list_head global_memhead;

int load_dotso_plugin(void **lib_handle, const char *file_path,
		DMOBJ **main_entry,
		DM_MAP_VENDOR *main_Extension[],
		DM_MAP_VENDOR_EXCLUDE **main_Extension_exclude)
{
	if (!lib_handle || !file_path || !strlen(file_path) || !main_entry || !main_Extension || !main_Extension_exclude)
		return -1;

	void *handle = dlopen(file_path, RTLD_NOW|RTLD_LOCAL);
	if (!handle) {
		fprintf(stderr, "ERROR: Plugin failed [%s]\n", dlerror());
		return -1;
	}

	*lib_handle = handle;

	//Dynamic Object
	DM_MAP_OBJ *dynamic_obj = NULL;
	*(void **) (&dynamic_obj) = dlsym(handle, "tDynamicObj");
	if (dynamic_obj) {
		char *node_obj = dm_dynamic_strdup(&global_memhead, dynamic_obj[0].path);
		unsigned int len = strlen(node_obj);

		if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[len-1] != '.') {
			fprintf(stderr, "ERROR: Object (%s) not valid\n", node_obj);
			return -1;
		}

		DMOBJ *dm_entryobj = (DMOBJ *)dm_dynamic_calloc(&global_memhead, 2, sizeof(DMOBJ));
		if (dm_entryobj == NULL) {
			fprintf(stderr, "ERROR: No Memory exists\n");
			return -1;
		}

		node_obj[len-1] = 0;

		dm_entryobj[0].obj = node_obj;
		dm_entryobj[0].permission = &DMREAD;
		dm_entryobj[0].nextobj = dynamic_obj[0].root_obj;
		dm_entryobj[0].leaf = dynamic_obj[0].root_leaf;
		dm_entryobj[0].bbfdm_type = BBFDM_BOTH;

		*main_entry = dm_entryobj;
	} else {
		fprintf(stderr, "ERROR: Main entry not available");
		return -1;
	}

	//Vendor Extension
	DM_MAP_VENDOR *vendor_extension = NULL;
	*(void **) (&vendor_extension) = dlsym(handle, "tVendorExtension");
	if (vendor_extension) main_Extension[0] = vendor_extension;

	//Vendor Extension Overwrite
	DM_MAP_VENDOR *vendor_extension_overwrite = NULL;
	*(void **) (&vendor_extension_overwrite) = dlsym(handle, "tVendorExtensionOverwrite");
	if (vendor_extension_overwrite) main_Extension[1] = vendor_extension_overwrite;

	//Vendor Extension Exclude
	DM_MAP_VENDOR_EXCLUDE *vendor_extension_exclude = NULL;
	*(void **) (&vendor_extension_exclude) = dlsym(handle, "tVendorExtensionExclude");
	if (vendor_extension_exclude) *main_Extension_exclude = vendor_extension_exclude;

	return 0;
}

int free_dotso_plugin(void *lib_handle)
{
	if (lib_handle) {
		dlclose(lib_handle);
		lib_handle = NULL;
	}

	return 0;
}

int load_json_plugin(struct list_head *json_plugin, struct list_head *json_list, struct list_head *json_memhead, const char *file_path,
		DMOBJ **main_entry)
{
	int json_plugin_version = 0;

	if (!file_path || !strlen(file_path) || !main_entry)
		return -1;

	json_object *json_obj = json_object_from_file(file_path);
	if (!json_obj)
		return -1;

	save_loaded_json_files(json_plugin, json_obj);

	json_object_object_foreach(json_obj, key, jobj) {

		if (strcmp(key, "json_plugin_version") == 0) {
			json_plugin_version = json_object_get_int(jobj);
			continue;
		}

		char *node_obj = replace_str(key, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX);
		unsigned int len = strlen(node_obj);

		if (strncmp(node_obj, ROOT_NODE, strlen(ROOT_NODE)) != 0 || node_obj[len-1] != '.') {
			fprintf(stderr, "ERROR: Object (%s) not valid\n", node_obj);
			return -1;
		}

		char obj_prefix[512] = {0};
		find_prefix_obj(node_obj, obj_prefix, sizeof(obj_prefix));
		obj_prefix[strlen(obj_prefix)-1] = 0;

		DMOBJ *dm_entryobj = (DMOBJ *)dm_dynamic_calloc(json_memhead, 2, sizeof(DMOBJ));
		if (dm_entryobj == NULL) {
			fprintf(stderr, "ERROR: No Memory exists\n");
			return -1;
		}

		*main_entry = dm_entryobj;

		dm_entryobj[0].obj = dm_dynamic_strdup(json_memhead, obj_prefix);
		dm_entryobj[0].permission = &DMREAD;
		dm_entryobj[0].nextobj = (DMOBJ *)dm_dynamic_calloc(json_memhead, 2, sizeof(DMOBJ));
		dm_entryobj[0].leaf = NULL;
		dm_entryobj[0].bbfdm_type = BBFDM_BOTH;

		parse_obj(node_obj, jobj, dm_entryobj[0].nextobj, 0, json_plugin_version, json_list);
		FREE(node_obj);
		break;
	}

	return 0;
}

int free_json_plugin(void)
{
	return free_json_plugins();
}
