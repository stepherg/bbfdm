/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "dotso_plugin.h"
#include "../dmplugin.h"

LIST_HEAD(loaded_library_list);

struct loaded_library
{
	struct list_head list;
	void *library;
};

static void add_list_loaded_libraries(struct list_head *library_list, void *library)
{
	struct loaded_library *lib = calloc(1, sizeof(struct loaded_library));

	list_add_tail(&lib->list, library_list);
	lib->library = library;
}

static void free_all_list_open_library(struct list_head *library_list)
{
	struct loaded_library *lib = NULL;

	while (library_list->next != library_list) {
		lib = list_entry(library_list->next, struct loaded_library, list);
		list_del(&lib->list);
		if (lib->library) {
			dlclose(lib->library);
		}
		FREE(lib);
	}
}

static void dotso_plugin_disable_requested_entries(DMOBJ *entryobj, DMOBJ *requested_obj, DMLEAF *requested_leaf, const char *parent_obj, const char *plugin_path)
{
	if (!entryobj)
		return;

	for (; (requested_obj && requested_obj->obj); requested_obj++)
		disable_entry_obj(entryobj, requested_obj->obj, parent_obj, plugin_path);

	for (; (requested_leaf && requested_leaf->parameter); requested_leaf++)
		disable_entry_leaf(entryobj, requested_leaf->parameter, parent_obj, plugin_path);
}

int load_dotso_plugins(DMOBJ *entryobj, const char *plugin_path)
{
#ifndef BBF_SCHEMA_FULL_TREE
	void *handle = dlopen(plugin_path, RTLD_NOW|RTLD_LOCAL);
#else
	void *handle = dlopen(plugin_path, RTLD_LAZY);
#endif
	if (!handle) {
		BBF_ERR("Plugin failed [%s]\n", dlerror());
		return 0;
	}

	//Load Dynamic Object handler
	DM_MAP_OBJ *dynamic_obj = NULL;
	*(void **) (&dynamic_obj) = dlsym(handle, "tDynamicObj");

	if (dynamic_obj == NULL) {
		dlclose(handle);
		BBF_ERR("Plugin %s missing init symbol ...", plugin_path);
		return 0;
	}

	for (int i = 0; dynamic_obj[i].path; i++) {

		DMOBJ *dm_entryobj = find_entry_obj(entryobj, dynamic_obj[i].path);
		if (!dm_entryobj)
			continue;

		dotso_plugin_disable_requested_entries(dm_entryobj, dynamic_obj[i].root_obj, dynamic_obj[i].root_leaf, dynamic_obj[i].path, plugin_path);

		if (dynamic_obj[i].root_obj) {

			if (dm_entryobj->nextdynamicobj == NULL) {
				dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
				dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
				dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
			}

			if (dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj == NULL) {
				dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj = calloc(2, sizeof(DMOBJ *));
				dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj[0] = dynamic_obj[i].root_obj;
			} else {
				int idx = get_obj_idx(dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj);
				dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj = realloc(dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj, (idx + 2) * sizeof(DMOBJ *));
				dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj[idx] = dynamic_obj[i].root_obj;
				dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj[idx+1] = NULL;
			}

		}

		if (dynamic_obj[i].root_leaf) {

			if (dm_entryobj->dynamicleaf == NULL) {
				dm_entryobj->dynamicleaf = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_leaf));
				dm_entryobj->dynamicleaf[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
				dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
			}

			if (dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf == NULL) {
				dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf = calloc(2, sizeof(DMLEAF *));
				dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[0] = dynamic_obj[i].root_leaf;
			} else {
				int idx = get_leaf_idx(dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf);
				dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf = realloc(dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf, (idx + 2) * sizeof(DMLEAF *));
				dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[idx] = dynamic_obj[i].root_leaf;
				dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[idx+1] = NULL;
			}

		}
	}
	add_list_loaded_libraries(&loaded_library_list, handle);

	return 0;
}

int free_dotso_plugins(void)
{
	free_all_list_open_library(&loaded_library_list);
	return 0;
}
