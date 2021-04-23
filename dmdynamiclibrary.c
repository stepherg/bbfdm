/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmdynamiclibrary.h"
#include "dmoperate.h"

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
	struct loaded_library *lib;
	while (library_list->next != library_list) {
		lib = list_entry(library_list->next, struct loaded_library, list);
		list_del(&lib->list);
		if (lib->library) {
			dlclose(lib->library);
		}
		FREE(lib);
	}
}

static void dm_browse_node_dynamic_object_tree(DMNODE *parent_node, DMOBJ *entryobj)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + INDX_LIBRARY_MOUNT;
			FREE(next_dyn_array->nextobj);
		}

		if (entryobj->dynamicleaf) {
			struct dm_dynamic_leaf *next_dyn_array = entryobj->dynamicleaf + INDX_LIBRARY_MOUNT;
			FREE(next_dyn_array->nextleaf);
		}

		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		if (entryobj->nextobj)
			dm_browse_node_dynamic_object_tree(&node, entryobj->nextobj);
	}
}

void free_library_dynamic_arrays(DMOBJ *dm_entryobj)
{
	DMOBJ *root = dm_entryobj;
	DMNODE node = {.current_object = ""};

	free_all_list_open_library(&loaded_library_list);
	dm_browse_node_dynamic_object_tree(&node, root);
	FREE(dynamic_operate);
}

int load_library_dynamic_arrays(struct dmctx *ctx)
{
	struct dirent *ent = NULL;
	DIR *dir = NULL;

	if (folder_exists(LIBRARY_FOLDER_PATH)) {
		sysfs_foreach_file(LIBRARY_FOLDER_PATH, dir, ent) {

			if (!strstr(ent->d_name, ".so"))
				continue;

			char buf[512] = {0};
			snprintf(buf, sizeof(buf), "%s/%s", LIBRARY_FOLDER_PATH, ent->d_name);

			void *handle = dlopen(buf, RTLD_LAZY);
			if (!handle) continue;

			//Dynamic Object
			DM_MAP_OBJ *dynamic_obj = NULL;
			*(void **) (&dynamic_obj) = dlsym(handle, "tDynamicObj");
			if (dynamic_obj) {

				for (int i = 0; dynamic_obj[i].path; i++) {

					DMOBJ *dm_entryobj = NULL;
					bool obj_exists = find_root_entry(ctx, dynamic_obj[i].path, &dm_entryobj);
					if (obj_exists == false || !dm_entryobj)
						continue;

					if (dynamic_obj[i].root_obj) {

						if (dm_entryobj->nextdynamicobj == NULL) {
							dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
							dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
							dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
						}

						if (dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj == NULL) {
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj = calloc(2, sizeof(DMOBJ *));
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj[0] = dynamic_obj[i].root_obj;
						} else {
							int idx = get_obj_idx_dynamic_array(dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].nextobj);
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
							dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
						}

						if (dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf == NULL) {
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf = calloc(2, sizeof(DMLEAF *));
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[0] = dynamic_obj[i].root_leaf;
						} else {
							int idx = get_leaf_idx_dynamic_array(dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf);
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf = realloc(dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf, (idx + 2) * sizeof(DMLEAF *));
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[idx] = dynamic_obj[i].root_leaf;
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[idx+1] = NULL;
						}

					}
				}
			}

			//Dynamic Operate
			DM_MAP_OPERATE *dynamic_operate = NULL;
			*(void **) (&dynamic_operate) = dlsym(handle, "tDynamicOperate");
			if (dynamic_operate) {

				for (int i = 0; dynamic_operate[i].path; i++) {
					if (dynamic_operate[i].operate && dynamic_operate[i].type)
						add_dynamic_operate(dynamic_operate[i].path,
								dynamic_operate[i].operate,
								dynamic_operate[i].type,
								dynamic_operate[i].args);
				}
			}

			add_list_loaded_libraries(&loaded_library_list, handle);

		}
		if (dir) closedir(dir);
	}
	return 0;
}
