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

LIST_HEAD(loaded_library_list);
LIST_HEAD(dynamic_operate_list);
LIST_HEAD(library_memhead);

struct loaded_library
{
	struct list_head list;
	void *library;
};

struct dynamic_operate
{
	struct list_head list;
	char *operate_path;
	void *operate;
	void *operate_args;
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

static void add_list_dynamic_operates(struct list_head *operate_list, char *operate_path, void *operate, void *operate_args)
{
	struct dynamic_operate *dyn_operate = calloc(1, sizeof(struct dynamic_operate));
	list_add_tail(&dyn_operate->list, operate_list);
	dyn_operate->operate_path = strdup(operate_path);
	dyn_operate->operate = operate;
	dyn_operate->operate_args = operate_args;
}

static void free_list_dynamic_operates(struct list_head *operate_list)
{
	struct dynamic_operate *dyn_operate;
	while (operate_list->next != operate_list) {
		dyn_operate = list_entry(operate_list->next, struct dynamic_operate, list);
		list_del(&dyn_operate->list);
		if (dyn_operate->operate_path) {
			free(dyn_operate->operate_path);
		}
		FREE(dyn_operate);
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
	free_list_dynamic_operates(&dynamic_operate_list);
	dm_dynamic_cleanmem(&library_memhead);
	dm_browse_node_dynamic_object_tree(&node, root);
}

static bool operate_find_root_entry(struct dmctx *ctx, char *in_param, DMOBJ **root_entry)
{
	int obj_found = 0;
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};

	dm_check_dynamic_obj(ctx, &node, root, in_param, in_param, root_entry, &obj_found);

	return (obj_found && *root_entry) ? true : false;
}


static char *get_path_without_instance(char *path)
{
	char *pch = NULL, *pchr = NULL;
	char res_path[512] = {0};
	unsigned pos = 0;

	char *str = dm_dynamic_strdup(&library_memhead, path);

	res_path[0] = 0;
	for (pch = strtok_r(str, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (atoi(pch) == 0 && strcmp(pch, "{i}") != 0)
			pos += snprintf(&res_path[pos], sizeof(res_path) - pos, "%s%s", pch, (pchr != NULL && *pchr != '\0') ? "." : "");
	}

	dmfree(str);

	return dm_dynamic_strdup(&library_memhead, res_path);
}

static int get_dynamic_operate_args(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dynamic_operate *dyn_operate = NULL;
	operation_args *operate_args = NULL;

	char *operate_path = get_path_without_instance(refparam);
	list_for_each_entry(dyn_operate, &dynamic_operate_list, list) {
		if (strcmp(dyn_operate->operate_path, operate_path) == 0) {
			operate_args = (operation_args *)dyn_operate->operate_args;
			break;
		}
	}

	*value = (char *)operate_args;
	return 0;
}

static int dynamic_operate_leaf(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dynamic_operate *dyn_operate = NULL;
	operation operate_func = NULL;

	char *operate_path = get_path_without_instance(refparam);
	list_for_each_entry(dyn_operate, &dynamic_operate_list, list) {
		if (strcmp(dyn_operate->operate_path, operate_path) == 0) {
			operate_func = (operation)dyn_operate->operate;
			break;
		}
	}

	return operate_func ? operate_func(ctx, refparam, (json_object *)value) : CMD_FAIL;
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

			void *handle = dlopen(buf, RTLD_NOW|RTLD_LOCAL);
			if (!handle) {
				fprintf(stderr, "Plugin failed [%s]", dlerror());
				continue;
			}


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

			//Dynamic Operate is deprecated now.  It will be removed later.
			struct dm_map_operate *dynamic_operate = NULL;
			*(void **) (&dynamic_operate) = dlsym(handle, "tDynamicOperate");
			if (dynamic_operate) {

				for (int i = 0; dynamic_operate[i].path; i++) {
					if (dynamic_operate[i].operate && dynamic_operate[i].type) {
						char parent_path[256] = {'\0'};
						char operate_path[256] = {'\0'};
						DMOBJ *dm_entryobj = NULL;

						char *object_path = replace_str(dynamic_operate[i].path, ".*.", ".");
						snprintf(operate_path, sizeof(operate_path), "%s%s", object_path, !strstr(object_path, "()") ? "()" : "");
						dmfree(object_path);

						char *ret = strrchr(operate_path, '.');
						strncpy(parent_path, operate_path, ret - operate_path +1);

						bool obj_exists = operate_find_root_entry(ctx, parent_path, &dm_entryobj);
						if (obj_exists == false || !dm_entryobj)
							continue;

						add_list_dynamic_operates(&dynamic_operate_list, operate_path, dynamic_operate[i].operate, &dynamic_operate[i].args);

						if (dm_entryobj->dynamicleaf == NULL) {
							dm_entryobj->dynamicleaf = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_leaf));
							dm_entryobj->dynamicleaf[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
							dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
						}

						operation_args *args = &dynamic_operate[i].args;
						DMLEAF *new_leaf = dm_dynamic_calloc(&library_memhead, 2, sizeof(struct dm_leaf_s));
						new_leaf[0].parameter = dm_dynamic_strdup(&library_memhead, ret+1);
						new_leaf[0].permission = !strcmp(dynamic_operate[i].type, "sync") ? &DMSYNC : &DMASYNC;
						new_leaf[0].type = DMT_COMMAND;
						new_leaf[0].getvalue = (args->in || args->out) ? get_dynamic_operate_args : NULL;
						new_leaf[0].setvalue = dynamic_operate_leaf;
						new_leaf[0].bbfdm_type = BBFDM_USP;

						if (dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf == NULL) {
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf = calloc(2, sizeof(DMLEAF *));
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[0] = new_leaf;
						} else {
							int idx = get_leaf_idx_dynamic_array(dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf);
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf = realloc(dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf, (idx + 2) * sizeof(DMLEAF *));
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[idx] = new_leaf;
							dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].nextleaf[idx+1] = NULL;
						}

					}

				}
			}

			add_list_loaded_libraries(&loaded_library_list, handle);

		}
		if (dir) closedir(dir);
	}
	return 0;
}
