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

#include "plugin/json_plugin.h"
#include "plugin/dotso_plugin.h"

extern struct list_head global_memhead;

struct service
{
	struct list_head list;
	char *name;
	char *parent_dm;
	char *object;
};

static bool add_service_to_main_tree(DMOBJ *main_dm, char *srv_name, char *srv_parent_dm, char *srv_obj)
{
	DMOBJ *dm_entryobj = find_entry_obj(main_dm, srv_parent_dm);
	if (!dm_entryobj)
		return false;

	// Disable service object if it already exists in the main tree
	disable_entry_obj(dm_entryobj, srv_obj, srv_parent_dm, srv_name);

	if (dm_entryobj->nextdynamicobj == NULL) {
		dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
		dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
		dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
		dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].idx_type = INDX_SERVICE_MOUNT;
	}

	if (dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj == NULL) {
		dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj = calloc(2, sizeof(DMOBJ *));
	}

	if (dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] == NULL) {
		dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] = dm_dynamic_calloc(&global_memhead, 2, sizeof(struct dm_obj_s));
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[0]).obj = dm_dynamic_strdup(&global_memhead, srv_obj);
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[0]).checkdep = dm_dynamic_strdup(&global_memhead, srv_name);
	} else {
		int idx = get_entry_obj_idx(dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0]);
		dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] = dm_dynamic_realloc(&global_memhead, dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
		memset(dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[idx]).obj = dm_dynamic_strdup(&global_memhead, srv_obj);
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[idx]).checkdep = dm_dynamic_strdup(&global_memhead, srv_name);
	}

	return true;
}

static bool is_service_registered(struct list_head *srvlist, char *srv_name, char *srv_parent_dm, char *srv_obj)
{
	struct service *srv = NULL;

	list_for_each_entry(srv, srvlist, list) {
		if (DM_STRCMP(srv->name, srv_name) == 0 &&
			DM_STRCMP(srv->parent_dm, srv_parent_dm) == 0 &&
			DM_STRCMP(srv->object, srv_obj) == 0)
			return true;
	}

	return false;
}

static void add_service_to_list(struct list_head *srvlist, char *srv_name, char *srv_parent_dm, char *srv_object)
{
	struct service *srv = NULL;

	srv = calloc(1, sizeof(struct service));
	list_add_tail(&srv->list, srvlist);

	srv->name = strdup(srv_name);
	srv->parent_dm = strdup(srv_parent_dm);
	srv->object = strdup(srv_object);
}

void free_services_from_list(struct list_head *clist)
{
	struct service *srv = NULL;

	while (clist->next != clist) {
		srv = list_entry(clist->next, struct service, list);
		list_del(&srv->list);
		free(srv->name);
		free(srv->parent_dm);
		free(srv->object);
		free(srv);
	}
}

bool load_service(DMOBJ *main_dm, struct list_head *srv_list, char *srv_name, char *srv_parent_dm, char *srv_obj)
{
	if (!main_dm || !srv_list || !srv_name || !srv_parent_dm || !srv_obj) {
		BBF_ERR("Invalid arguments: main_dm, srv_list, srv_name, srv_parent_dm, and srv_obj must not be NULL.");
		return false;
	}

	if (is_service_registered(srv_list, srv_name, srv_parent_dm, srv_obj)) {
		BBF_DEBUG("Service registration failed: Service '%s' with parent DM '%s' and object '%s' is already registered.",
				srv_name, srv_parent_dm, srv_obj);
		return false;
	}

	if (!add_service_to_main_tree(main_dm, srv_name, srv_parent_dm, srv_obj)) {
		BBF_ERR("Failed to add service '%s' to main tree with parent DM '%s' and object '%s'.",
				srv_name, srv_parent_dm, srv_obj);
		return false;
	}

	add_service_to_list(srv_list, srv_name, srv_parent_dm, srv_obj);
	return true;
}

void get_list_of_registered_service(struct list_head *srvlist, struct blob_buf *bb)
{
	struct service *srv = NULL;
	void *table = NULL;

	list_for_each_entry(srv, srvlist, list) {
		table = blobmsg_open_table(bb, NULL);
		blobmsg_add_string(bb, "name", srv->name);
		blobmsg_add_string(bb, "parent_dm", srv->parent_dm);
		blobmsg_add_string(bb, "object", srv->object);
		blobmsg_close_table(bb, table);
	}
}

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

static void dm_check_dynamic_obj(struct list_head *mem_list, DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, DMOBJ **root_entry);
static void dm_check_dynamic_obj_entry(struct list_head *mem_list, DMNODE *parent_node, DMOBJ *entryobj, char *parent_obj, char *full_obj, DMOBJ **root_entry)
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

static void dm_check_dynamic_obj(struct list_head *mem_list, DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, DMOBJ **root_entry)
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

DMOBJ *find_entry_obj(DMOBJ *entryobj, char *obj_path)
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

void disable_entry_obj(DMOBJ *entryobj, char *obj_path, const char *parent_obj, const char *plugin_path)
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

void disable_entry_leaf(DMOBJ *entryobj, char *leaf_path, const char *parent_obj, const char *plugin_path)
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

void load_plugins(DMOBJ *dm_entryobj, const char *plugin_path)
{
	if (DM_STRLEN(plugin_path) == 0) // If empty, return without further action
		return;

	if (!folder_exists(plugin_path)) {
		BBF_ERR("(%s) doesn't exist", plugin_path);
		return;
	}

	struct dirent *ent = NULL;
	int num_files = 0;
	char *files[256];

	DIR *dir = opendir(plugin_path);
	if (dir == NULL) {
		BBF_ERR("Cannot open (%s) directory", plugin_path);
		return;
	}

	while ((ent = readdir(dir)) != NULL && num_files < 256) {
		files[num_files++] = strdup(ent->d_name);
	}

	closedir(dir);

	qsort(files, num_files, sizeof(char *), compare_strings);

	for (int i = 0; i < num_files; i++) {
		char buf[512] = {0};

		snprintf(buf, sizeof(buf), "%s/%s", plugin_path, files[i]);

		if (DM_LSTRSTR(files[i], ".json")) {
			load_json_plugins(dm_entryobj, buf);
		} else if (DM_LSTRSTR(files[i], ".so")) {
			load_dotso_plugins(dm_entryobj, buf);
		}

		free(files[i]);
	}
}

void free_plugins(DMOBJ *dm_entryobj)
{
	free_all_dynamic_nodes(dm_entryobj);

	free_json_plugins();
	free_dotso_plugins();
}
