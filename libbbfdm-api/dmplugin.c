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

#ifdef BBF_VENDOR_EXTENSION
#include "plugin/vendor_plugin.h"
#endif

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
	disable_entry_obj(dm_entryobj, srv_obj);

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
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[0]).obj = dm_dynamic_strdup(&global_memhead, srv_obj);
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[0]).checkdep = dm_dynamic_strdup(&global_memhead, srv_name);
	} else {
		int idx = get_entry_idx(dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0]);
		dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] = dm_dynamic_realloc(&global_memhead, dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
		memset(dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[idx]).obj = dm_dynamic_strdup(&global_memhead, srv_obj);
		((dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].nextobj[0])[idx]).checkdep = dm_dynamic_strdup(&global_memhead, srv_name);
	}

	return true;
}

static bool is_service_registered(struct list_head *srvlist, char *srv_name)
{
	struct service *srv = NULL;

	list_for_each_entry(srv, srvlist, list) {
		if (DM_STRCMP(srv->name, srv_name) == 0)
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
	if (!main_dm || !srv_list || !srv_name || !srv_parent_dm || !srv_obj)
		return false;

	if (is_service_registered(srv_list, srv_name))
		return false;

	if (!add_service_to_main_tree(main_dm, srv_name, srv_parent_dm, srv_obj))
		return false;

	add_service_to_list(srv_list, srv_name, srv_parent_dm, srv_obj);
	return true;
}

static void ubus_transaction_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *tb[2] = {0};
	const struct blobmsg_policy p[2] = {
			{ "updated_services", BLOBMSG_TYPE_ARRAY },
			{ "reverted_configs", BLOBMSG_TYPE_ARRAY }
	};

	if (msg == NULL || req == NULL)
		return;

	struct blob_buf *bb = (struct blob_buf *)req->priv;
	if (bb == NULL)
		return;

	blobmsg_parse(p, 2, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[0]) {
		struct blob_attr *service = NULL;
		size_t rem;

		blobmsg_for_each_attr(service, tb[0], rem) {
			blobmsg_add_string(bb, NULL, blobmsg_get_string(service));
		}
	}

	if (tb[1]) {
		struct blob_attr *config = NULL;
		size_t rem;

		blobmsg_for_each_attr(config, tb[1], rem) {
			blobmsg_add_string(bb, NULL, blobmsg_get_string(config));
		}
	}
}

int handle_transaction_of_registered_service(struct ubus_context *ctx, struct blob_buf *trans_bb, struct list_head *srvlist,
		const char *trans_cmd, int trans_id, uint32_t max_timeout, bool service_restart)
{
	struct service *srv = NULL;

	if (is_micro_service == true) // This should be called only from main daemon
		return -1;

	if (ctx == NULL || trans_id == 0)
		return -1;

	list_for_each_entry(srv, srvlist, list) {
		struct blob_buf bb = {0};
		void *table = NULL;
		uint32_t ubus_id;

		// check if object already present
		int ret = ubus_lookup_id(ctx, srv->name, &ubus_id);
		if (ret != 0)
			continue;

		memset(&bb, 0, sizeof(struct blob_buf));
		blob_buf_init(&bb, 0);

		blobmsg_add_string(&bb, "cmd", trans_cmd);
		blobmsg_add_u8(&bb, "restart_services", service_restart);
		blobmsg_add_u32(&bb, "timeout", max_timeout);

		table = blobmsg_open_table(&bb, "optional");
		blobmsg_add_u32(&bb, "transaction_id", trans_id);
		blobmsg_close_table(&bb, table);

		ubus_invoke(ctx, ubus_id, "transaction", bb.head, ubus_transaction_callback, (void *)trans_bb, 5000);
		blob_buf_free(&bb);
	}

	return 0;
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

static void dm_check_dynamic_obj(DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, DMOBJ **root_entry);
static void dm_check_dynamic_obj_entry(DMNODE *parent_node, DMOBJ *entryobj, char *parent_obj, char *full_obj, DMOBJ **root_entry)
{
	DMNODE node = {0};
	node.obj = entryobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level;
	node.matched = parent_node->matched;

	dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);
	if (DM_STRCMP(node.current_object, full_obj) == 0) {
		*root_entry = entryobj;
		return;
	}

	int err = plugin_obj_match(full_obj, &node);
	if (err)
		return;

	if (entryobj->nextobj || entryobj->nextdynamicobj)
		dm_check_dynamic_obj(&node, entryobj->nextobj, full_obj, root_entry);
}

static void dm_check_dynamic_obj(DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, DMOBJ **root_entry)
{
	char *parent_obj = parent_node->current_object;

	for (; (entryobj && entryobj->obj); entryobj++) {
		dm_check_dynamic_obj_entry(parent_node, entryobj, parent_obj, full_obj, root_entry);
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
							dm_check_dynamic_obj_entry(parent_node, jentryobj, parent_obj, full_obj, root_entry);
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

	char *in_obj = replace_str(obj_path, ".{i}.", ".");
	dm_check_dynamic_obj(&node, entryobj, in_obj, &obj);
	FREE(in_obj);

	return obj;
}

void disable_entry_obj(DMOBJ *entryobj, char *obj_path)
{
	if (!entryobj || DM_STRLEN(obj_path) == 0)
		return;

	DMOBJ *nextobj = entryobj->nextobj;

	for (; (nextobj && nextobj->obj); nextobj++) {

		if (DM_STRCMP(nextobj->obj, obj_path) == 0) {
			nextobj->bbfdm_type = BBFDM_NONE;
			return;
		}
	}
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

int load_plugins(DMOBJ *dm_entryobj, DM_MAP_VENDOR *dm_VendorExtension[], DM_MAP_VENDOR_EXCLUDE *dm_VendorExtensionExclude, const char *plugin_path)
{
	int max_num_files = 256;

#ifdef BBF_VENDOR_EXTENSION
	// Load objects and parameters exposed via vendor extension plugin
	free_specific_dynamic_node(dm_entryobj, INDX_VENDOR_MOUNT);
	load_vendor_dynamic_arrays(dm_entryobj, dm_VendorExtension, dm_VendorExtensionExclude);
#endif /* BBF_VENDOR_EXTENSION */

	if (DM_STRLEN(plugin_path) == 0)
		return 0;

	if (!folder_exists(plugin_path)) {
		return 0;
	}

	free_json_plugins();
	free_specific_dynamic_node(dm_entryobj, INDX_JSON_MOUNT);
	free_dotso_plugins();
	free_specific_dynamic_node(dm_entryobj, INDX_LIBRARY_MOUNT);

	sysfs_foreach_file_sorted(plugin_path, max_num_files) {
		char buf[512] = {0};

		snprintf(buf, sizeof(buf), "%s/%s", plugin_path, files[i]);

		if (DM_LSTRSTR(files[i], ".json")) {
			load_json_plugins(dm_entryobj, buf);
		} else if (DM_LSTRSTR(files[i], ".so")) {
			load_dotso_plugins(dm_entryobj, buf);
		}

		dmfree(files[i]);
	}

	return 0;
}

void free_plugins(DMOBJ *dm_entryobj)
{
	free_all_dynamic_nodes(dm_entryobj);

	free_json_plugins();
	free_dotso_plugins();
}
