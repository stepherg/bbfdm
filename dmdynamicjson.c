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

#include "dmdynamicjson.h"
#include "dmentry.h"

#define json_object_get_string(x) (char *)json_object_get_string(x)

static LIST_HEAD(loaded_json_files);
static LIST_HEAD(json_list);
static LIST_HEAD(json_memhead);

static operation_args empty_cmd = {
	.in = (const char**)NULL,
	.out = (const char**)NULL
};

static event_args empty_event = {
	.param = (const char**)NULL,
};

struct loaded_json_file
{
	struct list_head list;
	json_object *data;
};

struct dm_json_obj {
	struct list_head list;
	json_object *data;
	char *name;
	int json_version;
	operation_args command_arg;
	event_args event_arg;
};

enum json_plugin_version {
	JSON_VERSION_0,
	JSON_VERSION_1
};

static void save_json_data(struct list_head *json_list, char *name, json_object *data, int json_version,
			   const char **in_p, const char **out_p, const char **ev_arg)
{
	struct dm_json_obj *dm_json_obj = dm_dynamic_calloc(&json_memhead, 1, sizeof(struct dm_json_obj));

	if (name) dm_json_obj->name = dm_dynamic_strdup(&json_memhead, name);
	if (data) dm_json_obj->data = data;
	dm_json_obj->json_version = json_version;
	dm_json_obj->command_arg.in = in_p;
	dm_json_obj->command_arg.out = out_p;
	dm_json_obj->event_arg.param = ev_arg;
	list_add_tail(&dm_json_obj->list, json_list);
}

static void free_event_command_args(const char **arg_p)
{
	if (arg_p) {
		int i = 0;
		while (arg_p[i]) {
			dmfree((char *)arg_p[i]);
			i++;
		}

		free((char **)arg_p);
	}
}

static void free_json_data(struct list_head *json_list)
{
	struct dm_json_obj *dm_json_obj = NULL;

	while (json_list->next != json_list) {
		/* list_entry() is an external macro and which cppcheck can't track so
		 * throws warning of null pointer dereferencing for second argument.
		 * Suppressed the warning */
		// cppcheck-suppress nullPointer
		dm_json_obj = list_entry(json_list->next, struct dm_json_obj, list);
		list_del(&dm_json_obj->list);
		dmfree(dm_json_obj->name);
		free_event_command_args(dm_json_obj->command_arg.in);
		free_event_command_args(dm_json_obj->command_arg.out);
		free_event_command_args(dm_json_obj->event_arg.param);
		dmfree(dm_json_obj);
	}
}

static void save_loaded_json_files(struct list_head *json_list, json_object *data)
{
	struct loaded_json_file *json_file = calloc(1, sizeof(struct loaded_json_file));
	list_add_tail(&json_file->list, json_list);
	json_file->data = data;
}

static void free_loaded_json_files(struct list_head *json_list)
{
	struct loaded_json_file *json_file;
	while (json_list->next != json_list) {
		/* list_entry() is an external macro and which cppcheck can't track so
		 * throws warning of null pointer dereferencing for second argument.
		 * Suppressed the warning */
		// cppcheck-suppress nullPointer
		json_file = list_entry(json_list->next, struct loaded_json_file, list);
		list_del(&json_file->list);
		if (json_file->data)
			json_object_put(json_file->data);
		FREE(json_file);
	}
}

static void dm_browse_node_json_object_tree(DMNODE *parent_node, DMOBJ *entryobj)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + INDX_JSON_MOUNT;
			FREE(next_dyn_array->nextobj);
		}

		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		if (entryobj->nextobj)
			dm_browse_node_json_object_tree(&node, entryobj->nextobj);
	}
}

static void free_node_object_tree_dynamic_array(DMOBJ *dm_entryobj)
{
	DMOBJ *root = dm_entryobj;
	DMNODE node = {.current_object = ""};

	dm_browse_node_json_object_tree(&node, root);
}

int free_json_dynamic_arrays(DMOBJ *dm_entryobj)
{
	free_loaded_json_files(&loaded_json_files);
	free_json_data(&json_list);
	dm_dynamic_cleanmem(&json_memhead);
	free_node_object_tree_dynamic_array(dm_entryobj);
	return 0;
}

static char *find_prefix_obj(char *full_obj)
{
	int last_occurent = 0, occur = 0;
	char *prefix_obj = "";

	char *full_object = replace_str(full_obj, ".{i}.", ".");
	for (int i = 0; full_object[i] != 0; i++) {

		if (full_object[i] == '.') {
			last_occurent = occur;
			occur = i;
		}
	}

	*(full_object + last_occurent + 1) = 0;
	prefix_obj = dm_dynamic_strdup(&json_memhead, full_object);
	dmfree(full_object);

	return prefix_obj;
}

static char *find_current_obj(char *full_obj)
{
	int last_occurent = 0, occur = 0;
	char *curr_obj = "";

	char *full_object = replace_str(full_obj, ".{i}.", ".");
	for (int i = 0; full_object[i] != 0; i++) {

		if (full_object[i] == '.') {
			last_occurent = occur;
			occur = i;
		}
	}

	full_object[occur] = 0;
	curr_obj = dm_dynamic_strdup(&json_memhead, full_object + last_occurent + 1);
	dmfree(full_object);

	return curr_obj;
}

static char *generate_path_without_instance(char *full_obj, bool is_obj)
{
	char *pch = NULL, *pchr = NULL;
	char buf[1024] = {0};
	int pos = 0;

	char *str = dm_dynamic_strdup(&json_memhead, full_obj);

	for (pch = strtok_r(str, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (DM_STRTOL(pch) == 0 && strcmp(pch, "{i}") != 0) {
			pos  += snprintf(buf + pos, sizeof(buf) - pos, "%s.", pch);
		}
	}

	if (pos && !is_obj)
		buf[pos - 1] = 0;

	dmfree(str);

	return dm_dynamic_strdup(&json_memhead, buf);
}

static int get_index_of_available_entry(DMOBJ *jentryobj)
{
	int idx = 0;
	for (; (jentryobj && jentryobj->obj); jentryobj++) {
		idx++;
	}
	return idx;
}

static json_object *get_requested_json_obj(json_object *json_obj, char *instance, const char *key, char *arr_name, size_t arr_len)
{
	struct json_object *res = json_obj;
	char *pch = NULL, *pchr = NULL;
	char buf_args[256] = {0};

	DM_STRNCPY(buf_args, key, sizeof(buf_args));

	for (pch = strtok_r(buf_args, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {

		if (pchr && *pchr && (strchr(pch, '['))) {
			char buf[32] = {0};
			unsigned idx_pos = 0;

			DM_STRNCPY(buf, pch, sizeof(buf));
			buf[strlen(buf) - 1] = 0;
			char *p = strchr(buf, '[');

			if (strcmp(p+1, "@index") == 0 || strcmp(p+1, "@i-1") == 0) {
				idx_pos = instance ? DM_STRTOL(instance)-1 : 1;
			} else {
				idx_pos = DM_STRTOL(p+1);
			}
			*p = 0;

			res = dmjson_select_obj_in_array_idx(res, idx_pos, 1, buf);

		} else if (pchr && *pchr) {
			res = dmjson_get_obj(res, 1, pch);
		}

		DM_STRNCPY(arr_name, pch, arr_len);
	}

	return res;
}

static int get_number_of_instances(char *refparam)
{
	char *pch = NULL, *pchr = NULL;
	char buf_path[512] = {0};
	int nbr_inst = 0;

	DM_STRNCPY(buf_path, refparam, sizeof(buf_path));

	for (pch = strtok_r(buf_path, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (DM_STRTOL(pch) != 0)
			nbr_inst++;
	}

	return nbr_inst;
}

static void replace_indexes(struct dmctx *ctx, char *old_key, char *new_key, size_t key_len)
{
	char buf_key[256] = {0};
	unsigned char idx = 0;
	unsigned pos = 0;

	DM_STRNCPY(buf_key, old_key, sizeof(buf_key));

	for (int i = 0; buf_key[i] != '\0'; i++) {
		if (strstr(&buf_key[i], "{i}") == &buf_key[i]) {
			pos += snprintf(&new_key[pos], key_len - pos, "%s", ctx->inst_buf[idx] ? ctx->inst_buf[idx] : "");
			idx++;
			i += 3; // increase i with length of "{i}"
		}

		pos += snprintf(&new_key[pos], key_len - pos, "%c", buf_key[i]);
	}
}

static void resolve_all_symbols(struct dmctx *ctx, void *data, char *instance, char *value, int nbr_instances, int json_version,
		const char *old_key, char *new_key, size_t key_len)
{
	char *pch = NULL, *pchr = NULL;
	char buf_key[256] = {0};
	bool has_dot = false;
	unsigned pos = 0;

	DM_STRNCPY(buf_key, old_key, sizeof(buf_key));

	if (buf_key[strlen(buf_key) - 1] == '.')
		has_dot = true;

	for (pch = strtok_r(buf_key, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {

		if (strcmp(pch, "@Name") == 0)
			pos += snprintf(&new_key[pos], key_len - pos, "%s.", data ? section_name((struct uci_section *)data) : "");
		else if (strcmp(pch, "@Value") == 0)
			pos += snprintf(&new_key[pos], key_len - pos, "%s.", value);
		else if (strcmp(pch, (json_version == JSON_VERSION_1) ? "@index" : "@i-1") == 0)
			pos += snprintf(&new_key[pos], key_len - pos, "%ld.", instance ? DM_STRTOL(instance)-1 : 1);
		else if (strstr(pch, "@index-")) {
			char *p = strchr(pch, '-');
			int idx_pos = DM_STRTOL(p + 1);

			if (idx_pos != 0 && nbr_instances - idx_pos >= 0)
				pos += snprintf(&new_key[pos], key_len - pos, "%s.", ctx->inst_buf[nbr_instances - idx_pos] ? ctx->inst_buf[nbr_instances - idx_pos] : "");
		} else
			pos += snprintf(&new_key[pos], key_len - pos, "%s.", pch);
	}

	if (pos && !has_dot)
		new_key[pos - 1] = 0;

	if (strstr(new_key, "{i}"))
		replace_indexes(ctx, new_key, new_key, key_len);
}

static int fill_ubus_arguments(struct dmctx *ctx, void *data, char *instance, char *value, int nbr_instances, int json_version,
		struct json_object *args_obj, struct ubus_arg u_args[])
{
	int u_args_size = 0;

	json_object_object_foreach(args_obj, key, val) {
		char buf_key[256] = {0};
		char buf_val[256] = {0};

		resolve_all_symbols(ctx, data, instance, value, nbr_instances, json_version, key, buf_key, sizeof(buf_key));
		resolve_all_symbols(ctx, data, instance, value, nbr_instances, json_version, json_object_get_string(val), buf_val, sizeof(buf_val));

		u_args[u_args_size].key = dm_dynamic_strdup(&json_memhead, buf_key);
		u_args[u_args_size].val = dm_dynamic_strdup(&json_memhead, buf_val);
		switch (json_object_get_type(val)) {
			case json_type_boolean:
				u_args[u_args_size].type = Boolean;
				break;
			case json_type_int:
				u_args[u_args_size].type = Integer;
				break;
			default:
				u_args[u_args_size].type = String;
				break;
		}
		u_args_size++;
	}

	return u_args_size;
}

static void free_ubus_arguments(struct ubus_arg u_args[], int u_args_size)
{
	for (int i = 0; i < u_args_size; i++) {
		dmfree((char *)u_args[i].key);
		dmfree((char *)u_args[i].val);
	}
}

static int browse_obj(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_json_obj *pobj = NULL;
	struct json_object *mapping_obj = NULL;
	struct json_object *mapping_0 = NULL;
	struct json_object *type = NULL;
	int json_version = JSON_VERSION_0;

	char *obj = generate_path_without_instance(parent_node->current_object, true);
	list_for_each_entry(pobj, &json_list, list) {
		if (DM_STRCMP(pobj->name, obj) == 0) {
			mapping_obj = pobj->data;
			json_version = pobj->json_version;
			break;
		}
	}

	if (json_version == JSON_VERSION_1 && mapping_obj && json_object_get_type(mapping_obj) == json_type_array) {
		mapping_0 = json_object_array_get_idx(mapping_obj, 0);
		json_object_object_get_ex(mapping_0, "type", &type);
	} else {
		json_object_object_get_ex(mapping_obj, "type", &type);
	}

	if (type && strcmp(json_object_get_string(type), "uci") == 0) {
		char buf_instance[64], buf_alias[64], *object = NULL;
		struct json_object *uci_obj = NULL;
		struct json_object *file = NULL;
		struct json_object *section = NULL;
		struct json_object *section_type = NULL;
		struct json_object *dmmap_file = NULL;
		char *inst = NULL;
		struct dmmap_dup *p = NULL;
		LIST_HEAD(dup_list);

		json_object_object_get_ex((mapping_0 && json_version == JSON_VERSION_1) ? mapping_0 : mapping_obj, "uci", &uci_obj);
		json_object_object_get_ex(uci_obj, "file", &file);
		json_object_object_get_ex(uci_obj, "section", &section);
		json_object_object_get_ex(section, "type", &section_type);
		json_object_object_get_ex(uci_obj, "dmmapfile", &dmmap_file);

		object = find_current_obj(parent_node->current_object);
		snprintf(buf_instance, sizeof(buf_instance), "%s_instance", object);
		snprintf(buf_alias, sizeof(buf_alias), "%s_alias", object);
		for (int i = 0; buf_instance[i]; i++)
			buf_instance[i] = tolower(buf_instance[i]);

		for (int i = 0; buf_alias[i]; i++)
			buf_alias[i] = tolower(buf_alias[i]);

		if(file && section_type && dmmap_file) {
			synchronize_specific_config_sections_with_dmmap(json_object_get_string(file), json_object_get_string(section_type), json_object_get_string(dmmap_file), &dup_list);
			list_for_each_entry(p, &dup_list, list) {

				inst = handle_instance(dmctx, parent_node, p->dmmap_section, buf_instance, buf_alias);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
					break;
			}
		}
		free_dmmap_config_dup_list(&dup_list);

	} else if (type && strcmp(json_object_get_string(type), "ubus") == 0) {
		struct json_object *res = NULL;
		struct json_object *dyn_obj = NULL;
		struct json_object *arrobj = NULL;
		struct json_object *ubus_obj = NULL;
		struct json_object *object = NULL;
		struct json_object *method = NULL;
		struct json_object *args_obj = NULL;
		struct json_object *key = NULL;
		struct ubus_arg u_args[16] = {0};
		char buf_object[256] = {0};
		char buf_method[256] = {0};
		int u_args_size = 0;

		int nbr_instances = get_number_of_instances(parent_node->current_object);

		json_object_object_get_ex((mapping_0 && json_version == JSON_VERSION_1) ? mapping_0 : mapping_obj, "ubus", &ubus_obj);
		json_object_object_get_ex(ubus_obj, "object", &object);
		json_object_object_get_ex(ubus_obj, "method", &method);
		json_object_object_get_ex(ubus_obj, "args", &args_obj);
		json_object_object_get_ex(ubus_obj, "key", &key);

		if (object)
			resolve_all_symbols(dmctx, prev_data, prev_instance, "", nbr_instances, json_version, json_object_get_string(object), buf_object, sizeof(buf_object));

		if (method)
			resolve_all_symbols(dmctx, prev_data, prev_instance, "", nbr_instances, json_version, json_object_get_string(method), buf_method, sizeof(buf_method));

		if (args_obj)
			u_args_size = fill_ubus_arguments(dmctx, prev_data, prev_instance, "", nbr_instances, json_version, args_obj, u_args);

		dmubus_call(buf_object, buf_method, u_args, u_args_size, &res);

		free_ubus_arguments(u_args, u_args_size);

		if (res && key) {
			char arr_name[32] = {0};
			int id = 0, i = 0;

			json_object *arr_obj = get_requested_json_obj(res, prev_instance, json_object_get_string(key), arr_name, sizeof(arr_name));

			dmjson_foreach_obj_in_array(arr_obj, arrobj, dyn_obj, i, 1, arr_name) {
				char *inst = handle_instance_without_section(dmctx, parent_node, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dyn_obj, inst) == DM_STOP)
					break;
			}
		}
	}

	return 0;
}

static int add_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dm_json_obj *pobj = NULL;
	struct json_object *mapping_obj = NULL;
	struct json_object *mapping_0 = NULL;
	struct json_object *obj_type = NULL;
	int json_version = JSON_VERSION_0;

	char *obj = generate_path_without_instance(refparam, true);
	list_for_each_entry(pobj, &json_list, list) {
		if (DM_STRCMP(pobj->name, obj) == 0) {
			mapping_obj = pobj->data;
			json_version = pobj->json_version;
			break;
		}
	}

	if (json_version == JSON_VERSION_1 && mapping_obj && json_object_get_type(mapping_obj) == json_type_array) {
		mapping_0 = json_object_array_get_idx(mapping_obj, 0);
		json_object_object_get_ex(mapping_0, "type", &obj_type);
	} else {
		json_object_object_get_ex(mapping_obj, "type", &obj_type);
	}

	if (obj_type && strcmp(json_object_get_string(obj_type), "uci") == 0) {
		struct json_object *uci_obj = NULL;
		struct json_object *file = NULL;
		struct json_object *section = NULL;
		struct json_object *section_type = NULL;
		struct json_object *dmmap_file = NULL;
		char *object = NULL;
		char buf_instance[64];

		json_object_object_get_ex((mapping_0 && json_version == JSON_VERSION_1) ? mapping_0 : mapping_obj, "uci", &uci_obj);
		json_object_object_get_ex(uci_obj, "file", &file);
		json_object_object_get_ex(uci_obj, "section", &section);
		json_object_object_get_ex(section, "type", &section_type);
		json_object_object_get_ex(uci_obj, "dmmapfile", &dmmap_file);

		object = find_current_obj(refparam);
		snprintf(buf_instance, sizeof(buf_instance), "%s_instance", object);
		for (int i = 0; buf_instance[i]; i++) {
			buf_instance[i] = tolower(buf_instance[i]);
		}

		if (file && section_type && dmmap_file) {
			struct uci_section *s = NULL, *dmmap_s = NULL;

			dmuci_add_section(json_object_get_string(file), json_object_get_string(section_type), &s);

			dmuci_add_section_bbfdm(json_object_get_string(dmmap_file), json_object_get_string(section_type), &dmmap_s);
			dmuci_set_value_by_section(dmmap_s, "section_name", section_name(s));
			dmuci_set_value_by_section(dmmap_s, buf_instance, *instance);
		}
	}

	return 0;
}

static int delete_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dm_json_obj *pobj = NULL;
	struct json_object *mapping_obj = NULL;
	struct json_object *mapping_0 = NULL;
	struct json_object *type_obj = NULL;
	int json_version = JSON_VERSION_0;

	char *obj = generate_path_without_instance(refparam, true);
	list_for_each_entry(pobj, &json_list, list) {
		if (DM_STRCMP(pobj->name, obj) == 0) {
			mapping_obj = pobj->data;
			json_version = pobj->json_version;
			break;
		}
	}

	if (json_version == JSON_VERSION_1 && mapping_obj && json_object_get_type(mapping_obj) == json_type_array) {
		mapping_0 = json_object_array_get_idx(mapping_obj, 0);
		json_object_object_get_ex(mapping_0, "type", &type_obj);
	} else {
		json_object_object_get_ex(mapping_obj, "type", &type_obj);
	}

	if (type_obj && strcmp(json_object_get_string(type_obj), "uci") == 0) {
		struct json_object *uci_obj = NULL;
		struct json_object *file = NULL;
		struct json_object *section = NULL;
		struct json_object *section_type = NULL;
		struct json_object *dmmap_file = NULL;

		json_object_object_get_ex((mapping_0 && json_version == JSON_VERSION_1) ? mapping_0 : mapping_obj, "uci", &uci_obj);
		json_object_object_get_ex(uci_obj, "file", &file);
		json_object_object_get_ex(uci_obj, "section", &section);
		json_object_object_get_ex(section, "type", &section_type);
		json_object_object_get_ex(uci_obj, "dmmapfile", &dmmap_file);

		if (file && section_type && dmmap_file) {
			struct uci_section *s = NULL, *stmp = NULL, *dmmap_section = NULL;

			switch (del_action) {
				case DEL_INST:
					get_dmmap_section_of_config_section(json_object_get_string(dmmap_file), json_object_get_string(section_type), section_name((struct uci_section *)data), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);

					dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
					break;
				case DEL_ALL:
					uci_foreach_sections_safe(json_object_get_string(file), json_object_get_string(section_type), stmp, s) {
						get_dmmap_section_of_config_section(json_object_get_string(dmmap_file), json_object_get_string(section_type), section_name(s), &dmmap_section);
						dmuci_delete_by_section(dmmap_section, NULL, NULL);

						dmuci_delete_by_section(s, NULL, NULL);
					}
					break;
			}
		}
	}

	return 0;
}

static char *uci_get_value(json_object *mapping_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *obj = NULL;
	struct json_object *file = NULL;
	struct json_object *section = NULL;
	struct json_object *type = NULL;
	struct json_object *section_name = NULL;
	struct json_object *option = NULL;
	struct json_object *option_name = NULL;
	struct json_object *list = NULL;
	struct json_object *list_name = NULL;
	struct json_object *path = NULL;
	char *value = "";

	json_object_object_get_ex(mapping_obj, "uci", &obj);
	json_object_object_get_ex(obj, "file", &file);
	json_object_object_get_ex(obj, "section", &section);
	json_object_object_get_ex(section, "type", &type);
	json_object_object_get_ex(section, "name", &section_name);
	json_object_object_get_ex(obj, "option", &option);
	json_object_object_get_ex(option, "name", &option_name);
	json_object_object_get_ex(obj, "list", &list);
	json_object_object_get_ex(list, "name", &list_name);
	json_object_object_get_ex(obj, "path", &path);

	char *opt_temp = NULL;
	if (list_name) {
		opt_temp = json_object_get_string(list_name);
	} else if (option_name) {
		opt_temp = json_object_get_string(option_name);
	}

	if (file && type && opt_temp && strstr(refparam, "NumberOfEntries")) {

		if (strcmp(opt_temp, "@Count") != 0 && json_version == JSON_VERSION_1)
			goto end;

		struct uci_section *s = NULL;
		int cnt = 0;

		uci_foreach_sections(json_object_get_string(file), json_object_get_string(type), s) {
			cnt++;
		}
		dmasprintf(&value, "%d", cnt);
		goto end;
	}

	if (data && file && type && opt_temp) {
		if (strcmp(opt_temp, "@Name") == 0) {
			dmasprintf(&value, "%s", section_name((struct uci_section *)data));
		} else {
			char uci_type[32] = {0};
			snprintf(uci_type, sizeof(uci_type), "@%s[%ld]", json_object_get_string(type), instance ? DM_STRTOL(instance)-1 : 0);
			if (option) {
				value = dmuci_get_value_by_path(json_object_get_string(path), json_object_get_string(file), uci_type, opt_temp);
			} else {
				struct uci_list *list_val;
				dmuci_get_option_value_list(json_object_get_string(file), uci_type, opt_temp, &list_val);
				value = dmuci_list_to_string(list_val, ",");
			}
		}
	} else if (file && section_name && opt_temp) {
		if (option) {
			value = dmuci_get_value_by_path(json_object_get_string(path), json_object_get_string(file), json_object_get_string(section_name), opt_temp);
		} else {
			struct uci_list *list_val;
			dmuci_get_option_value_list(json_object_get_string(file), json_object_get_string(section_name), opt_temp, &list_val);
			value = dmuci_list_to_string(list_val, ",");
		}
	}

	if (strstr(refparam, "Alias") && value[0] == '\0')
		dmasprintf(&value, "cpe-%s", instance);

end:
	return value;
}

static char *ubus_get_value(json_object *mapping_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *ubus_obj = NULL;
	struct json_object *object = NULL;
	struct json_object *method = NULL;
	struct json_object *key = NULL;
	struct json_object *args = NULL;
	struct json_object *res = NULL;
	char buf_object[256] = {0};
	char buf_method[256] = {0};
	struct ubus_arg u_args[16] = {0};
	int u_args_size = 0;
	char *value = "";

	int nbr_instances = get_number_of_instances(refparam);

	json_object_object_get_ex(mapping_obj, "ubus", &ubus_obj);
	json_object_object_get_ex(ubus_obj, "object", &object);
	json_object_object_get_ex(ubus_obj, "method", &method);
	json_object_object_get_ex(ubus_obj, "args", &args);
	json_object_object_get_ex(ubus_obj, "key", &key);

	if (object)
		resolve_all_symbols(ctx, data, instance, "", nbr_instances, json_version, json_object_get_string(object), buf_object, sizeof(buf_object));

	if (method)
		resolve_all_symbols(ctx, data, instance, "", nbr_instances, json_version, json_object_get_string(method), buf_method, sizeof(buf_method));

	if (args)
		u_args_size = fill_ubus_arguments(ctx, data, instance, "", nbr_instances, json_version, args, u_args);

	dmubus_call(buf_object, buf_method, u_args, u_args_size, &res);

	free_ubus_arguments(u_args, u_args_size);

	if (key) {
		json_object *json_obj = NULL;
		json_object *arr_obj = NULL;
		char key_buf[128] = {0};
		char key_name[32] = {0};

		DM_STRNCPY(key_buf, json_object_get_string(key), sizeof(key_buf));

		if (json_version == JSON_VERSION_1) {
			char *str = NULL;

			if ((str = strstr(key_buf, ".@Count")) != NULL)
				*str = 0;
		}

		char *is_array = strstr(key_buf, (json_version == JSON_VERSION_1) ? "[@index]" : "[@i-1]");
		if (data && is_array) {
			char *arguments = (json_version == JSON_VERSION_1) ? is_array + sizeof("[@index]") : is_array + sizeof("[@i-1]");
			json_obj = get_requested_json_obj((json_object *)data, instance, arguments, key_name, sizeof(key_name));
		} else {
			json_obj = get_requested_json_obj(res, instance, key_buf, key_name, sizeof(key_name));
		}

		json_object_object_get_ex(json_obj, key_name, &arr_obj);

		if (arr_obj && json_object_get_type(arr_obj) == json_type_array) {
			int nbre_entries = json_object_array_length(arr_obj);
			dmasprintf(&value, "%d", nbre_entries);
		} else {
			value = dmjson_get_value(json_obj, 1, key_name);
		}
	}

	return value;
}

static char *uci_v1_get_value(json_object *mapping_obj, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *data_s = NULL;
	struct json_object *key = NULL;
	char *value = "";

	json_object_object_get_ex(mapping_obj, "data", &data_s);
	json_object_object_get_ex(mapping_obj, "key", &key);

	/* json_object_object_get_ex is an external macro which changes the
	 * value of data_s that cppcheck can't track and throws warning as
	 * data_s value check always true. So suppressed the warning */
	// cppcheck-suppress knownConditionTrueFalse
	if (data == NULL || data_s == NULL || (data_s && strcmp(json_object_get_string(data_s), "@Parent") != 0))
		goto end;


	if (key) {
		if (strcmp(json_object_get_string(key), "@Name") == 0) {
			dmasprintf(&value, "%s", section_name((struct uci_section *)data));
		} else {
			dmuci_get_value_by_section_string((struct uci_section *)data, json_object_get_string(key), &value);
		}
	}

end:
	return value;
}

static char *ubus_v1_get_value(json_object *mapping_obj, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *data_json = NULL;
	struct json_object *key = NULL;
	char *value = "";

	json_object_object_get_ex(mapping_obj, "data", &data_json);
	json_object_object_get_ex(mapping_obj, "key", &key);

	/* json_object_object_get_ex is an external macro which changes the
	 * value of data_json that cppcheck can't track and throws warning as
	 * data_json value check always true. So suppressed the warning */
	// cppcheck-suppress knownConditionTrueFalse
	if (data == NULL || data_json == NULL || (data_json && strcmp(json_object_get_string(data_json), "@Parent") != 0))
		goto end;

	if (key) {
		char key_name[128] = {32};

		json_object *json_obj = get_requested_json_obj((json_object *)data, instance, json_object_get_string(key), key_name, sizeof(key_name));
		value = dmjson_get_value(json_obj, 1, key_name);
	}

end:
	return value;
}

static char *get_value_from_mapping(json_object *param_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *mapping_arr = NULL, *mapping = NULL;

	if (!param_obj)
		return "";

	json_object_object_get_ex(param_obj, "mapping", &mapping_arr);
	if (mapping_arr && json_object_get_type(mapping_arr) == json_type_array) {

		for (int idx = 0; (mapping = json_object_array_get_idx(mapping_arr, idx)) != NULL; idx++) {
			struct json_object *type = NULL;
			struct json_object *rpc = NULL;

			json_object_object_get_ex(mapping, "rpc", &rpc);
			json_object_object_get_ex(mapping, "type", &type);

			if (rpc && json_version == JSON_VERSION_1 && strcmp(json_object_get_string(rpc), "get") != 0)
				continue;

			if (type && strcmp(json_object_get_string(type), "uci") == 0)
				return uci_get_value(mapping, json_version, refparam, ctx, data, instance);
			else if (type && strcmp(json_object_get_string(type), "ubus") == 0)
				return ubus_get_value(mapping, json_version, refparam, ctx, data, instance);
			else if (type && strcmp(json_object_get_string(type), "uci_sec") == 0 && json_version == JSON_VERSION_1)
				return uci_v1_get_value(mapping, refparam, ctx, data, instance);
			else if (type && strcmp(json_object_get_string(type), "json") == 0 && json_version == JSON_VERSION_1)
				return ubus_v1_get_value(mapping, refparam, ctx, data, instance);
			else
				return "";
		}

	}

	return "";
}

static int getvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_json_obj *pleaf = NULL;
	json_object *param_obj = NULL;
	int json_version = JSON_VERSION_0;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (DM_STRCMP(pleaf->name, obj) == 0) {
			param_obj = pleaf->data;
			json_version = pleaf->json_version;
			break;
		}
	}

	*value = get_value_from_mapping(param_obj, json_version, refparam, ctx, data, instance);
	return 0;
}

static int ubus_set_operate(json_object *mapping_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, void *value, char *instance)
{
	struct json_object *ubus_obj = NULL;
	struct json_object *object = NULL;
	struct json_object *method = NULL;
	struct json_object *args = NULL;
	struct json_object *in_args = NULL;
	struct json_object *res = NULL;
	char buf_object[256] = {0};
	char buf_method[256] = {0};

	int nbr_instances = get_number_of_instances(refparam);

	json_object_object_get_ex(mapping_obj, "ubus", &ubus_obj);
	json_object_object_get_ex(ubus_obj, "object", &object);
	json_object_object_get_ex(ubus_obj, "method", &method);
	json_object_object_get_ex(ubus_obj, "args", &args);

	if (object)
		resolve_all_symbols(ctx, data, instance, "", nbr_instances, json_version, json_object_get_string(object), buf_object, sizeof(buf_object));

	if (method)
		resolve_all_symbols(ctx, data, instance, "", nbr_instances, json_version, json_object_get_string(method), buf_method, sizeof(buf_method));

	if (args) {
		struct ubus_arg u_args[16] = {0};

		int u_args_size = fill_ubus_arguments(ctx, data, instance, "", nbr_instances, json_version, args, u_args);

		if (u_args_size != 0) {
			in_args = json_object_new_object();

			for (int i = 0; i < u_args_size; i++)
				json_object_object_add(in_args, u_args[i].key, json_object_new_string(u_args[i].val));
		}
	}

	dmubus_call_blob(buf_object, buf_method, in_args, &res);

	if (in_args)
		json_object_put(in_args);

	if (res) {
		json_object_object_foreach(res, key, val) {
			char buf_key[256] = {0};
			char buf_val[256] = {0};

			resolve_all_symbols(ctx, data, instance, "", nbr_instances, json_version, key, buf_key, sizeof(buf_key));
			resolve_all_symbols(ctx, data, instance, "", nbr_instances, json_version, json_object_get_string(val), buf_val, sizeof(buf_val));

			add_list_parameter(ctx, dmstrdup(buf_key), dmstrdup(buf_val), DMT_TYPE[DMT_STRING], NULL);
		}
		json_object_put(res);
	}

	return CMD_SUCCESS;
}

static int getcommand_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_json_obj *leaf = NULL;
	bool found = false;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(leaf, &json_list, list) {
		if (DM_STRCMP(leaf->name, obj) == 0) {
			found = true;
			break;
		}
	}

	if (found) {
		*value = (char *)&leaf->command_arg;
	} else {
		*value = (char *)&empty_cmd;
	}

	return 0;
}

static int setcommand_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_json_obj *leaf_node = NULL;
	struct json_object *p_obj = NULL, *map_arr = NULL, *map_obj = NULL, *type = NULL;
	int json_version = JSON_VERSION_0;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(leaf_node, &json_list, list) {
		if (DM_STRCMP(leaf_node->name, obj) == 0) {
			p_obj = leaf_node->data;
			json_version = leaf_node->json_version;
			break;
		}
	}

	if (p_obj == NULL) {
		return CMD_FAIL;
	}

	json_object_object_get_ex(p_obj, "mapping", &map_arr);
	if (map_arr && json_object_get_type(map_arr) == json_type_array)
		map_obj = json_object_array_get_idx(map_arr, 0);

	if (!map_obj) {
		return CMD_FAIL;
	}

	json_object_object_get_ex(map_obj, "type", &type);

	if (type && strcmp(json_object_get_string(type), "ubus") == 0) {
		return ubus_set_operate(map_obj, json_version, refparam, ctx, data, value, instance);
	}

	return CMD_FAIL;
}

static int getevent_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_json_obj *leaf = NULL;
	bool found = false;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(leaf, &json_list, list) {
		if (DM_STRCMP(leaf->name, obj) == 0) {
			found = true;
			break;
		}
	}

	if (found) {
		*value = (char *)&leaf->event_arg;
	} else {
		*value = (char *)&empty_event;
	}

	return 0;
}

static int fill_all_arguments(struct json_object *range, struct range_args range_arg[], int range_len)
{
	for (int i = 0; i < range_len; i++) {
		struct json_object *range_val = NULL;
		struct json_object *range_val_min = NULL;
		struct json_object *range_val_max = NULL;

		if ((range_val = json_object_array_get_idx(range, i)) == NULL)
			return -1;

		json_object_object_get_ex(range_val, "min", &range_val_min);
		json_object_object_get_ex(range_val, "max", &range_val_max);

		range_arg[i].min = json_object_get_string(range_val_min);
		range_arg[i].max = json_object_get_string(range_val_max);
	}

	return 0;
}

static int fill_string_arguments(struct json_object *json_obj, int *min_length, int *max_length, char *enumeration[], char *pattern[])
{
	struct json_object *enum_obj = NULL;
	struct json_object *pattern_obj = NULL;
	struct json_object *range_obj = NULL;
	struct json_object *range_arr = NULL;

	json_object_object_get_ex(json_obj, "range", &range_arr);
	if (range_arr && json_object_get_type(range_arr) == json_type_array)
		range_obj = json_object_array_get_idx(range_arr, 0);

	if (range_obj) {
		struct json_object *range_min = NULL;
		struct json_object *range_max = NULL;

		json_object_object_get_ex(range_obj, "min", &range_min);
		json_object_object_get_ex(range_obj, "max", &range_max);

		*min_length = range_min ? DM_STRTOL(json_object_get_string(range_min)) : -1;
		*max_length = range_max ? DM_STRTOL(json_object_get_string(range_max)) : -1;
	}

	json_object_object_get_ex(json_obj, "enumerations", &enum_obj);
	if (enum_obj && json_object_get_type(enum_obj) != json_type_array) {
		return -1;
	}

	int enum_len = (enum_obj) ? json_object_array_length(enum_obj) + 1 : 1;
	for (int i = 0; i < enum_len - 1; i++) {
		struct json_object *enum_val = NULL;

		if ((enum_val = json_object_array_get_idx(enum_obj, i)) == NULL)
			return -1;

		enumeration[i] = json_object_get_string(enum_val);

	}
	enumeration[enum_len - 1] = NULL;


	json_object_object_get_ex(json_obj, "pattern", &pattern_obj);
	if ((pattern_obj != NULL) && json_object_get_type(pattern_obj) == json_type_array) {
		/* json_object_object_get_ex is an external macro which changes the
		 * value of pattern_obj that cppcheck can't track and throws warning as
		 * pattern_obj value check always true. So suppressed the warning */
		// cppcheck-suppress knownConditionTrueFalse
		int pattern_len = (pattern_obj) ? json_object_array_length(pattern_obj) + 1 : 1;

		for (int i = 0; i < pattern_len - 1; i++) {
			struct json_object *pattern_val = NULL;

			if ((pattern_val = json_object_array_get_idx(pattern_obj, i)) == NULL)
				return -1;

			pattern[i] = json_object_get_string(pattern_val);

		}
		pattern[pattern_len - 1] = NULL;

	}

	return 0;
}

static int dm_validate_value(json_object *json_obj, char *value)
{
	struct json_object *type_obj = NULL;

	if (!json_obj)
		return -1;

	json_object_object_get_ex(json_obj, "type", &type_obj);
	if (!type_obj)
		return -1;

	char *type = json_object_get_string(type_obj);
	if (!type)
		return -1;

	if (strcmp(type, "boolean") == 0) {
		if (dm_validate_boolean(value))
			return FAULT_9007;
	} else if (strcmp(type, "dateTime") == 0) {
		if (dm_validate_dateTime(value))
			return FAULT_9007;
	} else if (strcmp(type, "unsignedInt") == 0 || strcmp(type, "unsignedLong") == 0 ||
			strcmp(type, "hexBinary") == 0 || strcmp(type, "int") == 0 || strcmp(type, "long") == 0) {

		struct json_object *range_obj = NULL;
		struct range_args range_arg[16] = {0};
		int range_len = 1;

		json_object_object_get_ex(json_obj, "range", &range_obj);
		if (range_obj && json_object_get_type(range_obj) == json_type_array) {
			range_len = json_object_array_length(range_obj);

			if (fill_all_arguments(range_obj, range_arg, range_len))
				return -1;
		}

		if ((strcmp(type, "unsignedInt") == 0 && dm_validate_unsignedInt(value, range_arg, range_len)) ||
			(strcmp(type, "unsignedLong") == 0 && dm_validate_unsignedLong(value, range_arg, range_len)) ||
			(strcmp(type, "hexBinary") == 0 && dm_validate_hexBinary(value, range_arg, range_len)) ||
			(strcmp(type, "int") == 0 && dm_validate_int(value, range_arg, range_len)) ||
			(strcmp(type, "long") == 0 && dm_validate_long(value, range_arg, range_len)))
			return FAULT_9007;
	} else if (strcmp(type, "string") == 0) {
		struct json_object *list_obj = NULL;
		char *enum_tab[16] = {0};
		char *pattern_tab[16] = {0};
		int min_length = -1;
		int max_length = -1;

		json_object_object_get_ex(json_obj, "list", &list_obj);

		if (list_obj && json_object_get_type(list_obj) == json_type_object) {
			struct json_object *datatype_obj = NULL;
			struct json_object *maxsize = NULL;
			struct json_object *item_obj = NULL;
			int min_item = -1;
			int max_item = -1;
			int max_size = -1;

			json_object_object_get_ex(list_obj, "datatype", &datatype_obj);
			if (!datatype_obj)
				return -1;

			char *datatype = json_object_get_string(datatype_obj);
			if (!datatype)
				return -1;

			json_object_object_get_ex(list_obj, "maxsize", &maxsize);
			max_size = maxsize ? DM_STRTOL(json_object_get_string(maxsize)) : -1;

			json_object_object_get_ex(list_obj, "item", &item_obj);
			if (item_obj) {
				struct json_object *item_min = NULL;
				struct json_object *item_max = NULL;

				json_object_object_get_ex(item_obj, "min", &item_min);
				json_object_object_get_ex(item_obj, "max", &item_max);
				min_item = item_min ? DM_STRTOL(json_object_get_string(item_min)) : -1;
				max_item = item_max ? DM_STRTOL(json_object_get_string(item_max)) : -1;
			}

			if (strcmp(datatype, "unsignedInt") == 0 ||
				strcmp(datatype, "unsignedLong") == 0 ||
				strcmp(datatype, "hexBinary") == 0 ||
				strcmp(datatype, "int") == 0 ||
				strcmp(datatype, "long") == 0) {

				struct json_object *range_obj = NULL;
				struct range_args range_arg[16] = {0};
				int range_len = 1;

				json_object_object_get_ex(list_obj, "range", &range_obj);
				if (range_obj && json_object_get_type(range_obj) == json_type_array) {
					range_len = json_object_array_length(range_obj);

					if (fill_all_arguments(range_obj, range_arg, range_len))
						return -1;
				}

				if ((strcmp(datatype, "unsignedInt") == 0 && dm_validate_unsignedInt_list(value, min_item, max_item, max_size, range_arg, range_len)) ||
					(strcmp(datatype, "unsignedLong") == 0 && dm_validate_unsignedLong_list(value, min_item, max_item, max_size, range_arg, range_len)) ||
					(strcmp(datatype, "hexBinary") == 0 && dm_validate_hexBinary_list(value, min_item, max_item, max_size, range_arg, range_len)) ||
					(strcmp(datatype, "int") == 0 && dm_validate_int_list(value, min_item, max_item, max_size, range_arg, range_len)) ||
					(strcmp(datatype, "long") == 0 && dm_validate_long_list(value, min_item, max_item, max_size, range_arg, range_len)))
					return FAULT_9007;
			} else if (strcmp(datatype, "string") == 0) {
				if (fill_string_arguments(list_obj, &min_length, &max_length, enum_tab, pattern_tab))
					return -1;

				if (dm_validate_string_list(value, min_item, max_item, max_size, min_length, max_length, *enum_tab ? enum_tab : NULL, *pattern_tab ? pattern_tab : NULL))
					return FAULT_9007;
			}
		} else {
			if (fill_string_arguments(json_obj, &min_length, &max_length, enum_tab, pattern_tab))
				return -1;

			if (dm_validate_string(value, min_length, max_length, *enum_tab ? enum_tab : NULL, *pattern_tab ? pattern_tab : NULL))
				return FAULT_9007;
		}
	} else {
		return -1;
	}

	return 0;
}

static void uci_set_value(json_object *mapping_obj, int json_version, char *refparam, struct dmctx *ctx, const void *data, char *instance, char *value)
{
	struct json_object *uci_obj = NULL;
	struct json_object *file = NULL;
	struct json_object *section = NULL;
	struct json_object *type = NULL;
	struct json_object *section_name = NULL;
	struct json_object *option = NULL;
	struct json_object *option_name = NULL;
	struct json_object *list = NULL;
	struct json_object *list_name = NULL;
	struct json_object *path = NULL;

	json_object_object_get_ex(mapping_obj, "uci", &uci_obj);
	json_object_object_get_ex(uci_obj, "file", &file);
	json_object_object_get_ex(uci_obj, "section", &section);
	json_object_object_get_ex(section, "type", &type);
	json_object_object_get_ex(section, "name", &section_name);
	json_object_object_get_ex(uci_obj, "option", &option);
	json_object_object_get_ex(option, "name", &option_name);
	json_object_object_get_ex(uci_obj, "list", &list);
	json_object_object_get_ex(list, "name", &list_name);
	json_object_object_get_ex(uci_obj, "path", &path);

	char *opt_temp = NULL;
	if (list_name) {
		opt_temp = json_object_get_string(list_name);
	} else if (option_name) {
		opt_temp = json_object_get_string(option_name);
	}

	if (data && file && type && opt_temp) {
		char uci_type[32] = {0};

		snprintf(uci_type, sizeof(uci_type), "@%s[%ld]", json_object_get_string(type), instance ? DM_STRTOL(instance)-1 : 0);
		if (option) {
			dmuci_set_value_by_path(json_object_get_string(path), json_object_get_string(file), uci_type, opt_temp, value);
		} else {
			if (value != NULL) {
				dmuci_delete(json_object_get_string(file), uci_type, opt_temp, NULL);
				char *p = strtok(value, ",");
				while (p) {
					strip_lead_trail_whitespace(p);
					dmuci_add_list_value(json_object_get_string(file), uci_type, opt_temp, p);
					p = strtok(NULL, ",");
				}
			}
		}
	} else if (file && section_name && opt_temp) {
		if (option) {
			dmuci_set_value_by_path(json_object_get_string(path), json_object_get_string(file), json_object_get_string(section_name), opt_temp, value);
		} else {
			if (value != NULL) {
				dmuci_delete(json_object_get_string(file), json_object_get_string(section_name), opt_temp, NULL);
				char *p = strtok(value, ",");
				while (p) {
					strip_lead_trail_whitespace(p);
					dmuci_add_list_value(json_object_get_string(file), json_object_get_string(section_name), opt_temp, p);
					p = strtok(NULL, ",");
				}
			}
		}
	}
}

static void ubus_set_value(json_object *mapping_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, char *instance, char *value)
{
	struct json_object *ubus_obj = NULL;
	struct json_object *object = NULL;
	struct json_object *method = NULL;
	struct json_object *args = NULL;
	char buf_object[256] = {0};
	char buf_method[256] = {0};
	struct ubus_arg u_args[16] = {0};
	int u_args_size = 0;

	int nbr_instances = get_number_of_instances(refparam);

	json_object_object_get_ex(mapping_obj, "ubus", &ubus_obj);
	json_object_object_get_ex(ubus_obj, "object", &object);
	json_object_object_get_ex(ubus_obj, "method", &method);
	json_object_object_get_ex(ubus_obj, "args", &args);

	if (object)
		resolve_all_symbols(ctx, data, instance, value, json_version, nbr_instances, json_object_get_string(object), buf_object, sizeof(buf_object));

	if (method)
		resolve_all_symbols(ctx, data, instance, value, json_version, nbr_instances, json_object_get_string(method), buf_method, sizeof(buf_method));

	if (args)
		u_args_size = fill_ubus_arguments(ctx, data, instance, value, nbr_instances, json_version, args, u_args);

	dmubus_call_set(buf_object, buf_method, u_args, u_args_size);

	free_ubus_arguments(u_args, u_args_size);
}

static void uci_v1_set_value(json_object *mapping_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, char *instance, char *value)
{
	struct json_object *data_s = NULL;
	struct json_object *key = NULL;

	json_object_object_get_ex(mapping_obj, "data", &data_s);
	json_object_object_get_ex(mapping_obj, "key", &key);

	/* json_object_object_get_ex is an external macro which changes the
	 * value of data_s that cppcheck can't track and throws warning as
	 * data_s value check always true. So suppressed the warning */
	// cppcheck-suppress knownConditionTrueFalse
	if (data == NULL || data_s == NULL || (data_s && strcmp(json_object_get_string(data_s), "@Parent") != 0))
		return;

	if (key) {
		dmuci_set_value_by_section((struct uci_section *)data, json_object_get_string(key), value);
	}
}

static void set_value_from_mapping(json_object *param_obj, int json_version, char *refparam, struct dmctx *ctx, void *data, char *instance, char *value)
{
	struct json_object *mapping_arr = NULL, *mapping = NULL;

	if (!param_obj)
		return;

	json_object_object_get_ex(param_obj, "mapping", &mapping_arr);
	if (mapping_arr && json_object_get_type(mapping_arr) == json_type_array) {

		for (int idx = 0; (mapping = json_object_array_get_idx(mapping_arr, idx)) != NULL; idx++) {
			struct json_object *type = NULL;
			struct json_object *rpc = NULL;

			json_object_object_get_ex(mapping, "rpc", &rpc);
			json_object_object_get_ex(mapping, "type", &type);

			if (rpc && json_version == JSON_VERSION_1 && strcmp(json_object_get_string(rpc), "set") != 0)
				continue;

			if (type && strcmp(json_object_get_string(type), "uci") == 0)
				uci_set_value(mapping, json_version, refparam, ctx, data, instance, value);
			else if (type && strcmp(json_object_get_string(type), "ubus") == 0)
				ubus_set_value(mapping, json_version, refparam, ctx, data, instance, value);
			else if (type && strcmp(json_object_get_string(type), "uci_sec") == 0 && json_version == JSON_VERSION_1)
				uci_v1_set_value(mapping, json_version, refparam, ctx, data, instance, value);
			else
				return;
		}

	}
}

static int setvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_json_obj *pleaf = NULL;
	json_object *param_obj = NULL;
	int json_version = JSON_VERSION_0;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (DM_STRCMP(pleaf->name, obj) == 0) {
			param_obj = pleaf->data;
			json_version = pleaf->json_version;
			break;
		}
	}

	switch (action) {
		case VALUECHECK:
			if (dm_validate_value(param_obj, value))
				return FAULT_9007;
			break;
		case VALUESET:
			set_value_from_mapping(param_obj, json_version, refparam, ctx, data, instance, value);
			break;
	}

	return 0;
}

static bool is_obj(char *object, json_object *jobj)
{
	json_object_object_foreach(jobj, key, json_obj) {
		if((strcmp(key, "type") == 0) && (strcmp(json_object_get_string(json_obj), "object") == 0))
			return true;
		else if((strcmp(key, "type") == 0) && (strcmp(json_object_get_string(json_obj), "object") != 0))
			return false;
	}
	return false;
}

static void parse_mapping_obj(char *object, json_object *mapping_obj, int json_version, struct list_head *list)
{
	if (!mapping_obj)
		return;

	save_json_data(list, object, mapping_obj, json_version, NULL, NULL, NULL);
}

static bool valid_event_param(char *param)
{
	bool ret;

	if (strcmp(param, "type") == 0) {
		ret = false;
	} else if (strcmp(param, "version") == 0) {
		ret = false;
	} else if (strcmp(param, "protocols") == 0) {
		ret = false;
	} else {
		ret = true;
	}

	return ret;
}

static char** fill_command_param(int count, struct json_object *obj)
{
	char **res_p = NULL;
	if (!obj)
		return res_p;

	res_p = malloc(sizeof(char *) * (count + 1));
	if (res_p) {
		res_p[count] = NULL;
		int id = 0;

		json_object_object_foreach(obj, key, res_obj) {
			res_p[id] = dm_dynamic_strdup(&json_memhead, key);
			id++;
		}
	}

	return res_p;
}

static void parse_param(char *object, char *param, json_object *jobj, DMLEAF *pleaf, int i, int json_version, struct list_head *list)
{
	/* PARAM, permission, type, getvalue, setvalue, bbfdm_type(6)*/
	struct json_object *type = NULL, *protocols = NULL, *write = NULL, *async = NULL, *version =  NULL;;
	char full_param[512] = {0};
	size_t n_proto;
	char **in_p = NULL, **out_p = NULL, **ev_arg = NULL, **tmp = NULL;

	if (!jobj || !pleaf)
		return;

	//PARAM
	pleaf[i].parameter = dm_dynamic_strdup(&json_memhead, param);

	//type
	json_object_object_get_ex(jobj, "type", &type);
	if (type && strcmp(json_object_get_string(type), "boolean") == 0)
		pleaf[i].type = DMT_BOOL;
	else if (type && strcmp(json_object_get_string(type), "unsignedInt") == 0)
		pleaf[i].type = DMT_UNINT;
	else if (type && strcmp(json_object_get_string(type), "unsignedLong") == 0)
		pleaf[i].type = DMT_UNLONG;
	else if (type && strcmp(json_object_get_string(type), "hexBinary") == 0)
		pleaf[i].type = DMT_HEXBIN;
	else if (type && strcmp(json_object_get_string(type), "int") == 0)
		pleaf[i].type = DMT_INT;
	else if (type && strcmp(json_object_get_string(type), "long") == 0)
		pleaf[i].type = DMT_LONG;
	else if (type && strcmp(json_object_get_string(type), "dateTime") == 0)
		pleaf[i].type = DMT_TIME;
	else if (type && strcmp(json_object_get_string(type), "base64") == 0)
		pleaf[i].type = DMT_BASE64;
	else if (type && strcmp(json_object_get_string(type), "command") == 0)
		pleaf[i].type = DMT_COMMAND;
	else if (type && strcmp(json_object_get_string(type), "event") == 0)
		pleaf[i].type = DMT_EVENT;
	else
		pleaf[i].type = DMT_STRING;

	//permission
	if (pleaf[i].type == DMT_EVENT) {
		pleaf[i].permission = &DMREAD;
	} else if (pleaf[i].type == DMT_COMMAND) {
		json_object_object_get_ex(jobj, "async", &async);
		pleaf[i].permission = (async && json_object_get_boolean(async)) ? &DMASYNC : &DMSYNC;
	} else {
		json_object_object_get_ex(jobj, "write", &write);
		pleaf[i].permission = (write && json_object_get_boolean(write)) ? &DMWRITE : &DMREAD;
	}

	//getvalue
	if (pleaf[i].type == DMT_EVENT) {
		int param_count = 0;
		json_object_object_foreach(jobj, key, val) {
			if (valid_event_param(key)) {
				param_count++;
				if (!ev_arg) {
					ev_arg = malloc(sizeof(char*) * param_count);
					if (!ev_arg)
						break;
				} else {
					tmp = realloc(ev_arg, sizeof(char*) * param_count);
					if (tmp == NULL) {
						FREE(ev_arg);
						break;
					}
					ev_arg = tmp;
				}

				ev_arg[param_count - 1] = dm_dynamic_strdup(&json_memhead, key);
			}
		}

		if (ev_arg) {
			param_count++;
			tmp = realloc(ev_arg, sizeof(char*) * param_count);
			if (tmp == NULL) {
				FREE(ev_arg);
			}
			ev_arg = tmp;
			ev_arg[param_count - 1] = NULL;
		}

		pleaf[i].getvalue = ev_arg ? getevent_param : NULL;
	} else if (pleaf[i].type == DMT_COMMAND) {
		struct json_object *input_obj = NULL, *output_obj = NULL;

		json_object_object_get_ex(jobj, "input", &input_obj);
		json_object_object_get_ex(jobj, "output", &output_obj);

		if (input_obj && json_object_get_type(input_obj) == json_type_object) {
			int count = json_object_object_length(input_obj);
			if (count) {
				in_p = fill_command_param(count, input_obj);
			}
		}

		if (output_obj && json_object_get_type(output_obj) == json_type_object) {
			int count = json_object_object_length(output_obj);
			if (count) {
				out_p = fill_command_param(count, output_obj);
			}
		}

		pleaf[i].getvalue = getcommand_param;
	} else {
		pleaf[i].getvalue = getvalue_param;
	}

	//setvalue
	if (pleaf[i].type == DMT_EVENT) {
		pleaf[i].setvalue = NULL;
	} else if (pleaf[i].type == DMT_COMMAND) {
		pleaf[i].setvalue = setcommand_param;
	} else {
		pleaf[i].setvalue = (write && json_object_get_boolean(write)) ? setvalue_param : NULL;
	}

	//bbfdm_type
	json_object_object_get_ex(jobj, "protocols", &protocols);
	n_proto = protocols ? json_object_array_length(protocols) : 0;
	if (n_proto == 2)
		pleaf[i].bbfdm_type = BBFDM_BOTH;
	else if (n_proto == 1) {
		struct json_object *proto = protocols ? json_object_array_get_idx(protocols, 0) : NULL;
		if (proto && strcmp(json_object_get_string(proto), "cwmp") == 0)
			pleaf[i].bbfdm_type = BBFDM_CWMP;
		else if (proto && strcmp(json_object_get_string(proto), "usp") == 0)
			pleaf[i].bbfdm_type = BBFDM_USP;
		else
			pleaf[i].bbfdm_type = BBFDM_BOTH;
	} else
		pleaf[i].bbfdm_type = BBFDM_BOTH;
	
	//Version
	json_object_object_get_ex(jobj, "version", &version);
	DM_STRNCPY(pleaf[i].version, version ? json_object_get_string(version) : "", 10);

	snprintf(full_param, sizeof(full_param), "%s%s", object, param);
	save_json_data(list, full_param, jobj, json_version, (const char**)in_p, (const char**)out_p, (const char**)ev_arg);
}

static void count_obj_param_under_jsonobj(json_object *jsonobj, int *obj_number, int *param_number)
{
	json_object_object_foreach(jsonobj, key, jobj) {
		if (json_object_get_type(jobj) == json_type_object) {
			json_object_object_foreach(jobj, key1, jobj1) {
				if ((strcmp(key1, "type") == 0) && (strcmp(json_object_get_string(jobj1), "object") == 0)) {
					(*obj_number)++;
					break;
				} else if (((strcmp(key1, "type") == 0) && (strcmp(json_object_get_string(jobj1), "object") != 0)) && (strcmp(key, "mapping") != 0)) {
					(*param_number)++;
					break;
				}
			}
		}
	}
}

static void parse_obj(char *object, json_object *jobj, DMOBJ *pobj, int index, int json_version, struct list_head *list)
{
	/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys(13)*/

	int obj_number = 0, param_number = 0, i = 0, j = 0;
	DMOBJ *next_obj = NULL;
	DMLEAF *next_leaf = NULL;

	count_obj_param_under_jsonobj(jobj, &obj_number, &param_number);
	char *obj_path = replace_str(object, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX);
	char *full_obj = replace_str(obj_path, ".{i}.", ".");
	char *curr_obj = find_current_obj(full_obj);

	if (!pobj)
		return;

	//OBJ
	pobj[index].obj = curr_obj;

	//nextobj
	if (obj_number != 0)
		next_obj = dm_dynamic_calloc(&json_memhead, obj_number+1, sizeof(struct dm_obj_s));
	else
		next_obj = NULL;

	pobj[index].nextobj = next_obj;

	//leaf
	if (param_number != 0) {
		next_leaf = dm_dynamic_calloc(&json_memhead, param_number+1, sizeof(struct dm_leaf_s));
		pobj[index].leaf = next_leaf;
	} else {
		pobj[index].leaf = NULL;
	}

	//permission: Define object as readable by default
	pobj[index].permission = &DMREAD;

	json_object_object_foreach(jobj, key, json_obj) {
		//bbfdm_type
		if (strcmp(key, "protocols") == 0) {
			size_t n_proto = json_obj ? json_object_array_length(json_obj) : 0;
			if (n_proto == 2)
				pobj[index].bbfdm_type = BBFDM_BOTH;
			else if (n_proto == 1) {
				struct json_object *proto = json_obj ? json_object_array_get_idx(json_obj, 0) : NULL;
				if (proto && strcmp(json_object_get_string(proto), "cwmp") == 0)
					pobj[index].bbfdm_type = BBFDM_CWMP;
				else if (proto && strcmp(json_object_get_string(proto), "usp") == 0)
					pobj[index].bbfdm_type = BBFDM_USP;
				else
					pobj[index].bbfdm_type = BBFDM_BOTH;
			} else
				pobj[index].bbfdm_type = BBFDM_BOTH;
		}

		if (strcmp(key, "access") == 0) {
			//permission
			pobj[index].permission = json_object_get_boolean(json_obj) ? &DMWRITE : &DMREAD;

			//addobj
			pobj[index].addobj = json_object_get_boolean(json_obj) ? add_obj : NULL;

			//delobj
			pobj[index].delobj = json_object_get_boolean(json_obj) ? delete_obj : NULL;
		}

		if (strcmp(key, "array") == 0) {
			//checkdep
			pobj[index].checkdep = NULL;

			//browseinstobj
			pobj[index].browseinstobj = json_object_get_boolean(json_obj) ? browse_obj : NULL;

			//nextdynamicobj
			pobj[index].nextdynamicobj = NULL;

			//linker
			pobj[index].get_linker = NULL;
		}
		//Version
		if (strcmp(key,"version") == 0)
			DM_STRNCPY(pobj[index].version, json_object_get_string(json_obj), 10);

		if (strcmp(key, "mapping") == 0 &&
				((json_object_get_type(json_obj) == json_type_object && json_version == JSON_VERSION_0) ||
				(json_object_get_type(json_obj) == json_type_array && json_version == JSON_VERSION_1))) {
			parse_mapping_obj(full_obj, json_obj, json_version, list);
		}

		if (json_object_get_type(json_obj) == json_type_object && is_obj(key, json_obj)) {
			parse_obj(key, json_obj, next_obj, j, json_version, list);
			j++;
		}

		if (json_object_get_type(json_obj) == json_type_object && !is_obj(key, json_obj) && strcmp(key, "mapping") != 0) {
			parse_param(full_obj, key, json_obj, next_leaf, i, json_version, list);
			i++;
		}
	}
}

int load_json_dynamic_arrays(struct dmctx *ctx)
{
	struct dirent *ent = NULL;
	DIR *dir = NULL;

	if (folder_exists(JSON_FOLDER_PATH)) {
		sysfs_foreach_file(JSON_FOLDER_PATH, dir, ent) {

			if (!strstr(ent->d_name, ".json"))
				continue;

			char buf[512] = {0};
			int json_plugin_version = JSON_VERSION_0;

			snprintf(buf, sizeof(buf), "%s/%s", JSON_FOLDER_PATH, ent->d_name);

			json_object *json = json_object_from_file(buf);
			if (!json) continue;

			json_object_object_foreach(json, key, jobj) {
				if (!key)
					break;

				if (strcmp(key, "json_plugin_version") == 0) {
					json_plugin_version = json_object_get_int(jobj);
					continue;
				}

				DMOBJ *dm_entryobj = NULL;

				char *obj_path = replace_str(key, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX);
				char *obj_prefix = find_prefix_obj(obj_path);

				bool obj_exists = find_root_entry(ctx, obj_prefix, &dm_entryobj);
				if (obj_exists == 0 || !dm_entryobj)
					continue;

				if (dm_entryobj->nextdynamicobj == NULL) {
					dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
					dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
					dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
					dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
				}

				if (dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj == NULL) {
					dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj = calloc(2, sizeof(struct dm_obj_s *));
				}

				if (dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0] == NULL) {
					dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0] = dm_dynamic_calloc(&json_memhead, 2, sizeof(struct dm_obj_s));
					parse_obj(obj_path, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0], 0, json_plugin_version, &json_list);
				} else {
					int idx = get_index_of_available_entry(dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0]);
					dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0] = dm_dynamic_realloc(&json_memhead, dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
					memset(dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
					parse_obj(obj_path, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0], idx, json_plugin_version, &json_list);
				}
			}
			save_loaded_json_files(&loaded_json_files, json);
		}
		if (dir) closedir(dir);
	}
	return 0;
}
