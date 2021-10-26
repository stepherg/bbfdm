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

#ifdef BBFDM_ENABLE_JSON_PLUGIN

#define json_object_get_string(x) (char *)json_object_get_string(x)

static LIST_HEAD(loaded_json_files);
static LIST_HEAD(json_list);
static LIST_HEAD(json_memhead);

struct loaded_json_file
{
	struct list_head list;
	json_object *data;
};

struct dm_json_obj {
	struct list_head list;
	json_object *data;
	char *name;
};

static void save_json_data(struct list_head *json_list, char *name, json_object *data)
{
	struct dm_json_obj *dm_json_obj = dm_dynamic_calloc(&json_memhead, 1, sizeof(struct dm_json_obj));

	if (name) dm_json_obj->name = dm_dynamic_strdup(&json_memhead, name);
	if (data) dm_json_obj->data = data;
	list_add_tail(&dm_json_obj->list, json_list);
}

static void free_json_data(struct list_head *json_list)
{
	struct dm_json_obj *dm_json_obj = NULL;

	while (json_list->next != json_list) {
		dm_json_obj = list_entry(json_list->next, struct dm_json_obj, list);
		list_del(&dm_json_obj->list);
		dmfree(dm_json_obj->name);
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
		if (atoi(pch) == 0) {
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

static int browse_obj(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_json_obj *pobj = NULL;
	struct json_object *mapping_obj = NULL;
	struct json_object *type = NULL;

	char *obj = generate_path_without_instance(parent_node->current_object, true);
	list_for_each_entry(pobj, &json_list, list) {
		if (strcmp(pobj->name, obj) == 0) {
			mapping_obj = pobj->data;
			break;
		}
	}

	json_object_object_get_ex(mapping_obj, "type", &type);
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

		json_object_object_get_ex(mapping_obj, "uci", &uci_obj);
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
		char *args1 = NULL;

		json_object_object_get_ex(mapping_obj, "ubus", &ubus_obj);
		json_object_object_get_ex(ubus_obj, "object", &object);
		json_object_object_get_ex(ubus_obj, "method", &method);
		json_object_object_get_ex(ubus_obj, "args", &args_obj);
		json_object_object_foreach(args_obj, arg1, args2) {
			args1 = arg1;
		}
		json_object_object_get_ex(ubus_obj, "key", &key);

		if (object && method && args1 && args2)
			dmubus_call(json_object_get_string(object), json_object_get_string(method), UBUS_ARGS{{args1, json_object_get_string(args2), String}}, 1, &res);
		else
			dmubus_call(json_object_get_string(object), json_object_get_string(method), UBUS_ARGS{0}, 0, &res);
		if (res && key) {
			int id = 0, i = 0;

			dmjson_foreach_obj_in_array(res, arrobj, dyn_obj, i, 1, json_object_get_string(key)) {
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
	struct json_object *type = NULL;

	char *obj = generate_path_without_instance(refparam, true);
	list_for_each_entry(pobj, &json_list, list) {
		if (strcmp(pobj->name, obj) == 0) {
			mapping_obj = pobj->data;
			break;
		}
	}

	json_object_object_get_ex(mapping_obj, "type", &type);
	if (type && strcmp(json_object_get_string(type), "uci") == 0) {
		struct json_object *uci_obj = NULL;
		struct json_object *file = NULL;
		struct json_object *section = NULL;
		struct json_object *section_type = NULL;
		struct json_object *dmmap_file = NULL;
		char *object = NULL;
		char buf_instance[64];

		json_object_object_get_ex(mapping_obj, "uci", &uci_obj);
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
			struct uci_section *section = NULL, *dmmap = NULL;

			dmuci_add_section(json_object_get_string(file), json_object_get_string(section_type), &section);

			dmuci_add_section_bbfdm(json_object_get_string(dmmap_file), json_object_get_string(section_type), &dmmap);
			dmuci_set_value_by_section(dmmap, "section_name", section_name(section));
			dmuci_set_value_by_section(dmmap, buf_instance, *instance);
		}
	}

	return 0;
}

static int delete_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dm_json_obj *pobj = NULL;
	struct json_object *mapping_obj = NULL;
	struct json_object *type_obj = NULL;

	char *obj = generate_path_without_instance(refparam, true);
	list_for_each_entry(pobj, &json_list, list) {
		if (strcmp(pobj->name, obj) == 0) {
			mapping_obj = pobj->data;
			break;
		}
	}

	json_object_object_get_ex(mapping_obj, "type", &type_obj);
	if (type_obj && strcmp(json_object_get_string(type_obj), "uci") == 0) {
		struct json_object *uci_obj = NULL;
		struct json_object *file = NULL;
		struct json_object *section = NULL;
		struct json_object *section_type = NULL;
		struct json_object *dmmap_file = NULL;

		json_object_object_get_ex(mapping_obj, "uci", &uci_obj);
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

static char *get_param_ubus_value(json_object *json_obj, char *arguments)
{
	char *value = "";

	char *opt = strchr(arguments, '.');
	if (opt) {
		*opt = '\0';
		value = dmjson_get_value(json_obj, 2, arguments, opt + 1);
	} else {
		value = dmjson_get_value(json_obj, 1, arguments);
	}

	return value;
}

static char *uci_get_value(json_object *mapping_obj, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *obj = NULL;
	struct json_object *file = NULL;
	struct json_object *section = NULL;
	struct json_object *type = NULL;
	struct json_object *section_name = NULL;
	struct json_object *option = NULL;
	struct json_object *option_name = NULL;
	struct json_object *path = NULL;
	struct json_object *ref = NULL;
	char *value = "";

	json_object_object_get_ex(mapping_obj, "uci", &obj);
	json_object_object_get_ex(obj, "file", &file);
	json_object_object_get_ex(obj, "section", &section);
	json_object_object_get_ex(section, "type", &type);
	json_object_object_get_ex(section, "name", &section_name);
	json_object_object_get_ex(obj, "option", &option);
	json_object_object_get_ex(option, "name", &option_name);
	json_object_object_get_ex(obj, "path", &path);
	json_object_object_get_ex(obj, "ref", &ref);

	if (data && file && type && option_name) {
		if (strcmp(json_object_get_string(option_name), "@Name") == 0) {
			dmasprintf(&value, "%s", section_name((struct uci_section *)data));
		} else {
			char uci_type[32] = {0};
			snprintf(uci_type, sizeof(uci_type), "@%s[%d]", json_object_get_string(type), instance ? atoi(instance)-1 : 0);
			value = bbf_uci_get_value(json_object_get_string(path), json_object_get_string(file), uci_type, json_object_get_string(option_name));
			if (ref) {
				char *linker = dmstrdup(value);
				adm_entry_get_linker_param(ctx, json_object_get_string(path), linker, &value);
				dmfree(linker);
				if (value == NULL)
					value = "";
			}
		}
	} else if (file && section_name && option_name) {
		value = bbf_uci_get_value(json_object_get_string(path), json_object_get_string(file), json_object_get_string(section_name), json_object_get_string(option_name));
	}

	if (strstr(refparam, "Alias") && value[0] == '\0')
		dmasprintf(&value, "cpe-%s", instance);

	return value;
}

static char *ubus_get_value(json_object *mapping_obj, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *ubus_obj = NULL;
	struct json_object *object = NULL;
	struct json_object *method = NULL;
	struct json_object *key = NULL;
	struct json_object *args = NULL;
	struct json_object *res = NULL;
	char arg2_1[128] = {0}, *opt = NULL;
	char *args1 = NULL;
	char *value = "";

	json_object_object_get_ex(mapping_obj, "ubus", &ubus_obj);
	json_object_object_get_ex(ubus_obj, "object", &object);
	json_object_object_get_ex(ubus_obj, "method", &method);
	json_object_object_get_ex(ubus_obj, "args", &args);
	json_object_object_foreach(args, arg1, args2) {
		args1 = arg1;
	}
	json_object_object_get_ex(ubus_obj, "key", &key);

	if ((opt = strstr(json_object_get_string(object), "@Name"))) {
		*opt = '\0';
		snprintf(arg2_1, sizeof(arg2_1), "%s%s", json_object_get_string(object), section_name((struct uci_section *)data));
	} else if ((opt = strstr(json_object_get_string(object), "@i-1"))) {
		*opt = '\0';
		snprintf(arg2_1, sizeof(arg2_1), "%s%d", json_object_get_string(object), atoi(instance) - 1);
	} else {
		DM_STRNCPY(arg2_1, json_object_get_string(object), sizeof(arg2_1));
	}

	if (args1 && args2) {
		if (data && (strcmp(json_object_get_string(args2), "@Name") == 0))
			dmubus_call(arg2_1, json_object_get_string(method), UBUS_ARGS{{args1, section_name((struct uci_section *)data), String}}, 1, &res);
		else
			dmubus_call(arg2_1, json_object_get_string(method), UBUS_ARGS{{args1, json_object_get_string(args2), String}}, 1, &res);
	} else {
		dmubus_call(arg2_1, json_object_get_string(method), UBUS_ARGS{0}, 0, &res);
	}

	if (json_object_get_string(key)) {
		char arg6_buf[128] = "";

		DM_STRNCPY(arg6_buf, json_object_get_string(key), sizeof(arg6_buf));
		char *is_array = strstr(arg6_buf, "[@i-1]");
		if (is_array) {
			char *arguments = is_array + sizeof("[@i-1]");
			value = get_param_ubus_value((json_object *)data, arguments);
		} else {
			value = get_param_ubus_value(res, arg6_buf);
		}
	}

	return value;
}

static char *get_value_from_mapping(json_object *param_obj, char *refparam, struct dmctx *ctx, void *data, char *instance)
{
	struct json_object *mapping_arr = NULL, *mapping = NULL;

	if (!param_obj)
		return "";

	json_object_object_get_ex(param_obj, "mapping", &mapping_arr);
	if (mapping_arr && json_object_get_type(mapping_arr) == json_type_array)
		mapping = json_object_array_get_idx(mapping_arr, 0);

	if (mapping) {
		struct json_object *type = NULL;

		json_object_object_get_ex(mapping, "type", &type);

		if (type && strcmp(json_object_get_string(type), "uci") == 0)
			return uci_get_value(mapping, refparam, ctx, data, instance);
		else if (type && strcmp(json_object_get_string(type), "ubus") == 0)
			return ubus_get_value(mapping, refparam, ctx, data, instance);
		else
			return "";
	}

	return "";
}

static int getvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_json_obj *pleaf = NULL;
	json_object *param_obj = NULL;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			param_obj = pleaf->data;
			break;
		}
	}

	*value = get_value_from_mapping(param_obj, refparam, ctx, data, instance);
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

		*min_length = range_min ? atoi(json_object_get_string(range_min)) : -1;
		*max_length = range_max ? atoi(json_object_get_string(range_max)) : -1;
	}

	json_object_object_get_ex(json_obj, "enumerations", &enum_obj);
	if (enum_obj && json_object_get_type(enum_obj) == json_type_array) {
		int enum_len = (enum_obj) ? json_object_array_length(enum_obj) + 1 : 1;

		for (int i = 0; i < enum_len - 1; i++) {
			struct json_object *enum_val = NULL;

			if ((enum_val = json_object_array_get_idx(enum_obj, i)) == NULL)
				return -1;

			enumeration[i] = json_object_get_string(enum_val);

		}
		enumeration[enum_len - 1] = NULL;

	}

	json_object_object_get_ex(json_obj, "pattern", &pattern_obj);
	if (pattern_obj && json_object_get_type(pattern_obj) == json_type_array) {
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
			max_size = maxsize ? atoi(json_object_get_string(maxsize)) : -1;

			json_object_object_get_ex(list_obj, "item", &item_obj);
			if (item_obj) {
				struct json_object *item_min = NULL;
				struct json_object *item_max = NULL;

				json_object_object_get_ex(item_obj, "min", &item_min);
				json_object_object_get_ex(item_obj, "max", &item_max);
				min_item = item_min ? atoi(json_object_get_string(item_min)) : -1;
				max_item = item_max ? atoi(json_object_get_string(item_max)) : -1;
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

static void set_value_from_mapping(json_object *param_obj, char *refparam, struct dmctx *ctx, void *data, char *instance, char *value)
{
	struct json_object *mapping_arr = NULL, *mapping = NULL;

	if (!param_obj)
		return;

	json_object_object_get_ex(param_obj, "mapping", &mapping_arr);
	if (mapping_arr && json_object_get_type(mapping_arr) == json_type_array)
		mapping = json_object_array_get_idx(mapping_arr, 0);

	if (mapping) {
		struct json_object *type = NULL;

		json_object_object_get_ex(mapping, "type", &type);

		if (type && strcmp(json_object_get_string(type), "uci") == 0) {
			struct json_object *uci_obj = NULL;
			struct json_object *file = NULL;
			struct json_object *section = NULL;
			struct json_object *section_name = NULL;
			struct json_object *option = NULL;
			struct json_object *option_name = NULL;
			struct json_object *path = NULL;
			struct json_object *ref = NULL;

			json_object_object_get_ex(mapping, "uci", &uci_obj);
			json_object_object_get_ex(uci_obj, "file", &file);
			json_object_object_get_ex(uci_obj, "section", &section);
			json_object_object_get_ex(section, "type", &type);
			json_object_object_get_ex(section, "name", &section_name);
			json_object_object_get_ex(uci_obj, "option", &option);
			json_object_object_get_ex(option, "name", &option_name);
			json_object_object_get_ex(uci_obj, "path", &path);
			json_object_object_get_ex(uci_obj, "ref", &ref);

			if (data && file && type && option_name) {
				char uci_type[32] = {0};
				snprintf(uci_type, sizeof(uci_type), "@%s[%d]", json_object_get_string(type), instance ? atoi(instance)-1 : 0);
				if (ref) {
					char *linker;
					adm_entry_get_linker_value(ctx, value, &linker);
					if (linker) bbf_uci_set_value(json_object_get_string(path), json_object_get_string(file), uci_type, json_object_get_string(option_name), linker);
					dmfree(linker);
				} else {
					bbf_uci_set_value(json_object_get_string(path), json_object_get_string(file), uci_type, json_object_get_string(option_name), value);
				}
			} else if (file && section_name && option_name) {
				bbf_uci_set_value(json_object_get_string(path), json_object_get_string(file), json_object_get_string(section_name), json_object_get_string(option_name), value);
			}
		} else
			return;
	}
}

static int setvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_json_obj *pleaf = NULL;
	json_object *param_obj = NULL;

	char *obj = generate_path_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			param_obj = pleaf->data;
			break;
		}
	}

	switch (action) {
		case VALUECHECK:
			if (dm_validate_value(param_obj, value))
				return FAULT_9007;
			break;
		case VALUESET:
			set_value_from_mapping(param_obj, refparam, ctx, data, instance, value);
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

static void parse_mapping_obj(char *object, json_object *mapping_obj, struct list_head *list)
{
	if (!mapping_obj)
		return;

	save_json_data(list, object, mapping_obj);
}

static void parse_param(char *object, char *param, json_object *jobj, DMLEAF *pleaf, int i, struct list_head *list)
{
	/* PARAM, permission, type, getvalue, setvalue, bbfdm_type(6)*/
	struct json_object *type = NULL, *protocols = NULL, *write = NULL;
	char full_param[512] = {0};
	size_t n_proto;

	if (!jobj || !pleaf)
		return;

	//PARAM
	pleaf[i].parameter = dm_dynamic_strdup(&json_memhead, param);

	//permission
	json_object_object_get_ex(jobj, "write", &write);
	pleaf[i].permission = (write && json_object_get_boolean(write)) ? &DMWRITE : &DMREAD;

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
	else
		pleaf[i].type = DMT_STRING;

	//getvalue
	pleaf[i].getvalue = getvalue_param;

	//setvalue
	pleaf[i].setvalue = (write && json_object_get_boolean(write)) ? setvalue_param : NULL;

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

	snprintf(full_param, sizeof(full_param), "%s%s", object, param);
	save_json_data(list, full_param, jobj);
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

static void parse_obj(char *object, json_object *jobj, DMOBJ *pobj, int index, struct list_head *list)
{
	/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys(13)*/

	int obj_number = 0, param_number = 0, i = 0, j = 0;
	DMOBJ *next_obj = NULL;
	DMLEAF *next_leaf = NULL;

	count_obj_param_under_jsonobj(jobj, &obj_number, &param_number);
	char *full_obj = replace_str(object, ".{i}.", ".");
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

		if (strcmp(key, "mapping") == 0 && json_object_get_type(json_obj) == json_type_object) {
			parse_mapping_obj(full_obj, json_obj, list);
		}

		if (json_object_get_type(json_obj) == json_type_object && is_obj(key, json_obj)) {
			parse_obj(key, json_obj, next_obj, j, list);
			j++;
		}

		if (json_object_get_type(json_obj) == json_type_object && !is_obj(key, json_obj) && strcmp(key, "mapping") != 0) {
			parse_param(full_obj, key, json_obj, next_leaf, i, list);
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
			snprintf(buf, sizeof(buf), "%s/%s", JSON_FOLDER_PATH, ent->d_name);

			json_object *json = json_object_from_file(buf);
			if (!json) continue;

			json_object_object_foreach(json, key, jobj) {
				if (!key)
					break;

				DMOBJ *dm_entryobj = NULL;
				char *obj_prefix = find_prefix_obj(key);

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
					parse_obj(key, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0], 0, &json_list);
				} else {
					int idx = get_index_of_available_entry(dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0]);
					dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0] = dm_dynamic_realloc(&json_memhead, dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
					memset(dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
					parse_obj(key, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].nextobj[0], idx, &json_list);
				}
			}
			save_loaded_json_files(&loaded_json_files, json);
		}
		if (dir) closedir(dir);
	}
	return 0;
}

#endif  /* BBFDM_ENABLE_JSON_PLUGIN */
