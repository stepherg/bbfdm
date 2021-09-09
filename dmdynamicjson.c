/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmdynamicjson.h"
#include "dmdynamicmem.h"
#include "dmentry.h"

LIST_HEAD(json_list);
LIST_HEAD(json_memhead);

static void add_json_data_to_list(struct list_head *dup_list, char *name, char *arg1, const char *arg2, const char *arg3, const char *arg4,
					const char *arg5, const char *arg6, const char *arg7, const char *arg8)
{
	struct dm_json_parameter *dm_json_parameter = dm_dynamic_calloc(&json_memhead, 1, sizeof(struct dm_json_parameter));

	list_add_tail(&dm_json_parameter->list, dup_list);
	if (name) dm_json_parameter->name = dm_dynamic_strdup(&json_memhead, name);
	if (arg1) dm_json_parameter->arg1 = dm_dynamic_strdup(&json_memhead, arg1);
	if (arg2) dm_json_parameter->arg2 = dm_dynamic_strdup(&json_memhead, arg2);
	if (arg3) dm_json_parameter->arg3 = dm_dynamic_strdup(&json_memhead, arg3);
	if (arg4) dm_json_parameter->arg4 = dm_dynamic_strdup(&json_memhead, arg4);
	if (arg5) dm_json_parameter->arg5 = dm_dynamic_strdup(&json_memhead, arg5);
	if (arg6) dm_json_parameter->arg6 = dm_dynamic_strdup(&json_memhead, arg6);
	if (arg7) dm_json_parameter->arg7 = dm_dynamic_strdup(&json_memhead, arg7);
	if (arg8) dm_json_parameter->arg8 = dm_dynamic_strdup(&json_memhead, arg8);
}

static void delete_json_data_from_list(struct dm_json_parameter *dm_json_parameter)
{
	list_del(&dm_json_parameter->list);
	if (dm_json_parameter->name) dm_dynamic_free(dm_json_parameter->name);
	if (dm_json_parameter->arg1) dm_dynamic_free(dm_json_parameter->arg1);
	if (dm_json_parameter->arg2) dm_dynamic_free(dm_json_parameter->arg2);
	if (dm_json_parameter->arg3) dm_dynamic_free(dm_json_parameter->arg3);
	if (dm_json_parameter->arg4) dm_dynamic_free(dm_json_parameter->arg4);
	if (dm_json_parameter->arg5) dm_dynamic_free(dm_json_parameter->arg5);
	if (dm_json_parameter->arg6) dm_dynamic_free(dm_json_parameter->arg6);
	if (dm_json_parameter->arg7) dm_dynamic_free(dm_json_parameter->arg7);
	if (dm_json_parameter->arg8) dm_dynamic_free(dm_json_parameter->arg8);
	if (dm_json_parameter) dm_dynamic_free(dm_json_parameter);
}

static void free_json_data_from_list(struct list_head *dup_list)
{
	struct dm_json_parameter *dm_json_parameter = NULL;

	while (dup_list->next != dup_list) {
		dm_json_parameter = list_entry(dup_list->next, struct dm_json_parameter, list);
		delete_json_data_from_list(dm_json_parameter);
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
	free_json_data_from_list(&json_list);
	dm_dynamic_cleanmem(&json_memhead);
	free_node_object_tree_dynamic_array(dm_entryobj);
	return 0;
}

static void generate_prefixobj_and_obj_full_obj(char *full_obj, char **prefix_obj, char **obj)
{
	char *pch = NULL, *pchr = NULL, *tmp_obj = NULL;

	char *full_object = replace_str(full_obj, ".{i}.", ".");
	char *str = dm_dynamic_strdup(&json_memhead, full_object);
	for (pch = strtok_r(str, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (pchr != NULL && *pchr != '\0') {
			if (*prefix_obj == NULL) {
				dm_dynamic_asprintf(&json_memhead, prefix_obj, "%s.", pch);
			} else {
				tmp_obj = dm_dynamic_strdup(&json_memhead, *prefix_obj);
				dm_dynamic_free(*prefix_obj);
				dm_dynamic_asprintf(&json_memhead, prefix_obj, "%s%s.", tmp_obj, pch);
				dm_dynamic_free(tmp_obj);
			}
		} else {
			*obj = dm_dynamic_strdup(&json_memhead, pch);
		}
	}
	dm_dynamic_free(str);
	dmfree(full_object);
}

static char *generate_obj_without_instance(char *full_obj, bool is_obj)
{
	char *pch = NULL, *pchr = NULL, *tmp_obj = NULL, *obj = NULL;

	char *str = dm_dynamic_strdup(&json_memhead, full_obj);
	for (pch = strtok_r(str, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (atoi(pch) == 0) {
			if (obj == NULL) {
				dm_dynamic_asprintf(&json_memhead, &obj, "%s.", pch);
			} else {
				tmp_obj = dm_dynamic_strdup(&json_memhead, obj);
				dm_dynamic_free(obj);
				if (is_obj)
					dm_dynamic_asprintf(&json_memhead, &obj, "%s%s.", tmp_obj, pch);
				else {
					if (pchr != NULL && *pchr != '\0')
						dm_dynamic_asprintf(&json_memhead, &obj, "%s%s.", tmp_obj, pch);
					else
						dm_dynamic_asprintf(&json_memhead, &obj, "%s%s", tmp_obj, pch);
				}
				dm_dynamic_free(tmp_obj);
			}
		}
	}
	if(str) dm_dynamic_free(str);
	return obj;
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
	struct dm_json_parameter *pleaf = NULL;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *arg5 = NULL, *arg6 = NULL;

	char *obj = generate_obj_without_instance(parent_node->current_object, true);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			arg5 = pleaf->arg5;
			arg6 = pleaf->arg6;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

		char buf_instance[64], buf_alias[64], *prefix_obj = NULL, *object = NULL;
		char *inst = NULL;
		struct dmmap_dup *p = NULL;
		LIST_HEAD(dup_list);

		generate_prefixobj_and_obj_full_obj(parent_node->current_object, &prefix_obj, &object);
		snprintf(buf_instance, sizeof(buf_instance), "%s_instance", object);
		snprintf(buf_alias, sizeof(buf_alias), "%s_alias", object);
		for (int i = 0; buf_instance[i]; i++)
			buf_instance[i] = tolower(buf_instance[i]);

		for (int i = 0; buf_alias[i]; i++)
			buf_alias[i] = tolower(buf_alias[i]);

		if(arg2 && arg3 && arg4) {
			synchronize_specific_config_sections_with_dmmap(arg2, arg3, arg4, &dup_list);
			list_for_each_entry(p, &dup_list, list) {

				inst = handle_instance(dmctx, parent_node, p->dmmap_section, buf_instance, buf_alias);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
					break;
			}
		}
		free_dmmap_config_dup_list(&dup_list);
	}
	else if (arg1 && strcmp(arg1, "ubus") == 0) {
		//UBUS: arg1=type :: arg2=ubus_object :: arg3=ubus_method :: arg4=ubus_args1 :: arg5=ubus_args2 :: arg6=ubus_key

		json_object *res = NULL, *dyn_obj = NULL, *arrobj = NULL;

		if (arg2 && arg3 && arg4 && arg5)
			dmubus_call(arg2, arg3, UBUS_ARGS{{arg4, arg5, String}}, 1, &res);
		else
			dmubus_call(arg2, arg3, UBUS_ARGS{{}}, 0, &res);
		if (res && arg6) {
			int id = 0, j = 0;

			dmjson_foreach_obj_in_array(res, arrobj, dyn_obj, j, 1, arg6) {
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
	//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *prefix_obj = NULL, *object = NULL;
	struct dm_json_parameter *pleaf = NULL;

	char *obj = generate_obj_without_instance(refparam, true);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		char buf_instance[64];

		generate_prefixobj_and_obj_full_obj(refparam, &prefix_obj, &object);
		snprintf(buf_instance, sizeof(buf_instance), "%s_instance", object);
		for (int i = 0; buf_instance[i]; i++) {
			buf_instance[i] = tolower(buf_instance[i]);
		}

		if(arg2 && arg3 && arg4) {
			struct uci_section *section = NULL, *dmmap = NULL;

			dmuci_add_section(arg2, arg3, &section);

			dmuci_add_section_bbfdm(arg4, arg3, &dmmap);
			dmuci_set_value_by_section(dmmap, "section_name", section_name(section));
			dmuci_set_value_by_section(dmmap, buf_instance, *instance);
		}
	}
	return 0;
}

static int delete_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL;
	struct dm_json_parameter *pleaf = NULL;

	char *obj = generate_obj_without_instance(refparam, true);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		if(arg2 && arg3 && arg4) {
			struct uci_section *s = NULL, *stmp = NULL, *dmmap_section= NULL;

			switch (del_action) {
				case DEL_INST:
					get_dmmap_section_of_config_section(arg4, arg3, section_name((struct uci_section *)data), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);

					dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
					break;
				case DEL_ALL:
					uci_foreach_sections_safe(arg2, arg3, stmp, s) {
						get_dmmap_section_of_config_section(arg4, arg3, section_name(s), &dmmap_section);
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

static int getvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_json_parameter *pleaf = NULL;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *arg5 = NULL, *arg6 = NULL, *arg7 = NULL, *arg8 = NULL;

	char *obj = generate_obj_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			arg5 = pleaf->arg5;
			arg6 = pleaf->arg6;
			arg7 = pleaf->arg7;
			arg8 = pleaf->arg8;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_section_name :: arg5=uci_section_index :: arg6=uci_option_name :: arg7=path :: arg8=ref

		if (data && arg2 && arg3 && arg6) {
			if (strcmp(arg6, "@Name") == 0) {
				dmasprintf(value, "%s", section_name((struct uci_section *)data));
			} else {
				char uci_type[32] = {0};
				snprintf(uci_type, sizeof(uci_type), "@%s[%d]", arg3, instance ? atoi(instance)-1 : 0);
				*value = bbf_uci_get_value(arg7, arg2, uci_type, arg6);
				if (arg8) {
					char *linker = dmstrdup(*value);
					adm_entry_get_linker_param(ctx, arg7, linker, value);
					dmfree(linker);
					if (*value == NULL)
						*value = "";
				}
			}
		} else if (arg2 && arg4 && arg6) {
			*value = bbf_uci_get_value(arg7, arg2, arg4, arg6);
		}

		if (strstr(refparam, "Alias") && (*value)[0] == '\0')
			dmasprintf(value, "cpe-%s", instance);
	} else if (arg1 && strcmp(arg1, "ubus") == 0) {
		//UBUS: arg1=type :: arg2=ubus_object :: arg3=ubus_method :: arg4=ubus_args1 :: arg5=ubus_args2 :: arg6=ubus_key

		json_object *res = NULL;
		char arg2_1[128] = {0}, *opt = NULL;
		if ((opt = strstr(arg2, "@Name"))) {
			*opt = '\0';
			snprintf(arg2_1, sizeof(arg2_1), "%s%s", arg2, section_name((struct uci_section *)data));
		} else if ((opt = strstr(arg2, "@i-1"))) {
			*opt = '\0';
			snprintf(arg2_1, sizeof(arg2_1), "%s%d", arg2, atoi(instance) - 1);
		} else {
			DM_STRNCPY(arg2_1, arg2, sizeof(arg2_1));
		}

		if (arg4 && arg5) {
			if (data && (strcmp(arg5, "@Name") == 0))
				dmubus_call(arg2_1, arg3, UBUS_ARGS{{arg4, section_name((struct uci_section *)data), String}}, 1, &res);
			else
				dmubus_call(arg2_1, arg3, UBUS_ARGS{{arg4, arg5, String}}, 1, &res);
		} else {
			dmubus_call(arg2_1, arg3, UBUS_ARGS{{}}, 0, &res);
		}

		DM_ASSERT(res, *value = "");

		if (arg6) {
			char arg6_buf[128] = "";

			DM_STRNCPY(arg6_buf, arg6, sizeof(arg6_buf));
			char *is_array = strstr(arg6_buf, "[@i-1]");
			if (is_array) {
				char *arguments = is_array + sizeof("[@i-1]");
				*value = get_param_ubus_value((json_object *)data, arguments);
			} else {
				*value = get_param_ubus_value(res, arg6_buf);
			}
		}
	} else {
		*value = "";
	}

	return 0;
}

static int setvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_json_parameter *pleaf = NULL;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *arg6 = NULL, *arg7 = NULL, *arg8 = NULL;

	char *obj = generate_obj_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			arg6 = pleaf->arg6;
			arg7 = pleaf->arg7;
			arg8 = pleaf->arg8;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_section_name :: arg5=uci_section_index :: arg6=uci_option_name  :: arg7=path :: arg8=ref

		switch (action) {
			case VALUECHECK:
				break;
			case VALUESET:
				if (data && arg2 && arg3 && arg6) {
					char uci_type[32] = {0};
					snprintf(uci_type, sizeof(uci_type), "@%s[%d]", arg3, instance ? atoi(instance)-1 : 0);
					if (arg8) {
						char *linker;
						adm_entry_get_linker_value(ctx, value, &linker);
						if (linker) bbf_uci_set_value(arg7, arg2, uci_type, arg6, linker);
						dmfree(linker);
					} else {
						bbf_uci_set_value(arg7, arg2, uci_type, arg6, value);
					}
				} else if (arg2 && arg4 && arg6) {
					bbf_uci_set_value(arg7, arg2, arg4, arg6, value);
				}
				break;
		}
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

static void parse_mapping_obj(char *object, json_object *mapping, struct list_head *list)
{
	if (!mapping)
		return;

	struct json_object *type = NULL, *obj = NULL;
	json_object_object_get_ex(mapping, "type", &type);

	if (type && strcmp(json_object_get_string(type), "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

		struct json_object *file, *section, *section_type, *dmmap_file;
		json_object_object_get_ex(mapping, "uci", &obj);
		json_object_object_get_ex(obj, "file", &file);
		json_object_object_get_ex(obj, "section", &section);
		json_object_object_get_ex(section, "type", &section_type);
		json_object_object_get_ex(obj, "dmmapfile", &dmmap_file);

		//Add to list
		add_json_data_to_list(list, object, "uci", json_object_get_string(file), json_object_get_string(section_type), json_object_get_string(dmmap_file), "", "", "", "");
	}
	else if (type && strcmp(json_object_get_string(type), "ubus") == 0) {
		//UBUS: arg1=type :: arg2=ubus_object :: arg3=ubus_method :: arg4=ubus_args1 :: arg5=ubus_args2 :: arg6=ubus_key

		struct json_object *obj1, *method, *key, *args;
		char *args1 = NULL;
		json_object_object_get_ex(mapping, "ubus", &obj);
		json_object_object_get_ex(obj, "object", &obj1);
		json_object_object_get_ex(obj, "method", &method);
		json_object_object_get_ex(obj, "args", &args);
		json_object_object_foreach(args, arg1, args2) {
			args1 = arg1;
		}
		json_object_object_get_ex(obj, "key", &key);

		//Add to list
		add_json_data_to_list(list, object, "ubus", json_object_get_string(obj1), json_object_get_string(method), args1, json_object_get_string(args2), json_object_get_string(key), "", "");
	}
}

static void parse_mapping_param(char *parameter, json_object *mapping, struct list_head *list)
{
	if (!mapping)
		return;

	struct json_object *type = NULL, *obj = NULL;
	json_object_object_get_ex(mapping, "type", &type);

	if (type && strcmp(json_object_get_string(type), "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_section_name :: arg5=uci_section_index :: arg6=uci_option_name  :: arg7=path :: arg8=ref

		struct json_object *file, *section, *type, *section_name, *index, *option, *option_name, *path, *ref;
		json_object_object_get_ex(mapping, "uci", &obj);
		json_object_object_get_ex(obj, "file", &file);
		json_object_object_get_ex(obj, "section", &section);
		json_object_object_get_ex(section, "type", &type);
		json_object_object_get_ex(section, "name", &section_name);
		json_object_object_get_ex(section, "index", &index);
		json_object_object_get_ex(obj, "option", &option);
		json_object_object_get_ex(option, "name", &option_name);
		json_object_object_get_ex(obj, "path", &path);
		json_object_object_get_ex(obj, "ref", &ref);

		//Add to list
		add_json_data_to_list(list, parameter, "uci", json_object_get_string(file), json_object_get_string(type), json_object_get_string(section_name), json_object_get_string(index),
							json_object_get_string(option_name), json_object_get_string(path), json_object_get_string(ref));
	}
	else if (type && strcmp(json_object_get_string(type), "ubus") == 0) {
		//UBUS: arg1=type :: arg2=ubus_object :: arg3=ubus_method :: arg4=ubus_args1 :: arg5=ubus_args2 :: arg6=ubus_key

		struct json_object *object, *method, *key, *args;
		char *args1 = NULL;
		json_object_object_get_ex(mapping, "ubus", &obj);
		json_object_object_get_ex(obj, "object", &object);
		json_object_object_get_ex(obj, "method", &method);
		json_object_object_get_ex(obj, "args", &args);
		json_object_object_foreach(args, arg1, args2) {
			args1 = arg1;
		}
		json_object_object_get_ex(obj, "key", &key);

		//Add to list
		add_json_data_to_list(list, parameter, "ubus", json_object_get_string(object), json_object_get_string(method), args1, json_object_get_string(args2), json_object_get_string(key), "", "");
	}
}

static void parse_param(char *object, char *param, json_object *jobj, DMLEAF *pleaf, int i, struct list_head *list)
{
	/* PARAM, permission, type, getvalue, setvalue, bbfdm_type(6)*/
	struct json_object *type = NULL, *protocols = NULL, *write = NULL, *mapping_arr = NULL, *mapping = NULL;
	char full_param[256] = {0};
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
	json_object_object_get_ex(jobj, "mapping", &mapping_arr);
	if (mapping_arr && json_object_get_type(mapping_arr) == json_type_array)
		mapping = json_object_array_get_idx(mapping_arr, 0);
	else
		mapping = NULL;
	parse_mapping_param(full_param, mapping, list);
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

	char *prfix_obj = NULL, *obj_str = NULL;
	int obj_number = 0, param_number = 0, i = 0, j = 0;
	DMOBJ *next_obj = NULL;
	DMLEAF *next_leaf = NULL;

	count_obj_param_under_jsonobj(jobj, &obj_number, &param_number);
	char *full_obj = replace_str(object, ".{i}.", ".");
	generate_prefixobj_and_obj_full_obj(full_obj, &prfix_obj, &obj_str);

	if (!pobj)
		return;

	//OBJ
	pobj[index].obj = obj_str;

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

		if (strcmp(key, "array") == 0) {
			//permission
			pobj[index].permission = json_object_get_boolean(json_obj) ? &DMWRITE : &DMREAD;

			//addobj
			pobj[index].addobj = json_object_get_boolean(json_obj) ? add_obj : NULL;

			//delobj
			pobj[index].delobj = json_object_get_boolean(json_obj) ? delete_obj : NULL;

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

				char *obj_prefix = NULL;
				char *obj = NULL;

				generate_prefixobj_and_obj_full_obj(key, &obj_prefix, &obj);

				DMOBJ *dm_entryobj = NULL;
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
			if (json) json_object_put(json);

		}
		if (dir) closedir(dir);
	}
	return 0;
}
