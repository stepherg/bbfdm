/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmmem.h"
#include "dmcommon.h"
#include "dmbbf.h"

#define MAX_DM_PATH (1024)

char *DMT_TYPE[] = {
	[DMT_STRING] = "xsd:string",
	[DMT_UNINT] = "xsd:unsignedInt",
	[DMT_INT] = "xsd:int",
	[DMT_UNLONG] = "xsd:unsignedLong",
	[DMT_LONG] = "xsd:long",
	[DMT_BOOL] = "xsd:boolean",
	[DMT_TIME] = "xsd:dateTime",
	[DMT_HEXBIN] = "xsd:hexBinary",
	[DMT_BASE64] = "xsd:base64",
	[DMT_COMMAND] = "xsd:command",
	[DMT_EVENT] = "xsd:event"
};

struct dm_permession_s DMREAD = {"0", NULL};
struct dm_permession_s DMWRITE = {"1", NULL};
struct dm_permession_s DMSYNC = {"sync", NULL};
struct dm_permession_s DMASYNC = {"async", NULL};

static int dm_browse(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, void *data, char *instance);

static bool is_instance_number_alias(char **str)
{
	char *s = *str;

	if (*(s-1) != '.')
		return 0;

	if (isdigit(*s)) {
		while(isdigit(*s))
			s++;

		if (*s == '.') {
			*str = s - 1;
			return 1;
		}
	}

	if (*s == '[') {
		while(*s != ']')
			s++;

		if (*(s+1) == '.') {
			*str = s;
			return 1;
		}
	}

	return 0;
}

static char *dm_strstr_wildcard(char *str, char *match)
{
	char *sp = str, *mp = match;

	if (str == NULL || match == NULL)
		return NULL;

	while (*match) {
		if (*str == '\0')
			return NULL;

		if ((*match == *str) ||
			(mp != match && *match == '*' && is_instance_number_alias(&str)) ||
			(sp != str && *str == '*' && is_instance_number_alias(&match))) {
			str++;
			match++;
		} else {
			return NULL;
		}
	}

	return sp;
}

static char *find_param_postfix_wildcard(char *str1, char *str2)
{
	char *sp1 = str1, *sp2 = str2;

	if (str1 == NULL || str2 == NULL)
		return NULL;

	if (*str1 == '\0')
		return NULL;

	while (*str2) {
		if (*str1 == '\0')
			return str2;

		if ((*str2 == *str1) ||
			(sp2 != str2 && *str2 == '*' && is_instance_number_alias(&str1)) ||
			(sp1 != str1 && *str1 == '*' && is_instance_number_alias(&str2))) {
			str1++;
			str2++;
		} else {
			return NULL;
		}
	}

	return str2;
}

static int dm_strcmp_wildcard(char *str1, char *str2)
{
	char *sp1 = str1, *sp2 = str2;

	if (str1 == NULL || str2 == NULL)
		return -1;

	while (*str2) {
		if (*str1 == '\0')
			return -1;

		if ((*str2 == *str1) ||
				(sp2 != str2 && *str2 == '*' && is_instance_number_alias(&str1)) ||
				(sp1 != str1 && *str1 == '*' && is_instance_number_alias(&str2))) {
			str1++;
			str2++;
		} else {
			return -1;
		}
	}

	if (*str1)
		return -1;

	return 0;
}

static int plugin_obj_match(DMOBJECT_ARGS)
{
	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam && DM_STRSTR(node->current_object, dmctx->in_param) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}

	if (DM_STRSTR(dmctx->in_param, node->current_object) == dmctx->in_param)
		return 0;

	return FAULT_9005;
}

static int plugin_leaf_match(DMOBJECT_ARGS)
{
	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam)
		return FAULT_9005;

	char *str = dmctx->in_param + DM_STRLEN(node->current_object);
	if (!DM_STRCHR(str, '.'))
		return 0;

	return FAULT_9005;
}

static int plugin_leaf_onlyobj_match(DMOBJECT_ARGS)
{
	return FAULT_9005;
}

static int plugin_obj_nextlevel_match(DMOBJECT_ARGS)
{
	if (DM_STRCMP(dmctx->in_param, "Device") == 0 && DM_STRCMP(dmctx->in_value, "core") != 0)
		return FAULT_9005;

	unsigned int current_object_dot_num = count_occurrences(node->current_object, '.');
	unsigned int in_path_dot_num = count_occurrences(dmctx->in_param, '.');

	if (current_object_dot_num > in_path_dot_num + 1)
		return FAULT_9005;

	if (node->matched > 1)
		return FAULT_9005;

	if (node->matched) {
		node->matched++;
		return 0;
	}

	if (!dmctx->inparam_isparam && DM_STRSTR(node->current_object, dmctx->in_param) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}

	if (DM_STRSTR(dmctx->in_param, node->current_object) == dmctx->in_param)
		return 0;

	return FAULT_9005;
}

static int plugin_leaf_nextlevel_match(DMOBJECT_ARGS)
{
	if (node->matched > 1)
		return FAULT_9005;

	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam)
		return FAULT_9005;

	char *str = dmctx->in_param + DM_STRLEN(node->current_object);
	if (!DM_STRCHR(str, '.'))
		return 0;

	return FAULT_9005;
}

static int plugin_obj_wildcard_match(DMOBJECT_ARGS)
{
	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam && dm_strstr_wildcard(node->current_object, dmctx->in_param) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}

	if (dm_strstr_wildcard(dmctx->in_param, node->current_object) == dmctx->in_param)
		return 0;

	return FAULT_9005;
}

static int plugin_leaf_wildcard_match(DMOBJECT_ARGS)
{
	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam)
		return FAULT_9005;

	char *str = find_param_postfix_wildcard(node->current_object, dmctx->in_param);
	if (!DM_STRCHR(str, '.'))
		return 0;

	return FAULT_9005;
}

static int plugin_obj_wildcard_nextlevel_match(DMOBJECT_ARGS)
{
	if (DM_STRCMP(dmctx->in_param, "Device") == 0 && DM_STRCMP(dmctx->in_value, "core") != 0)
		return FAULT_9005;

	unsigned int current_object_dot_num = count_occurrences(node->current_object, '.');
	unsigned int in_path_dot_num = count_occurrences(dmctx->in_param, '.');

	if (current_object_dot_num > in_path_dot_num + 1)
		return FAULT_9005;

	if (node->matched > 1)
		return FAULT_9005;

	if (node->matched) {
		node->matched++;
		return 0;
	}

	if (!dmctx->inparam_isparam && dm_strstr_wildcard(node->current_object, dmctx->in_param) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}

	if (dm_strstr_wildcard(dmctx->in_param, node->current_object) == dmctx->in_param)
		return 0;

	return FAULT_9005;
}

static int plugin_leaf_wildcard_nextlevel_match(DMOBJECT_ARGS)
{
	if (node->matched > 1)
		return FAULT_9005;

	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam)
		return FAULT_9005;

	char *str = find_param_postfix_wildcard(node->current_object, dmctx->in_param);
	if (!DM_STRCHR(str, '.'))
		return 0;

	return FAULT_9005;
}

static int bbfdatamodel_matches(unsigned int dm_type, const enum bbfdm_type_enum type)
{
	return (dm_type == BBFDM_BOTH || type == BBFDM_BOTH || dm_type == type) && type != BBFDM_NONE;
}

static bool check_dependency(const char *conf_obj)
{
#ifndef BBF_SCHEMA_FULL_TREE
	/* Available cases */
	/* one file => "file:/etc/config/network" */
	/* multiple files => "file:/etc/config/network,/lib/netifd/proto/dhcp.sh" */
	/* one ubus => "ubus:router.network" (with method : "ubus:router.network->hosts") */
	/* multiple ubus => "ubus:system->info,dsl->status,wifi" */
	/* one package => "opkg:icwmp" */
	/* multiple packages => "opkg:icwmp,obuspa" */
	/* directory => "dir:/sys/class/ieee80211/" */
	/* common (files, ubus and opkg) => "file:/etc/config/network,/etc/config/dhcp;ubus:system,dsl->status;opkg:icwmp" */

	char *pch = NULL, *spch = NULL;
	char conf_list[512] = {0};
	
	DM_STRNCPY(conf_list, conf_obj, sizeof(conf_list));

	for (pch = strtok_r(conf_list, ";", &spch); pch != NULL; pch = strtok_r(NULL, ";", &spch)) {
		char *conf_type = DM_STRCHR(pch, ':');
		if (!conf_type)
			return false;

		char *conf_name = dmstrdup(conf_type + 1);
		*conf_type = '\0';

		char *token, *saveptr;
		for (token = strtok_r(conf_name, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {

			if (!strcmp(pch, "file") && !file_exists(token))
				return false;

			if (!strcmp(pch, "dir") && !bbfdm_folder_exists(token))
				return false;

			if (!strcmp(pch, "ubus") && !dmubus_object_method_exists(token))
				return false;

			if (!strcmp(pch, "opkg")) {
				char opkg_path[256] = {0};

				snprintf(opkg_path, sizeof(opkg_path), "/usr/lib/opkg/info/%s.control", token);
				if (!file_exists(opkg_path))
					return false;
			}
		}
	}
#endif

	return true;
}

static int dm_browse_leaf(struct dmctx *dmctx, DMNODE *parent_node, DMLEAF *leaf, void *data, char *instance)
{
	int err = 0;

	for (; (leaf && leaf->parameter); leaf++) {

		if (!bbfdatamodel_matches(dmctx->dm_type, leaf->bbfdm_type))
			continue;

		if (!dmctx->isinfo) {
			if (dmctx->iscommand != (leaf->type == DMT_COMMAND) || dmctx->isevent != (leaf->type == DMT_EVENT))
				continue;
		}

		err = dmctx->method_param(dmctx, parent_node, leaf, data, instance);
		if (dmctx->stop)
			return err;
	}

	if (parent_node->obj) {
		if (parent_node->obj->dynamicleaf) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_leaf *next_dyn_array = parent_node->obj->dynamicleaf + i;
				if (next_dyn_array->nextleaf) {
					for (int j = 0; next_dyn_array->nextleaf[j]; j++) {
						DMLEAF *jleaf = next_dyn_array->nextleaf[j];
						for (; (jleaf && jleaf->parameter); jleaf++) {

							if (!bbfdatamodel_matches(dmctx->dm_type, jleaf->bbfdm_type))
								continue;

							if (!dmctx->isinfo) {
								if (dmctx->iscommand != (jleaf->type == DMT_COMMAND) || dmctx->isevent != (jleaf->type == DMT_EVENT))
									continue;
							}

							err = dmctx->method_param(dmctx, parent_node, jleaf, data, instance);
							if (dmctx->stop)
								return err;
						}
					}
				}
			}
		}
	}

	return err;
}

static void dm_browse_entry(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, void *data, char *instance, char *parent_obj, int *err)
{
	DMNODE node = {0};

	node.obj = entryobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level;
	node.matched = parent_node->matched;
	node.prev_data = data;
	node.prev_instance = instance;
	node.current_object_file = parent_node->current_object_file;

	if (!bbfdatamodel_matches(dmctx->dm_type, entryobj->bbfdm_type)) {
		*err = FAULT_9005;
		return;
	}

	if (entryobj->checkdep && (check_dependency(entryobj->checkdep) == false)) {
		*err = FAULT_9005;
		return;
	}

	if (entryobj->browseinstobj && dmctx->isgetschema)
		dmasprintf(&(node.current_object), "%s%s.{i}.", parent_obj, entryobj->obj);
	else
		dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);

	if (DM_STRCMP(parent_obj, ROOT_NODE) == 0) { // Case1: parent object is 'Device.'
		node.current_object_file = entryobj->obj;
	} else if (parent_node->parent && DM_STRLEN(parent_node->parent->current_object) == 0) { // Case2: parent object is 'Device.X.X.'
		size_t count = 0;

		char **parts = strsplit(parent_obj, ".", &count);
		if (count < 2)
			return;

		node.current_object_file = parts[1];
	}

	if (dmctx->checkobj) {
		*err = dmctx->checkobj(dmctx, &node, entryobj->permission, entryobj->addobj, entryobj->delobj, entryobj->get_linker, data, instance);
		if (*err)
			return;
	}

#ifndef BBF_SCHEMA_FULL_TREE
	if ((entryobj->browseinstobj && dmctx->isgetschema) || !dmctx->isgetschema) {
#endif
		*err = dmctx->method_obj(dmctx, &node, entryobj->permission, entryobj->addobj, entryobj->delobj, entryobj->get_linker, data, instance);
		if (dmctx->stop)
			return;
#ifndef BBF_SCHEMA_FULL_TREE
	}
#endif

	if (entryobj->browseinstobj && !dmctx->isgetschema) {
		entryobj->browseinstobj(dmctx, &node, data, instance);
		*err = dmctx->faultcode;
		return;
	}

	if (entryobj->leaf || entryobj->dynamicleaf) {
		if (dmctx->checkleaf) {
			*err = dmctx->checkleaf(dmctx, &node, entryobj->permission, entryobj->addobj, entryobj->delobj, entryobj->get_linker, data, instance);
			if (!*err) {
				*err = dm_browse_leaf(dmctx, &node, entryobj->leaf, data, instance);
				if (dmctx->stop)
					return;
			}
		} else {
			*err = dm_browse_leaf(dmctx, &node, entryobj->leaf, data, instance);
			if (dmctx->stop)
				return;
		}
	}

	if (entryobj->nextobj || entryobj->nextdynamicobj)
		*err = dm_browse(dmctx, &node, entryobj->nextobj, data, instance);
}

static int dm_browse(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, void *data, char *instance)
{
	char *parent_obj = parent_node->current_object;
	int err = 0;

	for (; (entryobj && entryobj->obj); entryobj++) {
		dm_browse_entry(dmctx, parent_node, entryobj, data, instance, parent_obj, &err);
		if (dmctx->stop)
			return err;
	}

	if (parent_node->obj) {
		if (parent_node->obj->nextdynamicobj) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_obj *next_dyn_array = parent_node->obj->nextdynamicobj + i;
				if (next_dyn_array->nextobj) {
					for (int j = 0; next_dyn_array->nextobj[j]; j++) {
						DMOBJ *jentryobj = next_dyn_array->nextobj[j];
						for (; (jentryobj && jentryobj->obj); jentryobj++) {
							dm_browse_entry(dmctx, parent_node, jentryobj, data, instance, parent_obj, &err);
							if (dmctx->stop)
								return err;
						}
					}
				}
			}
		}
	}

	return err;
}

int dm_link_inst_obj(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance)
{
	int err = 0;
	char *parent_obj;
	DMNODE node = {0};

	if (parent_node->browse_type == BROWSE_FIND_MAX_INST) { // To be removed later!!!!!!!!!!!!
		int curr_inst = (instance && *instance != '\0') ? DM_STRTOL(instance) : 0;
		if (curr_inst > parent_node->max_instance)
			parent_node->max_instance = curr_inst;
		return 0;
	}

	parent_node->num_of_entries++;
	if (parent_node->browse_type == BROWSE_NUM_OF_ENTRIES) // To be removed later!!!!!!!!!!!!
		return 0;

	DMOBJ *prevobj = parent_node->obj;
	DMOBJ *nextobj = prevobj->nextobj;
	DMLEAF *nextleaf = prevobj->leaf;

	node.obj = prevobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level + 1;
	node.is_instanceobj = 1;
	node.matched = parent_node->matched;
	node.current_object_file = parent_node->current_object_file;

	parent_obj = parent_node->current_object;
	if (instance == NULL)
		return -1;
	dmasprintf(&node.current_object, "%s%s.", parent_obj, instance);
	if (dmctx->checkobj) {
		err = dmctx->checkobj(dmctx, &node, prevobj->permission, prevobj->addobj, prevobj->delobj, prevobj->get_linker, data, instance);
		if (err)
			return err;
	}
	err = dmctx->method_obj(dmctx, &node, prevobj->permission, prevobj->addobj, prevobj->delobj, prevobj->get_linker, data, instance);
	if (dmctx->stop)
		return err;
	if (nextleaf) {
		if (dmctx->checkleaf) {
			err = dmctx->checkleaf(dmctx, &node, prevobj->permission, prevobj->addobj, prevobj->delobj, prevobj->get_linker, data, instance);
			if (!err) {
				err = dm_browse_leaf(dmctx, &node, nextleaf, data, instance);
				if (dmctx->stop)
					return err;
			}
		} else {
			err = dm_browse_leaf(dmctx, &node, nextleaf, data, instance);
			if (dmctx->stop)
				return err;
		}
	}
	if (nextobj || prevobj->nextdynamicobj) {
		err = dm_browse(dmctx, &node, nextobj, data, instance);
		if (dmctx->stop)
			return err;
	}
	return err;
}

static int rootcmp(const char *inparam, const char *rootobj)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%s.", rootobj);
	return DM_STRCMP(inparam, buf);
}

/***************************
 * update instance & alias
 ***************************/
int get_number_of_entries(struct dmctx *ctx, void *data, char *instance, int (*browseinstobj)(struct dmctx *ctx, struct dmnode *node, void *data, char *instance))
{
	DMNODE node = {0};

	if (browseinstobj == NULL) {
		int instance_level = 0;
		size_t count = 0;

		if (!ctx->addobj_instance)
			return 0;

		char **parts = strsplit(ctx->addobj_instance, ".", &count);
		if (count < 2)
			return -1;

		for (int idx = 0; idx < count - 1; idx++) {

			int i = 0;
			bool is_instance = true;
			while (parts[idx][i] != 0) {
				if (isdigit(parts[idx][i]) == false) {
					is_instance = false;
					break;
				}
				i++;
			}

			if (is_instance) instance_level++;
		}

		char *p = DM_STRSTR(parts[count - 1], "NumberOfEntries");
		if (p) *p = 0;

		node.obj = dmcalloc(1, sizeof(struct dm_obj_s));
		if (node.obj == NULL) {
			BBF_ERR("Failed to allocate memory");
			return 0;
		}

		node.current_object_file = parts[1];
		node.obj->obj = parts[count - 1];
		node.instance_level = instance_level;

		node.browse_type = BROWSE_NUM_OF_ENTRIES;
		generic_browse(ctx,&node, data, instance);
	} else {
		node.browse_type = BROWSE_NUM_OF_ENTRIES;
		(browseinstobj)(ctx, &node, data, instance);
	}

	node.browse_type = BROWSE_NORMAL;
	return node.num_of_entries;
}

static int find_max_instance(struct dmctx *ctx, DMNODE *node)
{
	if (node->max_instance == 0) {
		node->browse_type = BROWSE_FIND_MAX_INST;
		node->obj->browseinstobj(ctx, node, node->prev_data, node->prev_instance);
		node->browse_type = BROWSE_NORMAL;
	}

	return ++(node->max_instance);
}

char *handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct uci_section *s, const char *inst_opt, const char *alias_opt)
{
	char buf[64] = {0};
	char *instance = NULL;

	dmuci_get_value_by_section_string(s, inst_opt, &instance);

	switch(parent_node->browse_type) {
	case BROWSE_NORMAL:
		if (instance && *instance == '\0') {
			int max_inst = find_max_instance(dmctx, parent_node);
			snprintf(buf, sizeof(buf), "%d", max_inst);
			dmuci_set_value_by_section(s, inst_opt, buf);
			instance = dmstrdup(buf);
		}
		break;
	case BROWSE_FIND_MAX_INST:
	case BROWSE_NUM_OF_ENTRIES:
		break;
	}

	dmctx->inst_buf[parent_node->instance_level] = instance ? instance : "";

	return instance ? instance : "";
}

struct uci_section *create_dmmap_obj(struct dmctx *dmctx, unsigned char instance_level,
		const char *obj_file, const char *obj_name, struct uci_section *config_sec,
		char **instance)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;
	char config_sec_name[128] = {0};
	int max_instance = 0;

	if (!dmctx || !obj_file || !obj_name || !instance)
		return NULL;

	if (config_sec != NULL) {
		snprintf(config_sec_name, sizeof(config_sec_name), "%s.%s", section_config(config_sec), section_name(config_sec));
	}

	uci_path_foreach_sections(bbfdm, obj_file, obj_name, s) {
		bool is_same_parent = true;

		for (int i = 0; i < instance_level; i++) {
			char *curr_obj_inst = NULL;
			dmuci_get_value_by_section_string(s, dmctx->obj_buf[i], &curr_obj_inst);
			if (DM_STRCMP(curr_obj_inst, dmctx->inst_buf[i]) != 0) {
				is_same_parent = false;
				break;
			}
		}

		if (is_same_parent == false)
			continue;

		char *curr_instance = NULL;
		dmuci_get_value_by_section_string(s, "__instance__", &curr_instance);
		int curr_instance_int = (curr_instance && *curr_instance != '\0') ? DM_STRTOL(curr_instance) : 0;
		if (curr_instance_int > max_instance)
			max_instance = curr_instance_int;

		if (config_sec != NULL) {
			char *curr_sec_name = NULL;
			dmuci_get_value_by_section_string(s, "__section_name__", &curr_sec_name);
			if (DM_STRCMP(curr_sec_name, config_sec_name) == 0) {
				dmctx->obj_buf[instance_level] = obj_name;
				dmctx->inst_buf[instance_level] = curr_instance;
				*instance = curr_instance;
				return dmmap_section;
			}
		}
	}

	dmasprintf(instance, "%d", max_instance + 1);

	if (dmmap_section == NULL) {
		// Section not found -> create it
		char s_name[64] = {0};
		int pos = 0;

		dmuci_add_section_bbfdm(obj_file, obj_name, &dmmap_section);

		for (int i = 0; i < instance_level; i++) {
			dmuci_set_value_by_section(dmmap_section, dmctx->obj_buf[i], dmctx->inst_buf[i]);
			pos += snprintf(&s_name[pos], sizeof(s_name) - pos, "%s_%s", dmctx->obj_buf[i], dmctx->inst_buf[i]);
		}

		snprintf(&s_name[pos], sizeof(s_name) - pos, "%s_%s", obj_name, *instance);

		dmuci_rename_section_by_section(dmmap_section, s_name);

		dmuci_set_value_by_section(dmmap_section, "__section_name__", config_sec_name);
		dmuci_set_value_by_section(dmmap_section, "__instance__", *instance);
	}

	dmctx->obj_buf[instance_level] = obj_name;
	dmctx->inst_buf[instance_level] = *instance;

	return dmmap_section;
}

char *uci_handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct dm_data *data)
{
	char *instance = NULL;

	switch(parent_node->browse_type) {
	case BROWSE_NORMAL: // To be removed later!!!!!!!!!!!!
		dmuci_get_value_by_section_string(data->dmmap_section, "__instance__", &instance);
		dmctx->obj_buf[parent_node->instance_level] = parent_node->obj->obj;
		dmctx->inst_buf[parent_node->instance_level] = instance ? instance : "";
		break;
	case BROWSE_FIND_MAX_INST: // To be removed later!!!!!!!!!!!!
	case BROWSE_NUM_OF_ENTRIES: // To be removed later!!!!!!!!!!!!
		break;
	}

	return instance ? instance : "";
}

char *handle_instance_without_section(struct dmctx *dmctx, DMNODE *parent_node, int inst_nbr)
{
	char *instance = NULL;

	switch(parent_node->browse_type) {
	case BROWSE_NORMAL:
		dmasprintf(&instance, "%d", inst_nbr);
		break;
	case BROWSE_FIND_MAX_INST:
	case BROWSE_NUM_OF_ENTRIES:
		break;
	}

	dmctx->inst_buf[parent_node->instance_level] = instance ? instance : "";

	return instance ? instance : "";
}

int generic_browse(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data curr_data = {0};
	char *instance = NULL;

	// This check is added to prevent crashes if the object is updated to new design but forgot to update its NumberOfEntries parameter maps to it
	if (parent_node->obj == NULL)
		return 0;

	uci_path_foreach_sections(bbfdm, parent_node->current_object_file, parent_node->obj->obj, curr_data.dmmap_section) {
		char *config_sec_name = NULL;
		bool is_same_parent = true;

		for (int i = 0; i < parent_node->instance_level; i++) {
			char *curr_obj_inst = NULL;
			dmuci_get_value_by_section_string(curr_data.dmmap_section, dmctx->obj_buf[i], &curr_obj_inst);
			if (DM_STRCMP(curr_obj_inst, dmctx->inst_buf[i]) != 0) {
				is_same_parent = false;
				break;
			}
		}

		if (is_same_parent == false)
			continue;

		dmuci_get_value_by_section_string(curr_data.dmmap_section, "__section_name__", &config_sec_name);
		curr_data.config_section = get_config_section_from_dmmap_section_name(config_sec_name);

		instance = uci_handle_instance(dmctx, parent_node, &curr_data);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_data, instance) == DM_STOP)
			break;
	}

	return 0;
}

int get_empty(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup("");
	return 0;
}

static void bb_add_flags_arr(struct blob_buf *bb, uint32_t dm_flags)
{
	if (!bb || !dm_flags)
		return;

	void *flags_arr = blobmsg_open_array(bb, "flags");

	if (dm_flags & DM_FLAG_REFERENCE)
		blobmsg_add_string(bb, NULL, "Reference");
	if (dm_flags & DM_FLAG_UNIQUE)
		blobmsg_add_string(bb, NULL, "Unique");
	if (dm_flags & DM_FLAG_LINKER)
		blobmsg_add_string(bb, NULL, "Linker");
	if (dm_flags & DM_FLAG_SECURE)
		blobmsg_add_string(bb, NULL, "Secure");

	blobmsg_close_array(bb, flags_arr);
}

void fill_blob_param(struct blob_buf *bb, const char *path, const char *data, const char *type, uint32_t dm_flags)
{
	if (!bb || !path || !data || !type)
		return;

	void *table = blobmsg_open_table(bb, NULL);

	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "data", data);
	blobmsg_add_string(bb, "type", type);
	bb_add_flags_arr(bb, dm_flags);

	blobmsg_close_table(bb, table);
}

void fill_blob_event(struct blob_buf *bb, const char *path, const char *type, void *data)
{
	if (!bb || !path || !type)
		return;

	void *table = blobmsg_open_table(bb, NULL);

	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "type", type);

	if (data) {
		event_args *ev = (event_args *)data;

		blobmsg_add_string(bb, "data", (ev && ev->name) ? ev->name : "");

		if (ev && ev->param) {
			const char **in = ev->param;
			void *key = blobmsg_open_array(bb, "input");

			for (int i = 0; in[i] != NULL; i++) {
				void *in_table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", in[i]);
				blobmsg_close_table(bb, in_table);
			}

			blobmsg_close_array(bb, key);
		}
	}

	blobmsg_close_table(bb, table);
}

void fill_blob_operate(struct blob_buf *bb, const char *path, const char *data, const char *type, void *in_out)
{
	if (!bb || !path || !data || !type)
		return;

	void *op_table = blobmsg_open_table(bb, NULL);

	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "type", type);
	blobmsg_add_string(bb, "data", data);

	if (in_out) {
		void *array, *table;
		const char **in, **out;
		operation_args *args;
		int i;

		args = (operation_args *)in_out;
		in = args->in;
		if (in) {
			array = blobmsg_open_array(bb, "input");

			for (i = 0; in[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", in[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, array);
		}

		out = args->out;
		if (out) {
			array = blobmsg_open_array(bb, "output");

			for (i = 0; out[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", out[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, array);
		}
	}

	blobmsg_close_table(bb, op_table);
}

int string_to_bool(const char *v, bool *b)
{
	if (v[0] == '1' && v[1] == '\0') {
		*b = true;
		return 0;
	}
	if (v[0] == '0' && v[1] == '\0') {
		*b = false;
		return 0;
	}
	if (strcasecmp(v, "true") == 0) {
		*b = true;
		return 0;
	}
	if (strcasecmp(v, "false") == 0) {
		*b = false;
		return 0;
	}
	*b = false;
	return -1;
}

static int is64digit(char c)
{
	if ((c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c == '+' || c == '/' || c == '='))
		return 1;
	return 0;
}

static char *check_value_by_type(const char *param_name, char *value, int type)
{
	int i = 0, len = DM_STRLEN(value);
	char buf[len + 1];
	struct tm tm;

	snprintf(buf, sizeof(buf), "%s", value);

	switch (type) {
		case DMT_UNINT:
		case DMT_UNLONG:
			while (buf[i] != 0) {
				if (isdigit(buf[i]) == 0) {
					BBF_WARNING("The parameter '%s' contains an invalid value '%s' for its type. Defaulting to '0'", param_name, buf);
					return "0";
				}
				i++;
			}
			break;
		case DMT_INT:
		case DMT_LONG:
			if (buf[i] == '-')
				i++;
			while (buf[i] != 0) {
				if (isdigit(buf[i]) == 0) {
					BBF_WARNING("The parameter '%s' contains an invalid value '%s' for its type. Defaulting to '0'", param_name, buf);
					return "0";
				}
				i++;
			}
			break;
		case DMT_BOOL:
			return dmuci_string_to_boolean(buf) ? "1" : "0";
		case DMT_HEXBIN:
			while (buf[i] != 0) {
				if (isxdigit(buf[i]) == 0) {
					BBF_WARNING("The parameter '%s' contains an invalid hexadecimal value '%s'. Defaulting to an empty value", param_name, buf);
					return "";
				}
				i++;
			}
			break;
		case DMT_BASE64:
			while (buf[i] != 0) {
				if (is64digit(buf[i]) == 0) {
					BBF_WARNING("The parameter '%s' contains an invalid Base64 value '%s'. Defaulting to 'AA=='.", param_name, buf);
					return "AA==";
				}
				i++;
			}
			break;
		case DMT_TIME:
			if (!strptime(buf, "%Y-%m-%dT%H:%M:%S", &tm)) {
				BBF_WARNING("The parameter '%s' contains an invalid time value '%s'. Defaulting to '0001-01-01T00:00:00Z'.", param_name, buf);
				return "0001-01-01T00:00:00Z";
			}
			break;
		default:
			break;
	}
	return value;
}

static char *get_default_value_by_type(const char *param_name, int type)
{
	switch (type) {
		case DMT_UNINT:
		case DMT_INT:
		case DMT_UNLONG:
		case DMT_LONG:
		case DMT_BOOL:
			BBF_WARNING("The parameter '%s' is empty but must have a value according to its type. Defaulting to '0'", param_name);
			return "0";
		case DMT_BASE64:
			BBF_WARNING("The parameter '%s' is empty but must have a value according to its Base64 type. Defaulting to 'AA=='", param_name);
			return "AA=="; // base64 encoded hex value 00
		case DMT_TIME:
			BBF_WARNING("The parameter '%s' is empty but must have a value according to its Time type. Defaulting to '0001-01-01T00:00:00Z'", param_name);
			return "0001-01-01T00:00:00Z";
		default:
			return "";
	}
}

/* **********
 * get value 
 * **********/
static int get_value_obj(DMOBJECT_ARGS)
{
	return 0;
}

static int get_value_param(DMPARAM_ARGS)
{
	char *full_param = NULL;
	char *value = dmstrdup("");

	dmasprintf(&full_param, "%s%s", node->current_object, leaf->parameter);

	dmctx->addobj_instance = full_param; // This assignment is needed to pass the refparam in order to calculate the NumberOfEntries param

	(leaf->getvalue)(full_param, dmctx, data, instance, &value);

	if ((leaf->dm_flags & DM_FLAG_SECURE) && (dmctx->dm_type == BBFDM_CWMP)) {
		value = dmstrdup("");
	} else if (value && *value) {
		value = check_value_by_type(full_param, value, leaf->type);
	} else {
		value = get_default_value_by_type(full_param, leaf->type);
	}

	fill_blob_param(&dmctx->bb, full_param, value, DMT_TYPE[leaf->type], leaf->dm_flags);
	return 0;
}

static int mobj_get_value_in_param(DMOBJECT_ARGS)
{
	return 0;
}
static int mparam_get_value_in_param(DMPARAM_ARGS)
{
	char *full_param = NULL;
	char *value = dmstrdup("");

	dmasprintf(&full_param, "%s%s", node->current_object, leaf->parameter);

	if (dmctx->iswildcard) {
		if (dm_strcmp_wildcard(dmctx->in_param, full_param) != 0)
			return FAULT_9005;
	} else {
		if (DM_STRCMP(dmctx->in_param, full_param) != 0)
			return FAULT_9005;
	}

	dmctx->addobj_instance = full_param; // This assignment is needed to pass the refparam in order to calculate the NumberOfEntries param

	(leaf->getvalue)(full_param, dmctx, data, instance, &value);

	if ((leaf->dm_flags & DM_FLAG_SECURE) && (dmctx->dm_type == BBFDM_CWMP)) {
		value = dmstrdup("");
	} else if (value && *value) {
		value = check_value_by_type(full_param, value, leaf->type);
	} else {
		value = get_default_value_by_type(full_param, leaf->type);
	}

	fill_blob_param(&dmctx->bb, full_param, value, DMT_TYPE[leaf->type], leaf->dm_flags);

	dmctx->findparam = (dmctx->iswildcard) ? 1 : 0;
	dmctx->stop = (dmctx->iswildcard) ? false : true;
	return 0;
}

int dm_entry_get_value(struct dmctx *dmctx)
{
	int err = 0;
	unsigned char findparam_check = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	unsigned int len = DM_STRLEN(dmctx->in_param);

	if ((len > 2 && dmctx->in_param[len - 1] == '.' && dmctx->in_param[len - 2] == '*') ||
			(dmctx->in_param[0] == '.' && len == 1))
		return FAULT_9005;

	if (dmctx->in_param[0] == '\0' || rootcmp(dmctx->in_param, root->obj) == 0) {
		dmctx->inparam_isparam = 0;
		dmctx->method_obj = get_value_obj;
		dmctx->method_param = get_value_param;
		dmctx->checkobj = NULL;
		dmctx->checkleaf = NULL;
		dmctx->findparam = 1;
		dmctx->stop = 0;
		findparam_check = 1;
	} else if (dmctx->in_param[len - 1] == '.') {
		dmctx->inparam_isparam = 0;
		dmctx->findparam = 0;
		dmctx->stop = 0;
		dmctx->checkobj = (dmctx->iswildcard) ? plugin_obj_wildcard_match : plugin_obj_match;
		dmctx->checkleaf = (dmctx->iswildcard) ? plugin_leaf_wildcard_match : plugin_leaf_match;
		dmctx->method_obj = get_value_obj;
		dmctx->method_param = get_value_param;
		findparam_check = 1;
	} else {
		dmctx->inparam_isparam = 1;
		dmctx->findparam = 0;
		dmctx->stop = 0;
		dmctx->checkobj = (dmctx->iswildcard) ? plugin_obj_wildcard_match : plugin_obj_match;
		dmctx->checkleaf = (dmctx->iswildcard) ? plugin_leaf_wildcard_match : plugin_leaf_match;
		dmctx->method_obj = mobj_get_value_in_param;
		dmctx->method_param = mparam_get_value_in_param;
		findparam_check = (dmctx->iswildcard) ? 1 : 0;
	}

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (findparam_check && dmctx->findparam) ? 0 : err;
}

/* **********
 * get name 
 * **********/
static void fill_blob_alias_param(struct blob_buf *bb, const char *path, const char *data, const char *type, const char *alias)
{
	if (!bb || !path || !data || !type || !alias)
		return;

	void *table = blobmsg_open_table(bb, NULL);

	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "data", data);
	blobmsg_add_string(bb, "type", type);

	void *array = blobmsg_open_array(bb, "output");

	void *out_table = blobmsg_open_table(bb, NULL);
	blobmsg_add_string(bb, "data", alias);
	blobmsg_close_table(bb, out_table);

	blobmsg_close_array(bb, array);

	blobmsg_close_table(bb, table);
}

static int mobj_get_name(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;

	if (DM_STRCMP(node->current_object, ROOT_NODE) == 0 && DM_STRCMP(dmctx->in_value, "core") != 0)
		return 0;

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	fill_blob_param(&dmctx->bb, refparam, perm, "xsd:object", 0);
	return 0;
}

static int mparam_get_name(DMPARAM_ARGS)
{
	char *perm = leaf->permission->val;
	char refparam[MAX_DM_PATH] = {0};

	snprintf(refparam, sizeof(refparam), "%s%s", node->current_object, leaf->parameter);

	if (leaf->permission->get_permission != NULL)
		perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

	if (DM_LSTRCMP(leaf->parameter, "Alias") == 0) {
		char *alias = dmstrdup("");

		(leaf->getvalue)(refparam, dmctx, data, instance, &alias);
		fill_blob_alias_param(&dmctx->bb, refparam, perm, DMT_TYPE[leaf->type], alias);
	} else {
		fill_blob_param(&dmctx->bb, refparam, perm, DMT_TYPE[leaf->type], 0);
	}

	return 0;
}

static int mobj_get_name_in_param(DMOBJECT_ARGS)
{
	return 0;
}

static int mparam_get_name_in_param(DMPARAM_ARGS)
{
	char *perm = leaf->permission->val;
	char refparam[MAX_DM_PATH] = {0};

	snprintf(refparam, sizeof(refparam), "%s%s", node->current_object, leaf->parameter);

	if (dmctx->iswildcard) {
		if (dm_strcmp_wildcard(refparam, dmctx->in_param) != 0)
			return FAULT_9005;
	} else {
		if (DM_STRCMP(refparam, dmctx->in_param) != 0)
			return FAULT_9005;
	}

	dmctx->stop = (dmctx->iswildcard) ? 0 : 1;

	if (dmctx->nextlevel == 1) {
		dmctx->stop = 1;
		return FAULT_9003;
	}

	if (leaf->permission->get_permission != NULL)
		perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

	if (DM_LSTRCMP(leaf->parameter, "Alias") == 0) {
		char *alias = dmstrdup("");

		(leaf->getvalue)(refparam, dmctx, data, instance, &alias);
		fill_blob_alias_param(&dmctx->bb, refparam, perm, DMT_TYPE[leaf->type], alias);
	} else {
		fill_blob_param(&dmctx->bb, refparam, perm, DMT_TYPE[leaf->type], 0);
	}

	dmctx->findparam = (dmctx->iswildcard) ? 1 : 0;
	return 0;

}

static int mobj_get_name_in_obj(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;

	if (!node->matched)
		return FAULT_9005;

	if (DM_STRCMP(node->current_object, ROOT_NODE) == 0 && DM_STRCMP(dmctx->in_value, "core") != 0)
		return 0;

	if (dmctx->iswildcard) {
		if (dmctx->nextlevel && dm_strcmp_wildcard(node->current_object, dmctx->in_param) == 0)
			return 0;
	} else {
		if (dmctx->nextlevel && DM_STRCMP(node->current_object, dmctx->in_param) == 0)
			return 0;
	}

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	fill_blob_param(&dmctx->bb, refparam, perm, "xsd:object", 0);
	return 0;
}

static int mparam_get_name_in_obj(DMPARAM_ARGS)
{
	char *perm = leaf->permission->val;
	char refparam[MAX_DM_PATH] = {0};

	snprintf(refparam, sizeof(refparam), "%s%s", node->current_object, leaf->parameter);

	if (leaf->permission->get_permission != NULL)
		perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

	if (DM_LSTRCMP(leaf->parameter, "Alias") == 0) {
		char *alias = dmstrdup("");

		(leaf->getvalue)(refparam, dmctx, data, instance, &alias);
		fill_blob_alias_param(&dmctx->bb, refparam, perm, DMT_TYPE[leaf->type], alias);
	} else {
		fill_blob_param(&dmctx->bb, refparam, perm, DMT_TYPE[leaf->type], 0);
	}

	return 0;
}

int dm_entry_get_name(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	unsigned char findparam_check = 0;
	unsigned int len = DM_STRLEN(ctx->in_param);
	int err = 0;

	if ((len > 2 && ctx->in_param[len - 1] == '.' && ctx->in_param[len - 2] == '*') ||
			(ctx->in_param[0] == '.' && len == 1))
		return FAULT_9005;

	if (ctx->nextlevel == 0	&& (ctx->in_param[0] == '\0' || rootcmp(ctx->in_param, root->obj) == 0)) {
		ctx->inparam_isparam = 0;
		ctx->findparam = 1;
		ctx->stop = 0;
		ctx->checkobj = NULL;
		ctx->checkleaf = NULL;
		ctx->method_obj = mobj_get_name;
		ctx->method_param = mparam_get_name;
	} else if (ctx->nextlevel && (ctx->in_param[0] == '\0')) {
		ctx->inparam_isparam = 0;
		ctx->findparam = 1;
		ctx->stop = 0;
		ctx->checkobj = plugin_obj_nextlevel_match;
		ctx->checkleaf = plugin_leaf_nextlevel_match;
		ctx->method_obj = mobj_get_name;
		ctx->method_param = mparam_get_name;
		ctx->in_param = dmstrdup("Device");
		node.matched = 1;
		findparam_check = 1;
	} else if (*(ctx->in_param + len - 1) == '.') {
		ctx->inparam_isparam = 0;
		ctx->findparam = 0;
		ctx->stop = 0;
		if (ctx->iswildcard) {
			ctx->checkobj = (ctx->nextlevel) ? plugin_obj_wildcard_nextlevel_match : plugin_obj_wildcard_match;
			ctx->checkleaf = (ctx->nextlevel) ? plugin_leaf_wildcard_nextlevel_match : plugin_leaf_wildcard_match;
		} else {
			ctx->checkobj = (ctx->nextlevel) ? plugin_obj_nextlevel_match : plugin_obj_match;
			ctx->checkleaf = (ctx->nextlevel) ? plugin_leaf_nextlevel_match : plugin_leaf_match;
		}
		ctx->method_obj = mobj_get_name_in_obj;
		ctx->method_param = mparam_get_name_in_obj;
		findparam_check = 1;
	} else {
		ctx->inparam_isparam = 1;
		ctx->findparam = 0;
		ctx->stop = 0;
		ctx->checkobj = (ctx->iswildcard) ? plugin_obj_wildcard_match : plugin_obj_match;
		ctx->checkleaf = (ctx->iswildcard) ? plugin_leaf_wildcard_match : plugin_leaf_match;
		ctx->method_obj = mobj_get_name_in_param;
		ctx->method_param = mparam_get_name_in_param;
		findparam_check = (ctx->iswildcard) ? 1 : 0;
	}

	err = dm_browse(ctx, &node, root, NULL, NULL);

	return (findparam_check && ctx->findparam) ? 0 : err;
}

/* ***********************
 * get supported data model
 * ***********************/
static int mobj_get_supported_dm(DMOBJECT_ARGS)
{
	char *perm = permission ? permission->val : "0";
	char *refparam = node->current_object;

	if (node->matched && dmctx->isinfo) {
		fill_blob_param(&dmctx->bb, refparam, perm, "xsd:object", 0);
	}

	return 0;
}

static int mparam_get_supported_dm(DMPARAM_ARGS)
{
	char refparam[MAX_DM_PATH] = {0};
	char *value = NULL;

	snprintf(refparam, sizeof(refparam), "%s%s", node->current_object, leaf->parameter);

	if (node->matched) {
		if (leaf->type == DMT_EVENT) {
			if (dmctx->isevent) {
				if (leaf->getvalue)
					(leaf->getvalue)(refparam, dmctx, data, instance, &value);

				fill_blob_event(&dmctx->bb, refparam, DMT_TYPE[leaf->type], value);
			}

		} else if (leaf->type == DMT_COMMAND) {
			if (dmctx->iscommand) {

				if (leaf->getvalue)
					(leaf->getvalue)(refparam, dmctx, data, instance, &value);

				fill_blob_operate(&dmctx->bb, refparam, leaf->permission->val, DMT_TYPE[leaf->type], value);
			}
		} else {
			fill_blob_param(&dmctx->bb, refparam, leaf->permission->val, DMT_TYPE[leaf->type], leaf->dm_flags);
		}
	}

	return 0;
}

int dm_entry_get_supported_dm(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	size_t plen = DM_STRLEN(ctx->in_param);
	int err = 0;

	if (plen == 0 || ctx->in_param[plen - 1] != '.')
		return FAULT_9005;

	ctx->inparam_isparam = 0;
	ctx->isgetschema = 1;
	ctx->findparam = 1;
	ctx->stop =0;
	ctx->checkobj = plugin_obj_match;
	ctx->checkleaf = NULL;
	ctx->method_obj = mobj_get_supported_dm;
	ctx->method_param = mparam_get_supported_dm;

	err = dm_browse(ctx, &node, root, NULL, NULL);

	return (ctx->findparam) ? 0 : err;
}

/* **************
 * get_instances
 * **************/
static int mobj_get_instances_in_obj(DMOBJECT_ARGS)
{
	if (node->matched && node->is_instanceobj) {
		char path[MAX_DM_PATH] = {0};

		snprintf(path, sizeof(path), "%s", node->current_object);

		int len = DM_STRLEN(path);

		if (len) {
			path[len - 1] = 0;

			void *table = blobmsg_open_table(&dmctx->bb, NULL);
			blobmsg_add_string(&dmctx->bb, "path", path);
			blobmsg_close_table(&dmctx->bb, table);
		}
	}

	return 0;
}

static int mparam_get_instances_in_obj(DMPARAM_ARGS)
{
	return 0;
}

int dm_entry_get_instances(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	size_t plen = DM_STRLEN(ctx->in_param);
	int err = 0;

	if (ctx->in_param[0] == 0)
		ctx->in_param = dmstrdup(".");

	if (ctx->in_param[plen - 1] != '.')
		return FAULT_9005;

	ctx->inparam_isparam = 0;
	ctx->findparam = 0;
	ctx->stop = 0;
	ctx->checkobj = (ctx->iswildcard) ? plugin_obj_wildcard_match : plugin_obj_match;
	ctx->checkleaf = (ctx->iswildcard) ? plugin_leaf_wildcard_match : plugin_leaf_match;
	ctx->method_obj = mobj_get_instances_in_obj;
	ctx->method_param = mparam_get_instances_in_obj;

	err = dm_browse(ctx, &node, root, NULL, NULL);

	return (ctx->findparam == 0) ? err : 0;
}

/* **************
 * add object 
 * **************/
static int mobj_add_object(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;
	char *new_instance = NULL;
	char file_path[64] = {0};
	int fault = 0;

	if (DM_STRCMP(refparam, dmctx->in_param) != 0)
		return FAULT_9005;

	if (node->is_instanceobj)
		return FAULT_9005;

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	if (perm[0] == '0' || addobj == NULL)
		return FAULT_9005;

	snprintf(file_path, sizeof(file_path), "/etc/bbfdm/dmmap/%s", node->current_object_file);

	if (file_exists(file_path)) {
		struct dm_data curr_data = {0};

		curr_data.dmmap_section = create_dmmap_obj(dmctx, node->instance_level, node->current_object_file, node->obj->obj, NULL, &new_instance);
		if (DM_STRLEN(new_instance) == 0 || curr_data.dmmap_section == NULL)
			return FAULT_9005;

		dmctx->stop = 1;

		// cppcheck-suppress autoVariables
		dmctx->addobj_instance = (char *)&curr_data;

		fault = (addobj)(refparam, dmctx, data, &new_instance);
		if (fault)
			return fault;

		if (curr_data.config_section != NULL) {
			char sec_name[128] = {0};

			snprintf(sec_name, sizeof(sec_name), "%s.%s", section_config(curr_data.config_section), section_name(curr_data.config_section));
			dmuci_set_value_by_section(curr_data.dmmap_section, "__section_name__", sec_name);
		}
	} else {
		int max_inst = find_max_instance(dmctx, node);
		fault = dmasprintf(&new_instance, "%d", max_inst);
		if (fault)
			return fault;

		dmctx->stop = 1;

		fault = (addobj)(refparam, dmctx, data, &new_instance);
		if (fault)
			return fault;

	}

	dmctx->addobj_instance = new_instance;
	return 0;
}

static int mparam_add_object(DMPARAM_ARGS)
{
	return FAULT_9005;
}

int dm_entry_add_object(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err = 0;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0' ||
		(*(dmctx->in_param + DM_STRLEN(dmctx->in_param) - 1) != '.'))
		return FAULT_9005;

	dmctx->inparam_isparam = 0;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_onlyobj_match;
	dmctx->method_obj = mobj_add_object;
	dmctx->method_param = mparam_add_object;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/* **************
 * del object 
 * **************/
static int delete_object_obj(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;

	if (DM_STRCMP(refparam, dmctx->in_param) != 0)
		return FAULT_9005;

	dmctx->stop = 1;

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	if (perm[0] == '0' || delobj == NULL)
		return FAULT_9005;

	if (!node->is_instanceobj)
		return FAULT_9005;

	return (delobj)(refparam, dmctx, data, instance, DEL_INST);
}

static int delete_object_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

int dm_entry_delete_object(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err = 0;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0' ||
		(*(dmctx->in_param + DM_STRLEN(dmctx->in_param) - 1) != '.'))
		return FAULT_9005;

	dmctx->inparam_isparam = 0;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_onlyobj_match;
	dmctx->method_obj = delete_object_obj;
	dmctx->method_param = delete_object_param;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/* **************
 * set value  
 * **************/
static int mobj_set_value(DMOBJECT_ARGS)
{
	return FAULT_9005;
}

static int get_datatype(char *type)
{
	if (DM_STRLEN(type) == 0)
		return __DMT_INVALID;

	if (strcmp(type, "int") == 0)
		return DMT_INT;

	if (strcmp(type, "long") == 0)
		return DMT_LONG;

	if (strcmp(type, "unsignedInt") == 0)
		return DMT_UNINT;

	if (strcmp(type, "unsignedLong") == 0)
		return DMT_UNLONG;

	if (strcmp(type, "decimal") == 0)
		return DMT_STRING;

	if (strcmp(type, "hexBinary") == 0)
		return DMT_HEXBIN;

	if (strcmp(type, "dateTime") == 0)
		return DMT_TIME;

	if (strcmp(type, "boolean") == 0)
		return DMT_BOOL;

	if (strcmp(type, "base64") == 0)
		return DMT_BASE64;

	if (strcmp(type, "string") == 0)
		return DMT_STRING;

	return __DMT_INVALID;
}

static int mparam_set_value(DMPARAM_ARGS)
{
	char refparam[MAX_DM_PATH] = {0};
	char param_value[4096] = {0};
	char *value = dmstrdup("");

	snprintf(refparam, MAX_DM_PATH, "%s%s", node->current_object, leaf->parameter);
	if (DM_STRCMP(refparam, dmctx->in_param) != 0)
		return FAULT_9005;

	dmctx->stop = 1;
	dmctx->setaction = VALUECHECK;

	char *perm = leaf->permission->val;
	if (leaf->permission->get_permission != NULL)
		perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

	if (perm[0] == '0' || !leaf->setvalue)
		return FAULT_9008;

	// If type is not defined then bypass this check
	if (DM_STRLEN(dmctx->in_type) != 0) {
		int type = get_datatype(dmctx->in_type);

		if (type != leaf->type) {
			return FAULT_9006;
		}
	}

	(leaf->getvalue)(refparam, dmctx, data, instance, &value);

	snprintf(param_value, sizeof(param_value), "%s", dmctx->in_value);

	if (leaf->type == DMT_BOOL) {
		bool val = false;
		int res = 0;

		res = string_to_bool(dmctx->in_value, &val);
		if (res == 0 && dmuci_string_to_boolean(value) == val) {
			BBF_DEBUG("Requested value (%s) is same as current value (%s).", dmctx->in_value, value);
			return 0;
		}
	} else {
		if (DM_STRCMP(dmctx->in_value, value) == 0) {
			BBF_DEBUG("Requested value (%s) is same as current value (%s)...", dmctx->in_value, value);
			return 0;
		}
	}

	char *param_val = dmstrdup(param_value);

	int fault = (leaf->setvalue)(refparam, dmctx, data, instance, param_value, dmctx->setaction);
	if (fault)
		return fault;

	dmctx->setaction = VALUESET;

	return (leaf->setvalue)(refparam, dmctx, data, instance, param_val, dmctx->setaction);
}

int dm_entry_set_value(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err = 0;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0' ||
		(*(dmctx->in_param + DM_STRLEN(dmctx->in_param) - 1) == '.'))
		return FAULT_9005;

	dmctx->inparam_isparam = 1;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;
	dmctx->method_obj = mobj_set_value;
	dmctx->method_param = mparam_set_value;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/******************
 * get reference param
 *****************/
static int get_key_check_obj(DMOBJECT_ARGS)
{
	return FAULT_9005;
}

static int get_key_check_param(DMPARAM_ARGS)
{
	char full_param[MAX_DM_PATH] = {0};
	char *value = dmstrdup("");

	snprintf(full_param, sizeof(full_param), "%s%s", node->current_object, leaf->parameter);

	if (dm_strcmp_wildcard(dmctx->in_param, full_param) != 0)
		return FAULT_9005;

	(leaf->getvalue)(full_param, dmctx, data, instance, &value);

	if (DM_STRLEN(value) && DM_STRCMP(value, dmctx->linker) == 0) {
		if (node->current_object[DM_STRLEN(node->current_object) - 1] == '.')
			node->current_object[DM_STRLEN(node->current_object) - 1] = 0;
		dmctx->linker_param = dmstrdup(node->current_object);
		dmctx->stop = true;
		return 0;
	}

	return FAULT_9005;
}

int dm_entry_get_reference_param(struct dmctx *dmctx)
{
	int err = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->checkobj = plugin_obj_wildcard_match;
	dmctx->checkleaf = plugin_leaf_wildcard_match;
	dmctx->method_obj = get_key_check_obj;
	dmctx->method_param = get_key_check_param;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/******************
 * get reference value
 *****************/
static int get_reference_value_check_obj(DMOBJECT_ARGS)
{
	if (DM_STRCMP(node->current_object, dmctx->in_param) == 0) {

		if (!data || !instance)
			return FAULT_9005;

		struct dm_leaf_s *leaf = node->obj->leaf;
		if (!leaf)
			return FAULT_9005;

		for (; (leaf && leaf->parameter); leaf++) {

			if (leaf->dm_flags & DM_FLAG_LINKER) {
				char full_param[MAX_DM_PATH] = {0};
				char *link_val = NULL;

				snprintf(full_param, sizeof(full_param), "%s%s", node->current_object, leaf->parameter);

				(leaf->getvalue)(full_param, dmctx, data, instance, &link_val);

				dmctx->linker = link_val ? dmstrdup(link_val) : "";
				dmctx->stop = true;
				return 0;
			}
		}
	}

	return FAULT_9005;
}

static int get_reference_value_check_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

int dm_entry_get_reference_value(struct dmctx *dmctx)
{
	int err = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->method_obj = get_reference_value_check_obj;
	dmctx->method_param = get_reference_value_check_param;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/******************
 * object exists
 *****************/
static int object_exists_check_obj(DMOBJECT_ARGS)
{
	if (DM_STRCMP(node->current_object, dmctx->in_param) == 0) {
		dmctx->match = true;
		dmctx->stop = true;
		return 0;
	}

	return FAULT_9005;
}

static int object_exists_check_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

int dm_entry_object_exists(struct dmctx *dmctx)
{
	int err = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->method_obj = object_exists_check_obj;
	dmctx->method_param = object_exists_check_param;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/* **************
 * Operate  
 * **************/
static int mobj_operate(DMOBJECT_ARGS)
{
	return USP_FAULT_INVALID_PATH;
}

static int mparam_operate(DMPARAM_ARGS)
{
	char full_param[MAX_DM_PATH];

	snprintf(full_param, MAX_DM_PATH, "%s%s", node->current_object, leaf->parameter);
	if (DM_STRCMP(full_param, dmctx->in_param) != 0)
		return USP_FAULT_INVALID_PATH;

	dmctx->stop = 1;

	if (!leaf->setvalue)
		return USP_FAULT_COMMAND_FAILURE;

	json_object *j_input = (dmctx->in_value) ? json_tokener_parse(dmctx->in_value) : NULL;
	int fault = (leaf->setvalue)(full_param, dmctx, data, instance, (char *)j_input, 0);
	json_object_put(j_input);

	return fault;
}

int dm_entry_operate(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err = 0;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0' || (*(dmctx->in_param + DM_STRLEN(dmctx->in_param) - 1) != ')'))
		return USP_FAULT_INVALID_PATH;

	dmctx->iscommand = 1;
	dmctx->inparam_isparam = 1;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;
	dmctx->method_obj = mobj_operate;
	dmctx->method_param = mparam_operate;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : USP_FAULT_INVALID_PATH;
}

/* **************
 * Event
 * **************/
static int mobj_event(DMOBJECT_ARGS)
{
	return USP_FAULT_INVALID_PATH;
}

static int mparam_event(DMPARAM_ARGS)
{
	char full_param[MAX_DM_PATH];
	int fault = 0;

	snprintf(full_param, MAX_DM_PATH, "%s%s", node->current_object, leaf->parameter);

	if (dmctx->iswildcard) {
		if (dm_strcmp_wildcard(dmctx->in_param, full_param) != 0)
			return USP_FAULT_INVALID_PATH;
	} else {
		if (DM_STRCMP(dmctx->in_param, full_param) != 0)
			return USP_FAULT_INVALID_PATH;
	}

	if (!leaf->setvalue) {
		dmctx->stop = 1;
		return USP_FAULT_INTERNAL_ERROR;
	}

	json_object *j_input = (dmctx->in_value) ? json_tokener_parse(dmctx->in_value) : NULL;

	fault = (leaf->setvalue)(full_param, dmctx, data, instance, (char *)j_input, EVENT_CHECK);
	if (fault)
		goto end;

	dmctx->stop = 1;

	blobmsg_add_string(&dmctx->bb, "name", full_param);
	void *array = blobmsg_open_array(&dmctx->bb, "input");

	fault = (leaf->setvalue)(full_param, dmctx, data, instance, (char *)j_input, EVENT_RUN);

	blobmsg_close_array(&dmctx->bb, array);

end:
	json_object_put(j_input);
	return fault;
}

int dm_entry_event(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err = 0;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0' || (*(dmctx->in_param + DM_STRLEN(dmctx->in_param) - 1) != '!'))
		return USP_FAULT_INVALID_PATH;

	dmctx->isevent = 1;
	dmctx->inparam_isparam = 1;
	dmctx->stop = 0;
	dmctx->checkobj = (dmctx->iswildcard) ? plugin_obj_wildcard_match : plugin_obj_match;
	dmctx->checkleaf = (dmctx->iswildcard) ? plugin_leaf_wildcard_match : plugin_leaf_match;
	dmctx->method_obj = mobj_event;
	dmctx->method_param = mparam_event;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : USP_FAULT_INVALID_PATH;
}

/* **********
 * get instances data base
 * **********/
typedef struct db_entry {
    struct list_head list;
    json_object *json_obj;
	char obj_name[32];
} db_entry_t;

struct retry_context {
	json_object *json_obj;
	struct uloop_timeout retry_timer;
	char file_path[128];
};

static json_object *find_db_json_obj(struct list_head *registered_db, const char *obj_name)
{
	db_entry_t *db_obj = NULL;

	if (list_empty(registered_db))
		return NULL;

	list_for_each_entry(db_obj, registered_db, list) {
		if (DM_STRCMP(db_obj->obj_name, obj_name) == 0)
			return db_obj->json_obj;
	}

	return NULL;
}

static json_object *register_new_db_json_obj(struct list_head *registered_db, const char *obj_name)
{
	db_entry_t *db_obj = NULL;

	if (!obj_name) {
		BBF_ERR("Invalid object name");
		return NULL;
	}

	db_obj = (db_entry_t *)calloc(1, sizeof(db_entry_t));
	if (!db_obj) {
		BBF_ERR("Failed to allocate memory");
		return NULL;
	}

	list_add_tail(&db_obj->list, registered_db);

	db_obj->json_obj = json_object_new_object();
	DM_STRNCPY(db_obj->obj_name, obj_name, sizeof(db_obj->obj_name));

	return db_obj->json_obj;
}

/**
 * @brief Write a JSON object to a file safely using exclusive locking.
 *
 * This function serializes the given `json_object` to the specified file path
 * using json-c's pretty formatting. It ensures safe concurrent access by
 * acquiring an exclusive file lock (`LOCK_EX`) before writing, preventing
 * other processes from reading or writing the file during the operation.
 *
 * Key behavior:
 * - Opens the file for writing (creates it if it does not exist).
 * - Acquires an exclusive lock (`LOCK_EX`) using `flock()` to ensure
 *   no other process reads or writes during the write.
 * - Serializes the JSON object using json-c with pretty formatting.
 * - Ensures that any readers using shared locks (`LOCK_SH`) are blocked
 *   during the write to avoid partial or inconsistent reads.
 * - Writes the data to the file stream (`FILE*`) derived from the file
 *   descriptor.
 * - Automatically flushes and closes the file, releasing the lock.
 *
 * @param file_path Full path to the JSON file to write.
 * @param json_obj Pointer to the `json_object` to serialize and store.
 * @return 0 on success, -1 on failure (file open, locking, or writing error).
 *
 * @note Any readers accessing this file should use `flock()` with `LOCK_SH`
 *       to avoid reading partial or inconsistent data while a write is in
 *       progress.
 */
static int bbfdm_json_object_to_file(const char *file_path, json_object *json_obj)
{
	// Open file for writing (create if it doesn't exist, truncate if it does)
	int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		BBF_ERR("Failed to open file for writing: %s", file_path);
		return -1;
	}

	// Acquire exclusive lock to prevent simultaneous writes
	if (flock(fd, LOCK_EX) == -1) {
		BBF_ERR("Failed to lock file: %s", file_path);
		close(fd);
		return -1;
	}

	// Associate a FILE* stream with the file descriptor
	FILE *fp = fdopen(fd, "w");
	if (!fp) {
		BBF_ERR("fdopen failed on file: %s", file_path);
		close(fd); // Releases the lock as well
		return -1;
	}

	// Serialize JSON object to string
	const char *json_str = json_object_to_json_string_ext(json_obj, JSON_C_TO_STRING_PRETTY);
	if (!json_str) {
		BBF_ERR("Failed to serialize JSON object");
		fclose(fp); // Closes fd and releases lock
		return -1;
	}

	// Write JSON string to file
	if (fprintf(fp, "%s\n", json_str) < 0) {
		BBF_ERR("Failed to write JSON to file: %s", file_path);
		fclose(fp); // Closes fd and releases lock
		return -1;
	}

	// Flush FILE* buffer and sync file descriptor to disk
	if (fflush(fp) != 0 || fsync(fd) != 0) {
		BBF_ERR("Failed to flush/sync JSON file: %s", file_path);
		fclose(fp); // Closes fd and releases lock
		return -1;
	}

	// Close stream (also closes file descriptor and releases lock)
	if (fclose(fp) != 0) {
		BBF_ERR("Failed to close file: %s", file_path);
		return -1;
	}

	return 0;
}

static void retry_write_cb(struct uloop_timeout *t)
{
	struct retry_context *ctx = container_of(t, struct retry_context, retry_timer);

	if (!ctx || !ctx->json_obj)
		return;

	int ret = bbfdm_json_object_to_file(ctx->file_path, ctx->json_obj);

	if (ret == 0) {
		BBF_INFO("Retry write succeeded: %s", ctx->file_path);
	} else {
		BBF_ERR("Retry write failed: %s", ctx->file_path);
	}

	json_object_put(ctx->json_obj);
	dmfree(ctx);
}

static void write_unregister_db_json_objs(struct list_head *registered_db)
{
	db_entry_t *db_obj = NULL, *tmp = NULL;

	list_for_each_entry_safe(db_obj, tmp, registered_db, list) {

		if (db_obj->json_obj) {
			char file_path[128] = {0};

			snprintf(file_path, sizeof(file_path), "%s/%s.json", DATA_MODEL_DB_PATH, db_obj->obj_name);

			int ret = bbfdm_json_object_to_file(file_path, db_obj->json_obj);

			if (ret != 0) {
				struct retry_context *ctx = dmcalloc(1, sizeof(struct retry_context));
				if (!ctx) {
					BBF_ERR("Failed to allocate retry context");
					json_object_put(db_obj->json_obj);
					goto cleanup;
				}

				BBF_ERR("Initial write to file failed: (%s). Scheduling retry in 500ms.", file_path);

				DM_STRNCPY(ctx->file_path, file_path, sizeof(ctx->file_path));
				ctx->json_obj = db_obj->json_obj;

				ctx->retry_timer.cb = retry_write_cb;
				uloop_timeout_set(&ctx->retry_timer, 500); // Retry after 500ms

			} else {
				json_object_put(db_obj->json_obj);
			}
		}

	cleanup:
		list_del(&db_obj->list);
		FREE(db_obj);
	}
}

static int mobj_get_references_db(DMOBJECT_ARGS)
{
	return 0;
}

static void add_path(struct list_head *registered_db, const char *path, const char *value)
{
	size_t count = 0;

	if (!path || !value)
		return;

	char **parts = strsplit(path, ".", &count);

	if (count < 2)
		return;

	// Path should be like: Device.X.Y.Z, so file name should use the second level which is X.json
	json_object *curr = find_db_json_obj(registered_db, parts[1]);
	if (curr == NULL) {
		curr = register_new_db_json_obj(registered_db, parts[1]);
	}

	if (curr == NULL)
		return;

	for (int i = 0; i < count; i++) {
		const char *key = parts[i];

		if (i == count - 1) {
			json_object_object_add(curr, key, json_object_new_string(value));
		} else {
			json_object *next = NULL;

			if (!json_object_object_get_ex(curr, key, &next)) {
				next = json_object_new_object();
				json_object_object_add(curr, key, next);
			}
			curr = next;
		}
	}
}

static int mparam_get_references_db(DMPARAM_ARGS)
{
	if (node->is_instanceobj == 0)
		return 0;

	if (leaf->dm_flags & DM_FLAG_LINKER) {
		char full_param[MAX_DM_PATH] = {0};
		char *value = dmstrdup("");

		snprintf(full_param, sizeof(full_param), "%s%s", node->current_object, leaf->parameter);

		(leaf->getvalue)(full_param, dmctx, data, instance, &value);

		add_path((struct list_head *)dmctx->addobj_instance, full_param, value);
	}

	return 0;
}

int dm_entry_references_db(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	LIST_HEAD(registered_db);
	int err = 0;

	ctx->inparam_isparam = 0;
	ctx->findparam = 1;
	ctx->stop = 0;
	ctx->checkobj = NULL;
	ctx->checkleaf = NULL;
	ctx->method_obj = mobj_get_references_db;
	ctx->method_param = mparam_get_references_db;
	ctx->addobj_instance = (void *)&registered_db; // This argument is used as internal variable to pass the address of registred DB list

	err = dm_browse(ctx, &node, root, NULL, NULL);

	write_unregister_db_json_objs(&registered_db);

	return (ctx->findparam == 0) ? err : 0;
}
