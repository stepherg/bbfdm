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
#define DEFAULT_LOG_LEVEL (2)

unsigned char gLogLevel = DEFAULT_LOG_LEVEL;
bool is_micro_service = false;

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

static int dm_strncmp_wildcard(char *str1, char *str2, size_t n)
{
	char *sp1 = str1, *sp2 = str2;
	size_t i = 0;

	if (str1 == NULL || str2 == NULL)
		return -1;

	while (*str2 && i < n) {
		if (*str1 == '\0')
			return -1;

		if ((*str2 == *str1) ||
				(sp2 != str2 && *str2 == '*' && is_instance_number_alias(&str1)) ||
				(sp1 != str1 && *str1 == '*' && is_instance_number_alias(&str2))) {
			str1++;
			str2++;
			i++;
		} else {
			return -1;
		}
	}

	if (i == n)
		return 0;

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

static void dm_browse_service(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, void *data, char *instance, char *parent_obj, int *err)
{
	DMNODE node = {0};

	node.obj = entryobj;
	node.parent = parent_node;
	node.is_ubus_service = true;

	if (dmctx->disable_mservice_browse == true)
		return;

	dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);

	if (dmctx->checkobj) {
		*err = dmctx->checkobj(dmctx, &node, NULL, NULL, NULL, NULL, data, instance);
		if (*err)
			return;
	}

	*err = dmctx->method_obj(dmctx, &node, NULL, NULL, NULL, NULL, data, instance);
	if (dmctx->stop)
		return;

	*err = dmctx->method_param(dmctx, &node, NULL, data, instance);
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

	if (!bbfdatamodel_matches(dmctx->dm_type, entryobj->bbfdm_type))
		return;

	if (entryobj->checkdep && (check_dependency(entryobj->checkdep) == false))
		return;

	if (entryobj->browseinstobj && dmctx->isgetschema)
		dmasprintf(&(node.current_object), "%s%s.{i}.", parent_obj, entryobj->obj);
	else
		dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);

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
							if (i == INDX_SERVICE_MOUNT)
								dm_browse_service(dmctx, parent_node, jentryobj, data, instance, parent_obj, &err);
							else
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

	if (parent_node->browse_type == BROWSE_FIND_MAX_INST) {
		int curr_inst = (instance && *instance != '\0') ? DM_STRTOL(instance) : 0;
		if (curr_inst > parent_node->max_instance)
			parent_node->max_instance = curr_inst;
		return 0;
	}

	parent_node->num_of_entries++;
	if (parent_node->browse_type == BROWSE_NUM_OF_ENTRIES)
		return 0;

	DMOBJ *prevobj = parent_node->obj;
	DMOBJ *nextobj = prevobj->nextobj;
	DMLEAF *nextleaf = prevobj->leaf;

	node.obj = prevobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level + 1;
	node.is_instanceobj = 1;
	node.matched = parent_node->matched;

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

static int rootcmp(char *inparam, char *rootobj)
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

	node.browse_type = BROWSE_NUM_OF_ENTRIES;
	(browseinstobj)(ctx, &node, data, instance);
	return node.num_of_entries;
}

static int get_instance_mode(struct dmctx *dmctx, DMNODE *node)
{
	unsigned char instancelevel = node->instance_level;
	int inst_mode = INSTANCE_MODE_NUMBER;

	if (dmctx->nbrof_instance <= instancelevel) {
		if (dmctx->instance_mode == INSTANCE_MODE_ALIAS)
			inst_mode = INSTANCE_MODE_ALIAS;
	} else if (dmctx->alias_register & (1 << instancelevel)) {
		inst_mode = INSTANCE_MODE_ALIAS;
	}

	return inst_mode;
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

char *handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct uci_section *s, char *inst_opt, char *alias_opt)
{
	char buf[64] = {0};
	char *instance = "";

	dmuci_get_value_by_section_string(s, inst_opt, &instance);

	switch(parent_node->browse_type) {
	case BROWSE_NORMAL:
		if (instance && *instance == '\0') {
			int max_inst = find_max_instance(dmctx, parent_node);
			snprintf(buf, sizeof(buf), "%d", max_inst);
			dmuci_set_value_by_section(s, inst_opt, buf);
			instance = dmstrdup(buf);
		}

		int inst_mode = get_instance_mode(dmctx, parent_node);

		if (inst_mode == INSTANCE_MODE_ALIAS) {
			char *alias = "";

			dmuci_get_value_by_section_string(s, alias_opt, &alias);
			if (alias && alias[0] == '\0') {
				snprintf(buf, sizeof(buf), "cpe-%s", instance);
				dmuci_set_value_by_section(s, alias_opt, buf);
				alias = dmstrdup(buf);
			}
			snprintf(buf, sizeof(buf), "[%s]", alias);
			instance = dmstrdup(buf);
		}
		break;
	case BROWSE_FIND_MAX_INST:
	case BROWSE_NUM_OF_ENTRIES:
		break;
	}

	dmctx->inst_buf[parent_node->instance_level] = instance;
	return instance;
}

char *handle_instance_without_section(struct dmctx *dmctx, DMNODE *parent_node, int inst_nbr)
{
	char *instance = "";

	switch(parent_node->browse_type) {
	case BROWSE_NORMAL:
		dmasprintf(&instance, "%d", inst_nbr);
		int inst_mode = get_instance_mode(dmctx, parent_node);
		if (inst_mode == INSTANCE_MODE_ALIAS)
			dmasprintf(&instance, "[cpe-%d]", inst_nbr);
		break;
	case BROWSE_FIND_MAX_INST:
	case BROWSE_NUM_OF_ENTRIES:
		break;
	}

	dmctx->inst_buf[parent_node->instance_level] = instance;
	return instance;
}

char *update_instance(char *max_inst, int argc, ...)
{
	va_list arg;
	char *instance, *last_inst = NULL;
	int i = 0;
	void *argv[8] = {0};

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, void*);
	}
	va_end(arg);

	instance = update_instance_alias(0, &last_inst, &max_inst, argv);

	return instance;
}

static int get_max_instance(char *dmmap_package, char *section_type, char *inst_opt, int (*check_browse)(struct uci_section *section, void *data), void *data)
{
	struct uci_section *s;
	char *inst;
	int max = 0;

	uci_path_foreach_sections(bbfdm, dmmap_package, section_type, s) {
		if (check_browse && check_browse(s, data) != 0)
			continue;

		dmuci_get_value_by_section_string(s, inst_opt, &inst);
		if (DM_STRLEN(inst) == 0)
			continue;

		int instance = DM_STRTOL(inst);

		max = max > instance ? max : instance;
	}

	return max;
}

char *update_instance_alias(int action, char **last_inst, char **max_inst, void *argv[])
{
	char *instance, *alias;
	char buf[64] = {0};
	int max_instance = 0;

	struct uci_section *s = (struct uci_section *) argv[0];
	char *inst_opt = (char *) argv[1];
	char *alias_opt = (char *) argv[2];
	int (*check_browse)(struct uci_section *section, void *data) = argv[3];
	void *data = (void *) argv[4];

	if (*max_inst == NULL)
		max_instance = get_max_instance(section_config(s), section_type(s), inst_opt, check_browse, data);
	else
		max_instance = DM_STRTOL(*max_inst);

	dmuci_get_value_by_section_string(s, inst_opt, &instance);
	if (instance[0] == '\0') {
		snprintf(buf, sizeof(buf), "%d", max_instance + 1);
		dmuci_set_value_by_section(s, inst_opt, buf);
		*max_inst = dmstrdup(instance);
	} else {
		dmasprintf(max_inst, "%d", max_instance);
	}
	*last_inst = instance;

	if (action == INSTANCE_MODE_ALIAS) {
		dmuci_get_value_by_section_string(s, alias_opt, &alias);
		if (alias[0] == '\0') {
			snprintf(buf, sizeof(buf), "cpe-%s", instance);
			dmuci_set_value_by_section(s, alias_opt, buf);
			alias = dmstrdup(buf);
		}
		snprintf(buf, sizeof(buf), "[%s]", alias);
		instance = dmstrdup(buf);
	}
	return instance;
}

int get_empty(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

void add_list_parameter(struct dmctx *ctx, char *param_name, char *param_data, char *param_type, char *additional_data)
{
	struct dm_parameter *dm_parameter;

	dm_parameter = dmcalloc(1, sizeof(struct dm_parameter));
	list_add_tail(&dm_parameter->list, &ctx->list_parameter);
	dm_parameter->name = param_name;
	dm_parameter->data = param_data;
	dm_parameter->type = param_type;
	dm_parameter->additional_data = additional_data;
}

static void api_del_list_parameter(struct dm_parameter *dm_parameter)
{
	list_del(&dm_parameter->list);
	dmfree(dm_parameter->name);
	dmfree(dm_parameter);
}

void free_all_list_parameter(struct dmctx *ctx)
{
	struct dm_parameter *dm_parameter = NULL;
	while (ctx->list_parameter.next != &ctx->list_parameter) {
		dm_parameter = list_entry(ctx->list_parameter.next, struct dm_parameter, list);
		api_del_list_parameter(dm_parameter);
	}
}

int string_to_bool(char *v, bool *b)
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

char *get_value_by_reference(struct dmctx *ctx, char *value)
{
	char *pch = NULL, *spch = NULL, *val = NULL;
	char buf[MAX_DM_PATH * 4] = {0};
	char buf_val[MAX_DM_PATH * 4] = {0};
	bool is_list = false;
	int pos = 0;

	if (DM_STRLEN(value) == 0 || !DM_LSTRSTR(value, "=="))
		return value;

	DM_STRNCPY(buf, value, sizeof(buf));

	if (DM_STRCHR(buf, '&'))
		is_list = true;

	buf_val[0] = 0;

	for (pch = strtok_r(buf, is_list ? "&" : ",", &spch); pch; pch = strtok_r(NULL, is_list ? "&" : ",", &spch)) {
		char path[MAX_DM_PATH] = {0};
		char key_name[256], key_value[256];
		regmatch_t pmatch[2];

		bool res = match(pch, "\\[(.*?)\\]", 2, pmatch);
		if (!res)
			goto end;

		snprintf(path, pmatch[0].rm_so + 1, "%s", pch);
		int len = DM_STRLEN(path);
		if (!len)
			goto end;

		char *match_str = pch + pmatch[1].rm_so;
		if (DM_STRLEN(match_str) == 0)
			goto end;

		int n = sscanf(match_str, "%255[^=]==\"%255[^\"]\"", key_name, key_value);
		if (n != 2) {
			n = sscanf(match_str, "%255[^=]==%255[^]]", key_name, key_value);
			if (n != 2) {
				goto end;
			}
		}

		snprintf(path + len, sizeof(path) - len, "*.%s", key_name);

		adm_entry_get_reference_param(ctx, path, key_value, &val);

		if (DM_STRLEN(val)) {
			pos += snprintf(&buf_val[pos], sizeof(buf_val) - pos, "%s,", val);

			if (!is_list) // Requested value is not list
				break;
		}
	}

	if (DM_STRLEN(buf_val)) {
		buf_val[pos - 1] = 0;
		return dmstrdup(buf_val);
	}

end:
	return is_micro_service ? value : "";
}

static bool has_same_reference(char *curr_value, char *new_value)
{
	struct dm_reference reference = {0};
	char buf[MAX_DM_PATH * 4] = {0};
	char param_value[2048] = {0};
	char *pch = NULL, *spch = NULL;

	snprintf(param_value, sizeof(param_value), "%s", new_value);
	bbf_get_reference_args(param_value, &reference);

	DM_STRNCPY(buf, curr_value, sizeof(buf));

	for (pch = strtok_r(buf, ",", &spch); pch; pch = strtok_r(NULL, ",", &spch)) {
		char key_name[256] = {0}, key_value[256] = {0};
		regmatch_t pmatch[2];

		bool res = match(pch, "\\[(.*?)\\]", 2, pmatch);
		if (!res && DM_STRCMP(pch, reference.path) == 0)
			return true;

		int len = pmatch[0].rm_so;
		if (len <= 0)
			continue;

		char *match_str = pch + pmatch[1].rm_so;
		if (DM_STRLEN(match_str) == 0)
			continue;

		int n = sscanf(match_str, "%255[^=]==\"%255[^\"]\"", key_name, key_value);
		if (n != 2)
			continue;

		if (dm_strncmp_wildcard(pch, reference.path, len) == 0 && DM_STRCMP(key_value, reference.value) == 0)
			return true;
	}

	return false;
}

static char *check_value_by_type(char *value, int type)
{
	int i = 0, len = DM_STRLEN(value);
	char buf[len + 1];
	struct tm tm;

	snprintf(buf, sizeof(buf), "%s", value);

	switch (type) {
		case DMT_UNINT:
		case DMT_UNLONG:
			while (buf[i] != 0) {
				if (isdigit(buf[i]) == 0)
					return "0";
				i++;
			}
			break;
		case DMT_INT:
		case DMT_LONG:
			if (buf[i] == '-')
				i++;
			while (buf[i] != 0) {
				if (isdigit(buf[i]) == 0)
					return "0";
				i++;
			}
			break;
		case DMT_BOOL:
			return dmuci_string_to_boolean(buf) ? "1" : "0";
		case DMT_HEXBIN:
			while (buf[i] != 0) {
				if (isxdigit(buf[i]) == 0)
					return "";
				i++;
			}
			break;
		case DMT_BASE64:
			while (buf[i] != 0) {
				if (is64digit(buf[i]) == 0)
					return "0";
				i++;
			}
			break;
		case DMT_TIME:
			if (!strptime(buf, "%Y-%m-%dT%H:%M:%S", &tm))
				return "0001-01-01T00:00:00Z";
			break;
		default:
			break;
	}
	return value;
}

static char *get_default_value_by_type(int type)
{
	switch (type) {
		case DMT_UNINT:
		case DMT_INT:
		case DMT_UNLONG:
		case DMT_LONG:
		case DMT_BOOL:
			return "0";
		case DMT_BASE64:
			return "AA=="; // base64 encoded hex value 00
		case DMT_TIME:
			return "0001-01-01T00:00:00Z";
		default:
			return "";
	}
}

void dmentry_instance_lookup_inparam(struct dmctx *ctx)
{
	char *pch, *spch, *in_param;
	in_param = dmstrdup(ctx->in_param);
	int i = 0;

	for (pch = strtok_r(in_param, ".", &spch); pch != NULL; pch = strtok_r(NULL, ".", &spch)) {
		if (pch[0]== '[') {
			ctx->alias_register |= (1 << i);
			i++;
		} else if (isdigit(pch[0])) {
			i++;
		}
	}
	dmfree(in_param);
	ctx->nbrof_instance = i;
}

static void get_reference_paramater_value(struct dmctx *dmctx, char *in_value, char *str, size_t size)
{
	char *pch = NULL, *pchr = NULL;
	char buf[2048] = {0};
	unsigned int pos = 0;

	if (!in_value || !str || !size)
		return;

	memset(str, 0, size);

	if (DM_STRLEN(in_value) == 0) {
		DM_STRNCPY(str, "=>", size);
		return;
	}

	DM_STRNCPY(buf, in_value, sizeof(buf));

	for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
		uint32_t len = DM_STRLEN(pch);
		char *linker = NULL;

		if (len && pch[len - 1] == '.')
			pch[len - 1] = 0;

		adm_entry_get_reference_value(dmctx, pch, &linker);

		pos += snprintf((char *)str + pos, size - pos, "%s=>%s,", pch, linker ? linker : "");
	}

	if (pos)
		str[pos - 1] = 0;
}

static int get_ubus_value(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;
	char *in_path = (dmctx->in_param[0] == '\0' || rootcmp(dmctx->in_param, "Device") == 0) ? node->current_object : dmctx->in_param;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "get",
			UBUS_ARGS{
						{"path", in_path, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			2, &res);

	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	if (nbre_obj == 0) {
		dmctx->findparam = 1;
		return 0;
	}

	for (size_t i = 0; i < nbre_obj; i++) {
		uint32_t *dm_flags = NULL;

		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			return DM_STRTOUL(fault);

		dmctx->findparam = 1;

		char *path = dmjson_get_value(res_obj, 1, "path");
		char *data = dmjson_get_value(res_obj, 1, "data");
		char *type = dmjson_get_value(res_obj, 1, "type");

		json_object *flags_array = dmjson_get_obj(res_obj, 1, "flags");
		if (flags_array) {
			size_t nbre_falgs = json_object_array_length(flags_array);

			dm_flags = (uint32_t *)dmcalloc(1, sizeof(uint32_t));

			for (size_t j = 0; j < nbre_falgs; j++) {
				json_object *flag_obj = json_object_array_get_idx(flags_array, j);

				const char *flag = json_object_get_string(flag_obj);

				if (DM_LSTRCMP(flag, "Reference") == 0) {
					data = get_value_by_reference(dmctx, data);
					*dm_flags |= DM_FLAG_REFERENCE;
				} else if (DM_LSTRCMP(flag, "Unique") == 0) {
					*dm_flags |= DM_FLAG_UNIQUE;
				} else if (DM_LSTRCMP(flag, "Linker") == 0) {
					*dm_flags |= DM_FLAG_LINKER;
				} else if (DM_LSTRCMP(flag, "Secure") == 0) {
					*dm_flags |= DM_FLAG_SECURE;
				}
			}
		}

		add_list_parameter(dmctx, dmstrdup(path), dmstrdup(data), dmstrdup(type), (char *)dm_flags);
	}

	return 0;
}

static int get_ubus_supported_dm(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;
	char *in_path = (dmctx->in_param[0] == '\0' || rootcmp(dmctx->in_param, "Device") == 0) ? node->current_object : dmctx->in_param;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "schema",
			UBUS_ARGS{
						{"path", in_path, String},
						{"first_level", dmctx->nextlevel ? "1" : "0", Boolean},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			3, &res);

	json_object_put(in_args);

	if (!res)
		return 0;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return 0;

	size_t nbre_obj = json_object_array_length(res_array);
	if (nbre_obj == 0) {
		dmctx->findparam = 1;
		return 0;
	}

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			continue;

		dmctx->findparam = 1;

		char *path = dmjson_get_value(res_obj, 1, "path");
		char *data = dmjson_get_value(res_obj, 1, "data");
		char *type = dmjson_get_value(res_obj, 1, "type");

		if (DM_LSTRCMP(type, "xsd:object") == 0) { //Object
			add_list_parameter(dmctx, dmstrdup(path), dmstrdup(data), "xsd:object", NULL);
		} else if (DM_LSTRCMP(type, "xsd:command") == 0) { //Command Leaf
			operation_args *op = NULL;

			op = dmcalloc(1, sizeof(operation_args));

			json_object *input_array = dmjson_get_obj(res_obj, 1, "input");
			if (input_array) {
				size_t j = 0;
				size_t in_nbre = json_object_array_length(input_array);
				op->in = dmcalloc(in_nbre + 1, sizeof(char *));

				for (j = 0; j < in_nbre; j++) {
					json_object *res_obj = json_object_array_get_idx(input_array, j);

					char *in_path = dmjson_get_value(res_obj, 1, "path");
					op->in[j] = dmstrdup(in_path);
				}
				op->in[j] = NULL;
			}

			json_object *output_array = dmjson_get_obj(res_obj, 1, "output");
			if (output_array) {
				size_t j = 0;
				size_t out_nbre = json_object_array_length(output_array);
				op->out = dmcalloc(out_nbre + 1, sizeof(char *));

				for (j = 0; j < out_nbre; j++) {
					json_object *res_obj = json_object_array_get_idx(output_array, j);

					char *in_path = dmjson_get_value(res_obj, 1, "path");
					op->out[j] = dmstrdup(in_path);
				}
				op->out[j] = NULL;
			}

			add_list_parameter(dmctx, dmstrdup(path), (char *)op, "xsd:command", dmstrdup(data));
		} else if (DM_LSTRCMP(type, "xsd:event") == 0) { //Event Leaf
			event_args *ev = NULL;

			json_object *input_array = dmjson_get_obj(res_obj, 1, "input");
			if (input_array) {
				ev = dmcalloc(1, sizeof(event_args));

				size_t j = 0;
				size_t in_nbre = json_object_array_length(input_array);
				ev->param = dmcalloc(in_nbre + 1, sizeof(char *));

				for (j = 0; j < in_nbre; j++) {
					json_object *res_obj = json_object_array_get_idx(input_array, j);

					char *in_path = dmjson_get_value(res_obj, 1, "path");
					ev->param[j] = dmstrdup(in_path);
				}
				ev->param[j] = NULL;
			}

			add_list_parameter(dmctx, dmstrdup(path), (char *)ev, "xsd:event", NULL);
		} else { //Param Leaf
			uint32_t *dm_flags = NULL;

			json_object *flags_array = dmjson_get_obj(res_obj, 1, "flags");
			if (flags_array) {
				size_t nbre_falgs = json_object_array_length(flags_array);

				dm_flags = (uint32_t *)dmcalloc(1, sizeof(uint32_t));

				for (size_t j = 0; j < nbre_falgs; j++) {
					json_object *flag_obj = json_object_array_get_idx(flags_array, j);

					const char *flag = json_object_get_string(flag_obj);

					if (DM_LSTRCMP(flag, "Reference") == 0) {
						data = get_value_by_reference(dmctx, data);
						*dm_flags |= DM_FLAG_REFERENCE;
					} else if (DM_LSTRCMP(flag, "Unique") == 0) {
						*dm_flags |= DM_FLAG_UNIQUE;
					} else if (DM_LSTRCMP(flag, "Linker") == 0) {
						*dm_flags |= DM_FLAG_LINKER;
					} else if (DM_LSTRCMP(flag, "Secure") == 0) {
						*dm_flags |= DM_FLAG_SECURE;
					}
				}
			}

			add_list_parameter(dmctx, dmstrdup(path), dmstrdup(data), dmstrdup(type), (char *)dm_flags);
		}
	}

	return 0;
}

static int get_ubus_instances(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "instances",
			UBUS_ARGS{
						{"path", dmctx->in_param, String},
						{"first_level", dmctx->nextlevel ? "1" : "0", Boolean},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			3, &res);

	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	if (nbre_obj == 0) {
		dmctx->findparam = 1;
		return 0;
	}

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			return DM_STRTOUL(fault);

		dmctx->findparam = 1;

		char *path = dmjson_get_value(res_obj, 1, "path");

		add_list_parameter(dmctx, dmstrdup(path), NULL, "xsd:object", NULL);
	}

	return 0;
}

static int add_ubus_object(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));
	json_object_object_add(in_args, "transaction_id", json_object_new_int(dmctx->trans_id));

	dmubus_call(ubus_name, "add",
			UBUS_ARGS{
						{"path", dmctx->in_param, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			2, &res);
	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault)) {
			char *fault_msg = dmjson_get_value(res_obj, 1, "fault_msg");
			bbfdm_set_fault_message(dmctx, "%s", fault_msg);
			return DM_STRTOUL(fault);
		}

		char *data = dmjson_get_value(res_obj, 1, "data");

		dmctx->stop = 1;
		dmctx->addobj_instance = dmstrdup(data);
	}

	return 0;
}

static int del_ubus_object(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));
	json_object_object_add(in_args, "transaction_id", json_object_new_int(dmctx->trans_id));

	dmubus_call(ubus_name, "del",
			UBUS_ARGS{
						{"path", dmctx->in_param, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			2, &res);
	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		dmctx->stop = 1;

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault)) {
			char *fault_msg = dmjson_get_value(res_obj, 1, "fault_msg");
			bbfdm_set_fault_message(dmctx, "%s", fault_msg);
			return DM_STRTOUL(fault);
		}
	}

	return 0;
}

static bool is_reference_parameter(char *ubus_name, char *param_name, json_object *in_args)
{
	json_object *res = NULL, *res_obj = NULL;

	dmubus_call(ubus_name, "get",
			UBUS_ARGS{
						{"path", param_name, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			2, &res);

	if (!res)
		return false;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return false;

	res_obj = json_object_array_get_idx(res_array, 0);
	if (!res_obj)
		return false;

	char *flags_list = dmjson_get_value_array_all(res_obj, ",", 1, "flags");

	return DM_LSTRSTR(flags_list, "Reference") ? true : false;
}

static int set_ubus_value(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;
	char param_value[2048] = {0};

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));
	json_object_object_add(in_args, "transaction_id", json_object_new_int(dmctx->trans_id));

	if (is_reference_parameter(ubus_name, dmctx->in_param, in_args)) {
		get_reference_paramater_value(dmctx, dmctx->in_value, param_value, sizeof(param_value));
	} else {
		snprintf(param_value, sizeof(param_value), "%s", dmctx->in_value);
	}

	dmubus_call(ubus_name, "set",
			UBUS_ARGS{
						{"path", dmctx->in_param, String},
						{"value", param_value, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			3, &res);
	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		dmctx->stop = 1;

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault)) {
			char *fault_msg = dmjson_get_value(res_obj, 1, "fault_msg");
			bbfdm_set_fault_message(dmctx, "%s", fault_msg);
			return DM_STRTOUL(fault);
		}
	}

	return 0;
}

static int get_ubus_name(struct dmctx *dmctx, struct dmnode *node)
{
	unsigned int in_path_dot_num = count_occurrences(dmctx->in_param, '.');
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;
	char *in_path = (dmctx->in_param[0] == '\0' || rootcmp(dmctx->in_param, "Device") == 0) ? node->current_object : dmctx->in_param;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string("cwmp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "schema",
			UBUS_ARGS{
						{"path", in_path, String},
						{"first_level", dmctx->nextlevel ? "1" : "0", Boolean},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			3, &res);

	json_object_put(in_args);

	if (!res)
		return 0;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return 0;

	size_t nbre_obj = json_object_array_length(res_array);

	if (nbre_obj == 0) {
		dmctx->findparam = 1;
		return 0;
	}

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			return DM_STRTOUL(fault);

		dmctx->findparam = 1;

		if (i == 0 &&  dmctx->nextlevel && (count_occurrences(node->current_object, '.') == in_path_dot_num + 1))
			add_list_parameter(dmctx, dmstrdup(node->current_object), "0", "xsd:object", NULL);

		char *path = dmjson_get_value(res_obj, 1, "path");
		char *data = dmjson_get_value(res_obj, 1, "data");
		char *type = dmjson_get_value(res_obj, 1, "type");

		if (dmctx->nextlevel) {
			unsigned int path_dot_num = count_occurrences(path, '.');
			size_t len = DM_STRLEN(path);

			if ((path[len - 1] == '.' && path_dot_num > in_path_dot_num + 1) ||
				(path[len - 1] != '.' && path_dot_num > in_path_dot_num))
				continue;
		}

		add_list_parameter(dmctx, dmstrdup(path), dmstrdup(data), dmstrdup(type), NULL);
	}

	return 0;
}

static int operate_ubus(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "operate",
			UBUS_ARGS{
						{"command", dmctx->in_param, String},
						{"command_key", dmctx->linker, String},
						{"input", dmctx->in_value ? dmctx->in_value : "{}", Table},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			4, &res);

	json_object_put(in_args);

	dmctx->stop = 1;

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			return DM_STRTOUL(fault);

		json_object *output_array = dmjson_get_obj(res_obj, 1, "output");
		if (output_array) {
			size_t out_nbre = json_object_array_length(output_array);

			for (size_t j = 0; j < out_nbre; j++) {
				json_object *out_obj = json_object_array_get_idx(output_array, j);

				char *path = dmjson_get_value(out_obj, 1, "path");
				char *data = dmjson_get_value(out_obj, 1, "data");
				char *type = dmjson_get_value(out_obj, 1, "type");

				add_list_parameter(dmctx, dmstrdup(path), dmstrdup(data), dmstrdup(type), NULL);
			}
		}
	}

	return 0;
}

static int get_ubus_reference_value(struct dmctx *dmctx, struct dmnode *node)
{
	unsigned int in_path_dot_num = count_occurrences(dmctx->in_param, '.');
	char *ubus_name = node->obj->checkdep;
	json_object *res = NULL;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "get",
			UBUS_ARGS{
						{"path", dmctx->in_param, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			2, &res);

	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);
	if (nbre_obj == 0)
		return FAULT_9005;

	for (size_t i = 0; i < nbre_obj; i++) {
		json_object *res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			return DM_STRTOUL(fault);

		char *path = dmjson_get_value(res_obj, 1, "path");

		unsigned int path_dot_num = count_occurrences(path, '.');
		if (path_dot_num > in_path_dot_num)
			continue;

		json_object *flags_array = dmjson_get_obj(res_obj, 1, "flags");
		if (flags_array) {
			size_t nbre_falgs = json_object_array_length(flags_array);

			for (size_t j = 0; j < nbre_falgs; j++) {
				json_object *flag_obj = json_object_array_get_idx(flags_array, j);

				const char *flag = json_object_get_string(flag_obj);

				if (DM_LSTRCMP(flag, "Linker") == 0) {
					char *data = dmjson_get_value(res_obj, 1, "data");
					dmctx->linker = data ? dmstrdup(data) : "";
					dmctx->stop = true;
					return 0;
				}
			}
		}
	}

	return FAULT_9005;
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
	if (node->is_ubus_service) {
		return get_ubus_value(dmctx, node);
	} else {
		char *full_param;
		char *value = "";

		dmastrcat(&full_param, node->current_object, leaf->parameter);
		(leaf->getvalue)(full_param, dmctx, data, instance, &value);

		if ((leaf->dm_falgs & DM_FLAG_SECURE) && (dmctx->dm_type == BBFDM_CWMP)) {
			value = "";
		} else if (value && *value) {
			if (leaf->dm_falgs & DM_FLAG_REFERENCE) {
				value = get_value_by_reference(dmctx, value);
			} else {
				value = check_value_by_type(value, leaf->type);
			}
		} else {
			value = get_default_value_by_type(leaf->type);
		}

		add_list_parameter(dmctx, full_param, value, DMT_TYPE[leaf->type], leaf->dm_falgs ? (char *)&leaf->dm_falgs : NULL);
	}

	return 0;
}

static int mobj_get_value_in_param(DMOBJECT_ARGS)
{
	return 0;
}
static int mparam_get_value_in_param(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		int err = get_ubus_value(dmctx, node);
		if (err)
			return FAULT_9005;

		dmctx->findparam = (dmctx->iswildcard) ? 1 : 0;
		dmctx->stop = (dmctx->iswildcard) ? false : true;
	} else {
		char *full_param;
		char *value = "";

		dmastrcat(&full_param, node->current_object, leaf->parameter);

		if (dmctx->iswildcard) {
			if (dm_strcmp_wildcard(dmctx->in_param, full_param) != 0) {
				dmfree(full_param);
				return FAULT_9005;
			}
		} else {
			if (DM_STRCMP(dmctx->in_param, full_param) != 0) {
				dmfree(full_param);
				return FAULT_9005;
			}
		}

		(leaf->getvalue)(full_param, dmctx, data, instance, &value);

		if ((leaf->dm_falgs & DM_FLAG_SECURE) && (dmctx->dm_type == BBFDM_CWMP)) {
			value = "";
		} else if (value && *value) {
			if (leaf->dm_falgs & DM_FLAG_REFERENCE) {
				value = get_value_by_reference(dmctx, value);
			} else
				value = check_value_by_type(value, leaf->type);
		} else {
			value = get_default_value_by_type(leaf->type);
		}

		add_list_parameter(dmctx, full_param, value, DMT_TYPE[leaf->type], leaf->dm_falgs ? (char *)&leaf->dm_falgs : NULL);

		dmctx->findparam = (dmctx->iswildcard) ? 1 : 0;
		dmctx->stop = (dmctx->iswildcard) ? false : true;
	}

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
static int mobj_get_name(DMOBJECT_ARGS)
{
	if (node->is_ubus_service) {
		return 0;
	} else {
		char *refparam = node->current_object;
		char *perm = permission->val;

		if (permission->get_permission != NULL)
			perm = permission->get_permission(refparam, dmctx, data, instance);

		add_list_parameter(dmctx, refparam, perm, "xsd:object", NULL);
		return 0;
	}
}

static int mparam_get_name(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		get_ubus_name(dmctx, node);
		return 0;
	} else {
		char *refparam;
		char *perm = leaf->permission->val;

		dmastrcat(&refparam, node->current_object, leaf->parameter);
		if (leaf->permission->get_permission != NULL)
			perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

		add_list_parameter(dmctx, refparam, perm, DMT_TYPE[leaf->type], NULL);
		return 0;
	}
}

static int mobj_get_name_in_param(DMOBJECT_ARGS)
{
	return 0;
}

static int mparam_get_name_in_param(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		int err = get_ubus_name(dmctx, node);
		dmctx->stop = true;
		return err ? err : 0;
	} else {
		char *refparam;
		char *perm = leaf->permission->val;

		dmastrcat(&refparam, node->current_object, leaf->parameter);

		if (dmctx->iswildcard) {
			if (dm_strcmp_wildcard(refparam, dmctx->in_param) != 0) {
				dmfree(refparam);
				return FAULT_9005;
			}
		} else {
			if (DM_STRCMP(refparam, dmctx->in_param) != 0) {
				dmfree(refparam);
				return FAULT_9005;
			}
		}

		dmctx->stop = (dmctx->iswildcard) ? 0 : 1;

		if (dmctx->nextlevel == 1) {
			dmctx->stop = 1;
			dmfree(refparam);
			return FAULT_9003;
		}

		if (leaf->permission->get_permission != NULL)
			perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

		add_list_parameter(dmctx, refparam, perm, DMT_TYPE[leaf->type], NULL);
		dmctx->findparam = (dmctx->iswildcard) ? 1 : 0;
		return 0;
	}
}

static int mobj_get_name_in_obj(DMOBJECT_ARGS)
{
	if (node->is_ubus_service) {
		return 0;
	} else {
		char *refparam = node->current_object;
		char *perm = permission->val;

		if (!node->matched)
			return FAULT_9005;

		if (dmctx->iswildcard) {
			if (dmctx->nextlevel && dm_strcmp_wildcard(node->current_object, dmctx->in_param) == 0)
				return 0;
		} else {
			if (dmctx->nextlevel && DM_STRCMP(node->current_object, dmctx->in_param) == 0)
				return 0;
		}

		if (permission->get_permission != NULL)
			perm = permission->get_permission(refparam, dmctx, data, instance);

		add_list_parameter(dmctx, refparam, perm, "xsd:object", NULL);
		return 0;
	}
}

static int mparam_get_name_in_obj(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		return get_ubus_name(dmctx, node);
	} else {
		char *refparam;
		char *perm = leaf->permission->val;

		dmastrcat(&refparam, node->current_object, leaf->parameter);

		if (leaf->permission->get_permission != NULL)
			perm = leaf->permission->get_permission(refparam, dmctx, data, instance);

		add_list_parameter(dmctx, refparam, perm, DMT_TYPE[leaf->type], NULL);
		return 0;
	}
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
		ctx->in_param = root->obj;
		ctx->disable_mservice_browse = true;
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
	if (node->is_ubus_service) {
		return 0;
	} else {
		char *perm = permission ? permission->val : "0";
		char *refparam = node->current_object;

		if (node->matched && dmctx->isinfo) {
			add_list_parameter(dmctx, refparam, perm, "xsd:object", NULL);
		}
	}

	return 0;
}

static int mparam_get_supported_dm(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		return get_ubus_supported_dm(dmctx, node);
	} else {
		char *value = NULL;
		char *refparam;

		dmastrcat(&refparam, node->current_object, leaf->parameter);

		if (node->matched) {
			if (leaf->type == DMT_EVENT) {
				if (dmctx->isevent) {
					if (leaf->getvalue)
						(leaf->getvalue)(refparam, dmctx, data, instance, &value);

					add_list_parameter(dmctx, refparam, value, DMT_TYPE[leaf->type], NULL);
				}

			} else if (leaf->type == DMT_COMMAND) {
				if (dmctx->iscommand) {

					if (leaf->getvalue)
						(leaf->getvalue)(refparam, dmctx, data, instance, &value);

					add_list_parameter(dmctx, refparam, value, DMT_TYPE[leaf->type], leaf->permission->val);
				}
			} else {
				add_list_parameter(dmctx, refparam, leaf->permission->val, DMT_TYPE[leaf->type], leaf->dm_falgs ? (char *)&leaf->dm_falgs : NULL);
			}
		}

		return 0;
	}
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
	if (node->is_ubus_service) {
		return get_ubus_instances(dmctx, node);
	} else {
		if (node->matched && node->is_instanceobj) {
			char *name = dmstrdup(node->current_object);

			if (name) {
				name[DM_STRLEN(name) - 1] = 0;
				add_list_parameter(dmctx, name, NULL, "xsd:object", NULL);
			}
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

	if (ctx->iswildcard) {
		ctx->checkobj = (ctx->nextlevel) ? plugin_obj_wildcard_nextlevel_match : plugin_obj_wildcard_match;
		ctx->checkleaf = (ctx->nextlevel) ? plugin_leaf_wildcard_nextlevel_match : plugin_leaf_wildcard_match;
	} else {
		ctx->checkobj = (ctx->nextlevel) ? plugin_obj_nextlevel_match : plugin_obj_match;
		ctx->checkleaf = (ctx->nextlevel) ? plugin_leaf_nextlevel_match : plugin_leaf_match;
	}
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
	if (node->is_ubus_service) {
		return add_ubus_object(dmctx, node);
	} else {
		char *refparam = node->current_object;
		char *perm = permission->val;
		char *new_instance = NULL;
		int fault = 0;

		if (DM_STRCMP(refparam, dmctx->in_param) != 0)
			return FAULT_9005;

		if (node->is_instanceobj)
			return FAULT_9005;

		if (permission->get_permission != NULL)
			perm = permission->get_permission(refparam, dmctx, data, instance);

		if (perm[0] == '0' || addobj == NULL)
			return FAULT_9005;

		int max_inst = find_max_instance(dmctx, node);
		fault = dmasprintf(&new_instance, "%d", max_inst);
		if (fault)
			return fault;

		dmctx->stop = 1;

		fault = (addobj)(refparam, dmctx, data, &new_instance);
		if (fault)
			return fault;

		dmctx->addobj_instance = new_instance;
		return 0;
	}
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
	if (node->is_ubus_service) {
		return del_ubus_object(dmctx, node);
	} else {
		char *refparam = node->current_object;
		char *perm = permission->val;
		unsigned char del_action = DEL_INST;

		if (DM_STRCMP(refparam, dmctx->in_param) != 0)
			return FAULT_9005;

		dmctx->stop = 1;

		if (permission->get_permission != NULL)
			perm = permission->get_permission(refparam, dmctx, data, instance);

		if (perm[0] == '0' || delobj == NULL)
			return FAULT_9005;

		if (!node->is_instanceobj)
			del_action = DEL_ALL;

		return (delobj)(refparam, dmctx, data, instance, del_action);
	}

	return 0;
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

static int mparam_set_value(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		return set_ubus_value(dmctx, node);
	} else {
		char refparam[MAX_DM_PATH] = {0};
		char param_value[2048] = {0};
		char *value = "";

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

		(leaf->getvalue)(refparam, dmctx, data, instance, &value);

		snprintf(param_value, sizeof(param_value), "%s", dmctx->in_value);

		if (leaf->type == DMT_BOOL) {
			bool val = false;
			int res = 0;

			res = string_to_bool(dmctx->in_value, &val);
			if (res == 0 && dmuci_string_to_boolean(value) == val) {
				BBF_DEBUG("Requested value (%s) is same as current value (%s)", dmctx->in_value, value);
				return 0;
			}
		} else if (leaf->dm_falgs & DM_FLAG_REFERENCE) {
			if (DM_LSTRSTR(dmctx->in_value, "=>") == NULL)
				get_reference_paramater_value(dmctx, dmctx->in_value, param_value, sizeof(param_value));

			if (has_same_reference(value, param_value)) {
				BBF_DEBUG("Requested value (%s) is same as current value (%s)", dmctx->in_value, value);
				return 0;
			}
		} else {
			if (DM_STRCMP(value, dmctx->in_value) == 0) {
				BBF_DEBUG("Requested value (%s) is same as current value (%s)", dmctx->in_value, value);
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
static int get_key_ubus_value(struct dmctx *dmctx, struct dmnode *node)
{
	json_object *res = NULL, *res_obj = NULL;
	char *ubus_name = node->obj->checkdep;

	json_object *in_args = json_object_new_object();
	json_object_object_add(in_args, "proto", json_object_new_string((dmctx->dm_type == BBFDM_BOTH) ? "both" : (dmctx->dm_type == BBFDM_CWMP) ? "cwmp" : "usp"));
	json_object_object_add(in_args, "instance_mode", json_object_new_string(dmctx->instance_mode ? "1" : "0"));
	json_object_object_add(in_args, "format", json_object_new_string("raw"));

	dmubus_call(ubus_name, "get",
			UBUS_ARGS{
						{"path", dmctx->in_param, String},
						{"optional", json_object_to_json_string(in_args), Table}
			},
			2, &res);

	json_object_put(in_args);

	if (!res)
		return FAULT_9005;

	json_object *res_array = dmjson_get_obj(res, 1, "results");
	if (!res_array)
		return FAULT_9005;

	size_t nbre_obj = json_object_array_length(res_array);

	if (nbre_obj == 0)
		return FAULT_9005;

	for (size_t i = 0; i < nbre_obj; i++) {
		res_obj = json_object_array_get_idx(res_array, i);

		char *fault = dmjson_get_value(res_obj, 1, "fault");
		if (DM_STRLEN(fault))
			return DM_STRTOUL(fault);

		char *path = dmjson_get_value(res_obj, 1, "path");
		char *data = dmjson_get_value(res_obj, 1, "data");

		if (data && DM_STRCMP(data, dmctx->linker) == 0) {
			dmctx->linker_param = dmstrdup(path);
			char *p = strrchr(dmctx->linker_param, '.');
			if (p) *p = 0;
			return 0;
		}
	}

	return 0;
}

static int get_key_check_obj(DMOBJECT_ARGS)
{
	return FAULT_9005;
}

static int get_key_check_param(DMPARAM_ARGS)
{
	if (node->is_ubus_service) {
		int err = get_key_ubus_value(dmctx, node);
		dmctx->stop = true;
		return err ? err : 0;
	} else {
		char *full_param;
		char *value = "";

		dmastrcat(&full_param, node->current_object, leaf->parameter);

		if (dm_strcmp_wildcard(dmctx->in_param, full_param) != 0) {
			dmfree(full_param);
			return FAULT_9005;
		}

		(leaf->getvalue)(full_param, dmctx, data, instance, &value);

		if (value && value[0] != '\0' && DM_STRCMP(value, dmctx->linker) == 0) {
			if (node->current_object[DM_STRLEN(node->current_object) - 1] == '.')
				node->current_object[DM_STRLEN(node->current_object) - 1] = 0;
			dmctx->linker_param = dmstrdup(node->current_object);
			dmctx->stop = true;
			return 0;
		}
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
 * get linker param
 *****************/
static int get_linker_check_obj(DMOBJECT_ARGS)
{
	char *link_val = "";

	if (!get_linker)
		return  FAULT_9005;

	if (node->obj->browseinstobj && !node->is_instanceobj)
		return  FAULT_9005;

	get_linker(node->current_object, dmctx, data, instance, &link_val);

	if (dmctx == NULL)
		return FAULT_9005;

	if (dmctx->linker == NULL)
		return FAULT_9005;

	if (dmctx->linker[0] == '\0')
		return  FAULT_9005;

	if (link_val && link_val[0] != '\0' && DM_STRCMP(link_val, dmctx->linker) == 0) {
		if (node->current_object[DM_STRLEN(node->current_object) - 1] == '.')
			node->current_object[DM_STRLEN(node->current_object) - 1] = 0;
		dmctx->linker_param = dmstrdup(node->current_object);
		dmctx->stop = true;
		return 0;
	}

	return FAULT_9005;
}

static int get_linker_check_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

int dm_entry_get_linker(struct dmctx *dmctx)
{
	int err = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->method_obj = get_linker_check_obj;
	dmctx->method_param = get_linker_check_param;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_onlyobj_match;

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/******************
 * get linker value
 *****************/
static int get_linker_value_check_obj(DMOBJECT_ARGS)
{
	if (!get_linker)
		return FAULT_9005;

	if (DM_STRCMP(node->current_object, dmctx->in_param) == 0) {
		char *link_val = NULL;

		if (!data || !instance)
			return FAULT_9005;

		get_linker(node->current_object, dmctx, data, instance, &link_val);
		dmctx->linker = link_val ? dmstrdup(link_val) : "";
		dmctx->stop = true;
		return 0;
	}
	return FAULT_9005;
}

static int get_linker_value_check_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

int dm_entry_get_linker_value(struct dmctx *dmctx)
{
	int err = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->method_obj = get_linker_value_check_obj;
	dmctx->method_param = get_linker_value_check_param;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;
	dmentry_instance_lookup_inparam(dmctx);

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/******************
 * get reference value
 *****************/
static int get_reference_value_check_obj(DMOBJECT_ARGS)
{
	if (node->is_ubus_service) {
		return get_ubus_reference_value(dmctx, node);
	} else {
		if (DM_STRCMP(node->current_object, dmctx->in_param) == 0) {

			if (!data || !instance)
				return FAULT_9005;

			struct dm_leaf_s *leaf = node->obj->leaf;
			if (!leaf)
				return FAULT_9005;

			for (; (leaf && leaf->parameter); leaf++) {

				if (leaf->dm_falgs & DM_FLAG_LINKER) {
					char *full_param = NULL;
					char *link_val = NULL;

					dmastrcat(&full_param, node->current_object, leaf->parameter);

					(leaf->getvalue)(full_param, dmctx, data, instance, &link_val);

					dmctx->linker = link_val ? dmstrdup(link_val) : "";
					dmctx->stop = true;
					return 0;
				}
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
	dmentry_instance_lookup_inparam(dmctx);

	err = dm_browse(dmctx, &node, root, NULL, NULL);

	return (dmctx->stop) ? err : FAULT_9005;
}

/******************
 * object exists
 *****************/
static int object_exists_check_obj(DMOBJECT_ARGS)
{
	if (node->is_ubus_service) {
		int fault =  get_ubus_instances(dmctx, node);
		if (fault)
			return fault;

		dmctx->match = true;
		dmctx->stop = true;
		return 0;
	} else {
		if (DM_STRCMP(node->current_object, dmctx->in_param) == 0) {
			dmctx->match = true;
			dmctx->stop = true;
			return 0;
		}
		return FAULT_9005;
	}
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
	dmentry_instance_lookup_inparam(dmctx);

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
	if (node->is_ubus_service) {
		return operate_ubus(dmctx, node);
	} else {
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

	fault = (leaf->setvalue)(full_param, dmctx, data, instance, (char *)j_input, EVENT_RUN);
	if (!fault)
		add_list_parameter(dmctx, dmstrdup("Event_Path"), dmstrdup(full_param), DMT_TYPE[DMT_STRING], NULL);

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
