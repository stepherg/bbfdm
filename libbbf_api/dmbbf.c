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

static char dm_browse_path[MAX_DM_PATH];

static int dm_browse(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, void *data, char *instance);
static int get_value_obj(DMOBJECT_ARGS);
static int get_value_param(DMPARAM_ARGS);
static int mobj_get_value_in_param(DMOBJECT_ARGS);
static int mparam_get_value_in_param(DMPARAM_ARGS);
static int mparam_get_name(DMPARAM_ARGS);
static int mobj_get_name(DMOBJECT_ARGS);
static int mparam_get_name_in_param(DMPARAM_ARGS);
static int mobj_get_name_in_param(DMOBJECT_ARGS);
static int mparam_get_name_in_obj(DMPARAM_ARGS);
static int mobj_get_name_in_obj(DMOBJECT_ARGS);
static int mobj_get_schema_name(DMOBJECT_ARGS);
static int mparam_get_schema_name(DMPARAM_ARGS);
static int mobj_get_instances_in_obj(DMOBJECT_ARGS);
static int mparam_get_instances_in_obj(DMPARAM_ARGS);
static int mparam_add_object(DMPARAM_ARGS);
static int mobj_add_object(DMOBJECT_ARGS);
static int delete_object_obj(DMOBJECT_ARGS);
static int delete_object_param(DMPARAM_ARGS);
static int mobj_set_value(DMOBJECT_ARGS);
static int mparam_set_value(DMPARAM_ARGS);
static int get_linker_check_obj(DMOBJECT_ARGS);
static int get_linker_check_param(DMPARAM_ARGS);
static int get_linker_value_check_obj(DMOBJECT_ARGS);
static int get_linker_value_check_param(DMPARAM_ARGS);
static int mobj_get_supported_dm(DMOBJECT_ARGS);
static int mparam_get_supported_dm(DMPARAM_ARGS);

int bbfdatamodel_type = BBFDM_BOTH;

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

static int plugin_obj_match(DMOBJECT_ARGS)
{
	if (node->matched)
		return 0;
	if (!dmctx->inparam_isparam && strstr(node->current_object, dmctx->in_param) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}
	if (strstr(dmctx->in_param, node->current_object) == dmctx->in_param) {
		return 0;
	}
	return FAULT_9005;
}

static int obj_match_supported_dm(DMOBJECT_ARGS)
{
	if(node->matched)
		return 0;
	if(!dmctx->inparam_isparam && strstr(node->current_object,dmctx->in_param) == node->current_object) {
		node->matched ++;
		dmctx->findparam = 1;
		return 0;
	}
	return 0;
}

static int plugin_leaf_match(DMOBJECT_ARGS)
{
	char *str;
	if (node->matched)
		return 0;
	if (!dmctx->inparam_isparam)
		return FAULT_9005;
	str = dmctx->in_param + strlen(node->current_object);
	if (!strchr(str, '.'))
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
	if (!dmctx->inparam_isparam && strstr(node->current_object, dmctx->in_param) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}
	if (strstr(dmctx->in_param, node->current_object) == dmctx->in_param) {
		return 0;
	}
	return FAULT_9005;
}

static int plugin_leaf_nextlevel_match(DMOBJECT_ARGS)
{
	char *str;
	if (node->matched > 1)
		return FAULT_9005;
	if (node->matched)
		return 0;
	if (!dmctx->inparam_isparam)
		return FAULT_9005;
	str = dmctx->in_param + strlen(node->current_object);
	if (!strchr(str, '.'))
		return 0;
	return FAULT_9005;
}

static int plugin_dynamic_obj_match(struct dmctx *dmctx, struct dmnode *node, char *entry_obj, char *full_obj)
{
	if (node->matched)
		return 0;

	if (!dmctx->inparam_isparam && strstr(node->current_object, full_obj) == node->current_object) {
		node->matched++;
		dmctx->findparam = 1;
		return 0;
	}

	if (strstr(full_obj, node->current_object) == full_obj)
		return 0;

	return FAULT_9005;
}

static int bbfdatamodel_matches(const enum bbfdm_type_enum type)
{
	return (bbfdatamodel_type == BBFDM_BOTH || type == BBFDM_BOTH || bbfdatamodel_type == type) && type != BBFDM_NONE;
}

static bool check_dependency(const char *conf_obj)
{
	/* Available cases */
	/* one file => "file:/etc/config/network" */
	/* multiple files => "file:/etc/config/network,/lib/netifd/proto/dhcp.sh" */
	/* one ubus => "ubus:router.network" (with method : "ubus:router.network->hosts") */
	/* multiple ubus => "ubus:router.system->info,dsl->status,wifi" */
	/* one package => "opkg:icwmp" */
	/* multiple packages => "opkg:icwmp,obuspa" */
	/* common (files, ubus and opkg) => "file:/etc/config/network,/etc/config/dhcp;ubus:router.system,dsl->status;opkg:icwmp" */

	char *pch = NULL, *spch = NULL;
	char conf_list[512] = {0};

	DM_STRNCPY(conf_list, conf_obj, sizeof(conf_list));

	for (pch = strtok_r(conf_list, ";", &spch); pch != NULL; pch = strtok_r(NULL, ";", &spch)) {
		char *conf_type = strchr(pch, ':');
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

	return true;
}

static int dm_browse_leaf(struct dmctx *dmctx, DMNODE *parent_node, DMLEAF *leaf, void *data, char *instance)
{
	int err = 0;

	for (; (leaf && leaf->parameter); leaf++) {

		if (!bbfdatamodel_matches(leaf->bbfdm_type))
			continue;
		if(!dmctx->isinfo){
			if (dmctx->iscommand != (leaf->type == DMT_COMMAND) || dmctx->isevent != (leaf->type == DMT_EVENT))
				continue;
		}
		snprintf(dm_browse_path, MAX_DM_PATH, "%s%s", parent_node->current_object, leaf->parameter);
		err = dmctx->method_param(dmctx, parent_node, leaf->parameter, leaf->permission, leaf->type, leaf->getvalue, leaf->setvalue, data, instance);
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

							if (!bbfdatamodel_matches(jleaf->bbfdm_type))
								continue;
							if(!dmctx->isinfo){
								if (dmctx->iscommand != (jleaf->type == DMT_COMMAND) || dmctx->isevent != (jleaf->type == DMT_EVENT))
									continue;
							}
							snprintf(dm_browse_path, MAX_DM_PATH, "%s%s", parent_node->current_object, jleaf->parameter);
							err = dmctx->method_param(dmctx, parent_node, jleaf->parameter, jleaf->permission, jleaf->type, jleaf->getvalue, jleaf->setvalue, data, instance);
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

	if (!bbfdatamodel_matches(entryobj->bbfdm_type))
		return;

	if (entryobj->checkdep && (check_dependency(entryobj->checkdep) == false))
		return;

	if (entryobj->browseinstobj && dmctx->isgetschema)
		dmasprintf(&(node.current_object), "%s%s.{i}.", parent_obj, entryobj->obj);
	else
		dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);

	snprintf(dm_browse_path, MAX_DM_PATH, "%s", node.current_object);
	if (dmctx->checkobj) {
		*err = dmctx->checkobj(dmctx, &node, entryobj->permission, entryobj->addobj, entryobj->delobj, entryobj->get_linker, data, instance);
		if (*err)
			return;
	}

	if ((entryobj->browseinstobj && dmctx->isgetschema) || !dmctx->isgetschema) {
		*err = dmctx->method_obj(dmctx, &node, entryobj->permission, entryobj->addobj, entryobj->delobj, entryobj->get_linker, data, instance);
		if (dmctx->stop)
			return;
	}

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
		snprintf(dm_browse_path, MAX_DM_PATH, "%s%s", parent_obj, entryobj->obj);
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
							snprintf(dm_browse_path, MAX_DM_PATH, "%s%s", parent_obj, jentryobj->obj);
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
		int curr_inst = (instance && *instance != '\0') ? atoi(instance) : 0;
		if (curr_inst > parent_node->max_instance)
			parent_node->max_instance = curr_inst;
		return 0;
	}

	if (parent_node->browse_type == BROWSE_NUM_OF_ENTRIES) {
		parent_node->num_of_entries++;
		return 0;
	}

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

void dm_exclude_obj(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, char *data)
{
	char *parent_obj = parent_node->current_object;

	for (; (entryobj && entryobj->obj); entryobj++) {
		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);
		if (strcmp(node.current_object, data) == 0) {
			entryobj->bbfdm_type = BBFDM_NONE;
			return;
		}

		int err = plugin_dynamic_obj_match(dmctx, &node, entryobj->obj, data);
		if (err)
			continue;

		if (entryobj->nextobj)
			dm_exclude_obj(dmctx, &node, entryobj->nextobj, data);
	}
}

static void dm_check_dynamic_obj_entry(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, char *parent_obj, char *full_obj, char *obj, DMOBJ **root_entry, int *obj_found)
{
	DMNODE node = {0};
	node.obj = entryobj;
	node.parent = parent_node;
	node.instance_level = parent_node->instance_level;
	node.matched = parent_node->matched;

	dmasprintf(&(node.current_object), "%s%s.", parent_obj, entryobj->obj);
	if (strcmp(node.current_object, obj) == 0) {
		*root_entry = entryobj;
		*obj_found = 1;
		return;
	}

	int err = plugin_dynamic_obj_match(dmctx, &node, entryobj->obj, full_obj);
	if (err)
		return;

	if (entryobj->nextobj || entryobj->nextdynamicobj)
		dm_check_dynamic_obj(dmctx, &node, entryobj->nextobj, full_obj, obj, root_entry, obj_found);
}

void dm_check_dynamic_obj(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, char *obj, DMOBJ **root_entry, int *obj_found)
{
	char *parent_obj = parent_node->current_object;

	for (; (entryobj && entryobj->obj); entryobj++) {
		dm_check_dynamic_obj_entry(dmctx, parent_node, entryobj, parent_obj, full_obj, obj, root_entry, obj_found);
		if (*obj_found == 1)
			return;
	}

	if (parent_node->obj) {
		if (parent_node->obj->nextdynamicobj) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_obj *next_dyn_array = parent_node->obj->nextdynamicobj + i;
				if (next_dyn_array->nextobj) {
					for (int j = 0; next_dyn_array->nextobj[j]; j++) {
						DMOBJ *jentryobj = next_dyn_array->nextobj[j];
						for (; (jentryobj && jentryobj->obj); jentryobj++) {
							dm_check_dynamic_obj_entry(dmctx, parent_node, jentryobj, parent_obj, full_obj, obj, root_entry, obj_found);
							if (*obj_found == 1)
								return;
						}
					}
				}
			}
		}
	}
}

bool find_root_entry(struct dmctx *ctx, char *in_param, DMOBJ **root_entry)
{
	int obj_found = 0;
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};

	char *obj_path = replace_str(in_param, ".{i}.", ".");
	dm_check_dynamic_obj(ctx, &node, root, obj_path, obj_path, root_entry, &obj_found);
	dmfree(obj_path);

	return (obj_found && *root_entry) ? true : false;
}

int get_obj_idx_dynamic_array(DMOBJ **entryobj)
{
	int i, idx = 0;
	for (i = 0; entryobj[i]; i++) {
		idx++;
	}
	return idx;
}

int get_leaf_idx_dynamic_array(DMLEAF **entryleaf)
{
	int i, idx = 0;
	for (i = 0; entryleaf[i]; i++) {
		idx++;
	}
	return idx;
}

void free_dm_browse_node_dynamic_object_tree(DMNODE *parent_node, DMOBJ *entryobj)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			for (int i = 0; i < __INDX_DYNAMIC_MAX; i++) {
				struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + i;
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

		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		if (entryobj->nextobj)
			free_dm_browse_node_dynamic_object_tree(&node, entryobj->nextobj);
	}
}

static int rootcmp(char *inparam, char *rootobj)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%s.", rootobj);
	return strcmp(inparam, buf);
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
			instance = dmuci_set_value_by_section(s, inst_opt, buf);
		}

		int inst_mode = get_instance_mode(dmctx, parent_node);

		if (inst_mode == INSTANCE_MODE_ALIAS) {
			char *alias = "";

			dmuci_get_value_by_section_string(s, alias_opt, &alias);
			if (alias && alias[0] == '\0') {
				snprintf(buf, sizeof(buf), "cpe-%s", instance);
				alias = dmuci_set_value_by_section(s, alias_opt, buf);
			}
			snprintf(buf, sizeof(buf), "[%s]", alias);
			instance = dmstrdup(buf);
		}
		break;
	case BROWSE_FIND_MAX_INST:
	case BROWSE_NUM_OF_ENTRIES:
		break;
	}

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
	return instance;
}

__attribute__ ((deprecated)) char *handle_update_instance(int instance_ranck, struct dmctx *ctx, char **max_inst, char * (*up_instance)(int action, char **last_inst, char **max_inst, void *argv[]), int argc, ...)
{
	va_list arg;
	char *instance, *last_inst = NULL;
	int i = 0;
	unsigned int action, pos = instance_ranck - 1;
	void *argv[argc+1];

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, void*);
	}
	argv[argc] = NULL;
	va_end(arg);

	if (pos < ctx->nbrof_instance)
		action = (ctx->alias_register & (1 << pos)) ? INSTANCE_UPDATE_ALIAS : INSTANCE_UPDATE_NUMBER;
	else
		action = (ctx->instance_mode == INSTANCE_MODE_ALIAS) ? INSTANCE_UPDATE_ALIAS : INSTANCE_UPDATE_NUMBER;

	instance = up_instance(action, &last_inst, max_inst, argv);
	if (last_inst)
		ctx->inst_buf[pos] = dmstrdup(last_inst);

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
		if (inst[0] == '\0')
			continue;

		max = max > atoi(inst) ? max : atoi(inst);
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
		max_instance = atoi(*max_inst);

	dmuci_get_value_by_section_string(s, inst_opt, &instance);
	if (instance[0] == '\0') {
		snprintf(buf, sizeof(buf), "%d", max_instance + 1);
		instance = dmuci_set_value_by_section(s, inst_opt, buf);
		*max_inst = instance;
	} else {
		dmasprintf(max_inst, "%d", max_instance);
	}
	*last_inst = instance;

	if (action == INSTANCE_MODE_ALIAS) {
		dmuci_get_value_by_section_string(s, alias_opt, &alias);
		if (alias[0] == '\0') {
			snprintf(buf, sizeof(buf), "cpe-%s", instance);
			alias = dmuci_set_value_by_section(s, alias_opt, buf);
		}
		snprintf(buf, sizeof(buf), "[%s]", alias);
		instance = dmstrdup(buf);
	}
	return instance;
}

__attribute__ ((deprecated)) char *update_instance_without_section(int action, char **last_inst, char **max_inst, void *argv[])
{
	char *instance, buf[64] = {0};
	int instnbr = (int)(long)argv[0];

	snprintf(buf, sizeof(buf), "%d", instnbr);
	instance = dmstrdup(buf);
	*last_inst = instance;

	if (action == INSTANCE_MODE_ALIAS) {
		snprintf(buf, sizeof(buf), "[cpe-%d]", instnbr);
		instance = dmstrdup(buf);
	}

	return instance;
}

__attribute__ ((deprecated)) char *get_last_instance_bbfdm(char *package, char *section, char *opt_inst)
{
	struct uci_section *s;
	char *inst = NULL, *last_inst = NULL;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		inst = update_instance(last_inst, 2, s, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(inst);
	}

	return inst;
}

__attribute__ ((deprecated)) char *get_last_instance(char *package, char *section, char *opt_inst)
{
	struct uci_section *s;
	char *inst = NULL, *last_inst = NULL;

	if (strcmp(package, DMMAP) == 0) {
		uci_path_foreach_sections(bbfdm, "dmmap", section, s) {
			inst = update_instance(last_inst, 2, s, opt_inst);
			if(last_inst)
				dmfree(last_inst);
			last_inst = dmstrdup(inst);
		}
	} else {
		uci_foreach_sections(package, section, s) {
			inst = update_instance(inst, 2, s, opt_inst);
		}
	}
	return inst;
}

__attribute__ ((deprecated)) char *get_last_instance_lev2_bbfdm_dmmap_opt(char *dmmap_package, char *section, char *opt_inst, char *opt_check, char *value_check)
{
	struct uci_section *s;
	char *instance = NULL, *last_inst = NULL;
	struct browse_args browse_args = {0};

	browse_args.option = opt_check;
	browse_args.value = value_check;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section, opt_check, value_check, s) {
		instance = update_instance(last_inst, 5, s, opt_inst, 0, check_browse_section, (void *)&browse_args);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(instance);
	}
	return instance;
}

__attribute__ ((deprecated)) char *get_last_instance_lev2_bbfdm(char *package, char *section, char* dmmap_package, char *opt_inst, char *opt_check, char *value_check)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;
	char *instance = NULL, *last_inst = NULL;

	uci_foreach_option_cont(package, section, opt_check, value_check, s) {
		get_dmmap_section_of_config_section(dmmap_package, section, section_name(s), &dmmap_section);
		if (dmmap_section == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "section_name", section_name(s));
		}
		instance = update_instance(last_inst, 2, dmmap_section, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(instance);
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
	struct list_head *ilist = NULL;

	list_for_each(ilist, &ctx->list_parameter) {
		dm_parameter = list_entry(ilist, struct dm_parameter, list);
		int cmp = strcmp(dm_parameter->name, param_name);
		if (cmp == 0) {
			return;
		} else if (cmp > 0) {
			break;
		}
	}
	dm_parameter = dmcalloc(1, sizeof(struct dm_parameter));
	_list_add(&dm_parameter->list, ilist->prev, ilist);
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

static void add_set_list_tmp(struct dmctx *ctx, char *param, char *value)
{
	struct set_tmp *set_tmp;
	set_tmp = dmcalloc(1, sizeof(struct set_tmp));
	list_add_tail(&set_tmp->list, &ctx->set_list_tmp);
	set_tmp->name = dmstrdup(param);
	set_tmp->value = value ? dmstrdup(value) : NULL;
}

static void del_set_list_tmp(struct set_tmp *set_tmp)
{
	list_del(&set_tmp->list);
	dmfree(set_tmp->name);
	dmfree(set_tmp->value);
	dmfree(set_tmp);
}

void free_all_set_list_tmp(struct dmctx *ctx)
{
	struct set_tmp *set_tmp = NULL;
	while (ctx->set_list_tmp.next != &ctx->set_list_tmp) {
		set_tmp = list_entry(ctx->set_list_tmp.next, struct set_tmp, list);
		del_set_list_tmp(set_tmp);
	}
}

void add_list_fault_param(struct dmctx *ctx, char *param, int fault)
{
	struct param_fault *param_fault;
	if (param == NULL) param = "";

	param_fault = dmcalloc(1, sizeof(struct param_fault));
	list_add_tail(&param_fault->list, &ctx->list_fault_param);
	param_fault->name = dmstrdup(param);
	param_fault->fault = fault;
}

void bbf_api_del_list_fault_param(struct param_fault *param_fault)
{
	list_del(&param_fault->list);
	dmfree(param_fault->name);
	dmfree(param_fault);
}

void free_all_list_fault_param(struct dmctx *ctx)
{
	struct param_fault *param_fault = NULL;
	while (ctx->list_fault_param.next != &ctx->list_fault_param) {
		param_fault = list_entry(ctx->list_fault_param.next, struct param_fault, list);
		bbf_api_del_list_fault_param(param_fault);
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

static char *check_value_by_type(char *value, int type)
{
	int i = 0, len = strlen(value);
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
			if (dm_validate_boolean(buf))
				return "0";
			break;
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

/* **********
 * get value 
 * **********/
int dm_entry_get_value(struct dmctx *dmctx)
{
	int err = 0;
	unsigned char findparam_check = 0;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = {.current_object = ""};

	if (dmctx->in_param[0] == '\0' || rootcmp(dmctx->in_param, root->obj) == 0) {
		dmctx->inparam_isparam = 0;
		dmctx->method_obj = get_value_obj;
		dmctx->method_param = get_value_param;
		dmctx->checkobj = NULL;
		dmctx->checkleaf = NULL;
		dmctx->findparam = 1;
		dmctx->stop = 0;
		findparam_check = 1;
	} else if (dmctx->in_param[strlen(dmctx->in_param) - 1] == '.') {
		dmctx->inparam_isparam = 0;
		dmctx->findparam = 0;
		dmctx->stop = 0;
		dmctx->checkobj = plugin_obj_match;
		dmctx->checkleaf = plugin_leaf_match;
		dmctx->method_obj = get_value_obj;
		dmctx->method_param = get_value_param;
		findparam_check = 1;
	} else {
		dmctx->inparam_isparam = 1;
		dmctx->findparam = 0;
		dmctx->stop = 0;
		dmctx->checkobj = plugin_obj_match;
		dmctx->checkleaf = plugin_leaf_match;
		dmctx->method_obj = mobj_get_value_in_param;
		dmctx->method_param = mparam_get_value_in_param;
	}
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (findparam_check && dmctx->findparam)
		return 0;
	else
		return err;
}

static int get_value_obj(DMOBJECT_ARGS)
{
	return 0;
}

static int get_value_param(DMPARAM_ARGS)
{
	char *full_param;
	char *value = "";

	dmastrcat(&full_param, node->current_object, lastname);
	(get_cmd)(full_param, dmctx, data, instance, &value);

	value = (value && *value) ? check_value_by_type(value, type) : get_default_value_by_type(type);

	add_list_parameter(dmctx, full_param, value, DMT_TYPE[type], NULL);
	return 0;
}

static int mobj_get_value_in_param(DMOBJECT_ARGS)
{
	return 0;
}
static int mparam_get_value_in_param(DMPARAM_ARGS)
{
	char *full_param;
	char *value = "";

	dmastrcat(&full_param, node->current_object, lastname);
	if (strcmp(dmctx->in_param, full_param) != 0) {
		dmfree(full_param);
		return FAULT_9005;
	}

	(get_cmd)(full_param, dmctx, data, instance, &value);

	value = (value && *value) ? check_value_by_type(value, type) : get_default_value_by_type(type);

	add_list_parameter(dmctx, full_param, value, DMT_TYPE[type], NULL);
	dmctx->stop = true;
	return 0;
}

/* **********
 * get name 
 * **********/
int dm_entry_get_name(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	unsigned char findparam_check = 0;
	int err;
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
		node.matched = 1;
		findparam_check = 1;
	} else if (*(ctx->in_param + strlen(ctx->in_param) - 1) == '.') {
		ctx->inparam_isparam = 0;
		ctx->findparam = 0;
		ctx->stop = 0;
		ctx->method_obj = mobj_get_name_in_obj;
		ctx->method_param = mparam_get_name_in_obj;
		ctx->checkobj = (ctx->nextlevel) ? plugin_obj_nextlevel_match : plugin_obj_match;
		ctx->checkleaf = (ctx->nextlevel) ? plugin_leaf_nextlevel_match : plugin_leaf_match;
		findparam_check = 1;
	} else {
		ctx->inparam_isparam = 1;
		ctx->findparam = 0;
		ctx->stop = 0;
		ctx->checkobj = plugin_obj_match;
		ctx->checkleaf = plugin_leaf_match;
		ctx->method_obj = mobj_get_name_in_param;
		ctx->method_param = mparam_get_name_in_param;
	}
	err = dm_browse(ctx, &node, root, NULL, NULL);
	if (findparam_check && ctx->findparam)
		return 0;
	else
		return err;
}

static int mparam_get_name(DMPARAM_ARGS)
{
	char *refparam;
	char *perm = permission->val;

	dmastrcat(&refparam, node->current_object, lastname);
	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	add_list_parameter(dmctx, refparam, perm, DMT_TYPE[type], NULL);
	return 0;
}

static int mobj_get_name(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	add_list_parameter(dmctx, refparam, perm, "xsd:object", NULL);
	return 0;
}

static int mparam_get_name_in_param(DMPARAM_ARGS)
{
	char *refparam;
	char *perm = permission->val;

	dmastrcat(&refparam, node->current_object, lastname);
	if (strcmp(refparam, dmctx->in_param) != 0) {
		dmfree(refparam);
		return FAULT_9005;
	}

	dmctx->stop = 1;

	if (dmctx->nextlevel == 1) {
		dmfree(refparam);
		return FAULT_9003;
	}

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	add_list_parameter(dmctx, refparam, perm, DMT_TYPE[type], NULL);
	return 0;
}

static int mobj_get_name_in_param(DMOBJECT_ARGS)
{
	return 0;
}

static int mparam_get_name_in_obj(DMPARAM_ARGS)
{
	char *refparam;
	char *perm = permission->val;

	dmastrcat(&refparam, node->current_object, lastname);

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	add_list_parameter(dmctx, refparam, perm, DMT_TYPE[type], NULL);
	return 0;
}

static int mobj_get_name_in_obj(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;

	if (!node->matched)
		return FAULT_9005;

	if (dmctx->nextlevel && strcmp(node->current_object, dmctx->in_param) == 0)
		return 0;

	if (permission->get_permission != NULL)
		perm = permission->get_permission(refparam, dmctx, data, instance);

	add_list_parameter(dmctx, refparam, perm, "xsd:object", NULL);
	return 0;
}

/* **********
 * get schema
 * **********/
int dm_entry_get_schema(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	int err;

	ctx->inparam_isparam = 0;
	ctx->isgetschema = 1;
	ctx->findparam = 0;
	ctx->stop = 0;
	ctx->checkobj = NULL;
	ctx->checkleaf = NULL;
	ctx->method_obj = mobj_get_schema_name;
	ctx->method_param = mparam_get_schema_name;
	err = dm_browse(ctx, &node, root, NULL, NULL);
	return err;
}

static int mobj_get_schema_name(DMOBJECT_ARGS)
{
	char *perm = permission->val;
	char *refparam = node->current_object;
	const char **unique_keys = NULL;

	if (node->obj)
		unique_keys = node->obj->unique_keys;

	add_list_parameter(dmctx, refparam, perm, "xsd:object", (char *)unique_keys);
	return 0;
}

static int mparam_get_schema_name(DMPARAM_ARGS)
{
	char *refparam;
	char *perm = permission->val;
	dmastrcat(&refparam, node->current_object, lastname);

	add_list_parameter(dmctx, refparam, perm, DMT_TYPE[type], NULL);
	return 0;
}


/* ***********************
 * get supported data model
 * ***********************/
static int mobj_get_supported_dm(DMOBJECT_ARGS)
{

	char *perm = permission->val;
	char *refparam = node->current_object;
	const char **unique_keys = NULL;

	if(node->matched && dmctx->isinfo){
		if (node->obj)
			unique_keys = node->obj->unique_keys;

		add_list_parameter(dmctx, refparam, perm, "xsd:object", (char *)unique_keys);
	}

	return 0;
}

static int mparam_get_supported_dm(DMPARAM_ARGS)
{
	char *value = NULL;
	char *refparam;

	dmastrcat(&refparam, node->current_object, lastname);

	if(node->matched) {
		if(type == DMT_EVENT) {
			if(dmctx->isevent) {
				if (get_cmd)
					(get_cmd)(refparam, dmctx, data, instance, &value);

				add_list_parameter(dmctx, refparam, value, DMT_TYPE[type], NULL);
			}

		} else if(type == DMT_COMMAND) {
			if(dmctx->iscommand) {

				if (get_cmd)
					(get_cmd)(refparam, dmctx, data, instance, &value);

				//add_list_parameter(dmctx, refparam, value, permission->val, NULL);
				add_list_parameter(dmctx, refparam, value, DMT_TYPE[type], permission->val);
			}
		}
		else {
			add_list_parameter(dmctx, refparam, permission->val, DMT_TYPE[type], NULL);
		}
	}
	return 0;
}

int dm_entry_get_supported_dm(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	int err;

	ctx->inparam_isparam = 0;
	ctx->isgetschema = 1;
	ctx->findparam = 1;
	ctx->stop =0;
	ctx->checkobj = obj_match_supported_dm;
	ctx->checkleaf = NULL;
	ctx->method_obj = mobj_get_supported_dm;
	ctx->method_param = mparam_get_supported_dm;
	err = dm_browse(ctx, &node, root, NULL, NULL);

	return err;
}

/* **************
 * get_instances
 * **************/
int dm_entry_get_instances(struct dmctx *ctx)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	size_t plen;
	int err;

	if (ctx->in_param[0] == 0)
		ctx->in_param = dmstrdup(".");

	plen = strlen(ctx->in_param);
	if (ctx->in_param[plen - 1] != '.')
		return FAULT_9005;

	ctx->inparam_isparam = 0;
	ctx->findparam = 0;
	ctx->stop = 0;
	ctx->checkobj = (ctx->nextlevel) ? plugin_obj_nextlevel_match : plugin_obj_match;
	ctx->checkleaf = (ctx->nextlevel) ? plugin_leaf_nextlevel_match : plugin_leaf_match;
	ctx->method_obj = mobj_get_instances_in_obj;
	ctx->method_param = mparam_get_instances_in_obj;

	err = dm_browse(ctx, &node, root, NULL, NULL);
	if (ctx->findparam == 0)
		return err;

	return 0;
}

static int mobj_get_instances_in_obj(DMOBJECT_ARGS)
{
	if (node->matched && node->is_instanceobj) {
		char *name = dmstrdup(node->current_object);

		if (name) {
			name[strlen(name) - 1] = 0;
			add_list_parameter(dmctx, name, NULL, "xsd:object", NULL);
		}
	}

	return 0;
}

static int mparam_get_instances_in_obj(DMPARAM_ARGS)
{
	return 0;
}

/* **************
 * add object 
 * **************/
int dm_entry_add_object(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0'
			|| (*(dmctx->in_param + strlen(dmctx->in_param) - 1) != '.'))
		return FAULT_9005;

	dmctx->inparam_isparam = 0;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_onlyobj_match;
	dmctx->method_obj = mobj_add_object;
	dmctx->method_param = mparam_add_object;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (dmctx->stop)
		return err;
	else
		return FAULT_9005;
}

static int mparam_add_object(DMPARAM_ARGS)
{
	return FAULT_9005;
}

static int mobj_add_object(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;
	char *new_instance = NULL;
	int fault = 0;

	if (strcmp(refparam, dmctx->in_param) != 0)
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

/* **************
 * del object 
 * **************/
int dm_entry_delete_object(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0'
			|| (*(dmctx->in_param + strlen(dmctx->in_param) - 1) != '.'))
		return FAULT_9005;

	dmctx->inparam_isparam = 0;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_onlyobj_match;
	dmctx->method_obj = delete_object_obj;
	dmctx->method_param = delete_object_param;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (dmctx->stop)
		return err;
	else
		return FAULT_9005;
}

static int delete_object_obj(DMOBJECT_ARGS)
{
	char *refparam = node->current_object;
	char *perm = permission->val;
	unsigned char del_action = DEL_INST;

	if (strcmp(refparam, dmctx->in_param) != 0)
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

static int delete_object_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

/* **************
 * set value  
 * **************/
int dm_entry_set_value(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0'
			|| (*(dmctx->in_param + strlen(dmctx->in_param) - 1) == '.'))
		return FAULT_9005;

	dmctx->inparam_isparam = 1;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;
	dmctx->method_obj = mobj_set_value;
	dmctx->method_param = mparam_set_value;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (dmctx->stop)
		return err;
	else
		return FAULT_9005;
}

static int mobj_set_value(DMOBJECT_ARGS)
{
	return FAULT_9005;
}

static int mparam_set_value(DMPARAM_ARGS)
{
	char refparam[MAX_DM_PATH];

	snprintf(refparam, MAX_DM_PATH, "%s%s", node->current_object, lastname);
	if (strcmp(refparam, dmctx->in_param) != 0)
		return FAULT_9005;

	dmctx->stop = 1;

	if (dmctx->setaction == VALUECHECK) {
		char *perm = permission->val;
		if (permission->get_permission != NULL)
			perm = permission->get_permission(refparam, dmctx, data, instance);

		if (perm[0] == '0' || !set_cmd)
			return FAULT_9008;

		int fault = (set_cmd)(refparam, dmctx, data, instance, dmctx->in_value, VALUECHECK);
		if (fault)
			return fault;

		add_set_list_tmp(dmctx, dmctx->in_param, dmctx->in_value);
	} else if (dmctx->setaction == VALUESET) {
		int fault = (set_cmd)(refparam, dmctx, data, instance, dmctx->in_value, VALUESET);
		if (fault)
			return fault;
	}
	return 0;
}

/******************
 * get linker param
 *****************/
int dm_entry_get_linker(struct dmctx *dmctx)
{
	int err;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->method_obj = get_linker_check_obj;
	dmctx->method_param = get_linker_check_param;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_onlyobj_match;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (dmctx->stop)
		return err;
	else
		return FAULT_9005;
}

static int get_linker_check_obj(DMOBJECT_ARGS)
{
	char *link_val = "";

	if (!get_linker)
		return  FAULT_9005;

	if (node->obj->browseinstobj && !node->is_instanceobj)
		return  FAULT_9005;

	get_linker(node->current_object, dmctx, data, instance, &link_val);

	if (dmctx->linker[0] == '\0')
		return  FAULT_9005;

	if (link_val && link_val[0] != '\0' && strcmp(link_val, dmctx->linker) == 0) {
		if (node->current_object[strlen(node->current_object) - 1] == '.')
			node->current_object[strlen(node->current_object) - 1] = 0;
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

/******************
 * get linker value
 *****************/
int dm_entry_get_linker_value(struct dmctx *dmctx)
{
	int err;
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };

	dmctx->method_obj = get_linker_value_check_obj;
	dmctx->method_param = get_linker_value_check_param;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;
	dmentry_instance_lookup_inparam(dmctx);
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (dmctx->stop)
		return err;
	else
		return FAULT_9005;
}

static int get_linker_value_check_obj(DMOBJECT_ARGS)
{
	if (!get_linker)
		return FAULT_9005;

	if (strcmp(node->current_object, dmctx->in_param) == 0) {
		char *link_val;
		get_linker(node->current_object, dmctx, data, instance, &link_val);
		dmctx->linker = dmstrdup(link_val);
		dmctx->stop = true;
		return 0;
	}
	return FAULT_9005;
}

static int get_linker_value_check_param(DMPARAM_ARGS)
{
	return FAULT_9005;
}

/* ************
 * list operate
 * ************/
static int mobj_list_operates_name(DMOBJECT_ARGS)
{
	return 0;
}

static int mparam_list_operates_name(DMPARAM_ARGS)
{
	char *full_param;
	char *value = NULL;

	dmastrcat(&full_param, node->current_object, lastname);
	if (get_cmd)
		(get_cmd)(full_param, dmctx, data, instance, &value);

	add_list_parameter(dmctx, full_param, value, permission->val, NULL);
	return 0;
}

int dm_entry_list_operates(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	int err;

	dmctx->inparam_isparam = 0;
	dmctx->isgetschema = 1;
	dmctx->iscommand = 1;
	dmctx->findparam = 0;
	dmctx->stop = 0;
	dmctx->checkobj = NULL;
	dmctx->checkleaf = NULL;
	dmctx->method_obj = mobj_list_operates_name;
	dmctx->method_param = mparam_list_operates_name;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	return err;
}

/* **************
 * Operate  
 * **************/
static int mobj_operate(DMOBJECT_ARGS)
{
	return CMD_NOT_FOUND;
}

static int mparam_operate(DMPARAM_ARGS)
{
	char full_param[MAX_DM_PATH];

	snprintf(full_param, MAX_DM_PATH, "%s%s", node->current_object, lastname);
	if (strcmp(full_param, dmctx->in_param) != 0)
		return CMD_NOT_FOUND;

	dmctx->stop = 1;

	if (!set_cmd)
		return CMD_FAIL;

	json_object *j_input = (dmctx->in_value) ? json_tokener_parse(dmctx->in_value) : NULL;
	int fault = (set_cmd)(full_param, dmctx, data, instance, (char *)j_input, VALUESET);
	json_object_put(j_input);
	return fault;
}

int dm_entry_operate(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = { .current_object = "" };
	int err;

	if (dmctx->in_param == NULL || dmctx->in_param[0] == '\0' || (*(dmctx->in_param + strlen(dmctx->in_param) - 1) != ')'))
		return CMD_NOT_FOUND;

	dmctx->iscommand = 1;
	dmctx->inparam_isparam = 1;
	dmctx->stop = 0;
	dmctx->checkobj = plugin_obj_match;
	dmctx->checkleaf = plugin_leaf_match;
	dmctx->method_obj = mobj_operate;
	dmctx->method_param = mparam_operate;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	if (dmctx->stop)
		return err;
	else
		return CMD_NOT_FOUND;
}

/* ************
 * list event
 * ************/
static int mobj_list_events_name(DMOBJECT_ARGS)
{
	return 0;
}

static int mparam_list_events_name(DMPARAM_ARGS)
{
	char *value = NULL;
	char *full_param;

	dmastrcat(&full_param, node->current_object, lastname);
	if (get_cmd)
		(get_cmd)(full_param, dmctx, data, instance, &value);

	add_list_parameter(dmctx, full_param, value, DMT_TYPE[type], NULL);
	return 0;
}

int dm_entry_list_events(struct dmctx *dmctx)
{
	DMOBJ *root = dmctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	int err;

	dmctx->inparam_isparam = 0;
	dmctx->isgetschema = 1;
	dmctx->isevent = 1;
	dmctx->findparam = 0;
	dmctx->stop = 0;
	dmctx->checkobj = NULL;
	dmctx->checkleaf = NULL;
	dmctx->method_obj = mobj_list_events_name;
	dmctx->method_param = mparam_list_events_name;
	err = dm_browse(dmctx, &node, root, NULL, NULL);
	return err;
}

int dm_browse_last_access_path(char *path, size_t len)
{
	snprintf(path, len, "%s", dm_browse_path);
	return 0;
}
