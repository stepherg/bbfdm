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

#include "dmdynamicvendor.h"
#include "dmtree/vendor/vendor.h"

static void dm_browse_node_vendor_object_tree(DMNODE *parent_node, DMOBJ *entryobj)
{
	for (; (entryobj && entryobj->obj); entryobj++) {

		if (entryobj->nextdynamicobj) {
			struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + INDX_VENDOR_MOUNT;
			FREE(next_dyn_array->nextobj);
		}

		if (entryobj->dynamicleaf) {
			struct dm_dynamic_leaf *next_dyn_array = entryobj->dynamicleaf + INDX_VENDOR_MOUNT;
			FREE(next_dyn_array->nextleaf);
		}

		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		if (entryobj->nextobj)
			dm_browse_node_vendor_object_tree(&node, entryobj->nextobj);
	}
}

void free_vendor_dynamic_arrays(DMOBJ *dm_entryobj)
{
	DMOBJ *root = dm_entryobj;
	DMNODE node = {.current_object = ""};

	dm_browse_node_vendor_object_tree(&node, root);
}

static void overwrite_param(DMOBJ *entryobj, DMLEAF *leaf)
{
	if (entryobj->leaf) {

		DMLEAF *entryleaf = entryobj->leaf;
		for (; (entryleaf && entryleaf->parameter); entryleaf++) {

			if (DM_STRCMP(entryleaf->parameter, leaf->parameter) == 0) {
				entryleaf->getvalue = leaf->getvalue;
				entryleaf->setvalue = leaf->setvalue;
				return;
			}

		}
	}
}

static void overwrite_obj(DMOBJ *entryobj, DMOBJ *dmobj)
{
	if (entryobj->nextobj) {

		DMOBJ *entrynextobj = entryobj->nextobj;
		for (; (entrynextobj && entrynextobj->obj); entrynextobj++) {

			if (DM_STRCMP(entrynextobj->obj, dmobj->obj) == 0) {

				entrynextobj->addobj = dmobj->addobj;
				entrynextobj->delobj = dmobj->delobj;
				entrynextobj->checkdep = dmobj->checkdep;
				entrynextobj->browseinstobj = dmobj->browseinstobj;
				entrynextobj->get_linker = dmobj->get_linker;


				if (dmobj->leaf) {
					DMLEAF *leaf = dmobj->leaf;
					for (; (leaf && leaf->parameter); leaf++) {
						overwrite_param(entrynextobj, leaf);
					}
				}

				if (dmobj->nextobj) {
					DMOBJ *dmnextobj = dmobj->nextobj;
					for (; (dmnextobj && dmnextobj->obj); dmnextobj++) {
						overwrite_obj(entrynextobj, dmnextobj);
					}
				}

				return;
			}

		}
	}
}

static void load_vendor_extension_arrays(struct dmctx *ctx)
{
	char vendor_list[512] = {0};
	size_t length = 0;

	DM_STRNCPY(vendor_list, BBF_VENDOR_LIST, sizeof(vendor_list));
	char **tokens = strsplit(vendor_list, ",", &length);

	for (int idx = length - 1; idx >= 0; idx--) {

		DM_MAP_VENDOR *vendor_map_obj = tVendorExtension;

		for (int j = 0; vendor_map_obj[j].vendor; j++) {

			if (DM_STRCMP(vendor_map_obj[j].vendor, tokens[idx]) != 0)
				continue;

			DM_MAP_OBJ *vendor_obj = vendor_map_obj[j].vendor_obj;

			for (int i = 0; vendor_obj[i].path; i++) {

				DMOBJ *dm_entryobj = NULL;
				bool obj_exists = find_root_entry(ctx, vendor_obj[i].path, &dm_entryobj);
				if (obj_exists == false || !dm_entryobj)
					continue;

				if (vendor_obj[i].root_obj) {
					if (dm_entryobj->nextdynamicobj == NULL) {
						dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
						dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
						dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
					}

					if (dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj == NULL) {
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj = calloc(2, sizeof(DMOBJ *));
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj[0] = vendor_obj[i].root_obj;
					} else {
						int obj_idx = get_obj_idx_dynamic_array(dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj);
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj = realloc(dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj, (obj_idx + 2) * sizeof(DMOBJ *));
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj[obj_idx] = vendor_obj[i].root_obj;
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj[obj_idx+1] = NULL;
					}
				}

				if (vendor_obj[i].root_leaf) {
					if (dm_entryobj->dynamicleaf == NULL) {
						dm_entryobj->dynamicleaf = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_leaf));
						dm_entryobj->dynamicleaf[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
						dm_entryobj->dynamicleaf[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
						dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
					}

					if (dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf == NULL) {
						dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf = calloc(2, sizeof(DMLEAF *));
						dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf[0] = vendor_obj[i].root_leaf;
					} else {
						int leaf_idx = get_leaf_idx_dynamic_array(dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf);
						dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf = realloc(dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf, (leaf_idx + 2) * sizeof(DMLEAF *));
						dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf[leaf_idx] = vendor_obj[i].root_leaf;
						dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf[leaf_idx+1] = NULL;
					}
				}

			}

			break;
		}

	}
}

static void load_vendor_extension_overwrite_arrays(struct dmctx *ctx)
{
	char vendor_list[512] = {0};
	size_t length = 0;

	DM_STRNCPY(vendor_list, BBF_VENDOR_LIST, sizeof(vendor_list));
	char **tokens = strsplit(vendor_list, ",", &length);

	for (int idx = length - 1; idx >= 0; idx--) {

		DM_MAP_VENDOR *vendor_map_obj = tVendorExtensionOverwrite;

		for (int j = 0; vendor_map_obj[j].vendor; j++) {

			if (DM_STRCMP(vendor_map_obj[j].vendor, tokens[idx]) != 0)
				continue;

			DM_MAP_OBJ *dynamic_overwrite_obj = vendor_map_obj[j].vendor_obj;
			DMOBJ *dm_entryobj = NULL;

			for (int i = 0; dynamic_overwrite_obj[i].path; i++) {

				bool obj_exists = find_root_entry(ctx, dynamic_overwrite_obj[i].path, &dm_entryobj);
				if (obj_exists == false || !dm_entryobj)
					continue;

				if (dynamic_overwrite_obj[i].root_obj) {
					DMOBJ *dmobj = dynamic_overwrite_obj[i].root_obj;
					for (; (dmobj && dmobj->obj); dmobj++) {
						overwrite_obj(dm_entryobj, dmobj);
					}
				}

				if (dynamic_overwrite_obj[i].root_leaf) {
					DMLEAF *leaf = dynamic_overwrite_obj[i].root_leaf;
					for (; (leaf && leaf->parameter); leaf++) {
						overwrite_param(dm_entryobj, leaf);
					}
				}

			}

			break;
		}

	}
}

static void exclude_obj(struct dmctx *ctx, char *in_obj)
{
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};

	char *obj_path = replace_str(in_obj, ".{i}.", ".");
	dm_exclude_obj(ctx, &node, root, obj_path);
	dmfree(obj_path);
}

static void exclude_param(struct dmctx *ctx, char *in_param)
{
	DMOBJ *entryobj = NULL;
	char obj_prefix[256] = {'\0'};

	if (in_param == NULL)
		return;

	char *ret = strrchr(in_param, '.');
	if (ret)
		DM_STRNCPY(obj_prefix, in_param, ret - in_param + 2);

	bool obj_exists = find_root_entry(ctx, obj_prefix, &entryobj);

	if (entryobj && obj_exists == true) {
		DMLEAF *leaf = entryobj->leaf;

		for (; (leaf && leaf->parameter); leaf++) {

			char *full_param;

			dmastrcat(&full_param, obj_prefix, leaf->parameter);
			if (strcmp(full_param, in_param) == 0) {
				leaf->bbfdm_type = BBFDM_NONE;
				dmfree(full_param);
				return;
			}

			dmfree(full_param);
		}

	}
}

static void load_vendor_extension_exclude_arrays(struct dmctx *ctx)
{
	char vendor_list[512] = {0};
	size_t length = 0;

	DM_STRNCPY(vendor_list, BBF_VENDOR_LIST, sizeof(vendor_list));
	char **tokens = strsplit(vendor_list, ",", &length);

	for (int idx = length - 1; idx >= 0; idx--) {

		DM_MAP_VENDOR_EXCLUDE *vendor_map_exclude_obj = tVendorExtensionExclude;

		for (int j = 0; vendor_map_exclude_obj[j].vendor; j++) {

			if (DM_STRCMP(vendor_map_exclude_obj[j].vendor, tokens[idx]) != 0)
				continue;

			char **dynamic_exclude_obj = vendor_map_exclude_obj[j].vendor_obj;

			for (; *dynamic_exclude_obj; dynamic_exclude_obj++) {

				if ((*dynamic_exclude_obj)[DM_STRLEN(*dynamic_exclude_obj) - 1] == '.')
					exclude_obj(ctx, *dynamic_exclude_obj);
				else
					exclude_param(ctx, *dynamic_exclude_obj);
			}

			break;
		}

	}
}

void load_vendor_dynamic_arrays(struct dmctx *ctx)
{
	load_vendor_extension_arrays(ctx);
	load_vendor_extension_overwrite_arrays(ctx);
	load_vendor_extension_exclude_arrays(ctx);
}
