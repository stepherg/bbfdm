/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "vendor_plugin.h"
#include "../dmplugin.h"

#ifndef BBF_VENDOR_LIST
#define BBF_VENDOR_LIST ""
#endif

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

static void load_vendor_extension_arrays(DMOBJ *entryobj, DM_MAP_VENDOR *vendor_map_obj)
{
	char *pch = NULL, *pchr = NULL;
	char vendor_list[512] = {0};

	DM_STRNCPY(vendor_list, BBF_VENDOR_LIST, sizeof(vendor_list));

	for (pch = strtok_r(vendor_list, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {

		for (int j = 0; vendor_map_obj && vendor_map_obj[j].vendor; j++) {

			if (DM_STRCMP(vendor_map_obj[j].vendor, pch) != 0)
				continue;

			DM_MAP_OBJ *vendor_obj = vendor_map_obj[j].vendor_obj;

			for (int i = 0; vendor_obj[i].path; i++) {

				DMOBJ *dm_entryobj = find_entry_obj(entryobj, vendor_obj[i].path);
				if (!dm_entryobj)
					continue;

				if (vendor_obj[i].root_obj) {
					if (dm_entryobj->nextdynamicobj == NULL) {
						dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
						dm_entryobj->nextdynamicobj[INDX_JSON_MOUNT].idx_type = INDX_JSON_MOUNT;
						dm_entryobj->nextdynamicobj[INDX_LIBRARY_MOUNT].idx_type = INDX_LIBRARY_MOUNT;
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].idx_type = INDX_VENDOR_MOUNT;
						dm_entryobj->nextdynamicobj[INDX_SERVICE_MOUNT].idx_type = INDX_SERVICE_MOUNT;
					}

					if (dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj == NULL) {
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj = calloc(2, sizeof(DMOBJ *));
						dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj[0] = vendor_obj[i].root_obj;
					} else {
						int obj_idx = get_obj_idx(dm_entryobj->nextdynamicobj[INDX_VENDOR_MOUNT].nextobj);
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
						int leaf_idx = get_leaf_idx(dm_entryobj->dynamicleaf[INDX_VENDOR_MOUNT].nextleaf);
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

static void load_vendor_extension_overwrite_arrays(DMOBJ *entryobj, DM_MAP_VENDOR *vendor_map_obj)
{
	char *pch = NULL, *pchr = NULL;
	char vendor_list[512] = {0};

	DM_STRNCPY(vendor_list, BBF_VENDOR_LIST, sizeof(vendor_list));

	for (pch = strtok_r(vendor_list, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {

		for (int j = 0; vendor_map_obj && vendor_map_obj[j].vendor; j++) {

			if (DM_STRCMP(vendor_map_obj[j].vendor, pch) != 0)
				continue;

			DM_MAP_OBJ *dynamic_overwrite_obj = vendor_map_obj[j].vendor_obj;

			for (int i = 0; dynamic_overwrite_obj[i].path; i++) {

				DMOBJ *dm_entryobj = find_entry_obj(entryobj, dynamic_overwrite_obj[i].path);
				if (!dm_entryobj)
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

static void exclude_obj(DMOBJ *dm_entryobj, char *in_obj)
{
	DMNODE node = {.current_object = ""};

	char *obj_path = replace_str(in_obj, ".{i}.", ".");
	dm_exclude_obj(dm_entryobj, &node, obj_path);
	FREE(obj_path);
}

static void exclude_param(DMOBJ *dm_entryobj, char *in_param)
{
	char obj_prefix[256] = {'\0'};

	if (in_param == NULL)
		return;

	char *ret = strrchr(in_param, '.');
	if (ret)
		DM_STRNCPY(obj_prefix, in_param, ret - in_param + 2);

	DMOBJ *entryobj = find_entry_obj(dm_entryobj, obj_prefix);

	if (entryobj) {
		DMLEAF *leaf = entryobj->leaf;

		for (; (leaf && leaf->parameter); leaf++) {

			char param[1024];

			snprintf(param, sizeof(param), obj_prefix, leaf->parameter);

			if (strcmp(param, in_param) == 0) {
				leaf->bbfdm_type = BBFDM_NONE;
				return;
			}

		}

	}
}

static void load_vendor_extension_exclude_arrays(DMOBJ *entryobj, DM_MAP_VENDOR_EXCLUDE *vendor_map_exclude_obj)
{
	char *pch = NULL, *pchr = NULL;
	char vendor_list[512] = {0};

	DM_STRNCPY(vendor_list, BBF_VENDOR_LIST, sizeof(vendor_list));

	for (pch = strtok_r(vendor_list, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {

		for (int j = 0; vendor_map_exclude_obj && vendor_map_exclude_obj[j].vendor; j++) {

			if (DM_STRCMP(vendor_map_exclude_obj[j].vendor, pch) != 0)
				continue;

			char **dynamic_exclude_obj = vendor_map_exclude_obj[j].vendor_obj;

			for (; *dynamic_exclude_obj; dynamic_exclude_obj++) {

				if ((*dynamic_exclude_obj)[DM_STRLEN(*dynamic_exclude_obj) - 1] == '.')
					exclude_obj(entryobj, *dynamic_exclude_obj);
				else
					exclude_param(entryobj, *dynamic_exclude_obj);
			}

			break;
		}

	}
}

void load_vendor_dynamic_arrays(DMOBJ *entryobj, DM_MAP_VENDOR *VendorExtension[], DM_MAP_VENDOR_EXCLUDE *VendorExtensionExclude)
{
	load_vendor_extension_arrays(entryobj, VendorExtension[0]);
	load_vendor_extension_overwrite_arrays(entryobj, VendorExtension[1]);
	load_vendor_extension_exclude_arrays(entryobj, VendorExtensionExclude);
}
