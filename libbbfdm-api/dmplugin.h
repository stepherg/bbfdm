/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#ifndef __DMPLUGIN_H__
#define __DMPLUGIN_H__

bool find_entry_obj(DMOBJ *root_entry, char *in_param, DMOBJ **entryobj);

void dm_exclude_obj(DMOBJ *entryobj, DMNODE *parent_node, char *obj_path);

int get_entry_idx(DMOBJ *entryobj);
int get_obj_idx(DMOBJ **entryobj);
int get_leaf_idx(DMLEAF **entryleaf);

void load_plugins(DMOBJ *dm_entryobj, DM_MAP_VENDOR *dm_VendorExtension[], DM_MAP_VENDOR_EXCLUDE *dm_VendorExtensionExclude, bool enable_plugins);
void free_plugins(DMOBJ *dm_entryobj, DM_MAP_VENDOR *dm_VendorExtension[], DM_MAP_VENDOR_EXCLUDE *dm_VendorExtensionExclude, bool enable_plugins);

#endif //__DMPLUGIN_H__
