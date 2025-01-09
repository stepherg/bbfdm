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

DMOBJ *find_entry_obj(DMOBJ *entryobj, const char *obj_path);

void disable_entry_obj(DMOBJ *entryobj, const char *obj_path, const char *parent_obj, const char *plugin_path);
void disable_entry_leaf(DMOBJ *entryobj, const char *leaf_path, const char *parent_obj, const char *plugin_path);

int get_entry_obj_idx(DMOBJ *entryobj);
int get_entry_leaf_idx(DMLEAF *entryleaf);
int get_obj_idx(DMOBJ **entryobj);
int get_leaf_idx(DMLEAF **entryleaf);

void load_plugins(DMOBJ *dm_entryobj, const char *plugin_path);
void free_plugins(DMOBJ *dm_entryobj);

#endif //__DMPLUGIN_H__
