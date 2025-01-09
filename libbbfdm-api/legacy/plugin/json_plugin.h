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

#ifndef __DMENTRYJSON_H__
#define __DMENTRYJSON_H__

#include "../dmcommon.h"

enum json_plugin_version {
	JSON_VERSION_0 = 1,
	JSON_VERSION_1 = 1 << 1,
	JSON_VERSION_2 = 1 << 2
};

void save_loaded_json_files(struct list_head *json_list, json_object *data);
void parse_obj(char *object, json_object *jobj, DMOBJ *pobj, int index, int json_version, struct list_head *list);
void json_plugin_find_prefix_obj(const char *full_obj, char *prefix_obj, size_t len);
void json_plugin_find_current_obj(const char *full_obj, char *curr_obj, size_t len);
int get_json_plugin_version(json_object *json_obj);

int load_json_plugins(DMOBJ *entryobj, const char *path);
int free_json_plugins(void);

#endif //__DMENTRYJSON_H__
