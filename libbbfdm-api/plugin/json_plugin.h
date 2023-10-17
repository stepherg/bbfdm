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

void save_loaded_json_files(struct list_head *json_list, json_object *data);
void parse_obj(char *object, json_object *jobj, DMOBJ *pobj, int index, int json_version, struct list_head *list);
void find_prefix_obj(char *full_obj, char *prefix_obj, size_t len);

int load_json_plugins(DMOBJ *entryobj, const char *path);
int free_json_plugins(void);

#endif //__DMENTRYJSON_H__
