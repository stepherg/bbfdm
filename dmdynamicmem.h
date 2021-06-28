/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DM_DYNAMIC_MEM_H
#define __DM_DYNAMIC_MEM_H

#include <libbbf_api/dmcommon.h>

struct dm_dynamic_mem
{
	struct list_head list;
	char mem[0];
};

void *__dm_dynamic_malloc(struct list_head *mem_list, size_t size);
void *__dm_dynamic_calloc(struct list_head *mem_list, int n, size_t size);
void *__dm_dynamic_realloc(struct list_head *mem_list, void *n, size_t size);
char *__dm_dynamic_strdup(struct list_head *mem_list, const char *s);
int __dm_dynamic_asprintf(struct list_head *mem_list, char **s, const char *format, ...);
void dm_dynamic_free(void *m);
void dm_dynamic_cleanmem(struct list_head *mem_list);

#define dm_dynamic_malloc(m, x) __dm_dynamic_malloc(m, x)
#define dm_dynamic_calloc(m, n, x) __dm_dynamic_calloc(m, n, x)
#define dm_dynamic_realloc(m, x, n) __dm_dynamic_realloc(m, x, n)
#define dm_dynamic_strdup(m, x) __dm_dynamic_strdup(m, x)
#define dm_dynamic_asprintf(m, s, format, ...) __dm_dynamic_asprintf(m, s, format, ## __VA_ARGS__)

#endif //__DM_DYNAMIC_MEM_H
