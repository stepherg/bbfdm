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

#include "dmdynamicmem.h"

inline void *__dm_dynamic_malloc(struct list_head *mem_list, size_t size)
{
	struct dm_dynamic_mem *m = malloc(sizeof(struct dm_dynamic_mem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, mem_list);
	return (void *)m->mem;
}

inline void *__dm_dynamic_calloc(struct list_head *mem_list, int n, size_t size)
{
	struct dm_dynamic_mem *m = calloc(n, sizeof(struct dm_dynamic_mem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, mem_list);
	return (void *)m->mem;
}

inline void *__dm_dynamic_realloc(struct list_head *mem_list, void *n, size_t size)
{
	struct dm_dynamic_mem *m = NULL;
	if (n != NULL) {
		m = container_of(n, struct dm_dynamic_mem, mem);
		list_del(&m->list);
	}
	struct dm_dynamic_mem *new_m = realloc(m, sizeof(struct dm_dynamic_mem) + size);
	if (new_m == NULL) {
		dm_dynamic_free(m);
		return NULL;
	} else
		m = new_m;
	list_add(&m->list, mem_list);
	return (void *)m->mem;
}

inline void dm_dynamic_free(void *m)
{
	if (m == NULL) return;
	struct dm_dynamic_mem *rm;
	rm = container_of(m, struct dm_dynamic_mem, mem);
	list_del(&rm->list);
	free(rm);
}

void dm_dynamic_cleanmem(struct list_head *mem_list)
{
	struct dm_dynamic_mem *dmm;
	while (mem_list->next != mem_list) {
		dmm = list_entry(mem_list->next, struct dm_dynamic_mem, list);
		list_del(&dmm->list);
		free(dmm);
	}
}

char *__dm_dynamic_strdup(struct list_head *mem_list, const char *s)
{
	size_t len = strlen(s) + 1;
	void *new = __dm_dynamic_malloc(mem_list, len);
	if (new == NULL) return NULL;
	return (char *) memcpy(new, s, len);
}

int __dm_dynamic_asprintf(struct list_head *mem_list, char **s, const char *format, ...)
{
	int size;
	char *str = NULL;
	va_list arg;

	va_start(arg, format);
	size = vasprintf(&str, format, arg);
	va_end(arg);

	if (size < 0 || str == NULL)
		return -1;

	*s = __dm_dynamic_strdup(mem_list, str);

	free(str);
	if (*s == NULL)
		return -1;
	return 0;	
}
