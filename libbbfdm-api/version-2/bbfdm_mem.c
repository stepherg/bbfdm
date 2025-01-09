/*
 * Copyright (C) 2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "bbfdm_api.h"

struct bbfdm_mem {
	struct list_head list;
	char mem[0];
};

void bbfdm_init_mem(struct bbfdm_ctx *bbfdm_ctx)
{
	bbfdm_ctx->mem_head = calloc(1, sizeof(struct list_head));
	if (bbfdm_ctx->mem_head == NULL) {
		BBFDM_ERR("Failed to allocate memory for the list head!!!");
		return;
	}

	// Initialize the list head
	INIT_LIST_HEAD(bbfdm_ctx->mem_head);
}

void bbfdm_free_mem(struct bbfdm_ctx *bbfdm_ctx)
{
	struct bbfdm_mem *dmm = NULL, *tmp = NULL;

	if (bbfdm_ctx->mem_head == NULL) {
		BBFDM_ERR("Memory list is NULL!");
		return;
	}

	list_for_each_entry_safe(dmm, tmp, bbfdm_ctx->mem_head, list) {
		list_del(&dmm->list);
		BBFDM_FREE(dmm);
	}

	BBFDM_FREE(bbfdm_ctx->mem_head);
}

void *bbfdm_malloc(struct bbfdm_ctx *bbfdm_ctx, size_t size)
{
	struct bbfdm_mem *m = malloc(sizeof(struct bbfdm_mem) + size);
	if (m == NULL)
		return NULL;

	list_add(&m->list, bbfdm_ctx->mem_head);
	return (void *)m->mem;
}

void *bbfdm_calloc(struct bbfdm_ctx *bbfdm_ctx, int n, size_t size)
{
	struct bbfdm_mem *m = calloc(n, sizeof(struct bbfdm_mem) + size);
	if (m == NULL)
		return NULL;

	list_add(&m->list, bbfdm_ctx->mem_head);
	return (void *)m->mem;
}

void *bbfdm_realloc(struct bbfdm_ctx *bbfdm_ctx, void *n, size_t size)
{
	struct bbfdm_mem *m = NULL;
	if (n != NULL) {
		m = container_of(n, struct bbfdm_mem, mem);
		list_del(&m->list);
	}

	struct bbfdm_mem *new_m = realloc(m, sizeof(struct bbfdm_mem) + size);
	if (new_m == NULL) {
		bbfdm_free_mem_bloc(m);
		return NULL;
	} else {
		m = new_m;
	}

	list_add(&m->list, bbfdm_ctx->mem_head);
	return (void *)m->mem;
}

char *bbfdm_strdup(struct bbfdm_ctx *bbfdm_ctx, const char *s)
{
	if (s == NULL)
		return NULL;

	size_t len = strlen(s) + 1;
	void *new = bbfdm_malloc(bbfdm_ctx, len);

	if (new == NULL)
		return NULL;

	return (char *) memcpy(new, s, len);
}

int bbfdm_asprintf(struct bbfdm_ctx *bbfdm_ctx, char **s, const char *format, ...)
{
	va_list arg;
	char *str = NULL;
	int size = 0;

	va_start(arg, format);
	size = vasprintf(&str, format, arg);
	va_end(arg);

	if (size < 0 || str == NULL)
		return -1;

	*s = bbfdm_strdup(bbfdm_ctx, str);

	BBFDM_FREE(str);
	if (*s == NULL)
		return -1;

	return 0;
}

void bbfdm_free_mem_bloc(const void *m)
{
	if (m == NULL) return;
	struct bbfdm_mem *rm;
	rm = container_of(m, struct bbfdm_mem, mem);
	list_del(&rm->list);
	BBFDM_FREE(rm);
}
