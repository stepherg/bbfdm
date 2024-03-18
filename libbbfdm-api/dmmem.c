/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *
 */

#include "dmbbf.h"
#include "dmmem.h"

#define CHECK_MEM_LIST(mem_list) \
	do { \
		if (mem_list == NULL) { \
			BBF_ERR("mem_list is not initialized !!!"); \
			return NULL; \
		} \
	} while(0)

struct dmmem {
	struct list_head list;
	char mem[0];
};

void __dminitmem(struct list_head *mem_list)
{
	INIT_LIST_HEAD(mem_list);
}

void __dmcleanmem(struct list_head *mem_list)
{
	struct dmmem *dmm;
	while (mem_list->next != mem_list) {
		dmm = list_entry(mem_list->next, struct dmmem, list);
		list_del(&dmm->list);
		FREE(dmm);
	}
}

void dmfree(void *m)
{
	if (m == NULL) return;
	struct dmmem *rm;
	rm = container_of(m, struct dmmem, mem);
	list_del(&rm->list);
	FREE(rm);
}

void *__dmmalloc(struct list_head *mem_list, size_t size)
{
	CHECK_MEM_LIST(mem_list);

	struct dmmem *m = malloc(sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, mem_list);
	return (void *)m->mem;
}

void *__dmcalloc(struct list_head *mem_list, int n, size_t size)
{
	CHECK_MEM_LIST(mem_list);

	struct dmmem *m = calloc(n, sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, mem_list);
	return (void *)m->mem;
}

void *__dmrealloc(struct list_head *mem_list, void *n, size_t size)
{
	CHECK_MEM_LIST(mem_list);

	struct dmmem *m = NULL;
	if (n != NULL) {
		m = container_of(n, struct dmmem, mem);
		list_del(&m->list);
	}

	struct dmmem *new_m = realloc(m, sizeof(struct dmmem) + size);
	if (new_m == NULL) {
		dmfree(m);
		return NULL;
	} else {
		m = new_m;
	}

	list_add(&m->list, mem_list);
	return (void *)m->mem;
}

char *__dmstrdup(struct list_head *mem_list, const char *s)
{
	if (s == NULL)
		return NULL;

	size_t len = strlen(s) + 1;
	void *new = __dmmalloc(mem_list, len);

	if (new == NULL)
		return NULL;

	return (char *) memcpy(new, s, len);
}

int __dmasprintf(struct list_head *mem_list, char **s, const char *format, ...)
{
	int size;
	char *str = NULL;
	va_list arg;

	va_start(arg, format);
	size = vasprintf(&str, format, arg);
	va_end(arg);

	if (size < 0 || str == NULL)
		return -1;

	*s = __dmstrdup(mem_list, str);

	FREE(str);
	if (*s == NULL)
		return -1;

	return 0;	
}

int __dmastrcat(struct list_head *mem_list, char **s, char *obj, char *lastname)
{
	char buf[2048];
	int olen = strlen(obj);
	memcpy(buf, obj, olen);
	int llen = strlen(lastname) + 1;
	memcpy(buf + olen, lastname, llen);

	*s = __dmstrdup(mem_list, buf);
	if (*s == NULL)
		return -1;

	return 0;	
}

/*
 *
 * New BBFDM Memory Management APIs
 *
 */
static struct list_head *dm_memhead_ptr = NULL;

static struct list_head *get_ctx_memhead_list(struct dmctx *ctx)
{
	if (!ctx) {
		if (!dm_memhead_ptr) {
			BBF_ERR("'ctx->mem_head' and 'dm_memhead_ptr' are not initialized! You should initialize 'ctx->mem_head' before using bbfdm memory APIs");
			return NULL;
		}
		return dm_memhead_ptr;
	}

	if (!ctx->memhead) {
		BBF_ERR("'ctx->mem_head' is not initialized! You should initialize 'ctx->mem_head' before using bbfdm memory APIs");
		return NULL;
	}

	return ctx->memhead;
}

void bbfdm_init_mem(struct dmctx *ctx)
{
	struct list_head *memory_list_head = calloc(1, sizeof(struct list_head));

	// Check if memory allocation was successful
	if (memory_list_head == NULL) {
		BBF_ERR("Failed to allocate memory for the list head!!!");
		return;
	}

	// Initialize the list head
	INIT_LIST_HEAD(memory_list_head);

	ctx->memhead = dm_memhead_ptr = memory_list_head;
}

void bbfdm_clean_mem(struct dmctx *ctx)
{
	struct dmmem *dmm = NULL;

	if (ctx->memhead == NULL) {
		BBF_ERR("Memory list is NULL!");
		return;
	}

	while (ctx->memhead->next != ctx->memhead) {
		dmm = list_entry(ctx->memhead->next, struct dmmem, list);
		list_del(&dmm->list);
		FREE(dmm);
	}

	FREE(ctx->memhead);
	dm_memhead_ptr = NULL;
}

void *bbfdm_malloc(struct dmctx *ctx, size_t size)
{
	struct list_head *ctx_memhead = get_ctx_memhead_list(ctx);
	if (ctx_memhead == NULL)
		return NULL;

	struct dmmem *m = malloc(sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, ctx_memhead);
	return (void *)m->mem;
}

void *bbfdm_calloc(struct dmctx *ctx, int n, size_t size)
{
	struct list_head *ctx_memhead = get_ctx_memhead_list(ctx);
	if (ctx_memhead == NULL)
		return NULL;

	struct dmmem *m = calloc(n, sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, ctx_memhead);
	return (void *)m->mem;
}

void *bbfdm_realloc(struct dmctx *ctx, void *n, size_t size)
{
	struct list_head *ctx_memhead = get_ctx_memhead_list(ctx);
	if (ctx_memhead == NULL)
		return NULL;

	struct dmmem *m = NULL;
	if (n != NULL) {
		m = container_of(n, struct dmmem, mem);
		list_del(&m->list);
	}

	struct dmmem *new_m = realloc(m, sizeof(struct dmmem) + size);
	if (new_m == NULL) {
		dmfree(m);
		return NULL;
	} else {
		m = new_m;
	}

	list_add(&m->list, ctx_memhead);
	return (void *)m->mem;
}

char *bbfdm_strdup(struct dmctx *ctx, const char *s)
{
	if (s == NULL)
		return NULL;

	size_t len = strlen(s) + 1;
	void *new = bbfdm_malloc(ctx, len);

	if (new == NULL)
		return NULL;

	return (char *) memcpy(new, s, len);
}

int bbfdm_asprintf(struct dmctx *ctx, char **s, const char *format, ...)
{
	va_list arg;
	char *str = NULL;
	int size = 0;

	va_start(arg, format);
	size = vasprintf(&str, format, arg);
	va_end(arg);

	if (size < 0 || str == NULL)
		return -1;

	*s = bbfdm_strdup(ctx, str);

	FREE(str);
	if (*s == NULL)
		return -1;

	return 0;
}

int bbfdm_astrcat(struct dmctx *ctx, char **s, char *obj, char *lastname)
{
	char buf[2048] = {0};

	if (obj == NULL || lastname == NULL)
		return -1;

	int olen = strlen(obj);
	memcpy(buf, obj, olen);
	int llen = strlen(lastname) + 1;
	memcpy(buf + olen, lastname, llen);

	*s = bbfdm_strdup(ctx, buf);
	if (*s == NULL)
		return -1;

	return 0;
}
