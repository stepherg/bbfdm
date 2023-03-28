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

#ifndef __DMMEM_H
#define __DMMEM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libubox/list.h>

extern struct list_head memhead;

void dmfree(void *m);

struct dmmem {
	struct list_head list;
	char mem[0];
};

void *__dmmalloc(struct list_head *mem_list, size_t size);
void *__dmcalloc(struct list_head *mem_list, int n, size_t size);
void *__dmrealloc(struct list_head *mem_list, void *n, size_t size);
char *__dmstrdup(struct list_head *mem_list, const char *s);
int __dmasprintf(struct list_head *mem_list, char **s, const char *format, ...);
int __dmastrcat(struct list_head *mem_list, char **s, char *obj, char *lastname);
void __dmcleanmem(struct list_head *mem_list);

#define dmmalloc(x) __dmmalloc(&memhead, x)
#define dmcalloc(n, x) __dmcalloc(&memhead, n, x)
#define dmrealloc(x, n) __dmrealloc(&memhead, x, n)
#define dmstrdup(x) __dmstrdup(&memhead, x)
#define dmasprintf(s, format, ...) __dmasprintf(&memhead, s, format, ## __VA_ARGS__)
#define dmastrcat(s, b, m) __dmastrcat(&memhead, s, b, m)
#define dmcleanmem() __dmcleanmem(&memhead)

#define dm_dynamic_malloc(m, x) __dmmalloc(m, x)
#define dm_dynamic_calloc(m, n, x) __dmcalloc(m, n, x)
#define dm_dynamic_realloc(m, x, n) __dmrealloc(m, x, n)
#define dm_dynamic_strdup(m, x) __dmstrdup(m, x)
#define dm_dynamic_asprintf(m, s, format, ...) __dmasprintf(m, s, format, ## __VA_ARGS__)
#define dm_dynamic_cleanmem(m) __dmcleanmem(m)

#endif /* __DMMEM_H */
