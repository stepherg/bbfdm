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
static inline void dm_empty_func()
{
}

#define WITH_MEMLEACKSEC 1
//#define WITH_MEMTRACK 1

#ifndef WITH_MEMLEACKSEC
#undef WITH_MEMTRACK
#endif

#ifdef WITH_MEMLEACKSEC
struct dmmem {
	struct list_head list;
#ifdef WITH_MEMTRACK
	char *file;
	char *func;
	int line;
#endif /*WITH_MEMTRACK*/
	char mem[0];
};

void *__dmmalloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, size_t size
);

void *__dmcalloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, int n, size_t size
);

void *__dmrealloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, void *n, size_t size
);

char *__dmstrdup
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, const char *s
);

void __dmcleanmem(struct list_head *mem_list);
#endif /*WITH_MEMLEACKSEC*/

int __dmasprintf
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, char **s, const char *format, ...
);

int __dmastrcat
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, char **s, char *obj, char *lastname
);

#ifdef WITH_MEMLEACKSEC
#ifdef WITH_MEMTRACK
#define dmmalloc(x) __dmmalloc(__FILE__, __func__, __LINE__, &memhead, x)
#define dmcalloc(n, x) __dmcalloc(__FILE__, __func__, __LINE__, &memhead, n, x)
#define dmrealloc(x, n) __dmrealloc(__FILE__, __func__, __LINE__, &memhead, x, n)
#define dmstrdup(x) __dmstrdup(__FILE__, __func__, __LINE__, &memhead, x)
#define dmasprintf(s, format, ...) __dmasprintf(__FILE__, __func__, __LINE__, &memhead, s, format, ## __VA_ARGS__)
#define dmastrcat(s, b, m) __dmastrcat(__FILE__, __func__, __LINE__, &memhead, s, b, m)
#define dmcleanmem() __dmcleanmem(&memhead)
#else
#define dmmalloc(x) __dmmalloc(&memhead, x)
#define dmcalloc(n, x) __dmcalloc(&memhead, n, x)
#define dmrealloc(x, n) __dmrealloc(&memhead, x, n)
#define dmstrdup(x) __dmstrdup(&memhead, x)
#define dmasprintf(s, format, ...) __dmasprintf(&memhead, s, format, ## __VA_ARGS__)
#define dmastrcat(s, b, m) __dmastrcat(&memhead, s, b, m)
#define dmcleanmem() __dmcleanmem(&memhead)
#endif /*WITH_MEMTRACK*/

#define dm_dynamic_malloc(m, x) __dmmalloc(m, x)
#define dm_dynamic_calloc(m, n, x) __dmcalloc(m, n, x)
#define dm_dynamic_realloc(m, x, n) __dmrealloc(m, x, n)
#define dm_dynamic_strdup(m, x) __dmstrdup(m, x)
#define dm_dynamic_asprintf(m, s, format, ...) __dmasprintf(m, s, format, ## __VA_ARGS__)
#define dm_dynamic_cleanmem(m) __dmcleanmem(m)

#else
#define dmmalloc(x) malloc(x)
#define dmcalloc(n, x) calloc(n, x)
#define __dmstrdup(x) strdup(x)
#define dmstrdup(x) strdup(x)
#define dmasprintf(s, format, ...) __dmasprintf(s, format, ## __VA_ARGS__)
#define dmastrcat(s, b, m) __dmastrcat(s, b, m)
#define dmfree(x) free(x)
#define dmcleanmem() dm_empty_func()
#endif /*WITH_MEMLEACKSEC*/

#define DMFREE(x) do { dmfree(x); x = NULL; } while (0);
#endif
