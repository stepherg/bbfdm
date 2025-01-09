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

#include "dmapi.h"

void dmfree(const void *m);

void __dminitmem(struct list_head *mem_list);
void __dmcleanmem(struct list_head *mem_list);
void *__dmmalloc(struct list_head *mem_list, size_t size);
void *__dmcalloc(struct list_head *mem_list, int n, size_t size);
void *__dmrealloc(struct list_head *mem_list, void *n, size_t size);
char *__dmstrdup(struct list_head *mem_list, const char *s);
int __dmasprintf(struct list_head *mem_list, char **s, const char *format, ...);
int __dmastrcat(struct list_head *mem_list, char **s, char *obj, char *lastname);

/*
 * Initialize memory management.
 * @param ctx - Pointer to bbf context
 */
void dm_init_mem(struct dmctx *ctx);

/*
 * Clean up memory management.
 * @param ctx - Pointer to bbf context
 */
void dm_clean_mem(struct dmctx *ctx);

/*
 * Allocate memory block of the specified size.
 * @param ctx - Pointer to bbf context
 * @param size - Size of memory block to allocate
 * @return Pointer to the allocated memory block
 */
void *dm_malloc(struct dmctx *ctx, size_t size);

/*
 * Allocate memory for an array of n elements, each of size bytes, initialized to zero.
 * @param ctx - Pointer to bbf context
 * @param n - Number of elements
 * @param size - Size of each element
 * @return Pointer to the allocated memory block
 */
void *dm_calloc(struct dmctx *ctx, int n, size_t size);

/*
 * Resize the memory block pointed to by n to the new size size.
 * @param ctx - Pointer to bbf context
 * @param n - Pointer to the memory block to resize
 * @param size - New size of the memory block
 * @return Pointer to the resized memory block
 */
void *dm_realloc(struct dmctx *ctx, void *n, size_t size);

/*
 * Duplicate the string s.
 * @param ctx - Pointer to bbf context
 * @param s - Pointer to the string to duplicate
 * @return Pointer to the duplicated string
 */
char *dm_strdup(struct dmctx *ctx, const char *s);

/*
 * Allocate a string with a format similar to printf.
 * @param ctx - Pointer to bbf context
 * @param s - Pointer to store the resulting string
 * @param format - Format string
 * @param ... - Additional arguments for the format string
 * @return 0 on success, -1 on failure
 */
int dm_asprintf(struct dmctx *ctx, char **s, const char *format, ...);

#define dmmalloc(x) dm_malloc(0, x)
#define dmcalloc(n, x) dm_calloc(0, n, x)
#define dmrealloc(x, n) dm_realloc(0, x, n)
#define dmstrdup(x) dm_strdup(0, x)
#define dmasprintf(s, format, ...) dm_asprintf(0, s, format, ## __VA_ARGS__)

#define dm_dynamic_malloc(m, x) __dmmalloc(m, x)
#define dm_dynamic_calloc(m, n, x) __dmcalloc(m, n, x)
#define dm_dynamic_realloc(m, x, n) __dmrealloc(m, x, n)
#define dm_dynamic_strdup(m, x) __dmstrdup(m, x)
#define dm_dynamic_asprintf(m, s, format, ...) __dmasprintf(m, s, format, ## __VA_ARGS__)
#define dm_dynamic_initmem(m) __dminitmem(m)
#define dm_dynamic_cleanmem(m) __dmcleanmem(m)

#endif /* __DMMEM_H */
