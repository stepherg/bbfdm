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

#include "dmmem.h"

#ifdef WITH_MEMLEACKSEC
LIST_HEAD(memhead);

inline void *__dmmalloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, size_t size
)
{
	struct dmmem *m = malloc(sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, mem_list);
#ifdef WITH_MEMTRACK
	m->file = (char *)file;
	m->func = (char *)func;
	m->line = line;
#endif /*WITH_MEMTRACK*/
	return (void *)m->mem;
}

inline void *__dmcalloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, int n, size_t size
)
{
	struct dmmem *m = calloc(n, sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, mem_list);
#ifdef WITH_MEMTRACK
	m->file = (char *)file;
	m->func = (char *)func;
	m->line = line;
#endif /*WITH_MEMTRACK*/
	return (void *)m->mem;
}

inline void *__dmrealloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, void *n, size_t size
)
{
	struct dmmem *m = NULL;
	if (n != NULL) {
		m = container_of(n, struct dmmem, mem);
		list_del(&m->list);
	}
	struct dmmem *new_m = realloc(m, sizeof(struct dmmem) + size);
	if (new_m == NULL) {
		dmfree(m);
		return NULL;
	} else
		m = new_m;
	list_add(&m->list, mem_list);
#ifdef WITH_MEMTRACK
	m->file = (char *)file;
	m->func = (char *)func;
	m->line = line;
#endif /*WITH_MEMTRACK*/
	return (void *)m->mem;
}

inline void dmfree(void *m)
{
	if (m == NULL) return;
	struct dmmem *rm;
	rm = container_of(m, struct dmmem, mem);
	list_del(&rm->list);
	free(rm);
}

inline void __dmcleanmem(struct list_head *mem_list)
{
	struct dmmem *dmm;
	while (mem_list->next != mem_list) {
		dmm = list_entry(mem_list->next, struct dmmem, list);
#ifdef WITH_MEMTRACK
		fprintf(stderr, "Allocated memory in {%s, %s(), line %d} is not freed\n", dmm->file, dmm->func, dmm->line);
#endif /*WITH_MEMTRACK*/
		list_del(&dmm->list);
		free(dmm);
	}
}

char *__dmstrdup
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, const char *s
)
{
	size_t len = strlen(s) + 1;
#ifdef WITH_MEMTRACK
	void *new = __dmmalloc(file, func, line, mem_list, len);
#else
	void *new = __dmmalloc(mem_list, len);
#endif /*WITH_MEMTRACK*/
	if (new == NULL) return NULL;
	return (char *) memcpy(new, s, len);
}
#endif /*WITH_MEMLEACKSEC*/

int __dmasprintf
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, char **s, const char *format, ...
)
{
	int size;
	char *str = NULL;
	va_list arg;

	va_start(arg, format);
	size = vasprintf(&str, format, arg);
	va_end(arg);

	if (size < 0 || str == NULL)
		return -1;

#ifdef WITH_MEMTRACK
	*s = __dmstrdup(file, func, line, mem_list, str);
#else
	*s = __dmstrdup(mem_list, str);
#endif /*WITH_MEMTRACK*/

	free(str);
	if (*s == NULL)
		return -1;
	return 0;	
}

int __dmastrcat
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
struct list_head *mem_list, char **s, char *obj, char *lastname
)
{
	char buf[2048];
	int olen = strlen(obj);
	memcpy(buf, obj, olen);
	int llen = strlen(lastname) + 1;
	memcpy(buf + olen, lastname, llen);
#ifdef WITH_MEMTRACK
	*s = __dmstrdup(file, func, line, mem_list, buf);
#else
	*s = __dmstrdup(mem_list, buf);
#endif /*WITH_MEMTRACK*/
	if (*s == NULL) return -1;
	return 0;	
}
