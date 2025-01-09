/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *
 */

#ifndef __DMUCI_H
#define __DMUCI_H

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <uci.h>
#include <libubox/list.h>

#include "dmapi.h"

#ifndef ETC_DB_CONFIG
#define ETC_DB_CONFIG "/etc/board-db/config"
#endif

struct package_change
{
	struct list_head list;
	char *package;
};

#define uci_path_foreach_sections(path, package, stype, section) \
	for (section = dmuci_walk_section_##path(package, stype, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section_##path(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION))

#define uci_path_foreach_sections_safe(path, package, stype, _tmp, section) \
	for (section = dmuci_walk_section_##path(package, stype, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? dmuci_walk_section_##path(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? dmuci_walk_section_##path(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION) : NULL)

#define uci_path_foreach_option_eq(path, package, stype, option, val, section) \
	for (section = dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_EQUAL, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION))

#define uci_path_foreach_option_eq_safe(path, package, stype, option, val, _tmp, section) \
	for (section = dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_EQUAL, NULL, NULL, GET_FIRST_SECTION), \
	    _tmp = (section) ? dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ?  dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION) : NULL)

#define uci_path_foreach_option_cont(path, package, stype, option, val, section) \
	for (section = dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section_##path(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, section, GET_NEXT_SECTION))

#define uci_foreach_sections(package, stype, section) \
	for (section = dmuci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION))

#define uci_foreach_sections_safe(package, stype, _tmp, section) \
	for (section = dmuci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? dmuci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? dmuci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION) : NULL)

#define uci_foreach_option_eq(package, stype, option, val, section) \
	for (section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION))

#define uci_foreach_option_eq_safe(package, stype, option, val, _tmp, section) \
	for (section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? dmuci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? dmuci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION) : NULL)

#define uci_foreach_option_cont(package, stype, option, val, section) \
	for (section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, section, GET_NEXT_SECTION))

#define uci_foreach_option_cont_safe(package, stype, option, val, _tmp, section) \
	for (section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONTAINING, NULL, section, GET_NEXT_SECTION) : NULL)

#define uci_foreach_option_cont_word(package, stype, option, val, section) \
	for (section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONT_WORD, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section(package, stype, option, val, CMP_OPTION_CONT_WORD, NULL, section, GET_NEXT_SECTION))

#define uci_foreach_list_cont(package, stype, option, val, section) \
	for (section = dmuci_walk_section(package, stype, option, val, CMP_LIST_CONTAINING, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section(package, stype, option, val, CMP_LIST_CONTAINING, NULL, section, GET_NEXT_SECTION))

#define uci_foreach_filter_func(package, stype, arg, func, section) \
	for (section = dmuci_walk_section(package, stype, arg, NULL, CMP_FILTER_FUNC, func, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_section(package, stype, arg, NULL, CMP_FILTER_FUNC, func, section, GET_NEXT_SECTION))

#define uci_package_foreach_sections(package, section) \
	for (section = dmuci_walk_all_sections(package, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = dmuci_walk_all_sections(package, section, GET_NEXT_SECTION))

#define uci_package_foreach_sections_safe(package, _tmp, section) \
	for (section = dmuci_walk_all_sections(package, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? dmuci_walk_all_sections(package, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? dmuci_walk_all_sections(package, section, GET_NEXT_SECTION) : NULL)

#define section_name(s) s ? (s)->e.name : ""
#define section_type(s) s ? (s)->type : ""
#define section_config(s) s ? (s)->package->e.name : ""

static inline void uci_list_insert(struct uci_list *list, struct uci_list *ptr)
{
	list->next->prev = ptr;
	ptr->prev = list;
	ptr->next = list->next;
	list->next = ptr;
}

static inline void uci_list_add(struct uci_list *head, struct uci_list *ptr)
{
	uci_list_insert(head->prev, ptr);
}

static inline void uci_list_init(struct uci_list *ptr)
{
	ptr->prev = ptr;
	ptr->next = ptr;
}

#define NEW_UCI_PATH(UCI_PATH)		\
struct uci_context *uci_ctx_##UCI_PATH = NULL;			\
int dmuci_get_section_type_##UCI_PATH(const char *package, const char *section,char **value)	\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_get_section_type(package, section, value);	\
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_get_option_value_string_##UCI_PATH(const char *package, const char *section, const char *option, char **value)	\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_get_option_value_string(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_get_option_value_list_##UCI_PATH(const char *package, const char *section, const char *option, struct uci_list **value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_get_option_value_list(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_set_value_##UCI_PATH(const char *package, const char *section, const char *option, const char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_set_value(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_add_list_value_##UCI_PATH(const char *package, const char *section, const char *option, const char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_add_list_value(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_del_list_value_##UCI_PATH(const char *package, const char *section, const char *option, const char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_del_list_value(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_add_section_##UCI_PATH(const char *package, const char *stype, struct uci_section **s)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_add_section(package, stype, s); \
	uci_ctx = save_uci_ctx;			\
	return res;				\
}\
int dmuci_delete_##UCI_PATH(const char *package, const char *section, const char *option, const char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_delete(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_set_value_by_section_##UCI_PATH(struct uci_section *s, const char *option, const char *value)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_set_value_by_section(s, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_delete_by_section_##UCI_PATH(struct uci_section *s, const char *option, const char *value)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_delete_by_section(s, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
struct uci_section *dmuci_walk_section_##UCI_PATH(const char *package, const char *stype, const void *arg1, const void *arg2, int cmp , int (*filter)(struct uci_section *s, const void *value), struct uci_section *prev_section, int walk)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	struct uci_section *s = dmuci_walk_section(package, stype, arg1, arg2, cmp ,filter, prev_section, walk); \
	uci_ctx = save_uci_ctx;			\
	return s;						\
}\
int dmuci_commit_package_##UCI_PATH(char *package) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_commit_package(package); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_commit_##UCI_PATH(void) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_commit(); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_delete_by_section_unnamed_##UCI_PATH(struct uci_section *s, const char *option, const char *value)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_delete_by_section_unnamed(s, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\

void dm_uci_init(struct dmctx *bbf_ctx);
void dm_uci_exit(struct dmctx *bbf_ctx);

char *dmuci_list_to_string(struct uci_list *list, const char *delimitor);
int dmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, const char *package, const char *section, const char *option, const char *value);
int dmuci_import(const char *package_name, const char *input_path);
int dmuci_export_package(char *package, const char *output_path);
int dmuci_export(const char *output_path);
int dmuci_commit_package(char *package);
int dmuci_commit(void);
int dmuci_revert_package(char *package);

int dmuci_get_section_type(const char *package, const char *section, char **value);
int dmuci_get_option_value_string(const char *package, const char *section, const char *option, char **value);
char *dmuci_get_option_value_fallback_def(const char *package, const char *section, const char *option, const char *default_value);
int dmuci_get_option_value_list(const char *package, const char *section, const char *option, struct uci_list **value);
int dmuci_set_value(const char *package, const char *section, const char *option, const char *value);
int dmuci_add_list_value(const char *package, const char *section, const char *option, const char *value);
int dmuci_del_list_value(const char *package, const char *section, const char *option, const char *value);
int dmuci_add_section(const char *package, const char *stype, struct uci_section **s);
int dmuci_delete(const char *package, const char *section, const char *option, const char *value);
int dmuci_rename_section(const char *package, const char *section, const char *value);
int dmuci_get_value_by_section_string(struct uci_section *s, const char *option, char **value);
char *dmuci_get_value_by_section_fallback_def(struct uci_section *s, const char *option, const char *default_value);
int dmuci_get_value_by_section_list(struct uci_section *s, const char *option, struct uci_list **value);
int dmuci_set_value_by_section(struct uci_section *s, const char *option, const char *value);
int dmuci_delete_by_section(struct uci_section *s, const char *option, const char *value);
int dmuci_delete_by_section_unnamed(struct uci_section *s, const char *option, const char *value);
int dmuci_add_list_value_by_section(struct uci_section *s, const char *option, const char *value);
int dmuci_del_list_value_by_section(struct uci_section *s, const char *option, const char *value);
int dmuci_rename_section_by_section(struct uci_section *s, const char *value);
int dmuci_reoder_section_by_section(struct uci_section *s, char *pos);
struct uci_section *dmuci_walk_section(const char *package, const char *stype, const void *arg1, const void *arg2, int cmp , int (*filter)(struct uci_section *s, const void *value), struct uci_section *prev_section, int walk);
struct uci_section *dmuci_walk_all_sections(const char *package, struct uci_section *prev_section, int walk);

int dmuci_get_option_value_string_bbfdm(const char *package, const char *section, const char *option, char **value);
int dmuci_set_value_bbfdm(const char *package, const char *section, const char *option, const char *value);
int dmuci_set_value_by_section_bbfdm(struct uci_section *s, const char *option, const char *value);
int dmuci_add_section_bbfdm(const char *package, const char *stype, struct uci_section **s);
int dmuci_delete_bbfdm(const char *package, const char *section, const char *option, const char *value);
int dmuci_delete_by_section_unnamed_bbfdm(struct uci_section *s, const char *option, const char *value);
int dmuci_delete_by_section_bbfdm(struct uci_section *s, const char *option, const char *value);
int dmuci_commit_package_bbfdm(char *package);
int dmuci_commit_bbfdm(void);
struct uci_section *dmuci_walk_section_bbfdm(const char *package, const char *stype, const void *arg1, const void *arg2, int cmp , int (*filter)(struct uci_section *s, const void *value), struct uci_section *prev_section, int walk);

struct uci_section *dmuci_walk_section_varstate(const char *package, const char *stype, const void *arg1, const void *arg2, int cmp , int (*filter)(struct uci_section *s, const void *value), struct uci_section *prev_section, int walk);
int dmuci_add_section_varstate(const char *package, const char *stype, struct uci_section **s);
int dmuci_delete_by_section_varstate(struct uci_section *s, const char *option, const char *value);
int dmuci_get_option_value_string_varstate(const char *package, const char *section, const char *option, char **value);
int dmuci_set_value_varstate(const char *package, const char *section, const char *option, const char *value);
int dmuci_set_value_by_section_varstate(struct uci_section *s, const char *option, const char *value);
int dmuci_commit_package_varstate(char *package);

int db_get_value_string(const char *package, const char *section, const char *option, char **value);

int dmuci_get_section_name(const char *sec_name, char **value);
int dmuci_set_section_name(const char *sec_name, char *str, size_t size);
bool dmuci_string_to_boolean(const char *value);
bool dmuci_is_option_value_empty(struct uci_section *s, const char *option_name);

#endif

