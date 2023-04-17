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

#define ETC_DB_CONFIG "/etc/board-db/config"
#define VARSTATE_CONFIG "/var/state"
#define BBFDM_CONFIG "/etc/bbfdm/dmmap"
#define BBFDM_SAVEDIR "/tmp/.bbfdm"
#define UCI_CONFIG_DIR "/etc/config/"
#define VARSTATE_CONFDIR "/var/state/"
#define VARSTATE_SAVEDIR "/tmp/.bbfdm_var"

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

#define NEW_UCI_PATH(UCI_PATH, CPATH, DPATH)		\
struct uci_context *uci_ctx_##UCI_PATH = NULL;			\
const char *uci_savedir_##UCI_PATH = DPATH; \
const char *uci_confdir_##UCI_PATH = CPATH; \
int dmuci_get_section_type_##UCI_PATH(char *package, char *section,char **value)	\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_get_section_type(package, section, value);	\
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_init_##UCI_PATH(void)		\
{\
	if (uci_ctx_##UCI_PATH == NULL) {				\
		uci_ctx_##UCI_PATH = uci_alloc_context();	\
		if (!uci_ctx_##UCI_PATH)					\
			return -1;								\
		uci_add_delta_path(uci_ctx_##UCI_PATH, uci_ctx_##UCI_PATH->savedir);	\
		uci_set_savedir(uci_ctx_##UCI_PATH, uci_savedir_##UCI_PATH);			\
		uci_set_confdir(uci_ctx_##UCI_PATH, uci_confdir_##UCI_PATH);			\
	}																			\
	return 0;	\
}\
void dmuci_exit_##UCI_PATH(void)		\
{\
	if (uci_ctx_##UCI_PATH) uci_free_context(uci_ctx_##UCI_PATH);\
	uci_ctx_##UCI_PATH = NULL; \
}\
int dmuci_get_option_value_string_##UCI_PATH(char *package, char *section, char *option, char **value)	\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_get_option_value_string(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_get_option_value_list_##UCI_PATH(char *package, char *section, char *option, struct uci_list **value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_get_option_value_list(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_set_value_##UCI_PATH(char *package, char *section, char *option, char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_set_value(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_add_list_value_##UCI_PATH(char *package, char *section, char *option, char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_add_list_value(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_del_list_value_##UCI_PATH(char *package, char *section, char *option, char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_del_list_value(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_add_section_##UCI_PATH(char *package, char *stype, struct uci_section **s)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_add_section(package, stype, s); \
	uci_ctx = save_uci_ctx;			\
	return res;				\
}\
int dmuci_delete_##UCI_PATH(char *package, char *section, char *option, char *value) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_delete(package, section, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_set_value_by_section_##UCI_PATH(struct uci_section *s, char *option, char *value)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_set_value_by_section(s, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_delete_by_section_##UCI_PATH(struct uci_section *s, char *option, char *value)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_delete_by_section(s, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
struct uci_section *dmuci_walk_section_##UCI_PATH(char *package, char *stype, void *arg1, void *arg2, int cmp , int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk)\
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
int dmuci_revert_##UCI_PATH(void) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_revert(); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_save_package_##UCI_PATH(char *package) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_save_package(package); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_revert_package_##UCI_PATH(char *package) \
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_revert_package(package); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\
int dmuci_delete_by_section_unnamed_##UCI_PATH(struct uci_section *s, char *option, char *value)\
{\
	struct uci_context *save_uci_ctx;	\
	save_uci_ctx = uci_ctx;			\
	uci_ctx = uci_ctx_##UCI_PATH;	\
	int res = dmuci_delete_by_section_unnamed(s, option, value); \
	uci_ctx = save_uci_ctx;			\
	return res;						\
}\

int dmuci_init(void);
void dmuci_exit(void);
int dm_uci_init(void);
int dm_uci_exit(void);
char *dmuci_list_to_string(struct uci_list *list, const char *delimitor);
void free_all_list_package_change(struct list_head *clist);
int dmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value);
int dmuci_import(char *package_name, const char *input_path);
int dmuci_export_package(char *package, const char *output_path);
int dmuci_export(const char *output_path);
int dmuci_commit_package(char *package);
int dmuci_commit(void);
int dmuci_save_package(char *package);
int dmuci_save(void);
int dmuci_revert_package(char *package);
int dmuci_revert(void);
int dmuci_change_packages(struct list_head *clist);

int dmuci_get_section_type(char *package, char *section, char **value);
int dmuci_get_option_value_string(char *package, char *section, char *option, char **value);
char *dmuci_get_option_value_fallback_def(char *package, char *section, char *option, char *default_value);
int dmuci_get_option_value_list(char *package, char *section, char *option, struct uci_list **value);
int dmuci_set_value(char *package, char *section, char *option, char *value);
int dmuci_add_list_value(char *package, char *section, char *option, char *value);
int dmuci_del_list_value(char *package, char *section, char *option, char *value);
int dmuci_add_section(char *package, char *stype, struct uci_section **s);
int dmuci_delete(char *package, char *section, char *option, char *value);
int dmuci_rename_section(char *package, char *section, char *value);
int dmuci_get_value_by_section_string(struct uci_section *s, char *option, char **value);
char *dmuci_get_value_by_section_fallback_def(struct uci_section *s, char *option, char *default_value);
int dmuci_get_value_by_section_list(struct uci_section *s, char *option, struct uci_list **value);
int dmuci_set_value_by_section(struct uci_section *s, char *option, char *value);
int dmuci_delete_by_section(struct uci_section *s, char *option, char *value);
int dmuci_delete_by_section_unnamed(struct uci_section *s, char *option, char *value);
int dmuci_add_list_value_by_section(struct uci_section *s, char *option, char *value);
int dmuci_del_list_value_by_section(struct uci_section *s, char *option, char *value);
int dmuci_rename_section_by_section(struct uci_section *s, char *value);
struct uci_section *dmuci_walk_section(char *package, char *stype, void *arg1, void *arg2, int cmp , int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk);
struct uci_section *dmuci_walk_all_sections(char *package, struct uci_section *prev_section, int walk);

int dmuci_get_option_value_string_bbfdm(char *package, char *section, char *option, char **value);
int dmuci_set_value_bbfdm(char *package, char *section, char *option, char *value);
int dmuci_set_value_by_section_bbfdm(struct uci_section *s, char *option, char *value);
int dmuci_set_value_by_section_varstate(struct uci_section *s, char *option, char *value);
int dmuci_add_section_bbfdm(char *package, char *stype, struct uci_section **s);
int dmuci_delete_bbfdm(char *package, char *section, char *option, char *value);
int dmuci_delete_by_section_unnamed_bbfdm(struct uci_section *s, char *option, char *value);
int dmuci_delete_by_section_bbfdm(struct uci_section *s, char *option, char *value);
int dmuci_delete_by_section_varstate(struct uci_section *s, char *option, char *value);
int dmuci_commit_package_bbfdm(char *package);
int dmuci_commit_bbfdm(void);
int dmuci_revert_bbfdm(void);
int dmuci_commit_package_varstate(char *package);
int dmuci_save_package_varstate(char *package);
int dmuci_revert_package_varstate(char *package);
struct uci_section *dmuci_walk_section_bbfdm(char *package, char *stype, void *arg1, void *arg2, int cmp , int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk);
struct uci_section *dmuci_walk_section_varstate(char *package, char *stype, void *arg1, void *arg2, int cmp , int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk);
int dmuci_init_bbfdm(void);
void dmuci_exit_bbfdm(void);
void commit_and_free_uci_ctx_bbfdm(char *dmmap_config);
int dmuci_add_section_varstate(char *package, char *stype, struct uci_section **s);
int dmuci_init_varstate(void);
void dmuci_exit_varstate(void);
int db_get_value_string(char *package, char *section, char *option, char **value);
int dmuci_get_option_value_string_varstate(char *package, char *section, char *option, char **value);
int dmuci_set_value_varstate(char *package, char *section, char *option, char *value);

bool dmuci_string_to_boolean(char *value);

#endif

