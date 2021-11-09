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
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include "dmcommon.h"
#include "dmuci.h"
#include "dmmem.h"

static struct uci_context *uci_ctx = NULL;
static struct uci_context *uci_varstate_ctx;
static char *db_config = NULL;

NEW_UCI_PATH(bbfdm, BBFDM_CONFIG, BBFDM_SAVEDIR)

int dmuci_init(void)
{
	if (uci_ctx == NULL) {
		uci_ctx = uci_alloc_context();
		if (!uci_ctx)
			return -1;
	}

	return 0;
}

void dmuci_exit(void)
{
	if (uci_ctx)
		uci_free_context(uci_ctx);
	uci_ctx = NULL;
}

int bbf_uci_init(void)
{
	dmuci_init();

	uci_varstate_ctx = uci_alloc_context();
	if (!uci_varstate_ctx)
		return -1;

	dmuci_init_bbfdm();

	db_config = (folder_exists(LIB_DB_CONFIG)) ? LIB_DB_CONFIG : ETC_DB_CONFIG;

	return 0;
}

int bbf_uci_exit(void)
{
	dmuci_exit();

	if (uci_varstate_ctx)
		uci_free_context(uci_varstate_ctx);
	uci_varstate_ctx = NULL;

	dmuci_exit_bbfdm();

	return 0;
}

char *dmuci_list_to_string(struct uci_list *list, const char *delimitor)
{
	if (list) {
		struct uci_element *e = NULL;
		char list_val[512] = {0};
		unsigned pos = 0;

		list_val[0] = 0;
		uci_foreach_element(list, e) {
			if (e->name)
				pos += snprintf(&list_val[pos], sizeof(list_val) - pos, "%s%s", e->name, delimitor);
		}

		if (pos)
			list_val[pos - 1] = 0;

		return dmstrdup(list_val); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		return "";
	}
}

static inline bool check_section_name(const char *str, bool name)
{
	if (!*str)
		return false;
	for (; *str; str++) {
		unsigned char c = *str;
		if (isalnum(c) || c == '_') 
			continue;
		if (name || (c < 33) || (c > 126)) 
			return false;
	}
	return true;
}

static void add_list_package_change(struct list_head *clist, char *package)
{
	struct package_change *pc = NULL;

	list_for_each_entry(pc, clist, list) {
		if (strcmp(pc->package, package) == 0)
			return;
	}
	pc = calloc(1, sizeof(struct package_change));//TODO !!!!! Do not use dmcalloc here
	list_add_tail(&pc->list, clist);
	pc->package = strdup(package); //TODO !!!!! Do not use dmstrdup here
}

void free_all_list_package_change(struct list_head *clist)
{
	struct package_change *pc;
	while (clist->next != clist) {
		pc = list_entry(clist->next, struct package_change, list);
		list_del(&pc->list);
		free(pc->package);//TODO !!!!! Do not use dmfree here
		free(pc);//TODO !!!!! Do not use dmfree here
	}
}

/**** UCI LOOKUP ****/
int dmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value)
{
	/*value*/
	ptr->value = value;

	/*package*/
	if (!package)
		return -1;
	ptr->package = package;

	/*section*/
	if (!section || !section[0]) {
		ptr->target = UCI_TYPE_PACKAGE;
		goto lookup;
	}
	ptr->section = section;
	if (ptr->section &&  !check_section_name(ptr->section , true))
		ptr->flags |= UCI_LOOKUP_EXTENDED;

	/*option*/
	if (!option || !option[0]) {
		ptr->target = UCI_TYPE_SECTION;
		goto lookup;
	}
	ptr->target = UCI_TYPE_OPTION;
	ptr->option = option;

lookup:
	if (uci_lookup_ptr(ctx, ptr, NULL, true) != UCI_OK || !UCI_LOOKUP_COMPLETE) {
		return -1;
	}
	return 0;
}

/**** UCI GET *****/
int dmuci_get_section_type(char *package, char *section, char **value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, NULL, NULL)) {
		*value = "";
		return -1;
	}
	if (ptr.s) {
		*value = dmstrdup(ptr.s->type); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = "";
		return -1;
	}
	return 0;
}

int dmuci_get_option_value_string(char *package, char *section, char *option, char **value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, NULL)) {
		*value = "";
		return -1;
	}
	if (ptr.o && ptr.o->type == UCI_TYPE_LIST) {
		*value = dmuci_list_to_string(&ptr.o->v.list, " ");
	} else if (ptr.o && ptr.o->v.string) {
		*value = dmstrdup(ptr.o->v.string); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = "";
		return -1;
	}
	return 0;
}

char *dmuci_get_option_value_fallback_def(char *package, char *section, char *option, char *default_value)
{
	char *value = "";

	dmuci_get_option_value_string(package, section, option, &value);
	if (*value == '\0')
		value = default_value;

	return value;
}

int dmuci_get_option_value_list(char *package, char *section, char *option, struct uci_list **value)
{
	struct uci_element *e = NULL;
	struct uci_ptr ptr = {0};
	struct uci_list *list;
	char *pch = NULL, *spch = NULL, *dup = NULL;

	*value = NULL;

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, NULL))
		return -1;

	if (ptr.o) {
		switch(ptr.o->type) {
			case UCI_TYPE_LIST:
				*value = &ptr.o->v.list;
				break;
			case UCI_TYPE_STRING:
				if (!ptr.o->v.string || (ptr.o->v.string)[0] == '\0')
					return 0;
				list = dmcalloc(1, sizeof(struct uci_list)); // MEM WILL BE FREED IN DMMEMCLEAN
				uci_list_init(list);
				dup = dmstrdup(ptr.o->v.string); // MEM WILL BE FREED IN DMMEMCLEAN
				pch = strtok_r(dup, " ", &spch);
				while (pch != NULL) {
					e = dmcalloc(1, sizeof(struct uci_element)); // MEM WILL BE FREED IN DMMEMCLEAN
					e->name = pch;
					uci_list_add(list, &e->list);
					pch = strtok_r(NULL, " ", &spch);
				}
				*value = list;
				break;
			default:
				return -1;
		}
	} else {
		return -1;
	}
	return 0;
}

static struct uci_option *dmuci_get_option_ptr(char *cfg_path, char *package, char *section, char *option)
{
	struct uci_option *o = NULL;
	struct uci_element *e = NULL;
	struct uci_ptr ptr = {0};
	char *oconfdir;

	oconfdir = uci_ctx->confdir;
	uci_ctx->confdir = cfg_path;

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, NULL))
		goto end;

	e = ptr.last;
	switch(e->type) {
		case UCI_TYPE_OPTION:
			o = ptr.o;
			break;
		default:
			break;
	}
end:
	uci_ctx->confdir = oconfdir;
	return o;
}

/**** UCI IMPORT *****/
int dmuci_import(char *package_name, const char *input_path)
{
	struct uci_package *package = NULL;
	struct uci_element *e = NULL;
	int ret = 0;

	FILE *input = fopen(input_path, "r");
	if (!input)
		return -1;

	if (uci_import(uci_ctx, input, package_name, &package, (package_name != NULL)) != UCI_OK) {
		ret = -1;
		goto end;
	}

	uci_foreach_element(&uci_ctx->root, e) {
		struct uci_package *p = uci_to_package(e);
		if (uci_commit(uci_ctx, &p, true) != UCI_OK)
			ret = -1;
	}

end:
	fclose(input);

	return ret;
}

/**** UCI EXPORT *****/
int dmuci_export_package(char *package, const char *output_path)
{
	struct uci_ptr ptr = {0};
	int ret = 0;

	FILE *out = fopen(output_path, "a");
	if (!out)
		return -1;

	if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK) {
		ret = -1;
		goto end;
	}

	if (uci_export(uci_ctx, out, ptr.p, true) != UCI_OK)
		ret = -1;

end:
	fclose(out);

	return ret;
}

int dmuci_export(const char *output_path)
{
	char **configs = NULL;
	char **p;

	if ((uci_list_configs(uci_ctx, &configs) != UCI_OK) || !configs)
		return -1;

	for (p = configs; *p; p++)
		dmuci_export_package(*p, output_path);

	free(configs);
	return 0;
}

/**** UCI COMMIT *****/
int dmuci_commit_package(char *package)
{
	struct uci_ptr ptr = {0};

	if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK)
		return -1;

	if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK)
		return -1;

	return 0;
}

int dmuci_commit(void)
{
	char **configs = NULL;
	char **p;

	if ((uci_list_configs(uci_ctx, &configs) != UCI_OK) || !configs)
		return -1;

	for (p = configs; *p; p++)
		dmuci_commit_package(*p);

	free(configs);
	return 0;
}

/**** UCI SAVE *****/
int dmuci_save_package(char *package)
{
	struct uci_ptr ptr = {0};

	if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

int dmuci_save(void)
{
	char **configs = NULL;
	char **bbfdm_configs = NULL;
	char **p;
	int rc = 0;

	if ((uci_list_configs(uci_ctx, &configs) != UCI_OK) || !configs) {
		rc = -1;
		goto end;
	}
	for (p = configs; *p; p++)
		dmuci_save_package(*p);

	if (uci_ctx_bbfdm) {
		if ((uci_list_configs(uci_ctx_bbfdm, &bbfdm_configs) != UCI_OK) || !bbfdm_configs) {
			rc = -1;
			goto out;
		}
		for (p = bbfdm_configs; *p; p++)
			dmuci_save_package_bbfdm(*p);

		free(bbfdm_configs);
	}

out:
	free(configs);
end:
	return rc;
}

/**** UCI REVERT *****/
int dmuci_revert_package(char *package)
{
	struct uci_ptr ptr = {0};

	if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK)
		return -1;

	if (uci_revert(uci_ctx, &ptr) != UCI_OK)
		return -1;

	return 0;
}

int dmuci_revert(void)
{
	char **configs = NULL;
	char **p;

	if ((uci_list_configs(uci_ctx, &configs) != UCI_OK) || !configs)
		return -1;

	for (p = configs; *p; p++)
		dmuci_revert_package(*p);

	free(configs);
	return 0;
}

/**** UCI CHANGES PACKAGES *****/
int dmuci_change_packages(struct list_head *clist)
{
	char **configs = NULL;
	char **p;

	if ((uci_list_configs(uci_ctx, &configs) != UCI_OK) || !configs)
		return -1;

	for (p = configs; *p; p++) {
		struct uci_ptr ptr = {0};

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK)
			continue;

		if (uci_list_empty(&ptr.p->delta))
			continue;

		add_list_package_change(clist, *p);
	}

	free(configs);
	return 0;
}

/**** UCI SET *****/
int dmuci_set_value(char *package, char *section, char *option, char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		return -1;

	if (uci_set(uci_ctx, &ptr) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI ADD LIST *****/
int dmuci_add_list_value(char *package, char *section, char *option, char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		return -1;

	if (uci_add_list(uci_ctx, &ptr) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DEL LIST *****/
int dmuci_del_list_value(char *package, char *section, char *option, char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		return -1;

	if (uci_del_list(uci_ctx, &ptr) != UCI_OK)
		return -1;

	return 0;
}

/****** UCI ADD *******/
int dmuci_add_section(char *package, char *stype, struct uci_section **s)
{
	struct uci_ptr ptr = {0};
	char fname[128];

	*s = NULL;

	snprintf(fname, sizeof(fname), "%s/%s", uci_ctx->confdir, package);
	if (!file_exists(fname)) {
		FILE *fptr = fopen(fname, "w");
		if (fptr)
			fclose(fptr);
		else
			return -1;
	}

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, NULL, NULL, NULL))
		return -1;

	if (uci_add_section(uci_ctx, ptr.p, stype, s) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DELETE *****/
int dmuci_delete(char *package, char *section, char *option, char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, NULL))
		return -1;

	if (uci_delete(uci_ctx, &ptr) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI RENAME SECTION *****/
int dmuci_rename_section(char *package, char *section, char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, NULL, value))
		return -1;

	if (uci_rename(uci_ctx, &ptr) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI LOOKUP by section pointer ****/
static int dmuci_lookup_ptr_by_section(struct uci_context *ctx, struct uci_ptr *ptr, struct uci_section *s, char *option, char *value)
{
	if (s == NULL || s->package == NULL)
		return -1;

	/*value*/
	ptr->value = value;

	/*package*/
	ptr->package = s->package->e.name;
	ptr->p = s->package;

	/* section */
	ptr->section = s->e.name;
	ptr->s = s;

	/*option*/
	if (!option || !option[0]) {
		ptr->target = UCI_TYPE_SECTION;
		goto lookup;
	}
	ptr->target = UCI_TYPE_OPTION;
	ptr->option = option;

lookup:
	if (uci_lookup_ptr(ctx, ptr, NULL, true) != UCI_OK || !UCI_LOOKUP_COMPLETE)
		return -1;

	return 0;
}

/**** UCI GET by section pointer*****/
int dmuci_get_value_by_section_string(struct uci_section *s, char *option, char **value)
{
	struct uci_element *e = NULL;
	struct uci_option *o;

	if (s == NULL || option == NULL)
		goto not_found;

	uci_foreach_element(&s->options, e) {
		o = (uci_to_option(e));
		if (!strcmp(o->e.name, option)) {
			if (o->type == UCI_TYPE_LIST) {
				*value = dmuci_list_to_string(&o->v.list, " ");
			} else {
				*value = o->v.string ? dmstrdup(o->v.string) : ""; // MEM WILL BE FREED IN DMMEMCLEAN
			}
			return 0;
		}
	}

not_found:
	*value = "";
	return -1;
}

char *dmuci_get_value_by_section_fallback_def(struct uci_section *s, char *option, char *default_value)
{
	char *value = "";

	dmuci_get_value_by_section_string(s, option, &value);
	if (*value == '\0')
		value = default_value;

	return value;
}

int dmuci_get_value_by_section_list(struct uci_section *s, char *option, struct uci_list **value)
{
	struct uci_element *e = NULL;
	struct uci_option *o;
	struct uci_list *list;
	char *pch = NULL, *spch = NULL, *dup;

	*value = NULL;

	if (s == NULL || option == NULL)
		return -1;

	uci_foreach_element(&s->options, e) {
		o = (uci_to_option(e));
		if (strcmp(o->e.name, option) == 0) {
			switch(o->type) {
				case UCI_TYPE_LIST:
					*value = &o->v.list;
					return 0;
				case UCI_TYPE_STRING:
					if (!o->v.string || (o->v.string)[0] == '\0')
						return 0;
					list = dmcalloc(1, sizeof(struct uci_list)); // MEM WILL BE FREED IN DMMEMCLEAN
					uci_list_init(list);
					dup = dmstrdup(o->v.string); // MEM WILL BE FREED IN DMMEMCLEAN
					pch = strtok_r(dup, " ", &spch);
					while (pch != NULL) {
						e = dmcalloc(1, sizeof(struct uci_element)); // MEM WILL BE FREED IN DMMEMCLEAN
						e->name = pch;
						uci_list_add(list, &e->list);
						pch = strtok_r(NULL, " ", &spch);
					}
					*value = list;
					return 0;
				default:
					return -1;
			}
		}
	}
	return -1;
}

/**** UCI SET by section pointer ****/
int dmuci_set_value_by_section(struct uci_section *s, char *option, char *value)
{
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(uci_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_set(uci_ctx, &up) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DELETE by section pointer *****/
int dmuci_delete_by_section(struct uci_section *s, char *option, char *value)
{
	struct uci_ptr up = {0};
	uci_ctx->flags |= UCI_FLAG_EXPORT_NAME;

	if (dmuci_lookup_ptr_by_section(uci_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_delete(uci_ctx, &up) != UCI_OK)
		return -1;

	return 0;
}

int dmuci_delete_by_section_unnamed(struct uci_section *s, char *option, char *value)
{
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(uci_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_delete(uci_ctx, &up) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI ADD LIST by section pointer *****/
int dmuci_add_list_value_by_section(struct uci_section *s, char *option, char *value)
{
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(uci_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_add_list(uci_ctx, &up) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DEL LIST by section pointer *****/
int dmuci_del_list_value_by_section(struct uci_section *s, char *option, char *value)
{
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(uci_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_del_list(uci_ctx, &up) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI RENAME SECTION by section pointer *****/
int dmuci_rename_section_by_section(struct uci_section *s, char *value)
{
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(uci_ctx, &up, s, NULL, value) == -1)
		return -1;

	if (uci_rename(uci_ctx, &up) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI WALK SECTIONS *****/
struct uci_section *dmuci_walk_section (char *package, char *stype, void *arg1, void *arg2, int cmp , int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk)
{
	struct uci_section *s = NULL;
	struct uci_element *e, *m = NULL;
	char *value, *dup, *pch, *spch;
	struct uci_list *list_value, *list_section;
	struct uci_ptr ptr = {0};

	if (walk == GET_FIRST_SECTION) {
		if (dmuci_lookup_ptr(uci_ctx, &ptr, package, NULL, NULL, NULL) != UCI_OK)
			goto end;

		list_section = &(ptr.p)->sections;
		e = list_to_element(list_section->next);
	} else {
		list_section = &prev_section->package->sections;
		e = list_to_element(prev_section->e.list.next);
	}

	while(&e->list != list_section) {
		s = uci_to_section(e);
		if (strcmp(s->type, stype) == 0) {
			switch(cmp) {
				case CMP_SECTION:
					goto end;
				case CMP_OPTION_EQUAL:
					dmuci_get_value_by_section_string(s, (char *)arg1, &value);
					if (strcmp(value, (char *)arg2) == 0)
						goto end;
					break;
				case CMP_OPTION_CONTAINING:
					dmuci_get_value_by_section_string(s, (char *)arg1, &value);
					if (strstr(value, (char *)arg2))
						goto end;
					break;
				case CMP_OPTION_CONT_WORD:
					dmuci_get_value_by_section_string(s, (char *)arg1, &value);
					dup = dmstrdup(value);
					pch = strtok_r(dup, " ", &spch);
					while (pch != NULL) {
						if (strcmp((char *)arg2, pch) == 0) {
							dmfree(dup);
							goto end;
						}
						pch = strtok_r(NULL, " ", &spch);
					}
					dmfree(dup);
					break;
				case CMP_LIST_CONTAINING:
					dmuci_get_value_by_section_list(s, (char *)arg1, &list_value);
					if (list_value != NULL) {
						uci_foreach_element(list_value, m) {
							if (strcmp(m->name, (char *)arg2) == 0)
								goto end;
						}
					}										
					break;
				case CMP_FILTER_FUNC:
					if (filter(s, arg1) == 0)
						goto end;
					break;
				default:
					break;
			}
		}
		e = list_to_element(e->list.next);
		s = NULL;
	}
end:
	return s;
}

/**** UCI GET db config *****/
int db_get_value_string(char *package, char *section, char *option, char **value)
{
	struct uci_option *o;

	o = dmuci_get_option_ptr((db_config) ? db_config : LIB_DB_CONFIG, package, section, option);
	if (o) {
		*value = o->v.string ? dmstrdup(o->v.string) : ""; // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = "";
		return -1;
	}
	return 0;
}

/**** UCI GET /var/state *****/
int varstate_get_value_string(char *package, char *section, char *option, char **value)
{
	struct uci_ptr ptr = {0};

	uci_add_delta_path(uci_varstate_ctx, uci_varstate_ctx->savedir);
	uci_set_confdir(uci_varstate_ctx, VARSTATE_CONFIG);

	if (dmuci_lookup_ptr(uci_varstate_ctx, &ptr, package, section, option, NULL)) {
		*value = "";
		return -1;
	}
	if (ptr.o && ptr.o->v.string) {
		*value = ptr.o->v.string;
	} else {
		*value = "";
		return -1;
	}
	return 0;
}

void commit_and_free_uci_ctx_bbfdm(char *dmmap_config)
{
	dmuci_commit_package_bbfdm(dmmap_config);

	if (uci_ctx_bbfdm)
		uci_free_context(uci_ctx_bbfdm);
	uci_ctx_bbfdm = NULL;
}

char *bbf_uci_get_value(char *path, char *package, char *section, char *option)
{
	struct uci_option *o;
	char *val = "";

	if (!package || !section || !option)
		return val;

	o = dmuci_get_option_ptr((path) ? path : UCI_CONFIG_DIR, package, section, option);

	if (!o)
		return val;

	if(o->type == UCI_TYPE_LIST)
		return dmuci_list_to_string(&o->v.list, " ");

	if (o->v.string)
		return dmstrdup(o->v.string);

	return val;
}

char *bbf_uci_set_value(char *path, char *package, char *section, char *option, char *value)
{
	struct uci_context *save_uci_ctx = NULL;
	struct uci_ptr ptr = {0};
	char *val = "";

	if (!package || !section || !option || !value)
		return val;

	if (path && strcmp(path, BBFDM_CONFIG) == 0) {
		save_uci_ctx = uci_ctx;
		uci_ctx = uci_ctx_bbfdm;
	}

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		goto end;

	if (uci_set(uci_ctx, &ptr) != UCI_OK)
		goto end;

	if (ptr.o && ptr.o->v.string)
		val = dmstrdup(ptr.o->v.string);

end:
	if (path && strcmp(path, BBFDM_CONFIG) == 0)
		uci_ctx = save_uci_ctx;

	return val;
}
