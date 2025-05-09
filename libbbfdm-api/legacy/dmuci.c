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

NEW_UCI_PATH(bbfdm)
NEW_UCI_PATH(varstate)

static const char *config_dir = "/etc/config/";
static const char *bbfdm_dir = "/etc/bbfdm/dmmap/";
static const char *varstate_dir = "/var/state/";

static void bbfdm_uci_init_ctx(struct uci_context **uci_ctx, const char *confdir, const char *savedir)
{
	*uci_ctx = uci_alloc_context();
	if (!*uci_ctx) {
		BBF_ERR("Failed to allocate memory for (%s) && (%s)!!!", confdir, savedir);
		return;
	}

	uci_set_confdir(*uci_ctx, confdir);
	uci_set_savedir(*uci_ctx, savedir);
}

void dm_uci_init(struct dmctx *bbf_ctx)
{
	if (bbf_ctx->dm_type == BBFDM_CWMP) {
		bbfdm_uci_init_ctx(&bbf_ctx->config_uci_ctx, config_dir, "/tmp/bbfdm/.cwmp/config/");
		bbfdm_uci_init_ctx(&bbf_ctx->dmmap_uci_ctx, bbfdm_dir, "/tmp/bbfdm/.cwmp/dmmap/");
	} else if (bbf_ctx->dm_type == BBFDM_USP) {
		bbfdm_uci_init_ctx(&bbf_ctx->config_uci_ctx, config_dir, "/tmp/bbfdm/.usp/config/");
		bbfdm_uci_init_ctx(&bbf_ctx->dmmap_uci_ctx, bbfdm_dir, "/tmp/bbfdm/.usp/dmmap/");
	} else {
		bbfdm_uci_init_ctx(&bbf_ctx->config_uci_ctx, config_dir, "/tmp/bbfdm/.bbfdm/config/");
		bbfdm_uci_init_ctx(&bbf_ctx->dmmap_uci_ctx, bbfdm_dir, "/tmp/bbfdm/.bbfdm/dmmap/");
	}

	bbfdm_uci_init_ctx(&bbf_ctx->varstate_uci_ctx, varstate_dir, "/tmp/bbfdm/.varstate/");

	uci_ctx = bbf_ctx->config_uci_ctx;
	uci_ctx_bbfdm = bbf_ctx->dmmap_uci_ctx;
	uci_ctx_varstate = bbf_ctx->varstate_uci_ctx;
}

void dm_uci_exit(struct dmctx *bbf_ctx)
{
	if (bbf_ctx->config_uci_ctx) {
		uci_free_context(bbf_ctx->config_uci_ctx);
		bbf_ctx->config_uci_ctx = NULL;
		uci_ctx = NULL;
	}

	if (bbf_ctx->dmmap_uci_ctx) {
		uci_free_context(bbf_ctx->dmmap_uci_ctx);
		bbf_ctx->dmmap_uci_ctx = NULL;
		uci_ctx_bbfdm = NULL;
	}

	if (bbf_ctx->varstate_uci_ctx) {
		uci_free_context(bbf_ctx->varstate_uci_ctx);
		bbf_ctx->varstate_uci_ctx = NULL;
		uci_ctx_varstate = NULL;
	}
}

static struct uci_context *get_uci_context_by_section(struct uci_section *section)
{
	size_t config_dir_len = strlen(config_dir);
	size_t bbfdm_dir_len = strlen(bbfdm_dir);
	size_t varstate_dir_len = strlen(varstate_dir);

	if (section && section->package && section->package->ctx) {
		const char *confdir = section->package->ctx->confdir;

		if (DM_STRNCMP(confdir, config_dir, config_dir_len) == 0) {
			return uci_ctx;
		} else if (DM_STRNCMP(confdir, bbfdm_dir, bbfdm_dir_len) == 0) {
			return uci_ctx_bbfdm;
		} else if (DM_STRNCMP(confdir, varstate_dir, varstate_dir_len) == 0) {
			return uci_ctx_varstate;
		} else {
			return uci_ctx;
		}
	}

	return uci_ctx;
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

/**** UCI LOOKUP ****/
int dmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, const char *package, const char *section, const char *option, const char *value)
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
int dmuci_get_section_type(const char *package, const char *section, char **value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, NULL, NULL)) {
		*value = dmstrdup("");
		return -1;
	}
	if (ptr.s) {
		*value = dmstrdup(ptr.s->type); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = dmstrdup("");
		return -1;
	}
	return 0;
}

int dmuci_get_option_value_string(const char *package, const char *section, const char *option, char **value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, NULL)) {
		*value = dmstrdup("");
		return -1;
	}
	if (ptr.o && ptr.o->type == UCI_TYPE_LIST) {
		*value = dmuci_list_to_string(&ptr.o->v.list, " ");
	} else if (ptr.o && ptr.o->v.string) {
		*value = dmstrdup(ptr.o->v.string); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = dmstrdup("");
		return -1;
	}
	return 0;
}

char *dmuci_get_option_value_fallback_def(const char *package, const char *section, const char *option, const char *default_value)
{
	char *value = NULL;

	dmuci_get_option_value_string(package, section, option, &value);
	if (DM_STRLEN(value) == 0)
		value = dmstrdup(default_value);

	return value;
}

int dmuci_get_option_value_list(const char *package, const char *section, const char *option, struct uci_list **value)
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

static struct uci_option *dmuci_get_option_ptr(const char *cfg_path, const char *package, const char *section, const char *option)
{
	struct uci_option *o = NULL;
	struct uci_element *e = NULL;
	struct uci_ptr ptr = {0};
	char *oconfdir;

	oconfdir = uci_ctx->confdir;
	uci_ctx->confdir = dmstrdup(cfg_path);

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
int dmuci_import(const char *package_name, const char *input_path)
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

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK)
		return -1;

	if (!configs)
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

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK)
		return -1;

	if (!configs)
		return -1;

	for (p = configs; *p; p++)
		dmuci_commit_package(*p);

	free(configs);
	return 0;
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


/**** UCI SET *****/
int dmuci_set_value(const char *package, const char *section, const char *option, const char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		return -1;

	if (uci_set(uci_ctx, &ptr) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI ADD LIST *****/
int dmuci_add_list_value(const char *package, const char *section, const char *option, const char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		return -1;

	if (uci_add_list(uci_ctx, &ptr) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DEL LIST *****/
int dmuci_del_list_value(const char *package, const char *section, const char *option, const char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, value))
		return -1;

	if (uci_del_list(uci_ctx, &ptr) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

/****** UCI ADD *******/
int dmuci_add_section(const char *package, const char *stype, struct uci_section **s)
{
	struct uci_ptr ptr = {0};
	char fname[128];

	*s = NULL;

	snprintf(fname, sizeof(fname), "%s/%s", uci_ctx->confdir, package);

	if (create_empty_file(fname))
		return -1;

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, NULL, NULL, NULL))
		return -1;

	if (uci_add_section(uci_ctx, ptr.p, stype, s) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DELETE *****/
int dmuci_delete(const char *package, const char *section, const char *option, const char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, option, NULL))
		return -1;

	if (uci_delete(uci_ctx, &ptr) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI RENAME SECTION *****/
int dmuci_rename_section(const char *package, const char *section, const char *value)
{
	struct uci_ptr ptr = {0};

	if (dmuci_lookup_ptr(uci_ctx, &ptr, package, section, NULL, value))
		return -1;

	if (uci_rename(uci_ctx, &ptr) != UCI_OK)
		return -1;

	if (uci_save(uci_ctx, ptr.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI LOOKUP by section pointer ****/
static int dmuci_lookup_ptr_by_section(struct uci_context *ctx, struct uci_ptr *ptr, struct uci_section *s, const char *option, const char *value)
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
int dmuci_get_value_by_section_string(struct uci_section *s, const char *option, char **value)
{
	struct uci_element *e = NULL;
	struct uci_option *o;

	if (s == NULL || option == NULL)
		goto not_found;

	uci_foreach_element(&s->options, e) {
		o = (uci_to_option(e));
		if (!DM_STRCMP(o->e.name, option)) {
			if (o->type == UCI_TYPE_LIST) {
				*value = dmuci_list_to_string(&o->v.list, " ");
			} else {
				*value = o->v.string ? dmstrdup(o->v.string) : dmstrdup(""); // MEM WILL BE FREED IN DMMEMCLEAN
			}
			return 0;
		}
	}

not_found:
	*value = dmstrdup("");
	return -1;
}

char *dmuci_get_value_by_section_fallback_def(struct uci_section *s, const char *option, const char *default_value)
{
	char *value = NULL;

	dmuci_get_value_by_section_string(s, option, &value);
	if (DM_STRLEN(value) == 0)
		value = dmstrdup(default_value);

	return value;
}

int dmuci_get_value_by_section_list(struct uci_section *s, const char *option, struct uci_list **value)
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
		if (DM_STRCMP(o->e.name, option) == 0) {
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
int dmuci_set_value_by_section(struct uci_section *s, const char *option, const char *value)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_set(curr_ctx, &up) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DELETE by section pointer *****/
int dmuci_delete_by_section(struct uci_section *s, const char *option, const char *value)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	curr_ctx->flags |= UCI_FLAG_EXPORT_NAME;

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_delete(curr_ctx, &up) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

int dmuci_delete_by_section_unnamed(struct uci_section *s, const char *option, const char *value)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_delete(curr_ctx, &up) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI ADD LIST by section pointer *****/
int dmuci_add_list_value_by_section(struct uci_section *s, const char *option, const char *value)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_add_list(curr_ctx, &up) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI DEL LIST by section pointer *****/
int dmuci_del_list_value_by_section(struct uci_section *s, const char *option, const char *value)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, option, value) == -1)
		return -1;

	if (uci_del_list(curr_ctx, &up) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI RENAME SECTION by section pointer *****/
int dmuci_rename_section_by_section(struct uci_section *s, const char *value)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, NULL, value) == -1)
		return -1;

	if (uci_rename(curr_ctx, &up) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI REORDER SECTION by section pointer *****/
int dmuci_reoder_section_by_section(struct uci_section *s, char *pos)
{
	struct uci_context *curr_ctx = get_uci_context_by_section(s);
	struct uci_ptr up = {0};

	if (dmuci_lookup_ptr_by_section(curr_ctx, &up, s, NULL, pos) == -1)
		return -1;

	if (uci_reorder_section(curr_ctx, up.s, strtoul(up.value, NULL, 10)) != UCI_OK)
		return -1;

	if (uci_save(curr_ctx, up.p) != UCI_OK)
		return -1;

	return 0;
}

/**** UCI WALK SECTIONS *****/
struct uci_section *dmuci_walk_section (const char *package, const char *stype, const void *arg1, const void *arg2, int cmp , int (*filter)(struct uci_section *s, const void *value), struct uci_section *prev_section, int walk)
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
		if (DM_STRCMP(s->type, stype) == 0) {
			switch(cmp) {
				case CMP_SECTION:
					goto end;
				case CMP_OPTION_EQUAL:
					dmuci_get_value_by_section_string(s, (const char *)arg1, &value);
					if (DM_STRCMP(value, (const char *)arg2) == 0)
						goto end;
					break;
				case CMP_OPTION_CONTAINING:
					dmuci_get_value_by_section_string(s, (const char *)arg1, &value);
					if (DM_STRSTR(value, (const char *)arg2))
						goto end;
					break;
				case CMP_OPTION_CONT_WORD:
					dmuci_get_value_by_section_string(s, (const char *)arg1, &value);
					dup = dmstrdup(value);
					pch = strtok_r(dup, " ", &spch);
					while (pch != NULL) {
						if (DM_STRCMP((const char *)arg2, pch) == 0) {
							dmfree(dup);
							goto end;
						}
						pch = strtok_r(NULL, " ", &spch);
					}
					dmfree(dup);
					break;
				case CMP_LIST_CONTAINING:
					dmuci_get_value_by_section_list(s, (const char *)arg1, &list_value);
					if (list_value != NULL) {
						uci_foreach_element(list_value, m) {
							if (DM_STRCMP(m->name, (const char *)arg2) == 0)
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

struct uci_section *dmuci_walk_all_sections(const char *package, struct uci_section *prev_section, int walk)
{
	struct uci_element *e = NULL;
	struct uci_list *list_section;
	struct uci_ptr ptr = {0};

	if (walk == GET_FIRST_SECTION) {
		if (dmuci_lookup_ptr(uci_ctx, &ptr, package, NULL, NULL, NULL) != UCI_OK)
			return NULL;

		list_section = &(ptr.p)->sections;
		e = list_to_element(list_section->next);
	} else {
		list_section = &prev_section->package->sections;
		e = list_to_element(prev_section->e.list.next);
	}

	return (&e->list != list_section) ? uci_to_section(e) : NULL;
}

/**** UCI GET db config *****/
int db_get_value_string(const char *package, const char *section, const char *option, char **value)
{
	struct uci_option *o = NULL;

	o = dmuci_get_option_ptr(ETC_DB_CONFIG, package, section, option);
	if (o) {
		*value = o->v.string ? dmstrdup(o->v.string) : dmstrdup(""); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = dmstrdup("");
		return -1;
	}
	return 0;
}

bool dmuci_string_to_boolean(const char *value)
{
	if (!value)
		return false;

	if (strncasecmp(value, "true", 4) == 0 ||
	    value[0] == '1' ||
	    strncasecmp(value, "on", 2) == 0 ||
	    strncasecmp(value, "yes", 3) == 0 ||
	    strncasecmp(value, "enable", 6) == 0)
		return true;

	return false;
}

bool dmuci_is_option_value_empty(struct uci_section *s, const char *option_name)
{
	char *option_value = NULL;

	if (!s || !option_name)
		return false;

	dmuci_get_value_by_section_string(s, option_name, &option_value);

	return (DM_STRLEN(option_value) == 0) ? true : false;
}

int dmuci_get_section_name(const char *sec_name, char **value)
{
	if (!sec_name)
		return -1;

	int len = DM_STRLEN(sec_name);
	if (len == 0)
		return 0;

	if (len > 2 && sec_name[0] == '4' && sec_name[1] == '0') {
		char res[256] = {0};

		convert_hex_to_string(sec_name + 2, res, sizeof(res));
		*value = dmstrdup(res);
	} else {
		*value = dmstrdup(sec_name);
	}

	return 0;
}

int dmuci_set_section_name(const char *sec_name, char *str, size_t size)
{
	if (!sec_name || !str || size == 0)
		return -1;

	if (special_char_exits(sec_name)) {
		if (size < 2)
			return -1;

		// section_name in hex should start with "40" as a prefix to indicate that the section name will be encoded
		str[0] = '4';
		str[1] = '0';

		convert_string_to_hex(sec_name, str + 2, size - 2);
	} else {
		snprintf(str, size, "%s", sec_name);
	}

	return 0;
}
