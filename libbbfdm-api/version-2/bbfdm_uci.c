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

int bbfdm_init_uci_ctx(struct bbfdm_ctx *bbfdm_ctx)
{
	bbfdm_ctx->uci_ctx = uci_alloc_context();
	if (!bbfdm_ctx->uci_ctx) {
		BBFDM_ERR("Failed to allocate UCI context");
		return -1;
	}

	if (bbfdm_ctx->uci_confdir) {
		BBFDM_DEBUG("Setting UCI configuration directory: %s", bbfdm_ctx->uci_confdir);
		uci_set_confdir(bbfdm_ctx->uci_ctx, bbfdm_ctx->uci_confdir);
	}

	if (bbfdm_ctx->uci_savedir) {
		BBFDM_DEBUG("Setting UCI save directory: %s", bbfdm_ctx->uci_savedir);
		uci_set_savedir(bbfdm_ctx->uci_ctx, bbfdm_ctx->uci_savedir);
	}

	return 0;
}

int bbfdm_free_uci_ctx(struct bbfdm_ctx *bbfdm_ctx)
{
	if (bbfdm_ctx->uci_ctx) {
		uci_free_context(bbfdm_ctx->uci_ctx);
	}

	return 0;
}

int bbfdm_uci_get_buf(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, const char *default_value,
		char *buffer, size_t buffer_size)
{
	struct uci_ptr ptr = {0};
	char uci_str[512] = {0};

	if (!package || !section || !option || !default_value || !buffer || !buffer_size) {
		BBFDM_ERR("Invalid parameters provided to bbfdm_uci_get_buf API");
		return -1;
	}

	if (!bbfdm_ctx || !bbfdm_ctx->uci_ctx) {
		BBFDM_ERR("Invalid UCI context");
		return -1;
	}

	snprintf(uci_str, sizeof(uci_str), "%s.%s.%s", package, section, option);

	if (uci_lookup_ptr(bbfdm_ctx->uci_ctx, &ptr, uci_str, true) != UCI_OK || ptr.o == NULL) {
		BBFDM_WARNING("UCI value not found for '%s.%s.%s'. Using default: '%s'", package, section, option, default_value);
		snprintf(buffer, buffer_size, "%s", default_value);
		return -1;
	}

	snprintf(buffer, buffer_size, "%s", ptr.o->v.string);
	return 0;
}

int bbfdm_uci_get(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, char **value)
{
	char buffer[1024] = {0};

	int res = bbfdm_uci_get_buf(bbfdm_ctx, package, section, option, "", buffer, sizeof(buffer));

	*value = bbfdm_strdup(bbfdm_ctx, buffer);
	return res;
}

int bbfdm_uci_get_fallback_def(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, const char *default_value, char **value)
{
	char buffer[1024] = {0};

	int res = bbfdm_uci_get_buf(bbfdm_ctx, package, section, option, default_value, buffer, sizeof(buffer));

	*value = bbfdm_strdup(bbfdm_ctx, buffer);
	return res;
}

int bbfdm_uci_get_by_section_buf(struct bbfdm_ctx *bbfdm_ctx, struct uci_section *section, const char *option, const char *default_value,
		char *buffer, size_t buffer_size)
{
	struct uci_element *e = NULL;

	if (!section || !option || !default_value || !buffer || !buffer_size) {
		BBFDM_ERR("Invalid parameters provided to bbfdm_uci_get_by_section_buf API");
		return -1;
	}

	uci_foreach_element(&section->options, e) {
		struct uci_option *o = uci_to_option(e);

		if (strcmp(o->e.name, option) == 0 && o->type == UCI_TYPE_STRING) {
			snprintf(buffer, buffer_size, "%s", o->v.string);
			return 0;
		}
	}

	snprintf(buffer, buffer_size, "%s", default_value);
	return -1;
}

int bbfdm_uci_get_by_section(struct bbfdm_ctx *bbfdm_ctx, struct uci_section *section, const char *option, char **value)
{
	char buffer[1024] = {0};

	int res = bbfdm_uci_get_by_section_buf(bbfdm_ctx, section, option, "", buffer, sizeof(buffer));

	*value = bbfdm_strdup(bbfdm_ctx, buffer);
	return res;
}

int bbfdm_uci_set(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, const char *value)
{
	struct uci_ptr ptr = {0};
	char uci_str[512] = {0};

	if (!package || !section || !value) {
		BBFDM_ERR("Invalid parameters provided to bbfdm_uci_set API");
		return -1;
	}

	if (!bbfdm_ctx || !bbfdm_ctx->uci_ctx) {
		BBFDM_ERR("Invalid UCI context");
		return -1;
	}

	snprintf(uci_str, sizeof(uci_str), "%s.%s%s%s=%s",
			package,
			section,
			option ? "." : "",
			option ? option : "",
			value);

	if (uci_lookup_ptr(bbfdm_ctx->uci_ctx, &ptr, uci_str, true) != UCI_OK ||
		uci_set(bbfdm_ctx->uci_ctx, &ptr) != UCI_OK ||
		uci_save(bbfdm_ctx->uci_ctx, ptr.p) != UCI_OK) {
		BBFDM_ERR("Failed to set UCI option: %s", uci_str);
		return -1;
	}

	return 0;
}

int bbfdm_uci_add(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *type, struct uci_section **s)
{
	struct uci_ptr ptr = {0};
	char uci_str[64] = {0};
	char config_name[128];

	if (!package || !type) {
		BBFDM_ERR("Invalid parameters provided to bbfdm_uci_add API");
		return -1;
	}

	if (!bbfdm_ctx || !bbfdm_ctx->uci_ctx) {
		BBFDM_ERR("Invalid UCI context");
		return -1;
	}

	snprintf(config_name, sizeof(config_name), "%s/%s", bbfdm_ctx->uci_ctx->confdir, package);

	if (bbfdm_create_empty_file(config_name)) {
		BBFDM_ERR("Failed to create empty UCI file: %s", config_name);
		return -1;
	}

	snprintf(uci_str, sizeof(uci_str), "%s", package);

	if (uci_lookup_ptr(bbfdm_ctx->uci_ctx, &ptr, uci_str, true) != UCI_OK ||
		uci_add_section(bbfdm_ctx->uci_ctx, ptr.p, type, s) != UCI_OK ||
		uci_save(bbfdm_ctx->uci_ctx, ptr.p) != UCI_OK) {
		BBFDM_ERR("Failed to add UCI section to package: %s with type: %s", package, type);
		return -1;
	}

	return 0;
}

int bbfdm_uci_delete(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option)
{
	struct uci_ptr ptr = {0};
	char uci_str[64] = {0};

	if (!package || !section)
		return -1;

	if (!bbfdm_ctx || !bbfdm_ctx->uci_ctx) {
		BBFDM_ERR("Invalid UCI context");
		return -1;
	}

	snprintf(uci_str, sizeof(uci_str), "%s.%s%s%s",
			package,
			section,
			option ? "." : "",
			option ? option : "");

	if (uci_lookup_ptr(bbfdm_ctx->uci_ctx, &ptr, uci_str, true) != UCI_OK ||
		uci_delete(bbfdm_ctx->uci_ctx, &ptr) != UCI_OK ||
		uci_save(bbfdm_ctx->uci_ctx, ptr.p) != UCI_OK) {
		BBFDM_ERR("Failed to delete UCI entry: %s", uci_str);
		return -1;
	}

	return 0;
}

int bbfdm_uci_delete_section(struct bbfdm_ctx *bbfdm_ctx, struct uci_section *s)
{
	return bbfdm_uci_delete(bbfdm_ctx, bbfdm_section_config(s), bbfdm_section_name(s), NULL);
}

int bbfdm_uci_commit_package(struct bbfdm_ctx *bbfdm_ctx, const char *package)
{
	struct uci_ptr ptr = {0};
	char uci_str[64] = {0};

	if (!package || !strlen(package)) {
		BBFDM_ERR("Invalid package name in bbfdm_uci_commit_package API");
		return -1;
	}

	if (!bbfdm_ctx || !bbfdm_ctx->uci_ctx) {
		BBFDM_ERR("Invalid UCI context");
		return -1;
	}

	snprintf(uci_str, sizeof(uci_str), "%s", package);

	if (uci_lookup_ptr(bbfdm_ctx->uci_ctx, &ptr, uci_str, true) != UCI_OK ||
		uci_commit(bbfdm_ctx->uci_ctx, &ptr.p, false) != UCI_OK) {
		BBFDM_ERR("Failed to commit UCI package: %s", package);
		return -1;
	}

	return 0;
}

struct uci_section *bbfdm_uci_walk_section(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *type, struct uci_section *prev_section)
{
	struct uci_list *ul = NULL, *shead = NULL;
	struct uci_ptr ptr = {0};

	if (prev_section) {
		ul = &prev_section->e.list;
		shead = &prev_section->package->sections;
	} else {
		char uci_str[64] = {0};

		snprintf(uci_str, sizeof(uci_str), "%s", package);

		if (uci_lookup_ptr(bbfdm_ctx->uci_ctx, &ptr, uci_str, true) != UCI_OK)
			return NULL;

		ul = &ptr.p->sections;
		shead = &ptr.p->sections;
	}

	while (ul->next != shead) {
		struct uci_element *e = container_of(ul->next, struct uci_element, list);
		struct uci_section *next_section = uci_to_section(e);

		if (strcmp(next_section->type, type) == 0)
			return next_section;

		ul = ul->next;
	}

	return NULL;
}
