/*
 * Copyright (C) 2021 IOPSYS Software Solutions AB
 *
 * Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "dmcommon.h"

/**
 *
 * BBF UCI API
 *
 */

int bbf_uci_add_section(const char *package, const char *type, struct uci_section **s)
{
	return dmuci_add_section(package, type, s);
}

int bbf_uci_delete_section(const char *package, const char *type, const char *option, const char *value)
{
	return dmuci_delete(package, type, option, value);
}

int bbf_uci_add_section_bbfdm(const char *package, const char *type, struct uci_section **s)
{
	return dmuci_add_section_bbfdm(package, type, s);
}

int bbf_uci_delete_section_bbfdm(const char *package, const char *type, const char *option, const char *value)
{
	return dmuci_delete_bbfdm(package, type, option, value);
}

int bbf_uci_rename_section(struct uci_section *s, const char *value)
{
	return dmuci_rename_section_by_section(s, value);
}

int bbf_uci_get_value(const char *package, const char *section, const char *option, char **value)
{
	return dmuci_get_option_value_string(package, section, option, value);
}

int bbf_uci_set_value(const char *package, const char *section, const char *option, const char *value)
{
	return dmuci_set_value(package, section, option, value);
}

int bbf_uci_get_value_by_section(struct uci_section *s, const char *option, char **value)
{
	return dmuci_get_value_by_section_string(s, option, value);
}

char *bbf_uci_get_value_by_section_fallback_def(struct uci_section *s, const char *option, const char *default_value)
{
	return dmuci_get_value_by_section_fallback_def(s, option, default_value);
}

int bbf_uci_set_value_by_section(struct uci_section *s, const char *option, const char *value)
{
	return dmuci_set_value_by_section(s, option, value);
}

int bbf_uci_delete_section_by_section(struct uci_section *s, const char *option, const char *value)
{
	return dmuci_delete_by_section(s, option, value);
}

int bbf_uci_get_section_name(const char *sec_name, char **value)
{
	return dmuci_get_section_name(sec_name, value);
}

int bbf_uci_set_section_name(const char *sec_name, char *str, size_t size)
{
	return dmuci_set_section_name(sec_name, str, size);
}

struct uci_section *bbf_uci_walk_section(const char *package, const char *type, const void *arg1, const void *arg2, int cmp, int (*filter)(struct uci_section *s, const void *value), struct uci_section *prev_section, int walk)
{
	return dmuci_walk_section(package, type, arg1, arg2, cmp, filter, prev_section, walk);

}


/**
 *
 * BBF UBUS API
 *
 */

int bbf_ubus_call(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	return dmubus_call(obj, method, u_args, u_args_size, req_res);
}

int bbf_ubus_call_set(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size)
{
	return dmubus_call_set(obj, method, u_args, u_args_size);
}


/**
 *
 * BBF MEMORY MANAGEMENT API
 *
 */

void *bbf_malloc(size_t size)
{
	return dmmalloc(size);
}

void *bbf_calloc(int nitems, size_t size)
{
	return dmcalloc(nitems, size);
}

void *bbf_realloc(void *ptr, size_t size)
{
	return dmrealloc(ptr, size);
}

char *bbf_strdup(const char *ptr)
{
	return dmstrdup(ptr);
}


/**
 *
 * BBF API
 *
 */

void bbf_synchronise_config_sections_with_dmmap(const char *package, const char *section_type, const char *dmmap_package, struct list_head *dup_list)
{
	return synchronize_specific_config_sections_with_dmmap(package, section_type, dmmap_package, dup_list);
}

void bbf_free_config_sections_list(struct list_head *dup_list)
{
	return free_dmmap_config_dup_list(dup_list);
}

char *bbf_handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct uci_section *s, char *inst_opt, char *alias_opt)
{
	return handle_instance(dmctx, parent_node, s, inst_opt, alias_opt);
}

int bbf_link_instance_object(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance)
{
	return DM_LINK_INST_OBJ(dmctx, parent_node, data, instance);
}

int bbf_get_number_of_entries(struct dmctx *ctx, void *data, char *instance, int (*browseinstobj)(struct dmctx *ctx, struct dmnode *node, void *data, char *instance))
{
	return get_number_of_entries(ctx, data, instance, browseinstobj);
}

int bbf_convert_string_to_bool(const char *str, bool *b)
{
	return string_to_bool(str, b);
}

void bbf_find_dmmap_section(const char *dmmap_package, const char *section_type, const char *section_name, struct uci_section **dmmap_section)
{
	return get_dmmap_section_of_config_section(dmmap_package, section_type, section_name, dmmap_section);
}

void bbf_find_dmmap_section_by_option(const char *dmmap_package, const char *section_type, const char *option_name, const char *option_value, struct uci_section **dmmap_section)
{
	return get_dmmap_section_of_config_section_eq(dmmap_package, section_type, option_name, option_value, dmmap_section);
}

int bbf_get_alias(struct dmctx *ctx, struct uci_section *s, const char *option_name, const char *instance, char **value)
{
	if (!ctx || !s || !option_name || !instance || !value)
		return -1;

	dmuci_get_value_by_section_string(s, option_name, value);
	if ((*value)[0] == '\0') {
		dmasprintf(value, "cpe-%s", instance);

		// Store Alias value
		dmuci_set_value_by_section(s, option_name, *value);
	}

	return 0;
}

int bbf_set_alias(struct dmctx *ctx, struct uci_section *s, const char *option_name, const char *instance, const char *value)
{
	if (!ctx || !s || !option_name || !instance || !value)
		return -1;

	switch (ctx->setaction) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(s, option_name, value);
		break;
	}

	return 0;
}

static void send_linker_request_event(struct ubus_context *ctx, const char *path)
{
	struct blob_buf bb;

	if (DM_STRLEN(path) == 0)
		return;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "path", path);

	ubus_send_event(ctx, "bbfdm.linker.request", bb.head);
	blob_buf_free(&bb);
}

int bbfdm_get_references(struct dmctx *ctx, int match_action, const char *base_path, const char *key_name, char *key_value, char *out, size_t out_len)
{
	char param_path[1024] = {0};
	char *value = NULL;

	if (DM_STRLEN(base_path) == 0) {
		BBF_ERR("Reference base path should not be empty!!!");
		return -1;
	}

	if (DM_STRLEN(key_name) == 0) {
		BBF_ERR("Reference key name should not be empty!!!");
		return -1;
	}

	if (DM_STRLEN(key_value) == 0) {
		BBF_DEBUG("Reference key value should not be empty!!!");
		return -1;
	}

	if (!out || !out_len) {
		BBF_ERR("Output buffer is NULL or has zero length. A valid buffer with sufficient size is required");
		return -1;
	}

	snprintf(param_path, sizeof(param_path), "%s*.%s", base_path, key_name);

	adm_entry_get_reference_param(ctx, param_path, key_value, &value);

	size_t len = strlen(out);

	if (DM_STRLEN(value) != 0) {

		if (out_len - len < strlen(value)) {
			BBF_ERR("Buffer overflow detected. The output buffer is not large enough to hold the additional data!!!");
			return -1;
		}

		snprintf(&out[len], out_len - len, "%s%s", len ? (match_action == MATCH_FIRST ? "," : ";") : "", value);
		return 0;
	}

	if (out_len - len < strlen(base_path) + strlen(key_name) + strlen(key_value) + 9) { // 9 = 'path[key_name==\"key_value\"].'
		BBF_ERR("Buffer overflow detected. The output buffer is not large enough to hold the additional data!!!");
		return -1;
	}

	snprintf(param_path, sizeof(param_path), "%s[%s==\"%s\"].", base_path, key_name, key_value);

	send_linker_request_event(ctx->ubus_ctx, param_path);

	snprintf(&out[len], out_len - len, "%s%s", len ? (match_action == MATCH_FIRST ? "," : ";") : "", param_path);

	return 0;
}

int _bbfdm_get_references(struct dmctx *ctx, const char *base_path, const char *key_name, char *key_value, char **value)
{
	char buf[1024] = {0};

	int res = bbfdm_get_references(ctx, MATCH_FIRST, base_path, key_name, key_value, buf, sizeof(buf));

	*value = (!res) ? dmstrdup(buf): "";

	return 0;
}

int bbfdm_get_reference_linker(struct dmctx *ctx, char *reference_path, struct dm_reference *reference_args)
{
	if (DM_STRLEN(reference_path) == 0) {
		bbfdm_set_fault_message(ctx, "%s: reference path should not be empty", __func__);
		return -1;
	}

	reference_args->path = reference_path;

	char *separator = strstr(reference_path, "=>");
	if (!separator) {
		bbfdm_set_fault_message(ctx, "%s: reference path must contain '=>' symbol to separate the path and value", __func__);
		return -1;
	}

	*separator = 0;

	reference_args->value = separator + 2;

	char *valid_path = strstr(separator + 2, "##");
	if (valid_path) {
		reference_args->is_valid_path = true;
		*valid_path = 0;
	}

	return 0;
}

int bbfdm_operate_reference_linker(struct dmctx *ctx, const char *reference_path, char **reference_value)
{
	if (!ctx) {
		BBF_ERR("%s: ctx should not be null", __func__);
		return -1;
	}

	if (DM_STRLEN(reference_path) == 0) {
		BBF_ERR("%s: reference path should not be empty", __func__);
		return -1;
	}

	if (!reference_value) {
		BBF_ERR("%s: reference_value should not be null", __func__);
		return -1;
	}

	adm_entry_get_reference_value(ctx, reference_path, reference_value);

	if (DM_STRLEN(*reference_value) != 0)
		return 0;

	return 0;
}
