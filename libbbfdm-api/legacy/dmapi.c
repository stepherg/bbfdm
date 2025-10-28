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

/**
 * @brief Safely read a JSON object from a file with shared locking.
 *
 * This function opens a JSON file and reads its contents into memory
 * using a shared lock (`flock` with `LOCK_SH`) to prevent concurrent
 * writes during the read operation. It replaces the use of
 * `json_object_from_file()` from json-c in scenarios where the file
 * may be modified by other processes.
 *
 * Key behavior:
 * - Acquires a shared lock (`LOCK_SH`) to ensure the file isn't being
 *   modified by a writer holding an exclusive lock (`LOCK_EX`).
 * - Reads the entire file into a buffer and parses it using
 *   `json_tokener_parse()`.
 * - Ensures memory safety and proper resource cleanup.
 *
 * @param file_path Path to the JSON file to read.
 * @return Pointer to the parsed `json_object`, or NULL on failure.
 *
 * @note All writers must acquire an exclusive lock (`LOCK_EX`) before
 * modifying the file to ensure this function reads consistent data.
 * Readers that bypass locking (e.g., using `json_object_from_file()`)
 * risk reading partial or corrupt data.
 */

static struct json_object *bbfdm_json_object_from_file(const char *file_path)
{
	int fd = open(file_path, O_RDONLY);
	if (fd < 0) {
		BBF_DEBUG("Cannot open file: %s", file_path);
		return NULL;
	}

	// Acquire shared lock
	if (flock(fd, LOCK_SH) < 0) {
		BBF_ERR("Failed to acquire shared lock on: %s", file_path);
		close(fd);
		return NULL;
	}

	// Read file into buffer
	off_t len = lseek(fd, 0, SEEK_END);
	if (len == -1 || lseek(fd, 0, SEEK_SET) == -1) {
		BBF_ERR("Failed to seek in file: %s", file_path);
		close(fd);
		return NULL;
	}

	char *buffer = malloc(len + 1);
	if (!buffer) {
		close(fd);
		return NULL;
	}

	if (read(fd, buffer, len) != len) {
		BBF_ERR("Failed to read file: %s", file_path);
		free(buffer);
		close(fd);
		return NULL;
	}

	buffer[len] = '\0'; // null-terminate

	json_object *jobj = json_tokener_parse(buffer);

	free(buffer);
	close(fd); // releases lock

	return jobj;
}

static char *join_path(const char *prefix, const char *key)
{
	size_t len = strlen(prefix) + strlen(key) + 2; // +1 for dot, +1 for null

	char *buf = dmmalloc(len);
	snprintf(buf, len, "%s%s.", prefix, key);
	return buf;
}

static char *find_path_recursive(json_object *curr, char **parts, int index, int total, const char *target_value, const char *current_path)
{
	if (index >= total || curr == NULL)
		return NULL;

	const char *part = parts[index];

	if (strcmp(part, "*") == 0) {
		json_object_object_foreach(curr, key, val) {
			if (!key || json_object_get_type(val) != json_type_object)
				continue;

			char *new_path = join_path(current_path, key);
			char *res = find_path_recursive(val, parts, index + 1, total, target_value, new_path);
			dmfree(new_path);

			if (res)
				return res;
		}
	} else {
		json_object *next = NULL;

		if (!json_object_object_get_ex(curr, part, &next))
			return NULL;

		if (index == total - 1) {
			if (json_object_get_type(next) == json_type_string &&
					strcmp(json_object_get_string(next), target_value) == 0) {
				char *reference_path = dmstrdup(current_path);
				int len = DM_STRLEN(reference_path);

				if (len > 0 && reference_path[len - 1] == '.')
					reference_path[len - 1] = 0;

				return reference_path;
			}
		} else if (json_object_get_type(next) == json_type_object) {
			char *new_path = join_path(current_path, part);
			char *res = find_path_recursive(next, parts, index + 1, total, target_value, new_path);
			dmfree(new_path);

			if (res)
				return res;
		}
	}

	return NULL;
}

char *bbfdm_resolve_external_reference_via_json(struct dmctx *ctx, const char *linker_path, const char *linker_value)
{
	char file_path[256] = {0};
	char *reference_path = NULL;
	size_t count = 0;

	if (!ctx || DM_STRLEN(linker_path) == 0 || !linker_value)
		return NULL;

	char **parts = strsplit(linker_path, ".", &count);
	if (count < 2)
		return NULL;

	snprintf(file_path, sizeof(file_path), "%s/%s.json", DATA_MODEL_DB_PATH, parts[1]);
	if (strlen(file_path) == 0)
		return NULL;

	json_object *root = bbfdm_json_object_from_file(file_path);
	if (!root)
		return NULL;

	reference_path = find_path_recursive(root, parts, 0, count, linker_value, "");

	json_object_put(root);

	return reference_path;
}

static char *bbfdm_resolve_external_reference_via_dmmap(struct dmctx *ctx, const char *linker_path, const char *linker_name, const char *linker_value)
{
	struct uci_section *dmmap_obj = NULL;
	size_t count = 0;

	if (DM_STRLEN(linker_path) == 0 || DM_STRLEN(linker_name) == 0 || DM_STRLEN(linker_value) == 0)
		return NULL;

	char **parts = strsplit(linker_path, ".", &count);
	if (count < 2)
		return NULL;

	uci_path_foreach_sections(bbfdm, parts[1], parts[count - 1], dmmap_obj) {
		char *curr_value = NULL;

		dmuci_get_value_by_section_string(dmmap_obj, linker_name, &curr_value);
		if (DM_STRCMP(curr_value, linker_value) == 0) {
			char reconstructed_path[1024] = {0};
			char *linker_instance = NULL;
			char *reference_path = NULL;
			char *option_value = NULL;
			int path_offset = 0;

			dmuci_get_value_by_section_string(dmmap_obj, "__instance__", &linker_instance);

			/* Parse linker path to extract instance numbers from instance wildcard if exists
			 * Example: linker path is Device.Bridging.Bridge.*.Port.
			 * We need to replace * with the parent instance number
			 */
			for (size_t i = 0; i < count; i++) {

				if (i > 0 && strcmp(parts[i], "*") == 0) {
					dmuci_get_value_by_section_string(dmmap_obj, parts[i - 1], &option_value);
					path_offset += snprintf(reconstructed_path + path_offset,
							sizeof(reconstructed_path) - path_offset,
							"%s.", option_value);
					continue;
				}

				path_offset += snprintf(reconstructed_path + path_offset,
						sizeof(reconstructed_path) - path_offset,
						"%s.", parts[i]);
			}

			/* Append the final instance number */
			dmasprintf(&reference_path, "%s%s", reconstructed_path, linker_instance);
			return reference_path;
		}
	}

	return NULL;
}

int bbfdm_get_references(struct dmctx *ctx, int match_action, const char *base_path, const char *key_name, char *key_value, char *out, size_t out_len)
{
	char param_path[1024] = {0};
	char *value = NULL;

	if (!out || !out_len) {
		BBF_ERR("Output buffer is NULL or has zero length. A valid buffer with sufficient size is required");
		return -1;
	}

	size_t len = strlen(out);

	if (match_action == MATCH_FIRST && len > 0) // Reference path is already resolved
		return 0;

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

	snprintf(param_path, sizeof(param_path), "%s*.%s", base_path, key_name);

	adm_entry_get_reference_param(ctx, param_path, key_value, &value);

	if (DM_STRLEN(value) != 0) {

		if (out_len - len < strlen(value)) {
			BBF_ERR("Buffer overflow detected. The output buffer is not large enough to hold the additional data!!!");
			return -1;
		}

		snprintf(&out[len], out_len - len, "%s%s", (len > 0) ? "," : "", value);
		return 0;
	}

	char *external_reference = NULL;

	// Try dmmap first
	external_reference = bbfdm_resolve_external_reference_via_dmmap(ctx, base_path, key_name, key_value);

	// Fall back to JSON if dmmap failed
	if (external_reference == NULL)
		external_reference = bbfdm_resolve_external_reference_via_json(ctx, param_path, key_value);

	if (external_reference != NULL) {

		if (out_len - len < strlen(external_reference)) {
			BBF_ERR("Buffer overflow detected. The output buffer is not large enough to hold the additional data!!!");
			return -1;
		}

		snprintf(&out[len], out_len - len, "%s%s", (len > 0) ? "," : "", external_reference);
		return 0;
	}

	return -1;
}

int _bbfdm_get_references(struct dmctx *ctx, const char *base_path, const char *key_name, char *key_value, char **value)
{
	char buf[1024] = {0};

	int res = bbfdm_get_references(ctx, MATCH_FIRST, base_path, key_name, key_value, buf, sizeof(buf));

	*value = (!res) ? dmstrdup(buf): "";

	return res;
}

static json_object *get_node(json_object *root, const char *path)
{
	size_t count = 0;

	if (!root || !path)
		return NULL;

	char **parts = strsplit(path, ".", &count);

	if (count == 0)
		return NULL;

	json_object *curr = root;
	for (int i = 0; i < count; i++) {
		if (!json_object_object_get_ex(curr, parts[i], &curr)) {
			curr = NULL;
			break;
		}
	}
	return curr;
}

static char *construct_section_name_from_path(char **parts, int count)
{
	char section_name[256] = {0};
	int offset = 0;
	int i;

	// Start from index 2 (skip "Device" and top-level like "IP")
	// Build section name: Type_Instance pairs
	// Example: Device.IP.Interface.1.IPv4Address.2 -> Interface_1IPv4Address_2
	for (i = 2; i < count; i++) {
		if (isdigit_str(parts[i])) {
			// This is an instance number, append it with underscore
			offset += snprintf(section_name + offset, sizeof(section_name) - offset, "_%s", parts[i]);
		} else {
			// This is an object type, only append if followed by an index number
			if (i + 1 < count && isdigit_str(parts[i + 1])) {
				offset += snprintf(section_name + offset, sizeof(section_name) - offset, "%s", parts[i]);
			}
		}
	}

	if (offset > 0)
		return dmstrdup(section_name);

	return NULL;
}

int bbfdm_get_reference_linker(struct dmctx *ctx, char *reference_path, struct dm_reference *reference_args)
{
	char file_path[256] = {0};
	size_t count = 0;

	if (!reference_path || !reference_args)
		return -1;

	reference_args->path = reference_path;

	if (DM_STRLEN(reference_args->path) == 0)
		return 0;

	char **parts = strsplit(reference_path, ".", &count);
	if (count < 2)
		return -1;

	// Try to resolve from dmmap first (UCI)
	char *section_name = construct_section_name_from_path(parts, count);

	if (section_name) {
		// Package name is the second level in the path (e.g., "IP" in Device.IP.Interface.1)
		const char *package_name = parts[1];
		char *name_value = NULL;

		// Get the Name option value directly using package name and section name
		int ret = dmuci_get_option_value_string_bbfdm(package_name, section_name, "Name", &name_value);

		if (ret == 0 && DM_STRLEN(name_value) > 0) {
			reference_args->value = dmstrdup(name_value);
			reference_args->is_valid_path = true;
			dmfree(section_name);
			return 0;
		}

		dmfree(section_name);
	}

	// Fallback to JSON resolution
	snprintf(file_path, sizeof(file_path), "%s/%s.json", DATA_MODEL_DB_PATH, parts[1]);
	if (strlen(file_path) == 0)
		return -1;

	json_object *root = bbfdm_json_object_from_file(file_path);
	if (!root)
		return -1;

	json_object *node_obj = get_node(root, reference_path);
	if (node_obj == NULL) {
		reference_args->value = dmstrdup("");
		reference_args->is_valid_path = false;
	} else {
		char *value = NULL;

		json_object_object_foreach(node_obj, key, val) {
			(void)key; // Suppress unused variable warning

			if (json_object_get_type(val) != json_type_string)
				continue;

			value = dmstrdup(json_object_get_string(val));
			break;
		}

		reference_args->value = dmstrdup(value ? value : "");
		reference_args->is_valid_path = true;
	}

	json_object_put(root);
	return 0;
}

int bbfdm_operate_reference_linker(struct dmctx *ctx, const char *reference_path, char **reference_value) //TO be removed
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
