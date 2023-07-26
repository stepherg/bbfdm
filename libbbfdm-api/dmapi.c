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

int bbf_uci_add_section(char *package, char *type, struct uci_section **s)
{
	return dmuci_add_section(package, type, s);
}

int bbf_uci_delete_section(char *package, char *type, char *option, char *value)
{
	return dmuci_delete(package, type, option, value);
}

int bbf_uci_add_section_bbfdm(char *package, char *type, struct uci_section **s)
{
	return dmuci_add_section_bbfdm(package, type, s);
}

int bbf_uci_delete_section_bbfdm(char *package, char *type, char *option, char *value)
{
	return dmuci_delete_bbfdm(package, type, option, value);
}

int bbf_uci_rename_section(struct uci_section *s, char *value)
{
	return dmuci_rename_section_by_section(s, value);
}

int bbf_uci_get_value(char *package, char *section, char *option, char **value)
{
	return dmuci_get_option_value_string(package, section, option, value);
}

int bbf_uci_set_value(char *package, char *section, char *option, char *value)
{
	return dmuci_set_value(package, section, option, value);
}

int bbf_uci_get_value_by_section(struct uci_section *s, char *option, char **value)
{
	return dmuci_get_value_by_section_string(s, option, value);
}

char *bbf_uci_get_value_by_section_fallback_def(struct uci_section *s, char *option, char *default_value)
{
	return dmuci_get_value_by_section_fallback_def(s, option, default_value);
}

int bbf_uci_set_value_by_section(struct uci_section *s, char *option, char *value)
{
	return dmuci_set_value_by_section(s, option, value);
}

int bbf_uci_delete_section_by_section(struct uci_section *s, char *option, char *value)
{
	return dmuci_delete_by_section(s, option, value);
}

struct uci_section *bbf_uci_walk_section(char *package, char *type, void *arg1, void *arg2, int cmp, int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk)
{
	return dmuci_walk_section(package, type, arg1, arg2, cmp, filter, prev_section, walk);

}


/**
 *
 * BBF UBUS API
 *
 */

int bbf_ubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	return dmubus_call(obj, method, u_args, u_args_size, req_res);
}

int bbf_ubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size)
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

void bbf_synchronise_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list)
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

int bbf_convert_string_to_bool(char *str, bool *b)
{
	return string_to_bool(str, b);
}

void bbf_find_dmmap_section(char *dmmap_package, char *section_type, char *section_name, struct uci_section **dmmap_section)
{
	return get_dmmap_section_of_config_section(dmmap_package, section_type, section_name, dmmap_section);
}

void bbf_find_dmmap_section_by_option(char *dmmap_package, char *section_type, char *option_name, char *option_value, struct uci_section **dmmap_section)
{
	return get_dmmap_section_of_config_section_eq(dmmap_package, section_type, option_name, option_value, dmmap_section);
}

__attribute__ ((deprecated)) int bbf_validate_string(char *value, int min_length, int max_length, char *enumeration[], char *pattern[])
{
	struct dmctx ctx = {0};

	return bbfdm_validate_string(&ctx, value, min_length, max_length, enumeration, pattern);
}

__attribute__ ((deprecated)) int bbf_validate_boolean(char *value)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_boolean(&ctx, value);
}

__attribute__ ((deprecated)) int bbf_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_unsignedInt(&ctx, value, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_int(char *value, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_int(&ctx, value, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_unsignedLong(&ctx, value, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_long(char *value, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_long(&ctx, value, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_dateTime(char *value)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_dateTime(&ctx, value);
}

__attribute__ ((deprecated)) int bbf_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_hexBinary(&ctx, value, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])
{
	struct dmctx ctx = {0};

	return bbfdm_validate_string_list(&ctx, value, min_item,max_item, max_size, min, max, enumeration, pattern);
}

__attribute__ ((deprecated)) int bbf_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_unsignedInt_list(&ctx, value, min_item, max_item, max_size, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_int_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_int_list(&ctx, value, min_item, max_item, max_size, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_unsignedLong_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_unsignedLong_list(&ctx, value, min_item, max_item, max_size, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_long_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_long_list(&ctx, value, min_item, max_item, max_size, r_args, r_args_size);
}

__attribute__ ((deprecated)) int bbf_validate_hexBinary_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)
{
	struct dmctx ctx = {0};

	return bbfdm_validate_hexBinary_list(&ctx, value, min_item, max_item, max_size, r_args, r_args_size);
}
