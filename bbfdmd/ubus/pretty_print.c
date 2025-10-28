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

#include <sys/param.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>

#include "common.h"

#define MAX_KEY_LENGTH 256
#define DELIM '.'
#define GLOB_CHAR "[*]+"

struct pvNode {
	char *param;
	char *val;
	char *type;
	struct list_head list;
};

struct resultstack {
	void *cookie;
	char *key;
	struct list_head list;
};

enum dmt_type_enum {
	DMT_STRING,
	DMT_UNINT,
	DMT_INT,
	DMT_UNLONG,
	DMT_LONG,
	DMT_BOOL,
	DMT_TIME,
	DMT_HEXBIN,
	DMT_BASE64,
	DMT_COMMAND,
	DMT_EVENT,
	__DMT_INVALID
};

static void add_pv_list(const char *para, const char *val, const char *type, struct list_head *pv_list)
{
	struct pvNode *node = NULL;

	node = (struct pvNode *)calloc(1, sizeof(*node));

	if (!node) {
		BBFDM_ERR("Out of memory!");
		return;
	}

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, pv_list);

	node->param = (para) ? strdup(para) : strdup("");
	node->val = (val) ? strdup(val) : strdup("");
	node->type = (type) ? strdup(type) : strdup("");
}

static void free_pv_list(struct list_head *pv_list)
{
	struct pvNode *iter = NULL, *node = NULL;

	list_for_each_entry_safe(iter, node, pv_list, list) {
		BBFDM_FREE(iter->param);
		BBFDM_FREE(iter->val);
		BBFDM_FREE(iter->type);

		list_del(&iter->list);
		BBFDM_FREE(iter);
	}
}

static bool is_node_instance(const char *path)
{
	if (!path)
		return false;

	if (strtol(path, NULL, 10))
		return true;

	return false;
}

static int count_consecutive_digits(char *p)
{
	int num_digits = 0;
	char c;

	if (!p)
		return 0;

	c = *p++;
	while ((c >= '0') && (c <= 9)) {
		num_digits++;
		c = *p++;
	}

	return num_digits;
}

static int compare_path(const void *arg1, const void *arg2)
{
	const struct pvNode *pv1 = (const struct pvNode *)arg1;
	const struct pvNode *pv2 = (const struct pvNode *)arg2;

	char *s1 = pv1->param;
	char *s2 = pv2->param;

	char c1, c2;
	int num_digits_s1;
	int num_digits_s2;
	int delta;

	// Skip all characters which are the same
	while (true) {
		c1 = *s1;
		c2 = *s2;

		// Exit if reached the end of either string
		if ((c1 == '\0') || (c2 == '\0')) {
			// NOTE: The following comparision puts s1 before s2, if s1 terminates before s2 (and vice versa)
			return (int)c1 - (int)c2;
		}

		// Exit if the characters do not match
		if (c1 != c2) {
			break;
		}

		// As characters match, move to next characters
		s1++;
		s2++;
	}

	// If the code gets here, then we have reached a character which is different
	// Determine the number of digits in the rest of the string (this may be 0 if the first character is not a digit)
	num_digits_s1 = count_consecutive_digits(s1);
	num_digits_s2 = count_consecutive_digits(s2);

	// Determine if the number of digits in s1 is greater than in s2 (if so, s1 comes after s2)
	delta = num_digits_s1 - num_digits_s2;
	if (delta != 0) {
		return delta;
	}

	// If the code gets here, then the strings contain either no digits, or the same number of digits,
	// so just compare the characters (this also works if the characters are digits)
	return (int)c1 - (int)c2;
}

static struct pvNode *sort_pv_path(struct list_head *pv_list, size_t pv_count)
{
	if (!pv_list || pv_count == 0)
		return NULL;

	if (list_empty(pv_list))
		return NULL;

	struct pvNode *arr = (struct pvNode *)calloc(pv_count, sizeof(struct pvNode));
	if (arr == NULL)
		return NULL;

	struct pvNode *pv = NULL;
	size_t i = 0;

	list_for_each_entry(pv, pv_list, list) {
		if (i == pv_count)
			break;

		memcpy(&arr[i], pv, sizeof(struct pvNode));
		i++;
	}

	qsort(arr, pv_count, sizeof(struct pvNode), compare_path);

	return arr;
}

static bool is_leaf_element(char *path)
{
	char *ptr = NULL;

	if (!path)
		return true;

	ptr = strchr(path, DELIM);

	return (ptr == NULL);
}

static bool get_next_element(char *path, char *param)
{
	char *ptr = NULL;
	size_t len = 0;

	if (!path)
		return false;

	len = strlen(path);
	ptr = strchr(path, DELIM);
	if (ptr)
		bbfdm_strncpy(param, path, (size_t)labs(ptr - path) + 1);
	else
		bbfdm_strncpy(param, path, len + 1);

	return true;
}

static bool is_same_group(char *path, char *group)
{
	return (strncmp(path, group, strlen(group)) == 0);
}

static int get_dm_type(char *dm_type)
{
	if (dm_type == NULL)
		return DMT_STRING;

	if (strcmp(dm_type, "xsd:string") == 0)
		return DMT_STRING;
	else if (strcmp(dm_type, "xsd:unsignedInt") == 0)
		return DMT_UNINT;
	else if (strcmp(dm_type, "xsd:int") == 0)
		return DMT_INT;
	else if (strcmp(dm_type, "xsd:unsignedLong") == 0)
		return DMT_UNLONG;
	else if (strcmp(dm_type, "xsd:long") == 0)
		return DMT_LONG;
	else if (strcmp(dm_type, "xsd:boolean") == 0)
		return DMT_BOOL;
	else if (strcmp(dm_type, "xsd:dateTime") == 0)
		return DMT_TIME;
	else if (strcmp(dm_type, "xsd:hexBinary") == 0)
		return DMT_HEXBIN;
	else if (strcmp(dm_type, "xsd:base64") == 0)
		return DMT_BASE64;
	else if (strcmp(dm_type, "xsd:command") == 0)
		return DMT_COMMAND;
	else if (strcmp(dm_type, "xsd:event") == 0)
		return DMT_EVENT;
	else
		return DMT_STRING;

	return DMT_STRING;
}

bool get_boolean_string(char *value)
{
	if (!value)
		return false;

	if (strncasecmp(value, "true", 4) == 0 ||
	    value[0] == '1' ||
	    strncasecmp(value, "on", 2) == 0 ||
	    strncasecmp(value, "yes", 3) == 0 ||
	    strncasecmp(value, "enabled", 7) == 0)
		return true;

	return false;
}

static void add_data_blob(struct blob_buf *bb, char *param, char *value, char *type)
{
	if (param == NULL || value == NULL || type == NULL)
		return;

	switch (get_dm_type(type)) {
	case DMT_UNINT:
		blobmsg_add_u64(bb, param, (uint32_t)strtoul(value, NULL, 10));
		break;
	case DMT_INT:
		blobmsg_add_u32(bb, param, (int)strtol(value, NULL, 10));
		break;
	case DMT_LONG:
		blobmsg_add_u64(bb, param, strtoll(value, NULL, 10));
		break;
	case DMT_UNLONG:
		blobmsg_add_u64(bb, param, (uint64_t)strtoull(value, NULL, 10));
		break;
	case DMT_BOOL:
		if (get_boolean_string(value))
			blobmsg_add_u8(bb, param, true);
		else
			blobmsg_add_u8(bb, param, false);
		break;
	default: //"xsd:hexbin" "xsd:dateTime" "xsd:string"
		blobmsg_add_string(bb, param, value);
		break;
	}
}

static void add_result_node(struct list_head *rlist, char *key, char *cookie)
{
	struct resultstack *rnode = NULL;

	rnode = (struct resultstack *)calloc(1, sizeof(*rnode));
	if (!rnode) {
		BBFDM_ERR("Out of memory!");
		return;
	}

	INIT_LIST_HEAD(&rnode->list);
	list_add(&rnode->list, rlist);

	rnode->key = (key) ? strdup(key) : strdup("");
	rnode->cookie = cookie;
}

static void free_result_node(struct resultstack *rnode)
{
	if (rnode) {
		BBFDM_FREE(rnode->key);

		list_del(&rnode->list);
		BBFDM_FREE(rnode);
	}
}

static void free_result_list(struct list_head *head)
{
	struct resultstack *iter = NULL, *node = NULL;

	list_for_each_entry_safe(iter, node, head, list) {
		BBFDM_FREE(iter->key);

		list_del(&iter->list);
		BBFDM_FREE(iter);
	}
}

static bool add_paths_to_stack(struct blob_buf *bb, char *path, size_t begin,
			       struct pvNode *pv, struct list_head *result_stack)
{
	char key[MAX_KEY_LENGTH], param[MAX_PATH_LENGTH], *ptr;
	size_t parsed_len = 0;
	void *c;
	char *k;

	ptr = path + begin;
	if (is_leaf_element(ptr)) {
		add_data_blob(bb, ptr, pv->val, pv->type);
		return true;
	}

	while (get_next_element(ptr, key)) {
		parsed_len += strlen(key) + 1;
		ptr += strlen(key) + 1;
		if (is_leaf_element(ptr)) {
			bbfdm_strncpy(param, path, begin + parsed_len + 1);
			if (is_node_instance(key))
				c = blobmsg_open_table(bb, NULL);
			else
				c = blobmsg_open_table(bb, key);

			k = param;
			add_result_node(result_stack, k, c);
			add_data_blob(bb, ptr, pv->val, pv->type);
			break;
		}
		bbfdm_strncpy(param, pv->param, begin + parsed_len + 1);
		if (is_node_instance(ptr))
			c = blobmsg_open_array(bb, key);
		else
			c = blobmsg_open_table(bb, key);

		k = param;
		add_result_node(result_stack, k, c);
	}

	return true;
}

static size_t list_length(struct list_head *head)
{
	struct list_head *pos;
	size_t count = 0;

	list_for_each(pos, head) {
		count++;
	}

	return count;
}

static void prepare_result_blob(struct blob_buf *bb, struct list_head *pv_list)
{
	struct resultstack *rnode = NULL;
	size_t pv_count = 0;

	if (!bb || !pv_list)
		return;

	if (list_empty(pv_list))
		return;

	pv_count = list_length(pv_list);

	struct pvNode *sortedPV = sort_pv_path(pv_list, pv_count);
	if (sortedPV == NULL)
		return;

	LIST_HEAD(result_stack);

	for (size_t i = 0; i < pv_count; i++) {
		struct pvNode *pv = &sortedPV[i];
		char *ptr = pv->param;
		if (list_empty(&result_stack)) {
			BBFDM_DEBUG("stack empty Processing (%s)", ptr);
			add_paths_to_stack(bb, pv->param, 0, pv, &result_stack);
		} else {
			bool is_done = false;

			while (is_done == false) {
				rnode = list_entry(result_stack.next, struct resultstack, list);
				if (is_same_group(ptr, rnode->key)) {
					size_t len = strlen(rnode->key);
					ptr = ptr + len;

					BBFDM_DEBUG("GROUP (%s), ptr(%s), len(%zu)", pv->param, ptr, len);
					add_paths_to_stack(bb, pv->param, len, pv, &result_stack);
					is_done = true;
				} else {
					// Get the latest entry before deleting it
					BBFDM_DEBUG("DIFF GROUP pv(%s), param(%s)", pv->param, ptr);
					blobmsg_close_table(bb, rnode->cookie);
					free_result_node(rnode);
					if (list_empty(&result_stack)) {
						add_paths_to_stack(bb, pv->param, 0, pv, &result_stack);
						is_done = true;
					}
				}
			}
		}
	}

	BBFDM_FREE(sortedPV);

	// Close the stack entry if left
	list_for_each_entry(rnode, &result_stack, list) {
		blobmsg_close_table(bb, rnode->cookie);
	}

	free_result_list(&result_stack);
}

static bool is_res_required(const char *str, size_t s_len, size_t *start, size_t *len)
{
	if (str_match(str, GLOB_CHAR, 0, NULL)) {
		char *star = strchr(str, '*');

		*start = (star) ? (size_t)labs(star - str) : s_len;
		*len = 1;
		return true;
	}

	*start = s_len;
	return false;
}

static size_t get_glob_len(const char *path)
{
	char temp_name[MAX_KEY_LENGTH] = {'\0'};
	char *end = NULL;
	size_t m_index = 0, m_len = 0, ret = 0;
	size_t plen = strlen(path);

	if (is_res_required(path, plen, &m_index, &m_len)) {
		if (m_index <= MAX_KEY_LENGTH)
			snprintf(temp_name, m_index, "%s", path);

		end = strrchr(temp_name, DELIM);
		if (end != NULL)
			ret = m_index - strlen(end);
	} else {
		char name[MAX_KEY_LENGTH] = {'\0'};

		if (plen == 0)
			return ret;

		if (path[plen - 1] == DELIM) {
			if (plen <= MAX_KEY_LENGTH)
				snprintf(name, plen, "%s", path);
		} else {
			ret = 1;
			if (plen < MAX_KEY_LENGTH)
				snprintf(name, plen + 1, "%s", path);
		}

		end = strrchr(name, DELIM);
		if (end == NULL)
			return ret;

		ret = ret + strlen(path) - strlen(end);

		if (is_node_instance(end + 1)) {
			int copy_len = plen - strlen(end);
			if (copy_len <= MAX_KEY_LENGTH)
				snprintf(temp_name, copy_len, "%s", path);
			end = strrchr(temp_name, DELIM);
			if (end != NULL)
				ret = ret - strlen(end);
		}
	}

	return(ret);
}

void prepare_pretty_response(const char *path, struct blob_attr *msg, struct blob_buf *bb_pretty)
{
	struct blob_attr *cur = NULL;
	size_t rem = 0;

	if (!path || !msg || !bb_pretty)
		return;

	struct blob_attr *raw_attr = get_results_array(msg);
	if (!raw_attr)
		return;

	LIST_HEAD(pv_local);

	size_t plen = get_glob_len(path);

	blobmsg_for_each_attr(cur, raw_attr, rem) {
		struct blob_attr *tb[4] = {0};
		const struct blobmsg_policy p[4] = {
				{ "path", BLOBMSG_TYPE_STRING },
				{ "data", BLOBMSG_TYPE_STRING },
				{ "type", BLOBMSG_TYPE_STRING },
				{ "fault", BLOBMSG_TYPE_INT32 },
		};

		blobmsg_parse(p, 4, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (tb[3]) {
			blobmsg_add_blob(bb_pretty, cur);
			return;
		}

		char *name = tb[0] ? blobmsg_get_string(tb[0]) : "";
		char *data = tb[1] ? blobmsg_get_string(tb[1]) : "";
		char *type = tb[2] ? blobmsg_get_string(tb[2]) : "";

		add_pv_list(name + plen, data, type, &pv_local);
	}

	prepare_result_blob(bb_pretty, &pv_local);

	free_pv_list(&pv_local);
}

