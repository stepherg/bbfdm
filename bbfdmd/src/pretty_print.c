/*
 * pretty_print.c: utils for pretty printing of results
 *
 * Copyright (C) 2020 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#include "common.h"
#include "get_helper.h"
#include "pretty_print.h"

// private function and structures
struct resultstack {
	void *cookie;
	char *key;
	struct list_head list;
};

static bool is_search_by_reference(char *path)
{
	DEBUG("Entry |%s|", path);
	if (match(path, "[+]+")) {
		size_t pindex = 0, bindex = 0;
		char *last_plus, *last_bracket;

		last_bracket = strrchr(path, ']');
		if (!last_bracket)
			return true;

		last_plus = strrchr(path, '+');

		pindex = (size_t)labs(last_plus - path);
		bindex = (size_t)labs(last_bracket - path);

		if (pindex > bindex)
			return true;
	}

	return false;
}

//if matched start will have first match index, end will have end index
static bool is_res_required(char *str, size_t *start, size_t *len)
{

	DEBUG("Entry |%s|", str);
	if (match(str, GLOB_CHAR)) {
		size_t s_len, b_len, p_len;
		char *star, *b_start, *b_end, *plus;
		char temp_char[MAX_DM_KEY_LEN] = {'\0'};

		s_len = DM_STRLEN(str);
		b_len = s_len;
		p_len = s_len;

		star = strchr(str, '*');
		b_start = strchr(str, '[');
		b_end = strchr(str, ']');
		plus = strchr(str, '+');

		if (star)
			s_len = (size_t)labs(star - str);

		if (b_start)
			b_len = (size_t)labs(b_start - str);

		if (plus)
			p_len = (size_t)labs(plus - str);

		*start = MIN(MIN(s_len, p_len), b_len);
		if (*start == s_len) {
			*len = 1;
		} else if (*start == p_len) {
			size_t i = 0, index = 0;

			while ((str+i) != plus) {
				if (str[i] == DELIM)
					index = i;
				++i;
			}
			*start = index+1;
			*len = p_len - index;
		} else {
			*len = (size_t)labs(b_end - b_start);
		}

		// Check if naming with aliases used
		snprintf(temp_char, *len+1, "%s", str + *start);
		if (match(temp_char, GLOB_EXPR))
			return true;

		if (match(temp_char, "[*+]+"))
			return true;
	}
	*start = DM_STRLEN(str);
	return false;
}

static size_t get_glob_len(char *path)
{
	size_t m_index = 0, m_len = 0, ret = 0;
	size_t plen = DM_STRLEN(path);
	char temp_name[MAX_DM_KEY_LEN] = {'\0'};
	char *end = NULL;

	DEBUG("Entry");
	if (is_res_required(path, &m_index, &m_len)) {
		if (m_index <= MAX_DM_KEY_LEN)
			snprintf(temp_name, m_index, "%s", path);
		end = strrchr(temp_name, DELIM);
		if (end != NULL)
			ret = m_index - DM_STRLEN(end);
	} else {
		char name[MAX_DM_KEY_LEN] = {'\0'};

		if (plen == 0)
			return ret;

		if (path[plen - 1] == DELIM) {
			if (plen <= MAX_DM_KEY_LEN)
				snprintf(name, plen, "%s", path);
		} else {
			ret = 1;
			if (plen < MAX_DM_KEY_LEN)
				snprintf(name, plen + 1, "%s", path);
		}
		end = strrchr(name, DELIM);
		if (end == NULL)
			return ret;

		ret = ret + DM_STRLEN(path) - DM_STRLEN(end);
		if (is_node_instance(end+1)) {
			int copy_len = plen - DM_STRLEN(end);
			if (copy_len <= MAX_DM_KEY_LEN)
				snprintf(temp_name, copy_len, "%s", path);

			end = strrchr(temp_name, DELIM);
			if (end != NULL)
				ret = ret - DM_STRLEN(end);
		}
	}
	return(ret);
}

static void resulting(uint8_t maxdepth, char *path, struct dmctx *bbf_ctx, struct list_head *pv_local)
{
	struct dm_parameter *n;
	uint8_t count;

	size_t plen = get_glob_len(bbf_ctx->in_param);
	size_t path_len = DM_STRLEN(path);

	list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
		if (path_len == 0)
			continue;

		if (path[path_len - 1] == DELIM) {
			if (!strncmp(n->name, path, path_len)) {
				if (is_search_by_reference(bbf_ctx->in_param))
					plen = 0;

				if (maxdepth > 4 || maxdepth == 0) {
					add_pv_list(n->name + plen, n->data, n->type, pv_local);
				} else {
					count = count_delim(n->name + path_len);
					if (count < maxdepth)
						add_pv_list(n->name + plen, n->data, n->type, pv_local);
				}
			}
		} else {
			if (!strcmp(n->name, path)) {
				if (is_search_by_reference(bbf_ctx->in_param))
					plen = 0;

				if (maxdepth > 4 || maxdepth == 0) {
					add_pv_list(n->name + plen, n->data, n->type, pv_local);
				} else {
					count = count_delim(n->name + path_len);
					if (count < maxdepth)
						add_pv_list(n->name + plen, n->data, n->type, pv_local);
				}
			}
		}
	}
}

static void add_data_blob(struct blob_buf *bb, char *param, char *value, char *type)
{
	if (param == NULL || value == NULL || type == NULL)
		return;

	DEBUG("# Adding BLOB (%s)::(%s)", param, value);
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
		bb_add_string(bb, param, value);
		break;
	}
}

static void free_result_list(struct list_head *head)
{
	struct resultstack *iter = NULL, *node = NULL;

	list_for_each_entry_safe(iter, node, head, list) {
		free(iter->key);
		list_del(&iter->list);
		free(iter);
	}
}

static void free_result_node(struct resultstack *rnode)
{
	if (rnode) {
		DEBUG("## ResStack DEL(%s)", rnode->key);
		free(rnode->key);
		list_del(&rnode->list);
		free(rnode);
	}
}

static void add_result_node(struct list_head *rlist, char *key, char *cookie)
{
	struct resultstack *rnode = NULL;

	rnode = (struct resultstack *) malloc(sizeof(*rnode));
	if (!rnode) {
		ERR("Out of memory!");
		return;
	}

	rnode->key = (key) ? strdup(key) : strdup("");
	rnode->cookie = cookie;
	DEBUG("## ResSTACK ADD (%s) ##", rnode->key);

	INIT_LIST_HEAD(&rnode->list);
	list_add(&rnode->list, rlist);
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
	char *ptr;
	size_t len;

	if (!path)
		return false;

	len = DM_STRLEN(path);
	ptr = strchr(path, DELIM);
	if (ptr)
		strncpyt(param, path, (size_t)labs(ptr - path) + 1);
	else
		strncpyt(param, path, len + 1);

	return true;
}

static bool is_same_group(char *path, char *group)
{
	return (strncmp(path, group, DM_STRLEN(group)) == 0);
}

static bool add_paths_to_stack(struct blob_buf *bb, char *path, size_t begin,
			       struct pvNode *pv, struct list_head *result_stack)
{
	char key[MAX_DM_KEY_LEN], param[MAX_DM_PATH], *ptr;
	size_t parsed_len = 0;
	void *c;
	char *k;


	ptr = path + begin;
	if (is_leaf_element(ptr)) {
		add_data_blob(bb, ptr, pv->val, pv->type);
		return true;
	}

	while (get_next_element(ptr, key)) {
		parsed_len += DM_STRLEN(key) + 1;
		ptr += DM_STRLEN(key) + 1;
		if (is_leaf_element(ptr)) {
			strncpyt(param, path, begin + parsed_len + 1);
			if (is_node_instance(key))
				c = blobmsg_open_table(bb, NULL);
			else
				c = blobmsg_open_table(bb, key);

			k = param;
			add_result_node(result_stack, k, c);
			add_data_blob(bb, ptr, pv->val, pv->type);
			break;
		}
		strncpyt(param, pv->param, begin + parsed_len + 1);
		if (is_node_instance(ptr))
			c = blobmsg_open_array(bb, key);
		else
			c = blobmsg_open_table(bb, key);

		k = param;
		add_result_node(result_stack, k, c);
	}

	return true;
}

// public functions
void prepare_result_blob(struct blob_buf *bb, struct list_head *pv_list)
{
	char *ptr;
	size_t len;
	struct pvNode *pv;
	struct resultstack *rnode;

	LIST_HEAD(result_stack);

	if (!bb || !pv_list)
		return;

	if (list_empty(pv_list))
		return;

	list_for_each_entry(pv, pv_list, list) {
		ptr = pv->param;
		if (list_empty(&result_stack)) {
			DEBUG("stack empty Processing (%s)", ptr);
			add_paths_to_stack(bb, pv->param, 0, pv, &result_stack);
		} else {
			bool is_done = false;

			while (is_done == false) {
				rnode = list_entry(result_stack.next, struct resultstack, list);
				if (is_same_group(ptr, rnode->key)) {
					len = DM_STRLEN(rnode->key);
					ptr = ptr + len;

					DEBUG("GROUP (%s), ptr(%s), len(%d)", pv->param, ptr, len);
					add_paths_to_stack(bb, pv->param, len, pv, &result_stack);
					is_done = true;
				} else {
					// Get the latest entry before deleting it
					DEBUG("DIFF GROUP pv(%s), param(%s)", pv->param, ptr);
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

	// Close the stack entry if left
	list_for_each_entry(rnode, &result_stack, list) {
		blobmsg_close_table(bb, rnode->cookie);
	}
	free_result_list(&result_stack);
}

void prepare_pretty_result(uint8_t maxdepth, struct blob_buf *bb, struct dmctx *bbf_ctx)
{
	LIST_HEAD(pv_local);

	resulting(maxdepth, bbf_ctx->in_param, bbf_ctx, &pv_local);

	prepare_result_blob(bb, &pv_local);

	free_pv_list(&pv_local);
}
