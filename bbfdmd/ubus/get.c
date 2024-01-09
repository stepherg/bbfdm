/*
 * get.c: Get handler for bbfdmd
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "get.h"
#include "get_helper.h"
#include "pretty_print.h"

#include <libubus.h>

enum operation {
	OPER_EQUAL_EQUAL,
	OPER_NOT_EQUAL,
	OPER_LESS_THAN_EQUAL,
	OPER_GREATER_THAN_EQUAL,
	OPER_LESS_THAN,
	OPER_GREATER_THAN,
};

static const char * const operations[] = {
	[OPER_EQUAL_EQUAL] = "==",
	[OPER_NOT_EQUAL] = "!=",
	[OPER_LESS_THAN_EQUAL] = "<=",
	[OPER_GREATER_THAN_EQUAL] = ">=",
	[OPER_LESS_THAN] = "<",
	[OPER_GREATER_THAN] = ">"
};

static bool get_base_path(const char *query_path, char *base_path)
{
	size_t i, j, qlen;
	bool found = false;
	char ch;

	if (base_path == NULL)
		return false;

	base_path[0] = '\0';

	if (strncmp(query_path, ROOT_NODE, strlen(ROOT_NODE)) != 0)
		return false;

	qlen = DM_STRLEN(query_path);

	for (i = 0; i < qlen; i++) {
		switch (query_path[i]) {
		case '[':
			if (query_path[i - 1] != '.')
				return false;

			for (j = i + 1; j < qlen; j++) {
				ch = query_path[j];
				if ((ch == '>') ||
				    (ch == '<') ||
				    (ch == '=')) {
					found = true;
					break;
				}
				if (query_path[j] == ']') {
					i = j;
					break;
				}
			}
			break;
		}

		if (found)
			break;
	}

	strncpyt(base_path, query_path, i + 1);
	return true;
}

static bool get_next_param(char *qPath, size_t *pos, char *param)
{
	size_t qlen, i;
	bool found;

	if (qPath == NULL || pos == NULL || param == NULL)
		return false;

	qlen = DM_STRLEN(qPath);
	if (*pos >= qlen || *pos >= MAX_DM_PATH || qlen >= MAX_DM_PATH)
		return false;

	param[0] = '\0';
	found = false;
	for (i = *pos; i < qlen; i++) {
		switch (qPath[i]) {
		case '[':
			while (i < qlen) {
				if (qPath[++i] == ']')
					break;
			}
			if (qPath[++i] != '.') {
				ERR("No dot after search parameters");
				return false;
			}
			// skip the dot
			i++;
			found = true;
			break;
		case '.':
			i++;
			found = true;
			break;
		}

		if (found)
			break;
	}

	if (i == qlen)
		strncpyt(param, qPath + *pos, i - *pos + 1);
	else
		strncpyt(param, qPath + *pos, i - *pos);

	*pos = i;

	// removing last . from param
	qlen = DM_STRLEN(param);
	if (qlen > 0) {
		if (param[qlen - 1] == '.')
			param[qlen - 1] = '\0';
	}

	return true;
}

static bool is_present_in_datamodel(struct dmctx *bbf_ctx, char *path)
{
	bool found = false;
	struct dm_parameter *n;
	size_t plen;

	DEBUG("path(%s)", path);
	plen = DM_STRLEN(path);
	list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
		if (strncmp(n->name, path, plen) == 0) {
			found = true;
			break;
		}
	}

	return found;
}

static int seperator(char *token, char *para, enum operation *oper, char *value)
{
	char *ptr;
	size_t plen;
	bool found;
	uint8_t i, op_count;

	// handle ==, !=, <=, >=
	if (token == NULL || para == NULL ||
	    oper == NULL || value == NULL)
		return USP_FAULT_INTERNAL_ERROR;

	found = false;
	op_count = ARRAY_SIZE(operations);
	for (i = 0; i < op_count; i++) {
		ptr = strstr(token, operations[i]);
		if (ptr) {
			*oper = i;
			plen = (size_t)labs(ptr - token);
			ptr += DM_STRLEN(operations[i]);
			found = true;
			break;
		}
	}

	if (found) {
		strncpyt(para, token, plen + 1);
		plen = DM_STRLEN(ptr);
		strncpyt(value, ptr, plen + 1);
		return 0;
	}

	return USP_FAULT_INVALID_PATH_SYNTAX;
}

static bool get_instance(char *path, size_t start, char *instance)
{
	char *ptr;
	size_t plen, path_len;

	if (instance == NULL)
		return false;

	path_len = DM_STRLEN(path);
	if (path_len <= start)
		return false;

	ptr = strchr(path + start, '.');

	if (ptr == NULL)
		return false;

	plen = (size_t)labs(ptr - path) - start;
	if (plen > path_len)
		return false;

	strncpyt(instance, path + start, plen + 1);
	if (strtol(instance, NULL, 10) == 0) {
		if (instance[0] != '[')
			return false;
	}

	return true;
}

static void handle_special_escape_sequence(char *value, char *buff, size_t buff_len)
{
	size_t i, len, j;

	if (buff == NULL)
		return;

	len = DM_STRLEN(value);
	j = 0;
	for (i = 0; i < len && j < buff_len-1; ++i) {
		if (value[i] == '%' && len > i + 2) {
			if (value[i + 1] == '2') {
				if (value[i + 2] == '5') {
					buff[j++] = '%';
					i += 2;
					continue;
				} else if (value[i + 2] == '2') {
					buff[j++] = '"';
					i += 2;
					continue;
				}
			}
		}
		buff[j++] = value[i];
	}
	buff[j] = '\0';

	DEBUG("value(%s), new_value(%s)", value, buff);
}

static bool handle_string(char *v1, char *v2, enum operation op, int *fault)
{
	char temp[MAX_DM_VALUE];

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL) {
		return false;
	}

	int v2_len = DM_STRLEN(v2);
	if (v2_len == 0) {
		*fault = USP_FAULT_INVALID_PATH_SYNTAX;
		return false;
	}

	if (v2[0] != '"' || v2[v2_len - 1] != '"') {
		*fault = USP_FAULT_INVALID_PATH_SYNTAX;
		return false;
	}

	// Check for %22 and %25 special escape sequences
	char buff[MAX_DM_VALUE] = {0};
	handle_special_escape_sequence(v2, buff, MAX_DM_VALUE);

	snprintf(temp, MAX_DM_VALUE, "\"%s\"", v1);
	switch (op) {
	case OPER_EQUAL_EQUAL:
		return !strcmp(temp, buff);
	case OPER_NOT_EQUAL:
		return !!strcmp(temp, buff);
	case OPER_LESS_THAN:
	case OPER_GREATER_THAN:
	case OPER_LESS_THAN_EQUAL:
	case OPER_GREATER_THAN_EQUAL:
		*fault = USP_FAULT_INVALID_PATH_SYNTAX;
		return false;
	}

	return false;
}

static bool handle_uint(char *v1, char *v2, enum operation op, int *fault)
{
	uint32_t ui1, ui2;

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL)
		return false;

	ui1 = (uint32_t) strtoul(v1, NULL, 10);
	ui2 = (uint32_t) strtoul(v2, NULL, 10);

	if ((ui1 == 0 && v1[0] != '0') ||
	    (ui2 == 0 && v2[0] != '0')) {
		*fault = USP_FAULT_INVALID_TYPE;
		return false;
	}

	switch (op) {
	case OPER_EQUAL_EQUAL:
		return (ui1 == ui2);
	case OPER_NOT_EQUAL:
		return (ui1 != ui2);
	case OPER_LESS_THAN:
		return (ui1 < ui2);
	case OPER_GREATER_THAN:
		return (ui1 > ui2);
	case OPER_LESS_THAN_EQUAL:
		return (ui1 <= ui2);
	case OPER_GREATER_THAN_EQUAL:
		return (ui1 >= ui2);
	}

	return false;
}

static bool handle_int(char *v1, char *v2, enum operation op, int *fault)
{
	int32_t i1, i2;

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL)
		return false;

	i1 = (int32_t) strtol(v1, NULL, 10);
	i2 = (int32_t) strtol(v2, NULL, 10);

	if ((i1 == 0 && v1[0] != '0') ||
	    (i2 == 0 && v2[0] != '0')) {
		*fault = USP_FAULT_INVALID_TYPE;
		return false;
	}

	switch (op) {
	case OPER_EQUAL_EQUAL:
		return (i1 == i2);
	case OPER_NOT_EQUAL:
		return (i1 != i2);
	case OPER_LESS_THAN:
		return (i1 < i2);
	case OPER_GREATER_THAN:
		return (i1 > i2);
	case OPER_LESS_THAN_EQUAL:
		return (i1 <= i2);
	case OPER_GREATER_THAN_EQUAL:
		return (i1 >= i2);
	}

	return false;
}

static bool handle_unlong(char *v1, char *v2, enum operation op, int *fault)
{
	uint64_t ul1, ul2;

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL)
		return false;

	ul1 = (uint64_t) strtoll(v1, NULL, 10);
	ul2 = (uint64_t) strtoll(v2, NULL, 10);

	if ((ul1 == 0 && v1[0] != '0') ||
	    (ul2 == 0 && v2[0] != '0')) {
		*fault = USP_FAULT_INVALID_TYPE;
		return false;
	}

	switch (op) {
	case OPER_EQUAL_EQUAL:
		return (ul1 == ul2);
	case OPER_NOT_EQUAL:
		return (ul1 != ul2);
	case OPER_LESS_THAN:
		return (ul1 < ul2);
	case OPER_GREATER_THAN:
		return (ul1 > ul2);
	case OPER_LESS_THAN_EQUAL:
		return (ul1 <= ul2);
	case OPER_GREATER_THAN_EQUAL:
		return (ul1 >= ul2);
	}

	return false;
}

static bool handle_long(char *v1, char *v2, enum operation op, int *fault)
{
	int64_t l1, l2;

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL)
		return false;

	l1 = (int64_t) strtoll(v1, NULL, 10);
	l2 = (int64_t) strtoll(v2, NULL, 10);

	if ((l1 == 0 && v1[0] != '0') ||
	    (l2 == 0 && v2[0] != '0')) {
		*fault = USP_FAULT_INVALID_TYPE;
		return false;
	}

	switch (op) {
	case OPER_EQUAL_EQUAL:
		return (l1 == l2);
	case OPER_NOT_EQUAL:
		return (l1 != l2);
	case OPER_LESS_THAN:
		return (l1 < l2);
	case OPER_GREATER_THAN:
		return (l1 > l2);
	case OPER_LESS_THAN_EQUAL:
		return (l1 <= l2);
	case OPER_GREATER_THAN_EQUAL:
		return (l1 >= l2);
	}

	return false;
}

static bool handle_bool(char *v1, char *v2, enum operation op, int *fault)
{
	bool vb1, vb2;

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL)
		return false;

	vb1 = get_boolean_string(v1);
	vb2 = get_boolean_string(v2);

	switch (op) {
	case OPER_EQUAL_EQUAL:
		return (vb1 == vb2);
	case OPER_NOT_EQUAL:
		return (vb1 != vb2);
	case OPER_LESS_THAN:
	case OPER_GREATER_THAN:
	case OPER_LESS_THAN_EQUAL:
	case OPER_GREATER_THAN_EQUAL:
		*fault = USP_FAULT_INVALID_PATH_SYNTAX;
		return false;
	}

	return false;
}

static bool handle_time(char *v1, char *v2, enum operation op, const int *fault)
{
	struct tm tm1, tm2;
	char *tmp;
	time_t t1, t2;
	double sec;

	if (!fault)
		return false;

	if (v1 == NULL || v2 == NULL)
		return false;

	memset(&tm1, 0, sizeof(t1));
	memset(&tm2, 0, sizeof(t2));

	tmp = strptime(v1, "%Y-%m-%dT%H:%M:%S", &tm1);
	if (tmp == NULL)
		return USP_FAULT_INVALID_TYPE;

	tmp = strptime(v2, "%Y-%m-%dT%H:%M:%S", &tm2);
	if (tmp == NULL)
		return USP_FAULT_INVALID_TYPE;

	t1 = timegm(&tm1);
	t2 = timegm(&tm2);

	sec = difftime(t1, t2);
	switch (op) {
	case OPER_EQUAL_EQUAL:
		return (sec == 0);
	case OPER_NOT_EQUAL:
		return (sec != 0);
	case OPER_LESS_THAN:
		return (sec < 0);
	case OPER_GREATER_THAN:
		return (sec > 0);
	case OPER_LESS_THAN_EQUAL:
		return (sec <= 0);
	case OPER_GREATER_THAN_EQUAL:
		return (sec >= 0);
	}

	return false;
}

static bool handle_hexbin(const char *v1, const char *v2, enum operation op __attribute__((unused)),
			  int *fault)
{
	if (v1 == NULL || v2 == NULL)
		return false;

	*fault = USP_FAULT_INVALID_PATH_SYNTAX;
	return false;
}

static bool check_values(char *val_type, char *val1, char *val2, enum operation oper, int *fault)
{
	bool result = false;

	DEBUG("type(%s), val1(%s), Val2(%s), Oper(%d)", val_type, val1, val2, oper);
	switch (get_dm_type(val_type)) {
	case DMT_STRING:
		result = handle_string(val1, val2, oper, fault);
		break;
	case DMT_UNINT:
		result = handle_uint(val1, val2, oper, fault);
		break;
	case DMT_INT:
		result = handle_int(val1, val2, oper, fault);
		break;
	case DMT_UNLONG:
		result = handle_unlong(val1, val2, oper, fault);
		break;
	case DMT_LONG:
		result = handle_long(val1, val2, oper, fault);
		break;
	case DMT_BOOL:
		result = handle_bool(val1, val2, oper, fault);
		break;
	case DMT_TIME:
		result = handle_time(val1, val2, oper, fault);
		break;
	case DMT_HEXBIN:
		result = handle_hexbin(val1, val2, oper, fault);
		break;
	}

	return result;
}

static int search_n_apply(char *bPath, char *para, enum operation oper, char *value, struct list_head *fltrd, struct list_head *resolved_plist)
{
	char temp[MAX_DM_PATH * 2] = {0};
	struct pvNode *pv = NULL;
	size_t blen;
	int fault = 0;

	blen = DM_STRLEN(bPath);

	if (!list_empty(resolved_plist)) {
		struct pathNode *iter, *node;

		list_for_each_entry_safe(iter, node, resolved_plist, list) {
			bool is_present = false;

			snprintf(temp, sizeof(temp), "%s%s", iter->path, para);

			list_for_each_entry(pv, fltrd, list) {
				if (strcmp(pv->param, temp) == 0) {
					is_present = true;
					break;
				}
			}

			if (!is_present) {
				list_del(&iter->list);
				free(iter);
				continue;
			}

			if (check_values(pv->type, pv->val, value, oper, &fault) == false) {
				list_del(&iter->list);
				free(iter);
				if (fault != 0)
					return fault;
			}
		}
	} else {
		list_for_each_entry(pv, fltrd, list) {
			char inst[MAX_DM_KEY_LEN];

			if (strncmp(pv->param, bPath, blen) != 0)
				continue;

			if (get_instance(pv->param, blen, inst) == false)
				continue;

			snprintf(temp, sizeof(temp), "%s%s.%s", bPath, inst, para);

			if (strcmp(pv->param, temp) != 0)
				continue;

			if (check_values(pv->type, pv->val, value, oper, &fault)) {
				snprintf(temp, sizeof(temp), "%s%s.", bPath, inst);
				add_path_list(temp, resolved_plist); // Resolved List
			} else {
				if (fault)
					return fault;
			}
		}
	}

	return fault;
}

static int solve_all_filters(struct dmctx *bbf_ctx, char *bPath, char *param, struct list_head *resolved_plist)
{
	char *token, *save;
	struct dm_parameter *n;
	size_t blen;
	int ret = 0;

	LIST_HEAD(pv_local);
	LIST_HEAD(plist_local);

	INFO("## Basepath(%s), param(%s)", bPath, param);

	// Use shorter list for rest of the operation
	blen = DM_STRLEN(bPath);
	list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
		if (strncmp(n->name, bPath, blen) == 0) {
			add_pv_list(n->name, n->data, n->type, &pv_local);
		}
	}

	token = strtok_r(param, "&&", &save);
	while (token) {
		enum operation oper;
		char para[MAX_DM_KEY_LEN] = {0};
		char value[MAX_DM_VALUE] = {0};

		ret = seperator(token, para, &oper, value);
		if (ret != 0)
			break;

		INFO("Filter Para(%s), oper(%d), Val(%s)", para, oper, value);

		if (match(para, "[*]+", 0, NULL))
			ret = USP_FAULT_INVALID_TYPE;
		else
			ret = search_n_apply(bPath, para, oper, value, &pv_local, &plist_local);

		if (ret != 0)
			break;

		if (list_empty(&plist_local))
			break;

		token = strtok_r(NULL, "&&", &save);
	}

	if (ret == 0) {
		struct pathNode *iter;

		list_for_each_entry(iter, &plist_local, list) {
			add_path_list(iter->path, resolved_plist);
		}
	}

	free_path_list(&plist_local);
	free_pv_list(&pv_local);
	return ret;
}

static void refresh_path_list(struct list_head *path_list, struct list_head *plist_local)
{
	struct pathNode *iter;

	free_path_list(path_list);

	list_for_each_entry(iter, plist_local, list) {
		add_path_list(iter->path, path_list);
	}
}

static int resolve_path(struct dmctx *bbf_ctx, char *qPath, size_t pos, struct list_head *resolved_plist)
{
	char temp[MAX_DM_PATH + 5] = {0};
	char param[MAX_DM_PATH] = {0};
	size_t plen;
	struct pathNode *ptr;
	int fault;
	bool check = true;
	size_t start;
	bool non_leaf = false;

	LIST_HEAD(plist_local);

	start = pos;
	size_t qPath_len = DM_STRLEN(qPath);
	if (start >= qPath_len)
		return 0;

	if (list_empty(resolved_plist))
		return 0;

	INFO("Entry Len :: %d & qPath :: %s", start, qPath);

	if (strchr(qPath+start, '.') != NULL)
		non_leaf = true;

	if (get_next_param(qPath, &start, param) == false)
		return USP_FAULT_INVALID_PATH_SYNTAX;

	plen = DM_STRLEN(param);
	DEBUG("PARAM ::(%s) pos ::(%d)", param, start);

	fault = 0;
	list_for_each_entry(ptr, resolved_plist, list) {

		size_t len = DM_STRLEN(ptr->path);
		if (len == 0)
			continue;

		snprintf(temp, sizeof(temp), "%s%s", ptr->path, (ptr->path[len - 1] != '.') ? "." : "");

		if (param[0] == '[') {
			param[plen-1] = 0;
			fault = solve_all_filters(bbf_ctx, temp, param+1, &plist_local);
		} else {
			char buff[MAX_DM_VALUE] = {0};
			if (non_leaf)
				snprintf(buff, sizeof(buff), "%s%s.", temp, param);
			else
				snprintf(buff, sizeof(buff), "%s%s", temp, param);

			check = is_present_in_datamodel(bbf_ctx, buff);
			if (check)
				add_path_list(buff, &plist_local);
		}

		if (fault) {
			free_path_list(&plist_local);
			return fault;
		}
	}

	if (check == false && list_empty(&plist_local)) {
		free_path_list(&plist_local);
		return bbf_fault_map(bbf_ctx, FAULT_9005);
	}

	refresh_path_list(resolved_plist, &plist_local);
	free_path_list(&plist_local);

	return resolve_path(bbf_ctx, qPath, start, resolved_plist);
}

int get_resolved_paths(struct dmctx *bbf_ctx, char *qpath, struct list_head *resolved_paths)
{
	char bpath[MAX_DM_PATH] = {0};
	int fault = 0;

	if (get_base_path(qpath, bpath)) {
		size_t pos = 0;

		pos = strlen(bpath);
		INFO("Base Path :: |%s| Pos :: |%d|", bpath, pos);

		bbf_ctx->in_param = bpath;

		fault = bbfdm_cmd_exec(bbf_ctx, BBF_GET_VALUE);

		if (!fault) {
			add_path_list(bpath, resolved_paths);
			fault = resolve_path(bbf_ctx, qpath, pos, resolved_paths);
		}
	} else {
		INFO("Not able to get base path");
		fault = bbf_fault_map(bbf_ctx, FAULT_9005);
	}

	if (fault)
		WARNING("qpath(%s), fault(%d)", qpath, fault);

	return fault;
}

void bbfdm_get_value(bbfdm_data_t *data, void *output)
{
	struct pathNode *pn;
	void *array = NULL;
	int fault = 0;

	memset(&data->bb, 0, sizeof(struct blob_buf));

	bbf_init(&data->bbf_ctx);
	blob_buf_init(&data->bb, 0);

	if (data->is_raw)
		array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);
		LIST_HEAD(resolved_list);

		if (DM_STRLEN(pn->path) == 0)
			snprintf(pn->path, MAX_DM_PATH, ROOT_NODE);

		fault = get_resolved_paths(&data->bbf_ctx, pn->path, &resolved_list);

		if (fault) {
			data->bbf_ctx.in_param = pn->path;
			fill_err_code_table(data, fault);
		} else {
			INFO("Preparing result for(%s)", pn->path);

			data->bbf_ctx.in_param = pn->path;

			if (data->is_raw) {
				prepare_raw_result(&data->bb, &data->bbf_ctx, &resolved_list);
			} else {
				prepare_pretty_result(data->depth, &data->bb, &data->bbf_ctx, &resolved_list);
			}
		}

		free_path_list(&resolved_list);
		bbf_sub_cleanup(&data->bbf_ctx);
	}

	if (data->is_raw)
		blobmsg_close_array(&data->bb, array);

	if (!validate_msglen(data)) {
		ERR("IPC failed for path(%s)", data->bbf_ctx.in_param);
	}

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	if (output)
		memcpy(output, data->bb.head, blob_pad_len(data->bb.head));
	else
		ubus_send_reply(data->ctx, data->req, data->bb.head);

	// free
	blob_buf_free(&data->bb);
	bbf_cleanup(&data->bbf_ctx);
}

void bbfdm_get_names(bbfdm_data_t *data)
{
	int fault = 0;
	struct pathNode *pn;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_GET_NAME);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			struct dm_parameter *n = NULL;
			void *table = NULL;

			list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
				table = blobmsg_open_table(&data->bb, NULL);
				blobmsg_add_string(&data->bb, "path", n->name);
				blobmsg_add_string(&data->bb, "data", n->data);
				blobmsg_add_string(&data->bb, "type", n->type);
				blobmsg_close_table(&data->bb, table);
			}
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bb, array);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	bbf_cleanup(&data->bbf_ctx);
}

void bbfdm_get_instances(bbfdm_data_t *data)
{
	int fault = 0;
	struct pathNode *pn;

	bbf_init(&data->bbf_ctx);

	void *array = blobmsg_open_array(&data->bb, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_INSTANCES);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			struct dm_parameter *n;


			list_for_each_entry(n, &data->bbf_ctx.list_parameter, list) {
				void *table = blobmsg_open_table(&data->bb, NULL);
				blobmsg_add_string(&data->bb, "path", n->name);
				blobmsg_close_table(&data->bb, table);
			}
		}

		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(&data->bb, array);

	// Apply all bbfdm changes
	if (is_transaction_running() == false)
		dmuci_commit_bbfdm();

	bbf_cleanup(&data->bbf_ctx);
}

static void fill_operate_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "path", param->name);
	blobmsg_add_string(bb, "type", param->type);
	blobmsg_add_string(bb, "data", param->additional_data);

	if (param->data) {
		void *array, *table;
		const char **in, **out;
		operation_args *args;
		int i;

		args = (operation_args *) param->data;
		in = args->in;
		if (in) {
			array = blobmsg_open_array(bb, "input");

			for (i = 0; in[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", in[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, array);
		}

		out = args->out;
		if (out) {
			array = blobmsg_open_array(bb, "output");

			for (i = 0; out[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", out[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, array);
		}
	}
}

static void fill_event_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "path", param->name);
	blobmsg_add_string(bb, "type", param->type);

	if (param->data) {
		event_args *ev;
		void *table;

		ev = (event_args *)param->data;

		if (ev->param) {
			const char **in = ev->param;
			void *key = blobmsg_open_array(bb, "input");

			for (int i = 0; in[i] != NULL; i++) {
				table = blobmsg_open_table(bb, NULL);
				blobmsg_add_string(bb, "path", in[i]);
				blobmsg_close_table(bb, table);
			}

			blobmsg_close_array(bb, key);
		}
	}
}

static void fill_param_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	bb_add_string(bb, "path", param->name);
	bb_add_string(bb, "data", param->data ? param->data : "0");
	bb_add_string(bb, "type", param->type);
	bb_add_flags_arr(bb, param->additional_data);
}


struct blob_attr *get_parameters(struct blob_attr *msg, const char *key)
{
	struct blob_attr *params = NULL;
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem) {
		const char *name = blobmsg_name(cur);

		if (strcmp(key, name) == 0) {
			params = cur;
			break;
		}
	}
	return params;
}


bool valid_entry(bbfdm_data_t *data, struct blob_attr *input)
{
	bool ret = false;
	struct blob_attr *p;
	char *name;
	size_t len;
	struct pathNode *pn;

	p = get_parameters(input, "path");
	if (p) {
		name = blobmsg_get_string(p);
		list_for_each_entry(pn, data->plist, list) {
			len = strlen(pn->path);
			if (pn->path[len - 1] != '.') {
				continue;
			}
			if (strncmp(pn->path, name, len) == 0) {
				ret = true;
				break;
			}
		}
	}

	return ret;
}

void get_schema_from_blob(struct blob_buf *schema_bp, bbfdm_data_t *data)
{
	struct blob_buf *bp = &data->bb;
	struct blob_attr *schema_blob = NULL;
	struct blob_attr *params;
	struct blob_attr *cur;
	size_t rem = 0;

	void *array = blobmsg_open_array(bp, "results");

	schema_blob = blob_memdup(schema_bp->head);
	if (schema_blob == NULL) {
		goto end;
	}

	params = get_parameters(schema_blob, "results");
	if (params == NULL) {
		goto end;
	}

	blobmsg_for_each_attr(cur, params, rem) {
		if (valid_entry(data, cur)) {
			blobmsg_add_blob(bp, cur);
		}
	}
end:
	blobmsg_close_array(bp, array);
	FREE(schema_blob);
}

int bbf_dm_get_supported_dm(bbfdm_data_t *data)
{
	struct dm_parameter *param;
	struct pathNode *pn;
	int fault = 0;
	struct blob_buf *bp;

	bbf_init(&data->bbf_ctx);

	if (data->bbp) {
		bp = data->bbp;
	} else {
		bp = &data->bb;
	}

	void *array = blobmsg_open_array(bp, "results");

	list_for_each_entry(pn, data->plist, list) {
		bbf_sub_init(&data->bbf_ctx);

		data->bbf_ctx.in_param = pn->path;

		fault = bbfdm_cmd_exec(&data->bbf_ctx, BBF_SCHEMA);
		if (fault) {
			fill_err_code_table(data, fault);
		} else {
			INFO("Preparing result for(%s)", data->bbf_ctx.in_param);

			list_for_each_entry(param, &data->bbf_ctx.list_parameter, list) {
				int cmd = get_dm_type(param->type);

				void *table = blobmsg_open_table(bp, NULL);
				if (cmd == DMT_COMMAND) {
					fill_operate_schema(bp, param);
				} else if (cmd == DMT_EVENT) {
					fill_event_schema(bp, param);
				} else {
					fill_param_schema(bp, param);
				}
				blobmsg_close_table(bp, table);
			}
		}
		bbf_sub_cleanup(&data->bbf_ctx);
	}

	blobmsg_close_array(bp, array);

	bbf_cleanup(&data->bbf_ctx);

	return fault;
}
