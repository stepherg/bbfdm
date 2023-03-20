/*
 * get_helper.c: Get Fast handler for uspd
 *
 * Copyright (C) 2019 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Shubham Sharma <shubham.sharma@iopsys.eu>
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

#define _XOPEN_SOURCE
#define _DEFAULT_SOURCE

#include <time.h>
#include <setjmp.h>

#include <libbbfdm/dmbbfcommon.h>

#include "get_helper.h"
#include "common.h"
#include "pretty_print.h"

// uloop.h does not have versions, below line is to use
// deprecated uloop_timeout_remaining for the time being
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static struct {
	int trans_id;
	struct uloop_timeout trans_timeout;
	int timeout_ms;
	char app[10];
} g_current_trans = {.trans_id=0, .timeout_ms=10000};

static const char * const operations[] = {
	[OPER_EQUAL_EQUAL] = "==",
	[OPER_NOT_EQUAL] = "!=",
	[OPER_LESS_THAN_EQUAL] = "<=",
	[OPER_GREATER_THAN_EQUAL] = ">=",
	[OPER_LESS_THAN] = "<",
	[OPER_GREATER_THAN] = ">"
};

static jmp_buf gs_jump_location;
static bool gs_jump_called_by_bbf = false;
static char g_dm_version[10] = {'\0'};

// Common utilities
void set_datamodel_version (char *version)
{
	if(version)
		snprintf(g_dm_version, sizeof(g_dm_version), "%s", version);
}

void print_last_dm_object(void)
{
	char buff[MAX_DM_PATH];

	dm_debug_browse_path(buff, MAX_DM_PATH);
	ERR("# PID[%ld] Last DM path [%s] #", getpid(), buff);
}

void handle_pending_signal(int sig)
{
	if (gs_jump_called_by_bbf) {
		siglongjmp(gs_jump_location, 1);
	}

	ERR("Exception [%d] not cause by bbf dm, exit with error", sig);
	exit(1);
}

// blobmsg result in segfault when null values added
void bb_add_string(struct blob_buf *bb, const char *name, const char *value)
{
	if (value)
		blobmsg_add_string(bb, name, value);
	else
		blobmsg_add_string(bb, name, "");
}

void bbf_configure_ubus(struct ubus_context *ctx)
{
	dm_config_ubus(ctx);
}

void bbf_init(struct dmctx *dm_ctx, int instance)
{
	dm_ctx_init(dm_ctx, instance);
}

void bbf_cleanup(struct dmctx *dm_ctx)
{
	dm_ctx_clean(dm_ctx);
}

static void bbf_sub_init(struct dmctx *dm_ctx, char *path);
static void bbf_sub_cleanup(struct dmctx *dm_ctx);

static void bbf_sub_init(struct dmctx *dm_ctx, char *path)
{
	unsigned int instance = INSTANCE_MODE_NUMBER;

	if (match(path, "[[]+")) {
		if (!match(path, GLOB_EXPR))
			instance = INSTANCE_MODE_ALIAS;
	}
	DEBUG("instance|%u|", instance);
	dm_ctx_init_sub(dm_ctx, instance);
}

static void bbf_sub_cleanup(struct dmctx *dm_ctx)
{
	dm_ctx_clean_sub(dm_ctx);
}

static bool get_base_path(char *query_path, char *base_path)
{
	bool found;
	size_t i, qlen, lastdot, j;
	char ch;

	if (base_path == NULL)
		return false;

	base_path[0] = '\0';

	if (strncmp(query_path, ROOT_NODE, DM_STRLEN(ROOT_NODE)) != 0)
		return false;

	lastdot = 6;
	qlen = DM_STRLEN(query_path);
	found = false;
	for (i = 0; i < qlen; i++) {
		switch (query_path[i]) {
		case '.':
			lastdot = i + 1;
			break;
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
		case '*':
			if (query_path[i - 1] != '.' &&
			    query_path[i + 1] != '.')
				return false;
			found = true;
			break;
		case '+':
		case '#':
			if (query_path[i - 1] == '.')
				return false;

			i = lastdot;
			found = true;
			break;
		}
		if (found)
			break;
	}

	strncpyt(base_path, query_path, i + 1);
	return true;
}

int get_resolved_paths(struct dmctx *bbf_ctx, char *qpath, struct list_head *resolved_paths)
{
	int fault = USP_ERR_OK;
	char bpath[MAX_DM_PATH] = {0};

	if (get_base_path(qpath, bpath)) {
		size_t pos = 0;

		pos = DM_STRLEN(bpath);
		INFO("Base Path :: |%s| Pos :: |%d|", bpath, pos);

		fault = bbf_dm_get_values(bbf_ctx, bpath);
		if (fault == USP_ERR_OK) {
			add_path_node(bpath, resolved_paths);
			fault = resolve_path(bbf_ctx, qpath, pos, resolved_paths);
		}
	} else {
		INFO("Not able to get base path");
		fault = usp_fault_map(FAULT_9005);
	}

	if (fault)
		WARNING("qpath(%s), fault(%d)", qpath, fault);

	return fault;
}

bool get_instance(char *path, size_t start, char *instance)
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

bool present_in_path_list(struct list_head *plist, char *entry)
{
	struct pathNode *pos;

	list_for_each_entry(pos, plist, list) {
		if (!strcmp(pos->path, entry))
			return true;
	}

	return false;
}

/* This function is not used anywhere but kept for debugging purpose hence suppressed */
// cppcheck-suppress unusedFunction
bool path_present_in_pvlist(struct list_head *pvlist, char *entry)
{
	struct pvNode *pv;
	size_t len;

	len = DM_STRLEN(entry);
	list_for_each_entry(pv, pvlist, list) {
		if (!strncmp(pv->param, entry, len))
			return true;
	}

	return false;
}

int seperator(char *token, char *para, enum operation *oper, char *value)
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

void add_path_node(char *para, struct list_head *plist)
{
	struct pathNode *node = NULL;
	size_t len;

	node = (struct pathNode *) malloc(sizeof(*node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	len = DM_STRLEN(para);
	strncpyt(node->path, para, len + 1);

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, plist);
}

void add_pv_node(char *para, char *val, char *type, struct list_head *pv_list)
{
	struct pvNode *node = NULL;

	node = (struct pvNode *) malloc(sizeof(*node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	node->param = (para) ? strdup(para) : strdup("");
	node->val = (val) ? strdup(val) : strdup("");
	node->type = (type) ? strdup(type) : strdup("");

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, pv_list);
}


void free_path_list(struct list_head *head)
{
	struct pathNode *iter, *node;

	list_for_each_entry_safe(iter, node, head, list) {
		list_del(&iter->list);
		free(iter);
	}
}

void free_pv_list(struct list_head *head)
{
	struct pvNode *iter, *node;

	list_for_each_entry_safe(iter, node, head, list) {
		free(iter->param);
		free(iter->val);
		free(iter->type);

		list_del(&iter->list);
		free(iter);
	}
}

void refresh_path_list(struct list_head *path_list, struct list_head *plist_local)
{

	struct pathNode *iter;

	free_path_list(path_list);

	list_for_each_entry(iter, plist_local, list) {
		add_path_node(iter->path, path_list);
	}
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

static bool handle_hexbin(const char *v1, const char *v2,
			  enum operation op __attribute__((unused)),
			  int *fault)
{
	if (v1 == NULL || v2 == NULL)
		return false;

	*fault = USP_FAULT_INVALID_PATH_SYNTAX;
	return false;
}

void handle_special_escape_sequence(char *value, char *buff, size_t buff_len)
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

bool match_bbf_value(char *path, char *value, enum operation op, int *fault)
{
	bool ret;
	struct dm_parameter *n;
	struct dmctx sub_ctx;


	if (path == NULL || value == NULL || fault == NULL)
		return false;

	DEBUG("path(%s)", path);

	memset(&sub_ctx, 0, sizeof(struct dmctx));
	bbf_sub_init(&sub_ctx, path);

	*fault = bbf_dm_get_values(&sub_ctx, path);
	if (*fault) {
		bbf_sub_cleanup(&sub_ctx);
		ERR("Fault form bbf_get_value : |0x%x| ", fault);
		return false;
	}

	ret = false;
	list_for_each_entry(n, &sub_ctx.list_parameter, list) {
		ret = check_values(n->type, n->data, value, op, fault);
		if (ret)
			break;

		if (*fault != USP_ERR_OK)
			break;
	}

	bbf_sub_cleanup(&sub_ctx);
	return ret;
}

bool split_reference_info(char *para, char *refer, char *ref_num_str, char *ref_param)
{
	char *ptr;
	uint8_t index;
	bool found;
	size_t len, i;

	if (para == NULL || refer == NULL || ref_num_str == NULL || ref_param == NULL)
		return false;

	len = DM_STRLEN(para);
	found = false;
	ptr = refer;
	index = 0;
	ref_num_str[0] = '\0';
	ref_param[0] = '\0';
	refer[0] = '\0';
	for (i = 0; i < len; i++) {
		if (index >= len)
			return false;

		if (para[i] == '#') {
			found = true;
			ptr[index] = '\0';
			index = 0;
			ptr = ref_num_str;
		} else if (para[i] == '+') {
			ptr[index] = '\0';
			index = 0;
			ptr = ref_param;
		} else {
			ptr[index++] = para[i];
		}
	}
	ptr[index] = '\0';
	if (found) {
		if (ref_num_str[0] != '*' && strtol(ref_num_str, NULL, 10) == 0)
			return false;

		size_t ref_num_str_len = DM_STRLEN(ref_num_str);
		if (ref_num_str_len > 3)
			return false;
	}

	if (ref_param[0] != '.')
		return false;

	return true;
}

static int _get_ref_from_path(char *path, char *num, char *ref)
{
	long ref_num, count;
	char *token, *save;

	ref[0] = '\0';
	ref_num = strtol(num, NULL, 10);
	if (ref_num == 0)
		return USP_FAULT_INVALID_PATH_SYNTAX;

	token = strtok_r(path, DM_VALUE_SEP, &save);
	count = 0;
	while (token) {
		count++;
		if (ref_num == count)
			break;
		token = strtok_r(NULL, DM_VALUE_SEP, &save);
	}
	if (ref_num > count)
		return USP_FAULT_INVALID_PATH_SYNTAX;

	if (token) {
		size_t len = DM_STRLEN(token);
		strncpyt(ref, token, len + 1);
	}

	return USP_ERR_OK;
}

int handle_reference(char *bPath, struct list_head *pv_list, char *para,
		      enum operation oper, char *val, struct list_head *resolved_plist)
{
	char temp[MAX_DM_PATH+MAX_DM_KEY_LEN];
	int fault = 0;
	size_t len;
	char refer[MAX_DM_KEY_LEN], ref_num_str[MAX_DM_KEY_LEN] = {0}, ref_param[MAX_DM_KEY_LEN];
	bool found;
	struct pvNode *pv;
	char *token, *save;
	struct pathNode *iter;

	// parameter will be in order para (SSIDReference#n+.SSID) value("MyHome")
	found = split_reference_info(para, refer, ref_num_str, ref_param);
	if (found == false)
		return USP_FAULT_INVALID_PATH_SYNTAX;

	len = DM_STRLEN(bPath);
	if (list_empty(resolved_plist)) {
		list_for_each_entry(pv, pv_list, list) {
			char inst[MAX_DM_KEY_LEN];

			if (strncmp(pv->param, bPath, len) != 0)
				continue;

			if (get_instance(pv->param, len, inst) == false)
				continue;

			snprintf(temp, MAX_DM_PATH, "%s%s.%s", bPath, inst, refer);
			if (strcmp(pv->param, temp) != 0)
				continue;

			if (ref_num_str[0] == '*') {
				found = true;
				token = strtok_r(pv->val, DM_VALUE_SEP, &save);
				while (token) {
					snprintf(temp, MAX_DM_PATH, "%s.%s", token, &ref_param[1]);
					if (match_bbf_value(temp, val, oper, &fault) == false) {
						if (fault != 0)
							return fault;

						found = false;
						break;
					}
					snprintf(temp, MAX_DM_PATH, "%s%s.", bPath, inst);
					token = strtok_r(NULL, DM_VALUE_SEP, &save);
				}

				if (found)
					add_path_node(temp, resolved_plist); // Resolved List

				continue;
			}

			char buff[MAX_DM_PATH+MAX_DM_KEY_LEN+MAX_DM_KEY_LEN] = {0};
			if (DM_STRLEN(ref_num_str)) {
				fault = _get_ref_from_path(pv->val, ref_num_str, temp);
				if (fault)
					return fault;

				snprintf(buff, sizeof(buff), "%s.%s", temp, &ref_param[1]);
			} else {
				snprintf(buff, sizeof(buff), "%s.%s", pv->val, &ref_param[1]);
			}

			if (match_bbf_value(buff, val, oper, &fault)) {
				snprintf(buff, sizeof(buff), "%s%s.", bPath, inst);
				add_path_node(buff, resolved_plist); // Resolved List
			} else {
				if (fault != 0)
					return fault;
			}
		}
	} else {
		struct pathNode *node;

		list_for_each_entry_safe(iter, node, resolved_plist, list) {
			snprintf(temp, sizeof(temp), "%s%s", iter->path, refer);

			found = false;
			list_for_each_entry(pv, pv_list, list) {
				if (strcmp(pv->param, temp) == 0) {
					found = true;
					break;
				}
			}

			if (found == false)
				return USP_FAULT_INVALID_PATH_SYNTAX;

			if (ref_num_str[0] == '*') {
				token = strtok_r(pv->val, DM_VALUE_SEP, &save);
				while (token) {
					snprintf(temp, MAX_DM_PATH, "%s.%s", token, &ref_param[1]);
					if (match_bbf_value(temp, val, oper, &fault) == false) {
						list_del(&iter->list);
						free(iter);
						if (fault != 0)
							return fault;
					}
					token = strtok_r(NULL, DM_VALUE_SEP, &save);
				}
				continue;
			}

			char buff[MAX_DM_PATH+MAX_DM_KEY_LEN+MAX_DM_KEY_LEN] = {0};
			if (DM_STRLEN(ref_num_str)) {
				fault = _get_ref_from_path(pv->val, ref_num_str, temp);
				if (fault)
					return fault;

				snprintf(buff, sizeof(buff), "%s%s", temp, &ref_param[1]);
			} else {
				snprintf(buff, sizeof(buff), "%s.%s", pv->val, &ref_param[1]);
			}

			if (match_bbf_value(buff, val, oper, &fault) == false) {
				list_del(&iter->list);
				free(iter);
				if (fault != 0)
					return fault;
			}
		}
	}

	return 0;
}

int search_n_apply(char *bPath, char *para, enum operation oper, char *value,
		   struct list_head *fltrd, struct list_head *resolved_plist)
{
	char temp[MAX_DM_PATH] = {0};
	struct pvNode *pv;
	size_t blen;
	int fault = USP_ERR_OK;

	blen = DM_STRLEN(bPath);
	if (match(para, "[+]+"))
		return handle_reference(bPath, fltrd, para, oper, value, resolved_plist);

	if (!list_empty(resolved_plist)) {
		struct pathNode *iter, *node;

		list_for_each_entry_safe(iter, node, resolved_plist, list) {
			bool is_present = false;

			snprintf(temp, MAX_DM_PATH, "%s%s", iter->path, para);

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
				if (fault != USP_ERR_OK)
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

			snprintf(temp, MAX_DM_PATH, "%s%s.%s", bPath, inst, para);

			if (strcmp(pv->param, temp) != 0)
				continue;

			if (check_values(pv->type, pv->val, value, oper, &fault)) {
				snprintf(temp, MAX_DM_PATH, "%s%s.", bPath, inst);
				add_path_node(temp, resolved_plist); // Resolved List
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
	int ret = 0;
	char *token, *save;
	struct dm_parameter *n;
	size_t blen;

	LIST_HEAD(pv_local);
	LIST_HEAD(plist_local);

	INFO("## Basepath(%s), param(%s)", bPath, param);
	// Use shorter list for rest of the operation
	blen = DM_STRLEN(bPath);
	list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
		if (strncmp(n->name, bPath, blen) == 0)
			add_pv_node(n->name, n->data, n->type, &pv_local);
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
		if (match(para, "[*]+"))
			ret = USP_FAULT_INVALID_TYPE;
		else
			ret = search_n_apply(bPath, para, oper, value, &pv_local, &plist_local);

		if (ret != 0)
			break;

		if (list_empty(&plist_local))
			break;

		token = strtok_r(NULL, "&&", &save);
	}

	//dump_resolved_list(&plist_local);
	if (ret == 0) {
		struct pathNode *iter;

		list_for_each_entry(iter, &plist_local, list) {
			add_path_node(iter->path, resolved_plist);
		}
	}

	free_path_list(&plist_local);
	free_pv_list(&pv_local);
	return ret;
}

// Will fill param with only the Dot seperated_token
bool get_next_param(char *qPath, size_t *pos, char *param)
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
		case '+':
		case '#':
			i = qlen;
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

	if (param[0] == '*') {
		size_t param_len = DM_STRLEN(param);
		if (param_len > 1) {
			ERR("* followed by other characters(%s)", param);
			return false;
		}

		// * is not followed by .
		if (qPath[*pos - 1] != '.') {
			ERR("* not followed by dot(%c)", qPath[*pos - 1]);
			return false;
		}
	}

	return true;
}

static int append_all_instances(char *bPath, struct list_head *plist_local)
{
	int fault = USP_ERR_OK;
	char temp[MAX_DM_PATH];
	struct dmctx sub_ctx;
	struct dm_parameter *n;

	memset(&sub_ctx, 0, sizeof(struct dmctx));
	bbf_sub_init(&sub_ctx, bPath);

	fault = bbf_dm_get_instances(&sub_ctx, bPath, "1");
	list_for_each_entry(n, &sub_ctx.list_parameter, list) {
		temp[0] = '\0';

		// Add .
		snprintf(temp, MAX_DM_PATH, "%s.", n->name);
		add_path_node(temp, plist_local);
	}

	bbf_sub_cleanup(&sub_ctx);
	return fault;
}

static int follow_ref(struct dmctx *bbf_ctx, char *bPath, char *param,
		struct list_head *plist_local)
{
	char temp[MAX_DM_VALUE];
	char refer[MAX_DM_KEY_LEN], ref_num_str[MAX_DM_KEY_LEN], ref_param[MAX_DM_KEY_LEN];
	bool found;
	int fault;
	struct dm_parameter *n;
	uint8_t ref_num, count;
	char *token, *save;

	DEBUG("bpath(%s), param(%s)", bPath, param);

	found = split_reference_info(param, refer, ref_num_str, ref_param);
	if (found == false)
		return USP_FAULT_INVALID_PATH_SYNTAX;

	DEBUG("re(%s), num(%s), ref_param(%s)", refer, ref_num_str, ref_param);
	snprintf(temp, sizeof(temp), "%s%s", bPath, refer);

	found = false;
	list_for_each_entry(n, &bbf_ctx->list_parameter, list) {
		if (strcmp(n->name, temp) == 0) {
			found = true;
			break;
		}
	}

	if (found == false)
		return USP_FAULT_INVALID_PATH_SYNTAX;

	if (get_dm_type(n->type) != DMT_STRING)
		return USP_FAULT_INVALID_VALUE;

	// all references
	if (ref_num_str[0] == '*') {
		token = strtok_r(n->data, DM_VALUE_SEP, &save);
		while (token) {
			snprintf(temp, sizeof(temp), "%s.%s", token, &ref_param[1]);
			DEBUG("## Getting dm * (%s)", temp);
			fault = bbf_dm_get_values(bbf_ctx, temp);
			if (fault) {
				ERR("Fault form bbf_get_value : |0x%x| ", fault);
				return fault;
			}
			add_path_node(temp, plist_local);
			token = strtok_r(NULL, DM_VALUE_SEP, &save);
		}
		return USP_ERR_OK;
	}

	ref_num = (uint8_t) strtoul(ref_num_str, NULL, 10);
	count = 0;
	if (ref_num) {
		token = strtok_r(n->data, DM_VALUE_SEP, &save);
		while (token) {
			count++;
			if (count == ref_num) {
				break;
			}
			token = strtok_r(NULL, DM_VALUE_SEP, &save);
		}
		if (ref_num > count)
			return USP_FAULT_UNSUPPORTED_PARAM;
		if (token) {
			snprintf(temp, sizeof(temp), "%s.%s", token, &ref_param[1]);
		}
	} else {
		size_t ref_num_str_len = DM_STRLEN(ref_num_str);
		if (ref_num_str_len != 0)
			return USP_FAULT_INVALID_PATH_SYNTAX;

		snprintf(temp, sizeof(temp), "%s.%s", n->data, &ref_param[1]);
	}

	INFO("## Getting dm pv for (%s)", temp);
	fault = bbf_dm_get_values(bbf_ctx, temp);
	if (fault) {
		ERR("Fault form bbf_get_value : |0x%x| ", fault);
		return fault;
	}
	add_path_node(temp, plist_local);

	return 0;
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

int resolve_path(struct dmctx *bbf_ctx, char *qPath, size_t pos, struct list_head *resolved_plist)
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
		} else if (param[0] == '*') {
			fault = append_all_instances(temp, &plist_local);
		} else if (match(param, "[+]+")) {
			fault = follow_ref(bbf_ctx, temp, param, &plist_local);
		} else {
			char buff[MAX_DM_VALUE] = {0};
			if (non_leaf)
				snprintf(buff, sizeof(buff), "%s%s.", temp, param);
			else
				snprintf(buff, sizeof(buff), "%s%s", temp, param);

			check = is_present_in_datamodel(bbf_ctx, buff);
			if (check)
				add_path_node(buff, &plist_local);
		}
		if (fault) {
			free_path_list(&plist_local);
			return fault;
		}
	}

	if (check == false && list_empty(&plist_local)) {
		free_path_list(&plist_local);
		return usp_fault_map(FAULT_9005);
	}

	refresh_path_list(resolved_plist, &plist_local);
	free_path_list(&plist_local);

	return resolve_path(bbf_ctx, qPath, start, resolved_plist);
}

static int usp_dm_exec(struct dmctx *bbf_ctx, int cmd, char *path, char *arg1, char *arg2)
{
	int fault = 0;

	if (path == NULL)
		return USP_FAULT_INTERNAL_ERROR;

	if (sigsetjmp(gs_jump_location, 1) == 0) {
		gs_jump_called_by_bbf = true;
		fault = dm_entry_param_method(bbf_ctx, cmd, path, arg1, arg2);
	} else {
		ERR("PID [%ld]::Exception on [%d => %s]", getpid(), cmd, path);
		print_last_dm_object();
		fault = USP_FAULT_INTERNAL_ERROR;
	}

	gs_jump_called_by_bbf = false;

	if (fault)
		WARNING("Fault [%d => %d => %s]", fault, cmd, path);

	return fault;
}

int usp_dm_exec_apply(struct dmctx *bbf_ctx, int cmd)
{
	int fault = 0;

	if (sigsetjmp(gs_jump_location, 1) == 0) {
		gs_jump_called_by_bbf = true;
		fault = dm_entry_apply(bbf_ctx, cmd);
	} else {
		ERR("PID [%ld]::Exception on [%d] apply", getpid(), cmd);
		print_last_dm_object();
		fault = USP_FAULT_INTERNAL_ERROR;
	}

	gs_jump_called_by_bbf = false;

	return fault;
}

int usp_dm_set(struct dmctx *dm_ctx, char *path, char *value)
{
	int fault = 0;

	fault = usp_dm_exec(dm_ctx, CMD_SET_VALUE, path, value, NULL);

	INFO("path(%s), value(%s), fault(%d)", path, value, fault);

	return fault;
}

int usp_dm_operate(struct blob_buf *bb, char *path, char *input_params, bool raw, int instance)
{
	int fault = 0, ret = 0;
	struct dmctx bbf_ctx = {0};
	void *table, *array;

	LIST_HEAD(pv_local);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	bbf_init(&bbf_ctx, instance);

	ret = usp_dm_exec(&bbf_ctx, CMD_USP_OPERATE, path, input_params, NULL);
	switch (ret) {
	case CMD_NOT_FOUND:
		fault = USP_FAULT_INVALID_PATH;
		break;
	case CMD_INVALID_ARGUMENTS:
		fault = USP_FAULT_INVALID_ARGUMENT;
		break;
	case CMD_FAIL:
		fault = USP_FAULT_COMMAND_FAILURE;
		break;
	case CMD_SUCCESS:
		fault = USP_ERR_OK;
		DEBUG("command executed successfully");
		break;
	default:
		WARNING("Case(%d) not defined", fault);
		fault = USP_FAULT_INVALID_PATH;
		break;
	}

	if (ret == CMD_SUCCESS) {
		struct dm_parameter *n;

		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			add_pv_node(n->name, n->data, n->type, &pv_local);
		}
	} else {
		fill_err_code(bb, fault);
	}

	bbf_cleanup(&bbf_ctx);

	if (fault != USP_ERR_OK) {
		WARNING("Fault(%d) path(%s) input(%s)", fault, path, input_params);
		free_pv_list(&pv_local);
		return fault;
	}

	if (raw) {
		struct pvNode *pv;

		array = blobmsg_open_array(bb, "parameters");
		list_for_each_entry(pv, &pv_local, list) {
			table = blobmsg_open_table(bb, NULL);
			bb_add_string(bb, "parameter", pv->param);
			bb_add_string(bb, "value", pv->val);
			bb_add_string(bb, "type", pv->type);
			blobmsg_close_table(bb, table);
		}
		blobmsg_close_array(bb, array);
	} else {
		array = blobmsg_open_array(bb, "result");
		table = blobmsg_open_table(bb, NULL);
		prepare_result_blob(bb, &pv_local);
		blobmsg_close_table(bb, table);
		blobmsg_close_array(bb, array);
	}

	free_pv_list(&pv_local);

	return USP_ERR_OK;
}

int usp_add_object(struct dmctx *bbf_ctx, struct blob_buf *bb, char *path, const char *pkey)
{
	uint32_t fault = 0;

	INFO("Req to add object |%s|", path);

	if (pkey == NULL || pkey[0] == 0)
		pkey = "true";

	fault = (uint32_t)usp_dm_exec(bbf_ctx, CMD_ADD_OBJECT, path, (char *)pkey, NULL);

	bb_add_string(bb, "parameter", path);
	if (fault) {
		blobmsg_add_u32(bb, "fault", fault);
		blobmsg_add_u8(bb, "status", 0);
	} else {
		if (bbf_ctx->addobj_instance) {
			blobmsg_add_u8(bb, "status", 1);
			bb_add_string(bb, "instance", bbf_ctx->addobj_instance);
		} else {
			blobmsg_add_u8(bb, "status", 0);
		}
	}

	return fault;
}

int usp_del_object(struct dmctx *bbf_ctx, struct blob_buf *bb, char *path, const char *pkey)
{
	uint32_t fault = 0;

	if (pkey == NULL || pkey[0] == 0)
		pkey = "true";

	fault = (uint32_t)usp_dm_exec(bbf_ctx, CMD_DEL_OBJECT, path, (char *)pkey, NULL);

	bb_add_string(bb, "parameter", path);
	if (fault) {
		blobmsg_add_u8(bb, "status", 0);
		blobmsg_add_u32(bb, "fault", fault);
	} else {
		blobmsg_add_u8(bb, "status", 1);
	}

	return fault;
}

int bbf_get_blob(usp_data_t *data, struct blob_buf *bb)
{
	int fault = USP_ERR_OK;
	struct dmctx dm_ctx;
	struct pathNode *pn;

	memset(&dm_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);

	list_for_each_entry(pn, data->plist, list) {
		char *path = pn->path;
		size_t plen = DM_STRLEN(path);
		if (plen == 0)
			continue;

		bbf_init(&dm_ctx, data->instance);
		DEBUG("Entry path |%s|", path);
		fault = usp_dm_exec(&dm_ctx, data->dm_cmd, pn->path, data->next_level, NULL);
		if (!fault) {
			void *t = NULL;
			size_t poff = 0;
			struct dm_parameter *n;

			if (path[plen - 1] == '.') {
				t = blobmsg_open_table(bb, path);
				poff = plen;
			}

			// cppcheck-suppress unknownMacro
			list_for_each_entry(n, &dm_ctx.list_parameter, list)
				bb_add_string(bb, n->name + poff,  n->data);

			if (t)
				blobmsg_close_table(bb, t);
		} else {
			bb_add_string(bb, "path", path);
			blobmsg_add_u32(bb, "fault", (uint32_t)fault);
		}
		bbf_cleanup(&dm_ctx);
	}

	return fault;
}

int bbf_get_raw(usp_data_t *data, struct blob_buf *bb)
{
	int fault = USP_ERR_OK;
	struct dmctx dm_ctx;
	struct pathNode *pn;

	memset(&dm_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(data->proto);

	list_for_each_entry(pn, data->plist, list) {
		void *table;
		char *path = pn->path;

		INFO("Entry path |%s|", path);
		bbf_init(&dm_ctx, data->instance);
		fault = usp_dm_exec(&dm_ctx, data->dm_cmd, path, data->next_level, NULL);
		if (!fault) {
			struct dm_parameter *n;

			list_for_each_entry(n, &dm_ctx.list_parameter, list) {
				table = blobmsg_open_table(bb, NULL);
				bb_add_string(bb, "parameter", n->name);
				bb_add_string(bb, "value", n->data);
				bb_add_string(bb, "type", n->type);
				blobmsg_close_table(bb, table);
			}
		} else {
			table = blobmsg_open_table(bb, NULL);
			bb_add_string(bb, "parameter", path);
			blobmsg_add_u32(bb, "fault", (uint32_t)fault);
			blobmsg_close_table(bb, table);
		}
		bbf_cleanup(&dm_ctx);
	}

	return fault;
}

static void fill_operate_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter",param->name);
	blobmsg_add_string(bb,"type",param->type);
	blobmsg_add_string(bb,"cmd_type",param->additional_data);
	if(param->data) {
		void *array;
		const char **in, **out;
		operation_args *args;
		int i;

		args = (operation_args *) param->data;
		in = args->in;
		if (in) {
			array = blobmsg_open_array(bb, "in");
			for (i = 0; in[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, in[i]);

			blobmsg_close_array(bb, array);
		}

		out = args->out;
		if (out) {
			array = blobmsg_open_array(bb, "out");
			for (i = 0; out[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, out[i]);

			blobmsg_close_array(bb, array);
		}
	}
}

static void fill_event_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter",param->name);
	blobmsg_add_string(bb,"type",param->type);
	if(param->data) {
		event_args *ev;

		ev = (event_args *)param->data;

		if (ev->param) {
			const char **in = ev->param;
			void *key = blobmsg_open_array(bb, "in");

			for (int i = 0; in[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, in[i]);
			blobmsg_close_array(bb, key);
		}
	}
}

static void fill_param_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter",param->name);
	if(param->data)
		blobmsg_add_string(bb,"writable",param->data);
	else
		blobmsg_add_string(bb,"writable","0");
	blobmsg_add_string(bb,"type",param->type);
	if (param->additional_data) {
		const char **uniq_keys = (const char **)param->additional_data;
		void *key = blobmsg_open_array(bb, "unique_keys");

		for (int i = 0; uniq_keys[i] != NULL; i++)
			blobmsg_add_string(bb, NULL, uniq_keys[i]);

		blobmsg_close_array(bb, key);
	}
}

int bbf_dm_get_supported_dm(struct blob_buf *bb, char *path, bool first_level, int schema_type)
{
	int fault=0;
	struct dmctx bbf_ctx;
	struct dm_parameter *param;

	memset(&bbf_ctx,0 ,sizeof(struct dmctx));

	set_bbfdatamodel_type(BBFDM_USP);
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	fault = dm_get_supported_dm(&bbf_ctx, path, first_level, schema_type);
	if(fault) {
		blobmsg_add_u32(bb, "fault", fault);
		bbf_cleanup(&bbf_ctx);
		return fault;
	}

	void *array = blobmsg_open_array(bb,"parameters");

	list_for_each_entry(param, &bbf_ctx.list_parameter, list) {
		int cmd = get_dm_type(param->type);

		void *table = blobmsg_open_table(bb,NULL);
		if (cmd == DMT_COMMAND) {
			fill_operate_schema(bb, param);
		} else if (cmd == DMT_EVENT) {
			fill_event_schema(bb, param);
		} else {
			fill_param_schema(bb, param);
		}

		blobmsg_close_table(bb, table);
	}
	blobmsg_close_array(bb, array);

	bbf_cleanup(&bbf_ctx);

	return fault;
}

bool bbf_dm_event_registered(char *ename)
{
	bool ret = false;
	struct dmctx bbf_ctx;
	struct dm_parameter *param;

	memset(&bbf_ctx,0 ,sizeof(struct dmctx));
	set_bbfdatamodel_type(BBFDM_USP);
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	dm_get_supported_dm(&bbf_ctx, ROOT_NODE, false, EVENT_ONLY);
	list_for_each_entry(param, &bbf_ctx.list_parameter, list) {
		if (strcmp(param->name, ename) == 0) {
			ret = true;
			break;
		}
	}

	bbf_cleanup(&bbf_ctx);

	return ret;
}

int bbf_dm_get_schema(struct blob_buf *bb)
{
	int fault = 0;
	struct dmctx bbf_ctx;
	struct dm_parameter *n;
	void *array;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(BBFDM_USP);
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	fault = usp_dm_exec(&bbf_ctx, CMD_GET_SCHEMA, ROOT_NODE, NULL, NULL);
	if (fault) {
		bbf_cleanup(&bbf_ctx);
		return fault;
	}

	array = blobmsg_open_array(bb, "parameters");
	list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
		void *table = blobmsg_open_table(bb, NULL);

		blobmsg_add_string(bb, "parameter", n->name);
		if (n->data)
			blobmsg_add_string(bb, "writable", n->data);
		else
			blobmsg_add_string(bb, "writable", "0");

		blobmsg_add_string(bb, "type", n->type);

		if (n->additional_data) {
			const char **uniq_keys = (const char **)n->additional_data;
			void *key = blobmsg_open_array(bb, "unique_keys");

			for (int i = 0; uniq_keys[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, uniq_keys[i]);

			blobmsg_close_array(bb, key);
		}
		blobmsg_close_table(bb, table);
	}
	blobmsg_close_array(bb, array);

	bbf_cleanup(&bbf_ctx);

	return fault;
}

int bbf_dm_get_values(struct dmctx *bbf_ctx, char *path)
{
	int fault = 0;

	fault = usp_dm_exec(bbf_ctx, CMD_GET_VALUE, path, NULL, NULL);

	return fault;
}

int bbf_dm_get_instances(struct dmctx *bbf_ctx, char *path, char *next)
{
	int fault = 0;

	fault = usp_dm_exec(bbf_ctx, CMD_GET_INSTANCES, path, next, NULL);

	return fault;
}

int bbf_dm_get_names(struct dmctx *bbf_ctx, char *path, char *next)
{
	int fault = 0;

	fault = usp_dm_exec(bbf_ctx, CMD_GET_NAME, path, next, NULL);

	return fault;
}

int bbf_dm_list_operate(struct dmctx *bbf_ctx)
{
	int fault = 0;

	fault = usp_dm_exec(bbf_ctx, CMD_USP_LIST_OPERATE, ROOT_NODE, NULL, NULL);

	return fault;
}

bool get_granural_object_paths(struct list_head *path_list, uint8_t maxdepth)
{
	uint8_t count;
	int fault;
	struct dmctx bbf_ctx;
	struct dm_parameter *n;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(BBFDM_BOTH);
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	fault = bbf_dm_get_names(&bbf_ctx, ROOT_NODE, "0");
	list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
		if (strcmp(n->type, "xsd:object") == 0) {
			count = count_delim(n->name);
			if (count < maxdepth)
				add_path_node(n->name, path_list);
		}
	}

	bbf_cleanup(&bbf_ctx);

	if (fault)
		return false;

	return true;
}

void fill_err_code(struct blob_buf *bb, int fault)
{
	int f;

	f = usp_fault_map(fault);
	if (bb && fault)
		blobmsg_add_u32(bb, "fault", f);
}

void fill_resolve_err(struct blob_buf *bb, char *spath, int fault)
{
	int f;
	void *array, *table;

	f = usp_fault_map(fault);
	array = blobmsg_open_array(bb, "parameters");
	table = blobmsg_open_table(bb, NULL);
	blobmsg_add_string(bb, "parameter", spath);
	blobmsg_add_u8(bb, "status", false);
	blobmsg_add_u32(bb, "fault", f);
	blobmsg_close_table(bb, table);
	blobmsg_close_array(bb, array);
}

static void transaction_timeout_handler(struct uloop_timeout *t __attribute__((unused)))
{
	INFO("Transaction timeout called");
	transaction_abort(g_current_trans.trans_id);
}

static int get_random_id(void)
{
	int ret;

	srand(time(0));
	ret = rand();
	if (!ret)
		ret = 1;

	return ret;
}

// Returns transaction id if successful, otherwise 0
int transaction_start(const char *app, uint32_t max_timeout)
{
	int ret = 0;
	uint32_t timeout;

	if (g_current_trans.trans_id) {
		WARNING("Transaction already in-process");
		return 0;
	}

	if (max_timeout > 0) {
		timeout = max_timeout;
	} else {
		timeout = g_current_trans.timeout_ms;
	}
	ret = get_random_id();
	g_current_trans.trans_id = ret;
	strncpyt(g_current_trans.app, app, 10);
	g_current_trans.trans_timeout.cb = transaction_timeout_handler;
	uloop_timeout_set(&g_current_trans.trans_timeout, timeout);
	INFO("Transaction started with id %d, timeout %zd", g_current_trans.trans_id, timeout);

	return ret;
}

int fill_transaction_status(struct blob_buf *bb, int trans_id)
{
	if (g_current_trans.trans_id == trans_id) {
		int rem = uloop_timeout_remaining(&g_current_trans.trans_timeout);
		blobmsg_add_string(bb, "app", g_current_trans.app);
		blobmsg_add_string(bb, "status", "on-going");
		blobmsg_add_u32(bb, "remaining_time", rem);
	} else {
		blobmsg_add_string(bb, "status", "not-exists");
	}

	return 0;
}

bool is_transaction_running(void)
{
	return (g_current_trans.trans_id == 0 ? false : true);
}

bool is_transaction_valid(int trans_id)
{
	bool ret = false;

	if (trans_id == 0)
		return false;

	ret = (trans_id == g_current_trans.trans_id);

	return ret;
}

int transaction_commit(int trans_id, struct blob_buf *bp_service_list, bool is_service_restart)
{
	struct dmctx bbf_ctx;
	int ret = -1;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	if (is_transaction_valid(trans_id)) {
		uloop_timeout_cancel(&g_current_trans.trans_timeout);
		bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);
		g_current_trans.app[0] = '\0';
		g_current_trans.trans_id = 0;

		if (is_service_restart == false && bp_service_list != NULL) {
			INFO("Deffer restart services");
			dm_entry_manage_services(bp_service_list, is_service_restart);
		} else {
			INFO("Commit on-going transaction");
			dm_entry_restart_services();
		}

		bbf_cleanup(&bbf_ctx);

		ret = 0;
	} else {
		WARNING("Trans id mismatch(%d)", trans_id);
	}

	return ret;
}

int transaction_abort(int trans_id)
{
	struct dmctx bbf_ctx;
	int ret = -1;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	if (is_transaction_valid(trans_id)) {
		INFO("Abort on-going transaction");
		uloop_timeout_cancel(&g_current_trans.trans_timeout);
		bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);
		g_current_trans.trans_id = 0;
		g_current_trans.app[0] = '\0';
		dm_entry_revert_changes();
		bbf_cleanup(&bbf_ctx);

		ret = 0;
	} else {
		WARNING("Transaction id mismatch(%d)", trans_id);
	}

	return ret;
}

int configure_transaction_timeout(int timeout)
{
	if (timeout <= 0)
		return -1;

	g_current_trans.timeout_ms = timeout * 1000;

	return 0;
}
