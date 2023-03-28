/*
 * usp.c: USP deamon
 *
 * Copyright (C) 2021 iopsys Software Solutions AB. All rights reserved.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <sys/prctl.h>

#include "usp.h"
#include "set.h"
#include "get.h"
#include "get_helper.h"
#include "operate.h"
#include "add_delete.h"
#include "ipc.h"
#include "events.h"
#include "pretty_print.h"
#include "get_helper.h"
#include "libbbf_api/dmentry.h"

#define INSTANCE_UPDATE_TIMEOUT (25 * 1000)

static void periodic_instance_updater(struct uloop_timeout *t);

// Global variables
static unsigned int g_refresh_time = INSTANCE_UPDATE_TIMEOUT;
static int g_subprocess_level = USP_SUBPROCESS_DEPTH;
static int uspd_start_deferred(usp_data_t *data,
			       void (*EXEC_CB)(usp_data_t *data, void *output));

void signal_init();

static unsigned int get_refresh_time(void)
{
	char *temp = NULL;

	get_uci_option_string("uspd", "usp", "refresh_time", &temp);
	if (temp) {
		unsigned int refresh_time = (unsigned int) strtoul(temp, NULL, 10);
		free(temp);
		return (refresh_time * 1000);
	}

	return INSTANCE_UPDATE_TIMEOUT;
}

// In case of granular objects, Concatenate relative path to ubus object
// path must be of size PATH_MAX
static void get_path_from_gran_obj(char *path, const char *obj_name, struct blob_attr *blob)
{
	if (strncmp(obj_name, USPEXT, DM_STRLEN(USPEXT)) == 0) {
		snprintf(path, PATH_MAX, "%s%s", obj_name + USP_EXT_LEN,
			 (char *)blobmsg_data(blob));
	} else {
		snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(blob));
	}
}

static void add_ubus_obj(void *obj, struct list_head *o_list)
{
	struct obNode *node = NULL;

	node = (struct obNode *) malloc(sizeof(*node));

	if (!node) {
		ERR("Out of memory!");
		return;
	}

	node->obj = obj;

	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, o_list);
}

static void free_ubus_obj_list(struct list_head *head)
{
	struct obNode *iter = NULL, *node = NULL;

	list_for_each_entry_safe(iter, node, head, list) {
		char *name = (char *) iter->obj->name;
		struct ubus_object_type *type = iter->obj->type;

		free(iter->obj);
		list_del(&iter->list);
		free(type);
		free(iter);
		free(name);
	}
}

static int get_bbf_proto_type(struct blob_attr *proto)
{
	int type;

	if (proto) {
		const char *val = blobmsg_get_string(proto);

		if (is_str_eq("cwmp", val))
			type = BBFDM_CWMP;
		else if (is_str_eq("usp", val))
			type = BBFDM_USP;
		else
			type = BBFDM_BOTH;
	} else {
		type = BBFDM_BOTH;
	}

	set_bbfdatamodel_type(type);
	return type;
}

static int get_instance_mode(struct blob_attr *ins)
{
	int instance_mode = INSTANCE_MODE_NUMBER;

	if (ins)
		instance_mode = blobmsg_get_u32(ins);

	if (instance_mode > INSTANCE_MODE_ALIAS)
		instance_mode = INSTANCE_MODE_NUMBER;

	return instance_mode;
}

static const struct blobmsg_policy dm_getm_policy[] = {
	[DM_GET_SAFE_PATHS] = { .name = "paths", .type = BLOBMSG_TYPE_ARRAY },
	[DM_GET_SAFE_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_GET_SAFE_NXT_LVL] = { .name = "next-level", .type = BLOBMSG_TYPE_INT8 },
	[DM_GET_SAFE_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
};

int get_multi(struct ubus_context *ctx,
		    struct ubus_object *obj,
		    struct ubus_request_data *req,
		    struct blob_attr *msg,
		    int bbf_cmd)
{
	struct blob_attr *tb[__DM_GET_SAFE_MAX];
	struct blob_attr *paths;
	struct blob_attr *path;
	char *nxt_lvl = "0";
	size_t rem;
	usp_data_t data;
	LIST_HEAD(paths_list);

	memset(&data, 0, sizeof(usp_data_t));
	blobmsg_parse(dm_getm_policy, __DM_GET_SAFE_MAX,
		      tb, blob_data(msg), blob_len(msg));

	paths = tb[DM_GET_SAFE_PATHS];
	if (paths == NULL)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_GET_SAFE_NXT_LVL]) {
		if (blobmsg_get_u8(tb[DM_GET_SAFE_NXT_LVL]))
			nxt_lvl = "1";
	}


	blobmsg_for_each_attr(path, paths, rem) {
		char *path_str = blobmsg_get_string(path);

		add_path_node(path_str, &paths_list);
	}


	data.ctx = ctx;
	data.req = req;
	data.proto = get_bbf_proto_type(tb[DM_GET_SAFE_PROTO]);
	data.is_raw = is_str_eq(obj->name, USPRAW);
	data.next_level = nxt_lvl;
	data.plist = &paths_list;
	data.dm_cmd = bbf_cmd;
	data.instance = get_instance_mode(tb[DM_GET_SAFE_INSTANCE]);

	set_bbfdatamodel_type(data.proto);

	get_mpath(&data);

	free_path_list(&paths_list);

	return 0;
}

int usp_getm_values(struct ubus_context *ctx,
			struct ubus_object *obj,
			struct ubus_request_data *req,
			__attribute__((unused)) const char *method,
			struct blob_attr *msg)
{
	return get_multi(ctx, obj, req, msg, CMD_GET_VALUE);
}

int usp_getm_names(struct ubus_context *ctx,
			struct ubus_object *obj,
			struct ubus_request_data *req,
			__attribute__((unused)) const char *method,
			struct blob_attr *msg)
{
	return get_multi(ctx, obj, req, msg, CMD_GET_NAME);
}

static const struct blobmsg_policy dm_add_policy[] = {
	[DM_ADD_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_ADD_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_ADD_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
};

int usp_add_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_ADD_MAX];
	char path[PATH_MAX];
	struct blob_buf bb = {};
	usp_data_t data;
	int trans_id;

	if (blobmsg_parse(dm_add_policy, __DM_ADD_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_ADD_PATH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(&data, 0, sizeof(usp_data_t));
	data.ctx = ctx;
	data.proto = get_bbf_proto_type(tb[DM_ADD_PROTO]);
	data.is_raw = is_str_eq(obj->name, USPRAW);
	set_bbfdatamodel_type(data.proto);

	get_path_from_gran_obj(path, obj->name, tb[DM_ADD_PATH]);

	data.qpath = path;

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	data.instance = get_instance_mode(tb[DM_ADD_INSTANCE]);
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	// for non-raw objects start a transaction internally and commit
	trans_id = transaction_start("internal", 0);
	if (trans_id) {
		data.trans_id = trans_id;
		if (is_str_eq(method, "add_object"))
			create_add_response(&data, &bb);
		else if (is_str_eq(method, "del_object"))
			create_del_response(&data, &bb);

		transaction_commit(trans_id, NULL, true);
	} else {
		WARNING("Failed to get the lock for the transaction");
		fill_err_code(&bb, USP_FAULT_INTERNAL_ERROR);
	}

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static const struct blobmsg_policy dm_raw_add_policy[] = {
	[DM_RAW_ADD_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_RAW_ADD_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_RAW_ADD_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
	[DM_RAW_ADD_TRANS_ID] = { .name = "transaction_id", .type = BLOBMSG_TYPE_INT32 },
};

int usp_raw_add_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_RAW_ADD_MAX];
	char path[PATH_MAX];
	struct blob_buf bb = {};
	usp_data_t data;
	size_t len;

	if (blobmsg_parse(dm_raw_add_policy, __DM_RAW_ADD_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_RAW_ADD_PATH] || !tb[DM_RAW_ADD_TRANS_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(&bb, 0, sizeof(struct blob_buf));
	memset(&data, 0, sizeof(usp_data_t));
	data.ctx = ctx;
	data.proto = get_bbf_proto_type(tb[DM_RAW_ADD_PROTO]);
	data.is_raw = is_str_eq(obj->name, USPRAW);
	data.trans_id = blobmsg_get_u32(tb[DM_RAW_ADD_TRANS_ID]);
	set_bbfdatamodel_type(data.proto);

	// no need to process it further since transaction is not valid
	if (!is_transaction_valid(data.trans_id)) {
		WARNING("Transaction not started yet");
		blob_buf_init(&bb, 0);
		fill_err_code(&bb, USP_FAULT_INTERNAL_ERROR);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	get_path_from_gran_obj(path, obj->name, tb[DM_RAW_ADD_PATH]);
	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	len = DM_STRLEN(path);
	if (len == 0) {
		WARNING("Path len is 0");
		blob_buf_init(&bb, 0);
		fill_err_code(&bb, USP_FAULT_INTERNAL_ERROR);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	if (path[len - 1] != DELIM) {
		path[len] = DELIM;
		path[len + 1] = '\0';
	}

	data.qpath = path;

	data.instance = get_instance_mode(tb[DM_RAW_ADD_INSTANCE]);
	blob_buf_init(&bb, 0);

	if (is_str_eq(method, "add_object"))
		create_add_response(&data, &bb);
	else if (is_str_eq(method, "del_object"))
		create_del_response(&data, &bb);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static bool is_subprocess_required(const char *path)
{
	bool ret = false;
	size_t len = DM_STRLEN(path);
	if (len == 0)
		return ret;

	if (count_delim(path) < g_subprocess_level) {
		if (path[len - 1] == '.')
			ret = true;
	}

	return ret;
}

static const struct blobmsg_policy dm_get_policy[] = {
	[DM_GET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_GET_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_GET_MAXDEPTH] = { .name = "maxdepth", .type = BLOBMSG_TYPE_INT32 },
	[DM_GET_NXT_LVL] = { .name = "next-level", .type = BLOBMSG_TYPE_INT8 },
	[DM_GET_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy get_supported_dm_policy[] = {
	[DM_SUPPORTED_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SUPPORTED_NXT_LEVEL] = { .name = "next-level", .type = BLOBMSG_TYPE_INT8},
	[DM_SUPPORTED_SCHEMA_TYPE] = { .name = "schema_type", .type = BLOBMSG_TYPE_INT32},
};

int usp_get_handler(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_GET_MAX];
	usp_data_t data;
	const bool raw = is_str_eq(obj->name, USPRAW);
	char path[PATH_MAX];
	uint8_t maxdepth = 0;
	char *nxt_lvl_str = "0";

	if (blobmsg_parse(dm_get_policy, __DM_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_GET_PATH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_GET_MAXDEPTH])
		maxdepth = blobmsg_get_u32(tb[DM_GET_MAXDEPTH]);

	if (tb[DM_GET_NXT_LVL])
		nxt_lvl_str = blobmsg_get_u8(tb[DM_GET_NXT_LVL]) ? "1" :  "0";

	get_path_from_gran_obj(path, obj->name, tb[DM_GET_PATH]);

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);
	memset(&data, 0, sizeof(usp_data_t));

	data.ctx = ctx;
	data.req = req;
	data.qpath = path;
	data.proto = get_bbf_proto_type(tb[DM_GET_PROTO]);
	data.is_raw = raw;
	data.depth = maxdepth;
	data.next_level = nxt_lvl_str;
	data.instance = get_instance_mode(tb[DM_GET_INSTANCE]);
	set_bbfdatamodel_type(data.proto);

	if (is_str_eq(method, "get")) {
		if (is_subprocess_required(path)) {
			INFO("Creating subprocess for get (%s)", path);
			uspd_start_deferred(&data, usp_get_value_async);
		} else {
			usp_get_value(&data);
		}
	} else if (is_str_eq(method, "object_names")) {
		usp_get_name(&data);
	} else if (is_str_eq(method, "instances")) {
		usp_get_instance(&data);
	} else if (is_str_eq(method, "validate")) {
		usp_validate_path(&data);
	} else {
		ERR("method(%s) not defined", method);
	}

	return 0;
}

static const struct blobmsg_policy dm_set_policy[] = {
	[DM_SET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_VALUE_TABLE] = { .name = "values", .type = BLOBMSG_TYPE_TABLE },
	[DM_SET_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
};

int usp_set(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_buf bb = {};
	struct blob_attr *tb[__DM_SET_MAX] = {NULL};
	char path[PATH_MAX] = {'\0'};
	usp_data_t data;
	int fault = USP_ERR_OK;
	struct list_head pv_list;
	int trans_id = 0;

	INIT_LIST_HEAD(&pv_list);

	memset(&bb, 0, sizeof(struct blob_buf));
	memset(&data, 0, sizeof(usp_data_t));

	if (blobmsg_parse(dm_set_policy, __DM_SET_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_SET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!tb[DM_SET_VALUE] && !tb[DM_SET_VALUE_TABLE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	get_path_from_gran_obj(path, obj->name, tb[DM_SET_PATH]);
	data.proto = get_bbf_proto_type(tb[DM_SET_PROTO]);
	data.instance = get_instance_mode(tb[DM_SET_INSTANCE]);
	set_bbfdatamodel_type(data.proto);

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	// for non-raw objects start a transaction internally and commit afterwards
	// if transaction already in-progress return error
	trans_id = transaction_start("internal", 0);
	if (trans_id == 0) {
		WARNING("Failed to get the lock for the transaction");
		blob_buf_init(&bb, 0);
		fill_err_code(&bb, USP_FAULT_INTERNAL_ERROR);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	fault = fill_pvlist_from_path(path, tb[DM_SET_VALUE], &pv_list, data.instance);
	if (fault == USP_ERR_OK)
		fault = fill_pvlist_from_table(path, tb[DM_SET_VALUE_TABLE], &pv_list, data.instance);

	if (fault) {
		ERR("Fault in set path |%s|", path);
		blob_buf_init(&bb, 0);
		fill_resolve_err(&bb, path, fault);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);

		free_pv_list(&pv_list);
		transaction_abort(trans_id);
		return 0;
	}

	data.ctx = ctx;
	data.req = req;
	data.qpath = path;
	data.pv_list = &pv_list;
	data.is_raw = is_str_eq(obj->name, USPRAW);
	data.trans_id = trans_id;

	usp_set_value(&data);

	free_pv_list(&pv_list);
	transaction_commit(trans_id, NULL, true);

	return 0;
}

static const struct blobmsg_policy dm_raw_set_policy[] = {
	[DM_RAW_SET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_RAW_SET_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
	[DM_RAW_SET_VALUE_TABLE] = { .name = "values", .type = BLOBMSG_TYPE_TABLE },
	[DM_RAW_SET_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_RAW_SET_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
	[DM_RAW_SET_TRANS_ID] = { .name = "transaction_id", .type = BLOBMSG_TYPE_INT32 },
};

int usp_raw_set(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf bb = {};
	struct blob_attr *tb[__DM_RAW_SET_MAX] = {NULL};
	char path[PATH_MAX] = {'\0'};
	usp_data_t data;
	int fault = USP_ERR_OK;
	struct list_head pv_list;

	INIT_LIST_HEAD(&pv_list);
	memset(&bb, 0, sizeof(struct blob_buf));
	memset(&data, 0, sizeof(usp_data_t));

	if (blobmsg_parse(dm_raw_set_policy, __DM_RAW_SET_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_RAW_SET_PATH] || !tb[DM_RAW_SET_TRANS_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!tb[DM_RAW_SET_VALUE] && !tb[DM_RAW_SET_VALUE_TABLE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	get_path_from_gran_obj(path, obj->name, tb[DM_RAW_SET_PATH]);

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);


	data.instance = get_instance_mode(tb[DM_RAW_SET_INSTANCE]);
	data.proto = get_bbf_proto_type(tb[DM_RAW_SET_PROTO]);
	data.trans_id = blobmsg_get_u32(tb[DM_RAW_SET_TRANS_ID]);

	set_bbfdatamodel_type(data.proto);

	if (!is_transaction_valid(data.trans_id)) {
		WARNING("Transaction not started yet");
		blob_buf_init(&bb, 0);
		fill_err_code(&bb, USP_FAULT_INTERNAL_ERROR);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	fault = fill_pvlist_from_path(path, tb[DM_RAW_SET_VALUE], &pv_list, data.instance);
	if (fault == USP_ERR_OK)
		fault = fill_pvlist_from_table(path, tb[DM_RAW_SET_VALUE_TABLE], &pv_list, data.instance);

	if (fault) {
		ERR("Fault in raw set path |%s|", path);
		blob_buf_init(&bb, 0);
		fill_resolve_err(&bb, path, fault);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		free_pv_list(&pv_list);
		return 0;
	}

	data.ctx = ctx;
	data.req = req;
	data.qpath = path;
	data.pv_list = &pv_list;
	data.is_raw = is_str_eq(obj->name, USPRAW);

	usp_set_value(&data);

	free_pv_list(&pv_list);

	return 0;
}
static const struct blobmsg_policy dm_operate_policy[__DM_OPERATE_MAX] = {
	[DM_OPERATE_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_OPERATE_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
	[DM_OPERATE_INPUT] = { .name = "input", .type = BLOBMSG_TYPE_TABLE },
	[DM_OPERATE_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_OPERATE_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
};

static void async_req_free(struct uspd_async_req *r)
{
	free(r);
}

static void async_complete_cb(struct uloop_process *p, __attribute__((unused)) int ret)
{
	struct uspd_async_req *r = container_of(p, struct uspd_async_req, process);

	if (r) {
		INFO("Async call with pid(%d) completes", r->process.pid);
		struct blob_buf *bb = (struct blob_buf *)&r->result;

		ubus_send_reply(r->ctx, &r->req, bb->head);
		INFO("pid(%d) blob data sent raw(%d)", r->process.pid, blob_raw_len(bb->head));
		ubus_complete_deferred_request(r->ctx, &r->req, 0);
		munmap(r->result, DEF_IPC_DATA_LEN);
		async_req_free(r);
	}

}

static struct uspd_async_req *async_req_new(void)
{
	struct uspd_async_req *r = malloc(sizeof(*r));

	if (r) {
		memset(&r->process, 0, sizeof(r->process));
		r->result = NULL;
	}

	return r;
}

static int uspd_start_deferred(usp_data_t *data,
			       void (*EXEC_CB)(usp_data_t *data, void *d))
{
	struct uspd_async_req *r = NULL;
	pid_t child;
	struct usp_context *u;
	void *result = NULL;

	result = mmap(NULL, DEF_IPC_DATA_LEN, PROT_READ| PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		ERR("Error creating memory map for result");
		goto err_out;
	}
	memset(result, 0, DEF_IPC_DATA_LEN);
	r = async_req_new();
	if (r == NULL) {
		ERR("Error allocating async req");
		goto err_out;
	}

	child = fork();
	if (child == -1) {
		ERR("fork error");
		goto err_out;
	} else if (child == 0) {
		u = container_of(data->ctx, struct usp_context, ubus_ctx);
		if (u == NULL) {
			ERR("Failed to get the usp context");
			exit(EXIT_FAILURE);
		}

		// child initialise signal to prevent segfaults
		signal_init();
		/* free fd's and memory inherited from parent */
		ubus_shutdown(data->ctx);
		bbf_configure_ubus(NULL);
		uloop_done();
		async_req_free(r);
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		INFO("Calling from subprocess");
		EXEC_CB(data, result);
		if (data->op_input)
			free(data->op_input);

		usp_cleanup(u);
		closelog();
		/* write result and exit */
		exit(EXIT_SUCCESS);
	}

	// parent
	INFO("Creating usp(%d) sub process(%d) for path(%s)", getpid(), child, data->qpath);
	r->result = result;
	r->ctx = data->ctx;
	r->process.pid = child;
	r->process.cb = async_complete_cb;
	uloop_process_add(&r->process);
	ubus_defer_request(data->ctx, data->req, &r->req);
	return 0;

err_out:
	if (r)
		async_req_free(r);

	if (result)
		munmap(result, DEF_IPC_DATA_LEN);

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static bool is_sync_cmd(usp_data_t *data __attribute__((unused)))
{

	// TODO: Put a check to determine the command type
	return false;
}

int usp_operate(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		struct ubus_request_data *req, const char *method __attribute__((unused)),
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_OPERATE_MAX] = {NULL};
	char path[MAX_DM_PATH] = {0};
	char cmd[MAX_DM_KEY_LEN] = {0};
	char *blob_msg = NULL;
	usp_data_t data;

	if (blobmsg_parse(dm_operate_policy, __DM_OPERATE_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_OPERATE_PATH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!(tb[DM_OPERATE_ACTION]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	get_path_from_gran_obj(path, obj->name, tb[DM_ADD_PATH]);
	blob_msg = blobmsg_data(tb[DM_OPERATE_ACTION]);
	strncpyt(cmd, blob_msg, sizeof(cmd));
	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	memset(&data, 0, sizeof(usp_data_t));
	data.ctx = ctx;
	data.req = req;
	data.qpath = path;
	data.op_action = cmd;
	data.proto = get_bbf_proto_type(tb[DM_OPERATE_PROTO]);
	data.is_raw = is_str_eq(obj->name, USPRAW);

	if (tb[DM_OPERATE_INPUT])
		data.op_input = blobmsg_format_json(tb[DM_OPERATE_INPUT], true);

	if (is_sync_cmd(&data)) {
		usp_operate_cmd_sync(&data);
	} else {
		uspd_start_deferred(&data, usp_operate_cmd_async);
	}

	if (data.op_input)
		free(data.op_input);

	return 0;
}

int usp_list_supported_dm(struct ubus_context *actx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_SUPPORTED_MAX];
	char path[PATH_MAX] = "Device.";
	bool nxt_lvl = false;
	uint32_t schema_type = 0;
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));

	if (blobmsg_parse(get_supported_dm_policy, __DM_SUPPORTED_MAX, tb, blob_data(msg), blob_len(msg)) == 0) {

		if (tb[DM_SUPPORTED_PATH])
			get_path_from_gran_obj(path, obj->name, tb[DM_SUPPORTED_PATH]);

		if (tb[DM_SUPPORTED_NXT_LEVEL])
			nxt_lvl = blobmsg_get_bool(tb[DM_SUPPORTED_NXT_LEVEL]);

		if(tb[DM_SUPPORTED_SCHEMA_TYPE])
			schema_type = blobmsg_get_u32(tb[DM_SUPPORTED_SCHEMA_TYPE]);
	}

	INFO("Path:[%s], next:[%d], schema_type:[%u]", path, nxt_lvl, schema_type);
	blob_buf_init(&bb, 0);

	bbf_dm_get_supported_dm(&bb, path, nxt_lvl, schema_type);

	ubus_send_reply(actx, req, bb.head);

	blob_buf_free(&bb);

	return 0;
}

int usp_list_schema(struct ubus_context *actx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg __attribute__((unused)))
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	INFO("ubus method|%s|, name|%s|", method, obj->name);
	bbf_dm_get_schema(&bb);
	ubus_send_reply(actx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int usp_list_operate(struct ubus_context *actx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg __attribute__((unused)))
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	INFO("ubus method|%s|, name|%s|", method, obj->name);
	list_operate_schema(&bb);
	ubus_send_reply(actx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static const struct blobmsg_policy dm_notify_event_policy[] = {
	[DM_NOTIFY_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[DM_NOTIFY_PRAMS] = { .name = "input", .type = BLOBMSG_TYPE_TABLE },
};

int usp_notify_event(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req __attribute__((unused)), const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_NOTIFY_MAX] = {NULL};
	char *event_name;

	if (blobmsg_parse(dm_notify_event_policy, __DM_NOTIFY_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_NOTIFY_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	INFO("ubus method|%s|, name|%s|", method, obj->name);
	event_name = blobmsg_get_string(tb[DM_NOTIFY_NAME]);
	if (is_registered_event(event_name)) {
		ubus_send_event(ctx, "usp.event", msg);
	} else {
		WARNING("Event %s not registered", event_name);
	}

	return 0;
}

int usp_list_events(struct ubus_context *actx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg __attribute__((unused)))
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	INFO("ubus method|%s|, name|%s|", method, obj->name);
	list_event_schema(&bb);
	ubus_send_reply(actx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static const struct blobmsg_policy dm_set_multi_policy[] = {
	[DM_SET_MULTI_TUPLE] = { .name = "pv_tuple", .type = BLOBMSG_TYPE_ARRAY },
	[DM_SET_MULTI_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_MULTI_INSTANCE] = { .name = "instance_mode", .type = BLOBMSG_TYPE_INT32 },
	[DM_SET_MULTI_TRANS_ID] = { .name = "transaction_id", .type = BLOBMSG_TYPE_INT32 },
};

int handle_set_multi_value(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method __attribute__((unused)),
			   struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_SET_MULTI_MAX];
	usp_data_t data;
	struct list_head pv_list;
	struct blob_buf bb;

	memset(&data, 0, sizeof(usp_data_t));
	memset(&bb, 0, sizeof(struct blob_buf));
	blobmsg_parse(dm_set_multi_policy, __DM_SET_MULTI_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (tb[DM_SET_MULTI_TUPLE] == NULL || !tb[DM_SET_MULTI_TRANS_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	data.trans_id = blobmsg_get_u32(tb[DM_SET_MULTI_TRANS_ID]);
	data.proto = get_bbf_proto_type(tb[DM_SET_MULTI_PROTO]);

	set_bbfdatamodel_type(data.proto);
	// no need to process it further since transaction is not valid
	if (!is_transaction_valid(data.trans_id)) {
		WARNING("Transaction not started yet");
		blob_buf_init(&bb, 0);
		fill_err_code(&bb, USP_FAULT_INTERNAL_ERROR);
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	INIT_LIST_HEAD(&pv_list);

	fill_pvlist_from_tuple(tb[DM_SET_MULTI_TUPLE], &pv_list);
	if (list_empty(&pv_list)) {
		WARNING("Path value tuple contains invalid paths");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	data.ctx = ctx;
	data.req = req;
	data.is_raw = is_str_eq(obj->name, USPRAW);
	data.instance = get_instance_mode(tb[DM_SET_MULTI_INSTANCE]);
	data.pv_list = &pv_list;

	usp_set_value(&data);

	free_pv_list(&pv_list);

	return 0;
}
static struct ubus_method usp_methods[] = {
	UBUS_METHOD_NOARG("list_operate", usp_list_operate),
	UBUS_METHOD("get_supported_dm", usp_list_supported_dm, get_supported_dm_policy),
	UBUS_METHOD("get", usp_get_handler, dm_get_policy),
	UBUS_METHOD("object_names", usp_get_handler, dm_get_policy),
	UBUS_METHOD("instances", usp_get_handler, dm_get_policy),
	UBUS_METHOD("validate", usp_get_handler, dm_get_policy),
	UBUS_METHOD("set", usp_set, dm_set_policy),
	UBUS_METHOD("operate", usp_operate, dm_operate_policy),
	UBUS_METHOD("add_object", usp_add_del_handler, dm_add_policy),
	UBUS_METHOD("del_object", usp_add_del_handler, dm_add_policy),
};

enum {
	TRANS_ID,
	TRANS_APP_NAME = TRANS_ID,
	TRANS_TIMEOUT,
	__TRANS_MAX,
};

static const struct blobmsg_policy trans_policy[] = {
	[TRANS_ID] = { .name = "transaction_id", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy trans_start_policy[] = {
	[TRANS_APP_NAME] = { .name = "app", .type = BLOBMSG_TYPE_STRING },
	[TRANS_TIMEOUT] = { .name = "max_timeout", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	TRANS_COMMIT_ID,
	TRANS_COMMIT_RESTART,
	__TRANS_COMMIT_MAX,
};
static const struct blobmsg_policy trans_commit_policy[] = {
	[TRANS_COMMIT_ID] = { .name = "transaction_id", .type = BLOBMSG_TYPE_INT32 },
	[TRANS_COMMIT_RESTART] = { .name = "restart_services", .type = BLOBMSG_TYPE_INT8 },
};

int usp_transaction_commit_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct blob_attr *tb[__TRANS_COMMIT_MAX] = {NULL};
	struct blob_buf bb;
	int trans_id = 0, ret;
	bool is_service_restart = true;

	INFO("ubus method|%s|, name|%s|", method, obj->name);

	if (blobmsg_parse(trans_commit_policy, __TRANS_COMMIT_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[TRANS_COMMIT_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	trans_id = blobmsg_get_u32(tb[TRANS_COMMIT_ID]);

	if (tb[TRANS_COMMIT_RESTART])
		is_service_restart = blobmsg_get_bool(tb[TRANS_COMMIT_RESTART]);

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	ret = transaction_commit(trans_id, &bb, is_service_restart);
	blobmsg_add_u8(&bb, "status", (ret == 0));

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int usp_transaction_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct blob_attr *tb[__TRANS_MAX] = {NULL};
	struct blob_buf bb;
	int trans_id = 0, ret;
	const char *app = NULL;
	uint32_t max_timeout = 0;

	INFO("ubus method|%s|, name|%s|", method, obj->name);

	if (strcmp(method, "transaction_start") == 0) {
		if (blobmsg_parse(trans_start_policy, __TRANS_MAX, tb, blob_data(msg), blob_len(msg))) {
			ERR("Failed to parse blob");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		if (!tb[TRANS_APP_NAME])
			return UBUS_STATUS_INVALID_ARGUMENT;

		app = blobmsg_get_string(tb[TRANS_APP_NAME]);
		if (tb[TRANS_TIMEOUT])
			max_timeout = blobmsg_get_u32(tb[TRANS_TIMEOUT]);
	} else {
		if (blobmsg_parse(trans_policy, __TRANS_MAX, tb, blob_data(msg), blob_len(msg))) {
			ERR("Failed to parse blob");
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		if (!tb[TRANS_ID])
			return UBUS_STATUS_INVALID_ARGUMENT;

		trans_id = blobmsg_get_u32(tb[TRANS_ID]);
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (strcmp(method, "transaction_start") == 0) {
		ret = transaction_start(app, max_timeout);
		if (ret) {
			blobmsg_add_u8(&bb, "status", true);
			blobmsg_add_u32(&bb, "transaction_id", ret);
		} else {
			blobmsg_add_u8(&bb, "status", false);
		}
	} else if (strcmp(method, "transaction_abort") == 0) {
		ret = transaction_abort(trans_id);
		blobmsg_add_u8(&bb, "status", (ret == 0));
	} else if (strcmp(method, "transaction_status") == 0) {
		fill_transaction_status(&bb, trans_id);
	} else {
		WARNING("method(%s) not supported", method);
	}

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static struct ubus_method usp_raw_methods[] = {
	UBUS_METHOD_NOARG("dump_schema", usp_list_schema),
	UBUS_METHOD_NOARG("list_operate", usp_list_operate),
	UBUS_METHOD_NOARG("list_events", usp_list_events),
	UBUS_METHOD("get_supported_dm", usp_list_supported_dm, get_supported_dm_policy),
	UBUS_METHOD("get", usp_get_handler, dm_get_policy),
	UBUS_METHOD("getm_values", usp_getm_values, dm_getm_policy),
	UBUS_METHOD("getm_names", usp_getm_names, dm_getm_policy),
	UBUS_METHOD("object_names", usp_get_handler, dm_get_policy),
	UBUS_METHOD("instances", usp_get_handler, dm_get_policy),
	UBUS_METHOD("validate", usp_get_handler, dm_get_policy),
	UBUS_METHOD("transaction_start", usp_transaction_handler, trans_start_policy),
	UBUS_METHOD("set", usp_raw_set, dm_raw_set_policy),
	UBUS_METHOD("operate", usp_operate, dm_operate_policy),
	UBUS_METHOD("add_object", usp_raw_add_del_handler, dm_raw_add_policy),
	UBUS_METHOD("del_object", usp_raw_add_del_handler, dm_raw_add_policy),
	UBUS_METHOD("setm_values", handle_set_multi_value, dm_set_multi_policy),
	UBUS_METHOD("transaction_commit", usp_transaction_commit_handler, trans_commit_policy),
	UBUS_METHOD("transaction_abort", usp_transaction_handler, trans_policy),
	UBUS_METHOD("transaction_status", usp_transaction_handler, trans_policy),
	UBUS_METHOD("notify_event", usp_notify_event, dm_notify_event_policy),
};

static void test_client_subscribe_cb(USP_ATTR_UNUSED struct ubus_context *ctx,
				     struct ubus_object *obj)
{
	INFO("usp obj_name(%s), active Subscriber[%d]", obj->name, obj->has_subscribers);
}

static int usp_add_ubus_object(struct usp_context *u, char *name,
			       struct ubus_method *m, int method_count)
{
	int retval = UBUS_STATUS_OK;
	struct ubus_object *obj;
	struct ubus_object_type *type;
	char *obj_name;

	obj = (struct ubus_object *) calloc(1, sizeof(*obj));
	if (!obj) {
		ERR("Out of memory!!");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	type = (struct ubus_object_type *) calloc(1, sizeof(struct ubus_object_type));
	if (!type) {
		ERR("Out of memory!!");
		free(obj);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	obj_name = strdup(name);

	type->name = obj_name;
	type->id = 0;
	type->methods = m;
	type->n_methods = method_count;

	obj->name = obj_name;
	obj->type = type;
	obj->methods = m;
	obj->n_methods = method_count;
	obj->subscribe_cb = test_client_subscribe_cb;

	retval = ubus_add_object(&u->ubus_ctx, obj);
	if (retval)
		ERR("Failed to add 'usp' ubus object: %s\n", ubus_strerror(retval));

	if (strcmp(name, USPRAW) == 0)
		u->notify_object = obj;

	add_ubus_obj(obj, &u->obj_list);

	return retval;
}

static int add_granular_objects(struct usp_context *u, uint8_t gn_level)
{
	int fault;
	char obj_path[PATH_MAX];
	struct pathNode *pnode;
	int m_num;

	LIST_HEAD(path_list);

	get_granural_object_paths(&path_list, gn_level);

	fault = UBUS_STATUS_OK;
	m_num = ARRAY_SIZE(usp_methods);
	list_for_each_entry(pnode, &path_list, list) {
		snprintf(obj_path, PATH_MAX, "%s.%s", USP, pnode->path);
		fault = usp_add_ubus_object(u, obj_path, usp_methods, m_num);

		if (fault != UBUS_STATUS_OK)
			break;
	}

	free_path_list(&path_list);

	return fault;
}

static int usp_init(struct usp_context *u)
{
	int ret;
	uint8_t gran_level;
	char *temp = NULL;
	int m_num;

	INFO("Registering ubus objects....");

	get_uci_option_string("uspd", "usp", "loglevel", &temp);
	if (temp) {
		uint8_t log_level = (uint8_t) strtoul(temp, NULL, 10);
		set_debug_level(log_level);
		free(temp);
	}

	get_uci_option_string("uspd", "usp", "subprocess_level", &temp);
	if (temp) {
		g_subprocess_level = (uint8_t) strtoul(temp, NULL, 10);
		free(temp);
	}

	gran_level = 0;
	get_uci_option_string("uspd", "usp", "granularitylevel", &temp);
	if (temp) {
		gran_level = (uint8_t) strtoul(temp, NULL, 10);
		free(temp);
	}
	if (gran_level > MAX_GRANURALITY_DEPTH)
		gran_level = MAX_GRANURALITY_DEPTH;

	get_uci_option_string("uspd", "usp", "bbf_caching_time", &temp);
	if (temp) {
		uint8_t bbf_cache_time = (uint8_t) strtoul(temp, NULL, 10);
		dm_ctx_init_cache(bbf_cache_time);
		free(temp);
	}

	get_uci_option_string("uspd", "usp", "dm_version", &temp);
	if(temp){
		set_datamodel_version(temp);
		free (temp);
	}

	m_num = ARRAY_SIZE(usp_methods);
	ret = usp_add_ubus_object(u, USP, usp_methods, m_num);
	if (ret)
		return ret;

	m_num = ARRAY_SIZE(usp_raw_methods);
	ret = usp_add_ubus_object(u, USPRAW, usp_raw_methods, m_num);
	if (ret)
		return ret;

	// Get Granularity level of 'uspd' ubus objects
	if (gran_level)
		ret = add_granular_objects(u, gran_level);

	return ret;
}

bool usp_pre_init(struct usp_context *u)
{
	bool ret = true;
	struct blob_buf bb;
	// Initialize ubus ctx for bbf
	bbf_configure_ubus(&u->ubus_ctx);

	// Initialize dmmap
	init_dmmap();

	// Initialise blobs
	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (bbf_dm_get_supported_dm(&bb, ROOT_NODE, 0, 0) != 0)
		ret = false;

	u->dm_schema_len = blobmsg_len(bb.head);
	blob_buf_free(&bb);

	return ret;
}

static bool is_object_schema_update_available(struct usp_context *u)
{
	size_t ll, min_len;
	bool ret = false;
	struct blob_buf bb;
	void *table;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	// If new parameter gets added it would be a minimum tuple of three params
	table = blobmsg_open_table(&bb, NULL);
	blobmsg_add_string(&bb, "parameter", "Device.");
	blobmsg_add_string(&bb, "writable", "0");
	blobmsg_add_string(&bb, "type", "xsd:string");
	blobmsg_close_table(&bb, table);
	min_len = blobmsg_len(bb.head);
	blob_buf_free(&bb);
	blob_buf_init(&bb, 0);

	ret = bbf_dm_get_supported_dm(&bb, ROOT_NODE, 0, 0);
	if (ret != 0) {
		WARNING("Failed to get schema");
		blob_buf_free(&bb);
		return ret;
	}

	ll = blobmsg_len(bb.head);
	if (ll - u->dm_schema_len > min_len) {
		ERR("DM Schema update available old:new[%zd:%zd]", u->dm_schema_len, ll);
		ret = true;
	}
	u->dm_schema_len = ll;
	blob_buf_free(&bb);

	return ret;
}

static void periodic_process_updater(void)
{
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);
	bbf_dm_get_instances(&bbf_ctx, ROOT_NODE"DeviceInfo.ProcessStatus.Process.", "0");
	bbf_cleanup(&bbf_ctx);
}

static void periodic_schema_updater(struct uloop_timeout *t)
{
	bool ret;
	struct usp_context *u;
	struct blob_buf bb;

	u = container_of(t, struct usp_context, schema_timer);
	if (u == NULL) {
		ERR("Failed to get the usp context");
		return;
	}

	if (is_transaction_running()) {
		DEBUG("Transaction ongoing, schedule schema update timer after %dsec", SCHEMA_UPDATE_TIMEOUT);
		u->schema_timer.cb = periodic_schema_updater;
		uloop_timeout_set(&u->schema_timer, SCHEMA_UPDATE_TIMEOUT);
		return;
	}

	memset(&bb, 0, sizeof(struct blob_buf));

	ret = is_object_schema_update_available(u);
	if (ret) {
		INFO("Schema update available");
		blob_buf_init(&bb, 0);
		blobmsg_add_string(&bb, "action", "schema_update_available");
		ubus_notify(&u->ubus_ctx, u->notify_object, "usp.raw", bb.head, 1000);
		blob_buf_free(&bb);
	}

	periodic_process_updater();

	DEBUG("Creating timer for schema update checker(%d) ##", u->notify_object->id);
	u->schema_timer.cb = periodic_schema_updater;
	uloop_timeout_set(&u->schema_timer, SCHEMA_UPDATE_TIMEOUT);
}

enum inst_type {
	GET_INST_PARMS,
	__GET_INST_MAX
};

enum param_type {
	INST_PARM_NAME,
	__INST_PARM_MAX
};

const struct blobmsg_policy inst_policy[__GET_INST_MAX] = {
	[GET_INST_PARMS] = { .name = "parameters", .type = BLOBMSG_TYPE_ARRAY },
};

const struct blobmsg_policy param_policy[__INST_PARM_MAX] = {
	[INST_PARM_NAME] = { .name = "parameter", .type = BLOBMSG_TYPE_STRING },
};

static void broadcast_add_del_event(struct list_head *inst, bool is_add)
{
	struct ubus_context ctx;
	struct blob_buf bb;
	struct pathNode *ptr;
	void *a;
	int ret;

	if (list_empty(inst)) {
		return;
	}

	ret = ubus_connect_ctx(&ctx, NULL);
	if (ret != UBUS_STATUS_OK) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return;
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	a = blobmsg_open_array(&bb, "instances");
	list_for_each_entry(ptr, inst, list) {
		blobmsg_add_string(&bb, NULL, ptr->path);
		DEBUG("#%s:: %s #", (is_add)?"Add":"Del", ptr->path);
	}
	blobmsg_close_array(&bb, a);

	if (is_add)
		ubus_send_event(&ctx, USP_ADD_EVENT, bb.head);
	else
		ubus_send_event(&ctx, USP_DEL_EVENT, bb.head);

	blob_buf_free(&bb);
	ubus_shutdown(&ctx);
}

static void update_instances_list(struct list_head *inst)
{
	struct dmctx bbf_ctx;

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	set_bbfdatamodel_type(BBFDM_USP);
	bbf_init(&bbf_ctx, INSTANCE_MODE_NUMBER);

	if (0 == bbf_dm_get_instances(&bbf_ctx, ROOT_NODE, "0")) {
		struct dm_parameter *nptr_dp;

		list_for_each_entry(nptr_dp, &bbf_ctx.list_parameter, list) {
			add_path_node(nptr_dp->name, inst);
		}
	}
	bbf_cleanup(&bbf_ctx);
}

static void instance_fork_done(struct uloop_process *p, int ret)
{
	struct uspd_async_req *r = container_of(p, struct uspd_async_req, process);

	if (r) {
		INFO("Instance updater(%d) completed, starting a new instance timer", r->process.pid);
		struct usp_context *u = (struct usp_context *)r->result;

		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, g_refresh_time);
		free_path_list(&u->old_instances);
		async_req_free(r);
	}
	if (ret) {
		DEBUG("Instance updater cb failed %d", ret);
	}
}

void instance_compare_publish(struct list_head *new_inst, struct list_head *old_inst)
{
	struct pathNode *ptr;
	LIST_HEAD(inst_list);

	list_for_each_entry(ptr, old_inst, list) {
		if (!present_in_path_list(new_inst, ptr->path)) {
			add_path_node(ptr->path, &inst_list);
		}
	}
	broadcast_add_del_event(&inst_list, false);
	free_path_list(&inst_list);

	list_for_each_entry(ptr, new_inst, list) {
		if (!present_in_path_list(old_inst, ptr->path)) {
			add_path_node(ptr->path, &inst_list);
		}
	}
	broadcast_add_del_event(&inst_list, true);
	free_path_list(&inst_list);
}

static int fork_instance_checker(struct usp_context *u)
{
	struct uspd_async_req *r = NULL;
	pid_t child;

	r = async_req_new();
	if (r == NULL) {
		ERR("Error allocating instance req");
		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, g_refresh_time);
		free_path_list(&u->old_instances);
		goto err_out;
	}
	child = fork();
	if (child == 0) {
		prctl(PR_SET_NAME, (unsigned long) "usp_instance");
		// child initialise signal to prevent segfaults
		signal_init();
		/* free fd's and memory inherited from parent */
		ubus_shutdown(&u->ubus_ctx);
		bbf_configure_ubus(NULL);
		uloop_done();
		async_req_free(r);
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		DEBUG("subprocess instances checker");
		instance_compare_publish(&u->instances, &u->old_instances);
		usp_cleanup(u);
		closelog();
		/* write result and exit */
		exit(EXIT_SUCCESS);
	}

	// parent
	DEBUG("Creating instance checker process child %d", child);
	r->result = u;
	r->process.pid = child;
	r->process.cb = instance_fork_done;
	uloop_process_add(&r->process);
	return 0;

err_out:
	if (r)
		async_req_free(r);

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static void periodic_instance_updater(struct uloop_timeout *t)
{
	struct usp_context *u;

	u = container_of(t, struct usp_context, instance_timer);
	if (u == NULL) {
		ERR("Failed to get the usp context");
		return;
	}

	if (is_transaction_running()) {
		DEBUG("Transaction ongoing, schedule refresh timer after 1s");
		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, 1000);
		return;
	}

	if (list_empty(&u->instances)) {
		update_instances_list(&u->instances);
		DEBUG("Creating timer for instance update checker, init instances");
		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, g_refresh_time);
		return;
	}

	list_splice_init(&u->instances, &u->old_instances);
	update_instances_list(&u->instances);

	// fork a process and send it to compare, when process completes
	// delete the old instances and add a new timer
	fork_instance_checker(u);
}

bool usp_cleanup(struct usp_context *u)
{
	free_ubus_obj_list(&u->obj_list);
	free_path_list(&u->instances);
	free_path_list(&u->old_instances);
	bbf_dm_cleanup(DM_ROOT_OBJ);

	return true;
}

void sig_handler(int sig)
{
	if (sig == SIGSEGV) {
		handle_pending_signal(sig);
	} else if (sig == SIGUSR1) {
		print_last_dm_object();
	}
}

void signal_init()
{
	signal(SIGSEGV, sig_handler);
	signal(SIGUSR1, sig_handler);
}

void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -s <socket path>   ubus socket\n");
	fprintf(stderr, "    -t <timeout>       Transaction timeout in sec\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct usp_context usp_ctx;
	const char *ubus_socket = NULL;
	int ret = 0, ch;

	while ((ch = getopt(argc, argv, "hs:t:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 't':
			configure_transaction_timeout(strtol(optarg, NULL, 10));
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	openlog("uspd", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	memset(&usp_ctx, 0, sizeof(struct usp_context));
	INIT_LIST_HEAD(&usp_ctx.obj_list);
	INIT_LIST_HEAD(&usp_ctx.instances);
	INIT_LIST_HEAD(&usp_ctx.old_instances);
	INIT_LIST_HEAD(&usp_ctx.event_handlers);

	uloop_init();

	ret = ubus_connect_ctx(&usp_ctx.ubus_ctx, ubus_socket);
	if (ret != UBUS_STATUS_OK) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}
	signal_init();

	ret = register_events_to_ubus(&usp_ctx.ubus_ctx, &usp_ctx.event_handlers);
	if (ret != 0) {
		goto exit;
	}

	ubus_add_uloop(&usp_ctx.ubus_ctx);
	usp_pre_init(&usp_ctx);

	ret = usp_init(&usp_ctx);
	if (ret != UBUS_STATUS_OK) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto exit;
	}

	usp_ctx.schema_timer.cb = periodic_schema_updater;
	uloop_timeout_set(&usp_ctx.schema_timer, SCHEMA_UPDATE_TIMEOUT);

	g_refresh_time = get_refresh_time();
	if (g_refresh_time != 0) {
		usp_ctx.instance_timer.cb = periodic_instance_updater;
		// initial timer should be bigger to give more space to other applications
		// to initialize
		uloop_timeout_set(&usp_ctx.instance_timer, 3 * g_refresh_time);
	}

	INFO("Waiting on uloop....");
	uloop_run();

exit:
	free_ubus_event_handler(&usp_ctx.ubus_ctx, &usp_ctx.event_handlers);
	ubus_shutdown(&usp_ctx.ubus_ctx);
	bbf_configure_ubus(NULL);
	uloop_done();
	usp_cleanup(&usp_ctx);
	closelog();

	return ret;
}
