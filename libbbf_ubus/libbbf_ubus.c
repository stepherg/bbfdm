/*
 * Copyright (C) 2021 Iopsys Software Solutions AB
 *
 * Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
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

#include <stdio.h>
#include <stdlib.h>
#include <libubox/blobmsg.h>
#include "dmentry.h"
#include "dmbbfcommon.h"
#include "libbbf_ubus.h"

#define PATH_MAX	4096

struct obj_node {
	struct ubus_object *ob;
	struct ubus_object_type *ob_type;
	char *obj_name;
	DMOBJ *tUsrObj;
	struct obj_node *next;
};

enum {                                                                          
	LIBBBF_UBUS_GET_PATH,
	LIBBBF_UBUS_GET_PROTO,
        __LIBBBF_UBUS_GET_MAX
};

enum {                                                                          
	LIBBBF_UBUS_SET_PATH,
	LIBBBF_UBUS_SET_VALUE,
	LIBBBF_UBUS_SET_PROTO,
        __LIBBBF_UBUS_SET_MAX
};

enum {                                                                          
	LIBBBF_UBUS_OPERATE_PATH,
	LIBBBF_UBUS_OPERATE_INPUT,
        __LIBBBF_UBUS_OPERATE_MAX
};

enum {                                                                          
	LIBBBF_UBUS_SUPPORTED_PATH,
	LIBBBF_UBUS_SUPPORTED_PROTO,
	LIBBBF_UBUS_SUPPORTED_NXT_LEVEL,
	LIBBBF_UBUS_SUPPORTED_SCHEMA_TYPE,
        __LIBBBF_UBUS_SUPPORTED_MAX
};

enum {                                                                          
	LIBBBF_UBUS_ADD_DEL_PATH,
	LIBBBF_UBUS_ADD_DEL_PROTO,
        __LIBBBF_UBUS_ADD_DEL_MAX
};

static bool g_dynamicdm_transaction_start = false;
static struct obj_node *g_dynamicdm_head = NULL;

static int libbbf_ubus_supported_dm(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method __attribute__((unused)),
			struct blob_attr *msg);

static int libbbf_ubus_get_handler(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg);

static int libbbf_ubus_set_handler(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg);

static int libbbf_ubus_operate(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg);

static int libbbf_ubus_add_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg);

static int libbbf_ubus_transaction_handler(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg);

static const struct blobmsg_policy libbbf_ubus_supported_dm_policy[] = {
	[LIBBBF_UBUS_SUPPORTED_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_SUPPORTED_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_SUPPORTED_NXT_LEVEL] = { .name = "next-level", .type = BLOBMSG_TYPE_INT8},
	[LIBBBF_UBUS_SUPPORTED_SCHEMA_TYPE] = { .name = "schema_type", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy libbbf_ubus_get_policy[] = {
	[LIBBBF_UBUS_GET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_GET_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING }
};

static const struct blobmsg_policy libbbf_ubus_set_policy[] = {
	[LIBBBF_UBUS_SET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_SET_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_SET_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING }
};

static const struct blobmsg_policy libbbf_ubus_operate_policy[] = {      
	[LIBBBF_UBUS_OPERATE_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_OPERATE_INPUT] = { .name = "input", .type = BLOBMSG_TYPE_TABLE }
};

static const struct blobmsg_policy libbbf_ubus_add_del_policy[] = {
	[LIBBBF_UBUS_ADD_DEL_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[LIBBBF_UBUS_ADD_DEL_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING }
};

static struct ubus_method libbbf_ubus_methods[] = {                                 
        UBUS_METHOD("get_supported_dm", libbbf_ubus_supported_dm, libbbf_ubus_supported_dm_policy),
        UBUS_METHOD("get", libbbf_ubus_get_handler, libbbf_ubus_get_policy),
        UBUS_METHOD("set", libbbf_ubus_set_handler, libbbf_ubus_set_policy),
        UBUS_METHOD("operate", libbbf_ubus_operate, libbbf_ubus_operate_policy),
        UBUS_METHOD("add_object", libbbf_ubus_add_del_handler, libbbf_ubus_add_del_policy),
        UBUS_METHOD("del_object", libbbf_ubus_add_del_handler, libbbf_ubus_add_del_policy),
        UBUS_METHOD_NOARG("transaction_start", libbbf_ubus_transaction_handler),
        UBUS_METHOD_NOARG("transaction_abort", libbbf_ubus_transaction_handler),
        UBUS_METHOD_NOARG("transaction_commit", libbbf_ubus_transaction_handler),
};

static int get_protocol(const char *val)
{
	int type;

	if (DM_LSTRCMP(val, "cwmp") == 0)
		type = BBFDM_CWMP;
	else if (DM_LSTRCMP(val, "usp") == 0)
		type = BBFDM_USP;
	else
		type = BBFDM_BOTH;

	return type;
}

static int get_bbf_proto_type(struct blob_attr *proto)
{
	int type;

	if (proto) {
		const char *val = blobmsg_get_string(proto);
		type = get_protocol(val);
	} else {
		type = BBFDM_BOTH;
	}

	return type;
}

static void bb_add_string(struct blob_buf *bb, const char *name, const char *value)
{
	if (value)
		blobmsg_add_string(bb, name, value);
	else
		blobmsg_add_string(bb, name, "");
}

static struct obj_node* find_obj_node(const char *ubus_name)
{
	struct obj_node *temp = g_dynamicdm_head;
	if (temp == NULL)
		return NULL;

	while (DM_STRCMP(ubus_name, temp->obj_name) != 0) {
		if (temp->next == NULL) {
			return NULL;
		} else {
			temp = temp->next;
		}
	}

	return temp;
}

static DMOBJ* get_entry_object(const char *name)
{
	if (!name)
		return NULL;

	struct obj_node *ob_node = find_obj_node(name);
	if (!ob_node)
		return NULL;

	return ob_node->tUsrObj;
}

static void fill_operate_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter",param->name);
	blobmsg_add_string(bb,"type",param->type);
	blobmsg_add_string(bb,"cmd_type",param->additional_data);

	if(param->data) {
		const char **in, **out = NULL;
		operation_args *args = NULL;
		void *array = NULL;
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
		event_args *ev = NULL;

		ev = (event_args *)param->data;

		if (ev->param) {
			const char **in = NULL;
			void *key = NULL;
			int i;

			in = ev->param;
			key = blobmsg_open_array(bb, "in");
			for (i = 0; in[i] != NULL; i++)
				blobmsg_add_string(bb, NULL, in[i]);
			blobmsg_close_array(bb, key);
		}
	}
}

static void fill_param_schema(struct blob_buf *bb, struct dm_parameter *param)
{
	blobmsg_add_string(bb, "parameter", param->name);
	blobmsg_add_string(bb, "writable", param->data ? param->data : "0");
	blobmsg_add_string(bb, "type", param->type);

	if (param->additional_data) {
		const char **uniq_keys = NULL;
		void *key = NULL;
		int i;

		uniq_keys = (const char **)param->additional_data;
		key = blobmsg_open_array(bb, "unique_keys");
		for (i = 0; uniq_keys[i] != NULL; i++)
			blobmsg_add_string(bb, NULL, uniq_keys[i]);

		blobmsg_close_array(bb, key);
	}
}

static int handle_add_del_req(struct ubus_context *ctx, const char *ubus_name, struct ubus_request_data *req,
				char *path, const char *method, int proto)
{
	int fault = 0;
	struct dmctx bbf_ctx;
	struct blob_buf bb;
	char *pkey = "true";

	DMOBJ *tEntryObj = get_entry_object(ubus_name);
	if (!tEntryObj) {
		printf("Failed to get DM entry obj\n\r");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (!g_dynamicdm_transaction_start) {
		printf("Transaction not started\n\r");
		blobmsg_add_u32(&bb, "fault", usp_fault_map(USP_FAULT_INTERNAL_ERROR));
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	set_bbfdatamodel_type(proto);
	dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);

	if (DM_LSTRCMP(method, "add_object") == 0) {
		fault = dm_entry_param_method(&bbf_ctx, CMD_ADD_OBJECT, path, pkey, NULL);
	} else {
		fault = dm_entry_param_method(&bbf_ctx, CMD_DEL_OBJECT, path, pkey, NULL);
	}

	void *array = blobmsg_open_array(&bb, "parameters");
	void *table = blobmsg_open_table(&bb, NULL);

	bb_add_string(&bb, "parameter", path);
	if (fault) {
		blobmsg_add_u32(&bb, "fault", fault);
		blobmsg_add_u8(&bb, "status", 0);
	} else {
		if (DM_LSTRCMP(method, "add_object") == 0) {
			if (bbf_ctx.addobj_instance) {
				blobmsg_add_u8(&bb, "status", 1);
				bb_add_string(&bb, "instance", bbf_ctx.addobj_instance);
			} else {
				blobmsg_add_u8(&bb, "status", 0);
			}
		} else {
			blobmsg_add_u8(&bb, "status", 1);
		}
	}

	blobmsg_close_table(&bb, table);
	blobmsg_close_array(&bb, array);

	dm_ctx_clean(&bbf_ctx);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static void libbbf_ubus_obj_node_free(struct obj_node *obj)
{
	if (!obj)
		return;

	if (obj->ob_type)
		FREE(obj->ob_type);

	if (obj->ob)
		FREE(obj->ob);

	if (obj->obj_name)
		FREE(obj->obj_name);

	FREE(obj);
}

static int libbbf_ubus_supported_dm(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method __attribute__((unused)),
			struct blob_attr *msg)
{
	struct blob_attr *tb[__LIBBBF_UBUS_SUPPORTED_MAX];
	char path[PATH_MAX] = {0};
	bool nxt_lvl = false;
	uint32_t schema_type = 0;
	struct blob_buf bb;
	int fault = 0, proto;
	struct dmctx bbf_ctx;

	if (blobmsg_parse(libbbf_ubus_supported_dm_policy, __LIBBBF_UBUS_SUPPORTED_MAX, tb, blob_data(msg), blob_len(msg)) == 0) {
		if (tb[LIBBBF_UBUS_SUPPORTED_PATH])
			snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[LIBBBF_UBUS_SUPPORTED_PATH]));

		if (tb[LIBBBF_UBUS_SUPPORTED_NXT_LEVEL])
			nxt_lvl = blobmsg_get_bool(tb[LIBBBF_UBUS_SUPPORTED_NXT_LEVEL]);

		if (tb[LIBBBF_UBUS_SUPPORTED_SCHEMA_TYPE])
			schema_type = blobmsg_get_u32(tb[LIBBBF_UBUS_SUPPORTED_SCHEMA_TYPE]);
	}

	DMOBJ *tEntryObj = get_entry_object(obj->name);
	if (!tEntryObj) {
		printf("Failed to get DM entry obj\n\r");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	proto = get_bbf_proto_type(tb[LIBBBF_UBUS_SUPPORTED_PROTO]);
	set_bbfdatamodel_type(proto);

	dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);

	fault = dm_get_supported_dm(&bbf_ctx, path, nxt_lvl, schema_type);
	if(fault) {
		blobmsg_add_u32(&bb, "fault", fault);
	} else {
		struct dm_parameter *param = NULL;
		void *array = NULL, *table = NULL;

		array = blobmsg_open_array(&bb,"parameters");
		list_for_each_entry(param, &bbf_ctx.list_parameter, list) {
			int cmd = get_dm_type(param->type);

			table = blobmsg_open_table(&bb, NULL);
			if (cmd == DMT_COMMAND) {
				fill_operate_schema(&bb, param);
			} else if (cmd == DMT_EVENT) {
				fill_event_schema(&bb, param);
			} else {
				fill_param_schema(&bb, param);
			}

			blobmsg_close_table(&bb, table);
		}
		blobmsg_close_array(&bb, array);
	}

	ubus_send_reply(ctx, req, bb.head);

	blob_buf_free(&bb);
	dm_ctx_clean(&bbf_ctx);

	return fault;
}

static void init_dm_path(DMOBJ *tEntryObj)
{
	struct dmctx bbf_ctx;
	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	set_bbfdatamodel_type(BBFDM_BOTH);

	dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);

	dm_entry_param_method(&bbf_ctx, CMD_GET_VALUE, "", NULL, NULL);

	dm_ctx_clean(&bbf_ctx);
}

static int libbbf_ubus_get_handler(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg)
{
	struct blob_attr *tb[__LIBBBF_UBUS_GET_MAX] = {NULL};
	char path[PATH_MAX] = {0};
	struct dmctx bbf_ctx;
	struct blob_buf bb;
	int fault = 0, proto;

	if (blobmsg_parse(libbbf_ubus_get_policy, __LIBBBF_UBUS_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		printf("Failed to parse blob\n");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[LIBBBF_UBUS_GET_PATH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	DMOBJ *tEntryObj = get_entry_object(obj->name);
	if (!tEntryObj) {
		printf("Failed to get DM entry obj\n\r");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[LIBBBF_UBUS_GET_PATH]));

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	proto = get_bbf_proto_type(tb[LIBBBF_UBUS_GET_PROTO]);
	set_bbfdatamodel_type(proto);
	dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);

	fault = dm_entry_param_method(&bbf_ctx, CMD_GET_VALUE, path, NULL, NULL);

	if (!fault) {
		struct dm_parameter *n = NULL;

		void *array = blobmsg_open_array(&bb, "parameters");
		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			void *table = blobmsg_open_table(&bb, NULL);
			bb_add_string(&bb, "parameter", n->name);
			bb_add_string(&bb, "value", n->data);
			bb_add_string(&bb, "type", n->type);
			blobmsg_close_table(&bb, table);
		}
		blobmsg_close_array(&bb, array);
	} else {
		blobmsg_add_u32(&bb, "fault", fault);
	}

	ubus_send_reply(ctx, req, bb.head);

	blob_buf_free(&bb);
	dm_ctx_clean(&bbf_ctx);

	return fault;
}

static int libbbf_ubus_operate(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		struct ubus_request_data *req, const char *method __attribute__((unused)),
		struct blob_attr *msg)
{
	struct blob_attr *tb[__LIBBBF_UBUS_OPERATE_MAX] = {NULL};
	char path[PATH_MAX] = {0};
	char *input = NULL;
	struct blob_buf bb;
	struct dmctx bbf_ctx;
	int fault = 0, len;

	if (blobmsg_parse(libbbf_ubus_operate_policy, __LIBBBF_UBUS_OPERATE_MAX, tb, blob_data(msg), blob_len(msg))) {
		printf("Failed to parse blob\n\r");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[LIBBBF_UBUS_OPERATE_PATH]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[LIBBBF_UBUS_OPERATE_INPUT])
		input = blobmsg_format_json(tb[LIBBBF_UBUS_OPERATE_INPUT], true);

	DMOBJ *tEntryObj = get_entry_object(obj->name);
	if (!tEntryObj) {
		printf("Failed to get DM entry obj\n\r");
		if (input)
			free(input);

		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[LIBBBF_UBUS_OPERATE_PATH]));

	len = DM_STRLEN(path);
	if (len == 0) {
		if (input)
			free(input);

		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (path[len - 1] == '.') {
		printf("path can't end with (.)\n\r");
		if (input)
			free(input);

		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	set_bbfdatamodel_type(BBFDM_USP);
	dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);

	fault = dm_entry_param_method(&bbf_ctx, CMD_USP_OPERATE, path, input, NULL);

	switch (fault) {
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
		fault = 0;
		break;
	default:
		printf("Case(%d) not found\n\r", fault);
		fault = USP_FAULT_INVALID_PATH;
		break;
	}

	void *array = blobmsg_open_array(&bb, "Results");
	void *table = blobmsg_open_table(&bb, NULL);
	blobmsg_add_string(&bb, "path", path);

	if (fault == 0) {
		struct dm_parameter *n = NULL;

		void *array_in = blobmsg_open_array(&bb, "parameters");
		list_for_each_entry(n, &bbf_ctx.list_parameter, list) {
			void *table_in = blobmsg_open_table(&bb, NULL);
			bb_add_string(&bb, "parameter", n->name);
			bb_add_string(&bb, "value", n->data);
			bb_add_string(&bb, "type", n->type);
			blobmsg_close_table(&bb, table_in);
		}
		blobmsg_close_array(&bb, array_in);
	} else {
		fault = usp_fault_map(fault);
		blobmsg_add_u32(&bb, "fault", fault);
	}

	blobmsg_close_table(&bb, table);
	blobmsg_close_array(&bb, array);

	dm_ctx_clean(&bbf_ctx);
	ubus_send_reply(ctx, req, bb.head);

	blob_buf_free(&bb);

	if (input)
		free(input);

	return 0;
}

static int libbbf_ubus_add_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__LIBBBF_UBUS_ADD_DEL_MAX] = {NULL};
	char path[PATH_MAX] = {0};
	int plen, proto;

	if (blobmsg_parse(libbbf_ubus_add_del_policy, __LIBBBF_UBUS_ADD_DEL_MAX, tb, blob_data(msg), blob_len(msg))) {
		printf("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[LIBBBF_UBUS_ADD_DEL_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[LIBBBF_UBUS_ADD_DEL_PATH]));

	plen = DM_STRLEN(path);
	if (plen == 0) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (path[plen - 1] != '.') {
		if (plen > PATH_MAX - 2) {
			printf("path too long(%d) can't append (.)\n\r", plen);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
		strcat(path, ".");
	}

	proto = get_bbf_proto_type(tb[LIBBBF_UBUS_ADD_DEL_PROTO]);
	return handle_add_del_req(ctx, obj->name, req, path, method, proto);
}

static int libbbf_ubus_set_handler(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_buf bb;
	struct blob_attr *tb[__LIBBBF_UBUS_SET_MAX] = {NULL};
	char path[PATH_MAX] = {'\0'}, value[PATH_MAX] = {'\0'};
	int fault = 0, proto;
	void *array = NULL, *table = NULL;
	struct dmctx bbf_ctx;
	bool fault_occured = false;

	if (blobmsg_parse(libbbf_ubus_set_policy, __LIBBBF_UBUS_SET_MAX, tb, blob_data(msg), blob_len(msg))) {
		printf("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[LIBBBF_UBUS_SET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!tb[LIBBBF_UBUS_SET_VALUE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	DMOBJ *tEntryObj = get_entry_object(obj->name);
	if (!tEntryObj) {
		printf("Failed to get DM entry obj\n\r");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[LIBBBF_UBUS_SET_PATH]));
	snprintf(value, PATH_MAX, "%s", (char *)blobmsg_data(tb[LIBBBF_UBUS_SET_VALUE]));

	int plen = DM_STRLEN(path);
	if (plen == 0) {
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (path[plen - 1] == '.') {
		printf("path can't end with (.)\n\r");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (!g_dynamicdm_transaction_start) {
		printf("Transaction not started\n\r");
		blobmsg_add_u32(&bb, "fault", usp_fault_map(USP_FAULT_INTERNAL_ERROR));
		ubus_send_reply(ctx, req, bb.head);
		blob_buf_free(&bb);
		return 0;
	}

	proto = get_bbf_proto_type(tb[LIBBBF_UBUS_SET_PROTO]);
	set_bbfdatamodel_type(proto);
	memset(&bbf_ctx, 0, sizeof(struct dmctx));
	dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);

	fault = dm_entry_param_method(&bbf_ctx, CMD_SET_VALUE, path, value, NULL);
	if (fault) {
		if (fault_occured == false) {
			fault_occured = true;
			array = blobmsg_open_array(&bb, "parameters");
		}
	}

	while (bbf_ctx.list_fault_param.next != &bbf_ctx.list_fault_param) {
		struct param_fault *p = list_entry(bbf_ctx.list_fault_param.next, struct param_fault, list);
		table = blobmsg_open_table(&bb, NULL);
		bb_add_string(&bb, "path", p->name);
		blobmsg_add_u8(&bb, "status", false);
		blobmsg_add_u32(&bb, "fault", (uint32_t)p->fault);
		blobmsg_close_table(&bb, table);
		del_list_fault_param(p);
	}

	//Apply the parameter
	fault = dm_entry_apply(&bbf_ctx, CMD_SET_VALUE, NULL);
	if (fault == 0 && fault_occured == false) {
		blobmsg_add_u8(&bb, "status", true);
		if (get_bbfdatamodel_type() == BBFDM_CWMP)
			blobmsg_add_u64(&bb, "flag", bbf_ctx.end_session_flag);
	} else {
		if (!array)
			array = blobmsg_open_array(&bb, "parameters");

		while (bbf_ctx.list_fault_param.next != &bbf_ctx.list_fault_param) {
			struct param_fault *p = list_entry(bbf_ctx.list_fault_param.next, struct param_fault, list);
			table = blobmsg_open_table(&bb, NULL);
			bb_add_string(&bb, "path", p->name);
			blobmsg_add_u8(&bb, "status", false);
			blobmsg_add_u32(&bb, "fault", (uint32_t)p->fault);
			blobmsg_close_table(&bb, table);
			del_list_fault_param(p);
		}
	}

	if (array)
		blobmsg_close_array(&bb, array);

	ubus_send_reply(ctx, req, bb.head);

	// free
	blob_buf_free(&bb);
	dm_ctx_clean(&bbf_ctx);

	return 0;
}

static int libbbf_ubus_transaction_handler(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method __attribute__((unused)),
		       struct blob_attr *msg)
{
	struct dmctx bbf_ctx;
	struct blob_buf bb;

	DMOBJ *tEntryObj = get_entry_object(obj->name);
	if (!tEntryObj) {
		printf("Failed to get DM entry obj\n\r");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&bbf_ctx, 0, sizeof(struct dmctx));

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (DM_LSTRCMP(method, "transaction_start") == 0) {
		if (!g_dynamicdm_transaction_start) {
			g_dynamicdm_transaction_start = true;
			blobmsg_add_u8(&bb, "status", true);
		} else {
			printf("Transaction already in process\n");
			blobmsg_add_u8(&bb, "status", false);
		}
	} else if(DM_LSTRCMP(method, "transaction_abort") == 0) {
		if (g_dynamicdm_transaction_start) {
			g_dynamicdm_transaction_start = false;
			dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);
			dm_entry_revert_changes();
			dm_ctx_clean(&bbf_ctx);
			blobmsg_add_u8(&bb, "status", true);
		} else {
			printf("Transaction still not started\n\r");
			blobmsg_add_u8(&bb, "status", false);
		}
	} else if (DM_LSTRCMP(method, "transaction_commit") == 0) {
		if (g_dynamicdm_transaction_start) {
			g_dynamicdm_transaction_start = false;
			dm_ctx_init_entry(&bbf_ctx, tEntryObj, 0);
			dm_entry_manage_services(&bb, true);
			dm_entry_restart_services();
			dm_ctx_clean(&bbf_ctx);
			blobmsg_add_u8(&bb, "status", true);
		} else {
			printf("Transaction still not started\n\r");
			blobmsg_add_u8(&bb, "status", false);
		}
	} else {
		printf("Unsupported method %s\n\r", method);
	}

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int dynamicdm_init(struct ubus_context *ctx, char *ubus_name, DMOBJ *entry)
{
	if (!ctx || !ubus_name || ubus_name[0] == '\0' || !entry)
		return -1;

	struct obj_node *new = (struct obj_node *)malloc(sizeof(struct obj_node));
	if (!new)
		return -1;

	memset(new, 0, sizeof(struct obj_node));
	new->ob = (struct ubus_object *) calloc(1, sizeof(struct ubus_object));
	if (!new->ob) {
		printf("Out of memory!!\n\r");
		libbbf_ubus_obj_node_free(new);
		return -1;
	}

	new->ob_type = (struct ubus_object_type *) calloc(1, sizeof(struct ubus_object_type));
	if (!new->ob_type) {
		printf("Out of memory!!\n\r");
		libbbf_ubus_obj_node_free(new);
		return -1;
	}

	new->obj_name = strdup(ubus_name);

	new->ob_type->name = new->obj_name;
	new->ob_type->id = 0;
	new->ob_type->methods = libbbf_ubus_methods;
	new->ob_type->n_methods = ARRAY_SIZE(libbbf_ubus_methods);

	new->ob->name = new->obj_name;
	new->ob->type = new->ob_type;
	new->ob->methods = libbbf_ubus_methods;
	new->ob->n_methods = ARRAY_SIZE(libbbf_ubus_methods);

	if (ubus_add_object(ctx, new->ob)) {
		printf("Failed to add object.\n\r");
		libbbf_ubus_obj_node_free(new);
		return -1;
	}

	new->tUsrObj = entry;

	new->next = g_dynamicdm_head;
	g_dynamicdm_head = new;

	init_dm_path(entry);

	return 0;
}

int dynamicdm_init_plugin_object(struct ubus_context *ctx, char *ubus_name, DM_MAP_OBJ *entry)
{
	int i;
	DMOBJ *tEntryObj = NULL, *tmp = NULL;

	if (!entry)
		return -1;
	
	for (i = 0; entry[i].path != NULL; i++) {
		tmp = (DMOBJ*)realloc(tEntryObj, sizeof(DMOBJ) * (i+1));
		if (tmp == NULL) {
			FREE(tEntryObj);
			printf("No Memory exists\n\r");
			return -1;
		}

		tEntryObj = tmp;
		memset(&tEntryObj[i], 0, sizeof(DMOBJ));

		tEntryObj[i].obj = entry[i].path;
		tEntryObj[i].permission = &DMREAD;
		tEntryObj[i].nextobj = entry[i].root_obj;
		tEntryObj[i].leaf = entry[i].root_leaf;
		tEntryObj[i].bbfdm_type = BBFDM_BOTH;
	}

	/* Make the last empty entry */
	tmp = (DMOBJ*)realloc(tEntryObj, sizeof(DMOBJ) * (i+1));
	if (tmp == NULL) {
		FREE(tEntryObj);
		printf("No Memory exists\n\r");
		return -1;
	}

	tEntryObj = tmp;
	memset(&tEntryObj[i], 0, sizeof(DMOBJ));

	if (0 != dynamicdm_init(ctx, ubus_name, tEntryObj)) {
		FREE(tEntryObj);
		return -1;
	}

	return 0;
}

void dynamicdm_free(struct ubus_context *ctx, const char *ubus_name)
{
	struct obj_node *curr = g_dynamicdm_head, *prev = NULL;

	if (!ctx|| !ubus_name || ubus_name[0] == '\0')
		return;

	if (curr == NULL)
		return;

	while (DM_STRCMP(ubus_name, curr->obj_name) != 0) {
		if (curr->next == NULL) {
			return;
		} else {
			prev = curr;
			curr = curr->next;
		}
	}

	if (curr == g_dynamicdm_head) {
		g_dynamicdm_head = g_dynamicdm_head->next;
	} else {
		prev->next = curr->next;
	}

	if (curr->tUsrObj)
		dm_cleanup_dynamic_entry(curr->tUsrObj);

	ubus_remove_object(ctx, curr->ob);

	libbbf_ubus_obj_node_free(curr);
}

void dynamicdm_free_plugin_object(struct ubus_context *ctx, const char *ubus_name)
{
	if (!ctx || !ubus_name || ubus_name[0] == '\0')
		return;

	struct obj_node *ob_node = find_obj_node(ubus_name);
	if (!ob_node)
		return;

	dm_cleanup_dynamic_entry(ob_node->tUsrObj);
	FREE(ob_node->tUsrObj);

	dynamicdm_free(ctx, ubus_name);
}
