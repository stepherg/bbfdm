/*
 * bbfdm-ubus.c: bbfdm-ubus API to expose Data Model over ubus
 *
 * Copyright (C) 2023-2025 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include <sys/mman.h>

#include "bbfdm-ubus.h"
#include "set.h"
#include "get.h"
#include "operate.h"
#include "add_delete.h"
#include "events.h"
#include "get_helper.h"
#include "plugin.h"

#define BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH "/usr/share/bbfdm/micro_services"

// Global variables
static void *deamon_lib_handle = NULL;

static void bbfdm_ctx_cleanup(struct bbfdm_context *u)
{
	bbf_global_clean(DEAMON_DM_ROOT_OBJ);

	free_path_list(&u->linker_list);
	free_path_list(&u->obj_list);

	/* DotSo Plugin */
	bbfdm_free_dotso_plugin(u, &deamon_lib_handle);

	/* JSON Plugin */
	bbfdm_free_json_plugin();
}

static bool is_sync_operate_cmd(bbfdm_data_t *data __attribute__((unused)))
{
	return false;
}

static void fill_optional_data(bbfdm_data_t *data, struct blob_attr *msg)
{
	struct blob_attr *tb[1] = {0};
	const struct blobmsg_policy p[1] = {
			{ "proto", BLOBMSG_TYPE_STRING }
	};

	if (!data)
		return;

	data->bbf_ctx.dm_type = BBFDM_BOTH;

	if (!msg)
		return;

	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[0]) {
		const char *val = blobmsg_get_string(tb[0]);
		data->bbf_ctx.dm_type = get_proto_type(val);
		BBF_DEBUG("Proto:|%s|", (data->bbf_ctx.dm_type == BBFDM_BOTH) ? "both" : (data->bbf_ctx.dm_type == BBFDM_CWMP) ? "cwmp" : "usp");
	}
}

static char *get_value_by_reference_path(struct dmctx *ctx, char *reference_path)
{
	char path[MAX_DM_PATH] = {0};
	char key_name[256], key_value[256];
	char *reference_value = NULL;
	regmatch_t pmatch[2];

	if (!ctx || !reference_path)
		return NULL;

	if (!match(reference_path, "\\[(.*?)\\]", 2, pmatch))
		return NULL;

	snprintf(path, pmatch[0].rm_so + 1, "%s", reference_path);
	int len = DM_STRLEN(path);
	if (!len)
		return NULL;

	char *match_str = reference_path + pmatch[1].rm_so;
	if (DM_STRLEN(match_str) == 0)
		return NULL;

	int n = sscanf(match_str, "%255[^=]==\"%255[^\"]\"", key_name, key_value);
	if (n != 2) {
		n = sscanf(match_str, "%255[^=]==%255[^]]", key_name, key_value);
		if (n != 2)
			return NULL;
	}

	snprintf(path + len, sizeof(path) - len, "*.%s", key_name);

	adm_entry_get_reference_param(ctx, path, key_value, &reference_value);

	return reference_value;
}

static void async_req_free(struct bbfdm_async_req *r)
{
	free(r);
}

static void async_complete_cb(struct uloop_process *p, __attribute__((unused)) int ret)
{
	struct bbfdm_async_req *r = container_of(p, struct bbfdm_async_req, process);

	if (r) {
		BBF_INFO("Async call with pid(%d) completes", r->process.pid);
		struct blob_buf *bb = (struct blob_buf *)&r->result;

		ubus_send_reply(r->ctx, &r->req, bb->head);
		BBF_INFO("pid(%d) blob data sent raw(%zu)", r->process.pid, blob_raw_len(bb->head));
		ubus_complete_deferred_request(r->ctx, &r->req, 0);
		munmap(r->result, DEF_IPC_DATA_LEN);
		async_req_free(r);
	}
}

static struct bbfdm_async_req *async_req_new(void)
{
	struct bbfdm_async_req *r = (struct bbfdm_async_req *)calloc(1, sizeof(*r));

	if (r) {
		memset(&r->process, 0, sizeof(r->process));
		r->result = NULL;
	}

	return r;
}

static int bbfdm_start_deferred(bbfdm_data_t *data, void (*EXEC_CB)(bbfdm_data_t *data, void *d))
{
	struct bbfdm_async_req *r = NULL;
	pid_t child;
	struct bbfdm_context *u;
	void *result = NULL;

	result = mmap(NULL, DEF_IPC_DATA_LEN, PROT_READ| PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (result == MAP_FAILED) {
		BBF_ERR("Error creating memory map for result");
		goto err_out;
	}
	memset(result, 0, DEF_IPC_DATA_LEN);
	r = async_req_new();
	if (r == NULL) {
		BBF_ERR("Error allocating async req");
		goto err_out;
	}

	child = fork();
	if (child == -1) {
		BBF_ERR("fork error");
		goto err_out;
	} else if (child == 0) {
		u = container_of(data->ctx, struct bbfdm_context, ubus_ctx);
		if (u == NULL) {
			BBF_ERR("{fork} Failed to get the bbfdm context");
			exit(EXIT_FAILURE);
		}

		/* free fd's and memory inherited from parent */
		uloop_done();
		ubus_shutdown(data->ctx);
		async_req_free(r);
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		BBF_INFO("{fork} Calling from subprocess");
		EXEC_CB(data, result);

		bbfdm_ctx_cleanup(u);
		closelog();
		/* write result and exit */
		exit(EXIT_SUCCESS);
	}

	// parent
	BBF_INFO("Creating bbfdm(%d) sub process(%d) for path(%s)", getpid(), child, data->bbf_ctx.in_param);
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

static const struct blobmsg_policy dm_get_policy[] = {
	[DM_GET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_GET_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE},
};

static int bbfdm_get_handler(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_GET_MAX];
	LIST_HEAD(paths_list);
	bbfdm_data_t data;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_get_policy, __DM_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_GET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	add_path_list(blobmsg_get_string(tb[DM_GET_PATH]), &paths_list);

	data.ctx = ctx;
	data.req = req;
	data.plist = &paths_list;

	fill_optional_data(&data, tb[DM_GET_OPTIONAL]);

	BBF_INFO("ubus method|%s|, name|%s|", method, obj->name);

	bbfdm_get(&data, BBF_GET_VALUE);

	free_path_list(&paths_list);
	return 0;
}

static const struct blobmsg_policy dm_schema_policy[] = {
	[DM_SCHEMA_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SCHEMA_FIRST_LEVEL] = { .name = "first_level", .type = BLOBMSG_TYPE_BOOL},
	[DM_SCHEMA_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE},
};

static int bbfdm_schema_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_SCHEMA_MAX];
	LIST_HEAD(paths_list);
	bbfdm_data_t data;
	struct bbfdm_context *u;

	memset(&data, 0, sizeof(bbfdm_data_t));

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("Failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (blobmsg_parse(dm_schema_policy, __DM_SCHEMA_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_SCHEMA_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	char *path = blobmsg_get_string(tb[DM_SCHEMA_PATH]);
	add_path_list(path, &paths_list);

	fill_optional_data(&data, tb[DM_SCHEMA_OPTIONAL]);

	unsigned int dm_type = data.bbf_ctx.dm_type;

	data.ctx = ctx;
	data.req = req;
	data.bbf_ctx.nextlevel = (tb[DM_SCHEMA_FIRST_LEVEL]) ? blobmsg_get_bool(tb[DM_SCHEMA_FIRST_LEVEL]) : false;
	data.bbf_ctx.iscommand = (dm_type == BBFDM_CWMP) ? false : true;
	data.bbf_ctx.isevent = (dm_type == BBFDM_CWMP) ? false : true;
	data.bbf_ctx.isinfo = (dm_type == BBFDM_CWMP) ? false : true;
	data.plist = &paths_list;

#ifdef BBF_SCHEMA_FULL_TREE
	data.bbf_ctx.isinfo = true;
	bbfdm_get(&data, BBF_SCHEMA);
#else
	if (dm_type == BBFDM_CWMP) {
		char *service_name = strdup(u->config.service_name);
		data.bbf_ctx.in_value = (dm_type == BBFDM_CWMP) ? service_name : NULL;
		bbfdm_get(&data, BBF_GET_NAME);
		FREE(service_name);
	} else {
		bbfdm_get(&data, BBF_SCHEMA);
	}
#endif

	free_path_list(&paths_list);
	return 0;
}

static const struct blobmsg_policy dm_instances_policy[] = {
	[DM_INSTANCES_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_INSTANCES_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE },
};

static int bbfdm_instances_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_INSTANCES_MAX];
	LIST_HEAD(paths_list);
	bbfdm_data_t data;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_instances_policy, __DM_INSTANCES_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_INSTANCES_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	char *path = blobmsg_get_string(tb[DM_INSTANCES_PATH]);
	add_path_list(path, &paths_list);

	data.ctx = ctx;
	data.req = req;
	data.plist = &paths_list;

	fill_optional_data(&data, tb[DM_INSTANCES_OPTIONAL]);

	bbfdm_get(&data, BBF_INSTANCES);

	free_path_list(&paths_list);
	return 0;
}

static const struct blobmsg_policy dm_set_policy[] = {
	[DM_SET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_TYPE] = { .name = "datatype", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_OBJ_PATH] = { .name = "obj_path", .type = BLOBMSG_TYPE_TABLE },
	[DM_SET_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE },
};

int bbfdm_set_handler(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_SET_MAX] = {NULL};
	bbfdm_data_t data;
	int fault = 0;
	LIST_HEAD(pv_list);

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_set_policy, __DM_SET_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_SET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!tb[DM_SET_VALUE] && !tb[DM_SET_OBJ_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	char *path = blobmsg_get_string(tb[DM_SET_PATH]);
	char *value = blobmsg_get_string(tb[DM_SET_VALUE]);
	char *type = tb[DM_SET_TYPE] ? blobmsg_get_string(tb[DM_SET_TYPE]) : NULL;

	fill_optional_data(&data, tb[DM_SET_OPTIONAL]);

	BBF_INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	blob_buf_init(&data.bb, 0);

	fault = fill_pvlist_set(path, value, type, tb[DM_SET_OBJ_PATH], &pv_list);
	if (fault) {
		BBF_ERR("Fault in fill pvlist set path |%s| : |%d|", data.bbf_ctx.in_param, fault);
		fill_err_code_array(&data, fault);
		goto end;
	}

	if (list_empty(&pv_list)) {
		BBF_ERR("Fault in fill pvlist set path |%s| : |list is empty|", data.bbf_ctx.in_param);
		fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
		goto end;
	}

	data.plist = &pv_list;

	bbf_init(&data.bbf_ctx);
	fault = bbfdm_set_value(&data);

	if (data.bbf_ctx.dm_type == BBFDM_BOTH) {
		bbf_entry_services(data.bbf_ctx.dm_type, (!fault) ? true : false, true);
	}

	bbf_cleanup(&data.bbf_ctx);

end:
	free_pv_list(&pv_list);

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);

	return 0;
}

static const struct blobmsg_policy dm_operate_policy[__DM_OPERATE_MAX] = {
	[DM_OPERATE_COMMAND] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_OPERATE_COMMAND_KEY] = { .name = "command_key", .type = BLOBMSG_TYPE_STRING },
	[DM_OPERATE_INPUT] = { .name = "input", .type = BLOBMSG_TYPE_TABLE },
	[DM_OPERATE_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE },
};

static int bbfdm_operate_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		struct ubus_request_data *req, const char *method __attribute__((unused)),
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_OPERATE_MAX] = {NULL};
	char path[PATH_MAX] = {0};
	char *str = NULL;
	bbfdm_data_t data;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_operate_policy, __DM_OPERATE_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_OPERATE_COMMAND]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[DM_OPERATE_COMMAND]));

	data.ctx = ctx;
	data.req = req;
	data.bbf_ctx.in_param = path;
	data.bbf_ctx.linker = tb[DM_OPERATE_COMMAND_KEY] ? blobmsg_get_string(tb[DM_OPERATE_COMMAND_KEY]) : "";

	if (tb[DM_OPERATE_INPUT]) {
		str = blobmsg_format_json(tb[DM_OPERATE_INPUT], true);
		data.bbf_ctx.in_value = str;
	}

	fill_optional_data(&data, tb[DM_OPERATE_OPTIONAL]);

	BBF_INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, data.bbf_ctx.in_param);

	if (is_sync_operate_cmd(&data)) {
		bbfdm_operate_cmd(&data, NULL);
	} else {
		bbfdm_start_deferred(&data, bbfdm_operate_cmd);
	}

	FREE(str);
	return 0;
}

static const struct blobmsg_policy dm_add_policy[] = {
	[DM_ADD_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_ADD_OBJ_PATH] = { .name = "obj_path", .type = BLOBMSG_TYPE_TABLE },
	[DM_ADD_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE },
};

int bbfdm_add_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_ADD_MAX];
	char path[PATH_MAX];
	bbfdm_data_t data;
	int fault = 0;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_add_policy, __DM_ADD_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_ADD_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[DM_ADD_PATH]));

	data.ctx = ctx;
	data.bbf_ctx.in_param = path;

	fill_optional_data(&data, tb[DM_ADD_OPTIONAL]);

	BBF_INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, data.bbf_ctx.in_param);

	blob_buf_init(&data.bb, 0);
	bbf_init(&data.bbf_ctx);

	fault = create_add_response(&data);
	if (fault) {
		BBF_ERR("Fault in add path |%s|", data.bbf_ctx.in_param);
		goto end;
	}

	if (tb[DM_ADD_OBJ_PATH]) {
		LIST_HEAD(pv_list);

		snprintf(path, PATH_MAX, "%s%s.", (char *)blobmsg_data(tb[DM_ADD_PATH]), data.bbf_ctx.addobj_instance);

		fault = fill_pvlist_set(path, NULL, NULL, tb[DM_ADD_OBJ_PATH], &pv_list);
		if (fault) {
			BBF_ERR("Fault in fill pvlist set path |%s|", path);
			fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
			free_pv_list(&pv_list);
			goto end;
		}

		data.plist = &pv_list;

		bbfdm_set_value(&data);

		free_pv_list(&pv_list);
	}

end:
	if (data.bbf_ctx.dm_type == BBFDM_BOTH) {
		bbf_entry_services(data.bbf_ctx.dm_type, (!fault) ? true : false, true);
	}

	bbf_cleanup(&data.bbf_ctx);

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);

	return 0;
}

static const struct blobmsg_policy dm_del_policy[] = {
	[DM_DEL_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_DEL_PATHS] = { .name = "paths", .type = BLOBMSG_TYPE_ARRAY },
	[DM_DEL_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE },
};

int bbfdm_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_DEL_MAX];
	LIST_HEAD(paths_list);
	bbfdm_data_t data;
	int fault = 0;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_del_policy, __DM_DEL_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_DEL_PATH] && !tb[DM_DEL_PATHS])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_DEL_PATH]) {
		char *path = blobmsg_get_string(tb[DM_DEL_PATH]);
		add_path_list(path, &paths_list);
	}

	if (tb[DM_DEL_PATHS]) {
		struct blob_attr *paths = tb[DM_DEL_PATHS];
		struct blob_attr *path = NULL;
		size_t rem;

		blobmsg_for_each_attr(path, paths, rem) {
			char *path_str = blobmsg_get_string(path);

			add_path_list(path_str, &paths_list);
		}
	}

	data.ctx = ctx;
	data.plist = &paths_list;

	fill_optional_data(&data, tb[DM_DEL_OPTIONAL]);

	BBF_INFO("ubus method|%s|, name|%s|", method, obj->name);

	blob_buf_init(&data.bb, 0);
	bbf_init(&data.bbf_ctx);

	data.bbf_ctx.in_param = tb[DM_DEL_PATH] ? blobmsg_get_string(tb[DM_DEL_PATH]) : "";

	fault = create_del_response(&data);

	if (data.bbf_ctx.dm_type == BBFDM_BOTH) {
		bbf_entry_services(data.bbf_ctx.dm_type, (!fault) ? true : false, true);
	}

	bbf_cleanup(&data.bbf_ctx);
	free_path_list(&paths_list);

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);

	return 0;
}

int bbfdm_ref_path_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_GET_MAX];
	struct bbfdm_context *u;
	struct pvNode *node = NULL;
	struct blob_buf bb;
	bool reference_value_found = false;

	if (blobmsg_parse(dm_get_policy, __DM_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_GET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	BBFDM_INFO("ubus method|%s|, name|%s|", method, obj->name);

	char *path = blobmsg_get_string(tb[DM_GET_PATH]);

	if (!match_with_path_list(&u->obj_list, path))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	list_for_each_entry(node, &u->linker_list, list) {
		if (strcmp(node->param, path) == 0) {
			bb_add_string(&bb, "data", node->val);
			reference_value_found = true;
			break;
		}
	}

	if (!reference_value_found) {
		struct dmctx bbf_ctx = {0};

		bbf_init(&bbf_ctx);
		char *reference_path = get_value_by_reference_path(&bbf_ctx, path);

		add_pv_list(path, reference_path, NULL, &u->linker_list);
		bb_add_string(&bb, "data", reference_path ? reference_path : "");

		bbf_cleanup(&bbf_ctx);
	}

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

int bbfdm_ref_value_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_GET_MAX];
	struct bbfdm_context *u;
	struct dmctx bbf_ctx = {0};
	char *reference_value = NULL;
	struct blob_buf bb;

	if (blobmsg_parse(dm_get_policy, __DM_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_GET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	BBFDM_INFO("ubus method|%s|, name|%s|", method, obj->name);

	char *reference_path = blobmsg_get_string(tb[DM_GET_PATH]);

	if (!match_with_path_list(&u->obj_list, reference_path))
		return UBUS_STATUS_INVALID_ARGUMENT;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	bbf_init(&bbf_ctx);

	adm_entry_get_reference_value(&bbf_ctx, reference_path, &reference_value);

	bb_add_string(&bb, "data", reference_value ? reference_value : "");

	bbf_cleanup(&bbf_ctx);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static struct ubus_method bbf_methods[] = {
	UBUS_METHOD("get", bbfdm_get_handler, dm_get_policy),
	UBUS_METHOD("schema", bbfdm_schema_handler, dm_schema_policy),
	UBUS_METHOD("instances", bbfdm_instances_handler, dm_instances_policy),
	UBUS_METHOD("set", bbfdm_set_handler, dm_set_policy),
	UBUS_METHOD("operate", bbfdm_operate_handler, dm_operate_policy),
	UBUS_METHOD("add", bbfdm_add_handler, dm_add_policy),
	UBUS_METHOD("del", bbfdm_del_handler, dm_del_policy),
	UBUS_METHOD("reference_path", bbfdm_ref_path_handler, dm_get_policy),
	UBUS_METHOD("reference_value", bbfdm_ref_value_handler, dm_get_policy),
};

static struct ubus_object_type bbf_type = UBUS_OBJECT_TYPE("", bbf_methods);

static struct ubus_object bbf_object = {
	.name = "",
	.type = &bbf_type,
	.methods = bbf_methods,
	.n_methods = ARRAY_SIZE(bbf_methods)
};

static int regiter_ubus_object(struct ubus_context *ctx)
{
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("failed to get the bbfdm context");
		return -1;
	}

	bbf_object.name = u->config.out_name;
	bbf_object.type->name = u->config.out_name;

	return ubus_add_object(ctx, &bbf_object);
}

static void send_linker_response_event(struct ubus_context *ctx, const char *reference_path, const char *reference_value)
{
	struct blob_buf bb;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	bb_add_string(&bb, reference_path, reference_value ? reference_value : "");

	ubus_send_event(ctx, "bbfdm.linker.response", bb.head);
	blob_buf_free(&bb);
}

static void bbfdm_linker_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
				const char *type, struct blob_attr *msg)
{
	if (!type || !msg)
		return;

	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("failed to get the bbfdm context");
		return;
	}

	if (strcmp(type, "bbfdm.linker.cleanup") == 0) {
		//BBF_ERR("bbfdm.linker.cleanup");
		free_pv_list(&u->linker_list);
	} else if (strcmp(type, "bbfdm.linker.request") == 0) {
		//BBF_ERR("bbfdm.linker.request");

		struct dmctx bbf_ctx = {0};
		struct blob_attr *tb[1] = {0};
		const struct blobmsg_policy p[1] = {
				{ "path", BLOBMSG_TYPE_STRING }
		};

		blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));

		char *reference_path = tb[0] ? blobmsg_get_string(tb[0]) : "";

		if (DM_STRLEN(reference_path) == 0)
			return;

		if (!match_with_path_list(&u->obj_list, reference_path))
			return;

		if (present_in_pv_list(&u->linker_list, reference_path))
			return;

		bbf_init(&bbf_ctx);

		char *reference_value = get_value_by_reference_path(&bbf_ctx, reference_path);

		add_pv_list(reference_path, reference_value, NULL, &u->linker_list);
		send_linker_response_event(ctx, reference_path, reference_value);

		bbf_cleanup(&bbf_ctx);
	}
}

static void bbfdm_ctx_init(struct bbfdm_context *bbfdm_ctx)
{
	INIT_LIST_HEAD(&bbfdm_ctx->linker_list);
	INIT_LIST_HEAD(&bbfdm_ctx->obj_list);
	INIT_LIST_HEAD(&bbfdm_ctx->event_handlers);
}

static int load_micro_service_config(bbfdm_config_t *config)
{
	char opt_val[MAX_DM_PATH] = {0};

	if (!config || strlen(config->service_name) == 0) {
		BBF_ERR("Invalid input options for service name");
		return -1;
	}

	if (INTERNAL_ROOT_TREE == NULL) {
		// This API will only be called with micro-services started with '-m' option

		snprintf(opt_val, MAX_DM_PATH, "%s/%s.so", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
		if (!file_exists(opt_val)) {
			snprintf(opt_val, MAX_DM_PATH, "%s/%s.json", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
		}

		if (!file_exists(opt_val)) {
			BBF_ERR("Failed to load service plugin %s opt_val=%s", config->service_name, opt_val);
			return -1;
		}

		strncpyt(config->in_name, opt_val, sizeof(config->in_name));
	}

	snprintf(opt_val, MAX_DM_PATH, "%s/%s", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
	if (folder_exists(opt_val)) {
		strncpyt(config->in_plugin_dir, opt_val, sizeof(config->in_plugin_dir));
	}

	return 0;
}

static int load_micro_service_data_model(struct bbfdm_context *daemon_ctx)
{
	int err = 0;

	if (INTERNAL_ROOT_TREE) {
		BBF_INFO("Loading Data Model Internal plugin (%s)", daemon_ctx->config.service_name);
		err = bbfdm_load_internal_plugin(daemon_ctx, INTERNAL_ROOT_TREE, &DEAMON_DM_ROOT_OBJ);
	} else {
		BBF_INFO("Loading Data Model External plugin (%s)", daemon_ctx->config.service_name);
		err = bbfdm_load_external_plugin(daemon_ctx, &deamon_lib_handle, &DEAMON_DM_ROOT_OBJ);
	}

	if (err)
		return err;

	BBF_INFO("Loading sub-modules %s", daemon_ctx->config.in_plugin_dir);
	bbf_global_init(DEAMON_DM_ROOT_OBJ, daemon_ctx->config.in_plugin_dir);

	if (DM_STRLEN(daemon_ctx->config.out_name) == 0) {
		BBF_ERR("output name not defined");
		return -1;
	}

	return 0;
}

static struct ubus_event_handler bbfdm_linker_handler = { .cb = bbfdm_linker_cb };

int bbfdm_ubus_regiter_init(struct bbfdm_context *bbfdm_ctx)
{
	int err = 0;

	err = ubus_connect_ctx(&bbfdm_ctx->ubus_ctx, NULL);
	if (err != UBUS_STATUS_OK) {
		BBF_ERR("Failed to connect to ubus");
		return -5;  // Error code -5 indicating that ubus_ctx is connected
	}

	uloop_init();
	ubus_add_uloop(&bbfdm_ctx->ubus_ctx);

	bbfdm_ctx_init(bbfdm_ctx);

	err = load_micro_service_config(&bbfdm_ctx->config);
	if (err) {
		BBF_ERR("Failed to load micro-service config");
		return err;
	}

	err = load_micro_service_data_model(bbfdm_ctx);
	if (err) {
		BBF_ERR("Failed to load micro-service data model");
		return err;
	}

	err = regiter_ubus_object(&bbfdm_ctx->ubus_ctx);
	if (err != UBUS_STATUS_OK)
		return -1;

	err = register_events_to_ubus(&bbfdm_ctx->ubus_ctx, &bbfdm_ctx->event_handlers);
	if (err != 0)
		return err;

	return ubus_register_event_handler(&bbfdm_ctx->ubus_ctx, &bbfdm_linker_handler, "bbfdm.linker.*");
}

int bbfdm_ubus_regiter_free(struct bbfdm_context *bbfdm_ctx)
{
	free_ubus_event_handler(&bbfdm_ctx->ubus_ctx, &bbfdm_ctx->event_handlers);
	bbfdm_ctx_cleanup(bbfdm_ctx);
	uloop_done();
	ubus_shutdown(&bbfdm_ctx->ubus_ctx);

	return 0;
}

void bbfdm_ubus_set_service_name(struct bbfdm_context *bbfdm_ctx, const char *srv_name)
{
	strncpyt(bbfdm_ctx->config.service_name, srv_name, sizeof(bbfdm_ctx->config.service_name));
	snprintf(bbfdm_ctx->config.out_name, sizeof(bbfdm_ctx->config.out_name), "%s.%s", BBFDM_DEFAULT_UBUS_OBJ, srv_name);
}

void bbfdm_ubus_set_log_level(int log_level)
{
	setlogmask(LOG_UPTO(log_level));
}

void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj)
{
	INTERNAL_ROOT_TREE = DynamicObj;
}
