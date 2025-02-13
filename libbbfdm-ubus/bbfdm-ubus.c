/*
 * bbfdm-ubus.c: bbfdm-ubus API to expose Data Model over ubus
 *
 * Copyright (C) 2023-2024 IOPSYS Software Solutions AB. All rights reserved.
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
#include "pretty_print.h"
#include "get_helper.h"
#include "plugin.h"

#define BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH "/etc/bbfdm/services"
#define BBFDM_DEFAULT_MODULES_PATH "/usr/share/bbfdm"
#define BBFDM_DEFAULT_PLUGINS_PATH BBFDM_DEFAULT_MODULES_PATH"/plugins"
#define BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH BBFDM_DEFAULT_MODULES_PATH"/micro_services"

LIST_HEAD(head_registered_service);

// Global variables
static void *deamon_lib_handle = NULL;

static void bbfdm_ctx_cleanup(struct bbfdm_context *u)
{
	bbf_global_clean(DEAMON_DM_ROOT_OBJ);

	free_path_list(&u->config.list_objs);

	/* Main daemon */
	if (dm_is_micro_service() == false) {
		free_services_from_list(&head_registered_service);
	}

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
	struct blob_attr *attr;
	size_t rem;

	if (!data)
		return;

	data->bbf_ctx.dm_type = BBFDM_BOTH;

	if (!msg)
		return;

	blobmsg_for_each_attr(attr, msg, rem) {

		if (is_str_eq(blobmsg_name(attr), "proto")) {
			const char *val = blobmsg_get_string(attr);
			data->bbf_ctx.dm_type = get_proto_type(val);
		}

		if (is_str_eq(blobmsg_name(attr), "format"))
			data->is_raw = is_str_eq(blobmsg_get_string(attr), "raw") ? true : false;
	}

	char *proto = (data->bbf_ctx.dm_type == BBFDM_BOTH) ? "both" : (data->bbf_ctx.dm_type == BBFDM_CWMP) ? "cwmp" : "usp";
	BBF_DEBUG("Proto:|%s|, is_raw:|%d|", proto, data->is_raw);
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

static int bbfdm_start_deferred(bbfdm_data_t *data, void (*EXEC_CB)(bbfdm_data_t *data, void *d), bool is_operate)
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
	r->is_operate = is_operate;
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
	[DM_GET_PATHS] = { .name = "paths", .type = BLOBMSG_TYPE_ARRAY },
	[DM_GET_MAXDEPTH] = { .name = "maxdepth", .type = BLOBMSG_TYPE_INT32 },
	[DM_GET_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE},
};

static int bbfdm_get_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_GET_MAX];
	LIST_HEAD(paths_list);
	bbfdm_data_t data;
	uint8_t maxdepth = 0;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("Failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_get_policy, __DM_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_GET_PATH]) && !(tb[DM_GET_PATHS]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_GET_PATH]) {
		char *path = blobmsg_get_string(tb[DM_GET_PATH]);
		add_path_list(path, &paths_list);
	}

	if (tb[DM_GET_PATHS]) {
		struct blob_attr *paths = tb[DM_GET_PATHS];
		struct blob_attr *path = NULL;
		size_t rem;

		blobmsg_for_each_attr(path, paths, rem) {
			char *path_str = blobmsg_get_string(path);

			add_path_list(path_str, &paths_list);
		}
	}

	if (tb[DM_GET_MAXDEPTH])
		maxdepth = blobmsg_get_u32(tb[DM_GET_MAXDEPTH]);

	data.ctx = ctx;
	data.req = req;
	data.plist = &paths_list;
	data.depth = maxdepth;

	fill_optional_data(&data, tb[DM_GET_OPTIONAL]);

	bbfdm_get_value(&data, NULL);

	free_path_list(&paths_list);
	return 0;
}

static const struct blobmsg_policy dm_schema_policy[] = {
	[DM_SCHEMA_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SCHEMA_PATHS] = { .name = "paths", .type = BLOBMSG_TYPE_ARRAY },
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

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("Failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_schema_policy, __DM_SCHEMA_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_SCHEMA_PATH]) && !(tb[DM_SCHEMA_PATHS]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_SCHEMA_PATH]) {
		char *path = blobmsg_get_string(tb[DM_SCHEMA_PATH]);

		add_path_list(path, &paths_list);
	}

	if (tb[DM_SCHEMA_PATHS]) {
		struct blob_attr *paths = tb[DM_GET_PATHS];
		struct blob_attr *path = NULL;
		size_t rem;

		blobmsg_for_each_attr(path, paths, rem) {
			char *path_str = blobmsg_get_string(path);

			add_path_list(path_str, &paths_list);
		}
	}

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
	bbfdm_get_supported_dm(&data);
#else
	if (dm_type == BBFDM_CWMP)
		bbfdm_get_names(&data);
	else
		bbfdm_get_supported_dm(&data);
#endif

	free_path_list(&paths_list);
	return 0;
}

static const struct blobmsg_policy dm_instances_policy[] = {
	[DM_INSTANCES_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_INSTANCES_PATHS] = { .name = "paths", .type = BLOBMSG_TYPE_ARRAY },
	[DM_INSTANCES_FIRST_LEVEL] = { .name = "first_level", .type = BLOBMSG_TYPE_BOOL },
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

	if (!(tb[DM_INSTANCES_PATH]) && !(tb[DM_INSTANCES_PATHS]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_INSTANCES_PATH]) {
		char *path = blobmsg_get_string(tb[DM_INSTANCES_PATH]);
		add_path_list(path, &paths_list);
	}

	if (tb[DM_INSTANCES_PATHS]) {
		struct blob_attr *paths = tb[DM_INSTANCES_PATHS];
		struct blob_attr *path = NULL;
		size_t rem;

		blobmsg_for_each_attr(path, paths, rem) {
			char *path_str = blobmsg_get_string(path);

			add_path_list(path_str, &paths_list);
		}
	}

	data.ctx = ctx;
	data.req = req;
	data.bbf_ctx.nextlevel = (tb[DM_INSTANCES_FIRST_LEVEL]) ? blobmsg_get_bool(tb[DM_INSTANCES_FIRST_LEVEL]) : false;
	data.plist = &paths_list;

	fill_optional_data(&data, tb[DM_INSTANCES_OPTIONAL]);

	bbfdm_get_instances(&data);

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
	char path[PATH_MAX] = {'\0'};
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

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[DM_SET_PATH]));

	fill_optional_data(&data, tb[DM_SET_OPTIONAL]);

	BBF_INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	blob_buf_init(&data.bb, 0);
	bbf_init(&data.bbf_ctx);

	data.ctx = ctx;
	data.bbf_ctx.in_param = path;

	char *value = tb[DM_SET_VALUE] ? blobmsg_get_string(tb[DM_SET_VALUE]) : NULL;
	char *type = tb[DM_SET_TYPE] ? blobmsg_get_string(tb[DM_SET_TYPE]) : NULL;

	fault = fill_pvlist_set(&data, path, value, type, tb[DM_SET_OBJ_PATH], &pv_list);
	if (fault) {
		BBF_ERR("Fault in fill pvlist set path |%s| : |%d|", data.bbf_ctx.in_param, fault);
		fill_err_code_array(&data, fault);
		goto end;
	}

	if (list_empty(&pv_list)) {
		BBF_ERR("Fault in fill pvlist set path |%s| : |list is empty|", data.bbf_ctx.in_param);
		fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
		fault = USP_FAULT_INTERNAL_ERROR;
		goto end;
	}

	data.plist = &pv_list;

	fault = bbfdm_set_value(&data);

end:
	if ((data.bbf_ctx.dm_type == BBFDM_BOTH) && (dm_is_micro_service() == false)) {
		bbf_entry_services(data.bbf_ctx.dm_type, (!fault) ? true : false, true);
	}

	bbf_cleanup(&data.bbf_ctx);
	free_pv_list(&pv_list);

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);

	return 0;
}

static const struct blobmsg_policy dm_operate_policy[__DM_OPERATE_MAX] = {
	[DM_OPERATE_COMMAND] = { .name = "command", .type = BLOBMSG_TYPE_STRING },
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
		bbfdm_start_deferred(&data, bbfdm_operate_cmd, true);
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

		fault = fill_pvlist_set(&data, path, NULL, NULL, tb[DM_ADD_OBJ_PATH], &pv_list);
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
	if ((data.bbf_ctx.dm_type == BBFDM_BOTH) && (dm_is_micro_service() == false)) {
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

	if ((data.bbf_ctx.dm_type == BBFDM_BOTH) && (dm_is_micro_service() == false)) {
		bbf_entry_services(data.bbf_ctx.dm_type, (!fault) ? true : false, true);
	}

	bbf_cleanup(&data.bbf_ctx);
	free_path_list(&paths_list);

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);

	return 0;
}

static int bbfdm_service_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req __attribute__((unused)), const char *method,
			    struct blob_attr *msg)
{
	struct blob_buf bb;
	void *array = NULL;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	array = blobmsg_open_array(&bb, "registered_service");
	get_list_of_registered_service(&head_registered_service, &bb);
	blobmsg_close_array(&bb, array);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

enum {
	BBF_NOTIFY_NAME,
	BBF_NOTIFY_PRAMS,
	__BBF_NOTIFY_MAX,
};

static const struct blobmsg_policy dm_notify_event_policy[] = {
	[BBF_NOTIFY_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[BBF_NOTIFY_PRAMS] = { .name = "input", .type = BLOBMSG_TYPE_ARRAY },
};

static int bbfdm_notify_event(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req __attribute__((unused)), const char *method,
			    struct blob_attr *msg)
{
	struct blob_attr *tb[__BBF_NOTIFY_MAX] = {NULL};
	char method_name[256] = {0};
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (blobmsg_parse(dm_notify_event_policy, __BBF_NOTIFY_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBF_ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[BBF_NOTIFY_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	BBF_INFO("ubus method|%s|, name|%s|", method, obj->name);
	snprintf(method_name, sizeof(method_name), "%s.%s", DM_STRLEN(u->config.out_root_obj) ? u->config.out_root_obj : u->config.out_name, BBF_EVENT_NAME);
	ubus_send_event(ctx, method_name, msg);

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
	UBUS_METHOD("notify_event", bbfdm_notify_event, dm_notify_event_policy),
	UBUS_METHOD_NOARG("service", bbfdm_service_handler),
};

static struct ubus_object_type bbf_type = UBUS_OBJECT_TYPE("", bbf_methods);

static struct ubus_object bbf_object = {
	.name = "",
	.type = &bbf_type,
	.methods = bbf_methods,
	.n_methods = ARRAY_SIZE(bbf_methods)
};

static int _fill_daemon_input_option(json_object *daemon_obj, bbfdm_config_t *config)
{
	char opt_val[MAX_DM_PATH] = {0};

	if (!config || strlen(config->service_name) == 0) {
		BBF_ERR("Invalid input options for service name \n");
		return -1;
	}

	if (strchr(config->service_name, '/')) { // absolute path
		char *srv_name = dmjson_get_value(daemon_obj, 1, "service_name");
		if (strlen(srv_name)) {
			strncpyt(config->service_name, srv_name, sizeof(config->service_name));
		}
	}

	// check if the service plugin is DotSO plugin
	snprintf(opt_val, MAX_DM_PATH, "%s/%s.so", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
	if (!file_exists(opt_val)) {
		snprintf(opt_val, MAX_DM_PATH, "%s/%s.json", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
	}

	if (!file_exists(opt_val)) {
		BBF_ERR("Failed to load service plugin %s opt_val=%s\n", config->service_name, opt_val);
		return -1;
	}

	strncpyt(config->in_name, opt_val, sizeof(config->in_name));

	snprintf(opt_val, MAX_DM_PATH, "%s/%s", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
	if (folder_exists(opt_val)) {
		strncpyt(config->in_plugin_dir, opt_val, sizeof(config->in_plugin_dir));
	}

	return 0;
}

static int _fill_daemon_output_options(json_object *daemon_obj, bbfdm_config_t *config)
{
	char *opt_val = NULL;

	if (!config || !daemon_obj) {
		BBF_ERR("Invalid input options \n");
		return -1;
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "output", "root_obj");
	if (DM_STRLEN(opt_val)) {
		strncpyt(config->out_root_obj, opt_val, sizeof(config->out_root_obj));
	} else { // for main process, there is no root obj
		strncpyt(config->out_root_obj, BBFDM_DEFAULT_UBUS_OBJ, sizeof(config->out_root_obj));
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "output", "name");
	if (strlen(opt_val)) {
		snprintf(config->out_name, sizeof(config->out_name), "%s.%s", BBFDM_DEFAULT_UBUS_OBJ, opt_val);
	}

	return 0;
}

static int daemon_load_config_external_plugin(bbfdm_config_t *config)
{
	json_object *json_obj = NULL;
	char json_path[MAX_DM_PATH] = {0};
	int err = 0;

	if (!config || !strlen(config->service_name))
		return -1;

	if (strchr(config->service_name, '/')) { // absolute path
		strncpyt(json_path, config->service_name, MAX_DM_PATH);
	} else {
		snprintf(json_path, MAX_DM_PATH, "%s/%s.json", BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH, config->service_name);
	}

	json_obj = json_object_from_file(json_path);
	if (!json_obj) {
		BBF_ERR("Failed to read input %s file \n", json_path);
		return -1;
	}

	json_object *daemon_obj = dmjson_get_obj(json_obj, 1, "daemon");
	if (!daemon_obj) {
		err = -1;
		goto exit;
	}

	err = _fill_daemon_input_option(daemon_obj, config);
	if (err == -1) {
		goto exit;
	}

	err = _fill_daemon_output_options(daemon_obj, config);

exit:
	if (json_obj) {
		json_object_put(json_obj);
	}

	return err;
}

static int daemon_load_config_internal_plugin(bbfdm_config_t *config)
{
	char opt_val[MAX_DM_PATH] = {0};

	if (strlen(config->service_name) == 0 && dm_is_micro_service() == false) { // default value for main process
		strncpyt(config->service_name, BBFDM_DEFAULT_UBUS_OBJ, sizeof(config->service_name));
	}

	if (!config || strlen(config->service_name) == 0) {
		BBF_ERR("Invalid input options for service name \n");
		return -1;
	}

	if(dm_is_micro_service() == false) {
		strncpyt(config->in_plugin_dir, BBFDM_DEFAULT_PLUGINS_PATH, sizeof(config->in_plugin_dir));
		snprintf(config->out_name, sizeof(config->out_name), "%s", BBFDM_DEFAULT_UBUS_OBJ);
	} else {
		snprintf(opt_val, MAX_DM_PATH, "%s/%s", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, config->service_name);
		if (folder_exists(opt_val)) {
			strncpyt(config->in_plugin_dir, opt_val, sizeof(config->in_plugin_dir));
		}

		strncpyt(config->out_root_obj, BBFDM_DEFAULT_UBUS_OBJ, sizeof(config->out_root_obj));
	}

	return 0;
}

static int daemon_load_services(const char *name, const char *json_path)
{
	json_object *json_obj = NULL;
	json_object *jserv = NULL, *jservices = NULL;
	int idx = 0, err = 0;
	char buffer[MAX_DM_PATH/2] = {0}, service_name[MAX_DM_PATH] = {0};
	bool is_unified = false;

	if (!name || !json_path) {
		BBF_ERR("Invalid service name or json file path");
		return -1;
	}

	json_obj = json_object_from_file(json_path);
	if (!json_obj) {
		BBF_ERR("Failed to read input %s file for services", json_path);
		return -1;
	}

	json_object *daemon_obj = dmjson_get_obj(json_obj, 1, "daemon");
	if (!daemon_obj) {
		err = -1;
		goto exit;
	}

	strncpyt(buffer, name, sizeof(buffer));
	// Remove .json from the end
	size_t len = strlen(buffer) - strlen(".json");
	buffer[len] = '\0';

	snprintf(service_name, sizeof(service_name), "%s.%s", BBFDM_DEFAULT_UBUS_OBJ, buffer);
	string_to_bool(dmjson_get_value((daemon_obj), 1, "unified_daemon"), &is_unified);

	dmjson_foreach_obj_in_array(daemon_obj, jservices, jserv, idx, 1, "services") {
		if (jserv) {
			char parent[MAX_DM_PATH] = {0}, obj[MAX_DM_PATH] = {0};
			char *tmp;

			tmp = dmjson_get_value(jserv, 1, "parent_dm");
			replace_str(tmp, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX, parent, sizeof(parent));

			tmp = dmjson_get_value(jserv, 1, "object");
			replace_str(tmp, "{BBF_VENDOR_PREFIX}", BBF_VENDOR_PREFIX, obj, sizeof(obj));

			if ((DM_STRLEN(parent) == 0) || (DM_STRLEN(obj) == 0)) {
				BBF_ERR("Skip empty registration parent_dm[%s] or object[%s]", parent, obj);
				continue;
			}

			tmp = dmjson_get_value(jserv, 1, "proto");
			BBF_INFO("Registering [%s :: %s :: %s :: %d :: %s]", service_name, parent, obj, is_unified, tmp);
			load_service(DEAMON_DM_ROOT_OBJ, &head_registered_service, service_name, parent, obj, is_unified, get_proto_type(tmp));
		}
	}
exit:
	if (json_obj) {
		json_object_put(json_obj);
	}

	return err;
}

static int daemon_load_config(bbfdm_config_t *config)
{
	int err = 0;

	if (INTERNAL_ROOT_TREE) {
		err = daemon_load_config_internal_plugin(config);
		BBF_INFO("Loading Config Internal plugin (%s)", config->service_name);
	} else {
		// This API will only be called with micro-services
		err = daemon_load_config_external_plugin(config);
		BBF_INFO("Loading Config External plugin (%s)", config->service_name);
	}

	return err;
}

static int regiter_ubus_object(struct ubus_context *ctx)
{
	int ret;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		BBF_ERR("failed to get the bbfdm context");
		return -1;
	}

	bbf_object.name = u->config.out_name;
	bbf_object.type->name = u->config.out_name;
	if (dm_is_micro_service()) {
		bbf_object.n_methods = bbf_object.n_methods - 2;
		bbf_object.type->n_methods = bbf_object.n_methods;
		ret = ubus_add_object(ctx, &bbf_object);
	} else {
		ret = ubus_add_object(ctx, &bbf_object);
	}
	return ret;
}

static void bbfdm_ctx_init(struct bbfdm_context *bbfdm_ctx)
{
	INIT_LIST_HEAD(&bbfdm_ctx->event_handlers);
	INIT_LIST_HEAD(&bbfdm_ctx->config.list_objs);
}

static int daemon_load_data_model(struct bbfdm_context *daemon_ctx)
{
	int err = 0;

	if (INTERNAL_ROOT_TREE) {
		BBF_INFO("Loading Data Model Internal plugin (%s)", daemon_ctx->config.service_name);
		err = bbfdm_load_internal_plugin(daemon_ctx, INTERNAL_ROOT_TREE, &daemon_ctx->config, &DEAMON_DM_ROOT_OBJ);
	} else {
		BBF_INFO("Loading Data Model External plugin (%s)", daemon_ctx->config.service_name);
		err = bbfdm_load_external_plugin(daemon_ctx, &deamon_lib_handle, &daemon_ctx->config, &DEAMON_DM_ROOT_OBJ);
	}

	if (err)
		return err;

	BBF_INFO("Loading sub-modules %s", daemon_ctx->config.in_plugin_dir);
	bbf_global_init(DEAMON_DM_ROOT_OBJ, daemon_ctx->config.in_plugin_dir);

	if (DM_STRLEN(daemon_ctx->config.out_name) == 0) {
		BBF_ERR("output name not defined");
		return -1;
	}

	if (dm_is_micro_service()) {
		if (DM_STRLEN(daemon_ctx->config.out_parent_dm) == 0) {
			BBF_ERR("output parent dm not defined");
			return -1;
		}

		if (list_empty(&daemon_ctx->config.list_objs)) {
			BBF_ERR("output objects is not defined");
			return -1;
		}

		if (DM_STRLEN(daemon_ctx->config.out_root_obj) == 0) {
			BBF_ERR("output root obj not defined");
			return -1;
		}
	}

	return 0;
}

static int register_micro_services()
{
	DIR *dir_tmp = NULL;
	struct dirent *d_file = NULL;
	int err = 0;

	if (dm_is_micro_service() == true) {
		return 0;
	}

	sysfs_foreach_file(BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH, dir_tmp, d_file) {
		char config_name[512] = {0};

		if (d_file->d_name[0] == '.')
			continue;

		snprintf(config_name, sizeof(config_name), "%s/%s", BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH, d_file->d_name);

		if (!file_exists(config_name) || !is_regular_file(config_name))
			continue;

		err = daemon_load_services(d_file->d_name, config_name);
		if (err) {
			BBF_ERR("Failed to load micro-services %s", d_file->d_name);
			break;
		}
	}
	if (dir_tmp) {
		closedir (dir_tmp);
	}
	return err;
}

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

	err = daemon_load_config(&bbfdm_ctx->config);
	if (err) {
		BBF_ERR("Failed to load config");
		return err;
	}

	err = daemon_load_data_model(bbfdm_ctx);
	if (err) {
		BBF_ERR("Failed to load data_model");
		return err;
	}

	// Pre-load the services
	err = register_micro_services();
	if (err) {
		BBF_ERR("Failed to load micro-services");
		return err;
	}

	err = regiter_ubus_object(&bbfdm_ctx->ubus_ctx);
	if (err != UBUS_STATUS_OK)
		return -1;

	return  register_events_to_ubus(&bbfdm_ctx->ubus_ctx, &bbfdm_ctx->event_handlers);
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
	dm_set_micro_service();
}

void bbfdm_ubus_set_log_level(int log_level)
{
	setlogmask(LOG_UPTO(log_level));
}

void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj)
{
	INTERNAL_ROOT_TREE = DynamicObj;
}

void bbfdm_schedule_instance_refresh_timer(struct ubus_context *ctx, int start_in_sec) {} // To be removed later

