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
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
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
#define BBFDM_SERVICE_CONFIG_PATH "/etc/bbfdm/services"

// Global variables
static void *deamon_lib_handle = NULL;
static uint8_t s_log_level = 0xff;

static void bbfdm_ctx_init(struct bbfdm_context *bbfdm_ctx)
{
	INIT_LIST_HEAD(&bbfdm_ctx->event_handlers);
	INIT_LIST_HEAD(&bbfdm_ctx->config.apply_handlers);
	INIT_LIST_HEAD(&bbfdm_ctx->changed_uci);
}

static void bbfdm_ctx_cleanup(struct bbfdm_context *u)
{
	bbf_global_clean(DEAMON_DM_ROOT_OBJ);

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
		u = container_of(data->obj, struct bbfdm_context, ubus_obj);
		if (u == NULL) {
			BBF_ERR("{fork} Failed to get the bbfdm context");
			exit(EXIT_FAILURE);
		}

		/* free fd's and memory inherited from parent */
		uloop_done();
		ubus_free(data->ctx);
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

static int bbfdm_schema_handler(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__DM_SCHEMA_MAX];
	LIST_HEAD(paths_list);
	bbfdm_data_t data;
	struct bbfdm_context *u;

	memset(&data, 0, sizeof(bbfdm_data_t));

	u = container_of(obj, struct bbfdm_context, ubus_obj);
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

	if (dm_type == BBFDM_CWMP) {
		char *service_name = strdup(u->config.service_name);
		data.bbf_ctx.in_value = (dm_type == BBFDM_CWMP) ? service_name : NULL;
		bbfdm_get(&data, BBF_GET_NAME);
		FREE(service_name);
	} else {
		bbfdm_get(&data, BBF_SCHEMA);
	}

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

	bbfdm_refresh_references(data.bbf_ctx.dm_type, obj->name);

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

	// Make sure to refresh references db before calling set method to ensure that all references are stored in the database
	bbfdm_refresh_references(data.bbf_ctx.dm_type, obj->name);

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

	if (!fault) {
		bbfdm_refresh_references(data.bbf_ctx.dm_type, obj->name);
	}

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

static int bbfdm_operate_handler(struct ubus_context *ctx, struct ubus_object *obj,
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
	data.obj = obj;
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

end:
	if (data.bbf_ctx.dm_type == BBFDM_BOTH) {
		bbf_entry_services(data.bbf_ctx.dm_type, (!fault) ? true : false, true);
	}

	bbf_cleanup(&data.bbf_ctx);

	if (!fault) {
		bbfdm_refresh_references(data.bbf_ctx.dm_type, obj->name);
	}

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

	if (!fault) {
		bbfdm_refresh_references(data.bbf_ctx.dm_type, obj->name);
	}

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);

	return 0;
}

int bbfdm_refresh_references_db(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_buf bb = {0};

	BBF_INFO("ubus method|%s|, name|%s|", method, obj->name);

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	int res = bbfdm_refresh_references(BBFDM_BOTH, obj->name);

	blobmsg_add_u8(&bb, "status", !res ? true : false);

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
	UBUS_METHOD_NOARG("refresh_references_db", bbfdm_refresh_references_db)
};

static struct ubus_object_type bbf_type = UBUS_OBJECT_TYPE("", bbf_methods);

static int regiter_ubus_object(struct bbfdm_context *bbfdm_ctx)
{
	bbfdm_ctx->ubus_obj.name = bbfdm_ctx->config.out_name;
	bbfdm_ctx->ubus_obj.type = &bbf_type;
	bbfdm_ctx->ubus_obj.type->name = bbfdm_ctx->config.out_name;
	bbfdm_ctx->ubus_obj.methods = bbf_methods;
	bbfdm_ctx->ubus_obj.n_methods = ARRAY_SIZE(bbf_methods);

	return ubus_add_object(bbfdm_ctx->ubus_ctx, &bbfdm_ctx->ubus_obj);
}

static void free_apply_handlers(bbfdm_config_t *config)
{
	struct apply_handler_node *node = NULL, *tmp = NULL;

	if (config == NULL)
		return;

	list_for_each_entry_safe(node, tmp, &config->apply_handlers, list) {
		list_del(&node->list);
		BBFDM_FREE(node->file_path);
		BBFDM_FREE(node);
	}
}

static void free_changed_uci(struct bbfdm_context *bbfdm_ctx)
{
	struct apply_handler_node *node = NULL, *tmp = NULL;

	if (bbfdm_ctx == NULL)
		return;

	memset(bbfdm_ctx->uci_change_proto, 0, sizeof(bbfdm_ctx->uci_change_proto));

	list_for_each_entry_safe(node, tmp, &bbfdm_ctx->changed_uci, list) {
		list_del(&node->list);
		BBFDM_FREE(node->file_path);
		BBFDM_FREE(node);
	}
}

static int load_apply_handlers_from_file(bbfdm_config_t *config)
{
	char serv_config[MAX_DM_PATH] = {0};

	if (config == NULL) {
		BBF_ERR("bbfdm_config is null");
		return -1;
	}

	snprintf(serv_config, sizeof(serv_config), "%s/%s.json", BBFDM_SERVICE_CONFIG_PATH, config->service_name);
	if (!bbfdm_file_exists(serv_config) || !bbfdm_is_regular_file(serv_config)) {
		BBF_ERR("Config file %s not exists for service %s", serv_config, config->service_name);
		return 0;
	}

	json_object *json_root = json_object_from_file(serv_config);
	if (!json_root) {
		BBF_ERR("Failed to read json file %s", serv_config);
		return -1;
	}

	json_object *daemon_config = NULL;
	json_object_object_get_ex(json_root, "daemon", &daemon_config);
	if (!daemon_config) {
		BBFDM_ERR("Failed to find daemon object");
		json_object_put(json_root);
		return -1;
	}

	json_object *apply_handler = NULL;
	json_object_object_get_ex(daemon_config, "apply_handler", &apply_handler);
	if (!apply_handler) {
		json_object_put(json_root);
		return 0;
	}

	char type[2][8] = { "dmmap", "uci" };

	for (int i = 0; i < 2; i++) {
		json_object *array = NULL;

		if (!json_object_object_get_ex(apply_handler, type[i], &array) ||
		    json_object_get_type(array) != json_type_array) {
			continue;
		}

		size_t count = json_object_array_length(array);
		for (size_t j = 0; j < count; j++) {
			json_object *hndl_obj = json_object_array_get_idx(array, j);
			json_object *files = NULL;

			json_object_object_get_ex(hndl_obj, "file", &files);
			if (!files || json_object_get_type(files) != json_type_array) {
				continue;
			}

			size_t f_count = json_object_array_length(files);
			for (size_t k = 0; k < f_count; k++) {
				char path[MAX_DM_PATH] = {0};

				json_object *f_inst = json_object_array_get_idx(files, k);
				snprintf(path, sizeof(path), "/etc/%s/%s",
					(strcmp(type[i], "uci") == 0) ? "config" : "bbfdm/dmmap", json_object_get_string(f_inst));

				// check if already present
				bool exist = false;
				struct apply_handler_node *node = NULL;
				list_for_each_entry(node, &config->apply_handlers, list) {
					if (DM_STRCMP(node->file_path, path) == 0) {
						exist = true;
						break;
					}
				}

				if (exist == true)
					continue;

				node = (struct apply_handler_node *)calloc(1, sizeof(struct apply_handler_node));
				if (node == NULL) {
					BBFDM_ERR("Failed to allocate memory for apply handlers");
					free_apply_handlers(config);
					json_object_put(json_root);
					return -1;
				}

				INIT_LIST_HEAD(&node->list);
				list_add_tail(&node->list, &config->apply_handlers);

				node->file_path = strdup(path);
			}
		}
	}

	json_object_put(json_root);
	return 0;
}

static int load_micro_service_config(bbfdm_config_t *config)
{
	char opt_val[MAX_DM_PATH] = {0};

	if (!config || strlen(config->service_name) == 0) {
		BBF_ERR("Invalid input options for service name");
		return -1;
	}

	if (load_apply_handlers_from_file(config) != 0) {
		BBF_ERR("Failed to load handlers from service file");
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

int bbfdm_print_data_model_schema(struct bbfdm_context *bbfdm_ctx, const enum bbfdm_type_enum type)
{
	struct dmctx bbf_ctx = {
		.in_param = ROOT_NODE,
		.nextlevel = false,
		.iscommand = true,
		.isevent = true,
		.isinfo = true,
		.dm_type = type
	};
	int err = 0;

	bbfdm_ctx_init(bbfdm_ctx);

	err = load_micro_service_config(&bbfdm_ctx->config);
	if (err) {
		fprintf(stderr, "Failed to load micro-service config\n");
		return err;
	}

	err = load_micro_service_data_model(bbfdm_ctx);
	if (err) {
		fprintf(stderr, "Failed to load micro-service data model\n");
		bbfdm_ctx_cleanup(bbfdm_ctx);
		return err;
	}

	bbf_init(&bbf_ctx);

	err = bbf_entry_method(&bbf_ctx, BBF_SCHEMA);
	if (!err) {
		struct blob_attr *cur = NULL;
		size_t rem = 0;

		blobmsg_for_each_attr(cur, bbf_ctx.bb.head, rem) {
			struct blob_attr *tb[3] = {0};
			const struct blobmsg_policy p[3] = {
					{ "path", BLOBMSG_TYPE_STRING },
					{ "data", BLOBMSG_TYPE_STRING },
					{ "type", BLOBMSG_TYPE_STRING }
			};

			blobmsg_parse(p, 3, tb, blobmsg_data(cur), blobmsg_len(cur));

			char *name = (tb[0]) ? blobmsg_get_string(tb[0]) : "";
			char *data = (tb[1]) ? blobmsg_get_string(tb[1]) : "";
			char *type = (tb[2]) ? blobmsg_get_string(tb[2]) : "";

			printf("%s %s %s\n", name, type, strlen(data) ? data : "0");
		}
	} else {
		printf("ERROR: %d retrieving %s\n", err, ROOT_NODE);
		err = -1;
	}

	bbf_cleanup(&bbf_ctx);

	free_apply_handlers(&bbfdm_ctx->config);
	free_changed_uci(bbfdm_ctx);

	bbfdm_ctx_cleanup(bbfdm_ctx);
	return err;
}

static void perform_uci_sync_op(struct bbfdm_context *bbfdm_ctx)
{
	DM_MAP_OBJ *dynamic_obj = INTERNAL_ROOT_TREE;

	if (dynamic_obj == NULL || bbfdm_ctx == NULL)
		return;

	for (int i = 0; dynamic_obj[i].path; i++) {
		if (dynamic_obj[i].uci_sync_handler) {
			dynamic_obj[i].uci_sync_handler(bbfdm_ctx);
		}
	}

	free_changed_uci(bbfdm_ctx);

	if (bbfdm_refresh_references(BBFDM_BOTH, bbfdm_ctx->config.out_name)) {
		BBF_ERR("Failed to refresh instance data base");
	}
}

static void bbfdm_apply_event_cb(struct ubus_context *ctx __attribute__((unused)),
			struct ubus_event_handler *ev,
			const char *type __attribute__((unused)),
			struct blob_attr *msg)
{
	if (!msg)
		return;

	struct bbfdm_context *bbfdm_ctx = container_of(ev, struct bbfdm_context, apply_event);
	if (bbfdm_ctx == NULL)
		return;

	bbfdm_config_t *config = &bbfdm_ctx->config;

	const struct blobmsg_policy p[2] = {
		{ "proto", BLOBMSG_TYPE_STRING },
		{ "uci_changed", BLOBMSG_TYPE_ARRAY }
	};

	struct blob_attr *tb[2] = {NULL, NULL};
	blobmsg_parse(p, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	const char *proto = blobmsg_get_string(tb[0]);
	struct blob_attr *attr = NULL;
	int rem = 0;

	blobmsg_for_each_attr(attr, tb[1], rem) {
		char *conf_name = blobmsg_get_string(attr);

		/* Now check if the config file is intended file */
		struct apply_handler_node *node = NULL;

		list_for_each_entry(node, &config->apply_handlers, list) {
			if (DM_STRCMP(node->file_path, conf_name) != 0)
				continue;

			bool exist = false;
			struct apply_handler_node *uci_node = NULL;
			list_for_each_entry(uci_node, &bbfdm_ctx->changed_uci, list) {
				if (DM_STRCMP(uci_node->file_path, conf_name) == 0) {
					exist = true;
					break;
				}
			}

			if (exist == true)
				break;

			uci_node = (struct apply_handler_node *)calloc(1, sizeof(struct apply_handler_node));
			if (uci_node == NULL) {
				BBFDM_ERR("Failed to allocate memory for changed uci list");
				break;
			}

			INIT_LIST_HEAD(&uci_node->list);
			list_add_tail(&uci_node->list, &bbfdm_ctx->changed_uci);
			uci_node->file_path = strdup(conf_name);
			break;
		}
	}

	if (!list_empty(&bbfdm_ctx->changed_uci)) {
		BBF_INFO("Scheduling UCI sync operation for changes performed by %s", proto);
		if (DM_STRLEN(bbfdm_ctx->uci_change_proto) != 0) {
			BBFDM_ERR("!!! Overwritting proto from %s to %s for UCI sync", bbfdm_ctx->uci_change_proto, proto);
		}

		snprintf(bbfdm_ctx->uci_change_proto, sizeof(bbfdm_ctx->uci_change_proto), "%s", proto);
		perform_uci_sync_op(bbfdm_ctx);
	}
}

static int register_bbfdm_apply_event(struct bbfdm_context *bbfdm_ctx)
{
	if (bbfdm_ctx == NULL)
		return -1;

	memset(&bbfdm_ctx->apply_event, 0, sizeof(struct ubus_event_handler));
	bbfdm_ctx->apply_event.cb = bbfdm_apply_event_cb;

	ubus_register_event_handler(bbfdm_ctx->ubus_ctx, &bbfdm_ctx->apply_event, "bbfdm.apply");
	return 0;
}

static int bbfdm_ubus_init(struct bbfdm_context *bbfdm_ctx)
{
	bbfdm_ctx->ubus_ctx = ubus_connect(NULL);
	if (!bbfdm_ctx->ubus_ctx) {
		BBF_ERR("Failed to connect to ubus");
		return -1;
	}

	uloop_init();
	ubus_add_uloop(bbfdm_ctx->ubus_ctx);
	bbfdm_ctx->internal_ubus_ctx = true;
	return 0;
}

int bbfdm_ubus_register_init(struct bbfdm_context *bbfdm_ctx)
{
	int err = 0;

	// Set the logmask with default, if not already set by api
	if (s_log_level == 0xff) {
		BBF_INFO("Log level not set, setting default value %d", LOG_ERR);
		bbfdm_ubus_set_log_level(LOG_ERR);
	}

	if (bbfdm_ctx->ubus_ctx == NULL) {
		err = bbfdm_ubus_init(bbfdm_ctx);
		if (err) {
			BBF_ERR("Failed to initialize ubus_ctx internally");
			return err;
		}
	}

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

	err = regiter_ubus_object(bbfdm_ctx);
	if (err != UBUS_STATUS_OK)
		return -1;

	err = bbfdm_refresh_references(BBFDM_BOTH, bbfdm_ctx->config.out_name);
	if (err) {
		BBF_ERR("Failed to refresh instance data base");
		return -1;
	}

	err = register_bbfdm_apply_event(bbfdm_ctx);
	if (err) {
		BBF_ERR("Failed to register bbfdm apply event");
		return -1;
	}

	return register_events_to_ubus(bbfdm_ctx->ubus_ctx, &bbfdm_ctx->event_handlers);
}

int bbfdm_ubus_register_free(struct bbfdm_context *bbfdm_ctx)
{
	if (bbfdm_ctx->ubus_ctx) {
		ubus_unregister_event_handler(bbfdm_ctx->ubus_ctx, &bbfdm_ctx->apply_event);
		free_ubus_event_handler(bbfdm_ctx->ubus_ctx, &bbfdm_ctx->event_handlers);
		free_apply_handlers(&bbfdm_ctx->config);
		free_changed_uci(bbfdm_ctx);
		bbfdm_ctx_cleanup(bbfdm_ctx);
	}

	if (bbfdm_ctx->ubus_ctx && bbfdm_ctx->internal_ubus_ctx) {
		ubus_free(bbfdm_ctx->ubus_ctx);
		uloop_done();
	}

	return 0;
}

int bbfdm_ubus_regiter_init(struct bbfdm_context *bbfdm_ctx)
{
	return bbfdm_ubus_register_init(bbfdm_ctx);
}

int bbfdm_ubus_regiter_free(struct bbfdm_context *bbfdm_ctx)
{
	return bbfdm_ubus_register_free(bbfdm_ctx);
}

void bbfdm_ubus_set_service_name(struct bbfdm_context *bbfdm_ctx, const char *srv_name)
{
	strncpyt(bbfdm_ctx->config.service_name, srv_name, sizeof(bbfdm_ctx->config.service_name));
	snprintf(bbfdm_ctx->config.out_name, sizeof(bbfdm_ctx->config.out_name), "%s.%s", BBFDM_DEFAULT_UBUS_OBJ, srv_name);
}

void bbfdm_ubus_set_log_level(int log_level)
{
	setlogmask(LOG_UPTO(log_level));
	s_log_level = log_level;
}

uint8_t bbfdm_ubus_get_log_level(void)
{
	return s_log_level;
}

void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj)
{
	INTERNAL_ROOT_TREE = DynamicObj;
}

int bbfdm_refresh_references(unsigned int dm_type, const char *srv_obj_name)
{
	struct dmctx bbf_ctx = {
		.in_param = ROOT_NODE,
		.dm_type = dm_type
	};

	bbf_init(&bbf_ctx);
	int res = bbfdm_cmd_exec(&bbf_ctx, BBF_REFERENCES_DB);
	bbf_cleanup(&bbf_ctx);

	return res;
}
