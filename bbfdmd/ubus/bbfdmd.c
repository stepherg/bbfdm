/*
 * bbfdmd.c: BBFDMD deamon
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
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
#include <sys/prctl.h>
#include <sys/mman.h>

#include "bbfdmd.h"
#include "set.h"
#include "get.h"
#include "get_helper.h"
#include "operate.h"
#include "add_delete.h"
#include "events.h"
#include "pretty_print.h"
#include "get_helper.h"
#include "plugin.h"
#include "cli.h"

#ifndef DAEMON_JSON_INPUT
#define BBFDM_JSON_INPUT "/tmp/bbfdm/input.json"
#else
#define BBFDM_JSON_INPUT DAEMON_JSON_INPUT
#endif

#define BBFDM_DEFAULT_MODULES_PATH "/usr/share/bbfdm"
#define BBFDM_DEFAULT_PLUGINS_PATH BBFDM_DEFAULT_MODULES_PATH"/plugins"
#define BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH BBFDM_DEFAULT_MODULES_PATH"/micro_services"
#define BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH "/etc/bbfdm/micro_services"
#define BBFDM_DEFAULT_UBUS_OBJ "bbfdm"
#define BBFDM_DEFAULT_DEBUG_LEVEL LOG_ERR

extern struct list_head loaded_json_files;
extern struct list_head json_list;
extern struct list_head json_memhead;

// micro-services should not use fork by default
#define BBF_SUBPROCESS_DEPTH (0)
// default instance updater timeout
#define BBF_INSTANCES_UPDATE_TIMEOUT (60 * 1000)

LIST_HEAD(head_registered_service);

static void run_schema_updater(struct bbfdm_context *u);
static void periodic_instance_updater(struct uloop_timeout *t);

// Global variables
static void *deamon_lib_handle = NULL;

static void sig_handler(int sig)
{
	if (sig == SIGSEGV) {
		handle_pending_signal(sig);
	}
}

static void signal_init(void)
{
	signal(SIGSEGV, sig_handler);
}

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -s <socket path>    ubus socket\n");
	fprintf(stderr, "    -m <json path>      json input configuration for micro services\n");
	fprintf(stderr, "    -c <command input>  Run cli command\n");
	fprintf(stderr, "    -h                 Displays this help\n");
	fprintf(stderr, "\n");
}

static void bbfdm_cleanup(struct bbfdm_context *u)
{
	bbf_global_clean(DEAMON_DM_ROOT_OBJ);

	free_path_list(&u->instances);
	free_path_list(&u->old_instances);
	if (!is_micro_service) { // It's not a micro-service instance
		free_services_from_list(&head_registered_service);
	}

	blob_buf_free(&u->dm_schema);
	/* DotSo Plugin */
	free_dotso_plugin(deamon_lib_handle);
	deamon_lib_handle = NULL;

	/* JSON Plugin */
	free_json_plugin();
}

static bool is_sync_operate_cmd(bbfdm_data_t *data __attribute__((unused)))
{
	return false;
}

static bool is_subprocess_required(int subprocess_level, const char *path)
{
	bool ret = false;
	size_t len = DM_STRLEN(path);
	if (len == 0)
		return ret;

	if (count_delim(path) < subprocess_level) {
		if (path[len - 1] == '.')
			ret = true;
	}

	return ret;
}

static void fill_optional_data(bbfdm_data_t *data, struct blob_attr *msg)
{
	struct blob_attr *attr;
	size_t rem;

	if (!data || !msg)
		return;

	blobmsg_for_each_attr(attr, msg, rem) {

		if (is_str_eq(blobmsg_name(attr), "proto")) {
			const char *val = blobmsg_get_string(attr);
			data->bbf_ctx.dm_type = get_proto_type(val);
		}

		if (is_str_eq(blobmsg_name(attr), "transaction_id"))
			data->trans_id = blobmsg_get_u32(attr);

		if (is_str_eq(blobmsg_name(attr), "format"))
			data->is_raw = is_str_eq(blobmsg_get_string(attr), "raw") ? true : false;
	}

	char *proto = (data->bbf_ctx.dm_type == BBFDM_BOTH) ? "both" : (data->bbf_ctx.dm_type == BBFDM_CWMP) ? "cwmp" : "usp";
	DEBUG("Proto:|%s|, Tran-id:|%d|, is_raw:|%d|", proto, data->trans_id, data->is_raw);
}

static void async_req_free(struct bbfdm_async_req *r)
{
	free(r);
}

static void async_complete_cb(struct uloop_process *p, __attribute__((unused)) int ret)
{
	struct bbfdm_async_req *r = container_of(p, struct bbfdm_async_req, process);

	if (r) {
		INFO("Async call with pid(%d) completes", r->process.pid);
		struct blob_buf *bb = (struct blob_buf *)&r->result;

		ubus_send_reply(r->ctx, &r->req, bb->head);
		INFO("pid(%d) blob data sent raw(%d)", r->process.pid, blob_raw_len(bb->head));
		ubus_complete_deferred_request(r->ctx, &r->req, 0);
		if (r->is_operate) {
			register_instance_refresh_timer(r->ctx, 0);
		}
		munmap(r->result, DEF_IPC_DATA_LEN);
		async_req_free(r);
	}

}

static struct bbfdm_async_req *async_req_new(void)
{
	struct bbfdm_async_req *r = malloc(sizeof(*r));

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
		u = container_of(data->ctx, struct bbfdm_context, ubus_ctx);
		if (u == NULL) {
			ERR("{fork} Failed to get the bbfdm context");
			exit(EXIT_FAILURE);
		}

		// child initialise signal to prevent segfaults
		signal_init();
		/* free fd's and memory inherited from parent */
		uloop_done();
		ubus_shutdown(data->ctx);
		async_req_free(r);
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		INFO("{fork} Calling from subprocess");
		EXEC_CB(data, result);

		bbfdm_cleanup(u);
		closelog();
		/* write result and exit */
		exit(EXIT_SUCCESS);
	}

	// parent
	INFO("Creating bbfdm(%d) sub process(%d) for path(%s)", getpid(), child, data->bbf_ctx.in_param);
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

static bool is_object_schema_update_available(struct bbfdm_context *u)
{
	size_t ll, min_len;
	LIST_HEAD(paths_list);
	bbfdm_data_t data = {
			.is_raw = true,
			.plist = &paths_list,
			.bbf_ctx.nextlevel = false,
			.bbf_ctx.iscommand = true,
			.bbf_ctx.isevent = true,
			.bbf_ctx.isinfo = true,
			.bbf_ctx.dm_type = BBFDM_USP
	};

	memset(&data.bb, 0, sizeof(struct blob_buf));
	int schema_len = blobmsg_len(u->dm_schema.head);
	blob_buf_free(&u->dm_schema);
	blob_buf_init(&u->dm_schema, 0);
	data.bbp = &u->dm_schema;

	// If new parameter gets added it would be a minimum tuple of three params
	min_len = 100;

	add_path_list(ROOT_NODE, &paths_list);
	bool ret = bbf_dm_get_supported_dm(&data);
	if (ret != 0) {
		WARNING("Failed to get schema");
		free_path_list(&paths_list);
		return ret;
	}

	ll = blobmsg_len(data.bbp->head);
	if (ll - schema_len > min_len) {
		DEBUG("DM Schema update available old:new[%zd:%zd]", schema_len, ll);
		if (schema_len != 0) {
			ret = true;
		}
	}

	free_path_list(&paths_list);

	return ret;
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
	bool is_subprocess_needed = false;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("Failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_get_policy, __DM_GET_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!(tb[DM_GET_PATH]) && !(tb[DM_GET_PATHS]))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[DM_GET_PATH]) {
		char *path = blobmsg_get_string(tb[DM_GET_PATH]);
		add_path_list(path, &paths_list);
		is_subprocess_needed = is_subprocess_required(u->config.subprocess_level, path);
	}

	if (tb[DM_GET_PATHS]) {
		struct blob_attr *paths = tb[DM_GET_PATHS];
		struct blob_attr *path = NULL;
		size_t rem;

		blobmsg_for_each_attr(path, paths, rem) {
			char *path_str = blobmsg_get_string(path);

			add_path_list(path_str, &paths_list);
			if (!is_subprocess_needed)
				is_subprocess_needed = is_subprocess_required(u->config.subprocess_level, path_str);
		}
	}

	if (tb[DM_GET_MAXDEPTH])
		maxdepth = blobmsg_get_u32(tb[DM_GET_MAXDEPTH]);

	data.ctx = ctx;
	data.req = req;
	data.plist = &paths_list;
	data.depth = maxdepth;

	fill_optional_data(&data, tb[DM_GET_OPTIONAL]);

	if (is_subprocess_needed) {
		INFO("Creating subprocess for get method");
		bbfdm_start_deferred(&data, bbfdm_get_value, false);
	} else {
		bbfdm_get_value(&data, NULL);
	}

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
		ERR("Failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_schema_policy, __DM_SCHEMA_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
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

	data.bbf_ctx.nextlevel = (tb[DM_SCHEMA_FIRST_LEVEL]) ? blobmsg_get_bool(tb[DM_SCHEMA_FIRST_LEVEL]) : false;
	data.bbf_ctx.iscommand = (dm_type == BBFDM_CWMP) ? false : true;
	data.bbf_ctx.isevent = (dm_type == BBFDM_CWMP) ? false : true;
	data.bbf_ctx.isinfo = (dm_type == BBFDM_CWMP) ? false : true;
	data.plist = &paths_list;

	blob_buf_init(&data.bb, 0);

#ifdef BBF_SCHEMA_FULL_TREE
	data.bbf_ctx.isinfo = true;
	bbf_dm_get_supported_dm(&data);
#else
	if (dm_type == BBFDM_CWMP)
		bbfdm_get_names(&data);
	else
		get_schema_from_blob(&u->dm_schema, &data);
#endif

	ubus_send_reply(ctx, req, data.bb.head);

	blob_buf_free(&data.bb);
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
		ERR("Failed to parse blob");
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

	data.bbf_ctx.nextlevel = (tb[DM_INSTANCES_FIRST_LEVEL]) ? blobmsg_get_bool(tb[DM_INSTANCES_FIRST_LEVEL]) : false;
	data.plist = &paths_list;

	fill_optional_data(&data, tb[DM_INSTANCES_OPTIONAL]);

	blob_buf_init(&data.bb, 0);
	bbfdm_get_instances(&data);
	ubus_send_reply(ctx, req, data.bb.head);

	blob_buf_free(&data.bb);
	free_path_list(&paths_list);
	return 0;
}

static const struct blobmsg_policy dm_set_policy[] = {
	[DM_SET_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[DM_SET_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
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
	int trans_id = 0;
	LIST_HEAD(pv_list);

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_set_policy, __DM_SET_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_SET_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!tb[DM_SET_VALUE] && !tb[DM_SET_OBJ_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[DM_SET_PATH]));

	fill_optional_data(&data, tb[DM_SET_OPTIONAL]);

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, path);

	blob_buf_init(&data.bb, 0);
	bbf_init(&data.bbf_ctx);

	data.ctx = ctx;
	data.bbf_ctx.in_param = path;

	fault = fill_pvlist_set(&data, path, tb[DM_SET_VALUE] ? blobmsg_get_string(tb[DM_SET_VALUE]) : NULL, tb[DM_SET_OBJ_PATH], &pv_list);
	if (fault) {
		ERR("Fault in fill pvlist set path |%s| : |%d|", data.bbf_ctx.in_param, fault);
		fill_err_code_array(&data, fault);
		goto end;
	}

	if (list_empty(&pv_list)) {
		ERR("Fault in fill pvlist set path |%s| : |list is empty|", data.bbf_ctx.in_param);
		fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
		goto end;
	}

	data.plist = &pv_list;

	// no need to process it further since transaction-id is not valid
	if (data.trans_id && !is_transaction_valid(data.trans_id)) {
		WARNING("Transaction not started yet");
		fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
		goto end;
	} else {
		data.bbf_ctx.trans_id = data.trans_id;
	}

	if (data.trans_id == 0) {
		// Transaction-id is not defined so create an internal transaction
		cancel_instance_refresh_timer(ctx);
		trans_id = transaction_start(&data, "INT_SET", 0);
		if (trans_id == 0) {
			WARNING("Failed to get the lock for the transaction");
			fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
			goto end;
		}
	}

	bbfdm_set_value(&data);

	if (data.trans_id == 0) {
		// Internal transaction: need to commit the changes
		transaction_commit(NULL, trans_id, true);
		register_instance_refresh_timer(ctx, 100);
	}

end:
	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);
	free_pv_list(&pv_list);
	bbf_cleanup(&data.bbf_ctx);
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
		ERR("Failed to parse blob");
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

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, data.bbf_ctx.in_param);

	if (is_sync_operate_cmd(&data)) {
		bbfdm_operate_cmd_sync(&data);
	} else {
		cancel_instance_refresh_timer(ctx);
		bbfdm_start_deferred(&data, bbfdm_operate_cmd_async, true);
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
	int trans_id = 0;
	int fault = 0;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_add_policy, __DM_ADD_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[DM_ADD_PATH])
		return UBUS_STATUS_INVALID_ARGUMENT;

	snprintf(path, PATH_MAX, "%s", (char *)blobmsg_data(tb[DM_ADD_PATH]));

	data.ctx = ctx;
	data.bbf_ctx.in_param = path;

	fill_optional_data(&data, tb[DM_ADD_OPTIONAL]);

	INFO("ubus method|%s|, name|%s|, path(%s)", method, obj->name, data.bbf_ctx.in_param);

	blob_buf_init(&data.bb, 0);
	bbf_init(&data.bbf_ctx);

	// no need to process it further since transaction-id is not valid
	if (data.trans_id && !is_transaction_valid(data.trans_id)) {
		WARNING("Transaction not started yet");
		fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
		goto end;
	} else {
		data.bbf_ctx.trans_id = data.trans_id;
	}

	if (data.trans_id == 0) {
		// Transaction-id is not defined so create an internal transaction
		cancel_instance_refresh_timer(ctx);
		trans_id = transaction_start(&data, "INT_ADD", 0);
		if (trans_id == 0) {
			ERR("Failed to get the lock for the transaction");
			fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
			goto end;
		}
	}

	fault = create_add_response(&data);
	if (fault) {
		ERR("Fault in add path |%s|", data.bbf_ctx.in_param);

		if (data.trans_id == 0) {
			// Internal transaction: need to abort the changes
			transaction_abort(NULL, trans_id);
			register_instance_refresh_timer(ctx, 100);
		}

		goto end;
	}

	if (tb[DM_ADD_OBJ_PATH]) {
		LIST_HEAD(pv_list);

		snprintf(path, PATH_MAX, "%s%s.", (char *)blobmsg_data(tb[DM_ADD_PATH]), data.bbf_ctx.addobj_instance);

		fault = fill_pvlist_set(&data, path, NULL, tb[DM_ADD_OBJ_PATH], &pv_list);
		if (fault) {
			ERR("Fault in fill pvlist set path |%s|", path);
			fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);

			if (data.trans_id == 0) {
				// Internal transaction: need to abort the changes
				transaction_abort(NULL, trans_id);
				register_instance_refresh_timer(ctx, 100);
			}

			free_pv_list(&pv_list);
			goto end;
		}

		data.plist = &pv_list;

		bbfdm_set_value(&data);

		free_pv_list(&pv_list);
	}

	if (data.trans_id == 0) {
		// Internal transaction: need to commit the changes
		transaction_commit(NULL, trans_id, true);
		register_instance_refresh_timer(ctx, 100);
	}

end:
	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);
	bbf_cleanup(&data.bbf_ctx);
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
	int trans_id = 0;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(dm_del_policy, __DM_DEL_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
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

	INFO("ubus method|%s|, name|%s|", method, obj->name);

	blob_buf_init(&data.bb, 0);
	bbf_init(&data.bbf_ctx);

	data.bbf_ctx.in_param = tb[DM_DEL_PATH] ? blobmsg_get_string(tb[DM_DEL_PATH]) : "";

	// no need to process it further since transaction-id is not valid
	if (data.trans_id && !is_transaction_valid(data.trans_id)) {
		WARNING("Transaction not started yet");
		fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
		goto end;
	} else {
		data.bbf_ctx.trans_id = data.trans_id;
	}

	if (data.trans_id == 0) {
		// Transaction-id is not defined so create an internal transaction
		cancel_instance_refresh_timer(ctx);
		trans_id = transaction_start(&data, "INT_DEL", 0);
		if (trans_id == 0) {
			WARNING("Failed to get the lock for the transaction");
			fill_err_code_array(&data, USP_FAULT_INTERNAL_ERROR);
			goto end;
		}
	}

	create_del_response(&data);

	if (data.trans_id == 0) {
		// Internal transaction: need to commit the changes
		transaction_commit(NULL, trans_id, true);
		register_instance_refresh_timer(ctx, 100);
	}

end:
	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);
	bbf_cleanup(&data.bbf_ctx);
	free_path_list(&paths_list);
	return 0;
}

enum {
	TRANS_CMD,
	TRANS_TIMEOUT,
	TRANS_RESTART,
	TRANS_OPTIONAL,
	__TRANS_MAX,
};

static const struct blobmsg_policy transaction_policy[] = {
	[TRANS_CMD] = { .name = "cmd", .type = BLOBMSG_TYPE_STRING },
	[TRANS_TIMEOUT] = { .name = "timeout", .type = BLOBMSG_TYPE_INT32 },
	[TRANS_RESTART] = { .name = "restart_services", .type = BLOBMSG_TYPE_INT8 },
	[TRANS_OPTIONAL] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE },
};

static int bbfdm_transaction_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg)
{
	struct blob_attr *tb[__TRANS_MAX] = {NULL};
	bbfdm_data_t data;

	bool is_service_restart = true;
	uint32_t max_timeout = 0;
	char *trans_cmd = "status";
	int ret;

	memset(&data, 0, sizeof(bbfdm_data_t));

	if (blobmsg_parse(transaction_policy, __TRANS_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[TRANS_CMD])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[TRANS_CMD])
		trans_cmd = blobmsg_get_string(tb[TRANS_CMD]);

	if (tb[TRANS_TIMEOUT])
		max_timeout = blobmsg_get_u32(tb[TRANS_TIMEOUT]);

	if (tb[TRANS_RESTART])
		is_service_restart = blobmsg_get_bool(tb[TRANS_RESTART]);

	fill_optional_data(&data, tb[TRANS_OPTIONAL]);

	INFO("ubus method|%s|, name|%s|, cmd [%s]", method, obj->name, trans_cmd);

	bbf_init(&data.bbf_ctx);
	blob_buf_init(&data.bb, 0);

	data.ctx = ctx;

	if (is_str_eq(trans_cmd, "start")) {
		ret = transaction_start(&data, "API", max_timeout);
		if (ret) {
			blobmsg_add_u8(&data.bb, "status", true);
			blobmsg_add_u32(&data.bb, "transaction_id", ret);
		} else {
			blobmsg_add_u8(&data.bb, "status", false);
			transaction_status(&data.bb);
		}
	} else if (is_str_eq(trans_cmd, "commit")) {
		ret = transaction_commit(&data, data.trans_id, is_service_restart);
		blobmsg_add_u8(&data.bb, "status", (ret == 0));
	} else if (is_str_eq(trans_cmd, "abort")) {
		ret = transaction_abort(&data, data.trans_id);
		blobmsg_add_u8(&data.bb, "status", (ret == 0));
	} else if (is_str_eq(trans_cmd, "status")) {
		transaction_status(&data.bb);
	} else {
		WARNING("method(%s) not supported", method);
	}

	ubus_send_reply(ctx, req, data.bb.head);
	blob_buf_free(&data.bb);
	bbf_cleanup(&data.bbf_ctx);

	return 0;
}

enum {
	BBF_SERVICE_CMD,
	BBF_SERVICE_NAME,
	BBF_SERVICE_PARENT_DM,
	BBF_SERVICE_OBJECTS,
	__BBF_SERVICE_MAX,
};

static const struct blobmsg_policy service_policy[] = {
	[BBF_SERVICE_CMD] = { .name = "cmd", .type = BLOBMSG_TYPE_STRING },
	[BBF_SERVICE_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[BBF_SERVICE_PARENT_DM] = { .name = "parent_dm", .type = BLOBMSG_TYPE_STRING },
	[BBF_SERVICE_OBJECTS] = { .name = "objects", .type = BLOBMSG_TYPE_ARRAY },
};

static void service_list(struct blob_buf *bb)
{
	void *array;

	array = blobmsg_open_array(bb, "supported_cmd");
	blobmsg_add_string(bb, NULL, "register");
	blobmsg_add_string(bb, NULL, "list");
	blobmsg_close_array(bb, array);

	array = blobmsg_open_array(bb, "registered_service");
	get_list_of_registered_service(&head_registered_service, bb);
	blobmsg_close_array(bb, array);
}

static int bbfdm_service_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req __attribute__((unused)), const char *method,
			    struct blob_attr *msg)
{
	struct blob_attr *tb[__BBF_SERVICE_MAX] = {NULL};
	struct blob_buf bb;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("Failed to get the bbfdm context");
		return 0;
	}

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (blobmsg_parse(service_policy, __BBF_SERVICE_MAX, tb, blob_data(msg), blob_len(msg))) {
		service_list(&bb);
		goto end;
	}

	INFO("ubus method|%s|, name|%s|", method, obj->name);

	if (is_micro_service) { // It's a micro-service instance
		blobmsg_add_string(&bb, "error", "Its not allowed to register a micro-service for another micro-service!!");
		goto end;
	}

	if (!tb[BBF_SERVICE_CMD]) {
		service_list(&bb);
		goto end;
	}

	char *srv_cmd = blobmsg_get_string(tb[BBF_SERVICE_CMD]);

	if (is_str_eq(srv_cmd, "register")) {

		if (!tb[BBF_SERVICE_NAME]) {
			blobmsg_add_string(&bb, "error", "service name should be defined!!");
			goto end;
		}

		if (!tb[BBF_SERVICE_PARENT_DM]) {
			blobmsg_add_string(&bb, "error", "service parent dm should be defined!!");
			goto end;
		}

		if (!tb[BBF_SERVICE_OBJECTS]) {
			blobmsg_add_string(&bb, "error", "service objects should be defined!!");
			goto end;
		}

		char *srv_name = blobmsg_get_string(tb[BBF_SERVICE_NAME]);
		char *srv_parent_dm = blobmsg_get_string(tb[BBF_SERVICE_PARENT_DM]);
		bool res = true;

		if (tb[BBF_SERVICE_OBJECTS]) {
			struct blob_attr *objs = tb[BBF_SERVICE_OBJECTS];
			struct blob_attr *attr_obj = NULL;
			size_t rem;

			blobmsg_for_each_attr(attr_obj, objs, rem) {
				char *srv_obj = blobmsg_get_string(attr_obj);
				res |= load_service(DEAMON_DM_ROOT_OBJ, &head_registered_service, srv_name, srv_parent_dm, srv_obj);
			}
		} else {
			res = false;
		}

		blobmsg_add_u8(&bb, "status", res);
		run_schema_updater(u);
	} else {
		service_list(&bb);
	}

end:
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
	[BBF_NOTIFY_PRAMS] = { .name = "input", .type = BLOBMSG_TYPE_TABLE },
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
		ERR("failed to get the bbfdm context");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (blobmsg_parse(dm_notify_event_policy, __BBF_NOTIFY_MAX, tb, blob_data(msg), blob_len(msg))) {
		ERR("Failed to parse blob");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[BBF_NOTIFY_NAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	INFO("ubus method|%s|, name|%s|", method, obj->name);
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
	UBUS_METHOD("transaction", bbfdm_transaction_handler, transaction_policy),
	UBUS_METHOD("service", bbfdm_service_handler, service_policy),
	UBUS_METHOD("notify_event", bbfdm_notify_event, dm_notify_event_policy),
};

static struct ubus_object_type bbf_type = UBUS_OBJECT_TYPE("", bbf_methods);

static struct ubus_object bbf_object = {
	.name = "",
	.type = &bbf_type,
	.methods = bbf_methods,
	.n_methods = ARRAY_SIZE(bbf_methods)
};

static void run_schema_updater(struct bbfdm_context *u)
{
	bool ret;
	char method_name[256] = {0};

	ret = is_object_schema_update_available(u);
	if (ret && (is_micro_service == false)) {
		struct blob_buf bb;

		memset(&bb, 0, sizeof(struct blob_buf));
		INFO("Schema update available");
		snprintf(method_name, sizeof(method_name), "%s.%s", u->config.out_name, BBF_UPDATE_SCHEMA_EVENT);
		blob_buf_init(&bb, 0);
		ubus_send_event(&u->ubus_ctx, method_name, bb.head);
		blob_buf_free(&bb);
	}
}

static void broadcast_add_del_event(const char *method, struct list_head *inst, bool is_add)
{
	struct ubus_context ctx;
	struct blob_buf bb;
	struct pathNode *ptr;
	char method_name[40];
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
		DEBUG("#%s:: %s, method %s #", (is_add)?"Add":"Del", ptr->path, method);
	}
	blobmsg_close_array(&bb, a);

	snprintf(method_name, sizeof(method_name), "%s.%s", method, is_add ? BBF_ADD_EVENT : BBF_DEL_EVENT);

	if (is_add)
		ubus_send_event(&ctx, method_name, bb.head);
	else
		ubus_send_event(&ctx, method_name, bb.head);

	blob_buf_free(&bb);
	ubus_shutdown(&ctx);
}

static void update_instances_list(struct list_head *inst)
{
	int ret;
	struct dmctx bbf_ctx = {
			.in_param = ROOT_NODE,
			.nextlevel = false,
			.disable_mservice_browse = true,
			.dm_type = BBFDM_USP
	};

	bbf_init(&bbf_ctx);

	ret = bbfdm_cmd_exec(&bbf_ctx, BBF_INSTANCES);
	if (ret == 0) {
		struct dm_parameter *nptr_dp;

		list_for_each_entry(nptr_dp, &bbf_ctx.list_parameter, list) {
			add_path_list(nptr_dp->name, inst);
		}
	} else {
		WARNING("Failed to get instances, err code %d", ret);
	}

	bbf_cleanup(&bbf_ctx);
}

static void instance_fork_done(struct uloop_process *p, int ret)
{
	struct bbfdm_async_req *r = container_of(p, struct bbfdm_async_req, process);

	if (r) {
		INFO("Instance updater(%d) completed, starting a new instance timer", r->process.pid);
		struct bbfdm_context *u = (struct bbfdm_context *)r->result;

		if (u->config.refresh_time != 0) {
			u->instance_timer.cb = periodic_instance_updater;
			uloop_timeout_set(&u->instance_timer, u->config.refresh_time);
		}
		free_path_list(&u->old_instances);
		async_req_free(r);
	}
	if (ret) {
		WARNING("Instance updater cb failed %d", ret);
	}
}

static void instance_compare_publish(struct bbfdm_context *daemon_ctx)
{
	struct pathNode *ptr;
	LIST_HEAD(inst_list);
	struct list_head *new_inst, *old_inst;
	const char *method;

	new_inst = &daemon_ctx->instances;
	old_inst = &daemon_ctx->old_instances;

	method = DM_STRLEN(daemon_ctx->config.out_root_obj) ? daemon_ctx->config.out_root_obj : daemon_ctx->config.out_name;
	list_for_each_entry(ptr, old_inst, list) {
		if (!present_in_path_list(new_inst, ptr->path)) {
			add_path_list(ptr->path, &inst_list);
		}
	}
	broadcast_add_del_event(method, &inst_list, false);
	free_path_list(&inst_list);

	list_for_each_entry(ptr, new_inst, list) {
		if (!present_in_path_list(old_inst, ptr->path)) {
			add_path_list(ptr->path, &inst_list);
		}
	}
	broadcast_add_del_event(method, &inst_list, true);
	free_path_list(&inst_list);
}

static int fork_instance_checker(struct bbfdm_context *u)
{
	struct bbfdm_async_req *r = NULL;
	pid_t child;

	r = async_req_new();
	if (r == NULL) {
		ERR("Error allocating instance req");
		if (u->config.refresh_time != 0) {
			u->instance_timer.cb = periodic_instance_updater;
			uloop_timeout_set(&u->instance_timer, u->config.refresh_time);
		}
		free_path_list(&u->old_instances);
		goto err_out;
	}
	child = fork();
	if (child == 0) {
		char inst_ser[32] = {0};

		snprintf(inst_ser, sizeof(inst_ser), "dm_%s_in", u->config.service_name);
		INFO("{%s::fork} Instances checker entry", inst_ser);
		prctl(PR_SET_NAME, inst_ser, NULL, NULL, NULL);
		// child initialise signal to prevent segfaults
		signal_init();
		/* free fd's and memory inherited from parent */
		uloop_done();
		ubus_shutdown(&u->ubus_ctx);
		async_req_free(r);
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		instance_compare_publish(u);
		bbfdm_cleanup(u);
		closelog();
		INFO("{fork} Instances checker exit");
		/* write result and exit */
		exit(EXIT_SUCCESS);
	}

	// parent
	INFO("# Creating instance checker process child %d", child);
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
	struct bbfdm_context *u;

	u = container_of(t, struct bbfdm_context, instance_timer);
	if (u == NULL) {
		ERR("Failed to get the bbfdm context");
		return;
	}

	if (u->config.refresh_time == 0) {
		return; // periodic refresh disabled
	}

	if (is_transaction_running()) {
		DEBUG("Transaction ongoing, schedule refresh timer after 1s");
		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, 1000);
		return;
	}

	if (list_empty(&u->instances)) {
		if (!list_empty(&u->old_instances)) {
			list_splice_init(&u->old_instances, &u->instances);
		} else {
			update_instances_list(&u->instances);
			DEBUG("Creating timer for instance update checker, init instances");
			u->instance_timer.cb = periodic_instance_updater;
			uloop_timeout_set(&u->instance_timer, u->config.refresh_time);
			return;
		}
	}

	free_path_list(&u->old_instances);
	list_splice_init(&u->instances, &u->old_instances);
	update_instances_list(&u->instances);
	if (list_empty(&u->instances)) {
		update_instances_list(&u->instances);
		WARNING("Failed to get current instances, restart the timer");
		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, u->config.refresh_time);
		return;
	}

	// fork a process and send it to compare, when process completes
	// delete the old instances and add a new timer
	fork_instance_checker(u);
}

static bool register_service(struct ubus_context *ctx)
{
	struct blob_buf bb = {0};
	uint32_t ubus_id;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("failed to get the bbfdm context");
		return false;
	}
	// check if object already present
	int ret = ubus_lookup_id(ctx, u->config.out_root_obj, &ubus_id);
	if (ret != 0)
		return false;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "cmd", "register");
	blobmsg_add_string(&bb, "name", u->config.out_name);
	blobmsg_add_string(&bb, "parent_dm", u->config.out_parent_dm);

	void *arr = blobmsg_open_array(&bb, "objects");
	for (int i = 0; i < MAX_OBJS && DM_STRLEN(u->config.out_objects[i]) != 0; i++)
		blobmsg_add_string(&bb, NULL, u->config.out_objects[i]);
	blobmsg_close_array(&bb, arr);

	ubus_invoke(ctx, ubus_id, "service", bb.head, NULL, NULL, 5000);
	blob_buf_free(&bb);

	return true;
}

static int _parse_daemon_config_options(bbfdm_config_t *config, json_object *daemon_obj)
{
	char *opt_val = NULL;

	if (!config || !daemon_obj) {
		fprintf(stderr, "Invalid input options \n");
		return -1;
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "config", "loglevel");
	if (DM_STRLEN(opt_val)) {
		config->log_level = (uint8_t) strtoul(opt_val, NULL, 10);
		set_debug_level(config->log_level);
	} else {
		set_debug_level(BBFDM_DEFAULT_DEBUG_LEVEL);
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "config", "refresh_time");
	if (DM_STRLEN(opt_val)) {
		config->refresh_time = (unsigned int) strtoul(opt_val, NULL, 10) * 1000;
	} else {
		config->refresh_time = BBF_INSTANCES_UPDATE_TIMEOUT;
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "config", "transaction_timeout");
	if (DM_STRLEN(opt_val)) {
		config->transaction_timeout = (int) strtol(opt_val, NULL, 10);
		configure_transaction_timeout(config->transaction_timeout);
	} else {
		config->transaction_timeout = 30;
		configure_transaction_timeout(30*1000);
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "config", "subprocess_level");
	if (DM_STRLEN(opt_val)) {
		config->subprocess_level = (unsigned int) strtoul(opt_val, NULL, 10);
	} else {
		config->subprocess_level = BBF_SUBPROCESS_DEPTH;
	}
	return 0;
}

static int _parse_daemon_input_options(bbfdm_config_t *config, json_object *daemon_obj)
{
	char *opt_val = NULL;

	if (!config || !daemon_obj) {
		fprintf(stderr, "Invalid input options \n");
		return -1;
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "input", "plugin_dir");
	if (DM_STRLEN(opt_val)) {
		strncpyt(config->in_plugin_dir, opt_val, sizeof(config->in_plugin_dir));
	} else if(is_micro_service == false) {
		strncpyt(config->in_plugin_dir, BBFDM_DEFAULT_PLUGINS_PATH, sizeof(config->in_plugin_dir));
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "input", "name");
	if (DM_STRLEN(opt_val)) {
		strncpyt(config->in_name, opt_val, sizeof(config->in_name));

		opt_val = strrchr(opt_val, '/');
		if (opt_val) {
			strncpyt(config->service_name, opt_val + 1, sizeof(config->service_name));
		}
	} else if (is_micro_service == false) { // default value for main process
		snprintf(config->in_name, sizeof(config->in_name), "%s/libbbfdm.so", BBFDM_DEFAULT_MODULES_PATH);
		strncpyt(config->service_name, BBFDM_DEFAULT_UBUS_OBJ, sizeof(config->service_name));
	}
	return 0;
}

static int _fill_daemon_input_option(bbfdm_config_t *config, char *sname)
{
	char opt_val[MAX_DM_PATH] = {0};

	if (!config || !sname || strlen(sname) == 0) {
		fprintf(stderr, "Invalid input options for service name \n");
		return -1;
	}

	strncpyt(config->service_name, sname, sizeof(config->service_name));

	// check if the service plugin is DotSO plugin
	snprintf(opt_val, MAX_DM_PATH, "%s/%s.so", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, sname);
	if (!file_exists(opt_val)) {
		snprintf(opt_val, MAX_DM_PATH, "%s/%s.json", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, sname);
	}

	if (!file_exists(opt_val)) {
		fprintf(stderr, "Failed to load service plugin %s \n", sname);
		return -1;
	}

	strncpyt(config->in_name, opt_val, sizeof(config->in_name));

	snprintf(opt_val, MAX_DM_PATH, "%s/%s", BBFDM_DEFAULT_MICROSERVICE_MODULE_PATH, sname);
	if (folder_exists(opt_val)) {
		strncpyt(config->in_plugin_dir, opt_val, sizeof(config->in_plugin_dir));
	}

	return 0;
}

static int _parse_daemon_output_options(bbfdm_config_t *config, json_object *daemon_obj)
{
	char *opt_val = NULL;

	if (!config || !daemon_obj) {
		fprintf(stderr, "Invalid input options \n");
		return -1;
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "output", "root_obj");
	if (DM_STRLEN(opt_val)) {
		strncpyt(config->out_root_obj, opt_val, sizeof(config->out_root_obj));
	} else if (is_micro_service == true) { // for main process, there is no root obj
		strncpyt(config->out_root_obj, BBFDM_DEFAULT_UBUS_OBJ, sizeof(config->out_root_obj));
	}

	opt_val = dmjson_get_value(daemon_obj, 2, "output", "name");
	if (strlen(opt_val)) {
		snprintf(config->out_name, sizeof(config->out_name), "%s%s%s",
					is_micro_service ? config->out_root_obj : opt_val,
					is_micro_service ? "." : "",
					is_micro_service ? opt_val : "");
	} else {
		snprintf(config->out_name, sizeof(config->out_name), "%s", is_micro_service ? "" : BBFDM_DEFAULT_UBUS_OBJ);
	}

	return 0;
}

static int _parse_input_cli_options(bbfdm_config_t *config, json_object *json_obj)
{
	char *opt_val = NULL;

	if (!config || !json_obj) {
		fprintf(stderr, "Invalid input options \n");
		return -1;
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "config", "proto");
	if (DM_STRLEN(opt_val)) {
		config->proto = get_proto_type(opt_val);
	} else {
		config->proto = BBFDM_BOTH;
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "input", "type");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_in_type, sizeof(config->cli_in_type), "%s", opt_val);
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "input", "name");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_in_name, sizeof(config->cli_in_name), "%s", opt_val);
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "input", "plugin_dir");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_in_plugin_dir, sizeof(config->cli_in_plugin_dir), "%s", opt_val);
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "output", "type");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_out_type, sizeof(config->cli_out_type), "%s", opt_val);
	}
	return 0;
}

static int bbfdm_load_deamon_config(bbfdm_config_t *config, const char *module)
{
	char *opt_val = NULL;
	int err = 0;
	json_object *json_obj = NULL;
	char json_path[MAX_DM_PATH] = {0};

	if (!module || !strlen(module))
		return -1;

	if (strchr(module, '/')) { // absolute path
		strncpyt(json_path, module, MAX_DM_PATH);
	} else {
		snprintf(json_path, MAX_DM_PATH, "%s/%s.json", BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH, module);
	}

	json_obj = json_object_from_file(json_path);
	if (!json_obj) {
		fprintf(stderr, "Failed to read input %s file \n", json_path);
		goto exit;
	}

	_parse_input_cli_options(config, json_obj);

	json_object *daemon_obj = dmjson_get_obj(json_obj, 1, "daemon");
	if (!daemon_obj) {
		err = -1;
		goto exit;
	}

	_parse_daemon_config_options(config, daemon_obj);

	opt_val = dmjson_get_value(daemon_obj, 1, "service_name");
	if (strlen(opt_val)) {
		err = _fill_daemon_input_option(config, opt_val);
	} else {
		err = _parse_daemon_input_options(config, daemon_obj);
	}

	if (err == -1) {
		goto exit;
	}

	_parse_daemon_output_options(config, daemon_obj);

	json_object_put(json_obj);
	return err;
exit:
	if (json_obj) {
		json_object_put(json_obj);
	}

	return err;
}

static int bbfdm_regiter_ubus(struct ubus_context *ctx)
{
	int ret;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("failed to get the bbfdm context");
		return -1;
	}

	bbf_object.name = u->config.out_name;
	bbf_object.type->name = u->config.out_name;
	if (is_micro_service) {
		bbf_object.n_methods = bbf_object.n_methods - 2;
		bbf_object.type->n_methods = bbf_object.n_methods;
		ret = ubus_add_object(ctx, &bbf_object);
	} else {
		ret = ubus_add_object(ctx, &bbf_object);
	}
	return ret;
}

static void lookup_event_cb(struct ubus_context *ctx,
		struct ubus_event_handler *ev __attribute__((unused)),
		const char *type, struct blob_attr *msg)
{
	const struct blobmsg_policy policy = {
		"path", BLOBMSG_TYPE_STRING
	};
	struct blob_attr *attr;
	const char *path;
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("failed to get the bbfdm context");
		return;
	}

	if (type && strcmp(type, "ubus.object.add") != 0)
		return;

	blobmsg_parse(&policy, 1, &attr, blob_data(msg), blob_len(msg));

	if (!attr)
		return;

	path = blobmsg_data(attr);
	if (path && strcmp(path, u->config.out_root_obj) == 0) {
		// register micro-service
		register_service(ctx);
	}
}

void register_instance_refresh_timer(struct ubus_context *ctx, int start_in)
{
	struct bbfdm_context *u;
	unsigned refresh_time = 0;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("Failed to get the bbfdm context");
		return;
	}

	if (start_in < 0) {
		refresh_time = u->config.refresh_time;
	} else {
		refresh_time = start_in;
	}

	if (u->config.refresh_time != 0) {
		INFO("Register instance refresh timer in %d ms...", refresh_time);
		u->instance_timer.cb = periodic_instance_updater;
		uloop_timeout_set(&u->instance_timer, refresh_time);
	}
}

void cancel_instance_refresh_timer(struct ubus_context *ctx)
{
	struct bbfdm_context *u;

	u = container_of(ctx, struct bbfdm_context, ubus_ctx);
	if (u == NULL) {
		ERR("Failed to get the bbfdm context");
		return;
	}

	DEBUG("Cancelling Instance refresh timer");
	if (u->config.refresh_time != 0) {
		uloop_timeout_cancel(&u->instance_timer);
	}
}

static void bbf_config_change_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
				const char *type, struct blob_attr *msg)
{
	(void)ev;
	(void)ctx;
	(void)msg;

	if (type && strcmp(type, "bbf.config.change") != 0)
		return;

	cancel_instance_refresh_timer(ctx);
	register_instance_refresh_timer(ctx, 100);
}

static void bbfdm_ctx_init(struct bbfdm_context *bbfdm_ctx)
{
	memset(bbfdm_ctx, 0, sizeof(struct bbfdm_context));
	blob_buf_init(&bbfdm_ctx->dm_schema, 0);
	INIT_LIST_HEAD(&bbfdm_ctx->instances);
	INIT_LIST_HEAD(&bbfdm_ctx->old_instances);
	INIT_LIST_HEAD(&bbfdm_ctx->event_handlers);
}

static int daemon_load_datamodel(struct bbfdm_context *daemon_ctx)
{
	int err = -1;
	char *file_path = daemon_ctx->config.in_name;

	if (DM_STRLEN(file_path) == 0) {
		ERR("Input type/name not supported or defined");
		return -1;
	}

	char *ext = strrchr(file_path, '.');
	if (ext == NULL) {
		ERR("Input file without extension");
	} else if (strcasecmp(ext, ".json") == 0) {
		INFO("Loading JSON plugin %s", file_path);
		err = load_json_plugin(&loaded_json_files, &json_list, &json_memhead, file_path, &daemon_ctx->config, &DEAMON_DM_ROOT_OBJ);
	} else if (strcasecmp(ext, ".so") == 0) {
		INFO("Loading DotSo plugin %s", file_path);
		err = load_dotso_plugin(&deamon_lib_handle, file_path, &daemon_ctx->config, &DEAMON_DM_ROOT_OBJ);
	} else {
		ERR("Input type %s not supported", ext);
	}

	if (!err) {
		INFO("Loading sub-modules %s", daemon_ctx->config.in_plugin_dir);
		bbf_global_init(DEAMON_DM_ROOT_OBJ, daemon_ctx->config.in_plugin_dir);
	} else {
		ERR("Failed loading %s", file_path);
	}

	if (DM_STRLEN(daemon_ctx->config.out_name) == 0) {
		ERR("output name not defined");
		return -1;
	}

	if (is_micro_service) {
		if (DM_STRLEN(daemon_ctx->config.out_parent_dm) == 0) {
			ERR("output parent dm not defined");
			return -1;
		}

		if (DM_STRLEN(daemon_ctx->config.out_objects[0]) == 0) {
			ERR("output objects is not defined");
			return -1;
		}

		if (DM_STRLEN(daemon_ctx->config.out_root_obj) == 0) {
			ERR("output root obj not defined");
			return -1;
		}
	}

	return err;
}

static struct ubus_event_handler add_event = { .cb = lookup_event_cb };
static struct ubus_event_handler config_change_handler = { .cb = bbf_config_change_cb };

int main(int argc, char **argv)
{
	struct bbfdm_context bbfdm_ctx;
	const char *ubus_socket = NULL, *input_file = BBFDM_JSON_INPUT;
	char *cli_argv[4] = {0};
	int err = 0, ch, cli_argc = 0, i;
	bool ubus_init_done = false;
	char log_level[32] = {0};

	bbfdm_ctx_init(&bbfdm_ctx);

	while ((ch = getopt(argc, argv, "hs:m:c:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'm':
			input_file = optarg;
			is_micro_service = input_file ? true : false;
			break;
		case 'c':
			cli_argc = argc-optind+1;
			for (i = 0; i < cli_argc; i++) {
				cli_argv[i] = argv[optind - 1 + i];
			}
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	signal_init();

	err = bbfdm_load_deamon_config(&bbfdm_ctx.config, input_file);
	if (err) {
		fprintf(stderr, "Failed to load %s config from json file (%s)\n", bbfdm_ctx.config.service_name, input_file);
		goto exit;
	}

	snprintf(log_level, sizeof(log_level), "bbfdm%s%s",
			is_micro_service ? "." : "",
			is_micro_service ? bbfdm_ctx.config.service_name : "");

	openlog(log_level, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	if (cli_argc) {
		err = bbfdm_cli_exec_command(&bbfdm_ctx.config, cli_argc, cli_argv);
		goto exit;
	}

	err = daemon_load_datamodel(&bbfdm_ctx);
	if (err) {
		ERR("Failed to load datamodel");
		goto exit;
	}

	err = ubus_connect_ctx(&bbfdm_ctx.ubus_ctx, ubus_socket);
	if (err != UBUS_STATUS_OK) {
		ERR("Failed to connect to ubus");
		return -1;
	}

	uloop_init();
	ubus_add_uloop(&bbfdm_ctx.ubus_ctx);
	ubus_init_done = true;

	err = bbfdm_regiter_ubus(&bbfdm_ctx.ubus_ctx);
	if (err != UBUS_STATUS_OK)
		goto exit;

	run_schema_updater(&bbfdm_ctx);
	register_instance_refresh_timer(&bbfdm_ctx.ubus_ctx, 1000);

	err = register_events_to_ubus(&bbfdm_ctx.ubus_ctx, &bbfdm_ctx.event_handlers);
	if (err != 0)
		goto exit;

	err = ubus_register_event_handler(&bbfdm_ctx.ubus_ctx, &config_change_handler, "bbf.config.change");
	if (err != 0)
		goto exit;

	if (is_micro_service == true) { // It's a micro-service instance
		char proc_name[32] = {0};

		// Create process name using service name and prefix "dm_"
		snprintf(proc_name, sizeof(proc_name), "dm_%s", bbfdm_ctx.config.service_name);

		// Set process name for the current process
		prctl(PR_SET_NAME, proc_name, NULL, NULL, NULL);

		// Register the micro-service
		register_service(&bbfdm_ctx.ubus_ctx);

		// If the micro-service is not registered, listen for "ubus.object.add" event
		// and register the micro-service using event handler for it
		err = ubus_register_event_handler(&bbfdm_ctx.ubus_ctx, &add_event, "ubus.object.add");
		if (err != 0)
			goto exit;
	}

	INFO("Waiting on uloop....");
	uloop_run();

exit:
	free_ubus_event_handler(&bbfdm_ctx.ubus_ctx, &bbfdm_ctx.event_handlers);

	if (ubus_init_done) {
		uloop_done();
		ubus_shutdown(&bbfdm_ctx.ubus_ctx);
	}
	bbfdm_cleanup(&bbfdm_ctx);
	closelog();

	return err;
}
