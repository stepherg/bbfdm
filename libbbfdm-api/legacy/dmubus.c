/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 */

#include "dmubus.h"
#include "dmmem.h"
#include "dmcommon.h"

#define UBUS_TIMEOUT 5000
#define UBUS_MAX_BLOCK_TIME (120000) // 2 min
#define UBUS_MAX_CONSECUTIVE_TIMEOUTS 10

static LIST_HEAD(dm_ubus_cache);

struct dm_ubus_cache_entry {
	struct list_head list;
	char *obj;
	char *method;
	struct blob_attr *attr;
	json_object *data;
	int timeout;
	unsigned hash;
	unsigned int consecutive_timeouts; // Tracks successive timeouts
	bool is_blacklisted; // Marks if the ubus is blacklisted
	bool is_executed; // Marks if the ubus is executed
};

struct dm_ubus_hash_req {
	const char *obj;
	const char *method;
	struct blob_attr *attr;
};

struct ubus_struct {
	const char *ubus_method_name;
	bool ubus_method_exists;
};

static struct ubus_context *g_dm_ubus_ctx = NULL;

static const char *dm_ubus_str_error[__UBUS_STATUS_LAST] = {
	[UBUS_STATUS_OK] = "Success",
	[UBUS_STATUS_INVALID_COMMAND] = "Invalid command",
	[UBUS_STATUS_INVALID_ARGUMENT] = "Invalid argument",
	[UBUS_STATUS_METHOD_NOT_FOUND] = "Method not found",
	[UBUS_STATUS_NOT_FOUND] = "Not found",
	[UBUS_STATUS_NO_DATA] = "No response",
	[UBUS_STATUS_PERMISSION_DENIED] = "Permission denied",
	[UBUS_STATUS_TIMEOUT] = "Request timed out",
	[UBUS_STATUS_NOT_SUPPORTED] = "Operation not supported",
	[UBUS_STATUS_UNKNOWN_ERROR] = "Unknown error",
	[UBUS_STATUS_CONNECTION_FAILED] = "Connection failed",
	[UBUS_STATUS_NO_MEMORY] = "Out of memory",
	[UBUS_STATUS_PARSE_ERROR] = "Parsing message data failed",
	[UBUS_STATUS_SYSTEM_ERROR] = "System error",
};

/* Based on an efficient hash function published by D. J. Bernstein
 */
static unsigned int djbhash(unsigned hash, const char *data, unsigned len)
{
	unsigned  i;

	for (i = 0; i < len; i++)
		hash = ((hash << 5) + hash) + data[i];

	return (hash & 0x7FFFFFFF);
}

static unsigned dm_ubus_req_hash_from_blob(const struct dm_ubus_hash_req *req)
{
	unsigned hash = 5381;

	if (!req || !req->obj || !req->method)
		return hash;

	hash = djbhash(hash, req->obj, DM_STRLEN(req->obj));
	hash = djbhash(hash, req->method, DM_STRLEN(req->method));

	char *jmsg = req->attr ? blobmsg_format_json(req->attr, true) : NULL;
	if (!jmsg)
		return hash;

	hash = djbhash(hash, jmsg, DM_STRLEN(jmsg));
	free(jmsg);

	return hash;
}

static struct dm_ubus_cache_entry *dm_ubus_cache_lookup(unsigned hash)
{
	struct dm_ubus_cache_entry *entry_match = NULL;
	struct dm_ubus_cache_entry *entry = NULL;

	list_for_each_entry(entry, &dm_ubus_cache, list) {
		if (entry->hash == hash) {
			entry_match = entry;
			break;
		}
	}
	return entry_match;
}

static struct dm_ubus_cache_entry *dm_ubus_cache_entry_new(unsigned hash, const char *obj, const char *method, int timeout, struct blob_attr *attr)
{
	struct dm_ubus_cache_entry *entry = NULL;

	entry = (struct dm_ubus_cache_entry *)calloc(1, sizeof(struct dm_ubus_cache_entry));
	if (!entry) {
		BBF_ERR("Failed to allocate memory");
		return NULL;
	}

	list_add_tail(&entry->list, &dm_ubus_cache);

	entry->hash = hash;
	entry->obj = strdup(obj);
	entry->method = strdup(method);
	entry->timeout = timeout;
	entry->consecutive_timeouts = 0;
	entry->is_blacklisted = false;

	size_t blob_data_len = attr ? blob_raw_len(attr) : 0;

	if (blob_data_len) {
		entry->attr = (struct blob_attr *)calloc(1, blob_data_len);
		if (entry->attr) {
			memcpy(entry->attr, attr, blob_data_len);
		} else {
			BBF_ERR("Failed to allocate memory");
		}
	} else {
		entry->attr = NULL;
	}

	return entry;
}

static void dm_ubus_cache_entry_free(void)
{
	struct dm_ubus_cache_entry *entry = NULL;

	list_for_each_entry(entry, &dm_ubus_cache, list) {
		entry->is_executed = false;

		if (entry->data) {
			json_object_put(entry->data);
			entry->data = NULL;
		}
	}
}

static void dm_ubus_data_handler(struct ubus_request *req, int type, struct blob_attr *msg)
{
	if (!msg)
		return;

	if (req && req->priv) {
		json_object **req_res = (json_object **)req->priv;

		char *str = blobmsg_format_json_indent(msg, true, -1);
		if (!str) {
			req_res = NULL;
			return;
		}

		*req_res = json_tokener_parse(str);

		free((char *)str);
	}
}

static int dm_ubus_call_sync(struct ubus_context *ubus_ctx, const char *obj, const char *method, int timeout, struct blob_attr *attr, json_object **req_res)
{
	uint32_t id = 0;

	if (req_res) *req_res = NULL;

	if (ubus_ctx == NULL) {
		BBF_ERR("UBUS context is null");
		return -1;
	}

	if (!obj || !method || !attr) {
		BBF_ERR("obj or method or attr should not be NULL");
		return -1;
	}

	if (ubus_lookup_id(ubus_ctx, obj, &id)) {
		BBF_WARNING("Failed to lookup UBUS object ID for '%s' using method '%s'", obj, method);
		return -1;
	}

	int err = ubus_invoke(ubus_ctx, id, method, attr, dm_ubus_data_handler, req_res ? (void *)req_res : NULL, timeout);

	if (err != 0) {
		const char *err_msg = (err >= 0 && err < __UBUS_STATUS_LAST) ? dm_ubus_str_error[err] : "Unknown error";
		BBF_ERR("UBUS invoke failed [object: %s, method: %s, timeout: %d ms] with error (%s:%d)",
				obj, method, timeout, err_msg, err);
	}

	return err;
}

static void dm_ubus_data_handler_entry(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct dm_ubus_cache_entry *entry = NULL;
	char *str = NULL;

	if (!msg || !req || !req->priv)
		return;

	entry = (struct dm_ubus_cache_entry *)req->priv;

	str = blobmsg_format_json_indent(msg, true, -1);
	if (!str) {
		entry->data = NULL;
		return;
	}

	entry->data = json_tokener_parse(str);

	free((char *)str);
}

static int __dm_ubus_call_sync_entry(struct ubus_context *ubus_ctx, struct dm_ubus_cache_entry *entry, const char *obj, const char *method, int timeout, struct blob_attr *attr)
{
	uint32_t id = 0;

	if (entry == NULL) {
		BBF_ERR("UBUS entry should not be NULL");
		return -1;
	}

	entry->data = NULL;
	entry->is_executed = true;

	if (ubus_ctx == NULL) {
		BBF_ERR("UBUS context is null");
		return -1;
	}

	if (!obj || !method || !attr) {
		BBF_ERR("obj or method or attr should not be NULL");
		return -1;
	}

	if (ubus_lookup_id(ubus_ctx, obj, &id)) {
		BBF_WARNING("Failed to lookup UBUS object ID for '%s' using method '%s'", obj, method);
		return -1;
	}

	int err = ubus_invoke(ubus_ctx, id, method, attr, dm_ubus_data_handler_entry, (void *)entry, timeout);

	if (err != 0) {
		const char *err_msg = (err >= 0 && err < __UBUS_STATUS_LAST) ? dm_ubus_str_error[err] : "Unknown error";
		BBF_ERR("UBUS invoke failed [object: %s, method: %s, timeout: %d ms] with error (%s:%d)",
				obj, method, timeout, err_msg, err);

		if (err == UBUS_STATUS_TIMEOUT) {
			entry->consecutive_timeouts++;
			if (entry->consecutive_timeouts >= UBUS_MAX_CONSECUTIVE_TIMEOUTS) {
				entry->is_blacklisted = true;
				BBF_ERR("UBUS [object: %s, method: %s] has been blacklisted due to repeated timeouts", obj, method);
			}
		}
	} else {
		entry->consecutive_timeouts = 0;
	}

	return err;
}

static int dm_ubus_call_sync_entry(struct ubus_context *ubus_ctx, const char *obj, const char *method, int timeout, struct blob_attr *attr, json_object **req_res)
{
	int err = 0;

	if (!obj || !method || !attr) {
		BBF_ERR("obj or method or attr should not be NULL");
		return -1;
	}

	const struct dm_ubus_hash_req hash_req = {
		.obj = obj,
		.method = method,
		.attr = attr
	};

	const unsigned hash = dm_ubus_req_hash_from_blob(&hash_req);
	struct dm_ubus_cache_entry *entry = dm_ubus_cache_lookup(hash);

	if (entry && entry->is_blacklisted) {
		if (req_res) *req_res = NULL;
		return -1;
	}

	if (entry) {
		if (entry->is_executed == false) {
			err = __dm_ubus_call_sync_entry(ubus_ctx, entry, obj, method, timeout, attr);
		}

		if (req_res) *req_res = entry->data;
	} else {
		struct dm_ubus_cache_entry *new_entry = dm_ubus_cache_entry_new(hash, obj, method, timeout, attr);
		if (new_entry == NULL) {
			if (req_res) *req_res = NULL;
			return -1;
		}

		err = __dm_ubus_call_sync_entry(ubus_ctx, new_entry, obj, method, timeout, attr);
		if (req_res) *req_res = new_entry->data;
	}

	return err;
}

static int __dmubus_call(const char *obj, const char *method, int timeout,
		struct ubus_arg u_args[], int u_args_size, bool save_data, json_object **req_res)
{
	struct blob_buf bb = {0};
	int rc = 0;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	for (int i = 0; i < u_args_size; i++) {
		if (u_args[i].type == Integer) {
			blobmsg_add_u32(&bb, u_args[i].key, DM_STRTOL(u_args[i].val));
		} else if (u_args[i].type == Boolean) {
			bool val = false;
			string_to_bool(u_args[i].val, &val);
			blobmsg_add_u8(&bb, u_args[i].key, val);
		} else if (u_args[i].type == Table) {
			json_object *jobj = json_tokener_parse(u_args[i].val);
			blobmsg_add_json_element(&bb, u_args[i].key, jobj);
			json_object_put(jobj);
		} else {
			blobmsg_add_string(&bb, u_args[i].key, u_args[i].val);
		}
	}

	if (save_data)
		rc = dm_ubus_call_sync_entry(g_dm_ubus_ctx, obj, method, timeout, bb.head, req_res);
	else
		rc = dm_ubus_call_sync(g_dm_ubus_ctx, obj, method, timeout, bb.head, req_res);

	blob_buf_free(&bb);

	return rc;
}

int dmubus_call(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	return __dmubus_call(obj, method, UBUS_TIMEOUT, u_args, u_args_size, true, req_res);
}

int dmubus_call_timeout(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size, int timeout, json_object **req_res)
{
	return __dmubus_call(obj, method, timeout, u_args, u_args_size, false, req_res);
}

int dmubus_call_blocking(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	return __dmubus_call(obj, method, UBUS_MAX_BLOCK_TIME, u_args, u_args_size, false, req_res);
}

int dmubus_call_set(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size)
{
	return __dmubus_call(obj, method, UBUS_TIMEOUT, u_args, u_args_size, false, NULL);
}

static int __dmubus_call_blob(const char *obj, const char *method, int timeout,
		json_object *json_obj, bool save_data, json_object **resp)
{
	struct blob_buf bb = {0};
	int rc = 0;

	if (resp) *resp = NULL;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (json_obj != NULL) {
		if (!blobmsg_add_object(&bb, json_obj)) {
			blob_buf_free(&bb);
			return -1;
		}
	}

	if (save_data)
		rc = dm_ubus_call_sync_entry(g_dm_ubus_ctx, obj, method, timeout, bb.head, resp);
	else
		rc = dm_ubus_call_sync(g_dm_ubus_ctx, obj, method, timeout, bb.head, resp);

	blob_buf_free(&bb);

	return rc;
}

int dmubus_call_blob(const char *obj, const char *method, json_object *value, json_object **resp)
{
	return __dmubus_call_blob(obj, method, UBUS_TIMEOUT, value, true, resp);
}

int dmubus_call_blob_blocking(const char *obj, const char *method, json_object *value, json_object **resp)
{
	return __dmubus_call_blob(obj, method, UBUS_MAX_BLOCK_TIME, value, false, resp);
}

int dmubus_call_blob_set(const char *obj, const char *method, json_object *value)
{
	return __dmubus_call_blob(obj, method, UBUS_TIMEOUT, value, false, NULL);
}

int dmubus_call_blob_msg(const char *obj, const char *method, struct blob_buf *data, json_object **resp)
{
	return dm_ubus_call_sync(g_dm_ubus_ctx, obj, method, UBUS_TIMEOUT, data->head, resp);
}

int dmubus_call_blob_msg_timeout(const char *obj, const char *method, struct blob_buf *data, int timeout)
{
	return dm_ubus_call_sync(g_dm_ubus_ctx, obj, method, timeout, data->head, NULL);
}

int dmubus_call_blob_msg_set(const char *obj, const char *method, struct blob_buf *data)
{
	return dm_ubus_call_sync(g_dm_ubus_ctx, obj, method, UBUS_TIMEOUT, data->head, NULL);
}

static void _bbfdm_task_callback(struct uloop_timeout *t)
{
	struct bbfdm_task_data *task = container_of(t, struct bbfdm_task_data, timeout);

	if (task == NULL) {
		BBF_ERR("Failed to decode task");
		return;
	}
	task->taskcb(task->arg1, task->arg2);
	free(task);
}

int bbfdm_task_schedule(bbfdm_task_callback_t callback, const void *arg1, void *arg2, int timeout_sec)
{
	bbfdm_task_data_t *task;

	if (timeout_sec < 0) {
		BBF_ERR("Can't handler negative timeouts");
		return -1;
	}

	// do not use dmalloc here, as this needs to persists beyond session
	task = (bbfdm_task_data_t *)calloc(sizeof(bbfdm_task_data_t), 1);
	if (task == NULL) {
		BBF_ERR("Failed to allocate memory");
		return -1;
	}


	task->taskcb = callback;
	task->arg1 = arg1;
	task->arg2 = arg2;

	task->timeout.cb = _bbfdm_task_callback;

	// Set the initial timeout
	int ret = uloop_timeout_set(&task->timeout, timeout_sec * 1000);

	return ret;
}

static void _bbfdm_task_finish_callback(struct uloop_process *p, int ret)
{
	struct bbfdm_task_data *task = container_of(p, struct bbfdm_task_data, process);

	if (task == NULL) {
		BBF_ERR("Failed to decode forked task");
		return;
	}
	if (task->finishcb) {
		task->finishcb(task->arg1, task->arg2);
	}
	free(task);
}


int bbfdm_task_fork(bbfdm_task_callback_t taskcb, bbfdm_task_callback_t finishcb, const void *arg1, void *arg2)
{
	pid_t child;
	bbfdm_task_data_t *task;

	// do not use dmalloc here, as this needs to persists beyond session
	task = (bbfdm_task_data_t *)calloc(sizeof(bbfdm_task_data_t), 1);
	if (task == NULL) {
		BBF_ERR("Failed to allocate memory");
		return -1;
	}

	task->arg1 = arg1;
	task->arg2 = arg2;

	child = fork();
	if (child == -1) {
		BBF_ERR("Failed to fork a child for task");
		goto err_out;
	} else if (child == 0) {
		/* free fd's and memory inherited from parent */
		uloop_done();
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		BBF_INFO("{fork} Calling from subprocess");
		taskcb(task->arg1, task->arg2);

		/* write result and exit */
		exit(EXIT_SUCCESS);
	}

	// monitor the process if finish callback is defined
	if (finishcb) {
		task->finishcb = finishcb;
		task->process.pid = child;
		task->process.cb = _bbfdm_task_finish_callback;
		uloop_process_add(&task->process);
	} else {
		FREE(task);
	}
	return 0;

err_out:
	return -1;
}

static void dmubus_listen_timeout(struct uloop_timeout *timeout)
{
	uloop_end();
}
/*******************************************************************************
**
** dmubus_wait_for_event
**
** This API is to wait for the specified event to arrive on ubus or the timeout
** whichever is earlier
**
** NOTE: since this is a blocking call so it should only be called from DM_ASYNC
**       operations.
**
** \param   event - wait for this <event> to arrive on ubus
** \param   timeout - max time (seconds) to wait for the event
** \param   ev_data - data to be passed to the callback method
** \param   ev_callback - callback method to be invoked on arrival of the event
** \param   subtask - If not NULL then executes an operation before arrival of
**                    the event and the timeout expiry.
**                    subtask timeout must be less than actual timeout. Subtask
**                    may not be executed if event arrives prior the expiry of
**                    the subtask timer.
**
** E.G: event: sysupgrade, type: {"status":"Downloading","bank_id":"2"}
**
*******************************************************************************/
void dmubus_wait_for_event(const char *event, int timeout, void *ev_data,
		CB_FUNC_PTR ev_callback, struct dmubus_ev_subtask *subtask)
{
	if (DM_STRLEN(event) == 0)
		return;

	if (subtask && subtask->timeout >= timeout)
		return;

	struct ubus_context *ctx = ubus_connect(NULL);
	if (!ctx)
		return;

	struct dmubus_event_data data = {
		.tm.cb = dmubus_listen_timeout,
		.ev.cb = ev_callback,
		.ev_data = ev_data
	};

	uloop_init();
	ubus_add_uloop(ctx);

	int ret = ubus_register_event_handler(ctx, &data.ev, event);
	if (ret)
		goto end;

	if (subtask)
		uloop_timeout_set(&(subtask->sub_tm), subtask->timeout * 1000);

	uloop_timeout_set(&data.tm, timeout * 1000);
	uloop_run();
	uloop_done();
	ubus_unregister_event_handler(ctx, &data.ev);

end:
	ubus_free(ctx);
	return;
}

static void receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *cur = NULL;
	size_t rem = 0;

	if (!obj->signature || !priv)
		return;

	struct ubus_struct *ubus_s = (struct ubus_struct *)priv;

	if (!ubus_s->ubus_method_name)
		return;

	blob_for_each_attr(cur, obj->signature, rem) {
		const char *method_name = blobmsg_name(cur);
		if (!DM_STRCMP(ubus_s->ubus_method_name, method_name)) {
			ubus_s->ubus_method_exists = true;
			return;
		}
	}
}

bool dmubus_object_method_exists(const char *object)
{
	struct ubus_struct ubus_s = { 0, 0 };
	char ubus_object[64] = {0};

	if (object == NULL)
		return false;

	if (g_dm_ubus_ctx == NULL) {
		BBF_ERR("UBUS context is null");
		return false;
	}

	snprintf(ubus_object, sizeof(ubus_object), "%s", object);

	// check if the method exists in the ubus_object
	char *delimiter = strstr(ubus_object, "->");
	if (delimiter) {
		ubus_s.ubus_method_name = dmstrdup(delimiter + 2);
		*delimiter = '\0';
	}

	if (ubus_lookup(g_dm_ubus_ctx, ubus_object, receive_list_result, &ubus_s))
		return false;

	if (ubus_s.ubus_method_name && !ubus_s.ubus_method_exists)
		return false;

	return true;
}

static void dmubus_schedule_blacklisted_ubus_recovery(void);

static void blacklisted_ubus_recovery_timer_cb(struct uloop_timeout *timeout __attribute__((unused)))
{
	dmubus_schedule_blacklisted_ubus_recovery();
}

static struct uloop_timeout blacklisted_ubus_recovery_timer = {
	.cb = blacklisted_ubus_recovery_timer_cb
};

static void verify_ubus_method(struct dm_ubus_cache_entry *entry)
{
	struct ubus_context *ubus_ctx = ubus_connect(NULL);

	int err = dm_ubus_call_sync(ubus_ctx, entry->obj, entry->method, entry->timeout, entry->attr, NULL);

	if (err == 0) {
		BBF_INFO("Recovered ubus obj |%s| method |%s|", entry->obj, entry->method);

		entry->consecutive_timeouts = 0;
		entry->is_blacklisted = false;
	} else {
		BBF_INFO("ubus obj |%s| method |%s| still unreachable", entry->obj, entry->method);
	}

	ubus_free(ubus_ctx);
}

static void dmubus_schedule_blacklisted_ubus_recovery(void)
{
	int next_check_time = 60000; // 1 min

	if (g_dm_ubus_ctx != NULL) {
		BBF_INFO("A method is currently running. Rescheduling blacklisted ubus recovery in %d msecs", next_check_time);
		uloop_timeout_set(&blacklisted_ubus_recovery_timer, next_check_time);
		return;
	}

	struct dm_ubus_cache_entry *entry = NULL;

	list_for_each_entry(entry, &dm_ubus_cache, list) {
		if (entry->is_blacklisted) {
			verify_ubus_method(entry);
		}
	}

	BBF_DEBUG("Pid %d, Next blacklisted ubus recovery scheduled in %d msecs", getpid(), next_check_time);
	uloop_timeout_set(&blacklisted_ubus_recovery_timer, next_check_time);
}

static void dmubus_stop_blacklisted_ubus_recovery(void)
{
	uloop_timeout_cancel(&blacklisted_ubus_recovery_timer);
}

void dm_ubus_init(struct dmctx *bbf_ctx)
{
	bbf_ctx->ubus_ctx = g_dm_ubus_ctx = ubus_connect(NULL);
}

void dm_ubus_free(struct dmctx *bbf_ctx)
{
	dm_ubus_cache_entry_free();

	if (bbf_ctx->ubus_ctx) {
		ubus_free(bbf_ctx->ubus_ctx);
		bbf_ctx->ubus_ctx = g_dm_ubus_ctx = NULL;
	}
}

void dm_ubus_cache_init(void)
{
	INIT_LIST_HEAD(&dm_ubus_cache);

	dmubus_schedule_blacklisted_ubus_recovery();
}

void dm_ubus_cache_free(void)
{
	struct dm_ubus_cache_entry *entry = NULL, *tmp = NULL;

	list_for_each_entry_safe(entry, tmp, &dm_ubus_cache, list) {
		list_del(&entry->list);
		FREE(entry->obj);
		FREE(entry->method);
		FREE(entry->attr);
		FREE(entry);
	}

	dmubus_stop_blacklisted_ubus_recovery();
}
