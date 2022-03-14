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
#define UBUS_MAX_BLOCK_TIME (60000) // 60 sec

static LIST_HEAD(dmubus_cache);

struct dm_ubus_cache_entry {
	struct list_head list;
	json_object *data;
	unsigned hash;
	time_t last_request;
	time_t resp_time;
	bool failed;
	bool async_call_running;
	char obj[100];
	char method[100];
	struct blob_attr *breq;
};

struct dm_ubus_hash_req {
	const char *obj;
	const char *method;
	struct blob_attr *attr;
};

static struct ubus_context *ubus_ctx;
static json_object *json_res = NULL;
static char ubus_method[32] = {0};
static bool ubus_method_exists = false;
static bool local_ctx_g = false;
static int soft_limit_g = 0; /* In seconds */
static int hard_limit_g = 0; /* In seconds */

static const struct dm_ubus_cache_entry * dm_ubus_cache_lookup(unsigned hash);

static struct ubus_context * dm_libubus_init()
{
	local_ctx_g = true;
	return ubus_connect(NULL);
}

static void dm_libubus_free()
{
	if (local_ctx_g && ubus_ctx) {
		ubus_free(ubus_ctx);
		ubus_ctx = NULL;
		local_ctx_g = false;
	}
}

static void prepare_blob_message(struct blob_buf *b, const struct ubus_arg u_args[], int u_args_size)
{
	if (!b)
		return;

	blob_buf_init(b, 0);
	for (int i = 0; i < u_args_size; i++) {
		if (u_args[i].type == Integer) {
			blobmsg_add_u32(b, u_args[i].key, DM_STRTOL(u_args[i].val));
		} else if (u_args[i].type == Boolean) {
			bool val = false;
			string_to_bool((char *)u_args[i].val, &val);
			blobmsg_add_u8(b, u_args[i].key, val);
		} else if (u_args[i].type == Table) {
			json_object *jobj = json_tokener_parse(u_args[i].val);
			blobmsg_add_json_element(b, u_args[i].key, jobj);
			json_object_put(jobj);
		} else {
			blobmsg_add_string(b, u_args[i].key, u_args[i].val);
		}
	}
}

static void receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	const char *str;

	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	if (!str) {
		json_res = NULL;
		return;
	}

	json_res = json_tokener_parse(str);
	free((char *)str); //MEM should be free and not dmfree
}

static void __async_result_callback(struct ubus_request *req, int type, struct blob_attr *msg)
{
	time_t resp_time = time(NULL);

	const unsigned *hash = (unsigned *)req->priv;

	if (!hash) {
		// This should not happen
		printf("Hash found NULL in callback request\n\r");
		return;
	}

	struct dm_ubus_cache_entry *entry = (struct dm_ubus_cache_entry *)dm_ubus_cache_lookup(*hash);

	if (!entry) {
		// This should not happen unless resp took too long
		printf("Hash not found in cache\n\r");
	} else {
		entry->resp_time = resp_time;
		entry->async_call_running = false;

		if (entry->data) {
			json_object_put(entry->data);
		}

		if (difftime(resp_time, entry->last_request) >= UBUS_TIMEOUT/1000) {
			printf("Req [%s:%s] has been timedout in async call %lu, %lu\n\r",
				entry->obj, entry->method, resp_time, entry->last_request);
			entry->failed = true;
		} else {
			entry->failed = false;
		}

		if (!msg) {
			entry->data = NULL;
			return;
		}

		const char *str = blobmsg_format_json_indent(msg, true, -1);
		if (!str) {
			entry->data = NULL;
			return;
		}

		json_object *json_resp = json_tokener_parse(str);
		entry->data = json_resp;
		free((char *)str); //MEM should be free and not dmfree
	}
}

static void __async_complete_callback(struct ubus_request *req, int ret)
{
	if (req) {
		if (req->priv) {
			free(req->priv);
		}

		free(req);
	}
}

static int __dm_ubus_call(const char *obj, const char *method, struct blob_attr *attr)
{
	uint32_t id;
	int rc = 0;

	json_res = NULL;

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL) {
			printf("UBUS context is null\n\r");
			return -1;
		}
	}

	if (!ubus_lookup_id(ubus_ctx, obj, &id))
		rc = ubus_invoke(ubus_ctx, id, method, attr,
				receive_call_result_data, NULL, UBUS_TIMEOUT);
	else
		rc = -1;

	return rc;
}

static int __ubus_call_blocking(const char *obj, const char *method, struct blob_attr *attr)
{
	uint32_t id = 0;
	int rc = 0;

	json_res = NULL;

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL) {
			printf("UBUS context is null\n\r");
			return -1;
		}
	}

	if (ubus_lookup_id(ubus_ctx, obj, &id) != 0) {
		return -1;
	}

	rc = ubus_invoke(ubus_ctx, id, method, attr,
			receive_call_result_data, NULL, UBUS_MAX_BLOCK_TIME);

	return rc;
}

int dmubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size)
{
	struct blob_buf b;

	memset(&b, 0, sizeof(struct blob_buf));
	prepare_blob_message(&b, u_args, u_args_size);

	int rc = __dm_ubus_call(obj, method, b.head);

	if (json_res != NULL) {
		json_object_put(json_res);
		json_res = NULL;
	}

	blob_buf_free(&b);
	return rc;
}

struct dmubus_event_data {
	struct uloop_timeout tm;
	struct ubus_event_handler ev;
	struct blob_attr *ev_msg;
};

static void dmubus_receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
				const char *type, struct blob_attr *msg)
{
	struct dmubus_event_data *data;

	if (!msg || !ev)
		return;

	/* container_of() is an external macro and which cppcheck can't track
	 * so throws warning of null pointer dereferencing for second argument
	 * suppressed the warning */
	// cppcheck-suppress nullPointer
	data = container_of(ev, struct dmubus_event_data, ev);
	if (validate_blob_message(data->ev_msg, msg) == true) {
		uloop_end();
	}

	return;
}

static void dmubus_listen_timeout(struct uloop_timeout *timeout)
{
	uloop_end();
}

/*********************************************************************//**
**
** dmubus_register_event_blocking
**
** This API is to wait for the specified event to arrive on ubus or the timeout
** whichever is earlier
**
** NOTE: since this is a blocking call so it should only be called from DM_ASYNC
**       operations.
**
** \param   event - event to be listened on ubus
** \param   timeout - max time (seconds) to wait for the event
** \param   type - event type for which the process need to wait
**
** E.G: event: wifi.radio, type: {"radio":"wl1","action":"scan_finished"}
**
**************************************************************************/
void dmubus_register_event_blocking(char *event, int timeout, struct blob_attr *type)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	if (!ctx)
		return;

	struct dmubus_event_data data = {
		.tm.cb = dmubus_listen_timeout,
		.ev.cb = dmubus_receive_event,
		.ev_msg = type,
	};

	uloop_init();
	ubus_add_uloop(ctx);

	int ret = ubus_register_event_handler(ctx, &data.ev, event);
	if (ret)
		goto end;

	uloop_timeout_set(&data.tm, timeout * 1000);
	uloop_run();
	uloop_done();
	ubus_unregister_event_handler(ctx, &data.ev);

end:
	ubus_free(ctx);
	return;
}

static inline json_object *ubus_call_req(char *obj, char *method, struct blob_attr *attr)
{
	__dm_ubus_call(obj, method, attr);
	return json_res;
}

static int ubus_call_req_async(const char *obj, const char *method, const unsigned hash, struct blob_attr *attr)
{
	uint32_t id;

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL) {
			printf("UBUS context is null\n\r");
			return -1;
		}
	}

	if (!ubus_lookup_id(ubus_ctx, obj, &id)) {
		struct ubus_request *req = (struct ubus_request *)malloc(sizeof(struct ubus_request));
		if (req == NULL) {
			printf("Out of memory!\n\r");
			return -1;
		}

		memset(req, 0, sizeof(struct ubus_request));

		int rc = ubus_invoke_async(ubus_ctx, id, method, attr, req);
		if (rc) {
			printf("Ubus async invoke failed (%s)\n\r", ubus_strerror(rc));
			free(req);
			return -1;
		}

		unsigned *p = (unsigned *)malloc(sizeof(unsigned));
		if (p == NULL) {
			printf("memory allocation failed\n\r");
			free(req);
			return -1;
		}

		*p = hash;
		req->data_cb = __async_result_callback;
		req->complete_cb = __async_complete_callback;
		req->priv = (void *)p;

		ubus_complete_request_async(ubus_ctx, req);
	} else {
		printf("Ubus lookup id failed from async call\n\r");
		return -1;
	}

	return 0;
}

int dmubus_operate_blob_set(char *obj, char *method, void *value, json_object **resp)
{
	uint32_t id;
	struct blob_buf blob;
	int rc = -1;

	json_res = NULL;
	*resp = NULL;

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL) {
			printf("UBUS context is null\n\r");
			return -1;
		}
	}

	memset(&blob, 0, sizeof(struct blob_buf));
	blob_buf_init(&blob, 0);

	if (value != NULL) {
		if (!blobmsg_add_object(&blob, (json_object *)value)) {
			blob_buf_free(&blob);
			return rc;
		}
	}

	if (!ubus_lookup_id(ubus_ctx, obj, &id)) {
		rc = ubus_invoke(ubus_ctx, id, method, blob.head,
				 receive_call_result_data, NULL, UBUS_TIMEOUT);
	}

	*resp = json_res;
	blob_buf_free(&blob);
	return rc;
}

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
	if (!req) {
		return hash;
	}

	hash = djbhash(hash, req->obj, DM_STRLEN(req->obj));
	hash = djbhash(hash, req->method, DM_STRLEN(req->method));

	char *jmsg = blobmsg_format_json(req->attr, true);
	if (!jmsg) {
		return hash;
	}

	hash = djbhash(hash, jmsg, DM_STRLEN(jmsg));
	free(jmsg);
	return hash;
}

static const struct dm_ubus_cache_entry * dm_ubus_cache_lookup(unsigned hash)
{
	const struct dm_ubus_cache_entry *entry = NULL;
	const struct dm_ubus_cache_entry *entry_match = NULL;

	list_for_each_entry(entry, &dmubus_cache, list) {
		if (entry->hash == hash) {
			entry_match = entry;
			break;
		}
	}
	return entry_match;
}

static void dm_ubus_cache_entry_new(unsigned hash, json_object *data, char *obj, char *method,
		time_t req_time, time_t resp_time, struct blob_attr *breq)
{
	struct dm_ubus_cache_entry *entry = malloc(sizeof(*entry));

	if (entry) {
		entry->data = data;
		entry->hash = hash;
		entry->last_request = req_time;
		entry->resp_time = resp_time;
		entry->breq = breq;
		entry->failed = data ? true : false;
		entry->async_call_running = false;
		DM_STRNCPY(entry->obj, obj, sizeof(entry->obj));
		DM_STRNCPY(entry->method, method,  sizeof(entry->method));
		list_add_tail(&entry->list, &dmubus_cache);
	}
}

static void dm_ubus_cache_entry_free(struct dm_ubus_cache_entry *entry)
{
	list_del(&entry->list);

	if (entry->breq)
		FREE(entry->breq);

	if (entry->data)
		json_object_put(entry->data);

	FREE(entry);
}

int dmubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	struct blob_buf bmsg;

	memset(&bmsg, 0, sizeof(struct blob_buf));
	prepare_blob_message(&bmsg, u_args, u_args_size);

	const struct dm_ubus_hash_req hash_req = {
		.obj = obj,
		.method = method,
		.attr = bmsg.head
	};

	const unsigned hash = dm_ubus_req_hash_from_blob(&hash_req);
	const struct dm_ubus_cache_entry *entry = dm_ubus_cache_lookup(hash);
	json_object *res = NULL;

	if (entry) {
		res = entry->data;
	} else {
		time_t req_time = time(NULL);
		res = ubus_call_req(obj, method, bmsg.head);
		time_t resp_time = time(NULL);

		dm_ubus_cache_entry_new(hash, res, obj, method, req_time, resp_time, blob_memdup(bmsg.head));
	}

	blob_buf_free(&bmsg);
	*req_res = res;
	return 0;
}

int dmubus_call_blocking(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	int rc = 0;
	struct blob_buf bmsg;

	memset(&bmsg, 0, sizeof(struct blob_buf));
	prepare_blob_message(&bmsg, u_args, u_args_size);

	rc = __ubus_call_blocking(obj, method, bmsg.head);

	blob_buf_free(&bmsg);
	*req_res = json_res;

	return rc;
}

static int dmubus_call_async(const char *obj, const char *method, struct blob_attr *attr)
{
	const struct dm_ubus_hash_req hash_req = {
		.obj = obj,
		.method = method,
		.attr = attr
	};

	const unsigned hash = dm_ubus_req_hash_from_blob(&hash_req);
	struct dm_ubus_cache_entry *entry = (struct dm_ubus_cache_entry *)dm_ubus_cache_lookup(hash);

	if (entry) {
		entry->last_request = time(NULL);
		entry->failed = false;
		entry->async_call_running = true;
		if (-1 == ubus_call_req_async(obj, method, hash, attr)) {
			printf("Ubus call async failed\n\r");
			entry->failed = true;
			entry->resp_time = time(NULL);
			if (entry->data) {
				json_object_put(entry->data);
				entry->data = NULL;
			}
			entry->async_call_running = false;
		}
	}

	return 0;
}

static void receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *cur = NULL;
	size_t rem = 0;

	if (!obj->signature  || *ubus_method == '\0')
		return;

	blob_for_each_attr(cur, obj->signature, rem) {
		const char *method_name = blobmsg_name(cur);
		if (!DM_STRCMP(ubus_method, method_name)) {
			ubus_method_exists = true;
			return;
		}
	}
}

bool dmubus_object_method_exists(const char *obj)
{
	if (obj == NULL)
		return false;

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL) {
			return false;
		}
	}

	char *method = "";
	// check if the method exists in the obj
	// if yes, copy it in ubus_method buffer
	char *delimiter = strstr(obj, "->");
	if (delimiter) {
		method = dmstrdup(delimiter + 2);
		*delimiter = '\0';
	}

	DM_STRNCPY(ubus_method, method, sizeof(ubus_method));
	ubus_method_exists = false;

	if (ubus_lookup(ubus_ctx, obj, receive_list_result, NULL))
		return false;

	if (*ubus_method != '\0' && !ubus_method_exists)
		return false;

	return true;
}

void dmubus_configure(struct ubus_context *ctx)
{
	ubus_ctx = ctx;
}

void dmubus_clean_endlife_entries()
{
	if (hard_limit_g != 0) {
		struct dm_ubus_cache_entry *entry, *tmp;
		time_t curr_time = time(NULL);

		list_for_each_entry_safe(entry, tmp, &dmubus_cache, list) {
			if (difftime(curr_time, entry->last_request) >= hard_limit_g) {
				dm_ubus_cache_entry_free(entry);
			}
		}
	}
}

void dmubus_update_cached_entries()
{
	if (hard_limit_g == 0 || local_ctx_g == true) {
		dmubus_free();
		dm_libubus_free();
	} else {
		struct dm_ubus_cache_entry *entry;
		time_t curr_time = time(NULL);

		list_for_each_entry(entry, &dmubus_cache, list) {
			// There could be a case when async call done previously but response still
			// not received or the previous ubus call took >= soft_limit_g sec, so in that case no
			// need to perform async call again & wait for HARD_LIMIT to delete the entry from cache

			if (entry->async_call_running || entry->failed)
				continue;

			double time_elapsed = difftime(curr_time, entry->last_request);
			if (time_elapsed >= soft_limit_g && time_elapsed < hard_limit_g) {
				dmubus_call_async(entry->obj, entry->method, entry->breq);
			}
		}
	}
}

void dmubus_free()
{
	struct dm_ubus_cache_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &dmubus_cache, list)
		dm_ubus_cache_entry_free(entry);

}

void dmubus_set_caching_time(int seconds)
{
	if (seconds < 2)
		return;

	soft_limit_g = seconds/2;
	hard_limit_g = seconds;
}
