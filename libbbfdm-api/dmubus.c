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

static LIST_HEAD(dmubus_cache);

struct dm_ubus_cache_entry {
	struct list_head list;
	json_object *data;
	unsigned hash;
};

struct dm_ubus_hash_req {
	const char *obj;
	const char *method;
	struct blob_attr *attr;
};


struct ubus_struct {
	char *ubus_method_name;
	bool ubus_method_exists;
};

static struct ubus_context *ubus_ctx = NULL;
static json_object *json_res = NULL;

static const struct dm_ubus_cache_entry * dm_ubus_cache_lookup(unsigned hash);

static struct ubus_context *dm_libubus_init()
{
	return ubus_connect(NULL);
}

static void dm_libubus_free()
{
	if (ubus_ctx) {
		ubus_free(ubus_ctx);
		ubus_ctx = NULL;
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
**
** E.G: event: sysupgrade, type: {"status":"Downloading","bank_id":"2"}
**
*******************************************************************************/
void dmubus_wait_for_event(const char *event, int timeout, void *ev_data, CB_FUNC_PTR ev_callback)
{
	if (DM_STRLEN(event) == 0)
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

int dmubus_call_blob(char *obj, char *method, void *value, json_object **resp)
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

int dmubus_call_blob_set(char *obj, char *method, void *value)
{
	uint32_t id;
	struct blob_buf blob;
	int rc = -1;

	json_res = NULL;

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

	if (json_res != NULL) {
		json_object_put(json_res);
		json_res = NULL;
	}

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

static void dm_ubus_cache_entry_new(unsigned hash, json_object *data)
{
	struct dm_ubus_cache_entry *entry = malloc(sizeof(*entry));

	if (entry) {
		entry->data = data;
		entry->hash = hash;
		list_add_tail(&entry->list, &dmubus_cache);
	}
}

static void dm_ubus_cache_entry_free(struct dm_ubus_cache_entry *entry)
{
	list_del(&entry->list);

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
		res = ubus_call_req(obj, method, bmsg.head);
		dm_ubus_cache_entry_new(hash, res);
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

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL)
			return false;
	}

	snprintf(ubus_object, sizeof(ubus_object), "%s", object);

	// check if the method exists in the ubus_object
	char *delimiter = strstr(ubus_object, "->");
	if (delimiter) {
		ubus_s.ubus_method_name = dmstrdup(delimiter + 2);
		*delimiter = '\0';
	}

	if (ubus_lookup(ubus_ctx, ubus_object, receive_list_result, &ubus_s))
		return false;

	if (ubus_s.ubus_method_name && !ubus_s.ubus_method_exists)
		return false;

	return true;
}

void dmubus_free()
{
	struct dm_ubus_cache_entry *entry, *tmp;

	// cppcheck-suppress unknownMacro
	list_for_each_entry_safe(entry, tmp, &dmubus_cache, list)
		dm_ubus_cache_entry_free(entry);

	dm_libubus_free();

}
