/*
 * Copyright (C) 2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "bbfdm_api.h"

int bbfdm_init_ubus_ctx(struct bbfdm_ctx *bbfdm_ctx)
{
	bbfdm_ctx->ubus_ctx = ubus_connect(NULL);
	if (!bbfdm_ctx->ubus_ctx) {
		BBFDM_ERR("Failed to connect to UBUS");
		return -1;
	}

	return 0;
}

int bbfdm_free_ubus_ctx(struct bbfdm_ctx *bbfdm_ctx)
{
	if (bbfdm_ctx->ubus_ctx) {
		ubus_free(bbfdm_ctx->ubus_ctx);
	}

	return 0;
}

int bbfdm_ubus_invoke_sync(struct bbfdm_ctx *bbfdm_ctx, const char *obj, const char *method, struct blob_attr *msg, int timeout,
		bbfdm_ubus_cb data_callback, void *callback_args)
{
	uint32_t id;

	if (!bbfdm_ctx || !bbfdm_ctx->ubus_ctx) {
		BBFDM_ERR("Invalid context or UBUS context is NULL");
		return -1;
	}

	if (ubus_lookup_id(bbfdm_ctx->ubus_ctx, obj, &id)) {
		BBFDM_ERR("Failed to lookup UBUS object ID for '%s' using method '%s'", obj, method);
		return -1;
	}

	int ret = ubus_invoke(bbfdm_ctx->ubus_ctx, id, method, msg, data_callback, callback_args, timeout);

	if (ret != 0) {
		BBFDM_ERR("UBUS invoke failed for obj='%s', method='%s', error code=%d", obj, method, ret);
	}

	return ret;
}

int bbfdm_ubus_invoke_async(struct ubus_context *ubus_ctx, const char *obj, const char *method, struct blob_attr *msg,
		bbfdm_ubus_cb data_callback, bbfdm_ubus_async_cb complete_callback)
{
	struct ubus_request *req = NULL;
	uint32_t id;

	if (ubus_ctx == NULL) {
		BBFDM_ERR("UBUS context is NULL");
		return -1;
	}

	if (ubus_lookup_id(ubus_ctx, obj, &id)) {
		BBFDM_ERR("Failed to lookup UBUS object ID for '%s' using method '%s'", obj, method);
		return -1;
	}

	req = (struct ubus_request *)calloc(1, sizeof(struct ubus_request));
	if (req == NULL) {
		BBFDM_ERR("Failed to allocate memory for UBUS request");
		return -1;
	}

	if (ubus_invoke_async(ubus_ctx, id, method, msg, req)) {
		BBFDM_ERR("UBUS async invoke failed for obj='%s', method='%s'", obj, method);
		BBFDM_FREE(req);
		return -1;
	}

	if (data_callback)
		req->data_cb = data_callback;

	if (complete_callback)
		req->complete_cb = complete_callback;

	ubus_complete_request_async(ubus_ctx, req);
	return 0;
}

int bbfdm_ubus_send_event(struct bbfdm_ctx *bbfdm_ctx, const char *obj, struct blob_attr *msg)
{
	if (!bbfdm_ctx || !bbfdm_ctx->ubus_ctx) {
		BBFDM_ERR("Invalid context or UBUS context is NULL");
		return -1;
	}

	int ret = ubus_send_event(bbfdm_ctx->ubus_ctx, obj, msg);

	if (ret != 0) {
		BBFDM_ERR("UBUS send event failed for obj='%s', error code=%d", obj, ret);
	}

	return ret;
}
