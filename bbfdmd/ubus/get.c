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

#include <libubus.h>
#include <libubox/blobmsg_json.h>

#include "common.h"
#include "service.h"
#include "get.h"
#include "pretty_print.h"

extern int g_log_level;

static void prepare_and_send_response(struct async_request_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->path_matched == false) {
		print_fault_message(&ctx->tmp_bb, ctx->requested_path, 9005, "Invalid parameter name");
	}

	blobmsg_close_array(&ctx->tmp_bb, ctx->array);

	if (strcmp(ctx->ubus_method, "get") == 0 && ctx->raw_format == false) { // Pretty Format
		struct blob_buf bb_pretty = {0};

		memset(&bb_pretty, 0, sizeof(struct blob_buf));
		blob_buf_init(&bb_pretty, 0);

		prepare_pretty_response(ctx->requested_path, ctx->tmp_bb.head, &bb_pretty);

		ubus_send_reply(ctx->ubus_ctx, &ctx->request_data, bb_pretty.head);
		blob_buf_free(&bb_pretty);
	} else { // Raw Format
		ubus_send_reply(ctx->ubus_ctx, &ctx->request_data, ctx->tmp_bb.head);
	}
}

void send_response(struct async_request_context *ctx)
{
	prepare_and_send_response(ctx);

	ubus_complete_deferred_request(ctx->ubus_ctx, &ctx->request_data, UBUS_STATUS_OK);
	blob_buf_free(&ctx->tmp_bb);

	BBFDM_INFO("END: ubus method|%s|, name|bbfdm|, path|%s|", ctx->ubus_method, ctx->requested_path);
	BBFDM_FREE(ctx);
}

static void append_response_data(struct ubus_request_tracker *tracker, struct blob_attr *msg)
{
	struct blob_attr *attr = NULL;
	int remaining = 0;

	if (!tracker || !msg)
		return;

	struct blob_attr *results = get_results_array(msg);
	if (!results)
		return;

	blobmsg_for_each_attr(attr, results, remaining) {
		blobmsg_add_blob(&tracker->ctx->tmp_bb, attr);
	}
}

static void handle_request_timeout(struct uloop_timeout *timeout)
{
	struct ubus_request_tracker *tracker = container_of(timeout, struct ubus_request_tracker, timeout);
	BBFDM_WARNING("Timeout occurred for request: '%s %s'", tracker->request_name, tracker->ctx->requested_path);

	ubus_abort_request(tracker->ctx->ubus_ctx, &tracker->async_request);
	tracker->ctx->pending_requests--;

	service_entry_t *service = tracker->service;

	if (service) {
		service->consecutive_timeouts++;
		if (service->consecutive_timeouts >= SERVICE_MAX_CONSECUTIVE_TIMEOUTS) {
			service->is_blacklisted = true;
			BBFDM_ERR("Service '%s' has been blacklisted due to repeated timeouts", service->name);
		}
	}

	if (tracker->ctx->pending_requests == 0 && tracker->ctx->service_list_processed) {
		BBFDM_WARNING("All requests completed after timeout");
		send_response(tracker->ctx);
	}

	BBFDM_FREE(tracker);
}

static void ubus_result_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg __attribute__((unused)))
{
	struct ubus_request_tracker *tracker = container_of(req, struct ubus_request_tracker, async_request);

	if (msg) {
		BBFDM_DEBUG("Response from object '%s %s'", tracker->request_name, tracker->ctx->requested_path);
		append_response_data(tracker, msg);
	}
}

static void ubus_request_complete(struct ubus_request *req, int ret)
{
	struct ubus_request_tracker *tracker = container_of(req, struct ubus_request_tracker, async_request);
	BBFDM_DEBUG("Request completed for '%s %s' with status: '%d'", tracker->request_name, tracker->ctx->requested_path, ret);

	uloop_timeout_cancel(&tracker->timeout);
	tracker->ctx->pending_requests--;

	if (tracker->service && ret == UBUS_STATUS_OK)
		tracker->service->consecutive_timeouts = 0;

	if (tracker->ctx->pending_requests == 0 && tracker->ctx->service_list_processed) {
		BBFDM_DEBUG("Result Callback: All requests completed");
		send_response(tracker->ctx);
	}

	BBFDM_FREE(tracker);
}

void run_async_call(struct async_request_context *ctx, service_entry_t *service, struct blob_attr *msg)
{
	struct blob_buf req_buf = {0};
	struct blob_attr *attr = NULL;
	int remaining = 0;
	uint32_t id = 0;

	if (!ctx || !service || !msg || !service->name) {
		BBFDM_ERR("Invalid arguments");
		return;
	}

	if (ubus_lookup_id(ctx->ubus_ctx, service->name, &id)) {
		BBFDM_INFO("Failed to lookup object: %s", service->name);
		return;
	}

	struct ubus_request_tracker *tracker = (struct ubus_request_tracker *)calloc(1, sizeof(struct ubus_request_tracker));
	if (!tracker) {
		BBFDM_ERR("Failed to allocate memory for request tracker");
		return;
	}

	tracker->ctx = ctx;
	tracker->service = service;
	ctx->pending_requests++;
	ctx->path_matched = true;

	memset(&req_buf, 0, sizeof(struct blob_buf));
	blob_buf_init(&req_buf, 0);

	blob_for_each_attr(attr, msg, remaining) {
		blobmsg_add_field(&req_buf, blobmsg_type(attr), blobmsg_name(attr), blobmsg_data(attr), blobmsg_len(attr));
	}

	snprintf(tracker->request_name, sizeof(tracker->request_name), "%s->%s", service->name, ctx->ubus_method);

	tracker->timeout.cb = handle_request_timeout;
	uloop_timeout_set(&tracker->timeout, !strcmp(ctx->ubus_method, "operate") ? SERVICE_CALL_OPERATE_TIMEOUT : service->timeout);

	if (g_log_level == LOG_DEBUG) {
		char *json_str = blobmsg_format_json_indent(req_buf.head, true, -1);
		BBFDM_DEBUG("### ubus call %s %s '%s' ###", service->name, ctx->ubus_method, json_str);
		BBFDM_FREE(json_str);
	}

	if (ubus_invoke_async(ctx->ubus_ctx, id, ctx->ubus_method, req_buf.head, &tracker->async_request)) {
		BBFDM_WARNING("Failed to invoke async method for object: %s", tracker->request_name);
		uloop_timeout_cancel(&tracker->timeout);
		BBFDM_FREE(tracker);
	} else {
		tracker->async_request.data_cb = ubus_result_callback;
		tracker->async_request.complete_cb = ubus_request_complete;
		ubus_complete_request_async(ctx->ubus_ctx, &tracker->async_request);
	}

	blob_buf_free(&req_buf);
}
