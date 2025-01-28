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

static void add_linker_entry(struct async_request_context *ctx, const char *linker_path, const char *linker_value)
{
	struct linker_args *linker = calloc(1, sizeof(struct linker_args));
	if (!linker)
		return;

	list_add_tail(&linker->list, &ctx->linker_list);
	linker->path = strdup(linker_path ? linker_path : "");
	linker->value = strdup(linker_value ? linker_value : "");
}

static void free_linker_entries(struct async_request_context *ctx)
{
	struct linker_args *linker = NULL, *tmp = NULL;

	list_for_each_entry_safe(linker, tmp, &ctx->linker_list, list) {
		list_del(&linker->list);
		BBFDM_FREE(linker->path);
		BBFDM_FREE(linker->value);
		BBFDM_FREE(linker);
	}
}

static void fill_blob_param(struct blob_buf *bb, const char *path, const char *data, const char *type)
{
	if (!bb || !path || !data || !type)
		return;

	void *table = blobmsg_open_table(bb, NULL);

	blobmsg_add_string(bb, "path", path);
	blobmsg_add_string(bb, "data", data);
	blobmsg_add_string(bb, "type", type);

	blobmsg_close_table(bb, table);
}

static void resolve_reference_path(struct async_request_context *ctx, char *ref_path, char *output, size_t output_len)
{
	char *token = NULL, *saveptr = NULL;
	char buffer[MAX_PATH_LENGTH] = {0};

	if (!ref_path || !output || !output_len) {
		BBFDM_ERR("Invalid arguments");
		return;
	}

	// Initialize output buffer
	output[0] = 0;

	// Return if reference path is empty
	if (strlen(ref_path) == 0)
		return;

	snprintf(buffer, sizeof(buffer), "%s", ref_path);

	for (token = strtok_r(buffer, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {

		// Reference is found, don't need to parse the list
		if (!strchr(token, '[')) {
			snprintf(output, output_len, "%s", token);
			return;
		}

		struct linker_args *linker = NULL;
		list_for_each_entry(linker, &ctx->linker_list, list) {
			// Reference is found in the resolved list
			if (strcmp(linker->path, token) == 0 && strlen(linker->value) != 0) {
				snprintf(output, output_len, "%s", linker->value);
				return;
			}
		}

		// Reference is not found in the resolved list
		{
			// Try to get reference value from micro-services directly
			char *reference_path = get_reference_data(token, "reference_path");

			// Add path to list in order to be used by other parameters
			add_linker_entry(ctx, token, reference_path ? reference_path : "");

			// Reference value is found
			if (reference_path != NULL) {
				snprintf(output, output_len, "%s", reference_path);
				BBFDM_FREE(reference_path);
				return;
			}
		}
	}

	BBFDM_ERR("Can't resolve reference path '%s' -> Set its value to empty", ref_path);
}

static void prepare_and_send_response(struct async_request_context *ctx)
{
	struct blob_attr *attr = NULL;
	struct blob_buf bb = {0};
	int remaining = 0;

	if (!ctx)
		return;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	void *array = blobmsg_open_array(&bb, "results");

	if (ctx->path_matched == false) {
		void *table = blobmsg_open_table(&bb, NULL);
		blobmsg_add_string(&bb, "path", ctx->requested_path);
		blobmsg_add_u32(&bb, "fault", 9005);
		blobmsg_add_string(&bb, "fault_msg", "Invalid parameter name");
		blobmsg_close_table(&bb, table);
	} else {
		blobmsg_for_each_attr(attr, ctx->tmp_bb.head, remaining) {

			if (strcmp(ctx->ubus_method, "get") == 0) {
				struct blob_attr *fields[4];
				const struct blobmsg_policy policy[4] = {
					{ "path", BLOBMSG_TYPE_STRING },
					{ "data", BLOBMSG_TYPE_STRING },
					{ "type", BLOBMSG_TYPE_STRING },
					{ "reference", BLOBMSG_TYPE_BOOL },
				};

				blobmsg_parse(policy, 4, fields, blobmsg_data(attr), blobmsg_len(attr));

				bool is_reference = fields[3] ? blobmsg_get_u8(fields[3]) : false;

				if (is_reference) {
					char buffer[1024] = {0};

					char *path = fields[0] ? blobmsg_get_string(fields[0]) : "";
					char *data = fields[1] ? blobmsg_get_string(fields[1]) : "";
					char *type = fields[2] ? blobmsg_get_string(fields[2]) : "";

					resolve_reference_path(ctx, data, buffer, sizeof(buffer));
					fill_blob_param(&bb, path, buffer, type);
				} else {
					blobmsg_add_blob(&bb, attr);
				}
			} else {
				blobmsg_add_blob(&bb, attr);
			}
		}
	}

	blobmsg_close_array(&bb, array);

	ubus_send_reply(ctx->ubus_ctx, &ctx->request_data, bb.head);
	blob_buf_free(&bb);
}

void send_response(struct async_request_context *ctx)
{
	prepare_and_send_response(ctx);

	if (strcmp(ctx->ubus_method, "get") == 0) {
		ubus_unregister_event_handler(ctx->ubus_ctx, &ctx->linker_handler);
		send_linker_cleanup_event(ctx->ubus_ctx);
		free_linker_entries(ctx);
	}

	ubus_complete_deferred_request(ctx->ubus_ctx, &ctx->request_data, UBUS_STATUS_OK);
	blob_buf_free(&ctx->tmp_bb);
	BBFDM_FREE(ctx);
}

static struct blob_attr *get_results_array(struct blob_attr *msg)
{
	struct blob_attr *tb[1] = {0};
	const struct blobmsg_policy p[1] = {
			{ "results", BLOBMSG_TYPE_ARRAY }
	};

	if (msg == NULL)
		return NULL;

	blobmsg_parse(p, 1, tb, blobmsg_data(msg), blobmsg_len(msg));

	return tb[0];
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
	BBFDM_ERR("Timeout occurred for request: '%s'", tracker->request_name);

	ubus_abort_request(tracker->ctx->ubus_ctx, &tracker->async_request);
	tracker->ctx->pending_requests--;

	if (tracker->ctx->pending_requests == 0 && tracker->ctx->service_list_processed) {
		BBFDM_ERR("All requests completed after timeout");
		send_response(tracker->ctx);
	}

	BBFDM_FREE(tracker);
}

static void ubus_result_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg __attribute__((unused)))
{
	struct ubus_request_tracker *tracker = container_of(req, struct ubus_request_tracker, async_request);

	if (msg) {
		BBFDM_DEBUG("Response from object '%s'", tracker->request_name);
		append_response_data(tracker, msg);
	}
}

static void ubus_request_complete(struct ubus_request *req, int ret)
{
	struct ubus_request_tracker *tracker = container_of(req, struct ubus_request_tracker, async_request);
	BBFDM_DEBUG("Request completed for '%s' with status: '%d'", tracker->request_name, ret);

	uloop_timeout_cancel(&tracker->timeout);
	tracker->ctx->pending_requests--;

	if (tracker->ctx->pending_requests == 0 && tracker->ctx->service_list_processed) {
		BBFDM_DEBUG("Result Callback: All requests completed");
		send_response(tracker->ctx);
	}

	BBFDM_FREE(tracker);
}

void run_async_call(struct async_request_context *ctx, const char *ubus_obj, struct blob_attr *msg)
{
	struct blob_buf req_buf = {0};
	struct blob_attr *attr = NULL;
	int remaining = 0;
	uint32_t id = 0;

	if (!ctx || !ubus_obj || !msg) {
		BBFDM_ERR("Invalid arguments");
		return;
	}

	if (ubus_lookup_id(ctx->ubus_ctx, ubus_obj, &id)) {
		BBFDM_ERR("Failed to lookup object: %s", ubus_obj);
		return;
	}

	struct ubus_request_tracker *tracker = calloc(1, sizeof(struct ubus_request_tracker));
	if (!tracker) {
		BBFDM_ERR("Failed to allocate memory for request tracker");
		return;
	}

	tracker->ctx = ctx;
	ctx->pending_requests++;
	ctx->path_matched = true;

	memset(&req_buf, 0, sizeof(struct blob_buf));
	blob_buf_init(&req_buf, 0);

	blob_for_each_attr(attr, msg, remaining) {
		blobmsg_add_field(&req_buf, blobmsg_type(attr), blobmsg_name(attr), blobmsg_data(attr), blobmsg_len(attr));
	}

	snprintf(tracker->request_name, sizeof(tracker->request_name), "%s->%s", ubus_obj, ctx->ubus_method);

	tracker->timeout.cb = handle_request_timeout;
	uloop_timeout_set(&tracker->timeout, SERVICE_CALL_TIMEOUT);

	BBFDM_DEBUG("### ubus call %s %s '%s' ###", ubus_obj, ctx->ubus_method, blobmsg_format_json_indent(req_buf.head, true, -1));

	if (ubus_invoke_async(ctx->ubus_ctx, id, ctx->ubus_method, req_buf.head, &tracker->async_request)) {
		BBFDM_ERR("Failed to invoke async method for object: %s", tracker->request_name);
		uloop_timeout_cancel(&tracker->timeout);
		BBFDM_FREE(tracker);
	} else {
		tracker->async_request.data_cb = ubus_result_callback;
		tracker->async_request.complete_cb = ubus_request_complete;
		ubus_complete_request_async(ctx->ubus_ctx, &tracker->async_request);
	}

	blob_buf_free(&req_buf);
}

void send_linker_cleanup_event(struct ubus_context *ctx)
{
	struct blob_buf bb = {0};

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);
	ubus_send_event(ctx, "bbfdm.linker.cleanup", bb.head);
	blob_buf_free(&bb);
}

void linker_response_callback(struct ubus_context *ctx __attribute__((unused)), struct ubus_event_handler *ev, const char *type __attribute__((unused)), struct blob_attr *msg)
{
	struct async_request_context *context = NULL;
	struct blob_attr *attr = NULL;
	size_t rem = 0;

	if (!msg)
		return;

	context = container_of(ev, struct async_request_context, linker_handler);
	if (context == NULL) {
		BBFDM_ERR("Failed to get the request context");
		return;
	}

	blobmsg_for_each_attr(attr, msg, rem) {
		BBFDM_DEBUG("LINKER RESPONSE: '%s' <=> '%s'", blobmsg_name(attr), blobmsg_get_string(attr));
		add_linker_entry(context, blobmsg_name(attr), blobmsg_get_string(attr));
	}
}
