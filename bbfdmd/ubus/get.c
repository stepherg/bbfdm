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

static void add_linker_entry(struct async_request_context *ctx, const char *linker_path, const char *linker_value)
{
	struct linker_args *linker = (struct linker_args *)calloc(1, sizeof(struct linker_args));
	if (!linker) {
		BBFDM_ERR("Failed to allocate memory");
		return;
	}

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

static bool is_reference_value(struct blob_attr *flags)
{
	struct blob_attr *flag = NULL;
	int rem = 0;

	if (!flags || blobmsg_type(flags) != BLOBMSG_TYPE_ARRAY)
		return false;

	blobmsg_for_each_attr(flag, flags, rem) {
		if (strcmp(blobmsg_get_string(flag), "Reference") == 0)
			return true;
	}

	return false;
}

static void fill_blob_param(struct blob_buf *bb, struct blob_attr *path, const char *data, struct blob_attr *type, struct blob_attr *flags)
{
	if (!bb || !path || !data || !type)
		return;

	void *table = blobmsg_open_table(bb, NULL);

	if (path) {
		blobmsg_add_field(bb, blobmsg_type(path), blobmsg_name(path), blobmsg_data(path), blobmsg_len(path));
	}

	blobmsg_add_string(bb, "data", data);

	if (type) {
		blobmsg_add_field(bb, blobmsg_type(type), blobmsg_name(type), blobmsg_data(type), blobmsg_len(type));
	}

	if (flags) {
		blobmsg_add_field(bb, blobmsg_type(flags), blobmsg_name(flags), blobmsg_data(flags), blobmsg_len(flags));
	}

	blobmsg_close_table(bb, table);
}

// Function to calculate FNV-1 hash
static void calculate_hash(const char *input, char *output, size_t out_len)
{
#define FNV_OFFSET_BASIS 0x811C9DC5
#define FNV_PRIME 0x1000193

	uint32_t hash = FNV_OFFSET_BASIS;

	while (*input != '\0') {
		hash *= FNV_PRIME;      // Multiply hash by prime
		hash ^= (uint8_t)(*input); // XOR with current character
		input++;
	}

	snprintf(output, out_len, "%08X", hash);
}

static int _uci_get_option_str(struct uci_context *uci_ctx,
		const char *package, const char *section, const char *option,
		char *out, size_t out_len)
{
	struct uci_ptr ptr = {0};
	char buf[128] = {0};

	snprintf(buf, sizeof(buf), "%s.%s.%s", package, section, option);

	if (uci_lookup_ptr(uci_ctx, &ptr, buf, true) != UCI_OK)
		return -1;

	if (ptr.o && ptr.o->type == UCI_TYPE_STRING)
		snprintf(out, out_len, "%s", ptr.o->v.string);

	return 0;
}

static void resolve_reference_path(struct async_request_context *ctx, struct blob_attr *data, char *output, size_t output_len)
{
	if (!ctx || !output || output_len == 0) {
		BBFDM_ERR("Invalid arguments");
		return;
	}

	output[0] = 0; // Ensure output buffer is initialized

	if (!data) {
		BBFDM_ERR("Invalid data value");
		return;
	}

	char *ref_path = blobmsg_get_string(data);
	if (!ref_path || ref_path[0] == '\0') // Empty reference path, nothing to resolve
		return;

	char buffer[MAX_VALUE_LENGTH] = {0};
	snprintf(buffer, sizeof(buffer), "%s", ref_path);

	// Check if it is a reference path (separator ',') or list paths (separator ';')
	bool is_ref_list = strchr(ref_path, ';') != NULL;
	char *token = NULL, *saveptr = NULL;
	unsigned pos = 0;

	for (token = strtok_r(buffer, is_ref_list ? ";" : ",", &saveptr);
		token;
		token = strtok_r(NULL, is_ref_list ? ";" : ",", &saveptr)) {

		// If token does not contain '[', it’s a direct reference
		if (!strchr(token, '[')) {
			pos += snprintf(&output[pos], output_len - pos, "%s,", token);
			if (!is_ref_list) break;
			continue;
		}

		// Search for token in the linker list
		struct linker_args *linker = NULL;
		bool linker_found = false;
		bool linker_empty = false;
		list_for_each_entry(linker, &ctx->linker_list, list) {
			if (strcmp(linker->path, token) == 0) {
				linker_found = true;

				if (linker->value[0] != '\0') {
					pos += snprintf(&output[pos], output_len - pos, "%s,", linker->value);
				} else {
					linker_empty = true;
				}

				break;
			}
		}

		if (linker_found) {
			if (linker_empty) continue;
			if (!is_ref_list) break;
			continue;
		}

		// If not found, attempt to resolve via micro-services
		{
			char reference_path[1024] = {0};
			char hash_str[9] = {0};

			calculate_hash(token, hash_str, sizeof(hash_str));

			_uci_get_option_str(ctx->uci_ctx, "bbfdm_reference_db", "reference_path", hash_str, reference_path, sizeof(reference_path));

			// Add path to list in order to be used by other parameters
			add_linker_entry(ctx, token, reference_path);

			// Reference value is found
			if (strlen(reference_path) != 0) {
				pos += snprintf(&output[pos], output_len - pos, "%s,", reference_path);
				if (!is_ref_list) break;
			}
		}
	}

	if (pos > 0) {
		output[pos - 1] = 0; // Remove trailing comma
	}
}

static void prepare_and_send_response(struct async_request_context *ctx)
{
	struct blob_attr *attr = NULL;
	struct blob_buf bb_raw = {0};
	size_t remaining = 0;

	if (!ctx)
		return;

	memset(&bb_raw, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb_raw, 0);

	void *array = blobmsg_open_array(&bb_raw, "results");

	if (ctx->path_matched == false) {
		print_fault_message(&bb_raw, ctx->requested_path, 9005, "Invalid parameter name");
	} else {
		blobmsg_for_each_attr(attr, ctx->tmp_bb.head, remaining) {
			if (strcmp(ctx->ubus_method, "get") == 0) {
				struct blob_attr *fields[4];
				const struct blobmsg_policy policy[4] = {
					{ "path", BLOBMSG_TYPE_STRING },
					{ "data", BLOBMSG_TYPE_STRING },
					{ "type", BLOBMSG_TYPE_STRING },
					{ "flags", BLOBMSG_TYPE_ARRAY },
				};

				blobmsg_parse(policy, 4, fields, blobmsg_data(attr), blobmsg_len(attr));

				if (is_reference_value(fields[3])) {
					char data[MAX_VALUE_LENGTH] = {0};
					resolve_reference_path(ctx, fields[1], data, sizeof(data));
					fill_blob_param(&bb_raw, fields[0], data, fields[2], fields[3]);
				} else {
					blobmsg_add_blob(&bb_raw, attr);
				}
			} else {
				blobmsg_add_blob(&bb_raw, attr);
			}
		}
	}

	blobmsg_close_array(&bb_raw, array);

	if (strcmp(ctx->ubus_method, "get") == 0 && ctx->raw_format == false) { // Pretty Format
		struct blob_buf bb_pretty = {0};

		memset(&bb_pretty, 0, sizeof(struct blob_buf));
		blob_buf_init(&bb_pretty, 0);

		prepare_pretty_response(ctx->requested_path, bb_raw.head, &bb_pretty);

		ubus_send_reply(ctx->ubus_ctx, &ctx->request_data, bb_pretty.head);
		blob_buf_free(&bb_pretty);
	} else { // Raw Format
		ubus_send_reply(ctx->ubus_ctx, &ctx->request_data, bb_raw.head);
	}

	blob_buf_free(&bb_raw);
}

void send_response(struct async_request_context *ctx)
{
	if (strcmp(ctx->ubus_method, "get") == 0) {
		// Init linker list for only Get method
		INIT_LIST_HEAD(&ctx->linker_list);

		// Init uci context for only Get method
		ctx->uci_ctx = uci_alloc_context();
		if (ctx->uci_ctx) uci_set_confdir(ctx->uci_ctx, "/var/state/");
	}

	prepare_and_send_response(ctx);

	if (strcmp(ctx->ubus_method, "get") == 0) {
		// Free uci context for only Get method
		if (ctx->uci_ctx) uci_free_context(ctx->uci_ctx);

		// Free linker list for only Get method
		free_linker_entries(ctx);
	}

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
