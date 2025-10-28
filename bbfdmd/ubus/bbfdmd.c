/*
 * Copyright (C) 2023-2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *    Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 *    Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>

#include <libubus.h>
#include <libubox/blobmsg_json.h>

#include "common.h"
#include "service.h"
#include "get.h"
#include "cli.h"

struct ubus_context g_ubus_ctx = {0};

extern struct list_head registered_services;
extern int g_log_level;

static void schedule_blacklisted_service_recovery(struct ubus_context *ctx);

static void blacklisted_recovery_timer_cb(struct uloop_timeout *timeout __attribute__((unused)))
{
	schedule_blacklisted_service_recovery(&g_ubus_ctx);
}

static struct uloop_timeout blacklisted_recovery_timer = {
	.cb = blacklisted_recovery_timer_cb
};

struct service_request_tracker {
	struct ubus_context *ubus_ctx;
	service_entry_t *service;
	struct ubus_request async_request;
	struct uloop_timeout timeout;
};

static void service_request_timeout(struct uloop_timeout *timeout)
{
	struct service_request_tracker *tracker = container_of(timeout, struct service_request_tracker, timeout);
	if (tracker == NULL) {
		BBFDM_ERR("Timeout occurred but tracker is not defined");
		return;
	}

	BBFDM_WARNING("Timeout occurred for request: '%s get'", tracker->service ? tracker->service->name : "unknown");
	ubus_abort_request(tracker->ubus_ctx, &tracker->async_request);
	BBFDM_FREE(tracker);
}

static void service_request_complete(struct ubus_request *req, int ret)
{
	struct service_request_tracker *tracker = container_of(req, struct service_request_tracker, async_request);
	if (tracker == NULL) {
		BBFDM_ERR("Request completed but tracker is not defined");
		return;
	}

	BBFDM_DEBUG("Request completed for '%s get' with status: '%d'", tracker->service ? tracker->service->name : "", ret);
	uloop_timeout_cancel(&tracker->timeout);

	if (tracker->service && ret == UBUS_STATUS_OK) {
		tracker->service->is_blacklisted = false;
		tracker->service->consecutive_timeouts = 0;
		BBFDM_INFO("Recovered blacklisted service: '%s'", tracker->service->name);
	} else {
		BBFDM_DEBUG("Service '%s' still unreachable", tracker->service ? tracker->service->name : "unknown");
	}

	BBFDM_FREE(tracker);
}

static void verify_service(struct ubus_context *ubus_ctx, service_entry_t *service)
{
	struct blob_buf req_buf = {0};
	uint32_t id = 0;

	if (!ubus_ctx || !service || !service->name) {
		BBFDM_WARNING("Invalid arguments");
		return;
	}

	if (ubus_lookup_id(ubus_ctx, service->name, &id)) {
		BBFDM_INFO("Failed to lookup object: %s", service->name);
		return;
	}

	struct service_request_tracker *tracker = (struct service_request_tracker *)calloc(1, sizeof(struct service_request_tracker));
	if (!tracker) {
		BBFDM_ERR("Failed to allocate memory for request tracker");
		return;
	}

	tracker->ubus_ctx = ubus_ctx;
	tracker->service = service;

	tracker->timeout.cb = service_request_timeout;
	uloop_timeout_set(&tracker->timeout, service->timeout);

	memset(&req_buf, 0, sizeof(struct blob_buf));
	blob_buf_init(&req_buf, 0);

	blobmsg_add_string(&req_buf, "path", BBFDM_ROOT_OBJECT);

	if (ubus_invoke_async(ubus_ctx, id, "get", req_buf.head, &tracker->async_request)) {
		BBFDM_WARNING("Failed to invoke async method for object: '%s get'", service->name);
		uloop_timeout_cancel(&tracker->timeout);
		BBFDM_FREE(tracker);
	} else {
		tracker->async_request.complete_cb = service_request_complete;
		ubus_complete_request_async(ubus_ctx, &tracker->async_request);
	}

	blob_buf_free(&req_buf);
}

static void schedule_blacklisted_service_recovery(struct ubus_context *ubus_ctx)
{
	service_entry_t *service = NULL;

	list_for_each_entry(service, &registered_services, list) {
		if (service->is_blacklisted) {
			verify_service(ubus_ctx, service);
		}
	}

	int next_check_time = rand_in_range(30, 60) * 1000;
	BBFDM_DEBUG("Next blacklisted service recovery scheduled in %d msecs", next_check_time);
	uloop_timeout_set(&blacklisted_recovery_timer, next_check_time);
}

static void stop_blacklisted_service_recovery(void)
{
	uloop_timeout_cancel(&blacklisted_recovery_timer);
}

static void bbfdm_ubus_add_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev __attribute__((unused)),
		const char *type, struct blob_attr *msg)
{
	const struct blobmsg_policy policy = {
		"path", BLOBMSG_TYPE_STRING
	};
	service_entry_t *service = NULL;
	struct blob_attr *attr = NULL;
	bool service_found = false;
	const char *path;

	if (type && strcmp(type, "ubus.object.add") != 0)
		return;

	blobmsg_parse(&policy, 1, &attr, blob_data(msg), blob_len(msg));
	if (!attr)
		return;

	path = blobmsg_data(attr);

	if (path && strncmp(path, BBFDM_UBUS_OBJECT".", strlen(BBFDM_UBUS_OBJECT) + 1) == 0) {

		BBFDM_INFO("Detected new service registration: '%s'", path);

		list_for_each_entry(service, &registered_services, list) {
			// Check if the service is present in the registred services list
			if (strcmp(service->name, path) == 0) {
				service->is_blacklisted = false;
				service->consecutive_timeouts = 0;
				service_found = true;
				fill_service_schema(ctx, 5000, service->name, &service->dm_schema);
				BBFDM_INFO("Service '%s' found in registry. Resetting blacklist and timeout counters.", path);
				break;
			}
		}

		if (!service_found) {
			BBFDM_WARNING("Newly registered service '%s' is not recognized in the registry."
					  " Possible missing configuration JSON file under '%s'.",
					  path, BBFDM_MICROSERVICE_INPUT_PATH);
		}
	}
}

static void bbfdm_handle_schema_request(struct ubus_context *ctx, struct ubus_request_data *req,
		const char *requested_path, unsigned int requested_proto)
{
	struct blob_buf bb = {0};
	bool schema_found = false;
	int len = strlen(requested_path);

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	void *array = blobmsg_open_array(&bb, "results");

	if (len > 0 && requested_path[len - 1] == '.') {
		service_entry_t *service = NULL;

		list_for_each_entry(service, &registered_services, list) {

			if (service->is_blacklisted ||
				!service_path_match(requested_path, requested_proto, service) ||
				!service->dm_schema)
				continue;

			struct blob_attr *attr = NULL;
			size_t remaining = 0;
			const struct blobmsg_policy policy[] = {
					{ "path", BLOBMSG_TYPE_STRING },
			};

			blobmsg_for_each_attr(attr, service->dm_schema->head, remaining) {
				struct blob_attr *fields[1];

				blobmsg_parse(policy, 1, fields, blobmsg_data(attr), blobmsg_len(attr));

				char *path = fields[0] ? blobmsg_get_string(fields[0]) : "";

				if (strlen(path) == 0)
					continue;

				if (strncmp(requested_path, path, len) == 0) {
					blobmsg_add_blob(&bb, attr);
					schema_found = true;
				}
			}
		}
	}

	if (!schema_found)
		print_fault_message(&bb, requested_path, 7026, "Path is not present in the data model schema");

	blobmsg_close_array(&bb, array);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);
}

static const struct blobmsg_policy bbfdm_policy[] = {
	[BBFDM_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[BBFDM_VALUE] = { .name = "value", .type = BLOBMSG_TYPE_STRING },
	[BBFDM_INPUT] = { .name = "optional", .type = BLOBMSG_TYPE_TABLE}
};

static int bbfdm_handler_async(struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__BBFDM_MAX];
	service_entry_t *service = NULL;
	unsigned int requested_proto = BBFDMD_BOTH;
	bool raw_format = false;

	if (blobmsg_parse(bbfdm_policy, __BBFDM_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBFDM_WARNING("Failed to parse input message");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[BBFDM_PATH]) {
		BBFDM_WARNING("%s: path must be defined", method);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	char *requested_path = blobmsg_get_string(tb[BBFDM_PATH]);
	fill_optional_input(tb[BBFDM_INPUT], &requested_proto, &raw_format);

	if (strcmp(method, "schema") == 0 && requested_proto != BBFDMD_CWMP) {
		BBFDM_INFO("START: ubus method|%s|, name|%s|, path|%s|, proto|%u|", method, obj->name, requested_path, requested_proto);
		bbfdm_handle_schema_request(ctx, req, requested_path, requested_proto);
		BBFDM_INFO("END: ubus method|%s|, name|%s|, path|%s|, proto|%u|", method, obj->name, requested_path, requested_proto);
		return 0;
	}

	struct async_request_context *context = (struct async_request_context *)calloc(1, sizeof(struct async_request_context));
	if (!context) {
		BBFDM_WARNING("Failed to allocate memory");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	BBFDM_INFO("START: ubus method|%s|, name|%s|, path|%s|, proto|%u|", method, obj->name, requested_path, requested_proto);

	snprintf(context->requested_path, sizeof(context->requested_path), "%s", requested_path);
	snprintf(context->ubus_method, sizeof(context->ubus_method), "%s", method);

	context->ubus_ctx = ctx;
	context->raw_format = raw_format;

	memset(&context->tmp_bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&context->tmp_bb, 0);

	ubus_defer_request(ctx, req, &context->request_data);

	list_for_each_entry(service, &registered_services, list) {

		if (service->is_blacklisted)
			continue;

		if (!service_path_match(context->requested_path, requested_proto, service))
			continue;

		run_async_call(context, service, msg);
	}

	context->service_list_processed = true;

	if (context->path_matched == false)
		send_response(context);

	return 0;
}

static int bbfdm_handler_sync(struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__BBFDM_MAX];
	service_entry_t *service = NULL;
	char requested_path[MAX_PATH_LENGTH];
	unsigned int requested_proto = BBFDMD_BOTH;
	bool raw_format = false;
	struct blob_buf bb = {0};

	if (blobmsg_parse(bbfdm_policy, __BBFDM_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBFDM_WARNING("Failed to parse input message");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[BBFDM_PATH]) {
		BBFDM_WARNING("%s: path must be defined", method);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	BBFDM_INFO("ubus method|%s|, name|%s|", method, obj->name);

	snprintf(requested_path, sizeof(requested_path), "%s", blobmsg_get_string(tb[BBFDM_PATH]));

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	fill_optional_input(tb[BBFDM_INPUT], &requested_proto, &raw_format);

	list_for_each_entry(service, &registered_services, list) {

		if (service->is_blacklisted)
			continue;

		if (!service_path_match(requested_path, requested_proto, service))
			continue;

		run_sync_call(service->name, method, msg, &bb);
	}

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static int bbfdm_services_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method, struct blob_attr *msg __attribute__((unused)))
{
	struct blob_buf bb;

	BBFDM_INFO("ubus method|%s|, name|%s|", method, obj->name);

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	list_registered_services(&bb);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static struct ubus_method bbfdm_methods[] = {
	UBUS_METHOD("get", bbfdm_handler_async, bbfdm_policy),
	UBUS_METHOD("schema", bbfdm_handler_async, bbfdm_policy),
	UBUS_METHOD("instances", bbfdm_handler_async, bbfdm_policy),
	UBUS_METHOD("operate", bbfdm_handler_async, bbfdm_policy),
	UBUS_METHOD("set", bbfdm_handler_sync, bbfdm_policy),
	UBUS_METHOD("add", bbfdm_handler_sync, bbfdm_policy),
	UBUS_METHOD("del", bbfdm_handler_sync, bbfdm_policy),
	UBUS_METHOD_NOARG("services", bbfdm_services_handler)
};

static struct ubus_object_type bbfdm_object_type = UBUS_OBJECT_TYPE(BBFDM_UBUS_OBJECT, bbfdm_methods);

static struct ubus_object bbfdm_object = {
	.name = BBFDM_UBUS_OBJECT,
	.type = &bbfdm_object_type,
	.methods = bbfdm_methods,
	.n_methods = ARRAY_SIZE(bbfdm_methods)
};

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -c <command input>  Run cli command\n");
	fprintf(stderr, "    -l <loglevel>       log verbosity value as per standard syslog\n");
	fprintf(stderr, "    -h                  Displays this help\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct ubus_event_handler add_event = {
		.cb = bbfdm_ubus_add_event_cb,
	};

	char *cli_argv[4] = {0};
	int err = 0, ch, cli_argc = 0, i;

	while ((ch = getopt(argc, argv, "hc:l:")) != -1) {
		switch (ch) {
		case 'c':
			cli_argc = argc-optind+1;
			for (i = 0; i < cli_argc; i++) {
				cli_argv[i] = argv[optind - 1 + i];
			}
			break;
		case 'l':
			if (optarg) {
				g_log_level = (int)strtod(optarg, NULL);
				if (g_log_level < 0 || g_log_level > 7)
					g_log_level = 7;
			}
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	if (cli_argc) {
		return bbfdmd_cli_exec_command(cli_argc, cli_argv);
	}

	openlog(BBFDM_UBUS_OBJECT, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	setlogmask(LOG_UPTO(g_log_level));

	init_rand_seed(); // Seed the random number generator

	err = ubus_connect_ctx(&g_ubus_ctx, NULL);
	if (err != UBUS_STATUS_OK) {
		BBFDM_ERR("Failed to connect to ubus");
		return -1;
	}

	uloop_init();
	ubus_add_uloop(&g_ubus_ctx);

	err = register_services(&g_ubus_ctx);
	if (err) {
		BBFDM_ERR("Failed to load micro-services");
		goto end;
	}

	err = ubus_add_object(&g_ubus_ctx, &bbfdm_object);
	if (err != UBUS_STATUS_OK) {
		BBFDM_ERR("Failed to add ubus object: %s", ubus_strerror(err));
		goto end;
	}

	if (ubus_register_event_handler(&g_ubus_ctx, &add_event, "ubus.object.add"))
		goto end;

	schedule_blacklisted_service_recovery(&g_ubus_ctx);

	BBFDM_INFO("Waiting on uloop....");
	uloop_run();

end:
	BBFDM_DEBUG("BBFDMD exits");
	stop_blacklisted_service_recovery();
	ubus_unregister_event_handler(&g_ubus_ctx, &add_event);
	unregister_services();
	uloop_done();
	ubus_shutdown(&g_ubus_ctx);

	closelog();

	return err;
}
