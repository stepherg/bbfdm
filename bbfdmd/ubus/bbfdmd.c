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

#include <libubus.h>
#include <libubox/blobmsg_json.h>

#include "common.h"
#include "service.h"
#include "get.h"
#include "cli.h"

extern struct list_head registered_services;

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

	if (blobmsg_parse(bbfdm_policy, __BBFDM_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBFDM_ERR("Failed to parse input message");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[BBFDM_PATH]) {
		BBFDM_ERR("%s: path must be defined", method);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	struct async_request_context *context = calloc(1, sizeof(struct async_request_context));
	if (!context) {
		BBFDM_ERR("Failed to allocate memory");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	BBFDM_INFO("ubus method|%s|, name|%s|", method, obj->name);

	snprintf(context->requested_path, sizeof(context->requested_path), "%s", blobmsg_get_string(tb[BBFDM_PATH]));
	snprintf(context->ubus_method, sizeof(context->ubus_method), "%s", method);

	context->ubus_ctx = ctx;

	memset(&context->tmp_bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&context->tmp_bb, 0);

	if (strcmp(method, "get") == 0) {
		INIT_LIST_HEAD(&context->linker_list);

		// Send linker cleanup event for all services
		send_linker_cleanup_event(ctx);

		// Event handler to wait for linker response
		context->linker_handler.cb = linker_response_callback;
		ubus_register_event_handler(ctx, &context->linker_handler, "bbfdm.linker.response");
	}

	unsigned int requested_proto = get_proto_type_option_value(tb[BBFDM_INPUT]);

	ubus_defer_request(ctx, req, &context->request_data);

	list_for_each_entry(service, &registered_services, list) {

		if (!is_path_match(context->requested_path, requested_proto, service))
			continue;

		run_async_call(context, service->name, msg);
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
	struct blob_buf bb = {0};

	if (blobmsg_parse(bbfdm_policy, __BBFDM_MAX, tb, blob_data(msg), blob_len(msg))) {
		BBFDM_ERR("Failed to parse input message");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (!tb[BBFDM_PATH]) {
		BBFDM_ERR("%s: path must be defined", method);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	BBFDM_INFO("ubus method|%s|, name|%s|", method, obj->name);

	snprintf(requested_path, sizeof(requested_path), "%s", blobmsg_get_string(tb[BBFDM_PATH]));

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	unsigned int requested_proto = get_proto_type_option_value(tb[BBFDM_INPUT]);

	list_for_each_entry(service, &registered_services, list) {

		if (!is_path_match(requested_path, requested_proto, service))
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
	struct ubus_context ubus_ctx = {0};
	char *cli_argv[4] = {0};
	int log_level = LOG_ERR;
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
				log_level = (int)strtod(optarg, NULL);
				if (log_level < 0 || log_level > 7)
					log_level = 3;
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

	setlogmask(LOG_UPTO(log_level));

	err = ubus_connect_ctx(&ubus_ctx, NULL);
	if (err != UBUS_STATUS_OK) {
		BBFDM_ERR("Failed to connect to ubus");
		return -1;
	}

	uloop_init();
	ubus_add_uloop(&ubus_ctx);

	err = register_services(&ubus_ctx);
	if (err) {
		BBFDM_ERR("Failed to load micro-services");
		goto end;
	}

	err = ubus_add_object(&ubus_ctx, &bbfdm_object);
	if (err != UBUS_STATUS_OK) {
		BBFDM_ERR("Failed to add ubus object: %s", ubus_strerror(err));
		goto end;
	}

	BBFDM_INFO("Waiting on uloop....");
	uloop_run();

end:
	BBFDM_ERR("Free context");
	unregister_services();
	uloop_done();
	ubus_shutdown(&ubus_ctx);

	closelog();

	return err;
}
