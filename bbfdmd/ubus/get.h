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

#ifndef BBFDMD_GET_H
#define BBFDMD_GET_H

enum {
	BBFDM_PATH,
	BBFDM_VALUE,
	BBFDM_INPUT,
	__BBFDM_MAX
};

struct linker_args {
	struct list_head list;
	char *path;
	char *value;
};

struct async_request_context {
	struct ubus_context *ubus_ctx;
	struct ubus_request_data request_data;
	struct ubus_event_handler linker_handler;
	struct list_head linker_list;
	struct blob_buf tmp_bb;
	char requested_path[MAX_PATH_LENGTH];
	char ubus_method[32];
	bool service_list_processed;
	bool path_matched;
	int pending_requests;
};

struct ubus_request_tracker {
	struct async_request_context *ctx;
	struct ubus_request async_request;
	struct uloop_timeout timeout;
	char request_name[128];
};

void send_linker_cleanup_event(struct ubus_context *ctx);
void linker_response_callback(struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg);

void run_async_call(struct async_request_context *ctx, const char *ubus_obj, struct blob_attr *msg);
void send_response(struct async_request_context *ctx);

#endif /* BBFDMD_GET_H */
