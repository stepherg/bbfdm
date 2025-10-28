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

struct async_request_context {
	struct ubus_context *ubus_ctx;
	struct ubus_request_data request_data;
	struct blob_buf tmp_bb;
	void *array;
	bool service_list_processed;
	bool path_matched;
	bool raw_format;
	int pending_requests;
	char requested_path[MAX_PATH_LENGTH];
	char ubus_method[32];
};

struct ubus_request_tracker {
	struct async_request_context *ctx;
	service_entry_t *service;
	struct ubus_request async_request;
	struct uloop_timeout timeout;
	char request_name[128];
};

void run_async_call(struct async_request_context *ctx, service_entry_t *service, struct blob_attr *msg);
void send_response(struct async_request_context *ctx);

#endif /* BBFDMD_GET_H */
