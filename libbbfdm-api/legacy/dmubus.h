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

#ifndef __DMUBUS_H
#define __DMUBUS_H

#include <json-c/json.h>
#include <libubus.h>
#include "dmapi.h"

struct dmubus_event_data {
	struct uloop_timeout tm;
	struct ubus_event_handler ev;
	void *ev_data;
};

struct dmubus_ev_subtask {
	struct uloop_timeout sub_tm;
	void *subtask_data;
	uint32_t timeout;
};

// bbfdm task related functions
typedef void (*bbfdm_task_callback_t)(const void *arg1, void *arg2);

typedef struct bbfdm_task_data {
	struct uloop_process process; // Used for forked task
	struct uloop_timeout timeout;
	bbfdm_task_callback_t taskcb;
	bbfdm_task_callback_t finishcb; // Used for forked task
	const void *arg1;
	void *arg2;
} bbfdm_task_data_t;

int bbfdm_task_schedule(bbfdm_task_callback_t callback, const void *arg1, void *arg2, int timeout);

int bbfdm_task_fork(bbfdm_task_callback_t taskcb, bbfdm_task_callback_t finishcb, const void *arg1, void *arg2);

typedef void (*CB_FUNC_PTR)(struct ubus_context *ctx, struct ubus_event_handler *ev,
			const char *type, struct blob_attr *msg);

void dmubus_wait_for_event(const char *event, int timeout, void *ev_data, CB_FUNC_PTR ev_callback,
			struct dmubus_ev_subtask *subtask);

int dmubus_call(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res);
int dmubus_call_blocking(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res);
int dmubus_call_set(const char *obj, const char *method, struct ubus_arg u_args[], int u_args_size);

int dmubus_call_blob(const char *obj, const char *method, json_object *value, json_object **resp);
int dmubus_call_blob_blocking(const char *obj, const char *method, json_object *value, json_object **resp);
int dmubus_call_blob_set(const char *obj, const char *method, json_object *value);

int dmubus_call_blob_msg_set(const char *obj, const char *method, struct blob_buf *blob_msg);

void dm_ubus_init(struct dmctx *bbf_ctx);
void dm_ubus_free(struct dmctx *bbf_ctx);

bool dmubus_object_method_exists(const char *obj);

#endif
