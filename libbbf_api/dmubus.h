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
#include <time.h>
#include "dmapi.h"

int dmubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res);
int dmubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size);
int dmubus_call_blob(char *obj, char *method, void *value, json_object **resp);
int dmubus_call_blob_set(char *obj, char *method, void *value);
bool dmubus_object_method_exists(const char *obj);
void dmubus_free();
void dmubus_configure(struct ubus_context *ctx);
void dmubus_update_cached_entries();
void dmubus_clean_endlife_entries();
void dmubus_set_caching_time(int seconds);
void dmubus_register_event_blocking(char *event, int timeout, struct blob_attr *type);
int dmubus_call_blocking(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res);
bool dmubus_object_exist(char *object);

#endif
