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

#ifndef BBFDMD_COMMON_H
#define BBFDMD_COMMON_H

#include "libbbfdm-api/version-2/bbfdm_api.h"

#define BBFDM_ROOT_OBJECT "Device."
#define BBFDM_UBUS_OBJECT "bbfdm"
#define BBFDM_ADD_EVENT "AddObj"
#define BBFDM_DEL_EVENT "DelObj"
#define BBFDM_EVENT_NAME "event"
#define BBFDM_MICROSERVICE_INPUT_PATH "/etc/bbfdm/services"
#define MAX_PATH_LENGTH 1024
#define SERVICE_CALL_TIMEOUT 5000

enum bbfdmd_type_enum {
	BBFDMD_NONE = 0,
	BBFDMD_CWMP = 1<<0,
	BBFDMD_USP = 1<<1,
	BBFDMD_BOTH = BBFDMD_CWMP | BBFDMD_USP,
};

unsigned int get_proto_type(const char *proto);
unsigned int get_proto_type_option_value(struct blob_attr *msg);
bool proto_matches(unsigned int dm_type, const enum bbfdmd_type_enum type);

char *get_reference_data(const char *path, const char *method_name);

void run_sync_call(const char *ubus_obj, const char *ubus_method, struct blob_attr *msg, struct blob_buf *bb_response);

#endif /* BBFDMD_COMMON_H */
