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

#include <regex.h>
#include "libbbfdm-api/version-2/bbfdm_api.h"

#define BBFDM_ROOT_OBJECT "Device."
#define BBFDM_UBUS_OBJECT "bbfdm"
#define BBFDM_MICROSERVICE_INPUT_PATH "/etc/bbfdm/services"
#define MAX_PATH_LENGTH 1024
#define MAX_VALUE_LENGTH 1024 * 4
#define SERVICE_CALL_TIMEOUT 10000 // 10 secs
#define SERVICE_CALL_OPERATE_TIMEOUT 1800000 // 30 mins
#define SERVICE_MAX_CONSECUTIVE_TIMEOUTS 10

enum bbfdmd_type_enum {
	BBFDMD_NONE = 0,
	BBFDMD_CWMP = 1<<0,
	BBFDMD_USP = 1<<1,
	BBFDMD_BOTH = BBFDMD_CWMP | BBFDMD_USP,
};

void init_rand_seed(void);
int rand_in_range(int min, int max);

unsigned int get_proto_type(const char *proto);

void fill_optional_input(struct blob_attr *msg, unsigned int *proto, bool *raw_format);

struct blob_attr *get_results_array(struct blob_attr *msg);

bool str_match(const char *string, const char *pattern, size_t nmatch, regmatch_t pmatch[]);
bool proto_match(unsigned int dm_type, const enum bbfdmd_type_enum type);

void print_fault_message(struct blob_buf *blob_buf, const char *path, uint32_t fault_code, const char *fault_msg);

void run_sync_call(const char *ubus_obj, const char *ubus_method, struct blob_attr *msg, struct blob_buf *bb_response);

#endif /* BBFDMD_COMMON_H */
