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

#include <string.h>
#include <libubox/blobmsg_json.h>

#include "common.h"

int g_log_level = LOG_ERR;

void init_rand_seed(void)
{
	srandom((unsigned int)time(NULL));
}

int rand_in_range(int min, int max)
{
	int range;

	if (min >= max)
		return -1;

	if (min == (max - 1))
		return min;

	range = max - min;

	return min + ((int)(((double)range) * ((double)random()) /
			(((double)RAND_MAX) + 1.0)));
}

unsigned int get_proto_type(const char *proto)
{
	int type = BBFDMD_BOTH;

	if (proto) {
		if (strcmp(proto, "cwmp") == 0)
			type = BBFDMD_CWMP;
		else if (strcmp(proto, "usp") == 0)
			type = BBFDMD_USP;
		else
			type = BBFDMD_BOTH;
	}

	return type;
}

static bool is_raw_format_type(const char *format)
{
	bool raw_format = false;

	if (format) {
		if (strcmp(format, "raw") == 0)
			raw_format = true;
		else
			raw_format = false;
	}

	return raw_format;
}

void fill_optional_input(struct blob_attr *msg, unsigned int *proto, bool *raw_format)
{
	struct blob_attr *tb[2] = {0};
	const struct blobmsg_policy p[2] = {
			{ "proto", BLOBMSG_TYPE_STRING },
			{ "format", BLOBMSG_TYPE_STRING }
	};

	*proto = BBFDMD_BOTH;
	*raw_format = false;

	if (!msg)
		return;

	blobmsg_parse(p, 2, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[0]) {
		const char *val = blobmsg_get_string(tb[0]);
		*proto = get_proto_type(val);
	}

	if (tb[1]) {
		const char *val = blobmsg_get_string(tb[1]);
		*raw_format = is_raw_format_type(val);
	}
}

struct blob_attr *get_results_array(struct blob_attr *msg)
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

bool str_match(const char *string, const char *pattern, size_t nmatch, regmatch_t pmatch[])
{
	regex_t re;

	if (!string || !pattern)
		return false;

	if (regcomp(&re, pattern, REG_EXTENDED) != 0)
		return false;

	int status = regexec(&re, string, nmatch, pmatch, 0);

	regfree(&re);

	return (status != 0) ? false : true;
}

bool proto_match(unsigned int dm_type, const enum bbfdmd_type_enum type)
{
	return (dm_type == BBFDMD_BOTH || type == BBFDMD_BOTH || dm_type == type) && type != BBFDMD_NONE;
}

void print_fault_message(struct blob_buf *blob_buf, const char *path, uint32_t fault_code, const char *fault_msg)
{
	if (!blob_buf || !path || !fault_msg)
		return;

	void *table = blobmsg_open_table(blob_buf, NULL);
	blobmsg_add_string(blob_buf, "path", path);
	blobmsg_add_u32(blob_buf, "fault", fault_code);
	blobmsg_add_string(blob_buf, "fault_msg", fault_msg);
	blobmsg_close_table(blob_buf, table);
}

static void sync_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *attr = NULL;
	int remaining = 0;

	if (!req || !msg)
		return;

	struct blob_buf *bb_response = (struct blob_buf *)req->priv;

	if (!bb_response)
		return;

	blob_for_each_attr(attr, msg, remaining) {
		blobmsg_add_field(bb_response, blobmsg_type(attr), blobmsg_name(attr), blobmsg_data(attr), blobmsg_len(attr));
	}
}

void run_sync_call(const char *ubus_obj, const char *ubus_method, struct blob_attr *msg, struct blob_buf *bb_response)
{
	struct blob_buf req_buf = {0};
	struct blob_attr *attr = NULL;
	int remaining = 0;

	if (!ubus_obj || !ubus_method || !msg || !bb_response)
		return;

	memset(&req_buf, 0, sizeof(struct blob_buf));
	blob_buf_init(&req_buf, 0);

	blob_for_each_attr(attr, msg, remaining) {
		blobmsg_add_field(&req_buf, blobmsg_type(attr), blobmsg_name(attr), blobmsg_data(attr), blobmsg_len(attr));
	}

	if (g_log_level == LOG_DEBUG) {
		char *json_str = blobmsg_format_json_indent(req_buf.head, true, -1);
		BBFDM_DEBUG("### ubus call %s %s '%s' ###", ubus_obj, ubus_method, json_str);
		BBFDM_FREE(json_str);		
	}

	BBFDM_UBUS_INVOKE_SYNC(ubus_obj, ubus_method, req_buf.head, 5000, sync_callback, bb_response);

	blob_buf_free(&req_buf);
}
