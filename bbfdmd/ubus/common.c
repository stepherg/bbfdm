/*
 * common.c: Common utils of Get/Set/Operate handlers
 *
 * Copyright (C) 2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include "common.h"
#include "get_helper.h"

#define DEFAULT_LOG_LEVEL (2)

static unsigned char gLogLevel = DEFAULT_LOG_LEVEL;

// Logging utilities
void set_debug_level(unsigned char level)
{
	gLogLevel = level;
}

void print_error(const char *format, ...)
{
	va_list arglist;

	if (gLogLevel < 1)
		return;

	va_start(arglist, format);
	vsyslog(LOG_ERR, format, arglist);
	va_end(arglist);
}

void print_warning(const char *format, ...)
{
	va_list arglist;

	if (gLogLevel < 2)
		return;

	va_start(arglist, format);
	vsyslog(LOG_WARNING, format, arglist);
	va_end(arglist);
}

void print_info(const char *format, ...)
{
	va_list arglist;

	if (gLogLevel < 3)
		return;

	va_start(arglist, format);
	vsyslog(LOG_INFO, format, arglist);
	va_end(arglist);
}

void print_debug(const char *format, ...)
{
	va_list arglist;

	if (gLogLevel < 4)
		return;

	va_start(arglist, format);
	vsyslog(LOG_DEBUG, format, arglist);
	va_end(arglist);
}


bool is_str_eq(const char *s1, const char *s2)
{
	if (strcmp(s1, s2) == 0)
		return true;

	return false;
}

bool get_boolean_string(char *value)
{
	if (!value)
		return false;

	if (strncasecmp(value, "true", 4) == 0 ||
	    value[0] == '1' ||
	    strncasecmp(value, "on", 2) == 0 ||
	    strncasecmp(value, "yes", 3) == 0 ||
	    strncasecmp(value, "enabled", 7) == 0)
		return true;

	return false;
}

bool is_node_instance(char *path)
{
	bool ret = false;
	char *rb = NULL;

	DEBUG("entry |%s|", path);
	if (!path)
		return false;

	if (path[0] == '[') {
		char temp_char[MAX_DM_KEY_LEN] = {'\0'};
		size_t shift;

		rb = strchr(path, ']');
		shift = (size_t) labs(rb - path);
		strncpyt(temp_char, path, shift + 1);
		if (!match(temp_char, GLOB_EXPR))
			ret = true;
	} else {
		if (strtol(path, NULL, 10))
			ret = true;
	}
	return ret;
}

// RE utilities
bool match(const char *string, const char *pattern)
{
	int status;
	regex_t re;

	if (regcomp(&re, pattern, REG_EXTENDED) != 0)
		return 0;

	status = regexec(&re, string, 0, NULL, 0);
	regfree(&re);
	if (status != 0)
		return false;

	return true;
}

int count_delim(const char *path)
{
	int count = 0;
	char *token, *save;
	char *pp = strdup(path);

	token = strtok_r(pp, ".", &save);
	while (token) {
		token = strtok_r(NULL, ".", &save);
		count++;
	}
	free(pp);

	// count is the count of tokens
	return (count - 1);
}

bool validate_msglen(bbfdm_data_t *data)
{
	size_t data_len = blob_pad_len(data->bb.head);

	if (data_len >= DEF_IPC_DATA_LEN) {
		ERR("Blob exceed max len(%zd), data len(%zd)", DEF_IPC_DATA_LEN, data_len);
		blob_buf_free(&data->bb);
		blob_buf_init(&data->bb, 0);
		fill_err_code_table(data, FAULT_9002);
		return false;
	}

	return true;
}

int get_dm_type(char *dm_type)
{
	if (dm_type == NULL)
		return DMT_STRING;

	if (DM_STRCMP(dm_type, DMT_TYPE[DMT_STRING]) == 0)
		return DMT_STRING;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_UNINT]) == 0)
		return DMT_UNINT;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_INT]) == 0)
		return DMT_INT;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_UNLONG]) == 0)
		return DMT_UNLONG;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_LONG]) == 0)
		return DMT_LONG;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_BOOL]) == 0)
		return DMT_BOOL;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_TIME]) == 0)
		return DMT_TIME;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_HEXBIN]) == 0)
		return DMT_HEXBIN;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_BASE64]) == 0)
		return DMT_BASE64;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_COMMAND]) == 0)
		return DMT_COMMAND;
	else if (DM_STRCMP(dm_type, DMT_TYPE[DMT_EVENT]) == 0)
		return DMT_EVENT;
	else
		return DMT_STRING;

	return DMT_STRING;
}

int get_proto_type(const char *proto)
{
	int type = BBFDM_BOTH;

	if (proto) {
		if (is_str_eq("cwmp", proto))
			type = BBFDM_CWMP;
		else if (is_str_eq("usp", proto))
			type = BBFDM_USP;
		else
			type = BBFDM_BOTH;
	}

	return type;
}

int get_instance_mode(int instance_mode)
{
	if (instance_mode > INSTANCE_MODE_ALIAS)
		instance_mode = INSTANCE_MODE_NUMBER;

	return instance_mode;
}
