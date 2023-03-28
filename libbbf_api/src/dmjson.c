/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Authro: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include "dmjson.h"

static json_object *dmjson_select_obj(json_object *jobj, char *argv[])
{
	int i;
	for (i = 0; argv[i]; i++) {
		if (jobj == NULL)
			return NULL;
		json_object_object_get_ex(jobj, argv[i], &jobj);
	}
	return jobj;
}

static char *dmjson_print_value(json_object *jobj)
{
	enum json_type type;
	char *ret = "";

	if (!jobj)
		return ret;

	type = json_object_get_type(jobj);
	switch (type) {
	case json_type_boolean:
	case json_type_double:
	case json_type_int:
	case json_type_string:
		ret = (char *)json_object_get_string(jobj);
		break;
	default:
		break;
	}
	return ret;
}

static char *____dmjson_get_value_in_obj(json_object *mainjobj, char *argv[])
{
	json_object *jobj = dmjson_select_obj(mainjobj, argv);
	return dmjson_print_value(jobj);
}

char *__dmjson_get_value_in_obj(json_object *mainjobj, int argc, ...)
{
	va_list arg;
	char *argv[64];
	int i;

	if (!mainjobj)
		return "";

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, char *);
	}
	argv[argc] = NULL;
	va_end(arg);
	return ____dmjson_get_value_in_obj(mainjobj, argv);
}

json_object *__dmjson_get_obj(json_object *mainjobj, int argc, ...)
{
	va_list arg;
	char *argv[64];
	int i;

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, char *);
	}
	argv[argc] = NULL;
	va_end(arg);
	return dmjson_select_obj(mainjobj, argv);
}

static json_object *____dmjson_select_obj_in_array_idx(json_object *mainjobj, json_object **arrobj, int index, char *argv[])
{
	json_object *jobj = NULL;

	if (arrobj == NULL || *arrobj == NULL) {
		jobj = dmjson_select_obj(mainjobj, argv);
		if (arrobj)
			*arrobj = jobj;
		if (jobj && json_object_get_type(jobj) == json_type_array) {
			jobj = json_object_array_get_idx(jobj, index);
			return jobj;
		} else {
			return NULL;
		}
	} else {
		jobj = json_object_array_get_idx(*arrobj, index);
		return jobj;
	}

	return NULL;
}

json_object *__dmjson_select_obj_in_array_idx(json_object *mainjobj, json_object **arrobj, int index, int argc, ...)
{
	va_list arg;
	json_object *jobj;
	char *argv[64];
	int i;

	if (mainjobj == NULL)
		return NULL;

	if (index < 0)
		return NULL;

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, char *);
	}
	argv[argc] = NULL;
	va_end(arg);
	jobj = ____dmjson_select_obj_in_array_idx(mainjobj, arrobj, index, argv);
	return jobj;
}

static char *____dmjson_get_value_in_array_idx(json_object *mainjobj, json_object **arrobj, int index, char *argv[])
{
	json_object *jobj = NULL;
	char *value = NULL;

	if (arrobj == NULL || *arrobj == NULL) {
		jobj = dmjson_select_obj(mainjobj, argv);
		if (arrobj)
			*arrobj = jobj;
		if (jobj && json_object_get_type(jobj) == json_type_array) {
			jobj = json_object_array_get_idx(jobj, index);
			if (jobj == NULL)
				return NULL;
			value = dmjson_print_value(jobj);
			return value;
		}
	} else {
		jobj = json_object_array_get_idx(*arrobj, index);
		if (jobj == NULL)
			return NULL;
		value = dmjson_print_value(jobj);
		return value;
	}
	return value;
}

char *__dmjson_get_value_in_array_idx(json_object *mainjobj, json_object **arrobj, char *defret, int index, int argc, ...)
{
	va_list arg;
	char *argv[64], *v;
	int i;

	if (mainjobj == NULL)
		return defret;

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, char *);
	}
	argv[argc] = NULL;
	va_end(arg);
	v = ____dmjson_get_value_in_array_idx(mainjobj, arrobj, index, argv);
	return (v ? v : defret) ;
}

static char *____dmjson_get_value_array_all(json_object *mainjobj, char *delim, char *argv[])
{
	json_object *arrobj;
	char *v, *ret = "";
	int i, dlen, rlen;

	delim = (delim) ? delim : ",";
	dlen = (delim) ? DM_STRLEN(delim) : 1;

	for (i = 0, arrobj = NULL, v = ____dmjson_get_value_in_array_idx(mainjobj, &arrobj, i, argv);
		v;
		v = ____dmjson_get_value_in_array_idx(mainjobj, &arrobj, ++i, argv)) {

		if (*ret == '\0') {
			ret = dmstrdup(v);
		} else if (*v) {
			rlen = strlen(ret);
			ret = dmrealloc(ret, rlen + dlen + strlen(v) + 1);
			snprintf(&ret[rlen], dlen + strlen(v) + 1, "%s%s", delim, v);
		}
	}
	return ret;
}

char *__dmjson_get_value_array_all(json_object *mainjobj, char *delim, int argc, ...)
{
	char *argv[64], *ret;
	va_list arg;
	int i;

	va_start(arg, argc);
	for (i = 0; i < argc; i++) {
		argv[i] = va_arg(arg, char *);
	}
	argv[argc] = NULL;
	va_end(arg);
	ret = ____dmjson_get_value_array_all(mainjobj, delim, argv);
	return ret;
}
