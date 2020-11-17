/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "dmbbfcommon.h"

int end_session_flag = 0;
unsigned int upnp_in_user_mask = DM_SUPERADMIN_MASK;

LIST_HEAD(list_execute_end_session);

int dm_add_end_session(struct dmctx *ctx, void(*function)(struct execute_end_session *), int action, void *data)
{
	struct execute_end_session *execute_end_session;

	execute_end_session = calloc (1,sizeof(struct execute_end_session));
	if (execute_end_session == NULL)
	{
		return -1;
	}
	execute_end_session->action = action;
	execute_end_session->data = data;
	execute_end_session->function = function;
	execute_end_session->amd_version = ctx->amd_version;
	execute_end_session->instance_mode = ctx->instance_mode;
	execute_end_session->dm_type = ctx->dm_type;
	list_add_tail (&(execute_end_session->list), &(list_execute_end_session));

	return 0;
}

void apply_end_session()
{
	struct execute_end_session *p, *q;
	list_for_each_entry_safe(p, q, &(list_execute_end_session), list) {
		p->function(p);
		list_del(&(p->list));
		FREE(p);
	}
}

void bbf_set_end_session_flag(struct dmctx *ctx, unsigned int flag)
{
	ctx->end_session_flag |= flag;
}

int set_bbfdatamodel_type(int bbf_type)
{
	bbfdatamodel_type = bbf_type;
	return 0;
}

int get_bbfdatamodel_type(void)
{
	return bbfdatamodel_type;
}

int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value)
{
	return dmuci_lookup_ptr(ctx, ptr, package, section, option, value);
}

void bbf_apply_end_session(void)
{
	apply_end_session();
}

int bbf_set_ip_version(int ipversion)
{
	ip_version = ipversion;
	return 0;
}

void del_list_parameter(struct dm_parameter *dm_parameter)
{
	api_del_list_parameter(dm_parameter);
}

int dm_update_file_enabled_notify(char *param, char *new_value)
{
	return bbf_api_dm_update_file_enabled_notify(param, new_value);
}

void dmjson_parse_init(char *msg)
{
	bbf_api_dmjson_parse_init(msg);
}

void dmjson_parse_fini(void)
{
	bbf_api_dmjson_parse_fini();
}

json_object *dmjson_select_obj(json_object * jobj, char *argv[])
{
	return (bbf_api_dmjson_select_obj(jobj, argv));
}

void del_list_fault_param(struct param_fault *param_fault)
{
	bbf_api_del_list_fault_param(param_fault);
}

int copy_temporary_file_to_original_file(char *f1, char *f2)
{
	return bbf_api_copy_temporary_file_to_original_file(f1, f2);
}

void dmjson_get_var(char *jkey, char **jval)
{
	bbf_api_dmjson_get_var(jkey, jval);
}

void dm_update_enabled_notify(struct dm_enabled_notify *p, char *new_value)
{
	free(p->value); // Should be free and not dmfree
	p->value = strdup(new_value);
}

void dmjson_get_string(char *jkey, char **jval)
{
	bbf_api_dmjson_get_string(jkey, jval);
}

void dmbbf_update_enabled_notify_file(unsigned int dm_type, unsigned int amd_version, int instance_mode)
{
	struct dmctx dmctx = {0};

	dm_ctx_init(&dmctx, dm_type, amd_version, instance_mode);
	dmctx.in_param = "";
	dm_entry_enabled_notify(&dmctx);

	dm_ctx_clean(&dmctx);
}

int get_dm_type(char *dm_str)
{
	if (dm_str == NULL)
		return DMT_STRING;

	if (strcmp(dm_str, DMT_TYPE[DMT_STRING]) == 0)
		return DMT_STRING;
	else if (strcmp(dm_str, DMT_TYPE[DMT_UNINT]) == 0)
		return DMT_UNINT;
	else if (strcmp(dm_str, DMT_TYPE[DMT_INT]) == 0)
		return DMT_INT;
	else if (strcmp(dm_str, DMT_TYPE[DMT_UNLONG]) == 0)
		return DMT_UNLONG;
	else if (strcmp(dm_str, DMT_TYPE[DMT_LONG]) == 0)
		return DMT_LONG;
	else if (strcmp(dm_str, DMT_TYPE[DMT_BOOL]) == 0)
		return DMT_BOOL;
	else if (strcmp(dm_str, DMT_TYPE[DMT_TIME]) == 0)
		return DMT_TIME;
	else if (strcmp(dm_str, DMT_TYPE[DMT_HEXBIN]) == 0)
		return DMT_HEXBIN;
	else if (strcmp(dm_str, DMT_TYPE[DMT_BASE64]) == 0)
		return DMT_BASE64;
	else
		return DMT_STRING;

	return DMT_STRING;
}
