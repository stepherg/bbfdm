/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *	  Author Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "dmapi.h"
#include "dmplugin.h"
#include "dmcommon.h"
#include "dmentry.h"

LIST_HEAD(head_package_change);
LIST_HEAD(global_memhead);

static struct dm_fault DM_FAULT_ARRAY[] = {
	{ FAULT_9000, "Method not supported" },
	{ FAULT_9001, "Request denied (no reason specified)" },
	{ FAULT_9002, "Internal error" },
	{ FAULT_9003, "Invalid arguments" },
	{ FAULT_9004, "Resources exceeded" },
	{ FAULT_9005, "Invalid parameter name" },
	{ FAULT_9006, "Invalid parameter type" },
	{ FAULT_9007, "Invalid parameter value" },
	{ FAULT_9008, "Attempt to set a non-writable parameter" },
	{ USP_FAULT_GENERAL_FAILURE, "general failure"},
	{ USP_FAULT_MESSAGE_NOT_UNDERSTOOD, "message was not understood"},
	{ USP_FAULT_REQUEST_DENIED, "Cannot or will not process message"},
	{ USP_FAULT_INTERNAL_ERROR, "Message failed due to an internal error"},
	{ USP_FAULT_INVALID_ARGUMENT, "invalid values in the request elements"},
	{ USP_FAULT_RESOURCES_EXCEEDED, "Message failed due to memory or processing limitations"},
	{ USP_FAULT_INVALID_TYPE, "Unable to convert string value to correct data type"},
	{ USP_FAULT_INVALID_VALUE, "Out of range or invalid enumeration"},
	{ USP_FAULT_PARAM_READ_ONLY, "Attempted to write to a read only parameter"},
	{ USP_FAULT_INVALID_PATH, "Path is not present in the data model schema"},
};

void bbf_ctx_init(struct dmctx *ctx, DMOBJ *tEntryObj)
{
	INIT_LIST_HEAD(&ctx->list_parameter);
	ctx->dm_entryobj = tEntryObj;
	bbfdm_init_mem(ctx);
	dm_uci_init();
}

void bbf_ctx_clean(struct dmctx *ctx)
{
	free_all_list_parameter(ctx);

	dm_uci_exit();
	dmubus_free();
	bbfdm_clean_mem(ctx);
}

void bbf_ctx_init_sub(struct dmctx *ctx, DMOBJ *tEntryObj)
{
	INIT_LIST_HEAD(&ctx->list_parameter);
	ctx->dm_entryobj = tEntryObj;
}

void bbf_ctx_clean_sub(struct dmctx *ctx)
{
	free_all_list_parameter(ctx);
}

static char *get_fault_message(int fault_code)
{
	for (int i = 0; i < ARRAY_SIZE(DM_FAULT_ARRAY); i++)
		if (DM_FAULT_ARRAY[i].code == fault_code)
			return DM_FAULT_ARRAY[i].description;

	return "BBFDM: Internal error";
}

int bbf_fault_map(struct dmctx *ctx, int fault)
{
	int out_fault;

	if (!fault)
		return 0;

	if (ctx->dm_type == BBFDM_USP) {
		switch(fault) {
		case FAULT_9000:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_MESSAGE_NOT_UNDERSTOOD));
			out_fault = USP_FAULT_MESSAGE_NOT_UNDERSTOOD;
			break;
		case FAULT_9001:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_REQUEST_DENIED));
			out_fault = USP_FAULT_REQUEST_DENIED;
			break;
		case FAULT_9002:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_INTERNAL_ERROR));
			out_fault = USP_FAULT_INTERNAL_ERROR;
			break;
		case FAULT_9003:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_INVALID_ARGUMENT));
			out_fault = USP_FAULT_INVALID_ARGUMENT;
			break;
		case FAULT_9004:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_RESOURCES_EXCEEDED));
			out_fault = USP_FAULT_RESOURCES_EXCEEDED;
			break;
		case FAULT_9005:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_INVALID_PATH));
			out_fault = USP_FAULT_INVALID_PATH;
			break;
		case FAULT_9006:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_INVALID_TYPE));
			out_fault = USP_FAULT_INVALID_TYPE;
			break;
		case FAULT_9007:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_PARAM_READ_ONLY));
			out_fault = USP_FAULT_INVALID_VALUE;
			break;
		case FAULT_9008:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_PARAM_READ_ONLY));
			out_fault = USP_FAULT_PARAM_READ_ONLY;
			break;
		default:
			if (fault >= FAULT_9000) {
				bbfdm_set_fault_message(ctx, "%s", get_fault_message(USP_FAULT_GENERAL_FAILURE));
				out_fault = USP_FAULT_GENERAL_FAILURE;
			} else {
				bbfdm_set_fault_message(ctx, "%s", get_fault_message(fault));
				out_fault = fault;
			}
		}
	} else if (ctx->dm_type == BBFDM_CWMP) {
		switch(fault) {
		case USP_FAULT_MESSAGE_NOT_UNDERSTOOD:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9000));
			out_fault = FAULT_9000;
			break;
		case USP_FAULT_REQUEST_DENIED:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9001));
			out_fault = FAULT_9001;
			break;
		case USP_FAULT_GENERAL_FAILURE:
		case USP_FAULT_INTERNAL_ERROR:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9002));
			out_fault = FAULT_9002;
			break;
		case USP_FAULT_INVALID_ARGUMENT:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9003));
			out_fault = FAULT_9003;
			break;
		case USP_FAULT_RESOURCES_EXCEEDED:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9004));
			out_fault = FAULT_9004;
			break;
		case USP_FAULT_INVALID_PATH:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9005));
			out_fault = FAULT_9005;
			break;
		case USP_FAULT_INVALID_TYPE:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9006));
			out_fault = FAULT_9006;
			break;
		case USP_FAULT_INVALID_VALUE:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9007));
			out_fault = FAULT_9007;
			break;
		case USP_FAULT_PARAM_READ_ONLY:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(FAULT_9008));
			out_fault =  FAULT_9008;
			break;
		default:
			bbfdm_set_fault_message(ctx, "%s", get_fault_message(fault));
			out_fault = fault;
		}
	} else {
		bbfdm_set_fault_message(ctx, "%s", get_fault_message(fault));
		out_fault = fault;
	}

	return out_fault;
}

int bbf_entry_method(struct dmctx *ctx, int cmd)
{
	int fault = 0;
	ctx->fault_msg[0] = 0;

	if (!ctx->dm_entryobj) {
		bbfdm_set_fault_message(ctx, "Root entry was not defined.");
		return bbf_fault_map(ctx, FAULT_9002);
	}

	if (!ctx->in_param) {
		bbfdm_set_fault_message(ctx, "Path should not be blank.");
		return bbf_fault_map(ctx, FAULT_9005);
	}

	dmentry_instance_lookup_inparam(ctx);
	ctx->iswildcard = DM_STRCHR(ctx->in_param, '*') ? 1 : 0;
	ctx->stop = false;

	switch(cmd) {
	case BBF_GET_VALUE:
		fault = dm_entry_get_value(ctx);
		break;
	case BBF_SCHEMA:
		fault = dm_entry_get_supported_dm(ctx);
		break;
	case BBF_INSTANCES:
		fault = dm_entry_get_instances(ctx);
		break;
	case BBF_GET_NAME:
		fault = dm_entry_get_name(ctx);
		break;
	case BBF_SET_VALUE:
		fault = dm_entry_set_value(ctx);
		if (!fault)
			dmuci_change_packages(&head_package_change);
		break;
	case BBF_ADD_OBJECT:
		fault = dm_entry_add_object(ctx);
		if (!fault)
			dmuci_change_packages(&head_package_change);
		break;
	case BBF_DEL_OBJECT:
		fault = dm_entry_delete_object(ctx);
		if (!fault)
			dmuci_change_packages(&head_package_change);
		break;
	case BBF_OPERATE:
		fault = dm_entry_operate(ctx);
		break;
	case BBF_EVENT:
		fault = dm_entry_event(ctx);
		break;
	}

	dmuci_save();
	return bbf_fault_map(ctx, fault);
}

void bbf_global_init(DMOBJ *dm_entryobj, const char *plugin_path)
{
	dm_dynamic_initmem(&global_memhead);
	load_plugins(dm_entryobj, plugin_path);
}

void bbf_global_clean(DMOBJ *dm_entryobj)
{
	free_plugins(dm_entryobj);
	dm_dynamic_cleanmem(&global_memhead);
}

int dm_entry_validate_allowed_objects(struct dmctx *ctx, char *value, char *objects[]) // To be removed later!!!!!!!!!!!!
{
	if (!value || !objects)
		return -1;

	if (*value == '\0')
		return 0;

	for (; *objects; objects++) {

		if (match(value, *objects, 0, NULL)) {
			char *linker = NULL;

			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker)
				return 0;
		}
	}

	bbfdm_set_fault_message(ctx, "'%s' value is not allowed.", value);
	return -1;
}

int dm_entry_validate_external_linker_allowed_objects(struct dmctx *ctx, char *value, char *objects[]) // To be removed later!!!!!!!!!!!!
{
	if (!value || !objects)
		return -1;

	if (*value == '\0')
		return 0;

	for (; *objects; objects++) {

		if (match(value, *objects, 0, NULL))
			return 0;
	}

	bbfdm_set_fault_message(ctx, "'%s' value is not allowed.", value);
	return -1;
}

int dm_validate_allowed_objects(struct dmctx *ctx, struct dm_reference *reference, char *objects[])
{
	if (!reference || !objects)
		return -1;

	if (DM_STRLEN(reference->path) == 0)
		return 0;

	for (; *objects; objects++) {

		if (match(reference->path, *objects, 0, NULL)) {

			if (is_micro_service) {
				if (DM_STRLEN(reference->value))
					return 0;
			} else {
				if (adm_entry_object_exists(ctx, reference->path))
					return 0;
			}
		}
	}

	bbfdm_set_fault_message(ctx, "'%s' value is not allowed.", reference->path);
	return -1;
}

int adm_entry_get_reference_param(struct dmctx *ctx, char *param, char *linker, char **value)
{
	struct dmctx dmctx = {0};
	*value = "";

	if (!param || !linker || *linker == 0)
		return 0;

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj);

	dmctx.iswildcard = 1;
	dmctx.inparam_isparam = 1;
	dmctx.in_param = param;
	dmctx.linker = linker;

	dm_entry_get_reference_param(&dmctx);

	*value = dmctx.linker_param ? dmctx.linker_param : "";

	bbf_ctx_clean_sub(&dmctx);
	return 0;
}

int adm_entry_get_reference_value(struct dmctx *ctx, char *param, char **value)
{
	struct dmctx dmctx = {0};
	char linker[256] = {0};
	*value = NULL;

	if (!param || param[0] == '\0')
		return 0;

	snprintf(linker, sizeof(linker), "%s%c", param, (param[DM_STRLEN(param) - 1] != '.') ? '.' : '\0');

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj);

	dmctx.in_param = linker;

	dm_entry_get_reference_value(&dmctx);

	*value = dmctx.linker;

	bbf_ctx_clean_sub(&dmctx);
	return 0;
}

int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value) // To be removed later!!!!!!!!!!!!
{
	struct dmctx dmctx = {0};
	*value = "";

	if (!param || !linker || *linker == 0)
		return 0;

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj);

	dmctx.in_param = param;
	dmctx.linker = linker;

	dm_entry_get_linker(&dmctx);
	*value = dmctx.linker_param;

	bbf_ctx_clean_sub(&dmctx);
	return 0;
}

int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value) // To be removed later!!!!!!!!!!!!
{
	struct dmctx dmctx = {0};
	char linker[256] = {0};
	*value = NULL;

	if (!param || param[0] == '\0')
		return 0;

	snprintf(linker, sizeof(linker), "%s%c", param, (param[DM_STRLEN(param) - 1] != '.') ? '.' : '\0');

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj);

	dmctx.in_param = linker;

	dm_entry_get_linker_value(&dmctx);
	*value = dmctx.linker;

	bbf_ctx_clean_sub(&dmctx);
	return 0;
}

bool adm_entry_object_exists(struct dmctx *ctx, char *param)
{
	struct dmctx dmctx = {0};
	char linker[256] = {0};

	if (!param || param[0] == '\0')
		return false;

	snprintf(linker, sizeof(linker), "%s%c", param, (param[DM_STRLEN(param) - 1] != '.') ? '.' : '\0');

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj);

	dmctx.in_param = linker;

	dm_entry_object_exists(&dmctx);

	bbf_ctx_clean_sub(&dmctx);

	return dmctx.match;
}

void bbf_entry_restart_services(struct blob_buf *bb, bool restart_services)
{
	struct package_change *pc = NULL;

	list_for_each_entry(pc, &head_package_change, list) {

		if (bb) blobmsg_add_string(bb, NULL, pc->package);

		if (restart_services) {
			dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", pc->package, String}}, 1);
		}
	}

	dmuci_commit_bbfdm();

	free_all_list_package_change(&head_package_change);
}

void bbf_entry_revert_changes(struct blob_buf *bb)
{
	struct package_change *pc = NULL;

	list_for_each_entry(pc, &head_package_change, list) {

		if (bb) blobmsg_add_string(bb, NULL, pc->package);

		dmubus_call_set("uci", "revert", UBUS_ARGS{{"config", pc->package, String}}, 1);
	}

	dmuci_revert_bbfdm();

	free_all_list_package_change(&head_package_change);
}
