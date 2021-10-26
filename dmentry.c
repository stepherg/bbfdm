/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "dmentry.h"
#include "dmdynamicjson.h"
#include "dmdynamiclibrary.h"
#include "dmdynamicvendor.h"
#include "device.h"
#include "dmbbfcommon.h"

LIST_HEAD(head_package_change);
LIST_HEAD(main_memhead);

#ifdef BBFDM_ENABLE_JSON_PLUGIN
static char json_hash[64] = {0};
#endif /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
static char library_hash[64] = {0};
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
static bool first_boot = false;
#endif

int dm_debug_browse_path(char *buff, size_t len)
{
	if (!buff)
		return -1;

	// initialise with default value
	buff[0] = '\0';

	return dm_browse_last_access_path(buff, len);
}

int usp_fault_map(int fault)
{
	int out_fault;

	if (bbfdatamodel_type == BBFDM_USP) {
		switch(fault) {
		case FAULT_9000:
			out_fault = USP_FAULT_MESSAGE_NOT_UNDERSTOOD;
			break;
		case FAULT_9001:
			out_fault = USP_FAULT_REQUEST_DENIED;
			break;
		case FAULT_9002:
			out_fault = USP_FAULT_INTERNAL_ERROR;
			break;
		case FAULT_9003:
			out_fault = USP_FAULT_INVALID_ARGUMENT;
			break;
		case FAULT_9004:
		case FAULT_9027:
			out_fault = USP_FAULT_RESOURCES_EXCEEDED;
			break;
		case FAULT_9005:
			out_fault = USP_FAULT_INVALID_PATH;
			break;
		case FAULT_9006:
			out_fault = USP_FAULT_INVALID_TYPE;
			break;
		case FAULT_9007:
			out_fault = USP_FAULT_INVALID_VALUE;
			break;
		case FAULT_9008:
			out_fault = USP_FAULT_PARAM_READ_ONLY;
			break;
		default:
			if (fault >= FAULT_9000)
				out_fault = USP_FAULT_GENERAL_FAILURE;
			else
				out_fault = fault;
		}
	} else if (bbfdatamodel_type == BBFDM_CWMP) {
		switch(fault) {
		case USP_FAULT_GENERAL_FAILURE:
			out_fault = FAULT_9002;
			break;
		case USP_FAULT_MESSAGE_NOT_UNDERSTOOD:
			out_fault = FAULT_9000;
			break;
		case USP_FAULT_REQUEST_DENIED:
			out_fault = FAULT_9001;
			break;
		case USP_FAULT_INTERNAL_ERROR:
			out_fault = FAULT_9002;
			break;
		case USP_FAULT_INVALID_ARGUMENT:
			out_fault = FAULT_9003;
			break;
		case USP_FAULT_RESOURCES_EXCEEDED:
			out_fault = FAULT_9004;
			break;
		case USP_FAULT_INVALID_TYPE:
			out_fault = FAULT_9006;
			break;
		case USP_FAULT_INVALID_VALUE:
			out_fault = FAULT_9007;
			break;
		case USP_FAULT_PARAM_READ_ONLY:
			out_fault =  FAULT_9008;
			break;
		case USP_FAULT_INVALID_PATH:
			out_fault = FAULT_9005;
			break;
		default:
			out_fault = fault;
		}
	} else {
		out_fault = fault;
	}

	return out_fault;
}

static int dm_ctx_init_custom(struct dmctx *ctx, unsigned int instance_mode, int custom)
{
	if (custom == CTX_INIT_ALL)
		bbf_uci_init();

	INIT_LIST_HEAD(&ctx->list_parameter);
	INIT_LIST_HEAD(&ctx->set_list_tmp);
	INIT_LIST_HEAD(&ctx->list_fault_param);
	ctx->instance_mode = instance_mode;
	ctx->dm_entryobj = tEntry181Obj;
	ctx->end_session_flag = 0;
	return 0;
}

static int dm_ctx_clean_custom(struct dmctx *ctx, int custom)
{
	free_all_list_parameter(ctx);
	free_all_set_list_tmp(ctx);
	free_all_list_fault_param(ctx);
	DMFREE(ctx->addobj_instance);
	if (custom == CTX_INIT_ALL) {
		bbf_uci_exit();
		dmubus_free();
		dmcleanmem();
	}
	return 0;
}

int dm_ctx_init(struct dmctx *ctx, unsigned int instance_mode)
{
	return dm_ctx_init_custom(ctx, instance_mode, CTX_INIT_ALL);
}

int dm_ctx_clean(struct dmctx *ctx)
{
	return dm_ctx_clean_custom(ctx, CTX_INIT_ALL);
}

int dm_ctx_init_sub(struct dmctx *ctx, unsigned int instance_mode)
{
	return dm_ctx_init_custom(ctx, instance_mode, CTX_INIT_SUB);
}

int dm_ctx_clean_sub(struct dmctx *ctx)
{
	return dm_ctx_clean_custom(ctx, CTX_INIT_SUB);
}

int dm_entry_param_method(struct dmctx *ctx, int cmd, char *inparam, char *arg1, char *arg2)
{
	int fault = 0;

	// Load dynamic objects and parameters
	load_dynamic_arrays(ctx);

	if (!inparam) inparam = "";
	ctx->in_param = inparam;
	dmentry_instance_lookup_inparam(ctx);
	ctx->stop = false;
	switch(cmd) {
		case CMD_GET_VALUE:
			if (ctx->in_param[0] == '.' && strlen(ctx->in_param) == 1)
				fault = FAULT_9005;
			else
				fault = dm_entry_get_value(ctx);
			break;
		case CMD_GET_NAME:
			if (ctx->in_param[0] == '.' && strlen(ctx->in_param) == 1)
				fault = FAULT_9005;
			else if (arg1 && string_to_bool(arg1, &ctx->nextlevel) == 0)
				fault = dm_entry_get_name(ctx);
			else
				fault = FAULT_9003;
			break;
		case CMD_SET_VALUE:
			ctx->in_value = arg1 ? arg1 : "";
			ctx->setaction = VALUECHECK;
			fault = dm_entry_set_value(ctx);
			if (fault)
				add_list_fault_param(ctx, ctx->in_param, usp_fault_map(fault));
			break;
		case CMD_ADD_OBJECT:
			fault = dm_entry_add_object(ctx);
			if (!fault) {
				dmuci_set_value("cwmp", "acs", "ParameterKey", arg1 ? arg1 : "");
				dmuci_change_packages(&head_package_change);
			}
			break;
		case CMD_DEL_OBJECT:
			fault = dm_entry_delete_object(ctx);
			if (!fault) {
				dmuci_set_value("cwmp", "acs", "ParameterKey", arg1 ? arg1 : "");
				dmuci_change_packages(&head_package_change);
			}
			break;
		case CMD_USP_OPERATE:
			ctx->in_value = arg1 ? arg1 : "";
			fault = dm_entry_operate(ctx);
			break;
		case CMD_USP_LIST_OPERATE:
			fault = dm_entry_list_operates(ctx);
			break;
		case CMD_USP_LIST_EVENT:
			fault = dm_entry_list_events(ctx);
			break;
		case CMD_GET_SCHEMA:
			fault = dm_entry_get_schema(ctx);
			break;
		case CMD_GET_INSTANCES:
			if (!arg1 || (arg1 && string_to_bool(arg1, &ctx->nextlevel) == 0))
				fault = dm_entry_get_instances(ctx);
			else
				fault = FAULT_9003;
			break;
	}

	dmuci_save();
	return usp_fault_map(fault);
}

int dm_entry_apply(struct dmctx *ctx, int cmd, char *arg1)
{
	struct set_tmp *n = NULL, *p = NULL;
	int fault = 0;

	switch(cmd) {
		case CMD_SET_VALUE:
			ctx->setaction = VALUESET;
			list_for_each_entry_safe(n, p, &ctx->set_list_tmp, list) {
				ctx->in_param = n->name;
				ctx->in_value = n->value ? n->value : "";
				ctx->stop = false;
				fault = dm_entry_set_value(ctx);
				if (fault) {
					add_list_fault_param(ctx, ctx->in_param, usp_fault_map(fault));
					break;
				}
			}
			if (!fault) {
				dmuci_set_value("cwmp", "acs", "ParameterKey", arg1 ? arg1 : "");
				dmuci_change_packages(&head_package_change);
				dmuci_save();
			}
			break;
	}
	free_all_set_list_tmp(ctx);

	return usp_fault_map(fault);
}

int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value)
{
	struct dmctx dmctx = {0};

	dm_ctx_init_sub(&dmctx, ctx->instance_mode);
	dmctx.in_param = param ? param : "";
	dmctx.linker = linker;

	dm_entry_get_linker(&dmctx);
	*value = dmctx.linker_param;

	dm_ctx_clean_sub(&dmctx);
	return 0;
}

int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value)
{
	struct dmctx dmctx = {0};
	char linker[256] = {0};
	*value = NULL;

	if (!param || param[0] == '\0')
		return 0;

	snprintf(linker, sizeof(linker), "%s%c", param, (param[strlen(param) - 1] != '.') ? '.' : '\0');

	dm_ctx_init_sub(&dmctx, ctx->instance_mode);
	dmctx.in_param = linker;

	dm_entry_get_linker_value(&dmctx);
	*value = dmctx.linker;

	dm_ctx_clean_sub(&dmctx);
	return 0;
}

int dm_entry_manage_services(struct blob_buf *bb, bool restart)
{
	struct package_change *pc = NULL;
	void *arr;

	if (!bb)
		return 0;

	arr = blobmsg_open_array(bb, "updated_services");
	list_for_each_entry(pc, &head_package_change, list) {
		blobmsg_add_string(bb, NULL, pc->package);
		if (restart) {
			dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", pc->package, String}}, 1);
		} else {
			dmuci_commit_package(pc->package);
		}
	}
	blobmsg_close_array(bb, arr);
	return 0;
}

int dm_entry_restart_services(void)
{
	struct package_change *pc = NULL;

	bbf_uci_commit_bbfdm();

	list_for_each_entry(pc, &head_package_change, list) {
		if (strcmp(pc->package, "cwmp") == 0) {
			dmuci_init();
			dmuci_commit_package("cwmp");
			dmuci_exit();
		} else {
			dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", pc->package, String}}, 1);
		}
	}
	free_all_list_package_change(&head_package_change);

	return 0;
}

int dm_entry_revert_changes(void)
{
	struct package_change *pc = NULL;

	bbf_uci_revert_bbfdm();

	list_for_each_entry(pc, &head_package_change, list) {
		dmubus_call_set("uci", "revert", UBUS_ARGS{{"config", pc->package, String}}, 1);
	}
	free_all_list_package_change(&head_package_change);

	return 0;
}

#if defined(BBFDM_ENABLE_JSON_PLUGIN) || defined(BBFDM_ENABLE_DOTSO_PLUGIN)
static char* get_folder_path(bool json_path)
{
	if (json_path) {
#ifdef BBFDM_ENABLE_JSON_PLUGIN
		return JSON_FOLDER_PATH;
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */
	} else {
#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
		return LIBRARY_FOLDER_PATH;
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */
	}

	return NULL;
}

static int get_stats_folder(bool json_path, int *count, unsigned long *size)
{
	const char *path = get_folder_path(json_path);
	if (path == NULL) {
		return 0;
	}

	if (folder_exists(path)) {
		struct dirent *entry = NULL;
		struct stat stats;
		int file_count = 0;
		unsigned long file_size = 0;
		char buf[512] = {0};

		DIR *dirp = opendir(path);
		while ((entry = readdir(dirp)) != NULL) {
			if ((entry->d_type == DT_REG) && (strstr(entry->d_name, json_path ? ".json" : ".so"))) {
				file_count++;
				snprintf(buf, sizeof(buf), "%s/%s", path, entry->d_name);
				if (!stat(buf, &stats))
					file_size += stats.st_size;
			}
		}

		if (dirp)
			closedir(dirp);

		*count = file_count;
		*size = file_size;
		return 1;
	}
	return 0;
}

static int check_stats_folder(bool json_path)
{
	int count = 0;
	unsigned long size = 0;
	char buf[64] = {0};

	if (!get_stats_folder(json_path, &count, &size))
		return 0;

	snprintf(buf, sizeof(buf), "count:%d,size:%lu", count, size);

	if (json_path) {
#ifdef BBFDM_ENABLE_JSON_PLUGIN
		if (strcmp(buf, json_hash) != 0) {
			strncpy(json_hash, buf, 64);
			return 1;
		}
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */
	} else {
#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
		if (strcmp(buf, library_hash) != 0) {
			strncpy(library_hash, buf, 64);
			return 1;
		}
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */
	}

	return 0;
}
#endif  /* (BBFDM_ENABLE_JSON_PLUGIN || BBFDM_ENABLE_DOTSO_PLUGIN) */

void load_dynamic_arrays(struct dmctx *ctx)
{
#ifdef BBFDM_ENABLE_JSON_PLUGIN
	// Load dynamic objects and parameters exposed via a JSON file
	if (check_stats_folder(true)) {
		free_json_dynamic_arrays(tEntry181Obj);
		load_json_dynamic_arrays(ctx);
	}
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
	// Load dynamic objects and parameters exposed via a library
	if (check_stats_folder(false)) {
		free_library_dynamic_arrays(tEntry181Obj);
		load_library_dynamic_arrays(ctx);
	}
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
	// Load objects and parameters exposed via vendor extension
	if (first_boot == false) {
		free_vendor_dynamic_arrays(tEntry181Obj);
		load_vendor_dynamic_arrays(ctx);
		first_boot = true;
	}
#endif
}

void free_dynamic_arrays(void)
{
	DMOBJ *root = tEntry181Obj;
	DMNODE node = {.current_object = ""};

#ifdef BBFDM_ENABLE_JSON_PLUGIN
	free_json_dynamic_arrays(tEntry181Obj);
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
	free_library_dynamic_arrays(tEntry181Obj);
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
	free_vendor_dynamic_arrays(tEntry181Obj);
#endif
	free_dm_browse_node_dynamic_object_tree(&node, root);
	dm_dynamic_cleanmem(&main_memhead);
}
