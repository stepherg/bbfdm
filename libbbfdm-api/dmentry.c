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
#include "dmuci.h"
#include "dmbbf.h"
#include "dmmem.h"
#include "dmubus.h"
#include "dmentry.h"

#ifdef BBFDM_ENABLE_JSON_PLUGIN
#include "dm_plugin/dmdynamicjson.h"
static char json_hash[64] = {0};
#endif /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
#include "dm_plugin/dmdynamiclibrary.h"
static char library_hash[64] = {0};
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
#include "dm_plugin/dmdynamicvendor.h"
static bool first_boot = false;
#endif

LIST_HEAD(head_package_change);
LIST_HEAD(global_memhead);

void bbf_ctx_init(struct dmctx *ctx, DMOBJ *tEntryObj,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE *tVendorExtensionExclude)
{
	INIT_LIST_HEAD(&ctx->list_parameter);
	ctx->dm_entryobj = tEntryObj;
	ctx->dm_vendor_extension[0] = tVendorExtension ? tVendorExtension[0] : NULL;
	ctx->dm_vendor_extension[1] = tVendorExtension ? tVendorExtension[1] : NULL;
	ctx->dm_vendor_extension_exclude = tVendorExtensionExclude;
	dm_uci_init();
}

void bbf_ctx_clean(struct dmctx *ctx)
{
	free_all_list_parameter(ctx);

	dm_uci_exit();
	dmubus_free();
	dmcleanmem();
}

void bbf_ctx_init_sub(struct dmctx *ctx, DMOBJ *tEntryObj,
		DM_MAP_VENDOR *tVendorExtension[],
		DM_MAP_VENDOR_EXCLUDE *tVendorExtensionExclude)
{
	INIT_LIST_HEAD(&ctx->list_parameter);
	ctx->dm_entryobj = tEntryObj;
	ctx->dm_vendor_extension[0] = tVendorExtension ? tVendorExtension[0] : NULL;
	ctx->dm_vendor_extension[1] = tVendorExtension ? tVendorExtension[1] : NULL;
	ctx->dm_vendor_extension_exclude = tVendorExtensionExclude;
}

void bbf_ctx_clean_sub(struct dmctx *ctx)
{
	free_all_list_parameter(ctx);
}

int bbf_fault_map(unsigned int dm_type, int fault)
{
	int out_fault;

	if (dm_type == BBFDM_USP) {
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
	} else if (dm_type == BBFDM_CWMP) {
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
		if (DM_STRCMP(buf, json_hash) != 0) {
			DM_STRNCPY(json_hash, buf, sizeof(json_hash));
			return 1;
		}
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */
	} else {
#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
		if (DM_STRCMP(buf, library_hash) != 0) {
			DM_STRNCPY(library_hash, buf, sizeof(library_hash));
			return 1;
		}
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */
	}

	return 0;
}
#endif  /* (BBFDM_ENABLE_JSON_PLUGIN || BBFDM_ENABLE_DOTSO_PLUGIN) */

static void load_dynamic_arrays(struct dmctx *ctx)
{
#ifdef BBFDM_ENABLE_JSON_PLUGIN
	// Load dynamic objects and parameters exposed via a JSON file
	if (check_stats_folder(true)) {
		free_json_dynamic_arrays(ctx->dm_entryobj);
		load_json_dynamic_arrays(ctx);
	}
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
	// Load dynamic objects and parameters exposed via a library
	if (check_stats_folder(false)) {
		free_library_dynamic_arrays(ctx->dm_entryobj);
		load_library_dynamic_arrays(ctx);
	}
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
	// Load objects and parameters exposed via vendor extension
	if (first_boot == false) {
		free_vendor_dynamic_arrays(ctx->dm_entryobj);
		load_vendor_dynamic_arrays(ctx);
		first_boot = true;
	}
#endif
}

static void free_dynamic_arrays(DMOBJ *dm_entryobj)
{
	DMNODE node = {.current_object = ""};

#ifdef BBFDM_ENABLE_JSON_PLUGIN
	free_json_dynamic_arrays(dm_entryobj);
#endif  /* BBFDM_ENABLE_JSON_PLUGIN */

#ifdef BBFDM_ENABLE_DOTSO_PLUGIN
	free_library_dynamic_arrays(dm_entryobj);
#endif  /* BBFDM_ENABLE_DOTSO_PLUGIN */

#ifdef BBF_VENDOR_EXTENSION
	free_vendor_dynamic_arrays(dm_entryobj);
#endif

	free_dm_browse_node_dynamic_object_tree(&node, dm_entryobj);
}

int bbf_entry_method(struct dmctx *ctx, int cmd)
{
	int fault = 0;

	if (!ctx->dm_entryobj)
		return bbf_fault_map(ctx->dm_type, USP_FAULT_INVALID_CONFIGURATION);

	if (!ctx->in_param)
		return bbf_fault_map(ctx->dm_type, USP_FAULT_INVALID_PATH);

	// Load dynamic objects and parameters
	if (ctx->enable_plugins)
		load_dynamic_arrays(ctx);

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
		ctx->setaction = VALUECHECK;
		fault = dm_entry_set_value(ctx);
		if (fault)
			break;

		ctx->setaction = VALUESET;
		ctx->stop = false;
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
	}

	dmuci_save();
	return bbf_fault_map(ctx->dm_type, fault);
}

void bbf_global_clean(DMOBJ *dm_entryobj)
{
	free_dynamic_arrays(dm_entryobj);
	dm_dynamic_cleanmem(&global_memhead);
}

int dm_entry_validate_allowed_objects(struct dmctx *ctx, char *value, char *objects[])
{
	if (!value || !objects)
		return -1;

	if (*value == '\0')
		return 0;

	for (; *objects; objects++) {

		if (match(value, *objects)) {
			char *linker = NULL;

			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker)
				return 0;
		}
	}

	return -1;
}

int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value)
{
	struct dmctx dmctx = {0};
	*value = "";

	if (!param || !linker || *linker == 0)
		return 0;

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj, ctx->dm_vendor_extension, ctx->dm_vendor_extension_exclude);

	dmctx.in_param = param;
	dmctx.linker = linker;

	dm_entry_get_linker(&dmctx);
	*value = dmctx.linker_param;

	bbf_ctx_clean_sub(&dmctx);
	return 0;
}

int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value)
{
	struct dmctx dmctx = {0};
	char linker[256] = {0};
	*value = NULL;

	if (!param || param[0] == '\0')
		return 0;

	snprintf(linker, sizeof(linker), "%s%c", param, (param[DM_STRLEN(param) - 1] != '.') ? '.' : '\0');

	bbf_ctx_init_sub(&dmctx, ctx->dm_entryobj, ctx->dm_vendor_extension, ctx->dm_vendor_extension_exclude);

	dmctx.in_param = linker;

	dm_entry_get_linker_value(&dmctx);
	*value = dmctx.linker;

	bbf_ctx_clean_sub(&dmctx);
	return 0;
}

void bbf_entry_restart_services(struct blob_buf *bb, bool restart_services)
{
	struct package_change *pc = NULL;
	void *arr = NULL;

	if (bb) arr = blobmsg_open_array(bb, "updated_services");

	list_for_each_entry(pc, &head_package_change, list) {

		if (bb) blobmsg_add_string(bb, NULL, pc->package);

		if (restart_services) {
			dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", pc->package, String}}, 1);
		} else {
			dmuci_commit_package(pc->package);
		}
	}

	if (bb) blobmsg_close_array(bb, arr);

	dmuci_commit_bbfdm();

	free_all_list_package_change(&head_package_change);
}

void bbf_entry_revert_changes(struct blob_buf *bb)
{
	struct package_change *pc = NULL;
	void *arr = NULL;

	if (bb) arr = blobmsg_open_array(bb, "reverted_configs");

	list_for_each_entry(pc, &head_package_change, list) {

		if (bb) blobmsg_add_string(bb, NULL, pc->package);

		dmubus_call_set("uci", "revert", UBUS_ARGS{{"config", pc->package, String}}, 1);
	}

	if (bb) blobmsg_close_array(bb, arr);

	dmuci_revert_bbfdm();

	free_all_list_package_change(&head_package_change);
}

int bbf_debug_browse_path(char *buff, size_t len)
{
	if (!buff)
		return -1;

	// initialise with default value
	buff[0] = '\0';

	return dm_browse_last_access_path(buff, len);
}
