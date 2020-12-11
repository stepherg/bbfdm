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
#include "dmentryjson.h"
#include "dmentrylibrary.h"
#include "dmoperate.h"
#include "device.h"
#include "dmbbfcommon.h"

#ifdef BBF_TR064
#include "upnp_device.h"
#endif

LIST_HEAD(head_package_change);
LIST_HEAD(list_enabled_lw_notify);

static char json_hash[64] = {0};
static char library_hash[64] = {0};

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

static int dm_ctx_init_custom(struct dmctx *ctx, unsigned int dm_type, unsigned int amd_version, unsigned int instance_mode, int custom)
{
#ifdef BBF_TR064
	UPNP_SUPPORTED_DM *tUPNPSupportedDM = NULL;
#endif
	if (custom == CTX_INIT_ALL)
		bbf_uci_init();

	INIT_LIST_HEAD(&ctx->list_parameter);
	INIT_LIST_HEAD(&ctx->set_list_tmp);
	INIT_LIST_HEAD(&ctx->list_fault_param);
	ctx->amd_version = amd_version;
	ctx->instance_mode = instance_mode;
	ctx->dm_type = dm_type;
#ifdef BBF_TR064
	if (dm_type == DM_UPNP) {
		strcpy(dmroot, DMROOT_UPNP);
		dm_delim = DMDELIM_UPNP;
		ctx->dm_entryobj = tEntry181ObjUPNP;
		ctx->user_mask = 0;
	}
	else {
		strcpy(dmroot, "Device");
		dm_delim = DMDELIM_CWMP;
		ctx->dm_entryobj = tEntry181Obj;
	}

	tUPNPSupportedDM = malloc(tr181_size);
	if (tUPNPSupportedDM == NULL) {
		exit(0);
	}
	tUPNPSupportedDM = tUPNPSupportedDM_181;

	free(tUPNPSupportedDM);
#else
	dm_delim = DMDELIM_CWMP;
	ctx->dm_entryobj = tEntry181Obj;
#endif
	ctx->end_session_flag = 0;
	return 0;
}
void dm_ctx_init_list_parameter(struct dmctx *ctx)
{
	INIT_LIST_HEAD(&ctx->list_parameter);
	INIT_LIST_HEAD(&ctx->set_list_tmp);
	INIT_LIST_HEAD(&ctx->list_fault_param);
}
void dm_ctx_clean_list_parameter(struct dmctx *ctx)
{
	free_all_list_parameter(ctx);
	free_all_set_list_tmp(ctx);
	free_all_list_fault_param(ctx);
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

int dm_ctx_init(struct dmctx *ctx, unsigned int dm_type, unsigned int amd_version, unsigned int instance_mode)
{
	dm_ctx_init_custom(ctx, dm_type, amd_version, instance_mode, CTX_INIT_ALL);
	return 0;
}

int dm_ctx_clean(struct dmctx *ctx)
{
	dm_ctx_clean_custom(ctx, CTX_INIT_ALL);
	return 0;
}

int dm_ctx_init_sub(struct dmctx *ctx, unsigned int dm_type, unsigned int amd_version, unsigned int instance_mode)
{
	dm_ctx_init_custom(ctx, dm_type, amd_version, instance_mode, CTX_INIT_SUB);
	return 0;
}

int dm_ctx_clean_sub(struct dmctx *ctx)
{
	dm_ctx_clean_custom(ctx, CTX_INIT_SUB);
	return 0;
}

int dmentry_get_parameter_leaf_value(struct dmctx *ctx, char *inparam)
{
	int fault = 0;

	if (!inparam) inparam = "";
	ctx->in_param = inparam;

	if (ctx->dm_type == DM_CWMP && ctx->in_param[0] == dm_delim && strlen(ctx->in_param) == 1)
		fault = FAULT_9005;
	else
		fault = dm_entry_get_full_param_value(ctx);
	return fault;
}

int dm_entry_param_method(struct dmctx *ctx, int cmd, char *inparam, char *arg1, char *arg2)
{
	int err = 0, fault = 0;
	bool setnotif = true;
#ifdef BBF_TR064
	bool alarm = false, event = false;
	int err2 = 0;
#endif

	// Load dynamic objects and parameters
	load_dynamic_arrays(ctx);

	if (!inparam) inparam = "";
	ctx->in_param = inparam;
	dmentry_instance_lookup_inparam(ctx);
	ctx->stop = false;
	switch(cmd) {
		case CMD_GET_VALUE:
			if (ctx->dm_type == DM_CWMP && ctx->in_param[0] == dm_delim && strlen(ctx->in_param) == 1)
				fault = FAULT_9005;
			else
				fault = dm_entry_get_value(ctx);
			break;
		case CMD_GET_NAME:
			if (ctx->dm_type == DM_CWMP && ctx->in_param[0] == dm_delim && strlen(ctx->in_param) == 1)
				fault = FAULT_9005;
			else if (arg1 && string_to_bool(arg1, &ctx->nextlevel) == 0)
				fault = dm_entry_get_name(ctx);
			else
				fault = FAULT_9003;
			break;
		case CMD_GET_NOTIFICATION:
			if (ctx->dm_type == DM_CWMP && ctx->in_param[0] == dm_delim && strlen(ctx->in_param) == 1)
				fault = FAULT_9005;
			else
				fault = dm_entry_get_notification(ctx);
			break;
		case CMD_SET_VALUE:
			ctx->in_value = arg1 ? arg1 : "";
			ctx->setaction = VALUECHECK;
			fault = dm_entry_set_value(ctx);
			if (fault)
				add_list_fault_param(ctx, ctx->in_param, usp_fault_map(fault));
			break;
		case CMD_SET_NOTIFICATION:
			if (arg2)
				err = string_to_bool(arg2, &setnotif);
			if (!err && arg1 &&
				(strcmp(arg1, "0") == 0 ||
				strcmp(arg1, "1") == 0  ||
				strcmp(arg1, "2") == 0 ||
				strcmp(arg1, "3") == 0 ||
				strcmp(arg1, "4") == 0 ||
				strcmp(arg1, "5") == 0 ||
				strcmp(arg1, "6") == 0)) {
				ctx->in_notification = arg1;
				ctx->setaction = VALUECHECK;
				ctx->notification_change = setnotif;
				fault = dm_entry_set_notification(ctx);
			} else {
				fault = FAULT_9003;
			}
			break;
		case CMD_LIST_NOTIFY:
			ctx->in_param = "";
			fault = dm_entry_enabled_notify(ctx);
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
			fault = operate_on_node(ctx, ctx->in_param, ctx->in_value);
			break;
		case CMD_USP_LIST_OPERATE:
			operate_list_cmds(ctx);
			break;
		case CMD_GET_SCHEMA:
			fault = dm_entry_get_schema(ctx);
			break;
		case CMD_GET_INSTANCES:
			if (arg1)
				string_to_bool(arg1, &ctx->nextlevel);

			fault = dm_entry_get_instances(ctx);
			break;
#ifdef BBF_TR064
		case CMD_UPNP_GET_SUPPORTED_PARAMETERS:
			ctx->depth = atoi(arg1);
			fault = dm_entry_upnp_get_supported_parameters(ctx);
			break;
		case CMD_UPNP_GET_VALUES:
			fault = dm_entry_upnp_get_values(ctx);
			break;
		case CMD_UPNP_GET_SELECTED_VALUES:
			fault = dm_entry_upnp_get_selected_values(ctx);
			break;
		case CMD_UPNP_GET_INSTANCES:
			ctx->depth = atoi(arg1);
			fault = dm_entry_upnp_get_instances(ctx, false);
			break;
		case CMD_UPNP_SET_VALUES:
			ctx->in_value = arg1 ? arg1 : "";
			ctx->setaction = VALUECHECK;
			fault = dm_entry_upnp_set_values(ctx);
			break;
		case CMD_UPNP_SET_ATTRIBUTES:
			if (arg1)
				err = string_to_bool(arg1, &event);
			if (arg2)
				err2 = string_to_bool(arg2, &alarm);
			if (!err && !err2) {
				ctx->dmparam_flags |= (event) ? DM_PARAM_EVENT_ON_CHANGE : 0;
				ctx->dmparam_flags |= (alarm) ? DM_PARAM_ALARAM_ON_CHANGE : 0;
				ctx->setaction = VALUECHECK;
				fault = dm_entry_upnp_get_set_attributes(ctx, false);
			} else {
				fault = FAULT_9003;
			}
			break;
		case CMD_UPNP_GET_ATTRIBUTES:
			fault = dm_entry_upnp_get_set_attributes(ctx, true);
			break;
		case CMD_UPNP_DEL_INSTANCE:
			fault = dm_entry_upnp_delete_instance(ctx);
			if (!fault) {
				dmuci_change_packages(&head_package_change);
			}
			break;
		case CMD_UPNP_ADD_INSTANCE:
			fault = dm_entry_upnp_add_instance(ctx);
			if (!fault) {
				dmuci_change_packages(&head_package_change);
			}
			break;
		case CMD_UPNP_GET_ACLDATA:
			fault = dm_entry_upnp_get_acl_data(ctx);
			break;
#endif
	}

	dmuci_save();
	return usp_fault_map(fault);
}

int dm_entry_apply(struct dmctx *ctx, int cmd, char *arg1, char *arg2)
{
	int fault = 0;
	struct set_tmp *n, *p;
	
	switch(cmd) {
		case CMD_SET_VALUE:
			ctx->setaction = VALUESET;
			list_for_each_entry_safe(n, p, &ctx->set_list_tmp, list) {
				ctx->in_param = n->name;
				ctx->in_value = n->value ? n->value : "";
				ctx->stop = false;
				fault = dm_entry_set_value(ctx);
				if (fault) break;
			}
			if (fault) {
				//Should not happen
				add_list_fault_param(ctx, ctx->in_param, usp_fault_map(fault));
			} else {
				dmuci_set_value("cwmp", "acs", "ParameterKey", arg1 ? arg1 : "");
				dmuci_change_packages(&head_package_change);
				dmuci_save();
			}
			free_all_set_list_tmp(ctx);
			break;
		case CMD_SET_NOTIFICATION:
			ctx->setaction = VALUESET;
			list_for_each_entry_safe(n, p, &ctx->set_list_tmp, list) {
				ctx->in_param = n->name;
				ctx->in_notification = n->value ? n->value : "0";
				ctx->stop = false;
				fault = dm_entry_set_notification(ctx);
				if (fault) break;
			}
			if (!fault) {
				dmuci_save();
			}
			free_all_set_list_tmp(ctx);
			break;
#ifdef BBF_TR064
		case CMD_UPNP_SET_VALUES:
			ctx->setaction = VALUESET;
			list_for_each_entry_safe(n, p, &ctx->set_list_tmp, list) {
				ctx->in_param = n->name;
				ctx->in_value = n->value ? n->value : "";
				ctx->stop = false;
				fault = dm_entry_upnp_set_values(ctx);
				if (fault) break;
			}
			if (fault) {
				//Should not happen
				dmuci_revert();
			} else {
				dmuci_change_packages(&head_package_change);
				dmuci_commit();
			}
			break;
		case CMD_UPNP_SET_ATTRIBUTES:
			ctx->setaction = VALUESET;
			list_for_each_entry_safe(n, p, &ctx->set_list_tmp, list) {
				ctx->in_param = n->name;
				ctx->dmparam_flags = n->flags;
				ctx->stop = false;
				fault = dm_entry_upnp_get_set_attributes(ctx, false);
				if (fault) break;
			}
			if (fault) {
				//Should not happen
				dmuci_revert();
			} else {
				dmuci_commit();
			}
			free_all_set_list_tmp(ctx);
			break;
#endif
	}
	return usp_fault_map(fault);
}

void del_list_enabled_notify(struct dm_enabled_notify *dm_enabled_notify)
{
	list_del(&dm_enabled_notify->list); // Should be free and not dmfree
	free(dm_enabled_notify->name);
	free(dm_enabled_notify->value);
	free(dm_enabled_notify->notification);
	free(dm_enabled_notify);
}

int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value)
{
	struct dmctx dmctx = {0};

	dm_ctx_init_sub(&dmctx, ctx->dm_type, ctx->amd_version, ctx->instance_mode);
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

	dm_ctx_init_sub(&dmctx, ctx->dm_type, ctx->amd_version, ctx->instance_mode);
	dmctx.in_param = linker;

	dm_entry_get_linker_value(&dmctx);
	*value = dmctx.linker;

	dm_ctx_clean_sub(&dmctx);
	return 0;
}

#ifdef BBF_TR064
/****************************************
 * upnp load tracked on change parameters
 ****************************************/

int dm_entry_upnp_load_tracked_parameters(struct dmctx *dmctx)
{

	dmctx->in_param = "";

	free_all_list_upnp_param_track(&list_upnp_enabled_onevent);
	free_all_list_upnp_param_track(&list_upnp_enabled_onalarm);
	free_all_list_upnp_param_track(&list_upnp_enabled_version);
	dm_entry_upnp_tracked_parameters(dmctx);

	return 0;
}

/*********************************************
 * upnp check on change params (event & alarm)
 *********************************************/

void dm_upnp_update_enabled_track_value(struct dm_upnp_enabled_track *p, char *new_value)
{
	free(p->value); // Should be free and not dmfree
	p->value = strdup(new_value);
}

void dm_upnp_update_enabled_track_key(struct dm_upnp_enabled_track *p, char *key)
{
	free(p->key); // Should be free and not dmfree
	p->key = strdup(key);
}

int dm_entry_upnp_check_onchange_param(struct dmctx *pctx, struct list_head *enabled_head, struct list_head *changed_head)
{
	struct dmctx dmctx = {0};
	struct dm_upnp_enabled_track *p;
	struct dm_parameter *dm_parameter;
	int fault;
	int ischange = 0;
	char *all_instances;

	list_for_each_entry(p, enabled_head, list) {
		dm_ctx_init_sub(&dmctx, pctx->dm_type, pctx->amd_version, pctx->instance_mode);
		dmctx.user_mask = DM_SUPERADMIN_MASK;
		if (p->isobj) {
			all_instances = dm_entry_get_all_instance_numbers(&dmctx, p->name);
			if (all_instances && strcmp(all_instances, p->value) != 0) {
				dm_upnp_update_enabled_track_value(p, all_instances);
				add_list_upnp_param_track(&dmctx, changed_head, p->name, "1", all_instances, 1);
				ischange = 1;
			}
		} else {
			fault = dm_entry_param_method(&dmctx, CMD_UPNP_GET_VALUES, p->name, NULL, NULL);
			if (!fault && dmctx.list_parameter.next != &dmctx.list_parameter) {
				dm_parameter = list_entry(dmctx.list_parameter.next, struct dm_parameter, list);
				if (strcmp(dm_parameter->data, p->value) != 0) {
					dm_upnp_update_enabled_track_value(p, dm_parameter->data);
					add_list_upnp_param_track(&dmctx, changed_head, p->name, "1", dm_parameter->data, 0);
					ischange = 1;
				}
			}
			free_all_list_parameter(&dmctx);
		}
		dm_ctx_clean_sub(&dmctx);
		memset(&dmctx, 0, sizeof(struct dmctx));
	}
	return ischange;
}

int dm_entry_upnp_check_alarmonchange_param(struct dmctx *dmctx)
{
	int r;
	r = dm_entry_upnp_check_onchange_param(dmctx, &list_upnp_enabled_onalarm, &list_upnp_changed_onalarm);
	return r;
}

int dm_entry_upnp_check_eventonchange_param(struct dmctx *dmctx)
{
	int r;
	r = dm_entry_upnp_check_onchange_param(dmctx, &list_upnp_enabled_onevent, &list_upnp_changed_onevent);
	return r;
}

/*************************************
 * upnp check on change version params
 *************************************/

int dm_entry_upnp_update_version_configuration(struct dmctx *dmctx)
{
	char *v, *tmp, buf[32];
	struct uci_section *s;
	int version;

	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "current_configuration_version", &v);
	version = atoi(v);
	version++;

	dmuci_get_section_type(UPNP_CFG, "@dm[0]", &tmp);
	if (!tmp || tmp[0] == '\0') {
		dmuci_add_section(UPNP_CFG, "dm", &s);
	}
	snprintf(buf, sizeof(buf), "%d", version);
	dmuci_set_value(UPNP_CFG, "@dm[0]", "current_configuration_version", buf);
	snprintf(buf, sizeof(buf), "%ld", time(NULL));
	dmuci_set_value(UPNP_CFG, "@dm[0]", "current_configuration_epochtime", buf);

	return version;
}

int dm_entry_upnp_check_versiononchange_param(struct dmctx *pctx)
{
	struct dmctx dmctx = {0};
	struct dm_upnp_enabled_track *p;
	struct dm_parameter *parameter;
	int version, fault, ischange = 0;
	char *all_instances;

	list_for_each_entry(p, &list_upnp_enabled_version, list) {
		ischange = 0;
		dm_ctx_init_sub(&dmctx, pctx->dm_type, pctx->amd_version, pctx->instance_mode);
		dmctx.user_mask = DM_SUPERADMIN_MASK;
		if (p->isobj) {
			all_instances = dm_entry_get_all_instance_numbers(&dmctx, p->name);
			if (strcmp(all_instances, p->value) != 0) {
				dm_upnp_update_enabled_track_value(p, all_instances);
				add_list_upnp_param_track(&dmctx, &list_upnp_changed_version, p->name, "1", all_instances, 1);
				ischange = 1;
			}
		} else {
			fault = dm_entry_param_method(&dmctx, CMD_UPNP_GET_VALUES, p->name, NULL, NULL);
			if (!fault && dmctx.list_parameter.next != &dmctx.list_parameter) {
				parameter = list_entry(dmctx.list_parameter.next, struct dm_parameter, list);
				if (strcmp(parameter->data, p->value) != 0) {
					dm_upnp_update_enabled_track_value(p, parameter->data);
					add_list_upnp_param_track(&dmctx, &list_upnp_changed_version, p->name, p->key, parameter->data, 0);
					ischange = 1;
				}
			}
			free_all_list_parameter(&dmctx);
		}
		if (ischange) {
			char buf[32];
			char *tmp;
			struct uci_section *s = NULL;
			version = dm_entry_upnp_update_version_configuration(&dmctx);
			snprintf(buf, sizeof(buf), "%d", version);
			if (p->key) {
				dmuci_set_value(UPNP_CFG, p->key, "version", buf);
			} else {
				dmuci_add_section(UPNP_CFG, "parameter_version", &s);
				if (s != NULL) {
					dmuci_set_value_by_section(s, "version", buf);
					dmuci_set_value_by_section(s, "parameter", p->name);
					dm_upnp_update_enabled_track_key(p, section_name(s));
				}
			}
			dmuci_commit();
		}
		dm_ctx_clean_sub(&dmctx);
		memset(&dmctx, 0, sizeof(struct dmctx));
	}
	return ischange;
}

/* *************************
 * UPNP init state variables
 * ************************/
int upnp_state_variables_init(struct dmctx *dmctx)
{
	char *v, *tmp;
	struct uci_section *s;
	char buf[32];
	int n;

	dmuci_get_section_type(UPNP_CFG, "@dm[0]", &tmp);
	if (!tmp || tmp[0] == '\0') {
		dmuci_add_section(UPNP_CFG, "dm", &s);
	}
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "supported_datamodel_version", &v);
	n = atoi(v);
	if (n != UPNP_SUPPORTED_DATAMODEL_VERSION) {
		snprintf(buf, sizeof(buf), "%d", UPNP_SUPPORTED_DATAMODEL_VERSION);
		dmuci_set_value(UPNP_CFG, "@dm[0]", "supported_datamodel_version", buf);
		snprintf(buf, sizeof(buf), "%ld", time(NULL));
		dmuci_set_value(UPNP_CFG, "@dm[0]", "supported_datamodel_epochtime", buf);
	}
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "supported_parameters_version", &v);
	n = atoi(v);
	if (n != UPNP_SUPPORTED_PARAMETERS_VERSION) {
		snprintf(buf, sizeof(buf), "%d", UPNP_SUPPORTED_PARAMETERS_VERSION);
		dmuci_set_value(UPNP_CFG, "@dm[0]", "supported_parameters_version", buf);
		snprintf(buf, sizeof(buf), "%ld", time(NULL));
		dmuci_set_value(UPNP_CFG, "@dm[0]", "supported_parameters_epochtime", buf);
	}
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "current_configuration_version", &v);
	if (*v == '\0') {
		dmuci_set_value(UPNP_CFG, "@dm[0]", "current_configuration_version", "0");
		snprintf(buf, sizeof(buf), "%ld", time(NULL));
		dmuci_set_value(UPNP_CFG, "@dm[0]", "current_configuration_epochtime", buf);
	}
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "attribute_values_version", &v);
	if (*v == '\0') {
		dmuci_set_value(UPNP_CFG, "@dm[0]", "attribute_values_version", "0");
		snprintf(buf, sizeof(buf), "%ld", time(NULL));
		dmuci_set_value(UPNP_CFG, "@dm[0]", "attribute_values_epochtime", buf);
	}

	dmuci_commit();
	return 0;
}

/* ************************************
 * UPNP get supported parameters update
 * ***********************************/

int dm_entry_upnp_get_supported_parameters_update(struct dmctx *dmctx, char **value)
{
	static char csv[128] = "";
	char *v;
	time_t time_value;

	*value = csv;

	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "supported_parameters_epochtime", &v);
	if (v[0] != '0' && v[0] != '\0') {
		time_value = atoi(v);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SS.000Z"];
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S.000Z", localtime(&time_value));
		snprintf(csv, sizeof(csv), "%d,%s", UPNP_SUPPORTED_PARAMETERS_VERSION, s_now);
	}

	return 0;
}

/* ************************************
 * UPNP get supported_datamodel update
 * ***********************************/

int dm_entry_upnp_get_supported_datamodel_update(struct dmctx *dmctx, char **value)
{
	static char csv[128] = "";
	char *v;
	time_t time_value;

	*value = csv;

	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "supported_datamodel_epochtime", &v);
	if (v[0] != '0' && v[0] != '\0') {
		time_value = atoi(v);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SS.000Z"];
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S.000Z", localtime(&time_value));
		snprintf(csv, sizeof(csv), "%d,%s", UPNP_SUPPORTED_DATAMODEL_VERSION, s_now);
	}

	return 0;
}

/* ********************************
 * UPNP get attribute values update
 * ********************************/

int dm_entry_upnp_get_attribute_values_update(struct dmctx *dmctx, char **value)
{
	static char csv[128] = "";
	char *v, *s;
	time_t time_value;

	*value = csv;

	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "attribute_values_epochtime", &v);
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "attribute_values_version", &s);
	if (v[0] != '0' && v[0] != '\0' && s[0] != '\0') {
		time_value = atoi(v);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SS.000Z"];
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S.000Z", localtime(&time_value));
		snprintf(csv, sizeof(csv), "%s,%s", s, s_now);
	}

	return 0;
}

/* ********************************
 * UPNP get configuration update
 * ********************************/

int dm_entry_upnp_get_configuration_update(struct dmctx *dmctx, char **value)
{
	static char csv[128] = "";
	char *v, *s;
	time_t time_value;

	*value = csv;

	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "current_configuration_epochtime", &v);
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "current_configuration_version", &s);
	if (v[0] != '\0' && s[0] != '\0') {
		time_value = atoi(v);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SS.000Z"];
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S.000Z", localtime(&time_value));
		snprintf(csv, sizeof(csv), "%s,%s", s, s_now);
	}

	return 0;
}

/* **************************************
 * UPNP get current configuration version
 * *************************************/

int dm_entry_upnp_get_current_configuration_version(struct dmctx *dmctx, char **value)
{
	dmuci_get_option_value_string(UPNP_CFG, "@dm[0]", "current_configuration_version", value);
	return 0;
}
#endif
/************************/

int dm_entry_restart_services(void)
{
	struct package_change *pc;

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
	struct package_change *pc;

	bbf_uci_revert_bbfdm();

	list_for_each_entry(pc, &head_package_change, list) {
		dmubus_call_set("uci", "revert", UBUS_ARGS{{"config", pc->package, String}}, 1);
	}
	free_all_list_package_change(&head_package_change);

	return 0;
}

#ifdef BBF_TR064
int dm_entry_upnp_restart_services(void)
{
	struct package_change *pc;

	list_for_each_entry(pc, &head_package_change, list) {
		dmubus_call_set("uci", "commit", UBUS_ARGS{{"config", pc->package}}, 1);
	}
	free_all_list_package_change(&head_package_change);

	return 0;
}

int cli_output_dm_upnp_variable_state(struct dmctx *dmctx, int cmd, char *variable)
{
	switch (cmd) {
		case CMD_UPNP_GET_CONFIGURATION_UPDATE:
			fprintf (stdout, "{ \"ConfigurationUpdate\": \"%s\"}\n", variable);
			break;
		case CMD_UPNP_GET_CURRENT_CONFIGURATION_VERSION:
			fprintf (stdout, "{ \"CurrentConfigurationVersion\": \"%s\"}\n", variable);
			break;
		case CMD_UPNP_GET_SUPPORTED_DATA_MODEL_UPDATE:
			fprintf (stdout, "{ \"SupportedDataModelsUpdate\": \"%s\"}\n", variable);
			break;
		case CMD_UPNP_GET_SUPPORTED_PARAMETERS_UPDATE:
			fprintf (stdout, "{ \"SupportedParametersUpdate\": \"%s\"}\n", variable);
			break;
		case CMD_UPNP_GET_ATTRIBUTE_VALUES_UPDATE:
			fprintf (stdout, "{ \"AttributeValuesUpdate\": \"%s\"}\n", variable);
			break;
	}
	return 0;
}
#endif

static int get_stats_folder(const char *path, bool is_json, int *file_count, unsigned long *size, unsigned long *date)
{
	struct stat stats;
	struct dirent *entry;
	DIR *dirp = NULL;
	char buf[264] = {0};
	int filecount = 0;
	unsigned long filesize = 0, filedate = 0;

	if (folder_exists(path)) {
		dirp = opendir(path);
		while ((entry = readdir(dirp)) != NULL) {
			if ((entry->d_type == DT_REG) && (strstr(entry->d_name, is_json ? ".json" : ".so"))) {
				filecount++;
				snprintf(buf, sizeof(buf), "%s/%s", path, entry->d_name);
				if (!stat(buf, &stats)) {
					filesize = (filesize + stats.st_size) / 2;
					filedate = (filedate + stats.st_mtime) / 2;
				}
			}
		}
		if (dirp) closedir(dirp);

		*file_count = filecount;
		*size = filesize;
		*date = filedate;
		return 1;
	}
	return 0;
}

static int check_stats_folder(const char *path, bool is_json)
{
	int file_count = 0;
	unsigned long size = 0, date = 0;
	char buf[128] = {0};

	if (!get_stats_folder(path, is_json, &file_count, &size, &date))
		return 0;

	snprintf(buf, sizeof(buf), "count:%d,sizes:%lu,date:%lu", file_count, size, date);
	if (strcmp(buf, is_json ? json_hash : library_hash)) {
		strcpy(is_json ? json_hash : library_hash, buf);
		return 1;
	}

	return 0;
}

int load_dynamic_arrays(struct dmctx *ctx)
{
	// Load dynamic objects and parameters exposed via a JSON file
	if (check_stats_folder(JSON_FOLDER_PATH, true)) {
		free_json_dynamic_arrays(tEntry181Obj);
		load_json_dynamic_arrays(ctx);
	}

	// Load dynamic objects and parameters exposed via a library
	if (check_stats_folder(LIBRARY_FOLDER_PATH, false)) {
		free_library_dynamic_arrays(tEntry181Obj);
		load_library_dynamic_arrays(ctx);
	}

	return 0;
}

int free_dynamic_arrays(void)
{
	DMOBJ *root = tEntry181Obj;
	DMNODE node = {.current_object = ""};

	free_dm_browse_node_dynamic_object_tree(&node, root);
	free_json_dynamic_arrays(tEntry181Obj);
	free_library_dynamic_arrays(tEntry181Obj);

	return 0;
}
