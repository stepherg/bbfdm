/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicecallcontrol.h"
#include "common.h"
#include "dmentry.h"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_voice_service_line_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? section_name((struct uci_section *)data) : "";
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.!UCI:asterisk/tel_line/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlLineInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "tel_line", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &inst_last, update_instance_alias, 3,
			   p->dmmap_section, "lineinstance", "linealias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlIncomingMapInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &inst_last, update_instance_alias, 3,
			   p->dmmap_section, "clientinstance", "clientalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlOutgoingMapInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &inst_last, update_instance_alias, 3,
			   p->dmmap_section, "clientinstance", "clientalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.!UCI:asterisk/tel_advanced/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlNumberingPlanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "tel_advanced", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "numberingplaninstance", "numberingplanalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.!UCI:asterisk/advanced_features/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlCallingFeaturesSetInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "advanced_features", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "setinstance", "setalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}.!UCI:asterisk/call_filter_rule_incoming/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlCallingFeaturesSetSCREJInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "call_filter_rule_incoming", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(3, dmctx, &inst_last, update_instance_alias, 3,
			   p->dmmap_section, "screjinstance", "screjalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjServicesVoiceServiceCallControlLine(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	TR104_DEBUG("VoiceService.1.CallControl.Line. can't be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlLine(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	TR104_DEBUG("VoiceService.1.CallControl.Line. can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlIncomingMap(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	TR104_DEBUG("VoiceService.1.CallControl.IncomingMap. has a 1:1 mapping to Services.VoiceService."
			"1.SIP.Client. so it can't be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlIncomingMap(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	TR104_DEBUG("VoiceService.1.CallControl.IncomingMap. has a 1:1 mapping to Services.VoiceService."
				"1.SIP.Client. so it can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlOutgoingMap(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	TR104_DEBUG("VoiceService.1.CallControl.OutgoingMap. has a 1:1 mapping to Services.VoiceService."
				"1.SIP.Client. so it can't be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlOutgoingMap(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	TR104_DEBUG("VoiceService.1.CallControl.OutgoingMap. has a 1:1 mapping to Services.VoiceService."
					"1.SIP.Client. so it can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlNumberingPlan(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	TR104_DEBUG("VoiceService.1.CallControl.NumberingPlan. has only one instance so it can't be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlNumberingPlan(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	TR104_DEBUG("VoiceService.1.CallControl.NumberingPlan. has only one instance so it can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlCallingFeaturesSet(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	TR104_DEBUG("VoiceService.1.CallControl.CallingFeatures.Set. has only one instance so it can't be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlCallingFeaturesSet(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	TR104_DEBUG("VoiceService.1.CallControl.CallingFeatures.Set. has only one instance so it can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	char *inst = get_last_instance_bbfdm("dmmap_asterisk", "call_filter_rule_incoming", "screjinstance");
	dmuci_add_section("asterisk", "call_filter_rule_incoming", &s);

	dmuci_add_section_bbfdm("dmmap_asterisk", "call_filter_rule_incoming", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(inst, 2, dmmap, "screjinstance");
	return 0;
}

static int delObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_asterisk", "call_filter_rule_incoming", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("asterisk", "call_filter_rule_incoming", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_asterisk", "call_filter_rule_incoming", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_asterisk", "call_filter_rule_incoming", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ServicesVoiceServiceCallControlLine_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

static int get_ServicesVoiceServiceCallControlLine_CallStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	int line_num = atoi(instance) - 1;
	char line_str[16];

	snprintf(line_str, sizeof(line_str), "%d", line_num);
	dmubus_call("endpt", "status", UBUS_ARGS{{"line", line_str, Integer}}, 1, &res);
	if (res) {
		/*
		 * Convert the status to a value specified in TR-104.
		 *
		 * Note that the current status provided by UBUS "endpt status" can not be mapped to those values
		 * specified in TR-104.
		 *
		 * TODO: the corresponding UBUS RPC will be enhanced in order to provide more TR-104 compliant values
		 */
		char *offhook = dmjson_get_value(res, 1, "offhook");
		*value = *offhook == '1' ? "Connected" : "Idle";
	} else {
		TR104_DEBUG("dmubus_call() failed\n");
	}

	return 0;
}

static int get_ServicesVoiceServiceCallControlLine_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Static";
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.DirectoryNumber!UCI:asterisk/tel_line,@i-1/extension*/
static int get_ServicesVoiceServiceCallControlLine_DirectoryNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "extension", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlLine_DirectoryNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "extension", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.Provider!UCI:asterisk/tel_line,@i-1/sip_account*/
static int get_ServicesVoiceServiceCallControlLine_Provider(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "sip_account", &linker);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cServices%cVoiceService%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_ServicesVoiceServiceCallControlLine_Provider(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char sip_client[64] = "Device.Services.VoiceService.1.SIP.Client.";
	size_t client_len = strlen(sip_client);

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strncmp(value, sip_client, client_len) == 0) {
				/* check linker is available */
				char *linker = NULL;
				adm_entry_get_linker_value(ctx, value, &linker);
				if (linker && *linker) {
					dmuci_set_value_by_section((struct uci_section *)data, "sip_account", linker);
					dmfree(linker);
				}
			}
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.Line!UCI:asterisk/sip_service_provider,@i-1/call_lines*/
static int get_ServicesVoiceServiceCallControlIncomingMap_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "call_lines", &tmp);
	if (tmp && *tmp) {
		char *token = NULL, *saveptr = NULL, *p, buf[512] = { 0, 0 }, linker[16] = {0};

		p = buf;
		for (token = strtok_r(tmp, " ", &saveptr); token != NULL; token = strtok_r(NULL, " ", &saveptr)) {
			snprintf(linker, sizeof(linker), "telline%s", token);
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cServices%cVoiceService%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
			if (*value == NULL)
				continue;
			dmstrappendstr(p, *value);
			dmstrappendchr(p, ',');
		}
		p = p -1;
		dmstrappendend(p);

		if (buf[0] != '\0')
			*value = dmstrdup(buf);
		dmfree(tmp);
	}
	return 0;
}

static int set_ServicesVoiceServiceCallControlIncomingMap_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dup = NULL, *token = NULL, *saveptr = NULL, *p, buf[16] = { 0, 0 };
	char call_line[64] = "Device.Services.VoiceService.1.CallControl.Line.";
	size_t line_len = strlen(call_line);

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			if ((dup = dmstrdup(value)) == NULL)
				return FAULT_9002;
			dmfree(dup);

			break;
		case VALUESET:
			p = buf;
			for (token = strtok_r(value, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {

				if (strncmp(token, call_line, line_len) == 0) {
					/* check linker is available */
					char *linker = NULL;
					adm_entry_get_linker_value(ctx, token, &linker);
					if (!linker || linker[0] == '\0')
						continue;

					dmstrappendstr(p, linker+7);
					dmstrappendchr(p, ' ');
				}
			}
			p = p -1;
			dmstrappendend(p);

			if (buf[0] != '\0')
				dmuci_set_value_by_section((struct uci_section *)data, "call_lines", buf);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.CLIPNoScreeningNumber!UCI:asterisk/sip_service_provider,@i-1/displayname*/
static int get_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "displayname", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "displayname", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.InterDigitTimerStd!UCI:asterisk/tel_advanced,tel_options/interdigit*/
static int get_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "tel_options", "interdigit", "15000");
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","50000"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "tel_options", "interdigit", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.CallWaitingEnable!UCI:asterisk/advanced_features,call_features/callwaiting_enabled*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "call_features", "callwaiting_enabled", "1");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("asterisk", "call_features", "callwaiting_enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.CallForwardUnconditionalEnable!UCI:asterisk/advanced_features,call_features/callforward_enabled*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "call_features", "callforward_enabled", "1");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("asterisk", "call_features", "callforward_enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.SCREJ.{i}.CallingNumber!UCI:asterisk/call_filter_rule_incoming,@i-1/extension*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "extension", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value(TR104_UCI_PACKAGE, "call_filter0", "block_incoming", "1");
			dmuci_set_value_by_section((struct uci_section *)data, "owner", "call_filter0");
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", "1");
			dmuci_set_value_by_section((struct uci_section *)data, "extension", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CallControl. *** */
DMOBJ tServicesVoiceServiceCallControlObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Line", &DMWRITE, addObjServicesVoiceServiceCallControlLine, delObjServicesVoiceServiceCallControlLine, NULL, browseServicesVoiceServiceCallControlLineInst, NULL, NULL, tServicesVoiceServiceCallControlLineParams, get_voice_service_line_linker, BBFDM_BOTH, LIST_KEY{"DirectoryNumber", "Alias", NULL}},
{"IncomingMap", &DMWRITE, addObjServicesVoiceServiceCallControlIncomingMap, delObjServicesVoiceServiceCallControlIncomingMap, NULL, browseServicesVoiceServiceCallControlIncomingMapInst, NULL, NULL, tServicesVoiceServiceCallControlIncomingMapParams, NULL, BBFDM_BOTH, LIST_KEY{"Line", "Extension", "Alias", NULL}},
{"OutgoingMap", &DMWRITE, addObjServicesVoiceServiceCallControlOutgoingMap, delObjServicesVoiceServiceCallControlOutgoingMap, NULL, browseServicesVoiceServiceCallControlOutgoingMapInst, NULL, NULL, tServicesVoiceServiceCallControlOutgoingMapParams, NULL, BBFDM_BOTH, LIST_KEY{"Extension", "Line", "Alias", NULL}},
{"NumberingPlan", &DMWRITE, addObjServicesVoiceServiceCallControlNumberingPlan, delObjServicesVoiceServiceCallControlNumberingPlan, NULL, browseServicesVoiceServiceCallControlNumberingPlanInst, NULL, NULL, tServicesVoiceServiceCallControlNumberingPlanParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"CallingFeatures", &DMREAD, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallControlCallingFeaturesObj, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.Line.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlLineParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Status, NULL, BBFDM_BOTH},
{"CallStatus", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlLine_CallStatus, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Origin, NULL, BBFDM_BOTH},
{"DirectoryNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlLine_DirectoryNumber, set_ServicesVoiceServiceCallControlLine_DirectoryNumber, BBFDM_BOTH},
{"Provider", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Provider, set_ServicesVoiceServiceCallControlLine_Provider, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlIncomingMapParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Line", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlIncomingMap_Line, set_ServicesVoiceServiceCallControlIncomingMap_Line, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlOutgoingMapParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CLIPNoScreeningNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber, set_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.NumberingPlan. *** */
DMLEAF tServicesVoiceServiceCallControlNumberingPlanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterDigitTimerStd", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd, set_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures. *** */
DMOBJ tServicesVoiceServiceCallControlCallingFeaturesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Set", &DMWRITE, addObjServicesVoiceServiceCallControlCallingFeaturesSet, delObjServicesVoiceServiceCallControlCallingFeaturesSet, NULL, browseServicesVoiceServiceCallControlCallingFeaturesSetInst, NULL, tServicesVoiceServiceCallControlCallingFeaturesSetObj, tServicesVoiceServiceCallControlCallingFeaturesSetParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}. *** */
DMOBJ tServicesVoiceServiceCallControlCallingFeaturesSetObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"SCREJ", &DMWRITE, addObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ, delObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ, NULL, browseServicesVoiceServiceCallControlCallingFeaturesSetSCREJInst, NULL, NULL, tServicesVoiceServiceCallControlCallingFeaturesSetSCREJParams, NULL, BBFDM_BOTH, LIST_KEY{"CallingNumber", "Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceCallControlCallingFeaturesSetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CallWaitingEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable, BBFDM_BOTH},
{"CallForwardUnconditionalEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlCallingFeaturesSetSCREJParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CallingNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber, set_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber, BBFDM_BOTH},
{0}
};

