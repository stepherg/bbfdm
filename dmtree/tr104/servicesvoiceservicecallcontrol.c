/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservice.h"
#include "servicesvoiceservicecallcontrol.h"
#include "common.h"
#include "dmentry.h"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_voice_service_line_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? section_name(((struct dmmap_dup *)data)->config_section) : "";
	return 0;
}

static int get_voice_service_callcontrol_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
        *linker = data ? section_name(((struct dmmap_dup *)data)->config_section) : "";
        return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static int set_CallControl_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Services.VoiceService.1.CallControl.Line.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "line", linker ? linker : "");
			break;
	}
	return 0;
}

static int set_CallControl_Group(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Services.VoiceService.1.CallControl.Group.", NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "extension", linker ? linker : "");
			break;
	}
	return 0;
}

static int set_CallControl_CallingFeaturesSet(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Services.VoiceService.1.CallControl.CallingFeatures.Set.", NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "calling_features", linker ? linker : "");
			break;
	}
	return 0;
}

static int set_SIP_Client(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Services.VoiceService.1.SIP.Client.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "provider", linker ? linker : "");
			break;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.!UCI:asterisk/line/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlLineInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "line", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "lineinstance", "linealias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.!UCI:asterisk/incoming_map/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlIncomingMapInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "incoming_map", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "incomingmapinstance", "incomingmapalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;

}
/*#Device.Services.VoiceService.{i}.CallControl.Group.{i}.!UCI:asterisk/group/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlGroupInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "group", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "groupinstance", "groupalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;

}
/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.!UCI:asterisk/extension/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlExtensionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "extension", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "extensioninstance", "extensionalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}
/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.!UCI:asterisk/outgoing_map/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlOutgoingMapInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "outgoing_map", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "outgoingmapinstance", "outgoingmapalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;

}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.!UCI:asterisk/numberingplan/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlNumberingPlanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "numberingplan", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "numberingplaninstance", "numberingplanalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.PrefixInfo!UCI:asterisk/prefixinfo/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlNumberingPlanPrefixInfo(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "prefixinfo", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
                char *type = NULL;
                dmuci_get_value_by_section_string(p->config_section, "facilityaction", &type);
                if( *type ){
                        if (!dm_validate_string(type, -1, -1, FacilityAction, NULL))
		                inst = handle_instance(dmctx, parent_node, p->dmmap_section, "prefixinfoinstance", "prefixinfoalias");
                }
                else
                        inst = handle_instance(dmctx, parent_node, p->dmmap_section, "prefixinfoinstance", "prefixinfoalias");

                if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
                        break;

                if (type && *type)
                        dmfree(type);
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.!UCI:asterisk/calling_features/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlCallingFeaturesSetInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "calling_features", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "setinstance", "setalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}.!UCI:asterisk/call_filter_rule_incoming/dmmap_asterisk*/
static int browseServicesVoiceServiceCallControlCallingFeaturesSetSCREJInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "call_filter_rule_incoming", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "screjinstance", "screjalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
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
	struct uci_section *dmmap = NULL;
	char new_sec_name[16];

	snprintf(new_sec_name, sizeof(new_sec_name), "line%s", *instance);

	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "line");

	dmuci_add_section_bbfdm("dmmap_asterisk", "line", &dmmap);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "enable", "0");
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name) ;
	dmuci_set_value_by_section(dmmap, "lineinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceCallControlLine(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
	case DEL_ALL:
		uci_foreach_sections_safe("asterisk", "line", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_asterisk", "line", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjServicesVoiceServiceCallControlIncomingMap(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL;
	char new_sec_name[32];

	snprintf(new_sec_name, sizeof(new_sec_name), "incoming_map%s", *instance);

	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "incoming_map");

	dmuci_add_section_bbfdm("dmmap_asterisk", "incoming_map", &dmmap);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "enable", "0");
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name) ;
	dmuci_set_value_by_section(dmmap, "incomingmapinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceCallControlIncomingMap(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
	case DEL_ALL:
		uci_foreach_sections_safe("asterisk", "incoming_map", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_asterisk", "incoming_map", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjServicesVoiceServiceCallControlOutgoingMap(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL;
	char new_sec_name[32];

	snprintf(new_sec_name, sizeof(new_sec_name), "outgoing_map%s", *instance);

	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "outgoing_map");

	dmuci_add_section_bbfdm("dmmap_asterisk", "outgoing_map", &dmmap);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "enable", "0");
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name) ;
	dmuci_set_value_by_section(dmmap, "outgoingmapinstance", *instance);
        return 0;
}

static int delObjServicesVoiceServiceCallControlOutgoingMap(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
	case DEL_ALL:
		uci_foreach_sections_safe("asterisk", "outgoing_map", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_asterisk", "outgoing_map", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjServicesVoiceServiceCallControlGroup(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL;
	char new_sec_name[16];

	snprintf(new_sec_name, sizeof(new_sec_name), "group%s", *instance);

	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "group");

	dmuci_add_section_bbfdm("dmmap_asterisk", "group", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name) ;
	dmuci_set_value_by_section(dmmap, "groupinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceCallControlGroup(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
	case DEL_ALL:
		uci_foreach_sections_safe("asterisk", "group", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_asterisk", "group", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}
static int addObjServicesVoiceServiceCallControlExtension(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	BBF_DEBUG("VoiceService.1.CallControl.Extension. has multiple instance, but they can NOT added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlExtension(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	BBF_DEBUG("VoiceService.1.CallControl.Extension. has multiple instance, but they can NOT be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlNumberingPlan(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	BBF_DEBUG("VoiceService.1.CallControl.NumberingPlan. has only one instance so it can't be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlNumberingPlan(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	BBF_DEBUG("VoiceService.1.CallControl.NumberingPlan. has only one instance so it can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlNumberingPlanPrefixInfo(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	BBF_DEBUG("VoiceService.1.CallControl.NumberingPlan.PrefixInfo. cant be added or deleted\n");
	return 0;
}

static int delObjServicesVoiceServiceCallControlNumberingPlanPrefixInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	BBF_DEBUG("VoiceService.1.CallControl.NumberingPlan.PrefixInfo. can't be added or deleted\n");
	return 0;
}

static int addObjServicesVoiceServiceCallControlCallingFeaturesSet(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL;
	char new_sec_name[16];

	snprintf(new_sec_name, sizeof(new_sec_name), "set%s", *instance);

	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "set");

	dmuci_add_section_bbfdm("dmmap_asterisk", "calling_features", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name) ;
	dmuci_set_value_by_section(dmmap, "setinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceCallControlCallingFeaturesSet(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("asterisk", "calling_features", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_asterisk", "calling_features", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	dmuci_add_section("asterisk", "call_filter_rule_incoming", &s);

	dmuci_add_section_bbfdm("dmmap_asterisk", "call_filter_rule_incoming", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "screjinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("asterisk", "call_filter_rule_incoming", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_asterisk", "call_filter_rule_incoming", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
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

/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.CallStatus!UBUS:asterisk/call_status/line,@i-1/call_status*/
static int get_ServicesVoiceServiceCallControlLine_CallStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char line_str[16];

	snprintf(line_str, sizeof(line_str), "%d", instance ? atoi(instance) - 1 : 0);
	dmubus_call("asterisk", "call_status", UBUS_ARGS{{"line", line_str, Integer}}, 1, &res);
	if (res) {
		*value = dmjson_get_value(res, 1, "call_status");
	} else {
		BBF_DEBUG("dmubus_call() failed\n");
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
	char *sip_account = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "sip_account", &sip_account);
	dmuci_get_option_value_string("asterisk", sip_account, "directory_number", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlLine_DirectoryNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *sip_account = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "sip_account", &sip_account);
			dmuci_set_value("asterisk", sip_account, "directory_number", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.Provider!UCI:asterisk/line,@i-1/provider*/
static int get_ServicesVoiceServiceCallControlLine_Provider(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "provider", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlLine_Provider(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_SIP_Client(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.CallingFeatures!UCI:asterisk/line,@i-1/calling_features*/
static int get_ServicesVoiceServiceCallControlLine_CallingFeatures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "calling_features", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlLine_CallingFeatures(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_CallControl_CallingFeaturesSet(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.Line.{i}.Enable!UCI:asterisk/line,@i-1/enable*/
static int get_ServicesVoiceServiceCallControlLine_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlLine_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.Line!UCI:asterisk/incoming_map,@i-1/line*/
static int get_ServicesVoiceServiceCallControlIncomingMap_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "line", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlIncomingMap_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_CallControl_Line(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.Line!UCI:asterisk/incoming_map,@i-1/enable*/
static int get_ServicesVoiceServiceCallControlIncomingMap_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}
static int set_ServicesVoiceServiceCallControlIncomingMap_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}
/*#Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.Line!UCI:asterisk/incoming_map,@i-1/extension*/
static int get_ServicesVoiceServiceCallControlIncomingMap_Extension(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "extension", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlIncomingMap_Extension(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_CallControl_Group(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.CLIPNoScreeningNumber!UCI:asterisk/sip_service_provider,@i-1/displayname*/
static int get_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "displayname", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "displayname", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.Line!UCI:asterisk/outgoing_map,@i-1/enable*/
static int get_ServicesVoiceServiceCallControlOutgoingMap_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlOutgoingMap_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.Line!UCI:asterisk/outgoing_map,@i-1/line*/
static int get_ServicesVoiceServiceCallControlOutgoingMap_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "line", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlOutgoingMap_Line(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_CallControl_Line(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.Extension!UCI:asterisk/incoming_map,@i-1/extension*/
static int get_ServicesVoiceServiceCallControlOutgoingMap_Extension(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "extension", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlOutgoingMap_Extension(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_CallControl_Group(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.Group.{i}.Extensions!UCI:asterisk/group,@i-1/extensions*/
static int get_ServicesVoiceServiceCallControlGroup_Extensions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *extensions_list = NULL;
	char buf[512] = {0};

	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "extensions", &extensions_list);

	if (extensions_list != NULL) {
		struct uci_element *e = NULL;
		unsigned pos = 0;

		buf[0] = 0;
		uci_foreach_element(extensions_list, e) {
			char *linker = NULL;

			adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", e->name, &linker);
			if (linker && *linker)
				pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", linker);
		}

		if (pos)
			buf[pos - 1] = 0;
	}

	*value = (buf[0] != '\0') ? dmstrdup(buf) : "";
	return 0;
}

static int set_ServicesVoiceServiceCallControlGroup_Extensions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Services.VoiceService.1.CallControl.Extension.", NULL};
	char *pch = NULL, *spch = NULL;
	char value_buf[512] = {0};

	DM_STRNCPY(value_buf, value, sizeof(value_buf));

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value_buf, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;

			for (pch = strtok_r(value_buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

				if (dm_entry_validate_allowed_objects(ctx, pch, allowed_objects))
					return FAULT_9007;
			}

			break;
		case VALUESET:
			// Empty the existing code list first
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "extensions", "");
			for (pch = strtok_r(value_buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
				char *linker = NULL;

				adm_entry_get_linker_value(ctx, pch, &linker);
				dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "extensions", linker);
			}
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.Enable!UCI:asterisk/extension,@i-1/enable*/
static int get_ServicesVoiceServiceCallControlExtension_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}
/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.ExtensionNumber!UCI:asterisk/extension,@i-1/extension_number*/
static int get_ServicesVoiceServiceCallControlExtension_ExtensionNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "extension_number", "");
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_ExtensionNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "extension_number", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.Provider!UCI:asterisk/extension,@i-1/provider*/
static int get_ServicesVoiceServiceCallControlExtension_Provider(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *provider_string = NULL;
	char buf[512] = {0};
	char *type = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "type", &type);
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "provider", &provider_string);
	if (strlen(provider_string)) {
		unsigned pos = 0;
		char *ptr = NULL, *spch = NULL;
		buf[0] = 0;
		char *provider = dmstrdup(provider_string);
		ptr = strtok_r(provider, ",", &spch);
		while (ptr != NULL) {
			char *linker = NULL;

			adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", !strcmp(type, "fxs") ? section_name(((struct dmmap_dup *)data)->config_section) : ptr, &linker);
			if (linker && *linker)
				pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", linker);

			ptr = strtok_r(NULL, ",", &spch);
		}

		if (pos)
			buf[pos - 1] = 0;
	}

	*value = (buf[0] != '\0') ? dmstrdup(buf) : "";
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_Provider(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char fxs_extension[64] = "Device.Services.VoiceService.1.POTS.FXS.";
	char dect_extension[64] = "Device.Services.VoiceService.1.DECT.Portable.";
	size_t fxs_len = strlen(fxs_extension);
	size_t dect_len = strlen(dect_extension);
	char *pch = NULL, *spch = NULL;
	char value_buf[512] = {0};
	char *type;
	char buf[512] = {0};
	unsigned pos = 0;

	DM_STRNCPY(value_buf, value, sizeof(value_buf));

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value_buf, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (value_buf[0] == 0)
				break;

			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "type", &type);

			for (pch = strtok_r(value_buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
				char *linker = NULL;

				if (strncmp(pch, !strcmp(type, "fxs") ? fxs_extension : dect_extension, !strcmp(type, "fxs") ? fxs_len : dect_len) != 0)
					return FAULT_9007;

				adm_entry_get_linker_value(ctx, pch, &linker);
				if (linker == NULL)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			// Empty the existing list first
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "provider", "");
			for (pch = strtok_r(value_buf, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
				char *linker = NULL;

				if (pos != 0)
					pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s", ",");

				adm_entry_get_linker_value(ctx, pch, &linker);
				if(!strcmp(linker, "extension3"))
					pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s", "fxs1");
				else if(!strcmp(linker, "extension4"))
					pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s", "fxs2");
				else
					pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s", linker);
			}
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "provider", buf);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.CallingFeatures!UCI:asterisk/extension,@i-1/calling_features*/
static int get_ServicesVoiceServiceCallControlExtension_CallingFeatures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "calling_features", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_CallingFeatures(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_CallControl_CallingFeaturesSet(refparam, ctx, data, instance, value, action);
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.VoiceMail!UCI:asterisk/extension,@i-1/voice_mail*/
static int get_ServicesVoiceServiceCallControlExtension_VoiceMail(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "voice_mail", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_VoiceMail(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "voice_mail", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.Name!UCI:asterisk/extension,@i-1/name*/
static int get_ServicesVoiceServiceCallControlExtension_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.CallStatus!UBUS:asterisk/call_status/extension,@i-1/call_status*/
static int get_ServicesVoiceServiceCallControlExtension_CallStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char ext_str[16];

	snprintf(ext_str, sizeof(ext_str), "%d", instance ? atoi(instance) - 1 : 0);
	dmubus_call("asterisk", "call_status", UBUS_ARGS{{"extension", ext_str, Integer}}, 1, &res);
	if (res) {
		*value = dmjson_get_value(res, 1, "call_status");
	} else {
		BBF_DEBUG("dmubus_call() failed\n");
	}

	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.InterDigitTimerStd!UCI:asterisk/numberingplan/interdigitstdmsec*/
static int get_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "numberingplan", "interdigitstdmsec", "15000");
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
			dmuci_set_value("asterisk", "numberingplan", "interdigitstdmsec", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.InterDigitTimerOpen!UCI:asterisk/numberingplan/interdigitopenmsec*/
static int get_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerOpen(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "numberingplan", "interdigitopenmsec", "3000");
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerOpen(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","50000"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "numberingplan", "interdigitopenmsec", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.MinimumNumberOfDigits!UCI:asterisk/numberingplan/minimumnumberidigits*/
static int get_ServicesVoiceServiceCallControlNumberingPlan_MinimumNumberOfDigits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "numberingplan", "minimumnumberdigits", "1");
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlan_MinimumNumberOfDigits(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","32"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "numberingplan", "minimumnumberdigits", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.MaximumNumberOfDigits!UCI:asterisk/numberingplan/maxnumdigits*/
static int get_ServicesVoiceServiceCallControlNumberingPlan_MaximumNumberOfDigits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "numberingplan", "maxnumdigits", "15");
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlan_MaximumNumberOfDigits(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","32"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "numberingplan", "maxnumdigits", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.PrefixInfo.{i}.Enable!UCI:asterisk/prefixinfo,@i-1/prefixenable*/
static int get_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "prefixenable", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
	        case VALUESET:
		        string_to_bool(value, &b);
		        dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "prefixenable", b ? "1" : "0");
		        break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.PrefixInfo.{i}.PrefixRange!UCI:asterisk/prefixrange,@i-1/prefixrange*/
static int get_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_PrefixRange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "prefixrange", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_PrefixRange(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "prefixrange", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.PrefixInfo.{i}.FacilityAction!UCI:asterisk/prefixinfo,@i-1/facilityaction*/
static int get_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_FacilityAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "facilityaction", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_FacilityAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
                        if (dm_validate_string(value, -1, -1, FacilityAction, NULL))
                                return FAULT_9007;
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "facilityaction", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallWaitingEnable!UCI:asterisk/calling_features/call_waiting_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "call_waiting_enable", value);
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
                        dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "call_waiting_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallerIDEnable!UCI:asterisk/calling_features/caller_id_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdEnable (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "caller_id_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "caller_id_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallerIDNameEnable!UCI:asterisk/calling_features/caller_name_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdNameEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "caller_name_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdNameEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "caller_name_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallForwardOnBusyEnable!UCI:asterisk/calling_features/call_forward_on_busy*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnBusyEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "call_forward_on_busy", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnBusyEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "call_forward_on_busy", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallForwardUnconditionalEnable!UCI:asterisk/advanced_features,call_features/call_forward_unconditional*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "call_forward_unconditional", value);
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
            dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "call_forward_unconditional", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallForwardOnNoAnswerEnable!UCI:asterisk/calling_features/call_forward_on_no_answer*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnNoAnswerEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "call_forward_on_no_answer", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnNoAnswerEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "call_forward_on_no_answer", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.MWIEnable!UCI:asterisk/calling_features/mwi_enable*/
static int  get_ServicesVoiceServiceCallControlCallingFeaturesSet_MWIEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "mwi_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_MWIEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "mwi_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.AnonymousCallEnable!UCI:asterisk/calling_features/anonymous_call_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_AnonymousCallEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "anonymous_call_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_AnonymousCallEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "anonymous_call_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.DoNotDisturbEnable!UCI:asterisk/calling_features/dnd_enable*/
static int  get_ServicesVoiceServiceCallControlCallingFeaturesSet_DoNotDisturbEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dnd_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_DoNotDisturbEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dnd_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.VoiceMailEnable!UCI:asterisk/calling_features/voice_mail_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_VoiceMailEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "voice_mail_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_VoiceMailEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "voice_mail_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.RepeatDialEnable!UCI:asterisk/calling_features/redial_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_RepeatDialEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "redial_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_RepeatDialEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "redial_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CCBSEnable!UCI:asterisk/calling_features/ccbs_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CCBSEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ccbs_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CCBSEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ccbs_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.SCREJ.{i}.CallingNumber!UCI:asterisk/call_filter_rule_incoming,@i-1/extension*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "extension", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value(TR104_UCI_PACKAGE, "call_filter0", "block_incoming", "1");
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "owner", "call_filter0");
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", "1");
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "extension", value);
			break;
	}
	return 0;
}

/*Get Alias -  #Device.Services.VoiceService.{i}.CallControl.Line.{i}.*/
static int get_ServicesVoiceServiceCallControlLine_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "linealias");
}

/*Set Alias - #Device.Services.VoiceService.{i}.CallControl.Line.{i}.*/
static int set_ServicesVoiceServiceCallControlLine_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "linealias");
}

/*Get Alias - #Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.Alias*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "setalias");
}

/*Set Alias - #Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.Alias*/
static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "setalias");
}

/*Get Alias -  #Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}.*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "screjalias");
}

/*Set Alias - #Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}.*/
static int set_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "screjalias");
}

/*Get Alias -  #Device.Services.VoiceService.{i}.CallControl.NumberingPlan.*/
static int get_ServicesVoiceServiceCallControlNumberingPlan_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "numberingplanalias");
}

/*Set Alias - #Device.Services.VoiceService.{i}.CallControl.NumberingPlan.*/
static int set_ServicesVoiceServiceCallControlNumberingPlan_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "numberingplanalias");
}


/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CallControl. *** */
DMOBJ tServicesVoiceServiceCallControlObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Line", &DMWRITE, addObjServicesVoiceServiceCallControlLine, delObjServicesVoiceServiceCallControlLine, NULL, browseServicesVoiceServiceCallControlLineInst, NULL, NULL, NULL, tServicesVoiceServiceCallControlLineParams, get_voice_service_line_linker, BBFDM_BOTH, LIST_KEY{"DirectoryNumber", "Alias", NULL}},
{"IncomingMap", &DMWRITE, addObjServicesVoiceServiceCallControlIncomingMap, delObjServicesVoiceServiceCallControlIncomingMap, NULL, browseServicesVoiceServiceCallControlIncomingMapInst, NULL, NULL, NULL, tServicesVoiceServiceCallControlIncomingMapParams, get_voice_service_callcontrol_linker, BBFDM_BOTH, LIST_KEY{"Line", "Extension", "Alias", NULL}},
{"OutgoingMap", &DMWRITE, addObjServicesVoiceServiceCallControlOutgoingMap, delObjServicesVoiceServiceCallControlOutgoingMap, NULL, browseServicesVoiceServiceCallControlOutgoingMapInst, NULL, NULL, NULL, tServicesVoiceServiceCallControlOutgoingMapParams, get_voice_service_callcontrol_linker, BBFDM_BOTH, LIST_KEY{"Extension", "Line", "Alias", NULL}},
{"NumberingPlan", &DMWRITE, addObjServicesVoiceServiceCallControlNumberingPlan, delObjServicesVoiceServiceCallControlNumberingPlan, NULL, browseServicesVoiceServiceCallControlNumberingPlanInst, NULL, NULL, tServicesVoiceServiceCallControlNumberingPlanObj, tServicesVoiceServiceCallControlNumberingPlanParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"CallingFeatures", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallControlCallingFeaturesObj, NULL, NULL, BBFDM_BOTH},
{"Group", &DMWRITE, addObjServicesVoiceServiceCallControlGroup, delObjServicesVoiceServiceCallControlGroup, NULL, browseServicesVoiceServiceCallControlGroupInst, NULL, NULL, NULL, tServicesVoiceServiceCallControlGroupParams, get_voice_service_callcontrol_linker, BBFDM_BOTH},
{"Extension", &DMWRITE, addObjServicesVoiceServiceCallControlExtension, delObjServicesVoiceServiceCallControlExtension, NULL, browseServicesVoiceServiceCallControlExtensionInst, NULL, NULL, NULL, tServicesVoiceServiceCallControlExtensionParams, get_voice_service_callcontrol_linker, BBFDM_BOTH, LIST_KEY{"ExtensionNumber", NULL}},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.Line.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlLineParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlLine_Enable, set_ServicesVoiceServiceCallControlLine_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Status, NULL, BBFDM_BOTH},
{"CallStatus", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlLine_CallStatus, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Origin, NULL, BBFDM_BOTH},
{"DirectoryNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlLine_DirectoryNumber, set_ServicesVoiceServiceCallControlLine_DirectoryNumber, BBFDM_BOTH},
{"Provider", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Provider, set_ServicesVoiceServiceCallControlLine_Provider, BBFDM_BOTH},
{"CallingFeatures", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlLine_CallingFeatures, set_ServicesVoiceServiceCallControlLine_CallingFeatures, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlLine_Alias, set_ServicesVoiceServiceCallControlLine_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlIncomingMapParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Line", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlIncomingMap_Line, set_ServicesVoiceServiceCallControlIncomingMap_Line, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlIncomingMap_Enable, set_ServicesVoiceServiceCallControlIncomingMap_Enable, BBFDM_BOTH},
{"Extension", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlIncomingMap_Extension, set_ServicesVoiceServiceCallControlIncomingMap_Extension, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlOutgoingMapParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CLIPNoScreeningNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber, set_ServicesVoiceServiceCallControlOutgoingMap_CLIPNoScreeningNumber, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlOutgoingMap_Enable, set_ServicesVoiceServiceCallControlOutgoingMap_Enable, BBFDM_BOTH},
{"Line", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlOutgoingMap_Line, set_ServicesVoiceServiceCallControlOutgoingMap_Line, BBFDM_BOTH},
{"Extension", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlOutgoingMap_Extension, set_ServicesVoiceServiceCallControlOutgoingMap_Extension, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.Group.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlGroupParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Extensions", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlGroup_Extensions, set_ServicesVoiceServiceCallControlGroup_Extensions, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.Extension.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlExtensionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlExtension_Enable, set_ServicesVoiceServiceCallControlExtension_Enable, BBFDM_BOTH},
{"ExtensionNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_ExtensionNumber, set_ServicesVoiceServiceCallControlExtension_ExtensionNumber, BBFDM_BOTH},
{"Provider", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_Provider, set_ServicesVoiceServiceCallControlExtension_Provider, BBFDM_BOTH},
{"CallingFeatures", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_CallingFeatures, set_ServicesVoiceServiceCallControlExtension_CallingFeatures, BBFDM_BOTH},
{"VoiceMail", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_VoiceMail, set_ServicesVoiceServiceCallControlExtension_VoiceMail, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_Name, set_ServicesVoiceServiceCallControlExtension_Name, BBFDM_BOTH},
{"CallStatus", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_CallStatus, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.NumberingPlan. *** */
DMOBJ tServicesVoiceServiceCallControlNumberingPlanObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PrefixInfo", &DMWRITE, addObjServicesVoiceServiceCallControlNumberingPlanPrefixInfo, delObjServicesVoiceServiceCallControlNumberingPlanPrefixInfo, NULL, browseServicesVoiceServiceCallControlNumberingPlanPrefixInfo, NULL, NULL, NULL, tServicesVoiceServiceCallControlNumberingPlanPrefixInfoParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceCallControlNumberingPlanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterDigitTimerStd", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd, set_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerStd, BBFDM_BOTH},
{"InterDigitTimerOpen", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerOpen, set_ServicesVoiceServiceCallControlNumberingPlan_InterDigitTimerOpen, BBFDM_BOTH},
{"MinimumNumberOfDigits", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceCallControlNumberingPlan_MinimumNumberOfDigits, set_ServicesVoiceServiceCallControlNumberingPlan_MinimumNumberOfDigits, BBFDM_BOTH},
{"MaximumNumberOfDigits", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceCallControlNumberingPlan_MaximumNumberOfDigits, set_ServicesVoiceServiceCallControlNumberingPlan_MaximumNumberOfDigits, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlNumberingPlan_Alias, set_ServicesVoiceServiceCallControlNumberingPlan_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.PrefixInfo. *** */
DMLEAF tServicesVoiceServiceCallControlNumberingPlanPrefixInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_Enable, set_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_Enable, BBFDM_BOTH},
{"PrefixRange", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_PrefixRange, set_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_PrefixRange, BBFDM_BOTH},
{"FacilityAction", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_FacilityAction, set_ServicesVoiceServiceCallControlNumberingPlanPrefixInfo_FacilityAction, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures. *** */
DMOBJ tServicesVoiceServiceCallControlCallingFeaturesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Set", &DMWRITE, addObjServicesVoiceServiceCallControlCallingFeaturesSet, delObjServicesVoiceServiceCallControlCallingFeaturesSet, NULL, browseServicesVoiceServiceCallControlCallingFeaturesSetInst, NULL, NULL, tServicesVoiceServiceCallControlCallingFeaturesSetObj, tServicesVoiceServiceCallControlCallingFeaturesSetParams, get_voice_service_callcontrol_linker, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}. *** */
DMOBJ tServicesVoiceServiceCallControlCallingFeaturesSetObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"SCREJ", &DMWRITE, addObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ, delObjServicesVoiceServiceCallControlCallingFeaturesSetSCREJ, NULL, browseServicesVoiceServiceCallControlCallingFeaturesSetSCREJInst, NULL, NULL, NULL, tServicesVoiceServiceCallControlCallingFeaturesSetSCREJParams, NULL, BBFDM_BOTH, LIST_KEY{"CallingNumber", "Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceCallControlCallingFeaturesSetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CallWaitingEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallWaitingEnable, BBFDM_BOTH},
{"CallForwardUnconditionalEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardUnconditionalEnable, BBFDM_BOTH},
{"CallerIDEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdEnable, BBFDM_BOTH},
{"CallerIDNameEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdNameEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallerIdNameEnable, BBFDM_BOTH},
{"CallForwardOnBusyEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnBusyEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnBusyEnable, BBFDM_BOTH},
{"CallForwardOnNoAnswerEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnNoAnswerEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallForwardOnNoAnswerEnable, BBFDM_BOTH},
{"MWIEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_MWIEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_MWIEnable, BBFDM_BOTH},
{"AnonymousCallEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_AnonymousCallEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_AnonymousCallEnable, BBFDM_BOTH},
{"DoNotDisturbEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_DoNotDisturbEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_DoNotDisturbEnable, BBFDM_BOTH},
{"VoiceMailEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_VoiceMailEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_VoiceMailEnable, BBFDM_BOTH},
{"RepeatDialEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_RepeatDialEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_RepeatDialEnable, BBFDM_BOTH},
{"CCBSEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CCBSEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CCBSEnable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_Alias, set_ServicesVoiceServiceCallControlCallingFeaturesSet_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}. *** */
DMLEAF tServicesVoiceServiceCallControlCallingFeaturesSetSCREJParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CallingNumber", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber, set_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_CallingNumber, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_Alias, set_ServicesVoiceServiceCallControlCallingFeaturesSetSCREJ_Alias, BBFDM_BOTH},
{0}
};
