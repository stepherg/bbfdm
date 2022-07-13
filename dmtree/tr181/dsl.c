/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: AMIN Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dsl.h"

struct dsl_line_args
{
	struct uci_section *line_sec;
	char *id;
};

struct dsl_channel_args
{
	struct uci_section *channel_sec;
	char *id;
};

/**************************************************************************
* LINKER
***************************************************************************/
static int get_dsl_line_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct dsl_line_args *)data)->id) {
		dmasprintf(linker, "line_%s", ((struct dsl_line_args *)data)->id);
		return 0;
	}
	*linker = "" ;
	return 0;
}

static int get_dsl_channel_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (instance) {
		dmasprintf(linker, "dsl_channel_%s", instance);
		return 0;
	}
	*linker = "" ;
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_dsl_line(struct dsl_line_args *args, struct uci_section *s)
{
	args->line_sec = s;
	return 0;
}

static inline int init_dsl_channel(struct dsl_channel_args *args, struct uci_section *s)
{
	args->channel_sec = s;
	return 0;
}

/*************************************************************/
static struct uci_section *update_create_dmmap_dsl_line(char *curr_id)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "dsl_line", "id", curr_id, s) {
		return s;
	}
	if (!s) {
		char instance[16];

		snprintf(instance, sizeof(instance), "%ld", DM_STRTOL(curr_id));
		dmuci_add_section_bbfdm("dmmap", "dsl_line", &s);
		dmuci_set_value_by_section_bbfdm(s, "id", curr_id);
		dmuci_set_value_by_section_bbfdm(s, "dsl_line_instance", instance);
	}
	return s;
}

static struct uci_section *update_create_dmmap_dsl_channel(char *curr_id)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "dsl_channel", "id", curr_id, s) {
		return s;
	}
	if (!s) {
		char instance[16];

		snprintf(instance, sizeof(instance), "%ld", DM_STRTOL(curr_id));
		dmuci_add_section_bbfdm("dmmap", "dsl_channel", &s);
		dmuci_set_value_by_section_bbfdm(s, "id", curr_id);
		dmuci_set_value_by_section_bbfdm(s, "dsl_channel_instance", instance);
	}
	return s;
}
/*************************************************************
* ENTRY METHOD
*************************************************************/
static int browseDSLLineInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *line_obj = NULL;
	struct dsl_line_args cur_dsl_line_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;
	int entries = 0;

	dmubus_call("dsl", "status", UBUS_ARGS{0}, 0, &res);
	while (res) {
		line_obj = dmjson_select_obj_in_array_idx(res, entries, 1, "line");
		if(line_obj) {
			cur_dsl_line_args.id = dmjson_get_value(line_obj, 1, "id");
			entries++;
			s = update_create_dmmap_dsl_line(cur_dsl_line_args.id);
			init_dsl_line(&cur_dsl_line_args, s);

			inst = handle_instance(dmctx, parent_node, s, "dsl_line_instance", "dsl_line_alias");

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&cur_dsl_line_args, inst) == DM_STOP)
				break;
		}
		else
			break;
	}
	return 0;
}

static int browseDSLChannelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *line_obj = NULL, *channel_obj = NULL;
	struct dsl_channel_args cur_dsl_channel_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;
	int entries_line = 0, entries_channel = 0;

	dmubus_call("dsl", "status", UBUS_ARGS{0}, 0, &res);
	while (res) {
		line_obj = dmjson_select_obj_in_array_idx(res, entries_line, 1, "line");
		while (line_obj) {
			channel_obj = dmjson_select_obj_in_array_idx(line_obj, entries_channel, 1, "channel");
			if(channel_obj) {
				cur_dsl_channel_args.id = dmjson_get_value(channel_obj, 1, "id");
				entries_channel++;
				s = update_create_dmmap_dsl_channel(cur_dsl_channel_args.id);
				init_dsl_channel(&cur_dsl_channel_args, s);

				inst = handle_instance(dmctx, parent_node, s, "dsl_channel_instance", "dsl_channel_alias");

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&cur_dsl_channel_args, inst) == DM_STOP)
					break;
			}
			else
				break;
		}
		entries_line++;
		if(!line_obj)
			break;
	}
	return 0;
}

/**************************************************************************
* COMMON FUNCTIONS
***************************************************************************/
static char *get_dsl_value_without_argument(char *command1, char *id, char *command2, char *key)
{
	json_object *res = NULL;
	char command[16], *value = "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{0}, 0, &res);
	if (!res) return "";
	value = dmjson_get_value(res, 1, key);
	return value;
}

static char *get_dsl_value_without_argument_and_with_two_key(char *command1, char *id, char *command2, char *key1, char *key2)
{
	json_object *res = NULL;
	char command[16], *value = "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{0}, 0, &res);
	if (!res) return "";
	value = dmjson_get_value(res, 2, key1, key2);
	return value;
}

char *get_value_with_argument(char *command1, char *id, char *command2, char *argument, char *key)
{
	json_object *res = NULL;
	char command[16], *value = "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{{"interval", argument, String}}, 1, &res);
	if (!res) return "";
	value = dmjson_get_value(res, 1, key);
	return value;
}

static char *get_dsl_value_array_without_argument(char *command1, char *id, char *command2, char *key)
{
	json_object *res = NULL;
	char command[16], *value= "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{0}, 0, &res);
	if (!res) return "";
	value = dmjson_get_value_array_all(res, ",", 1, key);
	return value;
}

int get_line_linkstatus(char *method, char *id, char **value)
{
	char *link_status = get_dsl_value_without_argument(method, id, "status", "link_status");

	if (DM_LSTRCMP(link_status, "up") == 0)
		*value = "Up";
	else if (DM_LSTRCMP(link_status, "initializing") == 0)
		*value = "Initializing";
	else if (DM_LSTRCMP(link_status, "no_signal") == 0)
		*value = "NoSignal";
	else if (DM_LSTRCMP(link_status, "disabled") == 0)
		*value = "Disabled";
	else if (DM_LSTRCMP(link_status, "establishing") == 0)
		*value = "EstablishingLink";
	else if (DM_LSTRCMP(link_status, "error") == 0)
		*value = "Error";
	else
		*value = link_status;
	return 0;
}

/**************************************************************************
* GET & SET DSL PARAMETERS
***************************************************************************/
static int get_DSL_LineNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDSLLineInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DSL_ChannelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDSLChannelInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DSL.Line.{i}.Enable!UBUS:dsl.line.1/status//status*/
static int get_DSLLine_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "status");
		*value = (DM_LSTRCMP(status, "up") == 0) ? "1" : "0";
		return 0;
}

static int set_DSLLine_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.DSL.Line.{i}.Status!UBUS:dsl.line.1/status//status*/
static int get_DSLLine_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "status");
	*value = (DM_LSTRCMP(status, "up") == 0) ? "Up" : "Down";
	return 0;
}

static int get_DSLLine_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dsl_line_args *)data)->line_sec, "dsl_line_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DSLLine_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dsl_line_args *)data)->line_sec, "dsl_line_alias", value);
			break;
	}
	return 0;
}

static int get_DSLLine_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct dsl_line_args*)data)->id;
	return 0;
}

static int get_DSLLine_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_DSLLine_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.DSL.Line.{i}.Upstream!UBUS:dsl.line.1/status//upstream*/
static int get_DSLLine_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "upstream");
	return 0;
}

/*#Device.DSL.Line.{i}.FirmwareVersion!UBUS:dsl.line.1/status//firmware_version*/
static int get_DSLLine_FirmwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "firmware_version");
	return 0;
}

/*#Device.DSL.Line.{i}.LinkStatus!UBUS:dsl.line.1/status//link_status*/
static int get_DSLLine_LinkStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_line_linkstatus("dsl.line", ((struct dsl_line_args*)data)->id, value);
}

static char *get_dsl_standard(char *str)
{
	char *dsl_standard;

	if(DM_LSTRCMP(str, "gdmt_annexa") == 0)
		dsl_standard = "G.992.1_Annex_A";
	else if(DM_LSTRCMP(str, "gdmt_annexb") == 0)
		dsl_standard = "G.992.1_Annex_B";
	else if(DM_LSTRCMP(str, "gdmt_annexc") == 0)
		dsl_standard = "G.992.1_Annex_C";
	else if(DM_LSTRCMP(str, "t1413") == 0)
		dsl_standard = "T1.413";
	else if(DM_LSTRCMP(str, "t1413_i2") == 0)
		dsl_standard = "T1.413i2";
	else if(DM_LSTRCMP(str, "glite") == 0)
		dsl_standard = "G.992.2";
	else if(DM_LSTRCMP(str, "etsi_101_388") == 0)
		dsl_standard = "ETSI_101_388";
	else if(DM_LSTRCMP(str, "adsl2_annexa") == 0)
		dsl_standard = "G.992.3_Annex_A";
	else if(DM_LSTRCMP(str, "adsl2_annexb") == 0)
		dsl_standard = "G.992.3_Annex_B";
	else if(DM_LSTRCMP(str, "adsl2_annexc") == 0)
		dsl_standard = "G.992.3_Annex_C";
	else if(DM_LSTRCMP(str, "adsl2_annexi") == 0)
		dsl_standard = "G.992.3_Annex_I";
	else if(DM_LSTRCMP(str, "adsl2_annexj") == 0)
		dsl_standard = "G.992.3_Annex_J";
	else if(DM_LSTRCMP(str, "adsl2_annexl") == 0)
		dsl_standard = "G.992.3_Annex_L";
	else if(DM_LSTRCMP(str, "adsl2_annexm") == 0)
		dsl_standard = "G.992.3_Annex_M";
	else if(DM_LSTRCMP(str, "splitterless_adsl2") == 0)
		dsl_standard = "G.992.4";
	else if(DM_LSTRCMP(str, "adsl2p_annexa") == 0)
		dsl_standard = "G.992.5_Annex_A";
	else if(DM_LSTRCMP(str, "adsl2p_annexb") == 0)
		dsl_standard = "G.992.5_Annex_B";
	else if(DM_LSTRCMP(str, "adsl2p_annexc") == 0)
		dsl_standard = "G.992.5_Annex_C";
	else if(DM_LSTRCMP(str, "adsl2p_annexi") == 0)
		dsl_standard = "G.992.5_Annex_I";
	else if(DM_LSTRCMP(str, "adsl2p_annexj") == 0)
		dsl_standard = "G.992.5_Annex_J";
	else if(DM_LSTRCMP(str, "adsl2p_annexm") == 0)
		dsl_standard = "G.992.5_Annex_M";
	else if(DM_LSTRCMP(str, "vdsl") == 0)
		dsl_standard = "G.993.1";
	else if(DM_LSTRCMP(str, "vdsl2_annexa") == 0)
		dsl_standard = "G.993.2_Annex_A";
	else if(DM_LSTRCMP(str, "vdsl2_annexb") == 0)
		dsl_standard = "G.993.2_Annex_B";
	else if(DM_LSTRCMP(str, "vdsl2_annexc") == 0)
		dsl_standard = "G.993.2_Annex_C";
	else
		dsl_standard = str;

	return dsl_standard;
}

/*#Device.DSL.Line.{i}.StandardsSupported!UBUS:dsl.line.1/status//standards_supported*/
static int get_DSLLine_StandardsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *standards_supported, *pch, *spch, *tmp = NULL, *tmpPtr = NULL, *str = NULL;

	*value = "G.992.1_Annex_A";
	standards_supported = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "standards_supported");
	if (standards_supported[0] == '\0')
		return 0;
	for (pch = strtok_r(standards_supported, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		tmp = get_dsl_standard(pch);
		if(!str)
			dmasprintf(&str, "%s", tmp);
		else {
			tmpPtr = dmstrdup(str);
			dmfree(str);
			dmasprintf(&str, "%s,%s", tmpPtr, tmp);
			dmfree(tmpPtr);
		}
	}
	*value = str;
	return 0;
}

/*#Device.DSL.Line.{i}.XTSE!UBUS:dsl.line.1/status//xtse*/
static int get_DSLLine_XTSE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *xtse, *pch, *spch, *tmpPtr = NULL, *str = NULL;

	*value = "0000000000000000";
	xtse = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtse");
	if(xtse[0] == '\0')
		return 0;
	for (pch = strtok_r(xtse, ",", &spch); pch; pch = strtok_r(NULL, ",", &spch)) {
		if(!str)
			dmasprintf(&str, "%s", pch);
		else {
			tmpPtr = dmstrdup(str);
			dmfree(str);
			dmasprintf(&str, "%s%s", tmpPtr, pch);
			dmfree(tmpPtr);
		}
	}
	*value = str;
	return 0;
}

/*#Device.DSL.Line.{i}.StandardUsed!UBUS:dsl.line.1/status//standard_used*/
static int get_DSLLine_StandardUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *standard_used = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "standard_used");
	*value = get_dsl_standard(standard_used);
	return 0;
}

/*#Device.DSL.Line.{i}.XTSUsed!UBUS:dsl.line.1/status//xtse_used*/
static int get_DSLLine_XTSUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *xtse_used,*pch, *spch, *tmpPtr = NULL, *str = NULL;

	*value = "0000000000000000";
	xtse_used = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtse_used");
	if (xtse_used[0] == '\0')
		return 0;
	for (pch = strtok_r(xtse_used, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		if(!str)
			dmasprintf(&str, "%s", pch);
		else {
			tmpPtr = dmstrdup(str);
			dmfree(str);
			dmasprintf(&str, "%s%s", tmpPtr, pch);
			dmfree(tmpPtr);
		}
	}
	*value = str;
	return 0;
}

/*#Device.DSL.Line.{i}.LineEncoding!UBUS:dsl.line.1/status//line_encoding*/
static int get_DSLLine_LineEncoding(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *line_encoding = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "line_encoding");
	if(DM_LSTRCMP(line_encoding, "dmt") == 0)
		*value = "DMT";
	else if(DM_LSTRCMP(line_encoding, "cap") == 0)
		*value = "CAP";
	else if(DM_LSTRCMP(line_encoding, "2b1q") == 0)
		*value = "2B1Q";
	else if(DM_LSTRCMP(line_encoding, "43bt") == 0)
		*value = "43BT";
	else if(DM_LSTRCMP(line_encoding, "pam") == 0)
		*value = "PAM";
	else if(DM_LSTRCMP(line_encoding, "qam") == 0)
		*value = "QAM";
	else
		*value = line_encoding;
	return 0;
}

/*#Device.DSL.Line.{i}.AllowedProfiles!UBUS:dsl.line.1/status//allowed_profiles*/
static int get_DSLLine_AllowedProfiles(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "allowed_profiles");
	return 0;
}

/*#Device.DSL.Line.{i}.CurrentProfile!UBUS:dsl.line.1/status//current_profile*/
static int get_DSLLine_CurrentProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *current_profile = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "current_profile");
	*value = (current_profile && DM_LSTRCMP(current_profile, "unknown") == 0) ? "" : current_profile;
	return 0;
}

/*#Device.DSL.Line.{i}.PowerManagementState!UBUS:dsl.line.1/status//power_management_state*/
static int get_DSLLine_PowerManagementState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *power_mng_state = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "power_management_state");
	if(DM_LSTRCMP(power_mng_state, "l0") == 0)
		*value = "L0";
	else if(DM_LSTRCMP(power_mng_state, "l1") == 0)
		*value = "L1";
	else if(DM_LSTRCMP(power_mng_state, "l2") == 0)
		*value = "L2";
	else if(DM_LSTRCMP(power_mng_state, "l3") == 0)
		*value = "L3";
	else if(DM_LSTRCMP(power_mng_state, "l4") == 0)
		*value = "L4";
	else
		*value = power_mng_state;
	return 0;
}

/*#Device.DSL.Line.{i}.SuccessFailureCause!UBUS:dsl.line.1/status//success_failure_cause*/
static int get_DSLLine_SuccessFailureCause(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "success_failure_cause");
	return 0;
}

/*#Device.DSL.Line.{i}.UPBOKLERPb!UBUS:dsl.line.1/status//upbokler_pb*/
static int get_DSLLine_UPBOKLERPb(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "upbokler_pb");
	return 0;
}

/*#Device.DSL.Line.{i}.RXTHRSHds!UBUS:dsl.line.1/status//rxthrsh_ds*/
static int get_DSLLine_RXTHRSHds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "rxthrsh_ds");
	return 0;
}

/*#Device.DSL.Line.{i}.ACTRAMODEds!UBUS:dsl.line.1/status//act_ra_mode.ds*/
static int get_DSLLine_ACTRAMODEds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "act_ra_mode", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.ACTRAMODEus!UBUS:dsl.line.1/status//act_ra_mode.us*/
static int get_DSLLine_ACTRAMODEus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "act_ra_mode", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.SNRMROCus!UBUS:dsl.line.1/status//snr_mroc_us*/
static int get_DSLLine_SNRMROCus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "snr_mroc_us");
	return 0;
}

/*#Device.DSL.Line.{i}.LastStateTransmittedDownstream!UBUS:dsl.line.1/status//last_state_transmitted.ds*/
static int get_DSLLine_LastStateTransmittedDownstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "last_state_transmitted", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.LastStateTransmittedUpstream!UBUS:dsl.line.1/status//last_state_transmitted.us*/
static int get_DSLLine_LastStateTransmittedUpstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "last_state_transmitted", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.US0MASK!UBUS:dsl.line.1/status//us0_mask*/
static int get_DSLLine_US0MASK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "us0_mask");
	return 0;
}

/*#Device.DSL.Line.{i}.TRELLISds!UBUS:dsl.line.1/status//trellis.ds*/
static int get_DSLLine_TRELLISds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "trellis", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.TRELLISus!UBUS:dsl.line.1/status//trellis.us*/
static int get_DSLLine_TRELLISus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "trellis", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.ACTSNRMODEds!UBUS:dsl.line.1/status//act_snr_mode.ds*/
static int get_DSLLine_ACTSNRMODEds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "act_snr_mode", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.ACTSNRMODEus!UBUS:dsl.line.1/status//act_snr_mode.us*/
static int get_DSLLine_ACTSNRMODEus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "act_snr_mode", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.LineNumber!UBUS:dsl.line.1/status//line_number*/
static int get_DSLLine_LineNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "line_number");
	return 0;
}

/*#Device.DSL.Line.{i}.UpstreamMaxBitRate!UBUS:dsl.line.1/status//max_bit_rate.us*/
static int get_DSLLine_UpstreamMaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "max_bit_rate", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.DownstreamMaxBitRate!UBUS:dsl.line.1/status//max_bit_rate.ds*/
static int get_DSLLine_DownstreamMaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "max_bit_rate", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.UpstreamNoiseMargin!UBUS:dsl.line.1/status//noise_margin.us*/
static int get_DSLLine_UpstreamNoiseMargin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "noise_margin", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.DownstreamNoiseMargin!UBUS:dsl.line.1/status//noise_margin.ds*/
static int get_DSLLine_DownstreamNoiseMargin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "noise_margin", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.SNRMpbus!UBUS:dsl.line.1/status//snr_mpb_us*/
static int get_DSLLine_SNRMpbus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "snr_mpb_us");
	return 0;
}

/*#Device.DSL.Line.{i}.SNRMpbds!UBUS:dsl.line.1/status//snr_mpb_ds*/
static int get_DSLLine_SNRMpbds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_array_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "snr_mpb_ds");
	return 0;
}

/*#Device.DSL.Line.{i}.UpstreamAttenuation!UBUS:dsl.line.1/status//attenuation.us*/
static int get_DSLLine_UpstreamAttenuation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "attenuation", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.DownstreamAttenuation!UBUS:dsl.line.1/status//attenuation.ds*/
static int get_DSLLine_DownstreamAttenuation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "attenuation", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.UpstreamPower!UBUS:dsl.line.1/status//power.us*/
static int get_DSLLine_UpstreamPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "power", "us");
	return 0;
}

/*#Device.DSL.Line.{i}.DownstreamPower!UBUS:dsl.line.1/status//power.ds*/
static int get_DSLLine_DownstreamPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.line", ((struct dsl_line_args*)data)->id, "status", "power", "ds");
	return 0;
}

/*#Device.DSL.Line.{i}.XTURVendor!UBUS:dsl.line.1/status//xtur_vendor*/
static int get_DSLLine_XTURVendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtur_vendor");
	return 0;
}

/*#Device.DSL.Line.{i}.XTURCountry!UBUS:dsl.line.1/status//xtur_country*/
/*#Device.DSL.Line.{i}.XTURCountry!UCI:dsl/oem-parameters,oem/country_code*/
static int get_DSLLine_XTURCountry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtur_country");

	if ((*value)[0] == '0' || (*value)[0] == '\0')
		*value = dmuci_get_option_value_fallback_def("dsl", "oem", "country_code", "0000");

	return 0;
}

/*#Device.DSL.Line.{i}.XTURANSIStd!UBUS:dsl.line.1/status//xtur_ansi_std*/
static int get_DSLLine_XTURANSIStd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtur_ansi_std");
	return 0;
}

/*#Device.DSL.Line.{i}.XTURANSIRev!UBUS:dsl.line.1/status//xtur_ansi_rev*/
static int get_DSLLine_XTURANSIRev(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtur_ansi_rev");
	return 0;
}

/*#Device.DSL.Line.{i}.XTUCVendor!UBUS:dsl.line.1/status//xtuc_vendor*/
static int get_DSLLine_XTUCVendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtuc_vendor");
	return 0;
}

/*#Device.DSL.Line.{i}.XTUCCountry!UBUS:dsl.line.1/status//xtuc_country*/
static int get_DSLLine_XTUCCountry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtuc_country");
	return 0;
}

/*#Device.DSL.Line.{i}.XTUCANSIStd!UBUS:dsl.line.1/status//xtuc_ansi_std*/
static int get_DSLLine_XTUCANSIStd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "status", "xtuc_ansi_std");
	return 0;
}

/*#Device.DSL.Line.{i}.XTUCANSIRev!UBUS:dsl.line.1/status//xtuc_ansi_rev*/
static int get_DSLLine_XTUCANSIRev(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line",((struct dsl_line_args*)data)->id, "status", "xtuc_ansi_rev");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.BytesSent!UBUS:dsl.line.1/stats//bytes_sent*/
static int get_DSLLineStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "bytes_sent");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.BytesReceived!UBUS:dsl.line.1/stats//bytes_received*/
static int get_DSLLineStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "bytes_received");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.PacketsSent!UBUS:dsl.line.1/stats//packets_sent*/
static int get_DSLLineStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "packets_sent");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.PacketsReceived!UBUS:dsl.line.1/stats//packets_received*/
static int get_DSLLineStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "packets_received");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.ErrorsSent!UBUS:dsl.line.1/stats//errors_sent*/
static int get_DSLLineStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "errors_sent");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.ErrorsReceived!UBUS:dsl.line.1/stats//errors_received*/
static int get_DSLLineStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "errors_received");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.DiscardPacketsSent!UBUS:dsl.line.1/stats//discard_packets_sent*/
static int get_DSLLineStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "discard_packets_sent");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.DiscardPacketsReceived!UBUS:dsl.line.1/stats//discard_packets_received*/
static int get_DSLLineStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "discard_packets_received");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.TotalStart!UBUS:dsl.line.1/stats//total_start*/
static int get_DSLLineStats_TotalStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "total_start");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.ShowtimeStart!UBUS:dsl.line.1/stats//showtime_start*/
static int get_DSLLineStats_ShowtimeStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "showtime_start");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.LastShowtimeStart!UBUS:dsl.line.1/stats//last_showtime_start*/
static int get_DSLLineStats_LastShowtimeStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "last_showtime_start");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.CurrentDayStart!UBUS:dsl.line.1/stats//current_day_start*/
static int get_DSLLineStats_CurrentDayStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "current_day_start");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.QuarterHourStart!UBUS:dsl.line.1/stats//quarter_hour_start*/
static int get_DSLLineStats_QuarterHourStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "quarter_hour_start");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.Total.ErroredSecs!UBUS:dsl.line.1/stats//total.errored_secs*/
static int get_DSLLineStatsTotal_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "total", "errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.Total.SeverelyErroredSecs!UBUS:dsl.line.1/stats//total.severely_errored_secs*/
static int get_DSLLineStatsTotal_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "total", "severely_errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.Showtime.ErroredSecs!UBUS:dsl.line.1/stats//showtime.errored_secs*/
static int get_DSLLineStatsShowtime_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "showtime", "errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.Showtime.SeverelyErroredSecs!UBUS:dsl.line.1/stats//showtime.severely_errored_secs*/
static int get_DSLLineStatsShowtime_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "showtime", "severely_errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.LastShowtime.ErroredSecs!UBUS:dsl.line.1/stats//lastshowtime.errored_secs*/
static int get_DSLLineStatsLastShowtime_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "lastshowtime", "errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.LastShowtime.SeverelyErroredSecs!UBUS:dsl.line.1/stats//lastshowtime.severely_errored_secs*/
static int get_DSLLineStatsLastShowtime_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "lastshowtime", "severely_errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.CurrentDay.ErroredSecs!UBUS:dsl.line.1/stats//currentday.errored_secs*/
static int get_DSLLineStatsCurrentDay_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "currentday", "errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.CurrentDay.SeverelyErroredSecs!UBUS:dsl.line.1/stats//currentday.severely_errored_secs*/
static int get_DSLLineStatsCurrentDay_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "currentday", "severely_errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.QuarterHour.ErroredSecs!UBUS:dsl.line.1/stats//quarterhour.errored_secs*/
static int get_DSLLineStatsQuarterHour_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "quarterhour", "errored_secs");
	return 0;
}

/*#Device.DSL.Line.{i}.Stats.QuarterHour.SeverelyErroredSecs!UBUS:dsl.line.1/stats//quarterhour.severely_errored_secs*/
static int get_DSLLineStatsQuarterHour_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.line", ((struct dsl_line_args*)data)->id, "stats", "quarterhour", "severely_errored_secs");
	return 0;
}

/*#Device.DSL.Channel.{i}.Enable!UBUS:dsl.channel.1/status//status*/
static int get_DSLChannel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "status");
	*value = (DM_LSTRCMP(status, "up") == 0) ? "1" : "0";
	return 0;
}

static int set_DSLChannel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.DSL.Channel.{i}.Status!UBUS:dsl.channel.1/status//status*/
static int get_DSLChannel_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "status");
	if (DM_LSTRCMP(status, "up") == 0)
		*value = "Up";
	else if (DM_LSTRCMP(status, "down") == 0)
		*value = "Down";
	else if (DM_LSTRCMP(status, "dormant") == 0)
		*value = "Dormant";
	else if (DM_LSTRCMP(status, "not_present") == 0)
		*value = "NotPresent";
	else if (DM_LSTRCMP(status, "lower_layer_down") == 0)
		*value = "LowerLayerDown";
	else if (DM_LSTRCMP(status, "error") == 0)
		*value = "Error";
	else
		*value = "Unknown";
	return 0;
}

static int get_DSLChannel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dsl_channel_args *)data)->channel_sec, "dsl_channel_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DSLChannel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dsl_channel_args *)data)->channel_sec, "dsl_channel_alias", value);
			break;
	}
	return 0;
}

static int get_DSLChannel_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct dsl_channel_args*)data)->id;
	return 0;
}

static int get_DSLChannel_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char linker[8];

	snprintf(linker, sizeof(linker), "line_%s", ((struct dsl_line_args *)data)->id);
	adm_entry_get_linker_param(ctx, "Device.DSL.Line.", linker, value);
	return 0;
}

static char *get_dsl_link_encapsulation_standard(char *str)
{
	char *dsl_link_encapsulation_standard = "";

	if(DM_LSTRCMP(str, "adsl2_atm") == 0)
		dsl_link_encapsulation_standard = "G.992.3_Annex_K_ATM";
	else if(DM_LSTRCMP(str, "adsl2_ptm") == 0)
		dsl_link_encapsulation_standard = "G.992.3_Annex_K_PTM";
	else if(DM_LSTRCMP(str, "vdsl2_atm") == 0)
		dsl_link_encapsulation_standard = "G.993.2_Annex_K_ATM";
	else if(DM_LSTRCMP(str, "vdsl2_ptm") == 0)
		dsl_link_encapsulation_standard = "G.993.2_Annex_K_PTM";
	else
		dsl_link_encapsulation_standard = "G.994.1";

	return dsl_link_encapsulation_standard;
}

/*#Device.DSL.Channel.{i}.LinkEncapsulationSupported!UBUS:dsl.channel.1/status//link_encapsulation_supported*/
static int get_DSLChannel_LinkEncapsulationSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *link_encap,*pch, *spch, *tmp = NULL, *tmpPtr = NULL, *str = NULL;

	*value = "G.994.1";
	link_encap = get_dsl_value_array_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "link_encapsulation_supported");
	if(link_encap[0] == '\0')
		return 0;
	for (pch = strtok_r(link_encap, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		tmp = get_dsl_link_encapsulation_standard(pch);
		if(!str)
			dmasprintf(&str, "%s", tmp);
		else {
			tmpPtr = dmstrdup(str);
			dmfree(str);
			dmasprintf(&str, "%s,%s", tmpPtr, tmp);
			dmfree(tmpPtr);
		}
	}
	*value = str;
	return 0;
}

/*#Device.DSL.Channel.{i}.LinkEncapsulationUsed!UBUS:dsl.channel.1/status//link_encapsulation_used*/
static int get_DSLChannel_LinkEncapsulationUsed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *link_encapsulation_used = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "link_encapsulation_used");
	*value = (DM_LSTRCMP(link_encapsulation_used, "auto") != 0) ? get_dsl_link_encapsulation_standard(link_encapsulation_used) : "G.993.2_Annex_K_PTM";
	return 0;
}

/*#Device.DSL.Channel.{i}.LPATH!UBUS:dsl.channel.1/status//lpath*/
static int get_DSLChannel_LPATH(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "lpath");
	return 0;
}

/*#Device.DSL.Channel.{i}.INTLVDEPTH!UBUS:dsl.channel.1/status//intlvdepth*/
static int get_DSLChannel_INTLVDEPTH(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "intlvdepth");
	return 0;
}

/*#Device.DSL.Channel.{i}.INTLVBLOCK!UBUS:dsl.channel.1/status//intlvblock*/
static int get_DSLChannel_INTLVBLOCK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "intlvblock");
	return 0;
}

/*#Device.DSL.Channel.{i}.ActualInterleavingDelay!UBUS:dsl.channel.1/status//actual_interleaving_delay*/
static int get_DSLChannel_ActualInterleavingDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "actual_interleaving_delay");
	return 0;
}

/*#Device.DSL.Channel.{i}.ACTINP!UBUS:dsl.channel.1/status//actinp*/
static int get_DSLChannel_ACTINP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "actinp");
	return 0;
}

/*#Device.DSL.Channel.{i}.INPREPORT!UBUS:dsl.channel.1/status//inpreport*/
static int get_DSLChannel_INPREPORT(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "inpreport");
	return 0;
}

/*#Device.DSL.Channel.{i}.NFEC!UBUS:dsl.channel.1/status//nfec*/
static int get_DSLChannel_NFEC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "nfec");
	return 0;
}

/*#Device.DSL.Channel.{i}.RFEC!UBUS:dsl.channel.1/status//rfec*/
static int get_DSLChannel_RFEC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "rfec");
	return 0;
}

/*#Device.DSL.Channel.{i}.LSYMB!UBUS:dsl.channel.1/status//lsymb*/
static int get_DSLChannel_LSYMB(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "lsymb");
	return 0;
}

/*#Device.DSL.Channel.{i}.UpstreamCurrRate!UBUS:dsl.channel.1/status//curr_rate.us*/
static int get_DSLChannel_UpstreamCurrRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "curr_rate", "us");
	return 0;
}

/*#Device.DSL.Channel.{i}.DownstreamCurrRate!UBUS:dsl.channel.1/status//curr_rate.ds*/
static int get_DSLChannel_DownstreamCurrRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "curr_rate", "ds");
	return 0;
}

/*#Device.DSL.Channel.{i}.ACTNDR!UBUS:dsl.channel.1/status//actndr.ds*/
static int get_DSLChannel_ACTNDR(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "actndr", "ds");
	return 0;
}

/*#Device.DSL.Channel.{i}.ACTINPREIN!UBUS:dsl.channel.1/status//actinprein.ds*/
static int get_DSLChannel_ACTINPREIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument_and_with_two_key("dsl.channel", ((struct dsl_channel_args*)data)->id, "status", "actinprein", "ds");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.BytesSent!UBUS:dsl.channel.1/stats//bytes_sent*/
static int get_DSLChannelStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "bytes_sent");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.BytesReceived!UBUS:dsl.channel.1/stats//bytes_received*/
static int get_DSLChannelStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "bytes_received");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.PacketsSent!UBUS:dsl.channel.1/stats//packets_sent*/
static int get_DSLChannelStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "packets_sent");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.PacketsReceived!UBUS:dsl.channel.1/stats//packets_received*/
static int get_DSLChannelStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "packets_received");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.ErrorsSent!UBUS:dsl.channel.1/stats//errors_sent*/
static int get_DSLChannelStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "errors_sent");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.ErrorsReceived!UBUS:dsl.channel.1/stats//errors_received*/
static int get_DSLChannelStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "errors_received");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.DiscardPacketsSent!UBUS:dsl.channel.1/stats//discard_packets_sent*/
static int get_DSLChannelStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "discard_packets_sent");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.DiscardPacketsReceived!UBUS:dsl.channel.1/stats//discard_packets_received*/
static int get_DSLChannelStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "discard_packets_received");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.TotalStart!UBUS:dsl.channel.1/stats//total_start*/
static int get_DSLChannelStats_TotalStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total_start");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.ShowtimeStart(!UBUS:dsl.channel.1/stats//showtime_start*/
static int get_DSLChannelStats_ShowtimeStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime_start");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtimeStart!UBUS:dsl.channel.1/stats//last_showtime_start*/
static int get_DSLChannelStats_LastShowtimeStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "last_showtime_start");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDayStart!UBUS:dsl.channel.1/stats//current_day_start*/
static int get_DSLChannelStats_CurrentDayStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "current_day_start");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHourStart!UBUS:dsl.channel.1/stats//quarter_hour_start*/
static int get_DSLChannelStats_QuarterHourStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_dsl_value_without_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarter_hour_start");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Total.XTURFECErrors!UBUS:dsl.channel.1/stats//total.xtur_fec_errors*/
static int get_DSLChannelStatsTotal_XTURFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total", "xtur_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Total.XTUCFECErrors!UBUS:dsl.channel.1/stats//total.xtur_fec_errors*/
static int get_DSLChannelStatsTotal_XTUCFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total", "xtuc_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Total.XTURHECErrors!UBUS:dsl.channel.1/stats//total.xtur_fec_errors*/
static int get_DSLChannelStatsTotal_XTURHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total", "xtur_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Total.XTUCHECErrors!UBUS:dsl.channel.1/stats//total.xtur_fec_errors*/
static int get_DSLChannelStatsTotal_XTUCHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total", "xtuc_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Total.XTURCRCErrors!UBUS:dsl.channel.1/stats//total.xtur_fec_errors*/
static int get_DSLChannelStatsTotal_XTURCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total", "xtur_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Total.XTUCCRCErrors!UBUS:dsl.channel.1/stats//total.xtur_fec_errors*/
static int get_DSLChannelStatsTotal_XTUCCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "total", "xtuc_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Showtime.XTURFECErrors!UBUS:dsl.channel.1/stats//showtime.xtur_fec_errors*/
static int get_DSLChannelStatsShowtime_XTURFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime", "xtur_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Showtime.XTUCFECErrors!UBUS:dsl.channel.1/stats//showtime.xtuc_fec_errors*/
static int get_DSLChannelStatsShowtime_XTUCFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime", "xtuc_fec_errors");
	return 0;}

/*#Device.DSL.Channel.{i}.Stats.Showtime.XTURHECErrors!UBUS:dsl.channel.1/stats//showtime.xtur_hec_errors*/
static int get_DSLChannelStatsShowtime_XTURHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime", "xtur_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Showtime.XTUCHECErrors!UBUS:dsl.channel.1/stats//showtime.xtuc_hec_errors*/
static int get_DSLChannelStatsShowtime_XTUCHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime", "xtuc_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Showtime.XTURCRCErrors!UBUS:dsl.channel.1/stats//showtime.xtur_crc_errors*/
static int get_DSLChannelStatsShowtime_XTURCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime", "xtur_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.Showtime.XTUCCRCErrors!UBUS:dsl.channel.1/stats//showtime.xtuc_crc_errors*/
static int get_DSLChannelStatsShowtime_XTUCCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "showtime", "xtuc_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtime.XTURFECErrors!UBUS:dsl.channel.1/stats//lastshowtime.xtur_fec_errors*/
static int get_DSLChannelStatsLastShowtime_XTURFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "lastshowtime", "xtur_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtime.XTUCFECErrors!UBUS:dsl.channel.1/stats//lastshowtime.xtuc_fec_errors*/
static int get_DSLChannelStatsLastShowtime_XTUCFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "lastshowtime", "xtuc_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtime.XTURHECErrors!UBUS:dsl.channel.1/stats//lastshowtime.xtur_hec_errors*/
static int get_DSLChannelStatsLastShowtime_XTURHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "lastshowtime", "xtur_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtime.XTUCHECErrors!UBUS:dsl.channel.1/stats//lastshowtime.xtuc_hec_errors*/
static int get_DSLChannelStatsLastShowtime_XTUCHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "lastshowtime", "xtuc_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtime.XTURCRCErrors!UBUS:dsl.channel.1/stats//lastshowtime.xtur_crc_errors*/
static int get_DSLChannelStatsLastShowtime_XTURCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "lastshowtime", "xtur_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.LastShowtime.XTUCCRCErrors!UBUS:dsl.channel.1/stats//lastshowtime.xtuc_crc_errors*/
static int get_DSLChannelStatsLastShowtime_XTUCCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "lastshowtime", "xtuc_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDay.XTURFECErrors!UBUS:dsl.channel.1/stats//currentday.xtur_fec_errors*/
static int get_DSLChannelStatsCurrentDay_XTURFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "currentday", "xtur_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDay.XTUCFECErrors!UBUS:dsl.channel.1/stats//currentday.xtuc_fec_errors*/
static int get_DSLChannelStatsCurrentDay_XTUCFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "currentday", "xtuc_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDay.XTURHECErrors!UBUS:dsl.channel.1/stats//currentday.xtur_hec_errors*/
static int get_DSLChannelStatsCurrentDay_XTURHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "currentday", "xtur_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDay.XTUCHECErrors!UBUS:dsl.channel.1/stats//currentday.xtuc_hec_errors*/
static int get_DSLChannelStatsCurrentDay_XTUCHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "currentday", "xtuc_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDay.XTURCRCErrors!UBUS:dsl.channel.1/stats//currentday.xtur_crc_errors*/
static int get_DSLChannelStatsCurrentDay_XTURCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "currentday", "xtur_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.CurrentDay.XTUCCRCErrors!UBUS:dsl.channel.1/stats//currentday.xtuc_crc_errors*/
static int get_DSLChannelStatsCurrentDay_XTUCCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "currentday", "xtuc_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHour.XTURFECErrors!UBUS:dsl.channel.1/stats//quarterhour.xtur_fec_errors*/
static int get_DSLChannelStatsQuarterHour_XTURFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarterhour", "xtur_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHour.XTUCFECErrors!UBUS:dsl.channel.1/stats//quarterhour.xtuc_fec_errors*/
static int get_DSLChannelStatsQuarterHour_XTUCFECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarterhour", "xtuc_fec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHour.XTURHECErrors!UBUS:dsl.channel.1/stats//quarterhour.xtur_hec_errors*/
static int get_DSLChannelStatsQuarterHour_XTURHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarterhour", "xtur_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHour.XTUCHECErrors!UBUS:dsl.channel.1/stats//quarterhour.xtuc_hec_errors*/
static int get_DSLChannelStatsQuarterHour_XTUCHECErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarterhour", "xtuc_hec_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHour.XTURCRCErrors!UBUS:dsl.channel.1/stats//quarterhour.xtur_crc_errors*/
static int get_DSLChannelStatsQuarterHour_XTURCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarterhour", "xtur_crc_errors");
	return 0;
}

/*#Device.DSL.Channel.{i}.Stats.QuarterHour.XTUCCRCErrors!UBUS:dsl.channel.1/stats//quarterhour.xtuc_crc_errors*/
static int get_DSLChannelStatsQuarterHour_XTUCCRCErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("dsl.channel", ((struct dsl_channel_args*)data)->id, "stats", "quarterhour", "xtuc_crc_errors");
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.DSL. *** */
DMOBJ tDSLObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Line", &DMREAD, NULL, NULL, NULL, browseDSLLineInst, NULL, NULL, tDSLLineObj, tDSLLineParams, get_dsl_line_linker, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.0"},
{"Channel", &DMREAD, NULL, NULL, NULL, browseDSLChannelInst, NULL, NULL, tDSLChannelObj, tDSLChannelParams, get_dsl_channel_linker, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tDSLParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"LineNumberOfEntries", &DMREAD, DMT_UNINT, get_DSL_LineNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"ChannelNumberOfEntries", &DMREAD, DMT_UNINT, get_DSL_ChannelNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}. *** */
DMOBJ tDSLLineObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDSLLineStatsObj, tDSLLineStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tDSLLineParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DSLLine_Enable, set_DSLLine_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_DSLLine_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_DSLLine_Alias, set_DSLLine_Alias, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_DSLLine_Name, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_DSLLine_LowerLayers, set_DSLLine_LowerLayers, BBFDM_BOTH, "2.0"},
{"Upstream", &DMREAD, DMT_BOOL, get_DSLLine_Upstream, NULL, BBFDM_BOTH, "2.0"},
{"FirmwareVersion", &DMREAD, DMT_STRING, get_DSLLine_FirmwareVersion, NULL, BBFDM_BOTH, "2.0"},
{"LinkStatus", &DMREAD, DMT_STRING, get_DSLLine_LinkStatus, NULL, BBFDM_BOTH, "2.0"},
{"StandardsSupported", &DMREAD, DMT_STRING, get_DSLLine_StandardsSupported, NULL, BBFDM_BOTH, "2.0"},
{"XTSE", &DMREAD, DMT_HEXBIN, get_DSLLine_XTSE, NULL, BBFDM_BOTH, "2.8"},
{"StandardUsed", &DMREAD, DMT_STRING, get_DSLLine_StandardUsed, NULL, BBFDM_BOTH, "2.0"},
{"XTSUsed", &DMREAD, DMT_HEXBIN, get_DSLLine_XTSUsed, NULL, BBFDM_BOTH, "2.8"},
{"LineEncoding", &DMREAD, DMT_STRING, get_DSLLine_LineEncoding, NULL, BBFDM_BOTH, "2.0"},
{"AllowedProfiles", &DMREAD, DMT_STRING, get_DSLLine_AllowedProfiles, NULL, BBFDM_BOTH, "2.0"},
{"CurrentProfile", &DMREAD, DMT_STRING, get_DSLLine_CurrentProfile, NULL, BBFDM_BOTH, "2.0"},
{"PowerManagementState", &DMREAD, DMT_STRING, get_DSLLine_PowerManagementState, NULL, BBFDM_BOTH, "2.0"},
{"SuccessFailureCause", &DMREAD, DMT_UNINT, get_DSLLine_SuccessFailureCause, NULL, BBFDM_BOTH, "2.0"},
{"UPBOKLERPb", &DMREAD, DMT_STRING, get_DSLLine_UPBOKLERPb, NULL, BBFDM_BOTH, "2.8"},
{"RXTHRSHds", &DMREAD, DMT_INT, get_DSLLine_RXTHRSHds, NULL, BBFDM_BOTH, "2.8"},
{"ACTRAMODEds", &DMREAD, DMT_UNINT, get_DSLLine_ACTRAMODEds, NULL, BBFDM_BOTH, "2.8"},
{"ACTRAMODEus", &DMREAD, DMT_UNINT, get_DSLLine_ACTRAMODEus, NULL, BBFDM_BOTH, "2.8"},
{"SNRMROCus", &DMREAD, DMT_UNINT, get_DSLLine_SNRMROCus, NULL, BBFDM_BOTH, "2.8"},
{"LastStateTransmittedDownstream", &DMREAD, DMT_UNINT, get_DSLLine_LastStateTransmittedDownstream, NULL, BBFDM_BOTH, "2.0"},
{"LastStateTransmittedUpstream", &DMREAD, DMT_UNINT, get_DSLLine_LastStateTransmittedUpstream, NULL, BBFDM_BOTH, "2.0"},
{"US0MASK", &DMREAD, DMT_UNINT, get_DSLLine_US0MASK, NULL, BBFDM_BOTH, "2.0"},
{"TRELLISds", &DMREAD, DMT_INT, get_DSLLine_TRELLISds, NULL, BBFDM_BOTH, "2.0"},
{"TRELLISus", &DMREAD, DMT_INT, get_DSLLine_TRELLISus, NULL, BBFDM_BOTH, "2.0"},
{"ACTSNRMODEds", &DMREAD, DMT_UNINT, get_DSLLine_ACTSNRMODEds, NULL, BBFDM_BOTH, "2.0"},
{"ACTSNRMODEus", &DMREAD, DMT_UNINT, get_DSLLine_ACTSNRMODEus, NULL, BBFDM_BOTH, "2.0"},
{"LineNumber", &DMREAD, DMT_INT, get_DSLLine_LineNumber, NULL, BBFDM_BOTH, "2.0"},
{"UpstreamMaxBitRate", &DMREAD, DMT_UNINT, get_DSLLine_UpstreamMaxBitRate, NULL, BBFDM_BOTH, "2.0"},
{"DownstreamMaxBitRate", &DMREAD, DMT_UNINT, get_DSLLine_DownstreamMaxBitRate, NULL, BBFDM_BOTH, "2.0"},
{"UpstreamNoiseMargin", &DMREAD, DMT_INT, get_DSLLine_UpstreamNoiseMargin, NULL, BBFDM_BOTH, "2.0"},
{"DownstreamNoiseMargin", &DMREAD, DMT_INT, get_DSLLine_DownstreamNoiseMargin, NULL, BBFDM_BOTH, "2.0"},
{"SNRMpbus", &DMREAD, DMT_STRING, get_DSLLine_SNRMpbus, NULL, BBFDM_BOTH, "2.0"},
{"SNRMpbds", &DMREAD, DMT_STRING, get_DSLLine_SNRMpbds, NULL, BBFDM_BOTH, "2.0"},
{"UpstreamAttenuation", &DMREAD, DMT_INT, get_DSLLine_UpstreamAttenuation, NULL, BBFDM_BOTH, "2.0"},
{"DownstreamAttenuation", &DMREAD, DMT_INT, get_DSLLine_DownstreamAttenuation, NULL, BBFDM_BOTH, "2.0"},
{"UpstreamPower", &DMREAD, DMT_INT, get_DSLLine_UpstreamPower, NULL, BBFDM_BOTH, "2.0"},
{"DownstreamPower", &DMREAD, DMT_INT, get_DSLLine_DownstreamPower, NULL, BBFDM_BOTH, "2.0"},
{"XTURVendor", &DMREAD, DMT_HEXBIN, get_DSLLine_XTURVendor, NULL, BBFDM_BOTH, "2.0"},
{"XTURCountry", &DMREAD, DMT_HEXBIN, get_DSLLine_XTURCountry, NULL, BBFDM_BOTH, "2.0"},
{"XTURANSIStd", &DMREAD, DMT_UNINT, get_DSLLine_XTURANSIStd, NULL, BBFDM_BOTH, "2.0"},
{"XTURANSIRev", &DMREAD, DMT_UNINT, get_DSLLine_XTURANSIRev, NULL, BBFDM_BOTH, "2.0"},
{"XTUCVendor", &DMREAD, DMT_HEXBIN, get_DSLLine_XTUCVendor, NULL, BBFDM_BOTH, "2.0"},
{"XTUCCountry", &DMREAD, DMT_HEXBIN, get_DSLLine_XTUCCountry, NULL, BBFDM_BOTH, "2.0"},
{"XTUCANSIStd", &DMREAD, DMT_UNINT, get_DSLLine_XTUCANSIStd, NULL, BBFDM_BOTH, "2.0"},
{"XTUCANSIRev", &DMREAD, DMT_UNINT, get_DSLLine_XTUCANSIRev, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}.Stats. *** */
DMOBJ tDSLLineStatsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Total", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLLineStatsTotalParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Showtime", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLLineStatsShowtimeParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"LastShowtime", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLLineStatsLastShowtimeParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"CurrentDay", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLLineStatsCurrentDayParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"QuarterHour", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLLineStatsQuarterHourParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tDSLLineStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_DSLLineStats_BytesSent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_DSLLineStats_BytesReceived, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_DSLLineStats_PacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_DSLLineStats_PacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_DSLLineStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_DSLLineStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_DSLLineStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_DSLLineStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"TotalStart", &DMREAD, DMT_UNINT, get_DSLLineStats_TotalStart, NULL, BBFDM_BOTH, "2.0"},
{"ShowtimeStart", &DMREAD, DMT_UNINT, get_DSLLineStats_ShowtimeStart, NULL, BBFDM_BOTH, "2.0"},
{"LastShowtimeStart", &DMREAD, DMT_UNINT, get_DSLLineStats_LastShowtimeStart, NULL, BBFDM_BOTH, "2.0"},
{"CurrentDayStart", &DMREAD, DMT_UNINT, get_DSLLineStats_CurrentDayStart, NULL, BBFDM_BOTH, "2.0"},
{"QuarterHourStart", &DMREAD, DMT_UNINT, get_DSLLineStats_QuarterHourStart, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}.Stats.Total. *** */
DMLEAF tDSLLineStatsTotalParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsTotal_ErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsTotal_SeverelyErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}.Stats.Showtime. *** */
DMLEAF tDSLLineStatsShowtimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsShowtime_ErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsShowtime_SeverelyErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}.Stats.LastShowtime. *** */
DMLEAF tDSLLineStatsLastShowtimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsLastShowtime_ErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsLastShowtime_SeverelyErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}.Stats.CurrentDay. *** */
DMLEAF tDSLLineStatsCurrentDayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsCurrentDay_ErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsCurrentDay_SeverelyErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Line.{i}.Stats.QuarterHour. *** */
DMLEAF tDSLLineStatsQuarterHourParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsQuarterHour_ErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_DSLLineStatsQuarterHour_SeverelyErroredSecs, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Channel.{i}. *** */
DMOBJ tDSLChannelObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDSLChannelStatsObj, tDSLChannelStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};


DMLEAF tDSLChannelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DSLChannel_Enable, set_DSLChannel_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_DSLChannel_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_DSLChannel_Alias, set_DSLChannel_Alias, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_DSLChannel_Name, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMREAD, DMT_STRING, get_DSLChannel_LowerLayers, NULL, BBFDM_BOTH, "2.0"},
{"LinkEncapsulationSupported", &DMREAD, DMT_STRING, get_DSLChannel_LinkEncapsulationSupported, NULL, BBFDM_BOTH, "2.0"},
{"LinkEncapsulationUsed", &DMREAD, DMT_STRING, get_DSLChannel_LinkEncapsulationUsed, NULL, BBFDM_BOTH, "2.0"},
{"LPATH", &DMREAD, DMT_UNINT, get_DSLChannel_LPATH, NULL, BBFDM_BOTH, "2.0"},
{"INTLVDEPTH", &DMREAD, DMT_UNINT, get_DSLChannel_INTLVDEPTH, NULL, BBFDM_BOTH, "2.0"},
{"INTLVBLOCK", &DMREAD, DMT_INT, get_DSLChannel_INTLVBLOCK, NULL, BBFDM_BOTH, "2.0"},
{"ActualInterleavingDelay", &DMREAD, DMT_UNINT, get_DSLChannel_ActualInterleavingDelay, NULL, BBFDM_BOTH, "2.0"},
{"ACTINP", &DMREAD, DMT_INT, get_DSLChannel_ACTINP, NULL, BBFDM_BOTH, "2.0"},
{"INPREPORT", &DMREAD, DMT_BOOL, get_DSLChannel_INPREPORT, NULL, BBFDM_BOTH, "2.0"},
{"NFEC", &DMREAD, DMT_INT, get_DSLChannel_NFEC, NULL, BBFDM_BOTH, "2.0"},
{"RFEC", &DMREAD, DMT_INT, get_DSLChannel_RFEC, NULL, BBFDM_BOTH, "2.0"},
{"LSYMB", &DMREAD, DMT_INT, get_DSLChannel_LSYMB, NULL, BBFDM_BOTH, "2.0"},
{"UpstreamCurrRate", &DMREAD, DMT_UNINT, get_DSLChannel_UpstreamCurrRate, NULL, BBFDM_BOTH, "2.0"},
{"DownstreamCurrRate", &DMREAD, DMT_UNINT, get_DSLChannel_DownstreamCurrRate, NULL, BBFDM_BOTH, "2.0"},
{"ACTNDR", &DMREAD, DMT_UNINT, get_DSLChannel_ACTNDR, NULL, BBFDM_BOTH, "2.8"},
{"ACTINPREIN", &DMREAD, DMT_UNINT, get_DSLChannel_ACTINPREIN, NULL, BBFDM_BOTH, "2.8"},
{0}
};

/* *** Device.DSL.Channel.{i}.Stats. *** */
DMOBJ tDSLChannelStatsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Total", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLChannelStatsTotalParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Showtime", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLChannelStatsShowtimeParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"LastShowtime", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLChannelStatsLastShowtimeParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"CurrentDay", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLChannelStatsCurrentDayParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"QuarterHour", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLChannelStatsQuarterHourParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tDSLChannelStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_DSLChannelStats_BytesSent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_DSLChannelStats_BytesReceived, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_DSLChannelStats_PacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_DSLChannelStats_PacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_DSLChannelStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_DSLChannelStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_DSLChannelStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_DSLChannelStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"TotalStart", &DMREAD, DMT_UNINT, get_DSLChannelStats_TotalStart, NULL, BBFDM_BOTH, "2.0"},
{"ShowtimeStart", &DMREAD, DMT_UNINT, get_DSLChannelStats_ShowtimeStart, NULL, BBFDM_BOTH, "2.0"},
{"LastShowtimeStart", &DMREAD, DMT_UNINT, get_DSLChannelStats_LastShowtimeStart, NULL, BBFDM_BOTH, "2.0"},
{"CurrentDayStart", &DMREAD, DMT_UNINT, get_DSLChannelStats_CurrentDayStart, NULL, BBFDM_BOTH, "2.0"},
{"QuarterHourStart", &DMREAD, DMT_UNINT, get_DSLChannelStats_QuarterHourStart, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Channel.{i}.Stats.Total. *** */
DMLEAF tDSLChannelStatsTotalParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"XTURFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsTotal_XTURFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsTotal_XTUCFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsTotal_XTURHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsTotal_XTUCHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsTotal_XTURCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsTotal_XTUCCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Channel.{i}.Stats.Showtime. *** */
DMLEAF tDSLChannelStatsShowtimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"XTURFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsShowtime_XTURFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsShowtime_XTUCFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsShowtime_XTURHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsShowtime_XTUCHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsShowtime_XTURCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsShowtime_XTUCCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Channel.{i}.Stats.LastShowtime. *** */
DMLEAF tDSLChannelStatsLastShowtimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"XTURFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsLastShowtime_XTURFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsLastShowtime_XTUCFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsLastShowtime_XTURHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsLastShowtime_XTUCHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsLastShowtime_XTURCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsLastShowtime_XTUCCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Channel.{i}.Stats.CurrentDay. *** */
DMLEAF tDSLChannelStatsCurrentDayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"XTURFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsCurrentDay_XTURFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsCurrentDay_XTUCFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsCurrentDay_XTURHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsCurrentDay_XTUCHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsCurrentDay_XTURCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsCurrentDay_XTUCCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DSL.Channel.{i}.Stats.QuarterHour. *** */
DMLEAF tDSLChannelStatsQuarterHourParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"XTURFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsQuarterHour_XTURFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCFECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsQuarterHour_XTUCFECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsQuarterHour_XTURHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCHECErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsQuarterHour_XTUCHECErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTURCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsQuarterHour_XTURCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{"XTUCCRCErrors", &DMREAD, DMT_UNINT, get_DSLChannelStatsQuarterHour_XTUCCRCErrors, NULL, BBFDM_BOTH, "2.0"},
{0}
};
