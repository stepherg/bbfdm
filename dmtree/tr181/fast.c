/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Jani Juvan <jani.juvan@iopsys.eu>
 */

#include "dmentry.h"
#include "dsl.h"
#include "fast.h"

struct fast_line_args
{
	struct uci_section *line_sec;
	char *id;
};

/**************************************************************************
* LINKER
***************************************************************************/

static int get_fast_line_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (instance) {
		dmasprintf(linker, "fast_line_%s", instance);
		return 0;
	}
	*linker = "" ;
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_fast_line(struct fast_line_args *args, struct uci_section *s)
{
	args->line_sec = s;
	return 0;
}

/*************************************************************/
static struct uci_section *update_create_dmmap_fast_line(char *curr_id)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "fast_line", "id", curr_id, s) {
		return s;
	}
	if (!s) {
		char instance[16];

		snprintf(instance, sizeof(instance), "%d", atoi(curr_id));
		dmuci_add_section_bbfdm("dmmap", "fast_line", &s);
		dmuci_set_value_by_section_bbfdm(s, "id", curr_id);
		dmuci_set_value_by_section_bbfdm(s, "fast_line_instance", instance);
	}
	return s;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
static int browseFASTLineInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *line_obj = NULL;
	struct fast_line_args cur_fast_line_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL, *max_inst = NULL;
	int entries = 0;

	dmubus_call("fast", "status", UBUS_ARGS{}, 0, &res);
	while (res) {
		line_obj = dmjson_select_obj_in_array_idx(res, entries, 1, "line");
		if(line_obj) {
			cur_fast_line_args.id = dmjson_get_value(line_obj, 1, "id");
			entries++;
			s = update_create_dmmap_fast_line(cur_fast_line_args.id);
			init_fast_line(&cur_fast_line_args, s);

			inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
				   s, "fast_line_instance", "fast_line_alias");

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&cur_fast_line_args, inst) == DM_STOP)
				break;
		}
		else
			break;
	}
	return 0;
}

/**************************************************************************
* COMMON FUNCTIONS
***************************************************************************/
static char *get_fast_value_without_argument(char *command1, char *id, char *command2, char *key)
{
	json_object *res;
	char command[16], *value = "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{}, 0, &res);
	if (!res) return "";
	value = dmjson_get_value(res, 1, key);
	return value;
}

static char *get_fast_value_without_argument_and_with_two_key(char *command1, char *id, char *command2, char *key1, char *key2)
{
	json_object *res;
	char command[16], *value = "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{}, 0, &res);
	if (!res) return "";
	value = dmjson_get_value(res, 2, key1, key2);
	return value;
}

static char *get_fast_value_array_without_argument(char *command1, char *id, char *command2, char *key)
{
	json_object *res;
	char command[16], *value= "0";

	snprintf(command, sizeof(command), "%s.%s", command1, id);
	dmubus_call(command, command2, UBUS_ARGS{}, 0, &res);
	if (!res) return "";
	value = dmjson_get_value_array_all(res, ",", 1, key);
	return value;
}

/**************************************************************************
* GET & SET FAST PARAMETERS
***************************************************************************/
static int get_FAST_LineNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_sections(bbfdm, "dmmap", "fast_line", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.FAST.Line.{i}.Enable!UBUS:fast.line.1/status//status*/
static int get_FASTLine_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "status");
		*value = (strcmp(status, "up") == 0) ? "1" : "0";
		return 0;
}

static int set_FASTLine_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.FAST.Line.{i}.Status!UBUS:fast.line.1/status//status*/
static int get_FASTLine_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "status");
	*value = (strcmp(status, "up") == 0) ? "Up" : "Down";
	return 0;
}

static int get_FASTLine_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct fast_line_args *)data)->line_sec, "fast_line_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_FASTLine_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct fast_line_args *)data)->line_sec, "fast_line_alias", value);
			break;
	}
	return 0;
}

static int get_FASTLine_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct fast_line_args*)data)->id;
	return 0;
}

static int get_FASTLine_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_FASTLine_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.FAST.Line.{i}.Upstream!UBUS:fast.line.1/status//upstream*/
static int get_FASTLine_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "upstream");
	return 0;
}

/*#Device.FAST.Line.{i}.FirmwareVersion!UBUS:fast.line.1/status//firmware_version*/
static int get_FASTLine_FirmwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "firmware_version");
	return 0;
}

/*#Device.FAST.Line.{i}.LinkStatus!UBUS:fast.line.1/status//link_status*/
static int get_FASTLine_LinkStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_line_linkstatus("fast.line", ((struct fast_line_args*)data)->id, value);
}

/*#Device.FAST.Line.{i}.AllowedProfiles!UBUS:fast.line.1/status//allowed_profiles*/
static int get_FASTLine_AllowedProfiles(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *allowed_profiles = NULL;
	char list_profile[16], ubus_name[16], *profile = NULL;
	unsigned pos = 0, idx = 0;

	snprintf(ubus_name, sizeof(ubus_name), "fast.line.%s", ((struct fast_line_args*)data)->id);
	dmubus_call(ubus_name, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");

	list_profile[0] = 0;
	dmjson_foreach_value_in_array(res, allowed_profiles, profile, idx, 1, "allowed_profiles") {
		if (profile && (strcmp(profile, "106a") == 0 || strcmp(profile, "212a") == 0))
			pos += snprintf(&list_profile[pos], sizeof(list_profile) - pos, "%s,", profile);
	}

	/* cut tailing ',' */
	if (pos)
		list_profile[pos - 1] = 0;

	*value = dmstrdup(list_profile);
	return 0;
}

/*#Device.FAST.Line.{i}.CurrentProfile!UBUS:fast.line.1/status//current_profile*/
static int get_FASTLine_CurrentProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *current_profile = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "current_profile");
	*value = (current_profile && strcmp(current_profile, "unknown") == 0) ? "" : current_profile;
	return 0;
}

/*#Device.FAST.Line.{i}.PowerManagementState!UBUS:fast.line.1/status//power_management_state*/
static int get_FASTLine_PowerManagementState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *power_mng_state = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "power_management_state");
	if(strcmp(power_mng_state, "l0") == 0)
		*value = "L0";
	else if(strcmp(power_mng_state, "l1") == 0)
		*value = "L2.1";
	else if(strcmp(power_mng_state, "l2") == 0)
		*value = "L2.2";
	else if(strcmp(power_mng_state, "l3") == 0)
		*value = "L3";
	else
		*value = power_mng_state;
	return 0;
}

/*#Device.FAST.Line.{i}.SuccessFailureCause!UBUS:fast.line.1/status//success_failure_cause*/
static int get_FASTLine_SuccessFailureCause(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "success_failure_cause");
	return 0;
}

/*#Device.FAST.Line.{i}.UPBOKLER!UBUS:fast.line.1/status//upbokler*/
static int get_FASTLine_UPBOKLER(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_array_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "upbokler");
	return 0;
}

/*#Device.FAST.Line.{i}.UPBOKLE!UBUS:fast.line.1/status//upbokle*/
static int get_FASTLine_UPBOKLE(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_array_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "upbokle");
	return 0;
}

/*#Device.FAST.Line.{i}.LineNumber!UBUS:fast.line.1/status//line_number*/
static int get_FASTLine_LineNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "status", "line_number");
	return 0;
}

/*#Device.FAST.Line.{i}.UpstreamMaxBitRate!UBUS:fast.line.1/status//max_bit_rate.us*/
static int get_FASTLine_UpstreamMaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "max_bit_rate", "us");
	return 0;
}

/*#Device.FAST.Line.{i}.DownstreamMaxBitRate!UBUS:fast.line.1/status//max_bit_rate.ds*/
static int get_FASTLine_DownstreamMaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "max_bit_rate", "ds");
	return 0;
}

/*#Device.FAST.Line.{i}.UpstreamNoiseMargin!UBUS:fast.line.1/status//noise_margin.us*/
static int get_FASTLine_UpstreamNoiseMargin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "noise_margin", "us");
	return 0;
}

/*#Device.FAST.Line.{i}.DownstreamNoiseMargin!UBUS:fast.line.1/status//noise_margin.ds*/
static int get_FASTLine_DownstreamNoiseMargin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "noise_margin", "ds");
	return 0;
}

/*#Device.FAST.Line.{i}.UpstreamAttenuation!UBUS:fast.line.1/status//attenuation.us*/
static int get_FASTLine_UpstreamAttenuation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "attenuation", "us");
	return 0;
}

/*#Device.FAST.Line.{i}.DownstreamAttenuation!UBUS:fast.line.1/status//attenuation.ds*/
static int get_FASTLine_DownstreamAttenuation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "attenuation", "ds");
	return 0;
}

/*#Device.FAST.Line.{i}.UpstreamPower!UBUS:fast.line.1/status//power.us*/
static int get_FASTLine_UpstreamPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "power", "us");
	return 0;
}

/*#Device.FAST.Line.{i}.DownstreamPower!UBUS:fast.line.1/status//power.ds*/
static int get_FASTLine_DownstreamPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "power", "ds");
	return 0;
}

/*#Device.FAST.Line.{i}.SNRMRMCds!UBUS:fast.line.1/status//snrm_rmc.ds*/
static int get_FASTLine_SNRMRMCds(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "snrm_rmc", "ds");
	return 0;
}

/*#Device.FAST.Line.{i}.SNRMRMCus!UBUS:fast.line.1/status//snrm_rmc.us*/
static int get_FASTLine_SNRMRMCus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument_and_with_two_key("fast.line", ((struct fast_line_args*)data)->id, "status", "snrm_rmc", "us");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.BytesSent!UBUS:fast.line.1/stats//bytes_sent*/
static int get_FASTLineStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "bytes_sent");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.BytesReceived!UBUS:fast.line.1/stats//bytes_received*/
static int get_FASTLineStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "bytes_received");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.PacketsSent!UBUS:fast.line.1/stats//packets_sent*/
static int get_FASTLineStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "packets_sent");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.PacketsReceived!UBUS:fast.line.1/stats//packets_received*/
static int get_FASTLineStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "packets_received");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.ErrorsSent!UBUS:fast.line.1/stats//errors_sent*/
static int get_FASTLineStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "errors_sent");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.ErrorsReceived!UBUS:fast.line.1/stats//errors_received*/
static int get_FASTLineStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "errors_received");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.DiscardPacketsSent!UBUS:fast.line.1/stats//discard_packets_sent*/
static int get_FASTLineStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "discard_packets_sent");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.DiscardPacketsReceived!UBUS:fast.line.1/stats//discard_packets_received*/
static int get_FASTLineStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "discard_packets_received");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.TotalStart!UBUS:fast.line.1/stats//total_start*/
static int get_FASTLineStats_TotalStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total_start");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.ShowtimeStart!UBUS:fast.line.1/stats//showtime_start*/
static int get_FASTLineStats_ShowtimeStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime_start");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtimeStart!UBUS:fast.line.1/stats//last_showtime_start*/
static int get_FASTLineStats_LastShowtimeStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "last_showtime_start");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDayStart!UBUS:fast.line.1/stats//current_day_start*/
static int get_FASTLineStats_CurrentDayStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "current_day_start");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHourStart!UBUS:fast.line.1/stats//quarter_hour_start*/
static int get_FASTLineStats_QuarterHourStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_fast_value_without_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarter_hour_start");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.ErroredSecs!UBUS:fast.line.1/stats//total.errored_secs*/
static int get_FASTLineStatsTotal_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.SeverelyErroredSecs!UBUS:fast.line.1/stats//total.severely_errored_secs*/
static int get_FASTLineStatsTotal_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "severely_errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.LOSS!UBUS:fast.line.1/stats//total.loss*/
static int get_FASTLineStatsTotal_LOSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "loss");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.LORS!UBUS:fast.line.1/stats//total.lors*/
static int get_FASTLineStatsTotal_LORS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "lors");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.UAS!UBUS:fast.line.1/stats//total.uas*/
static int get_FASTLineStatsTotal_UAS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "uas");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.RTXUC!UBUS:fast.line.1/stats//total.rtx_uc*/
static int get_FASTLineStatsTotal_RTXUC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "rtx_uc");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.RTXTX!UBUS:fast.line.1/stats//total.rtx_tx*/
static int get_FASTLineStatsTotal_RTXTX(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "rtx_tx");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.SuccessBSW!UBUS:fast.line.1/stats//total.success_bsw*/
static int get_FASTLineStatsTotal_SuccessBSW(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "success_bsw");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.SuccessSRA!UBUS:fast.line.1/stats//total.success_sra*/
static int get_FASTLineStatsTotal_SuccessSRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "success_sra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.SuccessFRA!UBUS:fast.line.1/stats//total.success_fra*/
static int get_FASTLineStatsTotal_SuccessFRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "success_fra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.SuccessRPA!UBUS:fast.line.1/stats//total.success_rpa*/
static int get_FASTLineStatsTotal_SuccessRPA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "success_rpa");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Total.SuccessTIGA!UBUS:fast.line.1/stats//total.success_tiga*/
static int get_FASTLineStatsTotal_SuccessTIGA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "total", "success_tiga");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.ErroredSecs!UBUS:fast.line.1/stats//showtime.errored_secs*/
static int get_FASTLineStatsShowtime_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.SeverelyErroredSecs!UBUS:fast.line.1/stats//showtime.severely_errored_secs*/
static int get_FASTLineStatsShowtime_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "severely_errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.LOSS!UBUS:fast.line.1/stats//showtime.loss*/
static int get_FASTLineStatsShowtime_LOSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "loss");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.LORS!UBUS:fast.line.1/stats//showtime.lors*/
static int get_FASTLineStatsShowtime_LORS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "lors");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.UAS!UBUS:fast.line.1/stats//showtime.uas*/
static int get_FASTLineStatsShowtime_UAS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "uas");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.RTXUC!UBUS:fast.line.1/stats//showtime.rtx_uc*/
static int get_FASTLineStatsShowtime_RTXUC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "rtx_uc");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.RTXTX!UBUS:fast.line.1/stats//showtime.rtx_tx*/
static int get_FASTLineStatsShowtime_RTXTX(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "rtx_tx");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.SuccessBSW!UBUS:fast.line.1/stats//showtime.success_bsw*/
static int get_FASTLineStatsShowtime_SuccessBSW(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "success_bsw");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.SuccessSRA!UBUS:fast.line.1/stats//showtime.success_sra*/
static int get_FASTLineStatsShowtime_SuccessSRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "success_sra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.SuccessFRA!UBUS:fast.line.1/stats//showtime.success_fra*/
static int get_FASTLineStatsShowtime_SuccessFRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "success_fra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.SuccessRPA!UBUS:fast.line.1/stats//showtime.success_rpa*/
static int get_FASTLineStatsShowtime_SuccessRPA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "success_rpa");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.Showtime.SuccessTIGA!UBUS:fast.line.1/stats//showtime.success_tiga*/
static int get_FASTLineStatsShowtime_SuccessTIGA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "showtime", "success_tiga");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.ErroredSecs!UBUS:fast.line.1/stats//lastshowtime.errored_secs*/
static int get_FASTLineStatsLastShowtime_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.SeverelyErroredSecs!UBUS:fast.line.1/stats//lastshowtime.severely_errored_secs*/
static int get_FASTLineStatsLastShowtime_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "severely_errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.LOSS!UBUS:fast.line.1/stats//lastshowtime.loss*/
static int get_FASTLineStatsLastShowtime_LOSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "loss");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.LORS!UBUS:fast.line.1/stats//lastshowtime.lors*/
static int get_FASTLineStatsLastShowtime_LORS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "lors");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.UAS!UBUS:fast.line.1/stats//lastshowtime.uas*/
static int get_FASTLineStatsLastShowtime_UAS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "uas");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.RTXUC!UBUS:fast.line.1/stats//lastshowtime.rtx_uc*/
static int get_FASTLineStatsLastShowtime_RTXUC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "rtx_uc");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.RTXTX!UBUS:fast.line.1/stats//lastshowtime.rtx_tx*/
static int get_FASTLineStatsLastShowtime_RTXTX(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "rtx_tx");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.SuccessBSW!UBUS:fast.line.1/stats//lastshowtime.success_bsw*/
static int get_FASTLineStatsLastShowtime_SuccessBSW(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "success_bsw");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.SuccessSRA!UBUS:fast.line.1/stats//lastshowtime.success_sra*/
static int get_FASTLineStatsLastShowtime_SuccessSRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "success_sra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.SuccessFRA!UBUS:fast.line.1/stats//lastshowtime.success_fra*/
static int get_FASTLineStatsLastShowtime_SuccessFRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "success_fra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.SuccessRPA!UBUS:fast.line.1/stats//lastshowtime.success_rpa*/
static int get_FASTLineStatsLastShowtime_SuccessRPA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "success_rpa");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.LastShowtime.SuccessTIGA!UBUS:fast.line.1/stats//lastshowtime.success_tiga*/
static int get_FASTLineStatsLastShowtime_SuccessTIGA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "lastshowtime", "success_tiga");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.ErroredSecs!UBUS:fast.line.1/stats//currentday.errored_secs*/
static int get_FASTLineStatsCurrentDay_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.SeverelyErroredSecs!UBUS:fast.line.1/stats//currentday.severely_errored_secs*/
static int get_FASTLineStatsCurrentDay_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "severely_errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.LOSS!UBUS:fast.line.1/stats//currentday.loss*/
static int get_FASTLineStatsCurrentDay_LOSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "loss");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.LORS!UBUS:fast.line.1/stats//currentday.lors*/
static int get_FASTLineStatsCurrentDay_LORS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "lors");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.UAS!UBUS:fast.line.1/stats//currentday.uas*/
static int get_FASTLineStatsCurrentDay_UAS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "uas");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.RTXUC!UBUS:fast.line.1/stats//currentday.rtx_uc*/
static int get_FASTLineStatsCurrentDay_RTXUC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "rtx_uc");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.RTXTX!UBUS:fast.line.1/stats//currentday.rtx_tx*/
static int get_FASTLineStatsCurrentDay_RTXTX(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "rtx_tx");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.SuccessBSW!UBUS:fast.line.1/stats//currentday.success_bsw*/
static int get_FASTLineStatsCurrentDay_SuccessBSW(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "success_bsw");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.SuccessSRA!UBUS:fast.line.1/stats//currentday.success_sra*/
static int get_FASTLineStatsCurrentDay_SuccessSRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "success_sra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.SuccessFRA!UBUS:fast.line.1/stats//currentday.success_fra*/
static int get_FASTLineStatsCurrentDay_SuccessFRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "success_fra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.SuccessRPA!UBUS:fast.line.1/stats//currentday.success_rpa*/
static int get_FASTLineStatsCurrentDay_SuccessRPA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "success_rpa");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.CurrentDay.SuccessTIGA!UBUS:fast.line.1/stats//currentday.success_tiga*/
static int get_FASTLineStatsCurrentDay_SuccessTIGA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "currentday", "success_tiga");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.ErroredSecs!UBUS:fast.line.1/stats//quarterhour.errored_secs*/
static int get_FASTLineStatsQuarterHour_ErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.SeverelyErroredSecs!UBUS:fast.line.1/stats//quarterhour.severely_errored_secs*/
static int get_FASTLineStatsQuarterHour_SeverelyErroredSecs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "severely_errored_secs");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.LOSS!UBUS:fast.line.1/stats//quarterhour.loss*/
static int get_FASTLineStatsQuarterHour_LOSS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "loss");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.LORS!UBUS:fast.line.1/stats//quarterhour.lors*/
static int get_FASTLineStatsQuarterHour_LORS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "lors");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.UAS!UBUS:fast.line.1/stats//quarterhour.uas*/
static int get_FASTLineStatsQuarterHour_UAS(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "uas");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.RTXUC!UBUS:fast.line.1/stats//quarterhour.rtx_uc*/
static int get_FASTLineStatsQuarterHour_RTXUC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "rtx_uc");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.RTXTX!UBUS:fast.line.1/stats//quarterhour.rtx_tx*/
static int get_FASTLineStatsQuarterHour_RTXTX(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "rtx_tx");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.SuccessBSW!UBUS:fast.line.1/stats//quarterhour.success_bsw*/
static int get_FASTLineStatsQuarterHour_SuccessBSW(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "success_bsw");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.SuccessSRA!UBUS:fast.line.1/stats//quarterhour.success_sra*/
static int get_FASTLineStatsQuarterHour_SuccessSRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "success_sra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.SuccessFRA!UBUS:fast.line.1/stats//quarterhour.success_fra*/
static int get_FASTLineStatsQuarterHour_SuccessFRA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "success_fra");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.SuccessRPA!UBUS:fast.line.1/stats//quarterhour.success_rpa*/
static int get_FASTLineStatsQuarterHour_SuccessRPA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "success_rpa");
	return 0;
}

/*#Device.FAST.Line.{i}.Stats.QuarterHour.SuccessTIGA!UBUS:fast.line.1/stats//quarterhour.success_tiga*/
static int get_FASTLineStatsQuarterHour_SuccessTIGA(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_value_with_argument("fast.line", ((struct fast_line_args*)data)->id, "stats", "quarterhour", "success_tiga");
	return 0;
}

/* *** Device.FAST. *** */
DMOBJ tFASTObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Line", &DMREAD, NULL, NULL, NULL, browseFASTLineInst, NULL, tFASTLineObj, tFASTLineParams, get_fast_line_linker, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

DMLEAF tFASTParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"LineNumberOfEntries", &DMREAD, DMT_UNINT, get_FAST_LineNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}. *** */
DMOBJ tFASTLineObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, tFASTLineStatsObj, tFASTLineStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tFASTLineParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_FASTLine_Enable, set_FASTLine_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_FASTLine_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_FASTLine_Alias, set_FASTLine_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_FASTLine_Name, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_FASTLine_LowerLayers, set_FASTLine_LowerLayers, BBFDM_BOTH},
{"Upstream", &DMREAD, DMT_BOOL, get_FASTLine_Upstream, NULL, BBFDM_BOTH},
{"FirmwareVersion", &DMREAD, DMT_STRING, get_FASTLine_FirmwareVersion, NULL, BBFDM_BOTH},
{"LinkStatus", &DMREAD, DMT_STRING, get_FASTLine_LinkStatus, NULL, BBFDM_BOTH},
{"AllowedProfiles", &DMREAD, DMT_STRING, get_FASTLine_AllowedProfiles, NULL, BBFDM_BOTH},
{"CurrentProfile", &DMREAD, DMT_STRING, get_FASTLine_CurrentProfile, NULL, BBFDM_BOTH},
{"PowerManagementState", &DMREAD, DMT_STRING, get_FASTLine_PowerManagementState, NULL, BBFDM_BOTH},
{"SuccessFailureCause", &DMREAD, DMT_UNINT, get_FASTLine_SuccessFailureCause, NULL, BBFDM_BOTH},
{"UPBOKLER", &DMREAD, DMT_UNINT, get_FASTLine_UPBOKLER, NULL, BBFDM_BOTH},
{"UPBOKLE", &DMREAD, DMT_UNINT, get_FASTLine_UPBOKLE, NULL, BBFDM_BOTH},
{"LineNumber", &DMREAD, DMT_INT, get_FASTLine_LineNumber, NULL, BBFDM_BOTH},
{"UpstreamMaxBitRate", &DMREAD, DMT_UNINT, get_FASTLine_UpstreamMaxBitRate, NULL, BBFDM_BOTH},
{"DownstreamMaxBitRate", &DMREAD, DMT_UNINT, get_FASTLine_DownstreamMaxBitRate, NULL, BBFDM_BOTH},
{"UpstreamNoiseMargin", &DMREAD, DMT_INT, get_FASTLine_UpstreamNoiseMargin, NULL, BBFDM_BOTH},
{"DownstreamNoiseMargin", &DMREAD, DMT_INT, get_FASTLine_DownstreamNoiseMargin, NULL, BBFDM_BOTH},
{"UpstreamAttenuation", &DMREAD, DMT_INT, get_FASTLine_UpstreamAttenuation, NULL, BBFDM_BOTH},
{"DownstreamAttenuation", &DMREAD, DMT_INT, get_FASTLine_DownstreamAttenuation, NULL, BBFDM_BOTH},
{"UpstreamPower", &DMREAD, DMT_INT, get_FASTLine_UpstreamPower, NULL, BBFDM_BOTH},
{"DownstreamPower", &DMREAD, DMT_INT, get_FASTLine_DownstreamPower, NULL, BBFDM_BOTH},
{"SNRMRMCds", &DMREAD, DMT_INT, get_FASTLine_SNRMRMCds, NULL, BBFDM_BOTH},
{"SNRMRMCus", &DMREAD, DMT_INT, get_FASTLine_SNRMRMCus, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}.Stats. *** */
DMOBJ tFASTLineStatsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Total", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tFASTLineStatsTotalParams, NULL, BBFDM_BOTH},
{"Showtime", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tFASTLineStatsShowtimeParams, NULL, BBFDM_BOTH},
{"LastShowtime", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tFASTLineStatsLastShowtimeParams, NULL, BBFDM_BOTH},
{"CurrentDay", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tFASTLineStatsCurrentDayParams, NULL, BBFDM_BOTH},
{"QuarterHour", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tFASTLineStatsQuarterHourParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tFASTLineStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_FASTLineStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_FASTLineStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_FASTLineStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_FASTLineStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_FASTLineStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_FASTLineStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_FASTLineStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_FASTLineStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"TotalStart", &DMREAD, DMT_UNINT, get_FASTLineStats_TotalStart, NULL, BBFDM_BOTH},
{"ShowtimeStart", &DMREAD, DMT_UNINT, get_FASTLineStats_ShowtimeStart, NULL, BBFDM_BOTH},
{"LastShowtimeStart", &DMREAD, DMT_UNINT, get_FASTLineStats_LastShowtimeStart, NULL, BBFDM_BOTH},
{"CurrentDayStart", &DMREAD, DMT_UNINT, get_FASTLineStats_CurrentDayStart, NULL, BBFDM_BOTH},
{"QuarterHourStart", &DMREAD, DMT_UNINT, get_FASTLineStats_QuarterHourStart, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}.Stats.Total. *** */
DMLEAF tFASTLineStatsTotalParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_ErroredSecs, NULL, BBFDM_BOTH},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_SeverelyErroredSecs, NULL, BBFDM_BOTH},
{"LOSS", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_LOSS, NULL, BBFDM_BOTH},
{"LORS", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_LORS, NULL, BBFDM_BOTH},
{"UAS", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_UAS, NULL, BBFDM_BOTH},
{"RTXUC", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_RTXUC, NULL, BBFDM_BOTH},
{"RTXTX", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_RTXTX, NULL, BBFDM_BOTH},
{"SuccessBSW", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_SuccessBSW, NULL, BBFDM_BOTH},
{"SuccessSRA", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_SuccessSRA, NULL, BBFDM_BOTH},
{"SuccessFRA", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_SuccessFRA, NULL, BBFDM_BOTH},
{"SuccessRPA", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_SuccessRPA, NULL, BBFDM_BOTH},
{"SuccessTIGA", &DMREAD, DMT_UNINT, get_FASTLineStatsTotal_SuccessTIGA, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}.Stats.Showtime. *** */
DMLEAF tFASTLineStatsShowtimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_ErroredSecs, NULL, BBFDM_BOTH},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_SeverelyErroredSecs, NULL, BBFDM_BOTH},
{"LOSS", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_LOSS, NULL, BBFDM_BOTH},
{"LORS", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_LORS, NULL, BBFDM_BOTH},
{"UAS", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_UAS, NULL, BBFDM_BOTH},
{"RTXUC", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_RTXUC, NULL, BBFDM_BOTH},
{"RTXTX", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_RTXTX, NULL, BBFDM_BOTH},
{"SuccessBSW", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_SuccessBSW, NULL, BBFDM_BOTH},
{"SuccessSRA", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_SuccessSRA, NULL, BBFDM_BOTH},
{"SuccessFRA", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_SuccessFRA, NULL, BBFDM_BOTH},
{"SuccessRPA", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_SuccessRPA, NULL, BBFDM_BOTH},
{"SuccessTIGA", &DMREAD, DMT_UNINT, get_FASTLineStatsShowtime_SuccessTIGA, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}.Stats.LastShowtime. *** */
DMLEAF tFASTLineStatsLastShowtimeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_ErroredSecs, NULL, BBFDM_BOTH},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_SeverelyErroredSecs, NULL, BBFDM_BOTH},
{"LOSS", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_LOSS, NULL, BBFDM_BOTH},
{"LORS", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_LORS, NULL, BBFDM_BOTH},
{"UAS", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_UAS, NULL, BBFDM_BOTH},
{"RTXUC", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_RTXUC, NULL, BBFDM_BOTH},
{"RTXTX", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_RTXTX, NULL, BBFDM_BOTH},
{"SuccessBSW", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_SuccessBSW, NULL, BBFDM_BOTH},
{"SuccessSRA", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_SuccessSRA, NULL, BBFDM_BOTH},
{"SuccessFRA", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_SuccessFRA, NULL, BBFDM_BOTH},
{"SuccessRPA", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_SuccessRPA, NULL, BBFDM_BOTH},
{"SuccessTIGA", &DMREAD, DMT_UNINT, get_FASTLineStatsLastShowtime_SuccessTIGA, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}.Stats.CurrentDay. *** */
DMLEAF tFASTLineStatsCurrentDayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_ErroredSecs, NULL, BBFDM_BOTH},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_SeverelyErroredSecs, NULL, BBFDM_BOTH},
{"LOSS", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_LOSS, NULL, BBFDM_BOTH},
{"LORS", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_LORS, NULL, BBFDM_BOTH},
{"UAS", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_UAS, NULL, BBFDM_BOTH},
{"RTXUC", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_RTXUC, NULL, BBFDM_BOTH},
{"RTXTX", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_RTXTX, NULL, BBFDM_BOTH},
{"SuccessBSW", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_SuccessBSW, NULL, BBFDM_BOTH},
{"SuccessSRA", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_SuccessSRA, NULL, BBFDM_BOTH},
{"SuccessFRA", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_SuccessFRA, NULL, BBFDM_BOTH},
{"SuccessRPA", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_SuccessRPA, NULL, BBFDM_BOTH},
{"SuccessTIGA", &DMREAD, DMT_UNINT, get_FASTLineStatsCurrentDay_SuccessTIGA, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.FAST.Line.{i}.Stats.QuarterHour. *** */
DMLEAF tFASTLineStatsQuarterHourParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_ErroredSecs, NULL, BBFDM_BOTH},
{"SeverelyErroredSecs", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_SeverelyErroredSecs, NULL, BBFDM_BOTH},
{"LOSS", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_LOSS, NULL, BBFDM_BOTH},
{"LORS", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_LORS, NULL, BBFDM_BOTH},
{"UAS", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_UAS, NULL, BBFDM_BOTH},
{"RTXUC", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_RTXUC, NULL, BBFDM_BOTH},
{"RTXTX", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_RTXTX, NULL, BBFDM_BOTH},
{"SuccessBSW", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_SuccessBSW, NULL, BBFDM_BOTH},
{"SuccessSRA", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_SuccessSRA, NULL, BBFDM_BOTH},
{"SuccessFRA", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_SuccessFRA, NULL, BBFDM_BOTH},
{"SuccessRPA", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_SuccessRPA, NULL, BBFDM_BOTH},
{"SuccessTIGA", &DMREAD, DMT_UNINT, get_FASTLineStatsQuarterHour_SuccessTIGA, NULL, BBFDM_BOTH},
{0}
};
