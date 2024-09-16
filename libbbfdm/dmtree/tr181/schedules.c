/*
 * Copyright (C) 2024 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * Author: Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 */

#include "schedules.h"

static char *allowed_days[] = {"Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday", NULL};

/*************************************************************
* ADD & DEL METHODS
**************************************************************/
static int addSchedule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char s_name[16] = {0};
	int i;

	snprintf(s_name, sizeof(s_name), "schedule_%s", *instance);

	dmuci_add_section("schedules", "schedule", &s);
	dmuci_rename_section_by_section(s, s_name);

	dmuci_set_value_by_section(s, "enable", "0");
	
	for (i = 0; allowed_days[i] != NULL; i++) {
		dmuci_add_list_value_by_section(s, "day", allowed_days[i]);
	}

	dmuci_set_value_by_section(s, "duration", "1");

	dmuci_add_section_bbfdm("dmmap_schedules", "schedule", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_s, "schedule_instance", *instance);
	return 0;
}

static int delSchedule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
	dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);

	return 0;
}

/*************************************************************
 * ENTRY METHODS
 *************************************************************/
static int browseScheduleInstance(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("schedules", "schedule", "dmmap_schedules", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "schedule_instance", "schedule_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
 * GET/SET METHODS
 *************************************************************/
static int get_schedules_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("schedules", "global", "enable", "0");
	return 0;
}

static int set_schedules_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	int ret = 0;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			ret = FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value("schedules", "global", "enable", b ? "1" : "0");
		break;
	}

	return ret;
}

static int get_schedule_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned int cnt = get_number_of_entries(ctx, data, instance, browseScheduleInstance);
	dmasprintf(value, "%u", cnt);
	return 0;
}

static int get_schedule_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_schedule_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	int ret = 0;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			ret = FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
		break;
	}

	return ret;
}

static int get_schedule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "schedule_alias", instance, value);
}

static int set_schedule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "schedule_alias", instance, value);
}

static int get_schedule_desc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "desc", value);
	return 0;
}

static int set_schedule_desc(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int ret = 0;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
			ret = FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "desc", value);
		break;
	}

	return ret;
}

static int get_schedule_day(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val = NULL;
	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "day", &val);
	*value = dmuci_list_to_string(val, ",");
	return 0;
}

static int set_schedule_day(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length, i;
	int ret = 0;
	char **arr;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string_list(ctx, value, 1, -1, -1, -1, -1, allowed_days, NULL))
			ret = FAULT_9007;
		break;
	case VALUESET:
		arr = strsplit(value, ",", &length);
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "day", "");
		for (i = 0; i < length; i++)
			dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "day", arr[i]);
		break;
	}

	return ret;
}

static int get_schedule_start(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "start", value);
	return 0;
}

static int set_schedule_start(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int ret = 0;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 5, NULL, NULL))
			ret = FAULT_9007;

		char *reg_exp = "^([01][0-9]|2[0-3]):[0-5][0-9]$";
		if (match(value, reg_exp, 0, NULL) != true)
			ret = FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "start", value);
		break;
	}

	return ret;
}

static int get_schedule_duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "duration", "1");
	return 0;
}

static int set_schedule_duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int ret = 0;

	switch (action) {
	case VALUECHECK:
		if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1", NULL}}, 1))
			ret = FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "duration", value);
		break;
	}

	return ret;
}

static int dayname_to_week_day(const char *day)
{
	if (DM_STRCMP(day, "Sunday") == 0)
		return 0;

	if (DM_STRCMP(day, "Monday") == 0)
		return 1;

	if (DM_STRCMP(day, "Tuesday") == 0)
		return 2;

	if (DM_STRCMP(day, "Wednesday") == 0)
		return 3;

	if (DM_STRCMP(day, "Thursday") == 0)
		return 4;

	if (DM_STRCMP(day, "Friday") == 0)
		return 5;

	if (DM_STRCMP(day, "Saturday") == 0)
		return 6;

	return -1;
}

static char *get_status(char *start, char *period, char *day)
{
	struct tm *info = NULL;
	unsigned int s_day, s_hr, s_min, s_sec, e_day, e_hr, e_min, e_sec;
	time_t ctime;
	size_t length, i;
	char **arr;
	unsigned int duration = 0;

	if (DM_STRLEN(day) == 0)
		return "Error";

	time(&ctime);
	info = localtime(&ctime);
	if (!info)
		return "Error";

	// If no start time given
	if (DM_STRLEN(start) == 0) {
		arr = strsplit(day, ",", &length);
		for (i = 0; i < length; i++) {
			int w_day = dayname_to_week_day(arr[i]);
			if (w_day == -1)
				return "Error";

			if (info->tm_wday == w_day) {
				return "Active";
			}
		}

		return "Inactive";
	}

	// When start time is given
	duration = DM_STRTOUL(period);

	if (2 != sscanf(start, "%u:%u", &s_hr, &s_min))
		return "Error";

	s_sec = 0;

	int day_add = 0;
	e_hr = s_hr + (duration / 3600);

	if (e_hr > 23) {
		day_add = e_hr / 24;
		e_hr = e_hr - (day_add * 24);
	}

	duration = duration % 3600;

	e_min = s_min + (duration / 60);
	e_sec = duration % 60;

	unsigned int cur_sec = info->tm_hour * 3600 + info->tm_min * 60 + info->tm_sec;
	unsigned int start_sec = s_hr * 3600 + s_min * 60 + s_sec;
	unsigned int end_sec = e_hr * 3600 + e_min *60 + e_sec;

	arr = strsplit(day, ",", &length);
	for (i = 0; i < length; i++) {
		s_day = dayname_to_week_day(arr[i]);
		if (s_day == -1)
			return "Error";

		e_day = s_day + day_add;

		if (info->tm_wday >= s_day && info->tm_wday <= e_day) {
			if (s_day == e_day) {
				if ((cur_sec >= start_sec) && (cur_sec <= end_sec)) {
					return "Active";
				}
				continue;
			}

			if (info->tm_wday == s_day) {
				if (cur_sec >= start_sec) {
					return "Active";
				}
				continue;
			}

			if (info->tm_wday == e_day) {
				if (cur_sec <= end_sec) {
					return "Active";
				}
				continue;
			}

			return "Active";
		}
	}

	return "Inactive";
}

static int get_schedule_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool glob_enable, inst_enable;
	char *val = NULL, *day = NULL, *start = NULL, *duration = NULL;
	struct uci_list *day_list = NULL;

	val = dmuci_get_option_value_fallback_def("schedules", "global", "enable", "0");
	string_to_bool(val, &glob_enable);

	val = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	string_to_bool(val, &inst_enable);

	if (glob_enable == false && inst_enable == true) {
		*value = "StackDisabled";
		return 0;
	}

	if (!inst_enable) {
		*value = "Inactive";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "start", &start);

	duration = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "duration", "1");

	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "day", &day_list);
	day = dmuci_list_to_string(day_list, ",");

	*value = get_status(start, duration, day);

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Schedules. *** */
DMOBJ tSchedulesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Schedule", &DMWRITE, addSchedule, delSchedule, NULL, browseScheduleInstance, NULL, NULL, NULL, tScheduleParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tSchedulesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_schedules_enable, set_schedules_enable, BBFDM_BOTH},
{"ScheduleNumberOfEntries", &DMREAD, DMT_UNINT, get_schedule_number, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tScheduleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_schedule_alias, set_schedule_alias, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"Enable", &DMWRITE, DMT_BOOL, get_schedule_enable, set_schedule_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_schedule_status, NULL, BBFDM_BOTH},
{"Description", &DMWRITE, DMT_STRING, get_schedule_desc, set_schedule_desc, BBFDM_BOTH},
{"Day", &DMWRITE, DMT_STRING, get_schedule_day, set_schedule_day, BBFDM_BOTH},
{"StartTime", &DMWRITE, DMT_STRING, get_schedule_start, set_schedule_start, BBFDM_BOTH},
{"Duration", &DMWRITE, DMT_UNINT, get_schedule_duration, set_schedule_duration, BBFDM_BOTH},
{0}
};
