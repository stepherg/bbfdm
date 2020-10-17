/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicecalllog.h"
#include "common.h"

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ServicesVoiceServiceCallLog_CallingPartyNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->calling_num);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_CalledPartyNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->called_num);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_Source(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->source);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_Destination(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->destination);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_UsedLine(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->used_line);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_Direction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->direction);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_Start(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->start_time);
	}

	return 0;
}

static int get_ServicesVoiceServiceCallLog_Duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->duration) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_CallTerminationCause(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->termination_cause);
	}

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CallLog.{i}. *** */
DMLEAF tServicesVoiceServiceCallLogParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"CallingPartyNumber", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_CallingPartyNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"CalledPartyNumber", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_CalledPartyNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"Source", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_Source, NULL, NULL, NULL, BBFDM_BOTH},
{"Destination", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_Destination, NULL, NULL, NULL, BBFDM_BOTH},
{"UsedLine", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_UsedLine, NULL, NULL, NULL, BBFDM_BOTH},
{"Direction", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_Direction, NULL, NULL, NULL, BBFDM_BOTH},
{"Start", &DMREAD, DMT_TIME, get_ServicesVoiceServiceCallLog_Start, NULL, NULL, NULL, BBFDM_BOTH},
{"Duration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Duration, NULL, NULL, NULL, BBFDM_BOTH},
{"CallTerminationCause", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_CallTerminationCause, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

