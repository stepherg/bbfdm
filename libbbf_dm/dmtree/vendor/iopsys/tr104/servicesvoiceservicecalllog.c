/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	Author Grzegorz Sluja <grzegorz.sluja@iopsys.eu>
 */

#include "servicesvoiceservicecalllog.h"
#include "common.h"

static int get_ServicesVoiceServiceCallLog_SipIpAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->sipIpAddress) : "";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_SipResponseCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->sipResponseCode) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_BurstDensity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localBurstDensity) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_BurstDensity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteBurstDensity) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_BurstDuration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localBurstDuration) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_BurstDuration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteBurstDuration) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_GapDensity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localGapDensity) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_GapDensity(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteGapDensity) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_GapDuration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localGapDuration) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_GapDuration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteGapDuration) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_JBAvgDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localJbRate) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_JBAvgDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteJbRate) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_JBMaxDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localJbMax) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_JBMaxDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteJbMax) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_JBNomDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localJbNominal) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_JBNomDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteJbNominal) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_PeakJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localJbAbsMax) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Dst_PeakJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteJbAbsMax) : "0";
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CallLog.{i}. *** */
DMLEAF tIOPSYS_VoiceServiceCallLogParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"SIPIPAddress", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_SipIpAddress, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"SIPResponseCode", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_SipResponseCode, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.RTP. *** */
DMLEAF tIOPSYS_VoiceServiceCallLogSessionSourceRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"BurstDensity", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_BurstDensity, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"BurstDuration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_BurstDuration, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"GapDensity", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_GapDensity, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"GapDuration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_GapDuration, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"JBAvgDelay", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_JBAvgDelay, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"JBMaxDelay", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_JBMaxDelay, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"JBNomDelay", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_JBNomDelay, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"PeakJitter", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_PeakJitter, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.RTP. *** */
DMLEAF tIOPSYS_VoiceServiceCallLogSessionDestinationRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"BurstDensity", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_BurstDensity, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"BurstDuration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_BurstDuration, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"GapDensity", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_GapDensity, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"GapDuration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_GapDuration, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"JBAvgDelay", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_JBAvgDelay, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"JBMaxDelay", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_JBMaxDelay, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"JBNomDelay", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_JBNomDelay, NULL, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"PeakJitter", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Dst_PeakJitter, NULL, BBFDM_BOTH},
{0}
};
