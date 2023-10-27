/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 *	Author: Grzegorz Sluja, grzegorz.sluja@iopsys.eu
 */

#include "servicesvoiceservicecalllog.h"
#include "common.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseServicesVoiceServiceCallLogSessionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	// prev_data is from its parent node SIP.Client.{i}. i.e. the UCI section of asterisk.sip_service_provider
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

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

static int get_ServicesVoiceServiceCallLog_UsedExtensions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;

	if (entry) {
		*value = dmstrdup(entry->used_extensions);
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

static int get_ServicesVoiceServiceCallLog_SessionId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->sessionId) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_SIPSessionId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->SIPSessionId) : "";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_CallTerminationCause(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->termination_cause) : "";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_FarEndIpAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->farEndIPAddress) : "";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_SessionDSPCodec(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	if (entry) {
		const char *codec_name = get_codec_name(entry->codec);
		*value = codec_name ? dmstrdup(codec_name) : "";
	}
	
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_PacketsDiscarded(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->discarded) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_PacketsLost(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->lost) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->rxpkts) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->txpkts) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_ReceiveInterarrivalJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->receiveInterarrivalJitter) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_AverageReceiveInterarrivalJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->averageReceiveInterarrivalJitter) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_FarEndInterarrivalJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->farEndInterarrivalJitter) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_AverageFarEndInterarrivalJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->averageFarEndInterarrivalJitter) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_MaxJitter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->maxJitter) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_AverageRoundTripDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->averageRoundTripDelay) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src__ReceivePacketLossRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->localLossRate) : "0";
	return 0;
}

static int get_ServicesVoiceServiceCallLog_Src_FarEndPacketLossRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct call_log_entry *entry = (struct call_log_entry *)data;
	*value = (entry) ? dmstrdup(entry->remoteLossRate) : "0";
	return 0;
}

/* Get Alias - Device.Services.VoiceService.{i}.CallLog.{i}. */
static int get_ServicesVoiceServiceCallLog_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_name(refparam, ctx, data, instance, value, "callLog", "callLog_inst");
}

/* Set Alias - Device.Services.VoiceService.{i}.CallLog.{i}. */
static int set_ServicesVoiceServiceCallLog_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_name(refparam, ctx, data, instance, value, action, "callLog", "callLog_inst");
}
/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CallLog.{i}. *** */
DMOBJ tServicesVoiceServiceCallLogObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Session", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceCallLogSessionInst, NULL, NULL, tServicesVoiceServiceCallLogSessionObj, tServicesVoiceServiceCallLogSessionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceCallLogParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"CallingPartyNumber", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_CallingPartyNumber, NULL, BBFDM_BOTH},
{"CalledPartyNumber", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_CalledPartyNumber, NULL, BBFDM_BOTH},
{"Source", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_Source, NULL, BBFDM_BOTH},
{"Destination", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_Destination, NULL, BBFDM_BOTH},
{"UsedLine", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_UsedLine, NULL, BBFDM_BOTH},
{"UsedExtensions", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_UsedExtensions, NULL, BBFDM_BOTH},
{"Direction", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_Direction, NULL, BBFDM_BOTH},
{"Start", &DMREAD, DMT_TIME, get_ServicesVoiceServiceCallLog_Start, NULL, BBFDM_BOTH},
{"Duration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Duration, NULL, BBFDM_BOTH},
{"CallTerminationCause", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_CallTerminationCause, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallLog_Alias, set_ServicesVoiceServiceCallLog_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}. *** */
DMOBJ tServicesVoiceServiceCallLogSessionObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Destination", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionDestinationObj, NULL, NULL, BBFDM_BOTH},
{"Source", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionSourceObj, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceCallLogSessionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Duration", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Duration, NULL, BBFDM_BOTH},
{"Start", &DMREAD, DMT_TIME, get_ServicesVoiceServiceCallLog_Start, NULL, BBFDM_BOTH},
{"SessionID", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_SessionId, NULL, BBFDM_BOTH},
{"SIPSessionID", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_SIPSessionId, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination. *** */
DMOBJ tServicesVoiceServiceCallLogSessionDestinationObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DSP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionDestinationDSPObj, NULL, NULL, BBFDM_BOTH},
{"RTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source. *** */
DMOBJ tServicesVoiceServiceCallLogSessionSourceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"DSP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionSourceDSPObj, NULL, NULL, BBFDM_BOTH},
{"RTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionSourceRTPParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.DSP. *** */
DMOBJ tServicesVoiceServiceCallLogSessionDestinationDSPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"ReceiveCodec", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionDestinationDSPCodecParams, NULL, BBFDM_BOTH},
{"TransmitCodec", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionDestinationDSPCodecParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.DSP. *** */
DMOBJ tServicesVoiceServiceCallLogSessionSourceDSPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"ReceiveCodec", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionSourceDSPCodecParams, NULL, BBFDM_BOTH},
{"TransmitCodec", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogSessionSourceDSPCodecParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.DSP.ReceiveCodec. *** */
DMLEAF tServicesVoiceServiceCallLogSessionDestinationDSPCodecParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Codec", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_SessionDSPCodec, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.DSP.ReceiveCodec. *** */
DMLEAF tServicesVoiceServiceCallLogSessionSourceDSPCodecParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Codec", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_SessionDSPCodec, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.RTP. *** */
DMLEAF tServicesVoiceServiceCallLogSessionSourceRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"FarEndIPAddress", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCallLog_FarEndIpAddress, NULL, BBFDM_BOTH},
{"PacketsDiscarded", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_PacketsDiscarded, NULL, BBFDM_BOTH},
{"PacketsLost", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_PacketsLost, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ServicesVoiceServiceCallLog_Src_PacketsReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ServicesVoiceServiceCallLog_Src_PacketsSent, NULL, BBFDM_BOTH},
{"ReceiveInterarrivalJitter", &DMREAD, DMT_INT, get_ServicesVoiceServiceCallLog_Src_ReceiveInterarrivalJitter, NULL, BBFDM_BOTH},
{"AverageReceiveInterarrivalJitter", &DMREAD, DMT_INT, get_ServicesVoiceServiceCallLog_Src_AverageReceiveInterarrivalJitter, NULL, BBFDM_BOTH},
{"FarEndInterarrivalJitter", &DMREAD, DMT_INT, get_ServicesVoiceServiceCallLog_Src_FarEndInterarrivalJitter, NULL, BBFDM_BOTH},
{"AverageFarEndInterarrivalJitter", &DMREAD, DMT_INT, get_ServicesVoiceServiceCallLog_Src_AverageFarEndInterarrivalJitter, NULL, BBFDM_BOTH},
{"FarEndPacketLossRate", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src_FarEndPacketLossRate, NULL, BBFDM_BOTH},
{"MaxJitter", &DMREAD, DMT_INT, get_ServicesVoiceServiceCallLog_Src_MaxJitter, NULL, BBFDM_BOTH},
{"AverageRoundTripDelay", &DMREAD, DMT_INT, get_ServicesVoiceServiceCallLog_Src_AverageRoundTripDelay, NULL, BBFDM_BOTH},
{"ReceivePacketLossRate", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCallLog_Src__ReceivePacketLossRate, NULL, BBFDM_BOTH},
{0}
};
