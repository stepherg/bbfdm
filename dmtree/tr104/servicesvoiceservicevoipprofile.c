/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicevoipprofile.h"
#include "common.h"

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.DTMFMethod!UCI:asterisk/sip_advanced,sip_options/dtmfmode*/
static int get_ServicesVoiceServiceVoIPProfile_DTMFMethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *method = NULL;

	dmuci_get_option_value_string(TR104_UCI_PACKAGE, "sip_options", "dtmfmode", &method);
	if (method && *method) {
		if (strcasecmp(method, "inband") == 0)
			*value = "InBand";
		else if (strcasecmp(method, "rfc2833") == 0)
			*value = "RFC4733";
		else if (strcasestr(method, "info") != NULL)
			*value = "SIPInfo";
	}

	return 0;
}

static int set_ServicesVoiceServiceVoIPProfile_DTMFMethod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *new_value = "";

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, DTMFMethod, 3, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "InBand") == 0)
				new_value = "inband";
			else if (strcasecmp(value, "RFC4733") == 0)
				new_value = "rfc2833";
			else if (strcasecmp(value, "SIPInfo") == 0)
				new_value = "info";
			dmuci_set_value(TR104_UCI_PACKAGE, "sip_options", "dtmfmode", new_value);
			break;
	}

	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.LocalPortMin!UCI:asterisk/sip_advanced,sip_options/rtpstart*/
static int get_ServicesVoiceServiceVoIPProfileRTP_LocalPortMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "rtpstart", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTP_LocalPortMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "rtpstart", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.LocalPortMax!UCI:asterisk/sip_advanced,sip_options/rtpend*/
static int get_ServicesVoiceServiceVoIPProfileRTP_LocalPortMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "rtpend", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTP_LocalPortMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "rtpend", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.DSCPMark!UCI:asterisk/sip_advanced,sip_options/tos_audio*/
static int get_ServicesVoiceServiceVoIPProfileRTP_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "tos_audio", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTP_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "tos_audio", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.TelephoneEventPayloadType!UCI:asterisk/tel_advanced,tel_options/tel_event_pt*/
static int get_ServicesVoiceServiceVoIPProfileRTP_TelephoneEventPayloadType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "tel_options", "tel_event_pt", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTP_TelephoneEventPayloadType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"96","127"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "tel_options", "tel_event_pt", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.JitterBufferType!UCI:asterisk/tel_advanced,tel_options/jbimpl*/
static int get_ServicesVoiceServiceVoIPProfileRTP_JitterBufferType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "tel_options", "jbimpl", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTP_JitterBufferType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, JitterBufferType, 2, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "tel_options", "jbimpl", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.JitterBufferMaxSize!UCI:asterisk/tel_advanced,tel_options/jbmaxsize*/
static int get_ServicesVoiceServiceVoIPProfileRTP_JitterBufferMaxSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "tel_options", "jbmaxsize", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTP_JitterBufferMaxSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "tel_options", "jbmaxsize", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.RTCP.TxRepeatInterval!UCI:asterisk/sip_advanced,sip_options/rtcpinterval*/
static int get_ServicesVoiceServiceVoIPProfileRTPRTCP_TxRepeatInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "rtcpinterval", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTPRTCP_TxRepeatInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "rtcpinterval", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.SRTP.Enable!UCI:asterisk/sip_service_provider,@i-1/encryption*/
static int get_ServicesVoiceServiceVoIPProfileRTPSRTP_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "encryption", value);
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTPSRTP_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "encryption", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceVoIPProfileRTPSRTP_KeyingMethods(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "SDP";
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTPSRTP_KeyingMethods(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, KeyingMethods, 4, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			// To be supported in the future perhaps
			return FAULT_9000;
	}
	return 0;
}

static int get_ServicesVoiceServiceVoIPProfileRTPSRTP_EncryptionKeySizes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "128";
	return 0;
}

static int set_ServicesVoiceServiceVoIPProfileRTPSRTP_EncryptionKeySizes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, -1, -1, -1, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			// To be supported in the future perhaps
			return FAULT_9000;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.VoIPProfile.{i}. *** */
DMOBJ tServicesVoiceServiceVoIPProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"RTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoIPProfileRTPObj, tServicesVoiceServiceVoIPProfileRTPParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceVoIPProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DTMFMethod", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceVoIPProfile_DTMFMethod, set_ServicesVoiceServiceVoIPProfile_DTMFMethod, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP. *** */
DMOBJ tServicesVoiceServiceVoIPProfileRTPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"RTCP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoIPProfileRTPRTCPParams, NULL, BBFDM_BOTH},
{"SRTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceVoIPProfileRTPSRTPParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceVoIPProfileRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LocalPortMin", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceVoIPProfileRTP_LocalPortMin, set_ServicesVoiceServiceVoIPProfileRTP_LocalPortMin, NULL, NULL, BBFDM_BOTH},
{"LocalPortMax", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceVoIPProfileRTP_LocalPortMax, set_ServicesVoiceServiceVoIPProfileRTP_LocalPortMax, NULL, NULL, BBFDM_BOTH},
{"DSCPMark", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceVoIPProfileRTP_DSCPMark, set_ServicesVoiceServiceVoIPProfileRTP_DSCPMark, NULL, NULL, BBFDM_BOTH},
{"TelephoneEventPayloadType", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceVoIPProfileRTP_TelephoneEventPayloadType, set_ServicesVoiceServiceVoIPProfileRTP_TelephoneEventPayloadType, NULL, NULL, BBFDM_BOTH},
{"JitterBufferType", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceVoIPProfileRTP_JitterBufferType, set_ServicesVoiceServiceVoIPProfileRTP_JitterBufferType, NULL, NULL, BBFDM_BOTH},
{"JitterBufferMaxSize", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceVoIPProfileRTP_JitterBufferMaxSize, set_ServicesVoiceServiceVoIPProfileRTP_JitterBufferMaxSize, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.RTCP. *** */
DMLEAF tServicesVoiceServiceVoIPProfileRTPRTCPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"TxRepeatInterval", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceVoIPProfileRTPRTCP_TxRepeatInterval, set_ServicesVoiceServiceVoIPProfileRTPRTCP_TxRepeatInterval, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.SRTP. *** */
DMLEAF tServicesVoiceServiceVoIPProfileRTPSRTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceVoIPProfileRTPSRTP_Enable, set_ServicesVoiceServiceVoIPProfileRTPSRTP_Enable, NULL, NULL, BBFDM_BOTH},
{"KeyingMethods", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceVoIPProfileRTPSRTP_KeyingMethods, set_ServicesVoiceServiceVoIPProfileRTPSRTP_KeyingMethods, NULL, NULL, BBFDM_BOTH},
{"EncryptionKeySizes", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceVoIPProfileRTPSRTP_EncryptionKeySizes, set_ServicesVoiceServiceVoIPProfileRTPSRTP_EncryptionKeySizes, NULL, NULL, BBFDM_BOTH},
{0}
};

