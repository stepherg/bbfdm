/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicecapabilities.h"
#include "common.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseServicesVoiceServiceCapabilitiesCodecInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int i;
	char inst[8];

	if (codecs_num <= 0)
		init_supported_codecs();

	for (i = 0; i < codecs_num; i++) {
		snprintf(inst, sizeof(inst), "%d", i + 1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&supported_codecs[i], inst) == DM_STOP)
			break;
	}

	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ServicesVoiceServiceCapabilities_MaxLineCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("hw", "board", "VoicePorts", value);
	return 0;
}

static int get_ServicesVoiceServiceCapabilities_MaxSessionsPerLine(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "2";
	return 0;
}

static int get_ServicesVoiceServiceCapabilities_MaxSessionCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *max_line;

	db_get_value_string("hw", "board", "VoicePorts", &max_line);
	if (max_line && *max_line) {
		int max_session = 2 * atoi(max_line);
		dmasprintf(value, "%d", max_session);
	}

	return 0;
}

static int get_ServicesVoiceServiceCapabilities_NetworkConnectionModes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "SIP/2.0";
	return 0;
}

static int get_ServicesVoiceServiceCapabilities_UserConnectionModes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "FXS";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_Extensions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "OPTIONS,REFER,SUBSCRIBE,NOTIFY,INFO,PUBLISH,MESSAGE";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_URISchemes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "sip";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_TLSAuthenticationProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	// Reference to https://en.wikipedia.org/wiki/OpenSSL#Algorithms
	*value = "MD5,SHA-1,SHA-2";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_TLSAuthenticationKeySizes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "128,160,256";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_TLSEncryptionProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "AES,Blowfish,Camellia,SEED,CAST-128,IDEA,RC5,3DES,SM4";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_TLSEncryptionKeySizes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "256,32-448,256,128,40-128,128,128,168,128";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesSIPClient_TLSKeyExchangeProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "RSA,DSA,Diffie–Hellman key exchange,Elliptic curve,X25519,Ed25519,X448,Ed448,SM2";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesPOTS_DialType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Tone";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesPOTS_ClipGeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesPOTS_ChargingPulse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesCodec_Codec(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (data) {
		struct codec_info *codec = (struct codec_info *)data;
		*value = dmstrdup(codec->codec);
	}
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesCodec_BitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (data) {
		struct codec_info *codec = (struct codec_info *)data;
		dmasprintf(value, "%d", codec->bit_rate);
	}
	return 0;
}

static int get_ServicesVoiceServiceCapabilitiesCodec_PacketizationPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (data) {
		struct codec_info *codec = (struct codec_info *)data;
		*value = dmstrdup(codec->packetization_period);
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.Capabilities. *** */
DMOBJ tServicesVoiceServiceCapabilitiesObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"SIP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesSIPObj, NULL, NULL, BBFDM_BOTH},
{"POTS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesPOTSParams, NULL, BBFDM_BOTH},
{"Codec", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceCapabilitiesCodecInst, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesCodecParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceCapabilitiesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MaxLineCount", &DMREAD, DMT_INT, get_ServicesVoiceServiceCapabilities_MaxLineCount, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxSessionsPerLine", &DMREAD, DMT_INT, get_ServicesVoiceServiceCapabilities_MaxSessionsPerLine, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxSessionCount", &DMREAD, DMT_INT, get_ServicesVoiceServiceCapabilities_MaxSessionCount, NULL, NULL, NULL, BBFDM_BOTH},
{"NetworkConnectionModes", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilities_NetworkConnectionModes, NULL, NULL, NULL, BBFDM_BOTH},
{"UserConnectionModes", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilities_UserConnectionModes, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities.SIP. *** */
DMOBJ tServicesVoiceServiceCapabilitiesSIPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Client", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesSIPClientParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities.SIP.Client. *** */
DMLEAF tServicesVoiceServiceCapabilitiesSIPClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Extensions", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_Extensions, NULL, NULL, NULL, BBFDM_BOTH},
{"URISchemes", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_URISchemes, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSAuthenticationProtocols", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_TLSAuthenticationProtocols, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSAuthenticationKeySizes", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_TLSAuthenticationKeySizes, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSEncryptionProtocols", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_TLSEncryptionProtocols, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSEncryptionKeySizes", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_TLSEncryptionKeySizes, NULL, NULL, NULL, BBFDM_BOTH},
{"TLSKeyExchangeProtocols", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesSIPClient_TLSKeyExchangeProtocols, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities.POTS. *** */
DMLEAF tServicesVoiceServiceCapabilitiesPOTSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DialType", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesPOTS_DialType, NULL, NULL, NULL, BBFDM_BOTH},
{"ClipGeneration", &DMREAD, DMT_BOOL, get_ServicesVoiceServiceCapabilitiesPOTS_ClipGeneration, NULL, NULL, NULL, BBFDM_BOTH},
{"ChargingPulse", &DMREAD, DMT_BOOL, get_ServicesVoiceServiceCapabilitiesPOTS_ChargingPulse, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.Capabilities.Codec.{i}. *** */
DMLEAF tServicesVoiceServiceCapabilitiesCodecParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Codec", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesCodec_Codec, NULL, NULL, NULL, BBFDM_BOTH},
{"BitRate", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceCapabilitiesCodec_BitRate, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketizationPeriod", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCapabilitiesCodec_PacketizationPeriod, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

