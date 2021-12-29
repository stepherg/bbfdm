/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "dmentry.h"
#include "servicesvoiceservicecodecprofile.h"
#include "common.h"

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Services.VoiceService.{i}.CodecProfile.{i}.Codec!UCI:asterisk/codec_profile,@i-1/name*/
static int get_ServicesVoiceServiceCodecProfile_Codec(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", &linker);
	adm_entry_get_linker_param(ctx, "Device.Services.VoiceService.", linker, value);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CodecProfile.{i}.PacketizationPeriod!UCI:asterisk/codec_profile,@i-1/ptime*/
static int get_ServicesVoiceServiceCodecProfile_PacketizationPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ptime", value);
	return 0;
}

static int set_ServicesVoiceServiceCodecProfile_PacketizationPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ptime", value);
			break;
	}
	return 0;
}

/*Get Device.Services.VoiceService.{i}.CodecProfile.{i}. Alias*/
static int get_ServicesVoiceServiceCodecProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "codecprofilealias");
}

/*Set Device.Services.VoiceService.{i}.CodecProfile.{i}. Alias*/
static int set_ServicesVoiceServiceCodecProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "codecprofilealias");
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CodecProfile.{i}. *** */
DMLEAF tServicesVoiceServiceCodecProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Codec", &DMREAD, DMT_STRING, get_ServicesVoiceServiceCodecProfile_Codec, NULL, BBFDM_BOTH},
{"PacketizationPeriod", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCodecProfile_PacketizationPeriod, set_ServicesVoiceServiceCodecProfile_PacketizationPeriod, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCodecProfile_Alias, set_ServicesVoiceServiceCodecProfile_Alias, BBFDM_BOTH},
{0}
};

