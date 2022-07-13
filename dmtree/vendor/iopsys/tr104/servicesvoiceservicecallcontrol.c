/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "servicesvoiceservicecallcontrol.h"
#include "common.h"

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.ComfortNoise!UCI:asterisk/extension,@i-1/comfort_noise*/
static int get_ServicesVoiceServiceCallControlExtension_ComfortNoise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "comfort_noise", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_ComfortNoise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "comfort_noise", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.TXGain!UCI:asterisk/extension,@i-1/txgain*/
static int get_ServicesVoiceServiceCallControlExtension_TXGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "txgain", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_TXGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "txgain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.RXGain!UCI:asterisk/extension,@i-1/rxgain*/
static int get_ServicesVoiceServiceCallControlExtension_RXGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "rxgain", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_RXGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "rxgain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.EchoCancel!UCI:asterisk/extension,@i-1/echo_cancel*/
static int get_ServicesVoiceServiceCallControlExtension_EchoCancel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "echo_cancel", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_EchoCancel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "echo_cancel", b ? "1" : "0");
	break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.Extension.{i}.Type!UCI:asterisk/extension,@i-1/type*/
static int get_ServicesVoiceServiceCallControlExtension_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "type", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlExtension_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "type", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.CallControl.Extension.{i}. *** */
DMLEAF tIOPSYS_VoiceServiceCallControlExtensionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"ComfortNoise", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_ComfortNoise, set_ServicesVoiceServiceCallControlExtension_ComfortNoise, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"TXGain", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_TXGain, set_ServicesVoiceServiceCallControlExtension_TXGain, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"RXGain", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_RXGain, set_ServicesVoiceServiceCallControlExtension_RXGain, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"EchoCancel", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_EchoCancel, set_ServicesVoiceServiceCallControlExtension_EchoCancel, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"Type", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlExtension_Type, set_ServicesVoiceServiceCallControlExtension_Type, BBFDM_BOTH},
{0}
};
