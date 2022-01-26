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

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CBBSType!UCI:asterisk/calling_features/cbbs_type*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "cbbs_type", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section,"cbbs_type", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.InternalService!UCI:asterisk/calling_features/internal_service*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_InternalService(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "internal_service", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_InternalService(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "internal_service", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallReturnEnable!UCI:asterisk/calling_features/callreturn_enable*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturnEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "callreturn_enable", value);
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturnEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "callreturn_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.MOHPassThrough!UCI:asterisk/calling_features/moh_passthrough*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_MOHPassThrough(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "moh_passthrough", "1");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_MOHPassThrough(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
		break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "moh_passthrough", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CBBSKey!UCI:asterisk/calling_features/cbbs_key*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "cbbs_key", "");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "cbbs_key", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CBBSMaxRetry!UCI:asterisk/calling_features/cbbs_maxretry*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSMaxRetry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "cbbs_maxretry", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSMaxRetry(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "cbbs_maxretry", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CBBSRetryTime!UCI:asterisk/calling_features/cbbs_retrytime*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSRetryTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "cbbs_retrytime", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSRetryTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "cbbs_retrytime", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CBBSWaitTime!UCI:asterisk/calling_features/cbbs_waittime*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSWaitTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "cbbs_waittime", "0");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSWaitTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "cbbs_waittime", value);
			break;
	}
	return 0;
}


/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CWStatus!UCI:asterisk/calling_features/cw_status*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CWStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "cw_status", "cwstatus");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CWStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "cw_status", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.CallReturn!UCI:asterisk/calling_features/callreturn*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturn(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "call_return", "callreturn");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturn(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "call_return", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.Redial!UCI:asterisk/calling_features/redial*/
static int get_ServicesVoiceServiceCallControlCallingFeaturesSet_Redial(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "redial", "redial");
	return 0;
}

static int set_ServicesVoiceServiceCallControlCallingFeaturesSet_Redial(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "redial", value);
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

/* *** Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}. *** */
DMLEAF tIOPSYS_VoiceServiceCallControlCallingFeaturesSetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"CBBSType", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSType, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSType, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"InternalService", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_InternalService, set_ServicesVoiceServiceCallControlCallingFeaturesSet_InternalService, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CallReturnEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturnEnable, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturnEnable, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"MOHPassThrough", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceCallControlCallingFeaturesSet_MOHPassThrough, set_ServicesVoiceServiceCallControlCallingFeaturesSet_MOHPassThrough, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CBBSKey", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSKey, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSKey, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CBBSMaxRetry", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSMaxRetry, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSMaxRetry, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CBBSRetryTime", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSRetryTime, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSRetryTime, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CBBSWaitTime", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSWaitTime, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CBBSWaitTime, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CWStatus", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CWStatus, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CWStatus, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"CallReturn", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturn, set_ServicesVoiceServiceCallControlCallingFeaturesSet_CallReturn, BBFDM_BOTH},
{BBF_VENDOR_PREFIX"Redial", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceCallControlCallingFeaturesSet_Redial, set_ServicesVoiceServiceCallControlCallingFeaturesSet_Redial, BBFDM_BOTH},
{0}
};

