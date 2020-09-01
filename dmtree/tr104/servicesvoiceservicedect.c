/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicedect.h"
#include "common.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
#if 0
static int browseServicesVoiceServiceDECTBaseInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

static int browseServicesVoiceServiceDECTPortableInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif

/*************************************************************
* GET & SET PARAM
**************************************************************/
#if 0
static int get_ServicesVoiceServiceDECTBase_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_RFPI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_MaxSupportedPP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_MaxSupportedPP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"4"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_RepeaterSupportEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_NEMOEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_NEMOEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_SubscriptionEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_SubscriptionEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_CipheringEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_CipheringEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_EncryptionType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_RFPowerControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_RFPowerControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, RFPowerControl, 2, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_FirmwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_EepromVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBase_HardwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBaseStats_Handovers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBaseStats_HandoverFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBaseStats_ControlFieldErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBaseStats_PayloadFieldErrors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTBaseStats_SyncFailures(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_RegistrationStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_IPUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_IPUILength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_IPEI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_PARK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_BaseAttachedTo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_PortableType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_SubscriptionTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_HardwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_SoftwareUpgrade(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_LastUpdateDateTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.DECT. *** */
DMOBJ tServicesVoiceServiceDECTObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
//{"Base", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceDECTBaseInst, NULL, NULL, NULL, tServicesVoiceServiceDECTBaseObj, tServicesVoiceServiceDECTBaseParams, NULL, BBFDM_BOTH},
//{"Portable", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceDECTPortableInst, NULL, NULL, NULL, NULL, tServicesVoiceServiceDECTPortableParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.DECT.Base.{i}. *** */
DMOBJ tServicesVoiceServiceDECTBaseObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
//{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceDECTBaseStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceDECTBaseParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Name", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_Name, NULL, NULL, NULL, BBFDM_BOTH},
//{"Standard", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_Standard, NULL, NULL, NULL, BBFDM_BOTH},
//{"RFPI", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTBase_RFPI, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxSupportedPP", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceDECTBase_MaxSupportedPP, set_ServicesVoiceServiceDECTBase_MaxSupportedPP, NULL, NULL, BBFDM_BOTH},
//{"PIN", &DMWRITE, DMT_HEXBIN, get_ServicesVoiceServiceDECTBase_PIN, set_ServicesVoiceServiceDECTBase_PIN, NULL, NULL, BBFDM_BOTH},
//{"RepeaterSupportEnabled", &DMREAD, DMT_BOOL, get_ServicesVoiceServiceDECTBase_RepeaterSupportEnabled, NULL, NULL, NULL, BBFDM_BOTH},
//{"NEMOEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceDECTBase_NEMOEnable, set_ServicesVoiceServiceDECTBase_NEMOEnable, NULL, NULL, BBFDM_BOTH},
//{"SubscriptionEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceDECTBase_SubscriptionEnable, set_ServicesVoiceServiceDECTBase_SubscriptionEnable, NULL, NULL, BBFDM_BOTH},
//{"CipheringEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceDECTBase_CipheringEnable, set_ServicesVoiceServiceDECTBase_CipheringEnable, NULL, NULL, BBFDM_BOTH},
//{"EncryptionType", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_EncryptionType, NULL, NULL, NULL, BBFDM_BOTH},
//{"RFPowerControl", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceDECTBase_RFPowerControl, set_ServicesVoiceServiceDECTBase_RFPowerControl, NULL, NULL, BBFDM_BOTH},
//{"FirmwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_FirmwareVersion, NULL, NULL, NULL, BBFDM_BOTH},
//{"EepromVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_EepromVersion, NULL, NULL, NULL, BBFDM_BOTH},
//{"HardwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_HardwareVersion, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.DECT.Base.{i}.Stats. *** */
DMLEAF tServicesVoiceServiceDECTBaseStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Handovers", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTBaseStats_Handovers, NULL, NULL, NULL, BBFDM_BOTH},
//{"HandoverFailures", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTBaseStats_HandoverFailures, NULL, NULL, NULL, BBFDM_BOTH},
//{"ControlFieldErrors", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTBaseStats_ControlFieldErrors, NULL, NULL, NULL, BBFDM_BOTH},
//{"PayloadFieldErrors", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTBaseStats_PayloadFieldErrors, NULL, NULL, NULL, BBFDM_BOTH},
//{"SyncFailures", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTBaseStats_SyncFailures, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.DECT.Portable.{i}. *** */
DMLEAF tServicesVoiceServiceDECTPortableParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"RegistrationStatus", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_RegistrationStatus, NULL, NULL, NULL, BBFDM_BOTH},
//{"IPUI", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTPortable_IPUI, NULL, NULL, NULL, BBFDM_BOTH},
//{"IPUILength", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTPortable_IPUILength, NULL, NULL, NULL, BBFDM_BOTH},
//{"IPEI", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTPortable_IPEI, NULL, NULL, NULL, BBFDM_BOTH},
//{"PARK", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTPortable_PARK, NULL, NULL, NULL, BBFDM_BOTH},
//{"BaseAttachedTo", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_BaseAttachedTo, NULL, NULL, NULL, BBFDM_BOTH},
//{"PortableType", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_PortableType, NULL, NULL, NULL, BBFDM_BOTH},
//{"SubscriptionTime", &DMREAD, DMT_TIME, get_ServicesVoiceServiceDECTPortable_SubscriptionTime, NULL, NULL, NULL, BBFDM_BOTH},
//{"HardwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_HardwareVersion, NULL, NULL, NULL, BBFDM_BOTH},
//{"SoftwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_SoftwareVersion, NULL, NULL, NULL, BBFDM_BOTH},
//{"SoftwareUpgrade", &DMREAD, DMT_BOOL, get_ServicesVoiceServiceDECTPortable_SoftwareUpgrade, NULL, NULL, NULL, BBFDM_BOTH},
//{"LastUpdateDateTime", &DMREAD, DMT_TIME, get_ServicesVoiceServiceDECTPortable_LastUpdateDateTime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

