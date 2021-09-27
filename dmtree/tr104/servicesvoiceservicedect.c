/*
 * Copyright (C) 2021 Iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 */

#include "servicesvoiceservicedect.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.!UBUS:dect/status/None,None/base*/
static int browseServicesVoiceServiceDECTBaseInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *obj = NULL, *arrobj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("dect", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, obj, i, 1, "base") {

			inst = handle_instance_without_section(dmctx, parent_node, ++id);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.!UBUS:dect/status/None,None/handsets*/
static int browseServicesVoiceServiceDECTPortableInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *obj = NULL, *arrobj = NULL;
	char *inst = NULL;
	int id = 0, i = 0;

	dmubus_call("dect", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, obj, i, 1, "handsets") {

			inst = handle_instance_without_section(dmctx, parent_node, ++id);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)obj, inst) == DM_STOP)
				break;
		}
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Services.VoiceService.{i}.DECT.BaseNumberOfEntries!UBUS:dect/status//base*/
static int get_ServicesVoiceServiceDECT_BaseNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	size_t num = 0;
	json_object *res, *base;

	dmubus_call("dect", "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "base", &base);
	
	num = (base) ? json_object_array_length(base) : 0;

	dmasprintf(value, "%d", num);

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.PortableNumberOfEntries!UBUS:dect/status//handsets*/
static int get_ServicesVoiceServiceDECT_PortableNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	size_t num = 0;
	json_object *res, *handsets;

	dmubus_call("dect", "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");

	json_object_object_get_ex(res, "handsets", &handsets);
	
	num = (handsets) ? json_object_array_length(handsets) : 0;

	dmasprintf(value, "%d", num);

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.Status!UBUS:dect/status//base[@i-1].status*/
static int get_ServicesVoiceServiceDECTBase_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = NULL;

	status = dmjson_get_value((json_object *)data, 1, "status");

	if (strcasecmp(status, "up") == 0) {
		*value = "Up";
	} else if (strcasecmp(status, "error") == 0) {
		*value = "Error";
	} else if (strcasecmp(status, "testing") == 0) {
		*value = "Testing";
	} else {
		*value = "Disabled";
	}

	return 0;

	return 0;
}

static int get_ServicesVoiceServiceDECTBase_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "dect", "base_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ServicesVoiceServiceDECTBase_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "dect", "base_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "dect", &dmmap);
			dmuci_set_value_by_section(dmmap, "base_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.Name!UBUS:dect/status//base[@i-1].id*/
static int get_ServicesVoiceServiceDECTBase_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *id = NULL;

	id = dmjson_get_value((json_object *)data, 1, "id");
	dmasprintf(value, "Base-%s", id);

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.Standard!UBUS:dect/status//base[@i-1].standard*/
static int get_ServicesVoiceServiceDECTBase_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "standard");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.RFPI!UBUS:dect/status//base[@i-1].rfpi*/
static int get_ServicesVoiceServiceDECTBase_RFPI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rfpi");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.RepeaterSupportEnabled!UBUS:dect/status//base[@i-1].repeater_support_enabled*/
static int get_ServicesVoiceServiceDECTBase_RepeaterSupportEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "repeater_support_enabled");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.SubscriptionEnable!UBUS:dect/status//base[@i-1].subscription_enabled*/
static int get_ServicesVoiceServiceDECTBase_SubscriptionEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "subscription_enabled");

	return 0;
}

static int set_ServicesVoiceServiceDECTBase_SubscriptionEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool enable;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &enable);
			if (enable)
				dmubus_call_set("dect", "registration_start", UBUS_ARGS{{"base", "1", Integer}}, 1);
			else
				dmubus_call_set("dect", "registration_stop", UBUS_ARGS{{"base", "1", Integer}}, 1);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.FirmwareVersion!UBUS:dect/status//base[@i-1].firmware_version*/
static int get_ServicesVoiceServiceDECTBase_FirmwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "firmware_version");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.EepromVersion!UBUS:dect/status//base[@i-1].eeprom_version*/
static int get_ServicesVoiceServiceDECTBase_EepromVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "eeprom_version");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Base.{i}.HardwareVersion!UBUS:dect/status//base[@i-1].hardware_version*/
static int get_ServicesVoiceServiceDECTBase_HardwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "hardware_version");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.Status!UBUS:dect/status//handsets[@i-1].status*/
static int get_ServicesVoiceServiceDECTPortable_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = NULL;

	status = dmjson_get_value((json_object *)data, 1, "status");

	if (strcasecmp(status, "Up") == 0) {
		*value = "Up";
	} else if (strcasecmp(status, "error") == 0) {
		*value = "Error";
	} else if (strcasecmp(status, "testing") == 0) {
		*value = "Testing";
	} else {
		*value = "Disabled";
	}

	return 0;
}

static int get_ServicesVoiceServiceDECTPortable_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "dect", "portable_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ServicesVoiceServiceDECTPortable_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "dect", "portable_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "dect", &dmmap);
			dmuci_set_value_by_section(dmmap, "portable_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.RegistrationStatus!UBUS:dect/status//handsets[@i-1].registration_status*/
static int get_ServicesVoiceServiceDECTPortable_RegistrationStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "registration_status");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.IPUI!UBUS:dect/status//handsets[@i-1].ipui*/
static int get_ServicesVoiceServiceDECTPortable_IPUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipui");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.IPEI!UBUS:dect/status//handsets[@i-1].ipui*/
static int get_ServicesVoiceServiceDECTPortable_IPEI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipui = dmjson_get_value((json_object *)data, 1, "ipui");
	char buff[14] = {0};

	*value = "";
	// Check for N type PUT
	if (ipui[0] == '0') {
		strcpy(buff, &ipui[1]);
		dmasprintf(value, "%s0", buff);
	}

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.IPUILength!UBUS:dect/status//handsets[@i-1].ipui_length*/
static int get_ServicesVoiceServiceDECTPortable_IPUILength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ipui_length");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.BaseAttachedTo!UBUS:dect/status//handsets[@i-1].base_id*/
static int get_ServicesVoiceServiceDECTPortable_BaseAttachedTo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *base = NULL;

	base = dmjson_get_value((json_object *)data, 1, "base_id");

	dmasprintf(value, "Device.VoiceService.1.DECT.Base.%s", base);

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.PortableType!UBUS:dect/status//handsets[@i-1].portable_type*/
static int get_ServicesVoiceServiceDECTPortable_PortableType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "portable_type");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.SubscriptionTime!UBUS:dect/status//handsets[@i-1].subscription_time*/
static int get_ServicesVoiceServiceDECTPortable_SubscriptionTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "subscription_time");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.HardwareVersion!UBUS:dect/status//handsets[@i-1].hardware_version*/
static int get_ServicesVoiceServiceDECTPortable_HardwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "hardware_version");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.SoftwareVersion!UBUS:dect/status//handsets[@i-1].software_version*/
static int get_ServicesVoiceServiceDECTPortable_SoftwareVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "software_version");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.SoftwareUpgrade!UBUS:dect/status//handsets[@i-1].software_upgrade*/
static int get_ServicesVoiceServiceDECTPortable_SoftwareUpgrade(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "software_upgrade");

	return 0;
}

/*#Device.Services.VoiceService.{i}.DECT.Portable.{i}.LastUpdateDateTime!UBUS:dect/status//handsets[@i-1].last_update_datetime*/
static int get_ServicesVoiceServiceDECTPortable_LastUpdateDateTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "last_update_datetime");

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.DECT. *** */
DMOBJ tServicesVoiceServiceDECTObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Base", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceDECTBaseInst, NULL, NULL, NULL, tServicesVoiceServiceDECTBaseParams, NULL, BBFDM_BOTH, LIST_KEY{"RFPI", "Name", "Alias", NULL}},
{"Portable", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceDECTPortableInst, NULL, NULL, NULL, tServicesVoiceServiceDECTPortableParams, NULL, BBFDM_BOTH, LIST_KEY{"IPEI", "Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceDECTParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BaseNumberOfEntries", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECT_BaseNumberOfEntries, NULL, BBFDM_BOTH},
{"PortableNumberOfEntries", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECT_PortableNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceDECTBaseParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceDECTBase_Alias, set_ServicesVoiceServiceDECTBase_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_Name, NULL, BBFDM_BOTH},
{"Standard", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_Standard, NULL, BBFDM_BOTH},
{"RFPI", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTBase_RFPI, NULL, BBFDM_BOTH},
{"RepeaterSupportEnabled", &DMREAD, DMT_BOOL, get_ServicesVoiceServiceDECTBase_RepeaterSupportEnabled, NULL, BBFDM_BOTH},
{"SubscriptionEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceDECTBase_SubscriptionEnable, set_ServicesVoiceServiceDECTBase_SubscriptionEnable, BBFDM_BOTH},
{"FirmwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_FirmwareVersion, NULL, BBFDM_BOTH},
{"EepromVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_EepromVersion, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTBase_HardwareVersion, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.DECT.Portable.{i}. *** */
DMLEAF tServicesVoiceServiceDECTPortableParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceDECTPortable_Alias, set_ServicesVoiceServiceDECTPortable_Alias, BBFDM_BOTH},
{"RegistrationStatus", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_RegistrationStatus, NULL, BBFDM_BOTH},
{"IPUI", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTPortable_IPUI, NULL, BBFDM_BOTH},
{"IPEI", &DMREAD, DMT_HEXBIN, get_ServicesVoiceServiceDECTPortable_IPEI, NULL, BBFDM_BOTH},
{"IPUILength", &DMREAD, DMT_UNINT, get_ServicesVoiceServiceDECTPortable_IPUILength, NULL, BBFDM_BOTH},
{"BaseAttachedTo", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_BaseAttachedTo, NULL, BBFDM_BOTH},
{"PortableType", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_PortableType, NULL, BBFDM_BOTH},
{"SubscriptionTime", &DMREAD, DMT_TIME, get_ServicesVoiceServiceDECTPortable_SubscriptionTime, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_HardwareVersion, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, get_ServicesVoiceServiceDECTPortable_SoftwareVersion, NULL, BBFDM_BOTH},
{"SoftwareUpgrade", &DMREAD, DMT_BOOL, get_ServicesVoiceServiceDECTPortable_SoftwareUpgrade, NULL, BBFDM_BOTH},
{"LastUpdateDateTime", &DMREAD, DMT_TIME, get_ServicesVoiceServiceDECTPortable_LastUpdateDateTime, NULL, BBFDM_BOTH},
{0}
};

