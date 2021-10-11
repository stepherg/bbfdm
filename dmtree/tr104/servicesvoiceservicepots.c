/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservicepots.h"
#include "common.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Services.VoiceService.{i}.POTS.FXS.{i}.!UCI:asterisk/tel_line/dmmap_asterisk*/
static int browseServicesVoiceServicePOTSFXSInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "tel_line", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *line_name = NULL;

		dmuci_get_value_by_section_string(p->config_section, "name", &line_name);
		if (line_name && (*line_name == '\0' || strcasestr(line_name, "DECT") == NULL)) {

			inst = handle_instance(dmctx, parent_node, p->dmmap_section, "fxsinstance", "fxsalias");

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
				break;
		}
		if (line_name && *line_name)
			dmfree(line_name);
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Services.VoiceService.{i}.POTS.Region!UCI:asterisk/tel_advanced,tel_options/country*/
static int get_ServicesVoiceServicePOTS_Region(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "tel_options", "country", value);
	return 0;
}

static int set_ServicesVoiceServicePOTS_Region(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 2, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "tel_options", "country", value);
			break;
	}
	return 0;
}

static int get_ServicesVoiceServicePOTSFXS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

/*#Device.Services.VoiceService.{i}.POTS.FXS.{i}.Name!UCI:asterisk/tel_line,@i-1/name*/
static int get_ServicesVoiceServicePOTSFXS_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", value);
	return 0;
}

static int get_ServicesVoiceServicePOTSFXS_DialType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Tone";
	return 0;
}

/*#Device.Services.VoiceService.{i}.POTS.FXS.{i}.ClipGeneration!UCI:asterisk/tel_line,@i-1/clir*/
static int get_ServicesVoiceServicePOTSFXS_ClipGeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *clir;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "clir", &clir);
	*value = *clir == '1' ? "0" : "1";
	return 0;
}

static int set_ServicesVoiceServicePOTSFXS_ClipGeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "clir", !b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ServicesVoiceServicePOTSFXS_Active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_ServicesVoiceServicePOTSFXS_TerminalType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Any";
	return 0;
}

/*#Device.Services.VoiceService.{i}.POTS.FXS.{i}.VoiceProcessing.TransmitGain!UCI:asterisk/tel_line,@i-1/txgain*/
static int get_ServicesVoiceServicePOTSFXSVoiceProcessing_TransmitGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "txgain", "0");
	return 0;
}

static int set_ServicesVoiceServicePOTSFXSVoiceProcessing_TransmitGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "txgain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.POTS.FXS.{i}.VoiceProcessing.ReceiveGain!UCI:asterisk/tel_line,@i-1/rxgain*/
static int get_ServicesVoiceServicePOTSFXSVoiceProcessing_ReceiveGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "rxgain", "0");
	return 0;
}

static int set_ServicesVoiceServicePOTSFXSVoiceProcessing_ReceiveGain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "rxgain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.POTS.FXS.{i}.VoiceProcessing.EchoCancellationEnable!UCI:asterisk/tel_line,@i-1/echo_cancel*/
static int get_ServicesVoiceServicePOTSFXSVoiceProcessing_EchoCancellationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "echo_cancel", "1");
	return 0;
}

static int set_ServicesVoiceServicePOTSFXSVoiceProcessing_EchoCancellationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
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

/*Get Device.Services.VoiceService.{i}.POTS.FXS.{i}. Alias*/
static int get_ServicesVoiceServicePOTSFXS_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "clientalias");
}

/*Set Device.Services.VoiceService.{i}.POTS.FXS.{i}. Alias*/
static int set_ServicesVoiceServicePOTSFXS_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "clientalias");
}
/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.POTS. *** */
DMOBJ tServicesVoiceServicePOTSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"FXS", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServicePOTSFXSInst, NULL, NULL, tServicesVoiceServicePOTSFXSObj, tServicesVoiceServicePOTSFXSParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServicePOTSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Region", &DMWRITE, DMT_STRING, get_ServicesVoiceServicePOTS_Region, set_ServicesVoiceServicePOTS_Region, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.POTS.FXS.{i}. *** */
DMOBJ tServicesVoiceServicePOTSFXSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"VoiceProcessing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServicePOTSFXSVoiceProcessingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServicePOTSFXSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServicePOTSFXS_Status, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_ServicesVoiceServicePOTSFXS_Name, NULL, BBFDM_BOTH},
{"DialType", &DMREAD, DMT_STRING, get_ServicesVoiceServicePOTSFXS_DialType, NULL, BBFDM_BOTH},
{"ClipGeneration", &DMWRITE, DMT_BOOL, get_ServicesVoiceServicePOTSFXS_ClipGeneration, set_ServicesVoiceServicePOTSFXS_ClipGeneration, BBFDM_BOTH},
{"Active", &DMREAD, DMT_BOOL, get_ServicesVoiceServicePOTSFXS_Active, NULL, BBFDM_BOTH},
{"TerminalType", &DMREAD, DMT_STRING, get_ServicesVoiceServicePOTSFXS_TerminalType, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServicePOTSFXS_Alias, set_ServicesVoiceServicePOTSFXS_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.POTS.FXS.{i}.VoiceProcessing. *** */
DMLEAF tServicesVoiceServicePOTSFXSVoiceProcessingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"TransmitGain", &DMWRITE, DMT_INT, get_ServicesVoiceServicePOTSFXSVoiceProcessing_TransmitGain, set_ServicesVoiceServicePOTSFXSVoiceProcessing_TransmitGain, BBFDM_BOTH},
{"ReceiveGain", &DMWRITE, DMT_INT, get_ServicesVoiceServicePOTSFXSVoiceProcessing_ReceiveGain, set_ServicesVoiceServicePOTSFXSVoiceProcessing_ReceiveGain, BBFDM_BOTH},
{"EchoCancellationEnable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServicePOTSFXSVoiceProcessing_EchoCancellationEnable, set_ServicesVoiceServicePOTSFXSVoiceProcessing_EchoCancellationEnable, BBFDM_BOTH},
{0}
};
