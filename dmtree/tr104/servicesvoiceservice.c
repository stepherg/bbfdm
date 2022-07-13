/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "common.h"
#include "servicesvoiceservice.h"

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
int browseVoiceServiceSIPProviderInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "clientinstance", "clientalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;

}

int delObjVoiceServiceSIPProvider(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("asterisk", "sip_service_provider", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseServicesVoiceServiceCallLogInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct call_log_entry *entry = NULL;
	char *inst = NULL;
	int i = 0;

	init_call_log();
	if (call_log_count <= 0)
		return 0;

	list_for_each_entry(entry, &call_log_list, list) {

		inst = handle_instance_without_section(dmctx, parent_node, ++i);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, entry, inst) == DM_STOP)
			break;

		if (i >= call_log_count)
			break;
	}

	return 0;
}

/*#Device.Services.VoiceService.{i}.VoIPProfile.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseServicesVoiceServiceVoIPProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return browseVoiceServiceSIPProviderInst(dmctx, parent_node, prev_data, prev_instance);
}

/*#Device.Services.VoiceService.{i}.CodecProfile.{i}.!UCI:asterisk/codec_profile/dmmap_asterisk*/
static int browseServicesVoiceServiceCodecProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);
	int i, j;
	int has_codec_profile = 0;

	// Initialize supported codecs if it has not been done
	if (codecs_num <= 0)
		init_supported_codecs();

	// Populate all supported codecs to UCI if there is none
	for (j = 0; j < 2; j++) {
		for (i = 0; i < codecs_num; i++) {
			struct codec_info *codec = &supported_codecs[i];
			char *value = NULL;

			dmuci_get_option_value_string(TR104_UCI_PACKAGE, codec->uci_name, "name", &value);
			if (!value || !*value) {
				if (j == 1) {
					char str[16];
					// Not found. Add this codec in the UCI
					dmuci_set_value(TR104_UCI_PACKAGE, codec->uci_name, "", "codec_profile");
					dmuci_set_value(TR104_UCI_PACKAGE, codec->uci_name, "name", codec->codec);
					snprintf(str, sizeof(str), "%u", codec->ptime_default);
					dmuci_set_value(TR104_UCI_PACKAGE, codec->uci_name, "ptime", str);
				}
			} else {
				dmfree(value);
				if (j == 0) {
					// At least there is one codec profile configured in UCI
					has_codec_profile = 1;
					break;
				}
			}
		}

		// Don't add any profile if there is any in UCI which has been configured
		if (has_codec_profile)
			break;
	}

	synchronize_specific_config_sections_with_dmmap("asterisk", "codec_profile", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "codecprofileinstance", "codecprofilealias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseVoiceServiceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = is_dmmap_section_exist("dmmap_asterisk", "voice_service");
	if (!s) dmuci_add_section_bbfdm("dmmap_asterisk", "voice_service", &s);
	handle_instance(dmctx, parent_node, s, "vsinstance", "vsalias");
	DM_LINK_INST_OBJ(dmctx, parent_node, s, "1");
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjServicesVoiceServiceVoIPProfile(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	dmuci_add_section("asterisk", "sip_service_provider", &s);

	dmuci_add_section_bbfdm("dmmap_asterisk", "sip_service_provider", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "clientinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceVoIPProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return delObjVoiceServiceSIPProvider(refparam, ctx, data, instance, del_action);
}

static int addObjServicesVoiceServiceCodecProfile(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;

	dmuci_add_section("asterisk", "codec_profile", &s);

	dmuci_add_section_bbfdm("dmmap_asterisk", "codec_profile", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "codecprofileinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceCodecProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("asterisk", "codec_profile", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_asterisk", "codec_profile", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vsalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "vsalias", value);
			return 0;
	}
	return 0;
}

static int get_ServicesVoiceService_CallLogNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseServicesVoiceServiceCallLogInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services. *** */
DMOBJ tServicesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"VoiceService", &DMREAD, NULL, NULL, "file:/etc/config/asterisk", browseVoiceServiceInst, NULL, NULL, tServicesVoiceServiceObj, tServicesVoiceServiceParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}. *** */
DMOBJ tServicesVoiceServiceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesObj, tServicesVoiceServiceCapabilitiesParams, NULL, BBFDM_BOTH},
{"ReservedPorts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceReservedPortsParams, NULL, BBFDM_BOTH},
{"POTS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServicePOTSObj, tServicesVoiceServicePOTSParams, NULL, BBFDM_BOTH},
{"DECT", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceDECTObj, tServicesVoiceServiceDECTParams, NULL, BBFDM_BOTH},
{"SIP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceSIPObj, NULL, NULL, BBFDM_BOTH},
{"CallControl", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallControlObj, NULL, NULL, BBFDM_BOTH},
{"CallLog", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceCallLogInst, NULL, NULL, tServicesVoiceServiceCallLogObj, tServicesVoiceServiceCallLogParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"VoIPProfile", &DMWRITE, addObjServicesVoiceServiceVoIPProfile, delObjServicesVoiceServiceVoIPProfile, NULL, browseServicesVoiceServiceVoIPProfileInst, NULL, NULL, tServicesVoiceServiceVoIPProfileObj, tServicesVoiceServiceVoIPProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"CodecProfile", &DMWRITE, addObjServicesVoiceServiceCodecProfile, delObjServicesVoiceServiceCodecProfile, NULL, browseServicesVoiceServiceCodecProfileInst, NULL, NULL, NULL, tServicesVoiceServiceCodecProfileParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_service_alias, set_service_alias, BBFDM_BOTH},
{"CallLogNumberOfEntries", &DMREAD, DMT_UNINT, get_ServicesVoiceService_CallLogNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};
