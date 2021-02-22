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
* ENTRY METHOD
**************************************************************/
static int browseServicesVoiceServiceCallLogInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct call_log_entry *entry;
	char inst[16];
	int i = 0;

	init_call_log();
	if (call_log_count <= 0)
		return 0;

	list_for_each_entry(entry, &call_log_list, list) {
		i++;
		snprintf(inst, sizeof(inst), "%d", i);
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
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst =  handle_update_instance(2, dmctx, &inst_last, update_instance_alias, 5,
				p->dmmap_section, "clientinstance", "clientalias", "dmmap_asterisk", "sip_service_provider");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.CodecProfile.{i}.!UCI:asterisk/codec_profile/dmmap_asterisk*/
static int browseServicesVoiceServiceCodecProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
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
					TR104_DEBUG("Created a UCI section: %s\n", str);
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

		inst =  handle_update_instance(2, dmctx, &inst_last, update_instance_alias, 5,
				p->dmmap_section, "codecprofileinstance", "codecprofilealias", "dmmap_asterisk", "codec_profile");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjServicesVoiceServiceVoIPProfile(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_asterisk");
	inst = get_last_instance_bbfdm("dmmap_asterisk", "sip_service_provider", "clientinstance");
	dmuci_add_section_and_rename("asterisk", "sip_service_provider", &s, &value);

	dmuci_add_section_bbfdm("dmmap_asterisk", "sip_service_provider", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(inst, 4, dmmap, "clientinstance", "dmmap_asterisk", "sip_service_provider");
	return 0;
}

static int delObjServicesVoiceServiceVoIPProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("asterisk", "sip_service_provider", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_asterisk", "sip_service_provider", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjServicesVoiceServiceCodecProfile(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_asterisk");
	inst = get_last_instance_bbfdm("dmmap_asterisk", "codec_profile", "codecprofileinstance");
	dmuci_add_section_and_rename("asterisk", "codec_profile", &s, &value);

	dmuci_add_section_bbfdm("dmmap_asterisk", "codec_profile", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(inst, 4, dmmap, "codecprofileinstance", "dmmap_asterisk", "codec_profile");
	return 0;
}

static int delObjServicesVoiceServiceCodecProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_asterisk", "codec_profile", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("asterisk", "codec_profile", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_asterisk", "codec_profile", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_asterisk", "codec_profile", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int browseVoiceServiceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *vs = NULL, *vs_last = NULL;

	update_section_list(DMMAP,"voice_service", NULL, 1, NULL, NULL, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap", "voice_service", s) {
		vs = handle_update_instance(1, dmctx, &vs_last, update_instance_alias, 5,
				s, "vsinstance", "vsalias", "dmmap", "voice_service");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, vs) == DM_STOP)
			break;
	}
	return 0;
}

int get_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services. *** */
DMOBJ tServicesObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"VoiceService", &DMREAD, NULL, NULL, "file:/etc/config/asterisk", browseVoiceServiceInst, NULL, NULL, NULL, tServicesVoiceServiceObj, tServicesVoiceServiceParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}. *** */
DMOBJ tServicesVoiceServiceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Capabilities", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCapabilitiesObj, tServicesVoiceServiceCapabilitiesParams, NULL, BBFDM_BOTH},
{"ReservedPorts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceReservedPortsParams, NULL, BBFDM_BOTH},
{"POTS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServicePOTSObj, tServicesVoiceServicePOTSParams, NULL, BBFDM_BOTH},
{"SIP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceSIPObj, NULL, NULL, BBFDM_BOTH},
{"CallControl", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallControlObj, NULL, NULL, BBFDM_BOTH},
{"CallLog", &DMREAD, NULL, NULL, NULL, browseServicesVoiceServiceCallLogInst, NULL, NULL, NULL, NULL, tServicesVoiceServiceCallLogParams, NULL, BBFDM_BOTH},
{"VoIPProfile", &DMWRITE, addObjServicesVoiceServiceVoIPProfile, delObjServicesVoiceServiceVoIPProfile, NULL, browseServicesVoiceServiceVoIPProfileInst, NULL, NULL, NULL, tServicesVoiceServiceVoIPProfileObj, tServicesVoiceServiceVoIPProfileParams, NULL, BBFDM_BOTH},
{"CodecProfile", &DMWRITE, addObjServicesVoiceServiceCodecProfile, delObjServicesVoiceServiceCodecProfile, NULL, browseServicesVoiceServiceCodecProfileInst, NULL, NULL, NULL, NULL, tServicesVoiceServiceCodecProfileParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tServicesVoiceServiceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_service_alias, set_service_alias, NULL, NULL, BBFDM_BOTH},
{0}
};
