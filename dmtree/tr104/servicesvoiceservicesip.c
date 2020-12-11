/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Yalu Zhang, yalu.zhang@iopsys.eu
 */

#include "servicesvoiceservice.h"
#include "servicesvoiceservicesip.h"
#include "common.h"
#include "dmentry.h"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_voice_service_sip_client_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? section_name((struct uci_section *)data) : "";
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseServicesVoiceServiceSIPClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return browseVoiceServiceSIPProviderInst(dmctx, parent_node, prev_data, prev_instance);
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.Contact.{i}.*/
static int browseServicesVoiceServiceSIPClientContactInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	// prev_data is from its parent node SIP.Client.{i}. i.e. the UCI section of asterisk.sip_service_provider
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}


/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseServicesVoiceServiceSIPNetworkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &inst_last, update_instance_alias, 3,
			   p->dmmap_section, "networkinstance", "networkalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer.{i}.*/
static int browseServicesVoiceServiceSIPNetworkFQDNServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	// prev_data is from its parent node SIP.Network.{i}. i.e. a UCI section of asterisk.sip_service_provider
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjServicesVoiceServiceSIPClient(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char new_sec_name[16], value[32];
	struct uci_section *dmmap = NULL;

	char *inst = get_last_instance_bbfdm("dmmap_asterisk", "sip_service_provider", "clientinstance");
	snprintf(new_sec_name, sizeof(new_sec_name), "sip%d", (inst) ? atoi(inst) : 0);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "sip_service_provider");
	TR104_DEBUG("section name is [%s]. last inst = [%s]\n", new_sec_name, inst);

	// Set default options
	snprintf(value, sizeof(value), "account %d", (inst) ? atoi(inst) + 1 : 1);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "name", value);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "enabled", "0");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "codec0", "alaw");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "ptime_alaw", "20");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cbbs_key", "5");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cbbs_maxretry", "5");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cbbs_retrytime", "300");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cbbs_waittime", "30");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "autoframing", "1");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cfim_on", "*21*");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cfim_off", "#21#");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cfbs_on", "*61*");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cfbs_off", "#61#");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cw_on", "*43*");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cw_off", "#43#");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "cw_status", "*#43#");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "call_return", "*69");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "redial", "*66");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "is_fax", "0");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "transport", "udp");

	dmuci_add_section_bbfdm("dmmap_asterisk", "sip_service_provider", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name);
	*instance = update_instance(inst, 2, dmmap, "clientinstance");

	return 0;
}

static int delObjServicesVoiceServiceSIPClient(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return delObjVoiceServiceSIPProvider(refparam, ctx, data, instance, del_action);
}

static int addObjServicesVoiceServiceSIPNetwork(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	TR104_DEBUG("Each Services.VoiceService.1.SIP.Network object is bound to one Services.VoiceService"
			".1.SIP.Client object\n");
	return 0;
}

static int delObjServicesVoiceServiceSIPNetwork(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	TR104_DEBUG("Each Services.VoiceService.1.SIP.Network object is bound to one Services.VoiceService"
				".1.SIP.Client object\n");
	return 0;
}

static int addObjServicesVoiceServiceSIPClientContact(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjServicesVoiceServiceSIPClientContact(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

static int addObjServicesVoiceServiceSIPNetworkFQDNServer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjServicesVoiceServiceSIPNetworkFQDNServer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.Enable!UCI:asterisk/sip_service_provider,@i-1/enabled*/
static int get_ServicesVoiceServiceSIPClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enabled", "1");
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceSIPClient_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *section = (struct uci_section *)data;
	char *enabled = NULL;

	dmuci_get_value_by_section_string(section, "enabled", &enabled);
	if (enabled && *enabled == '0') {
		*value = "Disabled";

		dmfree(enabled);
	} else {
		// Get registration status from ubus
		json_object *res = NULL, *sip, *client;

		dmubus_call("voice.asterisk", "status", UBUS_ARGS{}, 0, &res);
		if (res) {
			sip = dmjson_get_obj(res, 1, "sip");
			if (sip) {
				client = dmjson_get_obj(sip, 1, section->e.name);
				if (client) {
					char *state = dmjson_get_value(client, 1, "state");
					if (state && *state) {
						if (strcasecmp(state, "Registered") == 0) {
							*value = "Up";
						} else if (strcasecmp(state, "Request") == 0) {
							*value = "Registering";
						} else {
							*value = state;
						}
					}
				}
			}
		} else {
			TR104_DEBUG("dmubus_call() failed\n");
		}
	}

	// For internal failure
	if (!*value || !**value)
		*value = "Error_Registration";

	return 0;
}

static int get_ServicesVoiceServiceSIPClient_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Static";
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.AuthUserName!UCI:asterisk/sip_service_provider,@i-1/authuser*/
static int get_ServicesVoiceServiceSIPClient_AuthUserName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "authuser", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_AuthUserName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 128, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "authuser", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.AuthPassword!UCI:asterisk/sip_service_provider,@i-1/secret*/
static int get_ServicesVoiceServiceSIPClient_AuthPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "secret", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_AuthPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 128, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "secret", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.RegisterURI!UCI:asterisk/sip_service_provider,@i-1/user*/
static int get_ServicesVoiceServiceSIPClient_RegisterURI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "user", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_RegisterURI(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 389, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "user", value);
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceSIPClientContact_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Static";
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.Contact.Port!UCI:asterisk/sip_advanced,sip_options/bindport*/
static int get_ServicesVoiceServiceSIPClientContact_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "bindport", "0");
	return 0;
}

static int set_ServicesVoiceServiceSIPClientContact_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "bindport", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.Contact.ExpireTime!UCI:asterisk/sip_advanced,sip_options/defaultexpiry*/
static int get_ServicesVoiceServiceSIPClientContact_ExpireTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *section = (struct uci_section *)data;
	json_object *res = NULL, *sip, *client;

	*value = "0001-01-01T00:00:00Z";
	if (!section) {
		TR104_DEBUG("section shall NOT be null\n");
		return 0;
	}

	dmubus_call("voice.asterisk", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		sip = dmjson_get_obj(res, 1, "sip");
		if (sip) {
			client = dmjson_get_obj(sip, 1, section->e.name);
			if (client) {
				char *last_reg_time = dmjson_get_value(client, 1, "last_successful_registration");
				if (last_reg_time && *last_reg_time) {
					struct tm tm_last = { 0, };

					// The format of last_reg_time is like "Wed, 26 Aug 2020 11:50:13"
					if (strptime(last_reg_time, "%a, %d %b %Y %H:%M:%S", &tm_last)) {
						char *period_str = NULL, buf[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
						int period = 0;
						// Let mktime determine the DST setting according to the system configuration
						tm_last.tm_isdst = -1;
						time_t time_last = mktime(&tm_last), time_expires;

						dmuci_get_option_value_string(TR104_UCI_PACKAGE, "sip_options", "defaultexpiry", &period_str);
						if (period_str && *period_str) {
							period = atoi(period_str);
							dmfree(period_str);
						}
						if (period <= 0) {
							TR104_DEBUG("Use default registration expires\n");
							period = atoi(DEFAULT_SIP_REGISTER_EXPIRY_STR);
						}
						time_expires = time_last + period;

						if (strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", localtime(&time_expires)) == 0)
							return -1;

						*value = dmstrdup(buf);
					} else {
						TR104_DEBUG("Unexpected time format: %s\n", last_reg_time);
					}
				}
			}
		}
	}

	return 0;
}

static int get_ServicesVoiceServiceSIPClientContact_UserAgent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *section = (struct uci_section *)data;
	json_object *res = NULL, *sip, *client;

	if (!section) {
		TR104_DEBUG("section shall NOT be null\n");
		return 0;
	}

	dmubus_call("voice.asterisk", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		sip = dmjson_get_obj(res, 1, "sip");
		if (sip) {
			client = dmjson_get_obj(sip, 1, section->e.name);
			if (client)
				*value = dmjson_get_value(client, 1, "useragent");
		}
	} else {
		TR104_DEBUG("dmubus_call() failed\n");
	}

	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.Enable!UCI:asterisk/sip_service_provider,@i-1/enabled*/
static int get_ServicesVoiceServiceSIPNetwork_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enabled", "1");
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceSIPNetwork_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

static int get_server_address(struct uci_section *section, char *option, char **value)
{
	dmuci_get_value_by_section_string(section, option, value);
	if (*value && **value) {
		char *port = strchr(*value, ':');
		if (port) {
			char *server = dmstrdup(*value);
			if (server) {
				server[port - *value] = '\0';
				dmfree(*value);
				*value = server;
			}
		}
	}

	return 0;
}

static int set_server_address(struct uci_section *section, char *option, char *value)
{
	char *old_value, *port, *new_value;

	dmuci_get_value_by_section_string(section, option, &old_value);
	port = strchr(old_value, ':');
	if (port) {
		port++;
		new_value = (char *)dmmalloc(strlen(value) + strlen(port) + 2);
		if (new_value) {
			sprintf(new_value, "%s:%s", value, port);
			dmuci_set_value_by_section(section, option, new_value);
			dmfree(new_value);
		}
	} else {
		dmuci_set_value_by_section(section, option, value);
	}

	if (old_value && *old_value)
		dmfree(old_value);

	return 0;
}

static int get_server_port(struct uci_section *section, char *option, char **value)
{
	char *domain, *port = NULL;

	dmuci_get_value_by_section_string(section, option, &domain);
	if (domain && *domain) {
		port = strchr(domain, ':');
		if (port)
			port++;
	}

	if (port && *port)
		*value = dmstrdup(port);
	else
		*value = dmstrdup(DEFAULT_SIP_PORT_STR);

	if (domain && *domain)
		dmfree(domain);

	return 0;
}

static int set_server_port(struct uci_section *section, char *option, char *value)
{
	char *old_value, *new_value, *tmp;

	dmuci_get_value_by_section_string(section, option, &old_value);
	tmp = strchr(old_value, ':');
	if (tmp)
		*tmp = '\0';
	new_value = (char *)dmmalloc(strlen(old_value) + strlen(value) + 2);
	if (new_value) {
		sprintf(new_value, "%s:%s", old_value, value);
		dmuci_set_value_by_section(section, option, new_value);
		dmfree(new_value);
	}

	if (old_value && *old_value)
		dmfree(old_value);

	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.ProxyServer!UCI:asterisk/sip_service_provider,@i-1/host*/
static int get_ServicesVoiceServiceSIPNetwork_ProxyServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "host", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_ProxyServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "host", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.ProxyServerPort!UCI:asterisk/sip_service_provider,@i-1/port*/
static int get_ServicesVoiceServiceSIPNetwork_ProxyServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "port", DEFAULT_SIP_PORT_STR);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_ProxyServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "port", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.ProxyServerTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_ServicesVoiceServiceSIPNetwork_ProxyServerTransport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "transport", value);
	if (*value && **value) {
		// Convert to uppercase
		for (char *ch = *value; *ch != '\0'; ch++)
			*ch = toupper(*ch);
	} else {
		*value = "UDP";
	}
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_ProxyServerTransport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProxyServerTransport, 4, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			for (char *ch = value; *ch != '\0'; ch++)
				*ch = tolower(*ch);
			dmuci_set_value_by_section((struct uci_section *)data, "transport", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrarServer!UCI:asterisk/sip_service_provider,@i-1/host*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrarServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "host", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_RegistrarServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "host", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrarServerPort!UCI:asterisk/sip_service_provider,@i-1/port*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrarServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "port", DEFAULT_SIP_PORT_STR);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_RegistrarServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "port", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrarServerTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "transport", value);
	if (*value && **value) {
		for (char *ch = *value; *ch != '\0'; ch++)
			*ch = toupper(*ch);
	} else {
		*value = "UDP";
	}
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, RegistrarServerTransport, 4, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			for (char *ch = value; *ch != '\0'; ch++)
				*ch = tolower(*ch);
			dmuci_set_value_by_section((struct uci_section *)data, "transport", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.UserAgentDomain!UCI:asterisk/sip_service_provider,@i-1/domain*/
static int get_ServicesVoiceServiceSIPNetwork_UserAgentDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "domain", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_UserAgentDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "domain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.OutboundProxy!UCI:asterisk/sip_service_provider,@i-1/outboundproxy*/
static int get_ServicesVoiceServiceSIPNetwork_OutboundProxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_server_address(data, "outboundproxy", value);
}

static int set_ServicesVoiceServiceSIPNetwork_OutboundProxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_address(data, "outboundproxy", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.OutboundProxyPort!UCI:asterisk/sip_service_provider,@i-1/outboundproxy*/
static int get_ServicesVoiceServiceSIPNetwork_OutboundProxyPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_server_port(data, "outboundproxy", value);
}

static int set_ServicesVoiceServiceSIPNetwork_OutboundProxyPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_port(data, "outboundproxy", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.STUNServer!UCI:asterisk/sip_advanced,sip_options/stun_server*/
static int get_ServicesVoiceServiceSIPNetwork_STUNServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "stun_server", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_STUNServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "stun_server", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrationPeriod!UCI:asterisk/sip_advanced,sip_options/defaultexpiry*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrationPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "defaultexpiry", DEFAULT_SIP_REGISTER_EXPIRY_STR);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_RegistrationPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "defaultexpiry", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.Realm!UCI:asterisk/sip_advanced,sip_options/realm*/
static int get_ServicesVoiceServiceSIPNetwork_Realm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "realm", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_Realm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "realm", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegisterExpires!UCI:asterisk/sip_advanced,sip_options/defaultexpiry*/
static int get_ServicesVoiceServiceSIPNetwork_RegisterExpires(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "defaultexpiry", DEFAULT_SIP_REGISTER_EXPIRY_STR);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_RegisterExpires(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "defaultexpiry", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.DSCPMark!UCI:asterisk/sip_advanced,sip_options/tos_sip*/
static int get_ServicesVoiceServiceSIPNetwork_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("asterisk", "sip_options", "tos_sip", "0");
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("asterisk", "sip_options", "tos_sip", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.CodecList!UCI:asterisk/sip_service_provider,@i-1/codecs*/
static int get_ServicesVoiceServiceSIPNetwork_CodecList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp = NULL;

	*value = "";
	dmuci_get_value_by_section_string((struct uci_section *)data, "codecs", &tmp);
	if (tmp && *tmp) {
		char buf[256] = "";
		char *token, *saveptr;
		int len = 0;

		for (token = strtok_r(tmp, ", ", &saveptr); token; token = strtok_r(NULL, ", ", &saveptr)) {
			const char *codec = get_codec_name(token);
			if (codec && len < sizeof(buf)) {
				int res = snprintf(buf + len, sizeof(buf) - len, "%s%s", len == 0 ? "" : ",", codec);
				if (res <= 0) {
					TR104_DEBUG("buf might be too small\n");
					dmfree(tmp);
					return FAULT_9002;
				}
				len += res;
			}
		}

		if (buf[0] != '\0')
			*value = dmstrdup(buf);

		dmfree(tmp);
	}
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_CodecList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int res = 0;
	char *codec_list = NULL, *token, *saveptr, *uci_name;

	switch (action)	{
		case VALUECHECK:
			if (!value)
				return FAULT_9007;
			else if (*value) {
				codec_list = dmstrdup(value);
				for (token = strtok_r(codec_list, ", ", &saveptr); token; token = strtok_r(NULL, ", ", &saveptr)) {
					if (!get_codec_uci_name(token)) {
						res = FAULT_9007;
						break;
					}
				}
			}
			break;
		case VALUESET:
			if (value) {
				// Empty the existing code list first
				dmuci_set_value_by_section((struct uci_section *)data, "codecs", "");

				if (*value) {
					codec_list = dmstrdup(value);
					for (token = strtok_r(codec_list, ", ", &saveptr); token;
						 token = strtok_r(NULL, ", ", &saveptr)) {
						uci_name = (char *)get_codec_uci_name(token);
						if (uci_name) {
							dmuci_add_list_value_by_section((struct uci_section *)data, "codecs", uci_name);
						}
					}
				}
			}
			break;
	}

	if (codec_list)
		dmfree(codec_list);
	return res;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer.Enable!UCI:asterisk/sip_advanced,sip_options/srvlookup*/
static int get_ServicesVoiceServiceSIPNetworkFQDNServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("asterisk", "sip_options", "srvlookup", value);
	*value = (strcmp(*value, "yes") == 0) ? "1" : "0";
	return 0;
}

static int set_ServicesVoiceServiceSIPNetworkFQDNServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("asterisk", "sip_options", "srvlookup", b ? "yes" : "no");
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceSIPNetworkFQDNServer_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Static";
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer.Domain!UCI:asterisk/sip_service_provider,@i-1/domain*/
static int get_ServicesVoiceServiceSIPNetworkFQDNServer_Domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (!data) {
		TR104_DEBUG("data shall NOT be null\n");
		return 0;
	}
	return get_server_address(data, "domain", value);
}

static int set_ServicesVoiceServiceSIPNetworkFQDNServer_Domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	if (!data) {
		TR104_DEBUG("data shall NOT be null\n");
		return 0;
	}
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_address(data, "domain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer.Port!UCI:asterisk/sip_service_provider,@i-1/domain*/
static int get_ServicesVoiceServiceSIPNetworkFQDNServer_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (!data) {
		TR104_DEBUG("data shall NOT be null\n");
		return 0;
	}
	return get_server_port(data, "domain", value);
}

static int set_ServicesVoiceServiceSIPNetworkFQDNServer_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	if (!data) {
		TR104_DEBUG("data shall NOT be null\n");
		return 0;
	}
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_port(data, "domain", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.SIP. *** */
DMOBJ tServicesVoiceServiceSIPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Client", &DMWRITE, addObjServicesVoiceServiceSIPClient, delObjServicesVoiceServiceSIPClient, NULL, browseServicesVoiceServiceSIPClientInst, NULL, tServicesVoiceServiceSIPClientObj, tServicesVoiceServiceSIPClientParams, get_voice_service_sip_client_linker, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"Network", &DMWRITE, addObjServicesVoiceServiceSIPNetwork, delObjServicesVoiceServiceSIPNetwork, NULL, browseServicesVoiceServiceSIPNetworkInst, NULL, tServicesVoiceServiceSIPNetworkObj, tServicesVoiceServiceSIPNetworkParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Client.{i}. *** */
DMOBJ tServicesVoiceServiceSIPClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Contact", &DMWRITE, addObjServicesVoiceServiceSIPClientContact, delObjServicesVoiceServiceSIPClientContact, NULL, browseServicesVoiceServiceSIPClientContactInst, NULL, NULL, tServicesVoiceServiceSIPClientContactParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceSIPClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceSIPClient_Enable, set_ServicesVoiceServiceSIPClient_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPClient_Status, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPClient_Origin, NULL, BBFDM_BOTH},
{"AuthUserName", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPClient_AuthUserName, set_ServicesVoiceServiceSIPClient_AuthUserName, BBFDM_BOTH},
{"AuthPassword", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPClient_AuthPassword, set_ServicesVoiceServiceSIPClient_AuthPassword, BBFDM_BOTH},
{"RegisterURI", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPClient_RegisterURI, set_ServicesVoiceServiceSIPClient_RegisterURI, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Client.{i}.Contact.{i}. *** */
DMLEAF tServicesVoiceServiceSIPClientContactParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPClientContact_Origin, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPClientContact_Port, set_ServicesVoiceServiceSIPClientContact_Port, BBFDM_BOTH},
{"ExpireTime", &DMREAD, DMT_TIME, get_ServicesVoiceServiceSIPClientContact_ExpireTime, NULL, BBFDM_BOTH},
{"UserAgent", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPClientContact_UserAgent, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Network.{i}. *** */
DMOBJ tServicesVoiceServiceSIPNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"FQDNServer", &DMWRITE, addObjServicesVoiceServiceSIPNetworkFQDNServer, delObjServicesVoiceServiceSIPNetworkFQDNServer, NULL, browseServicesVoiceServiceSIPNetworkFQDNServerInst, NULL, NULL, tServicesVoiceServiceSIPNetworkFQDNServerParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Domain", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceSIPNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceSIPNetwork_Enable, set_ServicesVoiceServiceSIPNetwork_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Status, NULL, BBFDM_BOTH},
{"ProxyServer", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_ProxyServer, set_ServicesVoiceServiceSIPNetwork_ProxyServer, BBFDM_BOTH},
{"ProxyServerPort", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_ProxyServerPort, set_ServicesVoiceServiceSIPNetwork_ProxyServerPort, BBFDM_BOTH},
{"ProxyServerTransport", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_ProxyServerTransport, set_ServicesVoiceServiceSIPNetwork_ProxyServerTransport, BBFDM_BOTH},
{"RegistrarServer", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_RegistrarServer, set_ServicesVoiceServiceSIPNetwork_RegistrarServer, BBFDM_BOTH},
{"RegistrarServerPort", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_RegistrarServerPort, set_ServicesVoiceServiceSIPNetwork_RegistrarServerPort, BBFDM_BOTH},
{"RegistrarServerTransport", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport, set_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport, BBFDM_BOTH},
{"UserAgentDomain", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_UserAgentDomain, set_ServicesVoiceServiceSIPNetwork_UserAgentDomain, BBFDM_BOTH},
{"OutboundProxy", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_OutboundProxy, set_ServicesVoiceServiceSIPNetwork_OutboundProxy, BBFDM_BOTH},
{"OutboundProxyPort", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_OutboundProxyPort, set_ServicesVoiceServiceSIPNetwork_OutboundProxyPort, BBFDM_BOTH},
{"STUNServer", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_STUNServer, set_ServicesVoiceServiceSIPNetwork_STUNServer, BBFDM_BOTH},
{"RegistrationPeriod", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_RegistrationPeriod, set_ServicesVoiceServiceSIPNetwork_RegistrationPeriod, BBFDM_BOTH},
{"Realm", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Realm, set_ServicesVoiceServiceSIPNetwork_Realm, BBFDM_BOTH},
{"RegisterExpires", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_RegisterExpires, set_ServicesVoiceServiceSIPNetwork_RegisterExpires, BBFDM_BOTH},
{"DSCPMark", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_DSCPMark, set_ServicesVoiceServiceSIPNetwork_DSCPMark, BBFDM_BOTH},
{"CodecList", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_CodecList, set_ServicesVoiceServiceSIPNetwork_CodecList, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer. *** */
DMLEAF tServicesVoiceServiceSIPNetworkFQDNServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceSIPNetworkFQDNServer_Enable, set_ServicesVoiceServiceSIPNetworkFQDNServer_Enable, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPNetworkFQDNServer_Origin, NULL, BBFDM_BOTH},
{"Domain", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetworkFQDNServer_Domain, set_ServicesVoiceServiceSIPNetworkFQDNServer_Domain, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetworkFQDNServer_Port, set_ServicesVoiceServiceSIPNetworkFQDNServer_Port, BBFDM_BOTH},
{0}
};
