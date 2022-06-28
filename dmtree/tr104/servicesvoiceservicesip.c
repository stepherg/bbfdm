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

/**************************************************************************
* LINKER
***************************************************************************/
static int get_voice_service_sip_client_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? section_name(((struct dmmap_dup *)data)->config_section) : "";
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
/*
static int browseServicesVoiceServiceSIPClientContactInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	// prev_data is from its parent node SIP.Client.{i}. i.e. the UCI section of asterisk.sip_service_provider
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}
*/

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.!UCI:asterisk/sip_service_provider/dmmap_asterisk*/
static int browseServicesVoiceServiceSIPNetworkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("asterisk", "sip_service_provider", "dmmap_asterisk", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "networkinstance", "networkalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
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

	snprintf(new_sec_name, sizeof(new_sec_name), "sip%s", *instance);
	snprintf(value, sizeof(value), "account %s", *instance);

	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "", "sip_service_provider");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "name", value);
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "enable", "0");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "support_fax", "0");
	dmuci_set_value(TR104_UCI_PACKAGE, new_sec_name, "transport", "udp");

	dmuci_add_section_bbfdm("dmmap_asterisk", "sip_service_provider", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", new_sec_name);
	dmuci_set_value_by_section(dmmap, "clientinstance", *instance);
	return 0;
}

static int delObjServicesVoiceServiceSIPClient(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return delObjVoiceServiceSIPProvider(refparam, ctx, data, instance, del_action);
}

static int addObjServicesVoiceServiceSIPNetwork(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	BBF_DEBUG("Each Services.VoiceService.1.SIP.Network object is bound to one Services.VoiceService"
			".1.SIP.Client object\n");
	return 0;
}

static int delObjServicesVoiceServiceSIPNetwork(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	BBF_DEBUG("Each Services.VoiceService.1.SIP.Network object is bound to one Services.VoiceService"
				".1.SIP.Client object\n");
	return 0;
}

/*
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
*/

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.Enable!UCI:asterisk/sip_service_provider,@i-1/enable*/
static int get_ServicesVoiceServiceSIPClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "1");
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
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_ServicesVoiceServiceSIPClient_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *section = ((struct dmmap_dup *)data)->config_section;
	char *enabled = NULL;

	dmuci_get_value_by_section_string(section, "enable", &enabled);
	if (enabled && *enabled == '0') {
		*value = "Disabled";

		dmfree(enabled);
	} else {
		// Get registration status from ubus
		json_object *res = NULL, *sip = NULL, *client = NULL;

		dmubus_call("voice.asterisk", "status", UBUS_ARGS{0}, 0, &res);
		if (res) {
			sip = dmjson_get_obj(res, 1, "sip");
			if (sip) {
				client = dmjson_get_obj(sip, 1, section->e.name);
				if (client) {
					char *state = dmjson_get_value(client, 1, "state");
					if (state && *state) {
						if (strcasecmp(state, "Registered") == 0) {
							*value = "Up";
						} else if (strcasecmp(state, "Rejected") == 0) {
							*value = "Error_Registration";
						} else if (strcasecmp(state, "Stopped") == 0) {
							*value = "Quiescent";
						} else if (strcasecmp(state, "Unregistered") == 0) {
							*value = "Registering";
						}
					}
				}
			}
		} else {
			BBF_DEBUG("dmubus_call() failed\n");
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
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "authuser", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_AuthUserName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 128, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "authuser", value);
			break;
	}
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_AuthPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 128, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "secret", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Client.{i}.RegisterURI!UCI:asterisk/sip_service_provider,@i-1/user*/
static int get_ServicesVoiceServiceSIPClient_RegisterURI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *value_user = NULL;
	char *value_address = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "user", &value_user);
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "domain", &value_address);

	if (!(value_address && *value_address)) {
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "outbound_proxy", &value_address);
	}

	dmasprintf(value, "%s@%s", value_user, value_address);
	return 0;
}

static int set_ServicesVoiceServiceSIPClient_RegisterURI(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *value_user = NULL;
	char *value_domain = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 389, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			value_domain = DM_STRCHR(value, '@');
			if (value_domain) {
				value_domain++;
				value_user = dmstrdup(value);
				if (value_user) {
					value_user[value_domain - value - 1] = '\0';
					dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "user", value_user);
					dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "domain", value_domain);
				}
			}
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.Enable!UCI:asterisk/sip_service_provider,@i-1/enable*/
static int get_ServicesVoiceServiceSIPNetwork_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "1");
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
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
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
		char *port = DM_STRCHR(*value, ':');
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
	char *old_value = NULL;

	dmuci_get_value_by_section_string(section, option, &old_value);
	char *port = (old_value && *old_value) ? DM_STRCHR(old_value, ':') : NULL;
	if (port) {
		char new_value[32] = {0};

		port++;
		snprintf(new_value, sizeof(new_value), "%s:%s", value, port);
		dmuci_set_value_by_section(section, option, new_value);
	} else {
		dmuci_set_value_by_section(section, option, value);
	}

	if (old_value && *old_value)
		dmfree(old_value);

	return 0;
}

static int get_server_port(struct uci_section *section, char *option, char **value)
{
	char *domain = NULL, *port = NULL;

	dmuci_get_value_by_section_string(section, option, &domain);
	if (domain && *domain) {
		port = DM_STRCHR(domain, ':');
		if (port)
			port++;
	}

	*value = dmstrdup((port && *port) ? port : DEFAULT_SIP_PORT_STR);

	if (domain && *domain)
		dmfree(domain);

	return 0;
}

static int set_server_port(struct uci_section *section, char *option, char *value)
{
	char *old_value = NULL, new_value[32] = {0};

	dmuci_get_value_by_section_string(section, option, &old_value);
	char *tmp = old_value ? DM_STRCHR(old_value, ':') : NULL;
	if (tmp)
		*tmp = '\0';

	snprintf(new_value, sizeof(new_value), "%s:%s", old_value ? old_value : "", value);
	dmuci_set_value_by_section(section, option, new_value);

	if (old_value && *old_value)
		dmfree(old_value);

	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.ProxyServer!UCI:asterisk/sip_service_provider,@i-1/host*/
static int get_ServicesVoiceServiceSIPNetwork_ProxyServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "host", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_ProxyServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "host", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.ProxyServerPort!UCI:asterisk/sip_service_provider,@i-1/port*/
static int get_ServicesVoiceServiceSIPNetwork_ProxyServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "port", DEFAULT_SIP_PORT_STR);
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
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "port", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.ProxyServerTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.UserAgentTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_ServicesVoiceServiceSIPNetwork_Transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "transport", value);
	if (*value && **value) {
		// Convert to uppercase
		for (char *ch = *value; *ch != '\0'; ch++)
			*ch = toupper(*ch);
	} else {
		*value = "UDP";
	}
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_Transport(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProxyServerTransport, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			for (char *ch = value; *ch != '\0'; ch++)
				*ch = tolower(*ch);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "transport", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrarServer!UCI:asterisk/sip_service_provider,@i-1/host*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrarServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "host", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_RegistrarServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "host", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrarServerPort!UCI:asterisk/sip_service_provider,@i-1/port*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrarServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "port", DEFAULT_SIP_PORT_STR);
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
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "port", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.RegistrarServerTransport!UCI:asterisk/sip_service_provider,@i-1/transport*/
static int get_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "transport", value);
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
			if (dm_validate_string(value, -1, -1, RegistrarServerTransport, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			for (char *ch = value; *ch != '\0'; ch++)
				*ch = tolower(*ch);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "transport", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.UserAgentDomain!UCI:asterisk/sip_service_provider,@i-1/domain*/
static int get_ServicesVoiceServiceSIPNetwork_UserAgentDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "domain", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_UserAgentDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "domain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.OutboundProxy!UCI:asterisk/sip_service_provider,@i-1/outbound_proxy*/
static int get_ServicesVoiceServiceSIPNetwork_OutboundProxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "outbound_proxy", value);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_OutboundProxy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "outbound_proxy", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.OutboundProxyPort!UCI:asterisk/sip_service_provider,@i-1/outbound_proxy_port*/
static int get_ServicesVoiceServiceSIPNetwork_OutboundProxyPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "outbound_proxy_port", DEFAULT_SIP_PORT_STR);
	return 0;
}

static int set_ServicesVoiceServiceSIPNetwork_OutboundProxyPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "outbound_proxy_port", value);
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
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
			if (dm_validate_string(value, -1, -1, NULL, NULL))
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
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "codecs", &tmp);
	if (tmp && *tmp) {
		char buf[256] = "";
		char *token, *saveptr;
		int len = 0;

		for (token = strtok_r(tmp, ", ", &saveptr); token; token = strtok_r(NULL, ", ", &saveptr)) {
			const char *codec = get_codec_name(token);
			if (codec && len < sizeof(buf)) {
				int res = snprintf(buf + len, sizeof(buf) - len, "%s%s", len == 0 ? "" : ",", codec);
				if (res <= 0) {
					BBF_DEBUG("buf might be too small\n");
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
	char *codec_list = NULL, *token = NULL, *saveptr = NULL, *uci_name = NULL;
	int res = 0;

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
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "codecs", "");

				if (*value) {
					codec_list = dmstrdup(value);
					for (token = strtok_r(codec_list, ", ", &saveptr); token;
						 token = strtok_r(NULL, ", ", &saveptr)) {
						uci_name = (char *)get_codec_uci_name(token);
						if (uci_name) {
							dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "codecs", uci_name);
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
	*value = (DM_LSTRCMP(*value, "yes") == 0) ? "1" : "0";
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
	return get_server_address(((struct dmmap_dup *)data)->config_section, "domain", value);
}

static int set_ServicesVoiceServiceSIPNetworkFQDNServer_Domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_address(((struct dmmap_dup *)data)->config_section, "domain", value);
			break;
	}
	return 0;
}

/*#Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer.Port!UCI:asterisk/sip_service_provider,@i-1/domain*/
static int get_ServicesVoiceServiceSIPNetworkFQDNServer_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_server_port(((struct dmmap_dup *)data)->config_section, "domain", value);
}

static int set_ServicesVoiceServiceSIPNetworkFQDNServer_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_port(((struct dmmap_dup *)data)->config_section, "domain", value);
			break;
	}
	return 0;
}

/*Get Device.Services.VoiceService.{i}.SIP.Network.{i}. Alias*/
static int get_ServicesVoiceServiceSIPNetwork_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_Alias_value_by_inst(refparam, ctx, data, instance, value, "networkalias");
}

/*Set Device.Services.VoiceService.{i}.SIP.Network.{i}. Alias*/
static int set_ServicesVoiceServiceSIPNetwork_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_Alias_value_by_inst(refparam, ctx, data, instance, value, action, "networkalias");
}


/*Get Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer. Alias*/
static int get_ServicesVoiceServiceSIPNetworkFQDNServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    return get_Alias_value_by_name(refparam, ctx, data, instance, value, "FQDNServer", "FQDNServer_inst");
}

/*Set Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer. Alias*/
static int set_ServicesVoiceServiceSIPNetworkFQDNServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
    return set_Alias_value_by_name(refparam, ctx, data, instance, value, action, "FQDNServer", "FQDNServer_inst");
}

/*Get Device.Services.VoiceService.{i}.SIP.Client.{i}. Alias*/
static int get_ServicesVoiceServiceSIPClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    return get_Alias_value_by_name(refparam, ctx, data, instance, value, "SIPClient", "SIPClient_inst");
}

/*Set Device.Services.VoiceService.{i}.SIP.Client.{i}. Alias*/
static int set_ServicesVoiceServiceSIPClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
    return set_Alias_value_by_name(refparam, ctx, data, instance, value, action, "SIPClient", "SIPClient_inst");
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Services.VoiceService.{i}.SIP. *** */
DMOBJ tServicesVoiceServiceSIPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Client", &DMWRITE, addObjServicesVoiceServiceSIPClient, delObjServicesVoiceServiceSIPClient, NULL, browseServicesVoiceServiceSIPClientInst, NULL, NULL, tServicesVoiceServiceSIPClientObj, tServicesVoiceServiceSIPClientParams, get_voice_service_sip_client_linker, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"Network", &DMWRITE, addObjServicesVoiceServiceSIPNetwork, delObjServicesVoiceServiceSIPNetwork, NULL, browseServicesVoiceServiceSIPNetworkInst, NULL, NULL, tServicesVoiceServiceSIPNetworkObj, tServicesVoiceServiceSIPNetworkParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Client.{i}. *** */
DMOBJ tServicesVoiceServiceSIPClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
// {"Contact", &DMWRITE, addObjServicesVoiceServiceSIPClientContact, delObjServicesVoiceServiceSIPClientContact, NULL, browseServicesVoiceServiceSIPClientContactInst, NULL, NULL, NULL, tServicesVoiceServiceSIPClientContactParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceSIPClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceSIPClient_Enable, set_ServicesVoiceServiceSIPClient_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPClient_Status, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPClient_Origin, NULL, BBFDM_BOTH},
{"AuthUserName", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPClient_AuthUserName, set_ServicesVoiceServiceSIPClient_AuthUserName, BBFDM_BOTH},
{"AuthPassword", &DMWRITE, DMT_STRING, get_empty, set_ServicesVoiceServiceSIPClient_AuthPassword, BBFDM_BOTH},
{"RegisterURI", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPClient_RegisterURI, set_ServicesVoiceServiceSIPClient_RegisterURI, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPClient_Alias, set_ServicesVoiceServiceSIPClient_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Network.{i}. *** */
DMOBJ tServicesVoiceServiceSIPNetworkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"FQDNServer", &DMWRITE, NULL, NULL, NULL, browseServicesVoiceServiceSIPNetworkFQDNServerInst, NULL, NULL, NULL, tServicesVoiceServiceSIPNetworkFQDNServerParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Domain", NULL}},
//{"FQDNServer", &DMWRITE, addObjServicesVoiceServiceSIPNetworkFQDNServer, delObjServicesVoiceServiceSIPNetworkFQDNServer, NULL, browseServicesVoiceServiceSIPNetworkFQDNServerInst, NULL, NULL, NULL, tServicesVoiceServiceSIPNetworkFQDNServerParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Domain", NULL}},
{0}
};

DMLEAF tServicesVoiceServiceSIPNetworkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceSIPNetwork_Enable, set_ServicesVoiceServiceSIPNetwork_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Status, NULL, BBFDM_BOTH},
{"ProxyServer", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_ProxyServer, set_ServicesVoiceServiceSIPNetwork_ProxyServer, BBFDM_BOTH},
{"ProxyServerPort", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_ProxyServerPort, set_ServicesVoiceServiceSIPNetwork_ProxyServerPort, BBFDM_BOTH},
{"ProxyServerTransport", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Transport, set_ServicesVoiceServiceSIPNetwork_Transport, BBFDM_BOTH},
{"RegistrarServer", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_RegistrarServer, set_ServicesVoiceServiceSIPNetwork_RegistrarServer, BBFDM_BOTH},
{"RegistrarServerPort", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_RegistrarServerPort, set_ServicesVoiceServiceSIPNetwork_RegistrarServerPort, BBFDM_BOTH},
{"RegistrarServerTransport", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport, set_ServicesVoiceServiceSIPNetwork_RegistrarServerTransport, BBFDM_BOTH},
{"UserAgentDomain", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_UserAgentDomain, set_ServicesVoiceServiceSIPNetwork_UserAgentDomain, BBFDM_BOTH},
{"OutboundProxy", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_OutboundProxy, set_ServicesVoiceServiceSIPNetwork_OutboundProxy, BBFDM_BOTH},
{"OutboundProxyPort", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_OutboundProxyPort, set_ServicesVoiceServiceSIPNetwork_OutboundProxyPort, BBFDM_BOTH},
{"UserAgentTransport", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Transport, set_ServicesVoiceServiceSIPNetwork_Transport, BBFDM_BOTH},
{"STUNServer", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_STUNServer, set_ServicesVoiceServiceSIPNetwork_STUNServer, BBFDM_BOTH},
{"RegistrationPeriod", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_RegistrationPeriod, set_ServicesVoiceServiceSIPNetwork_RegistrationPeriod, BBFDM_BOTH},
{"Realm", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Realm, set_ServicesVoiceServiceSIPNetwork_Realm, BBFDM_BOTH},
{"RegisterExpires", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_RegisterExpires, set_ServicesVoiceServiceSIPNetwork_RegisterExpires, BBFDM_BOTH},
{"DSCPMark", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetwork_DSCPMark, set_ServicesVoiceServiceSIPNetwork_DSCPMark, BBFDM_BOTH},
{"CodecList", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_CodecList, set_ServicesVoiceServiceSIPNetwork_CodecList, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetwork_Alias, set_ServicesVoiceServiceSIPNetwork_Alias, BBFDM_BOTH},
{0}
};

/* *** Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer. *** */
DMLEAF tServicesVoiceServiceSIPNetworkFQDNServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ServicesVoiceServiceSIPNetworkFQDNServer_Enable, set_ServicesVoiceServiceSIPNetworkFQDNServer_Enable, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_ServicesVoiceServiceSIPNetworkFQDNServer_Origin, NULL, BBFDM_BOTH},
{"Domain", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetworkFQDNServer_Domain, set_ServicesVoiceServiceSIPNetworkFQDNServer_Domain, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_ServicesVoiceServiceSIPNetworkFQDNServer_Port, set_ServicesVoiceServiceSIPNetworkFQDNServer_Port, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ServicesVoiceServiceSIPNetworkFQDNServer_Alias, set_ServicesVoiceServiceSIPNetworkFQDNServer_Alias, BBFDM_BOTH},
{0}
};
