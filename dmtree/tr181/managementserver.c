/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "managementserver.h"
#include "dmbbfcommon.h"

/*#Device.ManagementServer.URL!UCI:cwmp/acs,acs/url*/
static int get_management_server_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp = NULL, *url = NULL, *dhcp_url = NULL;
	bool discovery = false;

	dmuci_get_option_value_string("cwmp", "acs", "dhcp_discovery", &dhcp);
	dmuci_get_option_value_string("cwmp", "acs", "url", &url);
	dmuci_get_option_value_string("cwmp", "acs", "dhcp_url", &dhcp_url);

	discovery = dmuci_string_to_boolean(dhcp);

	if ((discovery == true) && (DM_STRLEN(dhcp_url) != 0))
		*value = dhcp_url;
	else if (DM_STRLEN(url) != 0)
		*value = url;
	else
		*value = "";

	return 0;
}

static int set_management_server_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "dhcp_discovery", "disable");
			dmuci_set_value("cwmp", "acs", "url", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.Username!UCI:cwmp/acs,acs/userid*/
static int get_management_server_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "userid", value);
	return 0;	
}

static int set_management_server_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "userid", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.Password!UCI:cwmp/acs,acs/passwd*/
static int set_management_server_passwd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "passwd", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.ScheduleReboot!UCI:cwmp/cpe,cpe/schedule_reboot*/
static int get_management_server_schedule_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "schedule_reboot", value);
	return 0;
}

static int set_management_server_schedule_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "schedule_reboot", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.DelayReboot!UCI:cwmp/cpe,cpe/delay_reboot*/
static int get_management_server_delay_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "cpe", "delay_reboot", "-1");
	return 0;
}

static int set_management_server_delay_reboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "delay_reboot", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.ParameterKey!UCI:cwmp/acs,acs/ParameterKey*/
static int get_management_server_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_varstate("cwmp", "cpe", "ParameterKey", value);
	return 0;	
}

/*#Device.ManagementServer.PeriodicInformEnable!UCI:cwmp/acs,acs/periodic_inform_enable*/
static int get_management_server_periodic_inform_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "periodic_inform_enable", "1");
	return 0;	
}

static int set_management_server_periodic_inform_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:			
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp", "acs", "periodic_inform_enable", b ? "1" : "0");
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.PeriodicInformInterval!UCI:cwmp/acs,acs/periodic_inform_interval*/
static int get_management_server_periodic_inform_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "periodic_inform_interval", "1800");
	return 0;
}

static int set_management_server_periodic_inform_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "periodic_inform_interval", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.PeriodicInformTime!UCI:cwmp/acs,acs/periodic_inform_time*/
static int get_management_server_periodic_inform_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "periodic_inform_time", value);
	return 0;	
}

static int set_management_server_periodic_inform_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "periodic_inform_time", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

static int network_get_ipaddr(char *iface, int ipver, char **value)
{
	json_object *res = NULL, *jobj = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", iface, String}}, 1, &res);
	DM_ASSERT(res, *value = "");


	if (ipver == 6)
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
	else
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");

	*value = dmjson_get_value(jobj, 1, "address");

	if ((*value)[0] == '\0')
		return -1;

	return 0;
}

/*#Device.ManagementServer.ConnectionRequestURL!UCI:cwmp/cpe,cpe/port*/
static int get_management_server_connection_request_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ip = NULL, *port = NULL, *interface = NULL, *iface_name = NULL, *ip_version = NULL;

	dmuci_get_option_value_string("cwmp", "cpe", "default_wan_interface", &interface);
	dmuci_get_option_value_string("cwmp", "cpe", "interface", &iface_name);
	dmuci_get_option_value_string("cwmp", "acs", "ip_version", &ip_version);
	dmuci_get_option_value_string("cwmp", "cpe", "port", &port);

	if (network_get_ipaddr(interface, *ip_version == '6' ? 6 : 4, &ip) == -1) {
		// get ip from ioctl
		ip = (*ip_version == '6') ? get_ipv6(iface_name) : ioctl_get_ipv4(iface_name);
	}

	if (ip[0] != '\0' && port[0] != '\0') {
		char *path;

		dmuci_get_option_value_string("cwmp", "cpe", "path", &path);
		dmasprintf(value, "http://%s:%s/%s", ip, port, path ? path : "");
	}
	return 0;
}

/*#Device.ManagementServer.ConnectionRequestUsername!UCI:cwmp/cpe,cpe/userid*/
static int get_management_server_connection_request_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "userid", value);
	return 0;
}

static int set_management_server_connection_request_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "userid", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.ConnectionRequestPassword!UCI:cwmp/cpe,cpe/passwd*/
static int set_management_server_connection_request_passwd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "passwd", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UpgradesManaged!UCI:cwmp/cpe,cpe/upgrades_managed*/
static int get_upgrades_managed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "cpe", "upgrades_managed", "false");
	return 0;
}

static int set_upgrades_managed(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "upgrades_managed", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_lwn_protocol_supported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "UDP";
	return 0;
}

/*#Device.ManagementServer.LightweightNotificationProtocolsUsed!UCI:cwmp/lwn,lwn/enable*/
static int get_lwn_protocol_used(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	char *tmp;
	
	dmuci_get_option_value_string("cwmp", "lwn", "enable", &tmp);
	string_to_bool(tmp, &b);
	*value = b ? "UDP" : "";
	return 0;
}

static int set_lwn_protocol_used(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_STRCMP(value,"UDP") == 0)
				dmuci_set_value("cwmp", "lwn", "enable", "1");
			else
				dmuci_set_value("cwmp", "lwn", "enable", "0");
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UDPLightweightNotificationHost!UCI:cwmp/lwn,lwn/hostname*/
static int get_lwn_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{	
	dmuci_get_option_value_string("cwmp", "lwn", "hostname", value);
	return 0;
}

static int set_lwn_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "lwn", "hostname", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UDPLightweightNotificationPort!UCI:cwmp/lwn,lwn/port*/
static int get_lwn_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "lwn", "port", "7547");
	return 0;
}

static int set_lwn_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "lwn", "port", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_management_server_http_compression_supportted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "GZIP,Deflate";
	return 0;
}

/*#Device.ManagementServer.HTTPCompression!UCI:cwmp/acs,acs/compression*/
static int get_management_server_http_compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "compression", value);
	return 0;
}

static int set_management_server_http_compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcasecmp(value, "gzip") == 0 || strcasecmp(value, "deflate") == 0 || strncasecmp(value, "disable", 7) == 0) {
				dmuci_set_value("cwmp", "acs", "compression", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			}
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.CWMPRetryMinimumWaitInterval!UCI:cwmp/acs,acs/retry_min_wait_interval*/
static int get_management_server_retry_min_wait_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "retry_min_wait_interval", "5");
	return 0;
}

static int set_management_server_retry_min_wait_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "retry_min_wait_interval", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.CWMPRetryIntervalMultiplier!UCI:cwmp/acs,acs/retry_interval_multiplier*/
static int get_management_server_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "acs", "retry_interval_multiplier", "2000");
	return 0;
}

static int set_management_server_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1000","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "retry_interval_multiplier", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.AliasBasedAddressing!UCI:cwmp/cpe,cpe/amd_version*/
static int get_alias_based_addressing(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_option_value_fallback_def("cwmp", "cpe", "amd_version", "5");
	*value = (DM_STRTOL(res) <= AMD_4) ? "false" : "true";
	return 0;
}

/*#Device.ManagementServer.InstanceMode!UCI:cwmp/cpe,cpe/instance_mode*/
static int get_instance_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("cwmp", "cpe", "instance_mode", "InstanceNumber");
	return 0;
}

static int set_instance_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, InstanceMode, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "instance_mode", value);
			bbf_set_end_session_flag(ctx, BBF_END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*
 * XMPP parameters
 */
/*#Device.ManagementServer.ConnReqAllowedJabberIDs!UCI:xmpp/xmpp,xmpp/allowed_jid*/
static int get_management_server_conn_rep_allowed_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("xmpp", "xmpp", "allowed_jid", value);
	return 0;
}

static int set_management_server_conn_rep_allowed_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 32, -1, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("xmpp", "xmpp", "allowed_jid", value);
			return 0;
	}
	return 0;
}

static int get_management_server_conn_req_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *username, *domain, *resource, *tmpPtr = NULL, *strResponse = NULL;

	uci_foreach_sections("xmpp", "xmpp_connection", s) {
		dmuci_get_value_by_section_string(s, "username", &username);
		dmuci_get_value_by_section_string(s, "domain", &domain);
		dmuci_get_value_by_section_string(s, "resource", &resource);
		if(*username != '\0' || *domain != '\0' || *resource != '\0') {
			if(!strResponse)
				dmasprintf(&strResponse, "%s@%s/%s", username, domain, resource);
			else {
				tmpPtr = dmstrdup(strResponse);
				dmfree(strResponse);
				dmasprintf(&strResponse, "%s,%s@%s/%s", tmpPtr, username, domain, resource);
				dmfree(tmpPtr);
			}
		}
	}
	*value = strResponse ? strResponse : "";
	return 0;
}

static int get_management_server_conn_req_xmpp_connection(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *id;

	dmuci_get_option_value_string("xmpp", "xmpp", "id", &id);
	if (*id != '\0' && *id != '0') dmasprintf(value, "Device.XMPP.Connection.%s", id);
	return 0;
}

static int set_management_server_conn_req_xmpp_connection(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *str, *xmpp_id;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if ((str = DM_STRSTR(value, "Device.XMPP.Connection."))) {
				value = dmstrdup(str + sizeof("Device.XMPP.Connection.") - 1); //MEM WILL BE FREED IN DMMEMCLEAN
			}
			uci_foreach_sections("xmpp", "connection", s) {
				dmuci_get_value_by_section_string(s, "xmpp_id", &xmpp_id);
				if(DM_STRCMP(value, xmpp_id) == 0) {
					dmuci_set_value("xmpp", "xmpp", "id", value);
					break;
				}
			}
			return 0;
	}
	return 0;
}

static int get_management_server_supported_conn_req_methods(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,XMPP,STUN";
	return 0;
}

static int get_management_server_instance_wildcard_supported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int get_management_server_enable_cwmp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "enable", value);
	if ((*value)[0] == '\0')
		*value = "1";
	return 0;
}

static int set_management_server_enable_cwmp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp", "cpe", "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/*** ManagementServer. ***/
DMLEAF tManagementServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"URL", &DMWRITE, DMT_STRING, get_management_server_url, set_management_server_url, BBFDM_CWMP},
{"Username", &DMWRITE, DMT_STRING, get_management_server_username, set_management_server_username, BBFDM_CWMP, "2.0"},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_management_server_passwd, BBFDM_CWMP, "2.0"},
{"ScheduleReboot", &DMWRITE, DMT_TIME, get_management_server_schedule_reboot, set_management_server_schedule_reboot, BBFDM_CWMP, "2.10"},
{"DelayReboot", &DMWRITE, DMT_INT, get_management_server_delay_reboot, set_management_server_delay_reboot, BBFDM_CWMP, "2.10"},
{"PeriodicInformEnable", &DMWRITE, DMT_BOOL, get_management_server_periodic_inform_enable, set_management_server_periodic_inform_enable,  BBFDM_CWMP, "2.0"},
{"PeriodicInformInterval", &DMWRITE, DMT_UNINT, get_management_server_periodic_inform_interval, set_management_server_periodic_inform_interval, BBFDM_CWMP, "2.0"},
{"PeriodicInformTime", &DMWRITE, DMT_TIME, get_management_server_periodic_inform_time, set_management_server_periodic_inform_time, BBFDM_CWMP, "2.0"},
{"ParameterKey", &DMREAD, DMT_STRING, get_management_server_key, NULL, BBFDM_CWMP, "2.0"},
{"ConnectionRequestURL", &DMREAD, DMT_STRING, get_management_server_connection_request_url, NULL, BBFDM_CWMP, "2.0"},
{"ConnectionRequestUsername", &DMWRITE, DMT_STRING, get_management_server_connection_request_username, set_management_server_connection_request_username, BBFDM_CWMP, "2.0"},
{"ConnectionRequestPassword", &DMWRITE, DMT_STRING, get_empty, set_management_server_connection_request_passwd,  BBFDM_CWMP, "2.0"},
{"UpgradesManaged", &DMWRITE, DMT_BOOL, get_upgrades_managed, set_upgrades_managed, BBFDM_CWMP, "2.0"},
{"HTTPCompressionSupported", &DMREAD, DMT_STRING, get_management_server_http_compression_supportted, NULL, BBFDM_CWMP, "2.7"},
{"HTTPCompression", &DMWRITE, DMT_STRING, get_management_server_http_compression, set_management_server_http_compression, BBFDM_CWMP, "2.7"},
{"LightweightNotificationProtocolsSupported", &DMREAD, DMT_STRING, get_lwn_protocol_supported, NULL, BBFDM_CWMP, "2.7"},
{"LightweightNotificationProtocolsUsed", &DMWRITE, DMT_STRING, get_lwn_protocol_used, set_lwn_protocol_used, BBFDM_CWMP, "2.7"},
{"UDPLightweightNotificationHost", &DMWRITE, DMT_STRING, get_lwn_host, set_lwn_host, BBFDM_CWMP, "2.7"},
{"UDPLightweightNotificationPort", &DMWRITE, DMT_UNINT, get_lwn_port, set_lwn_port, BBFDM_CWMP, "2.7"},
{"CWMPRetryMinimumWaitInterval", &DMWRITE, DMT_UNINT, get_management_server_retry_min_wait_interval, set_management_server_retry_min_wait_interval, BBFDM_CWMP, "2.0"},
{"CWMPRetryIntervalMultiplier", &DMWRITE, DMT_UNINT, get_management_server_retry_interval_multiplier, set_management_server_retry_interval_multiplier, BBFDM_CWMP, "2.0"},
{"AliasBasedAddressing", &DMREAD, DMT_BOOL, get_alias_based_addressing, NULL, BBFDM_CWMP, "2.3"},
{"InstanceMode", &DMWRITE, DMT_STRING, get_instance_mode, set_instance_mode, BBFDM_CWMP, "2.3"},
{"ConnReqAllowedJabberIDs", &DMWRITE, DMT_STRING, get_management_server_conn_rep_allowed_jabber_id, set_management_server_conn_rep_allowed_jabber_id, BBFDM_CWMP, "2.7"},
{"ConnReqJabberID", &DMREAD, DMT_STRING, get_management_server_conn_req_jabber_id, NULL, BBFDM_CWMP, "2.7"},
{"ConnReqXMPPConnection", &DMWRITE, DMT_STRING, get_management_server_conn_req_xmpp_connection, set_management_server_conn_req_xmpp_connection, BBFDM_CWMP, "2.7"},
{"SupportedConnReqMethods", &DMREAD, DMT_STRING, get_management_server_supported_conn_req_methods, NULL, BBFDM_CWMP, "2.7"},
{"InstanceWildcardsSupported", &DMREAD, DMT_BOOL, get_management_server_instance_wildcard_supported, NULL, BBFDM_CWMP, "2.12"},
{"EnableCWMP", &DMWRITE, DMT_BOOL, get_management_server_enable_cwmp, set_management_server_enable_cwmp, BBFDM_CWMP, "2.12"},
{0}
};
