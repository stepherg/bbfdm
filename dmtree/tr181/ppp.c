/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "ppp.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.PPP.Interface.{i}.!UCI:network/interface/dmmap_network*/
static int browseInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *proto;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "interface", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "proto", &proto);
		if (!strstr(proto, "ppp"))
			continue;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "ppp_int_instance", "ppp_int_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_ppp_interface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_ppp = NULL;
	char name[16] = {0};

	snprintf(name, sizeof(name), "ppp_%s", *instance);

	dmuci_set_value("network", name, "", "interface");
	dmuci_set_value("network", name, "proto", "ppp");
	dmuci_set_value("network", name, "disabled", "1");

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_ppp);
	dmuci_set_value_by_section(dmmap_ppp, "section_name", name);
	dmuci_set_value_by_section(dmmap_ppp, "ppp_int_instance", *instance);
	return 0;
}

static int delete_ppp_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_cont_safe("network", "interface", "proto", "ppp", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(s), &dmmap_section);
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
/*#Device.PPP.Interface.{i}.Enable!UBUS:network.interface/status/interface,@Name/up*/
static int get_ppp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
	return 0;
}

static int set_ppp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *ubus_object;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmastrcat(&ubus_object, "network.interface.", section_name(((struct dmmap_dup *)data)->config_section));
			dmubus_call_set(ubus_object, b ? "up" : "down", UBUS_ARGS{}, 0);
			dmfree(ubus_object);
			break;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.Status!UBUS:network.interface/status/interface,@Name/up*/
static int get_PPPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *status;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "Down");
	status = dmjson_get_value(res, 1, "up");
	*value = (strcmp(status, "true") == 0) ? "Up" : "Down";
	return 0;
}

/*#Device.PPP.Interface.{i}.Alias!UCI:dmmap_network/interface,@i-1/ppp_int_alias*/
static int get_ppp_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "ppp_int_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ppp_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "ppp_int_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_PPPInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				char intf_obj[64] = {0};
				snprintf(intf_obj, sizeof(intf_obj), "network.interface.%s", section_name(((struct dmmap_dup *)data)->config_section));
				dmubus_call_set(intf_obj, "down", UBUS_ARGS{}, 0);
				dmubus_call_set(intf_obj, "up", UBUS_ARGS{}, 0);
			}
			break;
	}
	return 0;
}

static int get_ppp_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct dmmap_dup *)data)->config_section));
	return 0;
}

/*#Device.PPP.Interface.{i}.ConnectionStatus!UBUS:network.interface/status/interface,@Name/up*/
static int get_ppp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = NULL,  *uptime = NULL, *pending = NULL;
	json_object *res = NULL, *jobj = NULL;
	bool bstatus = false, bpend = false;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "Unconfigured");
	jobj = dmjson_get_obj(res, 1, "up");
	if (jobj) {
		status = dmjson_get_value(res, 1, "up");
		string_to_bool(status, &bstatus);
		if (bstatus) {
			uptime = dmjson_get_value(res, 1, "uptime");
			pending = dmjson_get_value(res, 1, "pending");			
			string_to_bool(pending, &bpend);
		}
	}
	if (uptime && atoi(uptime) > 0)
		*value = "Connected";
	else if (pending && bpend)
		*value = "Pending Disconnect";
	else
		*value = "Disconnected";
	return 0;
}

static int get_PPPInterface_LastConnectionError(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *status;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "ERROR_NONE");
	status = dmjson_get_value(res, 2, "data", "lastconnectionerror");

	switch (atoi(status)) {
		case 0:
			*value = "ERROR_NONE";
			break;
		case 1: case 10: case 13: case 14: case 17: case 18: case 20: case 22:
			*value = "ERROR_UNKNOWN";
			break;
		case 2: case 3: case 4: case 6: case 7: case 9:
			*value = "ERROR_COMMAND_ABORTED";
			break;
		case 5: case 15:
			*value = "ERROR_USER_DISCONNECT";
			break;
		case 8:
			*value = "ERROR_IP_CONFIGURATION";
			break;
		case 11: case 19: case 21:
			*value = "ERROR_AUTHENTICATION_FAILURE";
			break;
		case 12:
			*value = "ERROR_IDLE_DISCONNECT";
			break;
		case 16:
			*value = "ERROR_ISP_DISCONNECT";
			break;
		default:
			*value = "ERROR_NONE";
			break;
		}

	return 0;
}

/*#Device.PPP.Interface.{i}.Username!UCI:network/interface,@i-1/username*/
static int get_ppp_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "username", value);
	return 0;
}

static int set_ppp_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "username", value);
			return 0;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.Password!UCI:network/interface,@i-1/password*/
static int set_ppp_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "password", value);
			return 0;
	}
	return 0;
}

static int get_PPPInterface_MaxMRUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pppd_opt = NULL;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "pppd_options", &pppd_opt);
	if (pppd_opt && *pppd_opt == '\0') {
		*value = "1500";
		return 0;
	}

	char *token = NULL , *end = NULL;
	token = strtok_r(pppd_opt, " ", &end);
	while (NULL != token) {
		if (0 == strcmp(token, "mru")) {
			char mru_val[1024] = {0}, mru_str[1024] = {0};
			DM_STRNCPY(mru_val, end, sizeof(mru_val));
			sscanf(mru_val, "%1023s", mru_str);
			if ('\0' != mru_str[0]) {
				*value = dmstrdup(mru_str);
			}
			break;
		}
		token = strtok_r(NULL, " ", &end);
	}

	if (*value && (*value)[0] == '\0') {
		*value = "1500";
	}

	return 0;
}

static int configure_pppd_mru(char *pppd_opt, char *mru_str, void *data, char *value)
{
	char *token = NULL, *end = NULL;
	char list_options[1024] = {0}, mru_opt[1024] = {0};
	unsigned pos = 0;
	bool found = false;

	list_options[0] = 0;
	token = strtok_r(pppd_opt, " ", &end);
	while (NULL != token) {
		if (0 == strcmp(token, "mru")) {
			found = true;
			pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%s %s", token, value);
			DM_STRNCPY(mru_opt, end, sizeof(mru_opt));
			char *p, *q;
			p = strtok_r(mru_opt, " ", &q);
			if (p != NULL && q != NULL) {
				pos += snprintf(&list_options[pos], sizeof(list_options) - pos, " %s", q);
			}
			break;
		}
		pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%s ", token);
		token = strtok_r(NULL, " ", &end);
	}

	if (found == false)
		snprintf(&list_options[pos], sizeof(list_options) - pos, "%s", mru_str);

	dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "pppd_options", list_options);
	return 0;
}

static int set_PPPInterface_MaxMRUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char mru_str[1024] = {0};
	char *pppd_opt = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"64","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			snprintf(mru_str, sizeof(mru_str), "%s %s", "mru", value);
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "pppd_options", &pppd_opt);

			if (pppd_opt && *pppd_opt == '\0') {
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "pppd_options", mru_str);
			} else {
				// If mru is specified then we need to replace and keep the rest of the options intact.
				configure_pppd_mru(pppd_opt, mru_str, data, value);
			}
			break;
	}
	return 0;
}

static int get_PPPInterface_CurrentMRUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *status;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	status = dmjson_get_value(res, 1, "up");
	if (0 != strcmp(status, "true")) {
		*value = "";
		return 0;
	}

	char intf[1024] = {0};
	snprintf(intf, sizeof(intf), "%s-%s", "pppoe", section_name(((struct dmmap_dup *)data)->config_section));
	get_net_device_sysfs(intf, "mtu", value);

	return 0;
}

static int get_PPPInterface_LCPEcho(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *lcp_echo = NULL, *token = NULL;
	char echo_val[50] = {0};

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "keepalive", &lcp_echo);
	if (lcp_echo && *lcp_echo == '\0') {
		*value = "1";
		return 0;
	}

	token = strtok(lcp_echo , " ");
	if (NULL != token) {
		DM_STRNCPY(echo_val, token, sizeof(echo_val));
		*value = dmstrdup(echo_val);
	}

	return 0;
}

static int get_PPPInterface_LCPEchoRetry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *lcp_retry = NULL, *token = NULL;
	char lcp_interval[50] = {0};
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "keepalive", &lcp_retry);
	if (lcp_retry && *lcp_retry == '\0') {
		*value = "5";
	} else {
		token = strchr(lcp_retry , ' ');
		if (NULL != token) {
			DM_STRNCPY(lcp_interval, token + 1, sizeof(lcp_interval));
			*value = dmstrdup(lcp_interval);
		}
	}

	return 0;
}

static int configure_supported_ncp_options(struct uci_section *ss, char *value, char *option)
{
	char *proto, *pppd_opt = NULL;
	char list_options[1024] = {0};
	unsigned pos = 0;

	dmuci_get_value_by_section_string(ss, "proto", &proto);
	if (0 == strcmp(proto, "pppoe")) {
		dmuci_get_value_by_section_string(ss, "pppd_options", &pppd_opt);
	}

	if (pppd_opt && *pppd_opt != '\0') {
		char *token = NULL, *end = NULL;
		bool found = false;

		list_options[0] = 0;
		token = strtok_r(pppd_opt, " ", &end);
		while (NULL != token) {
			char ncp_opt[1024] = {0};
			DM_STRNCPY(ncp_opt, token, sizeof(ncp_opt));
			if (0 == strncmp(ncp_opt, option, sizeof(ncp_opt))) {
				found = true;
				if (0 == strcmp(value, "1") && NULL != end) {
					if (pos != 0)
						pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%c", ' ');

					pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%s", end);
					break;
				}
			} else {
				if (pos != 0)
					pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%c", ' ');

				pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%s", token);
			}
			token = strtok_r(NULL, " ", &end);
		}

		if ((0 == strcmp(value, "0")) && found == false) {
			if (pos != 0)
				pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%c", ' ');

			pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%s", option);
		}

		dmuci_set_value_by_section(ss, "pppd_options", list_options);
	} else {
		if (0 == strcmp(value, "0")) {
			dmuci_set_value_by_section(ss, "pppd_options", option);
		}
	}

	return 0;
}

static int parse_pppd_options(char *pppd_opt, int option)
{
	int noip = 0, noipv6 = 0;
	char *token = NULL, *end = NULL;

	token = strtok_r(pppd_opt, " ", &end);
	while (NULL != token) {
		char value[50] = {0};
		DM_STRNCPY(value, token, sizeof(value));

		if ((4 == strlen(value)) && 0 == strcmp(value, "noip")) {
			noip = 1;
		}

		if (0 == strncmp(value, "noipv6", 6)) {
			noipv6 = 1;
		}

		token = strtok_r(NULL, " ", &end);
	}

	if (option == IPCP) {
		return noip;
	} else {
		return noipv6;
	}
}

static int handle_supported_ncp_options(struct uci_section *s, char *instance, int option)
{
	char *pppd_opt = NULL, *proto = NULL;

	dmuci_get_value_by_section_string(s, "proto", &proto);
	if (proto && strcmp(proto, "pppoe") == 0)
		dmuci_get_value_by_section_string(s, "pppd_options", &pppd_opt);

	return pppd_opt ? parse_pppd_options(pppd_opt, option) : 0;
}

static int get_PPPInterface_IPCPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int ret = handle_supported_ncp_options(((struct dmmap_dup *)data)->config_section, instance, IPCP);
	*value = ret ? "0" : "1";
	return 0;
}

static int set_PPPInterface_IPCPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			configure_supported_ncp_options(((struct dmmap_dup *)data)->config_section, value, "noip");
			break;
	}
	return 0;
}

static int get_PPPInterface_IPv6CPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int ret = handle_supported_ncp_options(((struct dmmap_dup *)data)->config_section, instance, IPCPv6);
	*value = ret ? "0" : "1";
	return 0;
}

static int set_PPPInterface_IPv6CPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			configure_supported_ncp_options(((struct dmmap_dup *)data)->config_section, value, "noipv6");
			break;
	}
	return 0;
}

static int get_PPPInterfacePPPoE_SessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char path[1024] = {0};
	char session_id[20] = {0};
	FILE *fp;
	int i = 0;

	fp = fopen("/proc/net/pppoe" ,"r");
	if (NULL == fp) {
		*value  = "1";
	} else {
		while (fgets(path, sizeof(path), fp) != NULL) {
			i++;
			if (2 == i) {
				sscanf(path, "%19s", session_id);
				int number = (int)strtol(session_id, NULL, 16);
				memset(session_id, '\0', sizeof(session_id));
				snprintf(session_id, sizeof(session_id), "%d", number);
				if ('\0' == session_id[0]) {
					*value = "1";
				} else {
					*value = dmstrdup(session_id);
				}
				break;
			}
		}
		fclose(fp);
	}
	return 0;
}

static int get_PPPInterfaceIPCP_LocalIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	json_object *ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
	*value = dmjson_get_value(ipv4_obj, 1, "address");
	return 0;
}

static int get_PPPInterfaceIPCP_RemoteIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	json_object *ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
	*value = dmjson_get_value(ipv4_obj, 1, "ptpaddress");
	if (**value == '\0') {
		json_object *route_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "route");
		*value = dmjson_get_value(route_obj, 1, "nexthop");
	}
	return 0;
}

static int get_PPPInterfaceIPCP_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value_array_all(res, ",", 1, "dns-server");
	return 0;
}

static int get_PPPInterfaceIPv6CP_LocalInterfaceIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	json_object *ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
	*value = dmjson_get_value(ipv4_obj, 1, "address");
	return 0;
}

static int get_PPPInterfaceIPv6CP_RemoteInterfaceIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dmmap_dup *)data)->config_section), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "data", "llremote");
	return 0;
}

static int ppp_read_sysfs(struct uci_section *sect, const char *name, char **value)
{
	char *proto;
	int rc = 0;

	dmuci_get_value_by_section_string(sect, "proto", &proto);
	if (!strcmp(proto, "pppoe")) {
		char *l3_device = get_l3_device(section_name(sect));
		rc = get_net_device_sysfs(l3_device, name, value);
	}
	return rc;
}

/*#Device.PPP.Interface.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_ppp_eth_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_bytes", value);
}

/*#Device.PPP.Interface.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_ppp_eth_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_bytes", value);
}

/*#Device.PPP.Interface.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_ppp_eth_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_ppp_eth_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_PPPInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_errors", value);
}

/*#Device.PPP.Interface.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_PPPInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_errors", value);
}

/*#Device.PPP.Interface.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_PPPInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_dropped", value);
}

/*#Device.PPP.Interface.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_PPPInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_dropped", value);
}

/*#Device.PPP.Interface.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_PPPInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/multicast", value);
}

static int get_ppp_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker, *ifname;
	int ret = 0;
	struct uci_section *ss = NULL;
	char *dev = "0";

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "device", &linker);

	// Get wan interface
	dev = get_device(section_name(((struct dmmap_dup *)data)->config_section));

	// Check if interface name is same as dev value.
	char *token, *end = linker;
	while ((token = strtok_r(end, " ", &end))) {
		if (0 == strcmp(dev, token)) {
			ret = 1;
			break;
		}
	}

	if (0 == ret) {
		*value = "";
		return 0;
	}

	// Check if the interface is untagged or tagged.
	if (NULL != strchr(token, '.')) {
		// Get the device section and the ifname corresponding to it
		uci_foreach_option_eq("network", "device", "name", token, ss) {
			dmuci_get_value_by_section_string(ss, "ifname", &ifname);
			break;
		}
	} else {
		ifname = token;
	}

	adm_entry_get_linker_param(ctx, "Device.ATM.Link.", ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, "Device.PTM.Link.", ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", ifname, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_ppp_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *ppp_linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &ppp_linker);
			if (ppp_linker && *ppp_linker) {
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "device", ppp_linker);
				dmfree(ppp_linker);
			}
			return 0;
	}
	return 0;
}

static int get_PPP_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_PPP_SupportedNCPs(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "IPCP,IPv6CP";
	return 0;
}

/*#Device.PPP.Interface.{i}.PPPoE.ACName!UCI:network/interface,@i-1/ac*/
static int get_PPPInterfacePPPoE_ACName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "proto", &proto);
	if (strcmp(proto, "pppoe") == 0) {
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ac", value);
		return 0;
	}
	return 0;
}

static int set_PPPInterfacePPPoE_ACName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto_intf;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "proto", &proto_intf);
			if (strcmp(proto_intf, "pppoe") != 0)
				return FAULT_9001;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ac", value);
			break;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.PPPoE.ServiceName!UCI:network/interface,@i-1/service*/
static int get_PPPInterfacePPPoE_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "proto", &proto);
	if (strcmp(proto, "pppoe") == 0) {
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "service", value);
		return 0;
	}
	return 0;
}

static int set_PPPInterfacePPPoE_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "proto", &proto);
			if (strcmp(proto, "pppoe") != 0)
				return FAULT_9001;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "service", value);
			break;
	}
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_ppp_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = data ? dmstrdup(section_name(((struct dmmap_dup *)data)->config_section)) : "";
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char interface_obj[64] = {0};

	snprintf(interface_obj, sizeof(interface_obj), "network.interface.%s", section_name(((struct dmmap_dup *)data)->config_section));
	dmubus_call_set(interface_obj, "down", UBUS_ARGS{}, 0);
	dmubus_call_set(interface_obj, "up", UBUS_ARGS{}, 0);

	return CMD_SUCCESS;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.PPP. *** */
DMOBJ tPPPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Interface", &DMWRITE, add_ppp_interface, delete_ppp_interface, NULL, browseInterfaceInst, NULL, NULL, tPPPInterfaceObj, tPPPInterfaceParams, get_linker_ppp_interface, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

DMLEAF tPPPParams[] = {
/* PARAM, permission, type, getvlue, setvalue, bbfdm_type*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_PPP_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"SupportedNCPs", &DMREAD, DMT_STRING, get_PPP_SupportedNCPs, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}. *** */
DMOBJ tPPPInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"PPPoE", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfacePPPoEParams, NULL, BBFDM_BOTH},
{"IPCP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceIPCPParams, NULL, BBFDM_BOTH},
{"IPv6CP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceIPv6CPParams, NULL, BBFDM_BOTH},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tPPPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_ppp_alias, set_ppp_alias, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_ppp_enable, set_ppp_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_PPPInterface_Status, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_PPPInterface_LastChange, NULL, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_PPPInterface_Reset, set_PPPInterface_Reset, BBFDM_CWMP},
{"Name", &DMREAD, DMT_STRING, get_ppp_name, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ppp_lower_layer, set_ppp_lower_layer, BBFDM_BOTH},
{"ConnectionStatus", &DMREAD, DMT_STRING, get_ppp_status, NULL, BBFDM_BOTH},
{"LastConnectionError", &DMREAD, DMT_STRING, get_PPPInterface_LastConnectionError, NULL, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_ppp_username, set_ppp_username, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_ppp_password, BBFDM_BOTH},
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_PPPInterface_Reset, BBFDM_USP},
{"MaxMRUSize", &DMWRITE, DMT_UNINT, get_PPPInterface_MaxMRUSize, set_PPPInterface_MaxMRUSize, BBFDM_BOTH},
{"CurrentMRUSize", &DMREAD, DMT_UNINT, get_PPPInterface_CurrentMRUSize, NULL, BBFDM_BOTH},
{"LCPEcho", &DMREAD, DMT_UNINT, get_PPPInterface_LCPEcho, NULL, BBFDM_BOTH},
{"LCPEchoRetry", &DMREAD, DMT_UNINT, get_PPPInterface_LCPEchoRetry, NULL, BBFDM_BOTH},
{"IPCPEnable", &DMWRITE, DMT_BOOL, get_PPPInterface_IPCPEnable, set_PPPInterface_IPCPEnable, BBFDM_BOTH},
{"IPv6CPEnable", &DMWRITE, DMT_BOOL, get_PPPInterface_IPv6CPEnable, set_PPPInterface_IPv6CPEnable, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}.PPPoE. *** */
DMLEAF tPPPInterfacePPPoEParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SessionID", &DMREAD, DMT_UNINT, get_PPPInterfacePPPoE_SessionID, NULL, BBFDM_BOTH},
{"ACName", &DMWRITE, DMT_STRING, get_PPPInterfacePPPoE_ACName, set_PPPInterfacePPPoE_ACName, BBFDM_BOTH},
{"ServiceName", &DMWRITE, DMT_STRING, get_PPPInterfacePPPoE_ServiceName, set_PPPInterfacePPPoE_ServiceName, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}.IPCP. *** */
DMLEAF tPPPInterfaceIPCPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"LocalIPAddress", &DMREAD, DMT_STRING, get_PPPInterfaceIPCP_LocalIPAddress, NULL, BBFDM_BOTH},
{"RemoteIPAddress", &DMREAD, DMT_STRING, get_PPPInterfaceIPCP_RemoteIPAddress, NULL, BBFDM_BOTH},
{"DNSServers", &DMREAD, DMT_STRING, get_PPPInterfaceIPCP_DNSServers, NULL, BBFDM_BOTH},
//{"PassthroughEnable", &DMWRITE, DMT_BOOL, get_PPPInterfaceIPCP_PassthroughEnable, set_PPPInterfaceIPCP_PassthroughEnable, BBFDM_BOTH},
//{"PassthroughDHCPPool", &DMWRITE, DMT_STRING, get_PPPInterfaceIPCP_PassthroughDHCPPool, set_PPPInterfaceIPCP_PassthroughDHCPPool, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}.IPv6CP. *** */
DMLEAF tPPPInterfaceIPv6CPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"LocalInterfaceIdentifier", &DMREAD, DMT_STRING, get_PPPInterfaceIPv6CP_LocalInterfaceIdentifier, NULL, BBFDM_BOTH},
{"RemoteInterfaceIdentifier", &DMREAD, DMT_STRING, get_PPPInterfaceIPv6CP_RemoteInterfaceIdentifier, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}.Stats. *** */
DMLEAF tPPPInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesReceived", &DMREAD, DMT_UNLONG, get_ppp_eth_bytes_received, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNLONG, get_ppp_eth_bytes_sent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ppp_eth_pack_received, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ppp_eth_pack_sent, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};
