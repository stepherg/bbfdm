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

#include "ppp.h"

struct ppp_args
{
	struct uci_section *iface_s;
	struct uci_section *dmmap_s;
};

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
void ppp___update_sections(struct uci_section *s_from, struct uci_section *s_to)
{
	char *proto = NULL;
	char *device = NULL;
	char *username = NULL;
	char *password = NULL;
	char *pppd_options = NULL;
	char *service = NULL;
	char *ac = NULL;

	dmuci_get_value_by_section_string(s_from, "proto", &proto);
	dmuci_get_value_by_section_string(s_from, "device", &device);
	dmuci_get_value_by_section_string(s_from, "username", &username);
	dmuci_get_value_by_section_string(s_from, "password", &password);
	dmuci_get_value_by_section_string(s_from, "pppd_options", &pppd_options);
	dmuci_get_value_by_section_string(s_from, "service", &service);
	dmuci_get_value_by_section_string(s_from, "ac", &ac);

	dmuci_set_value_by_section(s_to, "proto", proto);
	dmuci_set_value_by_section(s_to, "device", device);
	dmuci_set_value_by_section(s_to, "username", username);
	dmuci_set_value_by_section(s_to, "password", password);
	dmuci_set_value_by_section(s_to, "pppd_options", pppd_options);
	dmuci_set_value_by_section(s_to, "service", service);
	dmuci_set_value_by_section(s_to, "ac", ac);
}

void ppp___reset_options(struct uci_section *ppp_s)
{
	dmuci_set_value_by_section(ppp_s, "device", "");
	dmuci_set_value_by_section(ppp_s, "username", "");
	dmuci_set_value_by_section(ppp_s, "password", "");
	dmuci_set_value_by_section(ppp_s, "pppd_options", "");
	dmuci_set_value_by_section(ppp_s, "service", "");
	dmuci_set_value_by_section(ppp_s, "ac", "");
}

static bool is_ppp_section_exist(char *sec_name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_ppp", "interface", "iface_name", sec_name, s) {
		return true;
	}

	return false;
}

static void dmmap_synchronizePPPInterface(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_ppp", "interface", stmp, s) {
		char *added_by_controller = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(s, "added_by_controller", &added_by_controller);
		if (DM_LSTRCMP(added_by_controller, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name)) {
			struct uci_section *iface_s = NULL;

			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

			if (!iface_s)
				dmuci_delete_by_section(s, NULL, NULL);
		}
	}

	uci_foreach_sections("network", "interface", s) {
		struct uci_section *ppp_s = NULL;
		char *proto = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (DM_LSTRNCMP(proto, "ppp", 3) != 0)
			continue;

		if (is_ppp_section_exist(section_name(s)))
			continue;

		dmuci_add_section_bbfdm("dmmap_ppp", "interface", &ppp_s);
		dmuci_set_value_by_section(ppp_s, "iface_name", section_name(s));
		ppp___update_sections(s, ppp_s);
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct ppp_args curr_ppp_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizePPPInterface(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap_ppp", "interface", s) {
		struct uci_section *iface_s = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name))
			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

		curr_ppp_args.iface_s = iface_s;
		curr_ppp_args.dmmap_s = s;

		inst = handle_instance(dmctx, parent_node, s, "ppp_int_instance", "ppp_int_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ppp_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_ppp_interface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_ppp = NULL;
	char name[8] = {0};

	snprintf(name, sizeof(name), "ppp_%s", *instance);

	dmuci_add_section_bbfdm("dmmap_ppp", "interface", &dmmap_ppp);
	dmuci_set_value_by_section(dmmap_ppp, "name", name);
	dmuci_set_value_by_section(dmmap_ppp, "proto", "ppp");
	dmuci_set_value_by_section(dmmap_ppp, "disabled", "1");
	dmuci_set_value_by_section(dmmap_ppp, "added_by_controller", "1");
	dmuci_set_value_by_section(dmmap_ppp, "ppp_int_instance", *instance);
	return 0;
}

static int delete_ppp_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct ppp_args *)data)->dmmap_s, NULL, NULL);

			if (((struct ppp_args *)data)->iface_s) {
				dmuci_set_value_by_section(((struct ppp_args *)data)->iface_s, "proto", "none");
				ppp___reset_options(((struct ppp_args *)data)->iface_s);
			}
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_ppp", "interface", stmp, s) {
				struct uci_section *iface_s = NULL;
				char *iface_name = NULL;

				dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
				if (DM_STRLEN(iface_name))
					get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

				dmuci_delete_by_section(s, NULL, NULL);

				if (iface_s) {
					dmuci_set_value_by_section(iface_s, "proto", "none");
					ppp___reset_options(iface_s);
				}
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ppp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char *disabled = NULL;

	dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "disabled", &disabled);
	*value = (disabled && *disabled == '1') ? "0" : "1";
	return 0;
}

static int set_ppp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(ppp->dmmap_s, "disabled", b ? "0" : "1");
			if (ppp->iface_s)
				dmuci_set_value_by_section(ppp->iface_s, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

static int get_PPPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_ppp_enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Up" : "Down";
	return 0;
}

/*#Device.PPP.Interface.{i}.Alias!UCI:dmmap_network/interface,@i-1/ppp_int_alias*/
static int get_ppp_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ppp_args *)data)->dmmap_s, "ppp_int_alias", value);
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
			dmuci_set_value_by_section(((struct ppp_args *)data)->dmmap_s, "ppp_int_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_PPPInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "0");
		*value = dmjson_get_value(res, 1, "uptime");
	} else {
		*value = "0";
	}
	return 0;
}

static int get_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			/* Reset can disrupt on-going cwmp session, so this parameter must be
			 * taken care by cwmp internally.
			 */
			break;
	}
	return 0;
}

static int get_ppp_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ppp_args *)data)->dmmap_s, "name", value);
	if ((*value)[0] == '\0')
		*value = dmstrdup(section_name(((struct ppp_args *)data)->iface_s));
	return 0;
}

/*#Device.PPP.Interface.{i}.ConnectionStatus!UBUS:network.interface/status/interface,@Name/up*/
static int get_ppp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		char *status = NULL,  *uptime = NULL, *pending = NULL;
		json_object *res = NULL, *jobj = NULL;
		bool bstatus = false, bpend = false;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
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
		if (uptime && DM_STRTOL(uptime) > 0)
			*value = "Connected";
		else if (pending && bpend)
			*value = "Pending Disconnect";
		else
			*value = "Disconnected";
	} else {
		*value = "Unconfigured";
	}
	return 0;
}

static int get_PPPInterface_LastConnectionError(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "ERROR_NONE");
		char *status = dmjson_get_value(res, 2, "data", "lastconnectionerror");

		switch (DM_STRTOL(status)) {
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
	} else {
		*value = "ERROR_NONE";
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.Username!UCI:network/interface,@i-1/username*/
static int get_ppp_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "username", value);
	return 0;
}

static int set_ppp_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(ppp->dmmap_s, "username", value);
			if (ppp->iface_s)
				dmuci_set_value_by_section(ppp->iface_s, "username", value);
			return 0;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.Password!UCI:network/interface,@i-1/password*/
static int set_ppp_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(ppp->dmmap_s, "password", value);
			if (ppp->iface_s)
				dmuci_set_value_by_section(ppp->iface_s, "password", value);
			return 0;
	}
	return 0;
}

static int get_PPPInterface_MaxMRUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char *pppd_opt = NULL;

	dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "pppd_options", &pppd_opt);
	if (pppd_opt && *pppd_opt == '\0') {
		*value = "1500";
		return 0;
	}

	char *token = NULL , *end = NULL;
	token = strtok_r(pppd_opt, " ", &end);
	while (NULL != token) {
		if (0 == DM_LSTRCMP(token, "mru")) {
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

static int configure_pppd_mru(char *pppd_opt, char *mru_str, struct uci_section *sec, char *value)
{
	char *token = NULL, *end = NULL;
	char list_options[1024] = {0}, mru_opt[1024] = {0};
	unsigned pos = 0;
	bool found = false;

	list_options[0] = 0;
	token = strtok_r(pppd_opt, " ", &end);
	while (NULL != token) {
		if (0 == DM_LSTRCMP(token, "mru")) {
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

	dmuci_set_value_by_section(sec, "pppd_options", list_options);
	return 0;
}

static int set_PPPInterface_MaxMRUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char mru_str[1024] = {0};
	char *pppd_opt = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"64","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			snprintf(mru_str, sizeof(mru_str), "%s %s", "mru", value);
			dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "pppd_options", &pppd_opt);

			if (pppd_opt && *pppd_opt == '\0') {
				dmuci_set_value_by_section(ppp->dmmap_s, "pppd_options", mru_str);
				if (ppp->iface_s)
					dmuci_set_value_by_section(ppp->iface_s, "pppd_options", mru_str);
			} else {
				// If mru is specified then we need to replace and keep the rest of the options intact.
				configure_pppd_mru(pppd_opt, mru_str, ppp->dmmap_s, value);
				if (ppp->iface_s)
					configure_pppd_mru(pppd_opt, mru_str, ppp->iface_s, value);
			}
			break;
	}
	return 0;
}

static int get_PPPInterface_CurrentMRUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		char intf[64] = {0};

		snprintf(intf, sizeof(intf), "%s-%s", "pppoe", section_name(ppp_s));
		get_net_device_sysfs(intf, "mtu", value);
	}

	return 0;
}

static int get_PPPInterface_LCPEcho(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		char *lcp_echo = NULL, *token = NULL;

		dmuci_get_value_by_section_string(ppp_s, "keepalive", &lcp_echo);
		if (lcp_echo && *lcp_echo == '\0') {
			*value = "1";
			return 0;
		}

		token = strtok(lcp_echo , " ");
		if (NULL != token) {
			char echo_val[50] = {0};

			DM_STRNCPY(echo_val, token, sizeof(echo_val));
			*value = dmstrdup(echo_val);
		}
	}
	return 0;
}

static int get_PPPInterface_LCPEchoRetry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		char *lcp_retry = NULL, *token = NULL;

		dmuci_get_value_by_section_string(ppp_s, "keepalive", &lcp_retry);
		if (!lcp_retry || *lcp_retry == '\0') {
			*value = "5";
		} else {
			token = DM_STRCHR(lcp_retry , ' ');
			if (NULL != token) {
				char lcp_interval[50] = {0};

				DM_STRNCPY(lcp_interval, token + 1, sizeof(lcp_interval));
				*value = dmstrdup(lcp_interval);
			}
		}
	}
	return 0;
}

static int configure_supported_ncp_options(struct uci_section *ss, char *value, char *option)
{
	char *proto, *pppd_opt = NULL;
	char list_options[1024] = {0};

	dmuci_get_value_by_section_string(ss, "proto", &proto);
	if (0 == DM_LSTRCMP(proto, "pppoe")) {
		dmuci_get_value_by_section_string(ss, "pppd_options", &pppd_opt);
	}

	if (pppd_opt && *pppd_opt != '\0') {
		char *token = NULL, *end = NULL;
		bool found = false;
		unsigned pos = 0;

		list_options[0] = 0;
		token = strtok_r(pppd_opt, " ", &end);
		while (NULL != token) {
			char ncp_opt[1024] = {0};
			DM_STRNCPY(ncp_opt, token, sizeof(ncp_opt));
			if (0 == DM_STRNCMP(ncp_opt, option, sizeof(ncp_opt))) {
				found = true;
				if (0 == DM_LSTRCMP(value, "1") && NULL != end) {
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

		if ((0 == DM_LSTRCMP(value, "0")) && found == false) {
			if (pos != 0)
				pos += snprintf(&list_options[pos], sizeof(list_options) - pos, "%c", ' ');

			snprintf(&list_options[pos], sizeof(list_options) - pos, "%s", option);
		}

		dmuci_set_value_by_section(ss, "pppd_options", list_options);
	} else {
		if (0 == DM_LSTRCMP(value, "0")) {
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

		if ((4 == DM_STRLEN(value)) && 0 == DM_LSTRCMP(value, "noip")) {
			noip = 1;
		}

		if (0 == DM_LSTRNCMP(value, "noipv6", 6)) {
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
	if (proto && DM_LSTRCMP(proto, "pppoe") == 0)
		dmuci_get_value_by_section_string(s, "pppd_options", &pppd_opt);

	return pppd_opt ? parse_pppd_options(pppd_opt, option) : 0;
}

static int get_PPPInterface_IPCPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	int ret = handle_supported_ncp_options(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, instance, IPCP);
	*value = ret ? "0" : "1";
	return 0;
}

static int set_PPPInterface_IPCPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			configure_supported_ncp_options(ppp->dmmap_s, value, "noip");
			if (ppp->iface_s)
				configure_supported_ncp_options(ppp->iface_s, value, "noip");

			break;
	}
	return 0;
}

static int get_PPPInterface_IPv6CPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	int ret = handle_supported_ncp_options(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, instance, IPCPv6);
	*value = ret ? "0" : "1";
	return 0;
}

static int set_PPPInterface_IPv6CPEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			configure_supported_ncp_options(ppp->dmmap_s, value, "noipv6");
			if (ppp->iface_s)
				configure_supported_ncp_options(ppp->iface_s, value, "noipv6");
			break;
	}
	return 0;
}

static int get_PPPInterfacePPPoE_SessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE *fp = fopen("/proc/net/pppoe" ,"r");
	if (NULL == fp) {
		*value  = "1";
	} else {
		char session_id[20] = {0};
		char path[1024] = {0};
		int i = 0;

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
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		json_object *ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		*value = dmjson_get_value(ipv4_obj, 1, "address");
	}
	return 0;
}

static int get_PPPInterfaceIPCP_RemoteIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		json_object *ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		*value = dmjson_get_value(ipv4_obj, 1, "ptpaddress");
		if (**value == '\0') {
			json_object *route_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "route");
			*value = dmjson_get_value(route_obj, 1, "nexthop");
		}
	}
	return 0;
}

static int get_PPPInterfaceIPCP_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		*value = dmjson_get_value_array_all(res, ",", 1, "dns-server");
	}
	return 0;
}

static int get_PPPInterfaceIPv6CP_LocalInterfaceIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		json_object *ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
		*value = dmjson_get_value(ipv4_obj, 1, "address");
	}
	return 0;
}

static int get_PPPInterfaceIPv6CP_RemoteInterfaceIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		json_object *res = NULL;

		char *if_name = section_name(ppp_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		*value = dmjson_get_value(res, 2, "data", "llremote");
	}
	return 0;
}

static int ppp_read_sysfs(void *data, const char *name, char **value)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	*value = "0";

	if (ppp_s) {
		char *proto;

		dmuci_get_value_by_section_string(ppp_s, "proto", &proto);
		if (!DM_LSTRCMP(proto, "pppoe")) {
			char *l3_device = get_l3_device(section_name(ppp_s));
			get_net_device_sysfs(l3_device, name, value);
		}
	}

	return 0;
}

static int get_PPPInterfaceStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
/*
 * Irrespective of underlying media, PPP is multicast incapable.
 * The stats pertaining to Multicast recv/xmit are irrelevant to ppp interfaces.
 * Hence the value of this stats marked ZERO.
 */
	*value = "0";
	return 0;
}

static int get_PPPInterfaceStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
/*
 * Irrespective of underlying media, PPP is broadcast incapable.
 * The stats pertaining to broadcast recv/xmit are irrelevant to ppp interfaces.
 * Hence the value of this stats marked ZERO.
 */
	*value = "0";
	return 0;
}

static int get_PPPInterfaceStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
/*
 * Irrespective of underlying media, PPP is broadcast incapable.
 * The stats pertaining to broadcast recv/xmit are irrelevant to ppp interfaces.
 * Hence the value of this stats marked ZERO.
 */
	*value = "0";
	return 0;
}

static int get_PPPInterfaceStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_unknown_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_PPPInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
/*
 * Irrespective of underlying media, PPP is multicast incapable.
 * The stats pertaining to Multicast recv/xmit are irrelevant for ppp interfaces.
 * Hence the value of this stats marked ZERO.
 */
	*value = "0";
        return 0;
}

/*#Device.PPP.Interface.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_ppp_eth_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.PPP.Interface.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_ppp_eth_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.PPP.Interface.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_ppp_eth_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_ppp_eth_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_PPPInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.PPP.Interface.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_PPPInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.PPP.Interface.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_PPPInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.PPP.Interface.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_PPPInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_dropped", value);
}

static int get_PPPInterfaceStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
/* By default all the data packets at a ppp end point are Unicast.
 * Hence the number of Unicast packets is equal to the tx_packets.
 */
	return ppp_read_sysfs(data, "statistics/tx_packets", value);
}

static int get_PPPInterfaceStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
/* Unicast Packets Received = (Total packets received - Unknown Protocol Packets Received)*/

	char *rx_other = NULL, *rx_pkts = NULL;
	unsigned long other_rcv = 0, total_rcv = 0;

	get_PPPInterfaceStats_UnknownProtoPacketsReceived(refparam, ctx, data, instance, &rx_other);
	get_ppp_eth_pack_received(refparam, ctx, data, instance, &rx_pkts);

	other_rcv = DM_STRTOUL(rx_other);
	total_rcv = DM_STRTOUL(rx_pkts);

	unsigned long ucast_rcv = total_rcv - other_rcv;
	dmasprintf(value, "%lu", ucast_rcv);
	return 0;
}

static int get_ppp_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;

	dmuci_get_value_by_section_string(ppp->dmmap_s, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		char *device = NULL;

		if (ppp->iface_s) {
			device = get_device(section_name(ppp->iface_s));
			if (DM_STRLEN(device) == 0)
				dmuci_get_value_by_section_string(ppp->iface_s, "device", &device);
		} else {
			dmuci_get_value_by_section_string(ppp->dmmap_s, "device", &device);
		}

		if (DM_STRLEN(device) == 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN", device, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.VLANTermination.", device, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Link.", device, value);
	} else {
		char *linker = NULL;

		adm_entry_get_linker_value(ctx, *value, &linker);
		if (!linker || *linker == 0)
			*value = "";
	}
	return 0;
}

static int set_ppp_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char eth_mac_vlan[] = "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN";
	char *allowed_objects[] = {
			eth_mac_vlan,
			"Device.Ethernet.VLANTermination.",
			"Device.Ethernet.Link.",
			NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);

			// Store LowerLayers value under dmmap_ppp section
			dmuci_set_value_by_section(ppp->dmmap_s, "LowerLayers", value);

			// Update proto option
			dmuci_set_value_by_section(ppp->dmmap_s, "proto", "pppoe");
			if (ppp->iface_s) dmuci_set_value_by_section(ppp->iface_s, "proto", "pppoe");

			if (DM_STRNCMP(value, "Device.Ethernet.Link.", DM_STRLEN("Device.Ethernet.Link.")) == 0) {
				struct uci_section *eth_link_s = NULL;
				char *is_eth = NULL;

				get_dmmap_section_of_config_section_eq("dmmap_ethernet", "link", "device", linker, &eth_link_s);
				if (eth_link_s) dmuci_get_value_by_section_string(eth_link_s, "is_eth", &is_eth);

				// Update proto option
				dmuci_set_value_by_section(ppp->dmmap_s, "proto", !DM_LSTRCMP(is_eth, "1") ? "pppoe" : "pppoa");
				if (ppp->iface_s) dmuci_set_value_by_section(ppp->iface_s, "proto", !DM_LSTRCMP(is_eth, "1") ? "pppoe" : "pppoa");
			}

			// Update device option
			dmuci_set_value_by_section(ppp->dmmap_s, "device", DM_STRLEN(linker) ? linker : "");
			if (ppp->iface_s) dmuci_set_value_by_section(ppp->iface_s, "device", DM_STRLEN(linker) ? linker : "");
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
	struct ppp_args *ppp = (struct ppp_args *)data;
	char *proto;

	dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "proto", &proto);
	if (DM_LSTRCMP(proto, "pppoe") == 0) {
		dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "ac", value);
		return 0;
	}
	return 0;
}

static int set_PPPInterfacePPPoE_ACName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char *proto_intf;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "proto", &proto_intf);
			if (DM_LSTRCMP(proto_intf, "pppoe") != 0)
				return FAULT_9001;
			break;
		case VALUESET:
			dmuci_set_value_by_section(ppp->dmmap_s, "ac", value);
			if (ppp->iface_s)
				dmuci_set_value_by_section(ppp->iface_s, "ac", value);
			break;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.PPPoE.ServiceName!UCI:network/interface,@i-1/service*/
static int get_PPPInterfacePPPoE_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char *proto;

	dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "proto", &proto);
	if (DM_LSTRCMP(proto, "pppoe") == 0) {
		dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "service", value);
		return 0;
	}
	return 0;
}

static int set_PPPInterfacePPPoE_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct ppp_args *ppp = (struct ppp_args *)data;
	char *proto;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(ppp->iface_s ? ppp->iface_s : ppp->dmmap_s, "proto", &proto);
			if (DM_LSTRCMP(proto, "pppoe") != 0)
				return FAULT_9001;
			break;
		case VALUESET:
			dmuci_set_value_by_section(ppp->dmmap_s, "service", value);
			if (ppp->iface_s)
				dmuci_set_value_by_section(ppp->iface_s, "service", value);
			break;
	}
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_ppp_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (((struct ppp_args *)data)->iface_s) {
		*linker = get_device(section_name(((struct ppp_args *)data)->iface_s));
		if (DM_STRLEN(*linker) == 0)
			dmuci_get_value_by_section_string(((struct ppp_args *)data)->iface_s, "device", linker);
	} else {
		dmuci_get_value_by_section_string(((struct ppp_args *)data)->dmmap_s, "device", linker);
	}

	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ppp_s = ((struct ppp_args *)data)->iface_s;

	if (ppp_s) {
		char interface_obj[64] = {0};

		snprintf(interface_obj, sizeof(interface_obj), "network.interface.%s", section_name(ppp_s));
		dmubus_call_set(interface_obj, "down", UBUS_ARGS{0}, 0);
		dmubus_call_set(interface_obj, "up", UBUS_ARGS{0}, 0);
	}

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.PPP. *** */
DMOBJ tPPPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Interface", &DMWRITE, add_ppp_interface, delete_ppp_interface, NULL, browseInterfaceInst, NULL, NULL, tPPPInterfaceObj, tPPPInterfaceParams, get_linker_ppp_interface, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tPPPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_PPP_InterfaceNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"SupportedNCPs", &DMREAD, DMT_STRING, get_PPP_SupportedNCPs, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.PPP.Interface.{i}. *** */
DMOBJ tPPPInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"PPPoE", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfacePPPoEParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"IPCP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceIPCPParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"IPv6CP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceIPv6CPParams, NULL, BBFDM_BOTH, NULL, "2.2"},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tPPPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_ppp_alias, set_ppp_alias, BBFDM_BOTH, "2.0"},
{"Enable", &DMWRITE, DMT_BOOL, get_ppp_enable, set_ppp_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_PPPInterface_Status, NULL, BBFDM_BOTH, "2.0"},
{"LastChange", &DMREAD, DMT_UNINT, get_PPPInterface_LastChange, NULL, BBFDM_BOTH, "2.0"},
{"Reset", &DMWRITE, DMT_BOOL, get_PPPInterface_Reset, set_PPPInterface_Reset, BBFDM_CWMP, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_ppp_name, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ppp_lower_layer, set_ppp_lower_layer, BBFDM_BOTH, "2.0"},
{"ConnectionStatus", &DMREAD, DMT_STRING, get_ppp_status, NULL, BBFDM_BOTH, "2.0"},
{"LastConnectionError", &DMREAD, DMT_STRING, get_PPPInterface_LastConnectionError, NULL, BBFDM_BOTH, "2.0"},
{"Username", &DMWRITE, DMT_STRING, get_ppp_username, set_ppp_username, BBFDM_BOTH, "2.0"},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_ppp_password, BBFDM_BOTH, "2.0"},
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_PPPInterface_Reset, BBFDM_USP, "2.12"},
{"MaxMRUSize", &DMWRITE, DMT_UNINT, get_PPPInterface_MaxMRUSize, set_PPPInterface_MaxMRUSize, BBFDM_BOTH, "2.0"},
{"CurrentMRUSize", &DMREAD, DMT_UNINT, get_PPPInterface_CurrentMRUSize, NULL, BBFDM_BOTH, "2.0"},
{"LCPEcho", &DMREAD, DMT_UNINT, get_PPPInterface_LCPEcho, NULL, BBFDM_BOTH, "2.0"},
{"LCPEchoRetry", &DMREAD, DMT_UNINT, get_PPPInterface_LCPEchoRetry, NULL, BBFDM_BOTH, "2.0"},
{"IPCPEnable", &DMWRITE, DMT_BOOL, get_PPPInterface_IPCPEnable, set_PPPInterface_IPCPEnable, BBFDM_BOTH, "2.2"},
{"IPv6CPEnable", &DMWRITE, DMT_BOOL, get_PPPInterface_IPv6CPEnable, set_PPPInterface_IPv6CPEnable, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.PPP.Interface.{i}.PPPoE. *** */
DMLEAF tPPPInterfacePPPoEParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SessionID", &DMREAD, DMT_UNINT, get_PPPInterfacePPPoE_SessionID, NULL, BBFDM_BOTH, "2.0"},
{"ACName", &DMWRITE, DMT_STRING, get_PPPInterfacePPPoE_ACName, set_PPPInterfacePPPoE_ACName, BBFDM_BOTH, "2.0"},
{"ServiceName", &DMWRITE, DMT_STRING, get_PPPInterfacePPPoE_ServiceName, set_PPPInterfacePPPoE_ServiceName, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.PPP.Interface.{i}.IPCP. *** */
DMLEAF tPPPInterfaceIPCPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"LocalIPAddress", &DMREAD, DMT_STRING, get_PPPInterfaceIPCP_LocalIPAddress, NULL, BBFDM_BOTH, "2.0"},
{"RemoteIPAddress", &DMREAD, DMT_STRING, get_PPPInterfaceIPCP_RemoteIPAddress, NULL, BBFDM_BOTH, "2.0"},
{"DNSServers", &DMREAD, DMT_STRING, get_PPPInterfaceIPCP_DNSServers, NULL, BBFDM_BOTH, "2.0"},
//{"PassthroughEnable", &DMWRITE, DMT_BOOL, get_PPPInterfaceIPCP_PassthroughEnable, set_PPPInterfaceIPCP_PassthroughEnable, BBFDM_BOTH, "2.0"},
//{"PassthroughDHCPPool", &DMWRITE, DMT_STRING, get_PPPInterfaceIPCP_PassthroughDHCPPool, set_PPPInterfaceIPCP_PassthroughDHCPPool, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.PPP.Interface.{i}.IPv6CP. *** */
DMLEAF tPPPInterfaceIPv6CPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version, version*/
{"LocalInterfaceIdentifier", &DMREAD, DMT_STRING, get_PPPInterfaceIPv6CP_LocalInterfaceIdentifier, NULL, BBFDM_BOTH, "2.2"},
{"RemoteInterfaceIdentifier", &DMREAD, DMT_STRING, get_PPPInterfaceIPv6CP_RemoteInterfaceIdentifier, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.PPP.Interface.{i}.Stats. *** */
DMLEAF tPPPInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesReceived", &DMREAD, DMT_UNLONG, get_ppp_eth_bytes_received, NULL, BBFDM_BOTH, "2.0"},
{"BytesSent", &DMREAD, DMT_UNLONG, get_ppp_eth_bytes_sent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ppp_eth_pack_received, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ppp_eth_pack_sent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{0}
};
