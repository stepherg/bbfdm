/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#include "x_test_com_dropbear.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
int browse_dropbear_instance(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dropbear", "dropbear", "dmmap_dropbear", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "dropbearinstance", "dropbearalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
int add_dropbear_instance(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dropbear_sec = NULL, *dmmap_sec = NULL;

	dmuci_add_section("dropbear", "dropbear", &dropbear_sec);
	dmuci_set_value_by_section(dropbear_sec, "verbose", "0");
	dmuci_set_value_by_section(dropbear_sec, "Port", "22");
	dmuci_set_value_by_section(dropbear_sec, "RootLogin", "1");
	dmuci_set_value_by_section(dropbear_sec, "GatewayPorts", "0");
	dmuci_set_value_by_section(dropbear_sec, "SSHKeepAlive", "300");
	dmuci_set_value_by_section(dropbear_sec, "IdleTimeout", "0");

	dmuci_add_section_bbfdm("dmmap_dropbear", "dropbear", &dmmap_sec);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(dropbear_sec));
	dmuci_set_value_by_section(dmmap_sec, "dropbearinstance", *instance);
	return 0;
}

int delete_dropbear_instance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
				dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
				dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("dropbear", "dropbear", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_x_test_com_dropbear_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "PasswordAuth", "1");
	*value = ((DM_STRCMP(res, "on") == 0) || *res == '1') ? "1" : "0";
	return 0;
}

static int set_x_test_com_dropbear_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "PasswordAuth", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_test_com_dropbear_root_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "RootPasswordAuth", "1");
	*value = ((DM_STRCMP(res, "on") == 0) || *res == '1') ? "1" : "0";
	return 0;
}

static int set_x_test_com_dropbear_root_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "RootPasswordAuth", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_test_com_dropbear_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "Port", "22");
	return 0;
}

static int set_x_test_com_dropbear_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "Port", value);
			return 0;
	}
	return 0;
}

static int get_x_test_com_dropbear_root_login(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "RootLogin", value);
	if ((*value)[0] == '\0' || ((*value)[0] == 'o' && (*value)[1] == 'n') || (*value)[0] == '1' )
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_x_test_com_dropbear_root_login(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "RootLogin", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_test_com_dropbear_gateway_ports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "GatewayPorts", "0");
	return 0;
}

static int set_x_test_com_dropbear_gateway_ports(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "GatewayPorts", b ? "1" : "");
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/*** Device.X_TEST_COM_Dropbear.{i}. ****/
DMLEAF X_TEST_COM_DropbearParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"PasswordAuth", &DMWRITE, DMT_BOOL, get_x_test_com_dropbear_password_auth, set_x_test_com_dropbear_password_auth, BBFDM_BOTH},
{"RootPasswordAuth", &DMWRITE, DMT_BOOL, get_x_test_com_dropbear_root_password_auth, set_x_test_com_dropbear_root_password_auth, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_x_test_com_dropbear_port, set_x_test_com_dropbear_port, BBFDM_BOTH},
{"RootLogin", &DMWRITE, DMT_BOOL, get_x_test_com_dropbear_root_login, set_x_test_com_dropbear_root_login, BBFDM_BOTH},
{"GatewayPorts", &DMWRITE, DMT_BOOL, get_x_test_com_dropbear_gateway_ports, set_x_test_com_dropbear_gateway_ports, BBFDM_BOTH},
{0}
};
