/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *      Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "users.h"

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Users.User.{i}.!UCI:users/user/dmmap_users*/
static int browseUserInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("users", "user", "dmmap_users", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "user_instance", "user_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int add_users_user(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_user = NULL;
	char sec_name[32];

	snprintf(sec_name, sizeof(sec_name), "user_%s", *instance);

	dmuci_add_section("users", "user", &s);
	dmuci_rename_section_by_section(s, sec_name);
	dmuci_set_value_by_section(s, "enabled", "0");
	dmuci_set_value_by_section(s, "remote_access", "0");

	dmuci_add_section_bbfdm("dmmap_users", "user", &dmmap_user);
	dmuci_set_value_by_section(dmmap_user, "section_name", sec_name);
	dmuci_set_value_by_section(dmmap_user, "user_instance", *instance);
	return 0;
}

static int delete_users_user(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("users", "user", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_users", "user", section_name(s), &dmmap_section);
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
/*#Device.Users.UserNumberOfEntries!UCI:users/user/*/
static int get_users_user_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseUserInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Users.User.{i}.Alias!UCI:dmmap_users/user,@i-1/user_alias*/
static int get_user_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "user_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

/*#Device.Users.User.{i}.Enable!UCI:users/user,@i-1/enabled*/
static int get_user_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "1");
    return 0;
}

static int get_user_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "section_name", value);
    return 0;
}

/*#Device.Users.User.{i}.Password!UCI:users/user,@i-1/password*/
static int get_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
    return 0;
}

/*#Device.Users.User.{i}.RemoteAccessCapable!UCI:users/user,@i-1/remote_access*/
static int get_user_remote_accessable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "remote_access", "1");
    return 0;
}

/*#Device.Users.User.{i}.Language!UCI:users/user,@i-1/language*/
static int get_user_language(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "language", value);
    return 0;
}

static int set_user_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "user_alias", value);
			return 0;
	}
	return 0;
}

static int set_user_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int set_user_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;

			// Check if the value is empty
			if (*value == '\0')
				return FAULT_9007;
			break;
		case VALUESET:
			// Update dmmap_users file
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "section_name", value);

			// Update users config
			dmuci_rename_section_by_section(((struct dmmap_dup *)data)->config_section, value);
			break;
	}
	return 0;
}

static int set_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "password", value);
			break;
	}
	return 0;
}

static int set_user_remote_accessable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "remote_access", b ? "1" : "0");
			break;
	}
	return 0;
}

static int set_user_language(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 16, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "language", value);
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.Users. *** */
DMOBJ tUsersObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"User", &DMWRITE, add_users_user, delete_users_user, NULL, browseUserInst, NULL, NULL, NULL, tUsersUserParams, NULL, BBFDM_BOTH, LIST_KEY{"Username", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tUsersParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"UserNumberOfEntries", &DMREAD, DMT_UNINT, get_users_user_number_of_entries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.Users.User.{i}. *** */
DMLEAF tUsersUserParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_user_alias, set_user_alias, BBFDM_BOTH, "2.3"},
{"Enable", &DMWRITE, DMT_BOOL, get_user_enable, set_user_enable, BBFDM_BOTH, "2.0"},
{"Username", &DMWRITE, DMT_STRING, get_user_username, set_user_username, BBFDM_BOTH, "2.0"},
{"Password", &DMWRITE, DMT_STRING, get_user_password, set_user_password, BBFDM_BOTH, "2.0"},
{"RemoteAccessCapable", &DMWRITE, DMT_BOOL, get_user_remote_accessable, set_user_remote_accessable, BBFDM_BOTH, "2.0"},
{"Language", &DMWRITE, DMT_STRING, get_user_language, set_user_language, BBFDM_BOTH, "2.0"},
{0}
};
