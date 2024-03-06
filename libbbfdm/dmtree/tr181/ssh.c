/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Suvendhu Hansa <suvendhu.hansa@iopsys.eu>
 *
 */

#include "ssh.h"

#define DROPBEAR_KEY_FILE "/etc/dropbear/authorized_keys"

struct ssh_session_args {
	struct list_head list;
	char ip[45];
	char port[6];
	char pid[15];
};

static void add_pubkey(const char *cur, const char *new)
{
	if (DM_STRLEN(cur) == 0) {
		if (DM_STRLEN(new) == 0)
			return;

		FILE *fp = fopen(DROPBEAR_KEY_FILE, "a");
		if (fp != NULL) {
			fputs(new, fp);
			fclose(fp);
		}
	} else {
		char line[5120] = {0};
		FILE *fp = fopen(DROPBEAR_KEY_FILE, "r");
		FILE *tmp = fopen("replace.tmp", "w");

		if (fp == NULL || tmp == NULL)
			return;

		while (fgets(line, sizeof(line), fp) != NULL) {
			remove_new_line(line);
			if (DM_STRCMP(line, cur) == 0 && DM_STRLEN(new) != 0)
				fputs(new, tmp);
			else
				fputs(line, tmp);
		}

		fclose(fp);
		fclose(tmp);

		remove(DROPBEAR_KEY_FILE);
		rename("replace.tmp", DROPBEAR_KEY_FILE);
	}
}

static void remove_pubkey(const char *key)
{
	if (DM_STRLEN(key) == 0)
		return;

	char line[5120] = {0};
	FILE *fp = fopen(DROPBEAR_KEY_FILE, "r");
	FILE *tmp = fopen("replace.tmp", "w");

	if (fp == NULL || tmp == NULL)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		remove_new_line(line);
		if (DM_STRCMP(line, key) != 0)
			fputs(line, tmp);
	}

	fclose(fp);
	fclose(tmp);

	remove(DROPBEAR_KEY_FILE);
	rename("replace.tmp", DROPBEAR_KEY_FILE);
}

static bool key_exist_in_keyfile(const char *key)
{
	if (DM_STRLEN(key) == 0)
		return true;

	char line[5120] = {0};
	FILE *fp = fopen(DROPBEAR_KEY_FILE, "r");
	if (fp == NULL)
		return false;

	bool ret = false;
	while (fgets(line, sizeof(line), fp) != NULL) {
		remove_new_line(line);
		if (DM_STRCMP(line, key) == 0) {
			ret = true;
			break;
		}
	}

	fclose(fp);
	return ret;
}

static bool key_exists(const char *key)
{
	struct uci_section *s = NULL, *stmp = NULL;
	bool exists = false;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_dropbear", "authkey", stmp, s) {
		char *val = NULL;
		dmuci_get_value_by_section_string(s, "pubkey", &val);
		if (DM_STRCMP(val, key) == 0) {
			exists = true;
			break;
		}
	}

	return exists;
}

static void ssh_server_session_init(struct list_head *sess_list)
{
	char cmd[512] = {0};

	snprintf(cmd, sizeof(cmd), "netstat -ntp | grep dropbear | awk \'{print $5,$7}\' | cut -d\'/\' -f 1");
	FILE *pp = popen(cmd, "r");
	if (pp == NULL)
		return;

	char line[256] = {0};
	while (fgets(line, sizeof(line), pp) != NULL) {
		remove_new_line(line);
		if (DM_STRLEN(line) == 0)
			continue;

		char *port = NULL;
		char *pid = NULL;

		char *chr = strchr(line, ':');
		if (chr) {
			*chr = 0;
			port = chr + 1;
		}

		if (DM_STRLEN(port) != 0) {
			char *sp = strchr(port, ' ');
			if (sp) {
				*sp = 0;
				pid = sp + 1;
			}
		}

		struct ssh_session_args *session = dmcalloc(1, sizeof(struct ssh_session_args));
		if (session == NULL)
			break;

		strncpy(session->ip, line, sizeof(session->ip));
		if (DM_STRLEN(port) != 0) {
			snprintf(session->port, sizeof(session->port), "%s", port);
		}

		if (DM_STRLEN(pid) != 0) {
			snprintf(session->pid, sizeof(session->pid), "%s", pid);
		}


		list_add_tail(&session->list, sess_list);
	}

	pclose(pp);
}

static void free_ssh_session_list(struct list_head *sess_list)
{
	struct ssh_session_args *session = NULL, *tmp = NULL;
	list_for_each_entry_safe(session, tmp, sess_list, list) {
		list_del(&session->list);
		dmfree(session);
	}
}

static void close_active_sessions(struct uci_section *s)
{
	bool b;
	char *value = dmuci_get_value_by_section_fallback_def(s, "enable", "1");
	string_to_bool(value, &b);
	if (!b)
		return;

	char pid_file[125] = {0};
	char *sec_name = section_name(s);
	if (DM_STRLEN(sec_name) == 0)
		return;

	snprintf(pid_file, sizeof(pid_file), "/var/run/dropbear.%s.pid", sec_name);
	if (DM_STRLEN(pid_file) == 0)
		return;

	FILE *fp = fopen(pid_file, "r");
	if (fp == NULL)
		return;

	unsigned int pid;
	if (fscanf(fp, "%u", &pid) != 1) {
		fclose(fp);
		return;
	}

	fclose(fp);
	char cmd[512] = {0};
	snprintf(cmd, sizeof(cmd), "ps -w | grep %s | grep -v grep | awk \'{print $1}\'", pid_file);
	FILE *pp = popen(cmd, "r");
	if (pp == NULL)
		return;

	char line[15] = {0};
	while (fgets(line, sizeof(line), pp) != NULL) {
		remove_new_line(line);
		if (DM_STRLEN(line) == 0)
			continue;

		if (strtoul(line, NULL, 10) == pid)
			continue;

		snprintf(cmd, sizeof(cmd), "kill -15 %s", line);
		if (system(cmd) == -1) {
			break;
		}
	}

	pclose(pp);
}

/*************************************************************
 * ADD & DEL OBJ
 *************************************************************/
static int addObjSSHServer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char s_name[16];

	snprintf(s_name, sizeof(s_name), "server_%s", *instance);

	dmuci_add_section("dropbear", "dropbear", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "Port", "22");
	dmuci_set_value_by_section(s, "IdleTimeout", "180");
	dmuci_set_value_by_section(s, "SSHKeepAlive", "300");
	dmuci_set_value_by_section(s, "RootLogin", "0");
	dmuci_set_value_by_section(s, "PasswordAuth", "0");
	dmuci_set_value_by_section(s, "RootPasswordAuth", "0");
	dmuci_set_value_by_section(s, "MaxAuthTries", "3");

	dmuci_add_section_bbfdm("dmmap_dropbear", "dropbear", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_s, "server_instance", *instance);
	return 0;
}

static int delObjSSHServer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			close_active_sessions(((struct dm_data *)data)->config_section);
			dmuci_delete_by_section(((struct dm_data *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dm_data *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("dropbear", "dropbear", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				close_active_sessions(s);
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjSSHKey(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL;

	dmuci_add_section_bbfdm("dmmap_dropbear", "authkey", &s);
	return 0;
}

static int delObjSSHKey(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *value = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "pubkey", &value);
			remove_pubkey(value);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dropbear", "authkey", stmp, s) {
				dmuci_get_value_by_section_string(s, "pubkey", &value);
				remove_pubkey(value);
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
 * ENTRY METHODS
 *************************************************************/
static int browseSSHServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_data *curr_data = NULL;
	LIST_HEAD(dup_list);
	LIST_HEAD(session_list);
	char *inst = NULL;

	ssh_server_session_init(&session_list);
	synchronize_specific_config_sections_with_dmmap("dropbear", "dropbear", "dmmap_dropbear", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {
		bool b;
		char *enable = dmuci_get_value_by_section_fallback_def(curr_data->config_section, "enable", "1");
		char *act_date = dmuci_get_value_by_section_fallback_def(curr_data->dmmap_section, "activationdate", "");

		string_to_bool(enable, &b);
		if (b && DM_STRLEN(act_date) == 0) {
			char *tm = NULL;
			dm_time_format(time(NULL), &tm);
			dmuci_set_value_by_section(curr_data->dmmap_section, "activationdate", tm);
		}

		curr_data->additional_data = (void *)&session_list;

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "server_instance", "server_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_ssh_session_list(&session_list);
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseSSHKeyInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *inst = NULL;
	char line[5120] = {0};

	/* create entries for the keys available in DROPBEAR_KEY_FILE but not in dmmap */
	FILE *fp = fopen(DROPBEAR_KEY_FILE, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp) != NULL) {
			struct uci_section *dmmap_sect = NULL;
			remove_new_line(line);
			bool exists = false;

			uci_path_foreach_sections_safe(bbfdm, "dmmap_dropbear", "authkey", stmp, s) {
				char *val = NULL;
				dmuci_get_value_by_section_string(s, "pubkey", &val);
				if (DM_STRCMP(val, line) == 0) {
					exists = true;
					break;
				}
			}

			if (!exists) {
				dmmap_sect = NULL;
				dmuci_add_section_bbfdm("dmmap_dropbear", "authkey", &dmmap_sect);
				dmuci_set_value_by_section(dmmap_sect, "pubkey", line);
			}
		}

		fclose(fp);
	}

	/* delete keys from dmmap which are not available in DROPBEAR_KEY_FILE */
	stmp = NULL;
	s = NULL;
	uci_path_foreach_sections_safe(bbfdm, "dmmap_dropbear", "authkey", stmp, s) {
		char *val = NULL;
		dmuci_get_value_by_section_string(s, "pubkey", &val);
		if (!key_exist_in_keyfile(val)) {
			dmuci_delete_by_section(s, NULL, NULL);
		}
	}

	/* enlist objects */
	stmp = NULL;
	s = NULL;
	uci_path_foreach_sections_safe(bbfdm, "dmmap_dropbear", "authkey", stmp, s) {
		inst = handle_instance(dmctx, parent_node, s, "instance", "alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseSSHServerSessionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	bool b;
	char *inst = NULL;
	int id = 0;

	struct uci_section *s = ((struct dm_data *)prev_data)->config_section;
	char *value = dmuci_get_value_by_section_fallback_def(s, "enable", "1");
	string_to_bool(value, &b);
	if (!b)
		return 0;

	char pid_file[125] = {0};
	char *sec_name = section_name(s);
	if (DM_STRLEN(sec_name) == 0)
		return 0;

	snprintf(pid_file, sizeof(pid_file), "/var/run/dropbear.%s.pid", sec_name);
	if (DM_STRLEN(pid_file) == 0)
		return 0;

	FILE *fp = fopen(pid_file, "r");
	if (fp == NULL)
		return 0;

	unsigned int pid;
	if (fscanf(fp, "%u", &pid) != 1) {
		fclose(fp);
		return 0;
	}

	fclose(fp);
	char cmd[512] = {0};
	snprintf(cmd, sizeof(cmd), "ps -w | grep %s | grep -v grep | awk \'{print $1}\'", pid_file);
	FILE *pp = popen(cmd, "r");
	if (pp == NULL) {
		return 0;
	}

	char line[15] = {0};
	while (fgets(line, sizeof(line), pp) != NULL) {
		remove_new_line(line);
		if (DM_STRLEN(line) == 0)
			continue;

		if (strtoul(line, NULL, 10) == pid) {
			continue;
		}

		struct ssh_session_args *session = NULL;
		struct list_head *sess_list = (struct list_head *)((struct dm_data *)prev_data)->additional_data;
		bool found = false;
		list_for_each_entry(session, sess_list, list) {
			if (DM_STRCMP(session->pid, line) == 0) {
				found = true;
				break;
			}
		}

		if (found) {
			inst = handle_instance_without_section(dmctx, parent_node, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)session, inst) == DM_STOP)
				break;
		}
	}

	pclose(pp);
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ssh_server_num(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseSSHServerInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_ssh_key_num(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseSSHKeyInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_ssh_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

static int get_ssh_server_session_num(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseSSHServerSessionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_ssh_server_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "enable", "1");
	return 0;
}

static int set_ssh_server_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			char *cur = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "enable", "1");
			bool cur_val;
			string_to_bool(cur, &cur_val);

			if (b == cur_val)
				break;

			if (b) {
				dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "enable", "1");
				char *tm = NULL;
				dm_time_format(time(NULL), &tm);
				dmuci_set_value_by_section(((struct dm_data *)data)->dmmap_section, "activationdate", tm);
			} else {
				close_active_sessions(((struct dm_data *)data)->config_section);
				dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "enable", "0");
				dmuci_set_value_by_section(((struct dm_data *)data)->dmmap_section, "activationdate", "");
			}
			break;
	}
	return 0;	
}

static int get_ssh_server_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "server_alias", instance, value);
}

static int set_ssh_server_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "server_alias", instance, value);
}

static int get_ssh_server_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "Interface", &linker);
	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", linker, value);
	return 0;
}

static int set_ssh_server_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "Interface", reference.value);
			break;
	}
	return 0;	
}

static int get_ssh_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "Port", "22");
	return 0;
}

static int set_ssh_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","65535"}},1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "Port", value);
			break;
	}
	return 0;	
}

static int get_ssh_server_idle(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "IdleTimeout", "0");
	return 0;
}

static int set_ssh_server_idle(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}},1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "IdleTimeout", value);
			break;
	}
	return 0;	
}

static int get_ssh_server_keepalive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "SSHKeepAlive", "300");
	return 0;
}

static int set_ssh_server_keepalive(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}},1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "SSHKeepAlive", value);
			break;
	}
	return 0;	
}

static int get_ssh_server_rootlogin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "RootLogin", "1");
	return 0;
}

static int set_ssh_server_rootlogin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "RootLogin", b ? "1" : "0");
			break;
	}
	return 0;	
}

static int get_ssh_server_passwordlogin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "PasswordAuth", "1");
	return 0;
}

static int set_ssh_server_passwordlogin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "PasswordAuth", b ? "1" : "0");
			break;
	}
	return 0;	
}

static int get_ssh_server_rootpasswordlogin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "RootPasswordAuth", "1");
	return 0;
}

static int set_ssh_server_rootpasswordlogin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "RootPasswordAuth", b ? "1" : "0");
			break;
	}
	return 0;	
}

static int get_ssh_server_maxauthtries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "MaxAuthTries", "3");
	return 0;
}

static int set_ssh_server_maxauthtries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}},1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "MaxAuthTries", value);
			break;
	}
	return 0;	
}

static int get_ssh_server_activationdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->dmmap_section, "activationdate", value);
	return 0;
}

static int get_ssh_server_pid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	struct uci_section *s = ((struct dm_data *)data)->config_section;
	char *en = dmuci_get_value_by_section_fallback_def(s, "enable", "1");

	*value = "0";
	string_to_bool(en, &b);
	if (!b)
		return 0;

	char *sec_name = section_name(s);
	if (DM_STRLEN(sec_name) == 0)
		return 0;

	char pid_file[256] = {0};
	snprintf(pid_file, sizeof(pid_file), "/var/run/dropbear.%s.pid", sec_name);
	if (DM_STRLEN(pid_file) == 0)
		return 0;

	FILE *fp = fopen(pid_file, "r");
	if (fp == NULL)
		return 0;

	unsigned int pid;
	if (fscanf(fp, "%u", &pid) != 1) {
		fclose(fp);
		return 0;
	}

	fclose(fp);
	dmasprintf(value, "%u", pid);
	return 0;
}

static int get_ssh_server_session_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ssh_session_args *args = (struct ssh_session_args *)data;
	*value = DM_STRLEN(args->ip) ? dmstrdup(args->ip) : "";
	return 0;
}

static int get_ssh_server_session_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct ssh_session_args *args = (struct ssh_session_args *)data;
	*value = DM_STRLEN(args->port) ? dmstrdup(args->port) : "";
	return 0;
}

static int get_ssh_key_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (struct uci_section *)data, "alias", instance, value);
}

static int set_ssh_key_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (struct uci_section *)data, "alias", instance, value);
}

static int get_ssh_key_pubkey(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "pubkey", value);
	return 0;
}

static int set_ssh_key_pubkey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *cur_val = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;

			/* check if same as current key value */
			dmuci_get_value_by_section_string((struct uci_section *)data, "pubkey", &cur_val);
			if (DM_STRCMP(cur_val, value) == 0)
				break;

			if (key_exists(value))
				return FAULT_9001;

			break;
		case VALUESET:
			/* check if same as current key value then nothing to do */
			dmuci_get_value_by_section_string((struct uci_section *)data, "pubkey", &cur_val);
			if (DM_STRCMP(cur_val, value) == 0)
				break;

			add_pubkey(cur_val, value);
			dmuci_set_value_by_section((struct uci_section *)data, "pubkey", value);
			break;
	}
	return 0;	
}

static int operate_session_delete(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int ret = -1;

	struct ssh_session_args *args = (struct ssh_session_args *)data;
	if (DM_STRLEN(args->pid) != 0) {
		char cmd[128] = {0};
		snprintf(cmd, sizeof(cmd), "kill -15 %s", args->pid);
		ret = system(cmd);
	}

	return (ret != -1) ? 0 : USP_FAULT_COMMAND_FAILURE;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.SSH. *** */
DMOBJ tSSHObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Server", &DMWRITE, addObjSSHServer, delObjSSHServer, NULL, browseSSHServerInst, NULL, NULL, tSSHServerObj, tSSHServerParams, NULL, BBFDM_BOTH, NULL},
{"AuthorizedKey", &DMWRITE, addObjSSHKey, delObjSSHKey, NULL, browseSSHKeyInst, NULL, NULL, NULL, tSSHKeyParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMOBJ tSSHServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Session", &DMREAD, NULL, NULL, NULL, browseSSHServerSessionInst, NULL, NULL, NULL, tSSHServerSessionParams, NULL, BBFDM_BOTH, NULL},
{0}
};

/* *** Device.SSH. *** */
DMLEAF tSSHParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_ssh_server_num, NULL, BBFDM_BOTH},
{"AuthorizedKeyNumberOfEntries", &DMREAD, DMT_UNINT, get_ssh_key_num, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ssh_status, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.SSH.Server. *** */
DMLEAF tSSHServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_ssh_server_enable, set_ssh_server_enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ssh_server_alias, set_ssh_server_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Interface", &DMWRITE, DMT_STRING, get_ssh_server_interface, set_ssh_server_interface, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"Port", &DMWRITE, DMT_UNINT, get_ssh_server_port, set_ssh_server_port, BBFDM_BOTH},
{"IdleTimeout", &DMWRITE, DMT_UNINT, get_ssh_server_idle, set_ssh_server_idle, BBFDM_BOTH},
{"KeepAlive", &DMWRITE, DMT_UNINT, get_ssh_server_keepalive, set_ssh_server_keepalive, BBFDM_BOTH},
{"AllowRootLogin", &DMWRITE, DMT_BOOL, get_ssh_server_rootlogin, set_ssh_server_rootlogin, BBFDM_BOTH},
{"AllowPasswordLogin", &DMWRITE, DMT_BOOL, get_ssh_server_passwordlogin, set_ssh_server_passwordlogin, BBFDM_BOTH},
{"AllowRootPasswordLogin", &DMWRITE, DMT_BOOL, get_ssh_server_rootpasswordlogin, set_ssh_server_rootpasswordlogin, BBFDM_BOTH},
{"MaxAuthTries", &DMWRITE, DMT_UNINT, get_ssh_server_maxauthtries, set_ssh_server_maxauthtries, BBFDM_BOTH},
{"ActivationDate", &DMREAD, DMT_TIME, get_ssh_server_activationdate, NULL, BBFDM_BOTH},
{"PID", &DMREAD, DMT_UNINT, get_ssh_server_pid, NULL, BBFDM_BOTH},
{"SessionNumberOfEntries", &DMREAD, DMT_UNINT, get_ssh_server_session_num, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tSSHServerSessionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IPAddress", &DMREAD, DMT_STRING, get_ssh_server_session_ip, NULL, BBFDM_BOTH},
{"Port", &DMREAD, DMT_UNINT, get_ssh_server_session_port, NULL, BBFDM_BOTH},
{"Delete()", &DMSYNC, DMT_COMMAND, NULL, operate_session_delete, BBFDM_USP},
{0}
};

DMLEAF tSSHKeyParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_ssh_key_alias, set_ssh_key_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Key", &DMWRITE, DMT_STRING, get_ssh_key_pubkey, set_ssh_key_pubkey, BBFDM_BOTH},
{0}
};

