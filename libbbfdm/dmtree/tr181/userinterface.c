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

#include "userinterface.h"


struct http_session_args
{
	struct list_head list;
	char c_ip[45];
	char c_port[6];
	char s_port[6];
};

struct dmmap_http
{
	struct list_head list;
	struct uci_section *config_section;
	struct uci_section *dmmap_section;
	struct list_head *sessions;
};

static void http_server_session_init(struct list_head *sess_list)
{
	char cmd[512] = {0};

	snprintf(cmd, sizeof(cmd), "netstat -ntp | grep nginx | awk \'{print $4,$5}\'");
	FILE *pp = popen(cmd, "r");
	if (pp == NULL)
		return;

	char line[256] = {0};
	while (fgets(line, sizeof(line), pp) != NULL) {
		remove_new_line(line);
		if (DM_STRLEN(line) == 0)
			continue;

		char *sport = NULL;
		char *tmp = strrchr(line, ' ');
		if (tmp == NULL)
			continue;

		char *tmp2 = tmp + 1;
		*tmp = 0;

		tmp = strrchr(line, ':');
		if (tmp == NULL)
			continue;

		sport = tmp + 1;
		if (DM_STRLEN(sport) == 0)
			continue;

		if (DM_STRLEN(tmp2) == 0)
			continue;

		char *cip = tmp2;
		char *cport = strrchr(tmp2, ':');
		if (cport == NULL)
			continue;

		*cport = 0;
		cport = cport + 1;

		struct http_session_args *session = dmcalloc(1, sizeof(struct http_session_args));
		if (session == NULL)
			break;

		strncpy(session->c_ip, cip, sizeof(session->c_ip));
		snprintf(session->s_port, sizeof(session->s_port), "%s", sport);
		if (DM_STRLEN(cport))
			snprintf(session->c_port, sizeof(session->c_port), "%s", cport);

		list_add_tail(&session->list, sess_list);
	}

	pclose(pp);
}

static void add_http_config_dup_list(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section)
{
	struct dmmap_http *dmmap_config;

	dmmap_config = dmcalloc(1, sizeof(struct dmmap_http));
	list_add_tail(&dmmap_config->list, dup_list);
	dmmap_config->config_section = config_section;
	dmmap_config->dmmap_section = dmmap_section;
}

static void free_http_config_dup_list(struct list_head *dup_list)
{
	struct dmmap_http *dmmap_config = NULL, *tmp = NULL;
	list_for_each_entry_safe(dmmap_config, tmp, dup_list, list) {
		list_del(&dmmap_config->list);
		dmfree(dmmap_config);
	}
}

static void free_http_session_list(struct list_head *sess_list)
{
	struct http_session_args *session = NULL, *tmp = NULL;
	list_for_each_entry_safe(session, tmp, sess_list, list) {
		list_del(&session->list);
		dmfree(session);
	}
}

static void synchronize_server_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *v;

	uci_foreach_sections(package, section_type, s) {
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(s));
		}
		add_http_config_dup_list(dup_list, s, dmmap_sect);
	}

	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static bool remote_access_enabled(struct uci_section *sec)
{
	char *access = NULL;

	dmuci_get_value_by_section_string(sec, "uci_access", &access);
	return (DM_STRCMP(access, "remote") == 0) ? true : false;
}

static void get_server_port(struct uci_section *sec, char **port)
{
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;

	if (sec == NULL || port == NULL)
		return;

	dmuci_get_value_by_section_list(sec, "listen", &uci_opt_list);
	if (uci_opt_list == NULL)
		return;

	uci_foreach_element(uci_opt_list, e) {
		if (DM_STRLEN(e->name) == 0)
			continue;

		char *tmp = strtok(e->name, " ");
		if (tmp == NULL)
			continue;

		if (DM_STRNCMP(tmp, "[::]:", 5) == 0) {
			*port = dmstrdup(tmp + 5);
			break;
		} else {
			*port = dmstrdup(tmp);
			break;
		}
	}
}

static void get_server_enable(struct uci_section *sec, bool *en)
{
	if (sec == NULL || en == NULL)
		return;

	char *val = dmuci_get_value_by_section_fallback_def(sec, "uci_enable", "1");
	*en = dmuci_string_to_boolean(val);
}

static bool port_used(char *port)
{
	struct uci_section *s = NULL, *stmp = NULL;
	uci_foreach_sections_safe("nginx", "server", stmp, s) {
		char *tmp = NULL;
		bool en = false;
		get_server_port(s, &tmp);
		get_server_enable(s, &en);
		if (en && (DM_STRCMP(tmp, port) == 0))
			return true;
	}

	return false;
}

static void add_new_host(char **list, char *host)
{
	char *prev = NULL;

	if (DM_STRLEN(host) <= 6)
		return;

	char *tmp = host + 6; // shift the pointer to the IP (eg. allow 1.1.1.1;)
	int len = strlen(tmp);
	if (len == 0)
		return;

	char *end = strchr(tmp, ';');
	if (end)
		*end = '\0';

	if (*list == NULL) {
		dmasprintf(list, "%s", tmp);
		return;
	} else {
		prev = dmstrdup(*list);
		free(*list);
		*list = NULL;
	}

	dmasprintf(list, "%s,%s", prev, tmp);
}

/*************************************************************
* ENTRY METHODS
**************************************************************/
static int addHTTPAccess(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char s_name[16];

	snprintf(s_name, sizeof(s_name), "server_%s", *instance);

	dmuci_add_section("nginx", "server", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "uci_enable", "0");
	dmuci_set_value_by_section(s, "server_name", s_name);
	dmuci_set_value_by_section(s, "root", "/www");
	dmuci_add_list_value_by_section(s, "listen", "443");
	dmuci_add_list_value_by_section(s, "listen", "[::]:443");

	dmuci_add_section_bbfdm("dmmap_nginx", "nginx", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_s, "server_instance", *instance);
	
	return 0;
}

static int delHTTPAccess(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch(del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_http *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_http *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("nginx", "server", stmp, s) {
				struct uci_section *dmmap_s = NULL;
				get_dmmap_section_of_config_section("dmmap_nginx", "server", section_name(s), &dmmap_s);
				dmuci_delete_by_section(s, NULL, NULL);
				dmuci_delete_by_section(dmmap_s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int browseHTTPAccess(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_http *p = NULL;
	LIST_HEAD(dup_list);
	LIST_HEAD(session_list);
	char *inst = NULL;

	http_server_session_init(&session_list);
	synchronize_server_config_sections_with_dmmap("nginx", "server", "dmmap_nginx", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		bool b;
		char *enable = dmuci_get_value_by_section_fallback_def(p->config_section, "uci_enable", "1");
		char *act_date = dmuci_get_value_by_section_fallback_def(p->dmmap_section, "activationdate", "");

		b = dmuci_string_to_boolean(enable);
		if (b && DM_STRLEN(act_date) == 0) {
			char *tm = NULL;
			dm_time_format(time(NULL), &tm);
			dmuci_set_value_by_section(p->dmmap_section, "activationdate", tm);
		}

		p->sessions = &session_list;
		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "server_instance", "server_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}

	free_http_session_list(&session_list);
	free_http_config_dup_list(&dup_list);
	return 0;
}

static int browseHTTPSession(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *tmp = NULL;
	bool enable = false;

	get_server_enable(((struct dmmap_http *)prev_data)->config_section, &enable);
	get_server_port(((struct dmmap_http *)prev_data)->config_section, &tmp);
	if (!enable || DM_STRLEN(tmp) == 0)
		return 0;

	char *inst = NULL;
	int id = 0;
	struct http_session_args *session = NULL;
	struct list_head *sess_list = ((struct dmmap_http *)prev_data)->sessions;
	list_for_each_entry(session, sess_list, list) {
		if (DM_STRCMP(tmp, session->s_port) != 0)
			continue;

		inst = handle_instance_without_section(dmctx, parent_node, ++id);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)session, inst) == DM_STOP)
			break;
	}

	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_ui_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *enable = dmuci_get_option_value_fallback_def("userinterface", "global", "enable", "1");
	*value = dmuci_string_to_boolean(enable) ? "1" : "0";
	return 0;
}

static int set_ui_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("userinterface", "global", "enable", value);
			break;
	}
	return 0;	
}

static int get_http_access_protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,HTTPS";
	return 0;
}

static int get_http_entries_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseHTTPAccess);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_http_access_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *enable = dmuci_get_value_by_section_fallback_def(((struct dmmap_http *)data)->config_section, "uci_enable", "1");
	*value = dmuci_string_to_boolean(enable) ? "1" : "0";
	return 0;
}

static int set_http_access_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool new_val, cur_val;
	char *cur;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			// check if same as current value
			string_to_bool(value, &new_val);
			cur = dmuci_get_value_by_section_fallback_def(((struct dmmap_http *)data)->config_section, "uci_enable", "1");
			cur_val = dmuci_string_to_boolean(cur);

			if (new_val == cur_val)
				break;

			if (new_val == false)
				break;

			// check if any enabled server is configured with same port
			char *port = NULL;
			get_server_port(((struct dmmap_http *)data)->config_section, &port);

			if (port_used(port))
				return FAULT_9001;
			break;
		case VALUESET:
			string_to_bool(value, &new_val);
			cur = dmuci_get_value_by_section_fallback_def(((struct dmmap_http *)data)->config_section, "uci_enable", "1");
			cur_val = dmuci_string_to_boolean(cur);

			if (new_val == cur_val)
				break;

			dmuci_set_value_by_section(((struct dmmap_http *)data)->config_section, "uci_enable", value);
			if (new_val) {
				char *tm = NULL;
				dm_time_format(time(NULL), &tm);
				dmuci_set_value_by_section(((struct dmmap_http *)data)->dmmap_section, "activationdate", tm);
			} else {
				dmuci_set_value_by_section(((struct dmmap_http *)data)->dmmap_section, "activationdate", "");
			}
			break;
	}
	return 0;	
}

static int get_http_access_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_http *)data)->dmmap_section, "server_alias", instance, value);
}

static int set_http_access_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_http *)data)->dmmap_section, "server_alias", instance, value);
}

static int get_http_access_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (remote_access_enabled(((struct dmmap_http *)data)->config_section) == true)
		*value = "RemoteAccess";
	else
		*value = "LocalAccess";

	return 0;
}

static int set_http_access_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_values[] = {"RemoteAccess", "LocalAccess", NULL};
	struct uci_section *stmp = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, allowed_values, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			stmp = ((struct dmmap_http *)data)->config_section;
			if (DM_STRCMP(value, "RemoteAccess") == 0 && !remote_access_enabled(stmp)) {
				dmuci_set_value_by_section(((struct dmmap_http *)data)->config_section, "uci_access", "remote");
			}

			if (DM_STRCMP(value, "LocalAccess") == 0 && remote_access_enabled(stmp)) {
				dmuci_set_value_by_section(((struct dmmap_http *)data)->config_section, "uci_access", "");
			}

			break;
	}
	return 0;	
}

static int get_http_access_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_http *)data)->config_section, "uci_interface", &linker);
	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", linker, value);
	return 0;
}

static int set_http_access_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
			dmuci_set_value_by_section(((struct dmmap_http *)data)->config_section, "uci_interface", reference.value);
			break;
	}
	return 0;	
}

static int get_http_access_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp = NULL;

	get_server_port(((struct dmmap_http *)data)->config_section, &tmp);
	if (DM_STRLEN(tmp) != 0)
		*value = dmstrdup(tmp);

	return 0;
}

static int set_http_access_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;
	struct uci_section *stmp = NULL;
	char *cur_val = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","65535"}},1))
				return FAULT_9007;

			// check if same as current value
			get_server_port(((struct dmmap_http *)data)->config_section, &cur_val);
			if (DM_STRCMP(value, cur_val) == 0)
				break;

			char *enable = dmuci_get_value_by_section_fallback_def(((struct dmmap_http *)data)->config_section, "uci_enable", "1");
			bool en = dmuci_string_to_boolean(enable);
			// check if any enabled server is configured with same port
			if (en && port_used(value))
				return FAULT_9001;
			break;
		case VALUESET:
			// check if same as current value do nothing
			get_server_port(((struct dmmap_http *)data)->config_section, &cur_val);
			if (DM_STRCMP(value, cur_val) == 0)
				break;

			stmp = ((struct dmmap_http *)data)->config_section;
			dmuci_get_value_by_section_list(stmp, "listen", &uci_opt_list);
			if (uci_opt_list != NULL) {
				uci_foreach_element(uci_opt_list, e) {
					dmuci_del_list_value_by_section(stmp, "listen", e->name);
				}
			}

			char bind6_addr[15] = {0};
			snprintf(bind6_addr, sizeof(bind6_addr), "[::]:%s", value);
			dmuci_add_list_value_by_section(stmp, "listen", value);
			dmuci_add_list_value_by_section(stmp, "listen", bind6_addr);
			break;
	}
	return 0;	
}

static int get_http_access_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def(((struct dmmap_http *)data)->config_section, "ssl_certificate", "");
	if (DM_STRLEN(res) == 0) {
		*value = "HTTP";
	} else {
		*value = "HTTPS";
	}

	return 0;
}

static int get_http_access_hosts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;
	char *res = NULL;
	char allowed_hosts[30] = {0};

	struct uci_section *sec = ((struct dmmap_http *)data)->config_section;
	snprintf(allowed_hosts, sizeof(allowed_hosts), "allow_host_%s", section_name(sec));

	dmuci_get_value_by_section_list(sec, "include", &uci_opt_list);
	if (uci_opt_list != NULL) {
		uci_foreach_element(uci_opt_list, e) {
			if (DM_STRCMP(e->name, allowed_hosts) != 0) {
				continue;
			}

			char filename[128] = {0};
			char line[128] = {0};
			snprintf(filename, sizeof(filename), "/etc/nginx/%s", allowed_hosts);
			FILE *fp = fopen(filename, "r");
			if (fp == NULL)
				break;

			while (fgets(line, sizeof(line), fp) != NULL) {
				char *allow = strstr(line, "allow");
				if (allow != NULL) {
					add_new_host(&res, allow);
				}
			}
			fclose(fp);
			break;
		}
	}

	if (res) {
		*value = dmstrdup(res);
	}

	return 0;
}

static int set_http_access_hosts(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char filepath[128] = {0};
	char filename[64] = {0};
	struct uci_section *sec;
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			sec = ((struct dmmap_http *)data)->config_section;
			snprintf(filename, sizeof(filename), "allow_host_%s", section_name(sec));
			snprintf(filepath, sizeof(filepath), "/etc/nginx/%s", filename);
			FILE *fp = fopen(filepath, "w");
			if (fp == NULL)
				return FAULT_9002;

			char *tmp = strdup(value);
			char *tok = strtok(tmp, ",");
			bool host_added = false;
			while (DM_STRLEN(tok) != 0) {
				host_added = true;
				fprintf(fp, "allow %s;\n", tok);
				tok = strtok(NULL, ",");
			}

			if (host_added)
				fprintf(fp, "deny all;\n");
			fclose(fp);
			free(tmp);

			bool allowed_hosts = false;
			dmuci_get_value_by_section_list(sec, "include", &uci_opt_list);
			if (uci_opt_list != NULL) {
				uci_foreach_element(uci_opt_list, e) {
					if (DM_STRCMP(e->name, filename) == 0) {
						allowed_hosts = true;
					}
				}
			}

			if (host_added && !allowed_hosts) {
				dmuci_add_list_value_by_section(sec, "include", filename);
			}

			if (!host_added && allowed_hosts) {
				remove(filepath);
				dmuci_del_list_value_by_section(sec, "include", filename);
			}

			break;
	}
	return 0;
}

static int get_http_access_path(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def(((struct dmmap_http *)data)->config_section, "root", "");
	if (DM_STRNCMP(res, "/www", 4) == 0) {
		*value = dmstrdup(res+4);
	} else {
		*value = dmstrdup(res);
	}

	return 0;
}

static int set_http_access_path(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char path[512] = {0};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			snprintf(path, sizeof(path), "/www%s", value);
			dmuci_set_value_by_section(((struct dmmap_http *)data)->config_section, "root", path);
			break;
	}
	return 0;	
}

static int get_http_access_activationdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_http *)data)->dmmap_section, "activationdate", value);
	return 0;
}

static int get_http_access_session_num(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned int cnt = get_number_of_entries(ctx, data, instance, browseHTTPSession);
	dmasprintf(value, "%u", cnt);
	return 0;
}

static int get_http_session_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct http_session_args *args = (struct http_session_args *)data;
	*value = DM_STRLEN(args->c_ip) ? dmstrdup(args->c_ip) : "";
	return 0;
}

static int get_http_session_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct http_session_args *args = (struct http_session_args *)data;
	*value = DM_STRLEN(args->c_port) ? dmstrdup(args->c_port) : "";
	return 0;
}
/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.UserInterface. *** */
DMLEAF tUIParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_ui_enable, set_ui_enable, BBFDM_BOTH},
{"HTTPAccessSupportedProtocols", &DMREAD, DMT_STRING, get_http_access_protocols, NULL, BBFDM_BOTH},
{"HTTPAccessNumberOfEntries", &DMREAD, DMT_UNINT, get_http_entries_count, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tUIHTTPAccessObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"HTTPAccess", &DMWRITE, addHTTPAccess, delHTTPAccess, "file:/etc/config/nginx", browseHTTPAccess, NULL, NULL, tHTTPSessionObj, tHTTPAccessParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tHTTPAccessParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_http_access_enable, set_http_access_enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_http_access_alias, set_http_access_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"AccessType", &DMWRITE, DMT_STRING, get_http_access_type, set_http_access_type, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_http_access_interface, set_http_access_interface, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"Port", &DMWRITE, DMT_UNINT, get_http_access_port, set_http_access_port, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Protocol", &DMREAD, DMT_STRING, get_http_access_protocol, NULL, BBFDM_BOTH},
{"AllowedHosts", &DMWRITE, DMT_STRING, get_http_access_hosts, set_http_access_hosts, BBFDM_BOTH},
{"AllowedPathPrefixes", &DMWRITE, DMT_STRING, get_http_access_path, set_http_access_path, BBFDM_BOTH},
{"ActivationDate", &DMREAD, DMT_TIME, get_http_access_activationdate, NULL, BBFDM_BOTH},
{"SessionNumberOfEntries", &DMREAD, DMT_UNINT, get_http_access_session_num, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tHTTPSessionObj[] = {
{"Session", &DMREAD, NULL, NULL, NULL, browseHTTPSession, NULL, NULL, NULL, tHTTPSessionParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tHTTPSessionParams[] = {
{"IPAddress", &DMREAD, DMT_STRING, get_http_session_ip, NULL, BBFDM_BOTH},
{"Port", &DMREAD, DMT_UNINT, get_http_session_port, NULL, BBFDM_BOTH},
{0}
};
