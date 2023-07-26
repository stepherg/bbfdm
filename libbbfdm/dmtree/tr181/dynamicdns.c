/*
 * Copyright (C) 2022 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dynamicdns.h"

#define DDNS_SERVICES_DEFAULT "/usr/share/ddns/default"
#define DDNS_SERVICES_CUSTOM "/usr/share/ddns/custom"
#define DDNS_SERVICES_BACKUP "/usr/share/ddns/backup"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_dynamicdns_server(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", linker);
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static bool service_exists(char *file_name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_ddns", "server", "file_name", file_name, s) {
		return true;
	}

	return false;
}

static void update_supported_services(void)
{
	struct uci_section *s = NULL;
	char *service_name = NULL;
	char supported_services[2048] = {0};
	unsigned pos = 0;

	supported_services[0] = 0;

	uci_path_foreach_sections(bbfdm, "dmmap_ddns", "server", s) {
		dmuci_get_value_by_section_string(s, "service_name", &service_name);

		if ((sizeof(supported_services) - pos) < DM_STRLEN(service_name))
			break;

		pos += snprintf(&supported_services[pos], sizeof(supported_services) - pos, "%s,", service_name);
	}

	if (pos)
		supported_services[pos - 1] = 0;

	dmuci_set_value_bbfdm("dmmap_ddns", "global", "supported_services", supported_services);
}

static void update_dmmap_ddns_global_settings(long int filecount)
{
	char last_update[16] = {0};
	char file_count[16] = {0};

	time_t t_time = time(NULL);

	snprintf(last_update, sizeof(last_update), "%lld", (long long) t_time);
	snprintf(file_count, sizeof(file_count), "%ld", filecount);

	dmuci_set_value_bbfdm("dmmap_ddns", "global", "last_update", last_update);
	dmuci_set_value_bbfdm("dmmap_ddns", "global", "file_count", file_count);
	update_supported_services();
}

static void check_deleted_files(long int nbr_deleted_file)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *file_name = NULL;
	char buf[512] = {0};
	int deleted_file_count = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_ddns", "server", stmp, s) {
		dmuci_get_value_by_section_string(s, "file_name", &file_name);

		snprintf(buf, sizeof(buf), "%s/%s", DDNS_SERVICES_DEFAULT, file_name);
		if (file_exists(buf))
			continue;

		if (folder_exists(DDNS_SERVICES_CUSTOM)) {
			snprintf(buf, sizeof(buf), "%s/%s", DDNS_SERVICES_CUSTOM, file_name);
			if (file_exists(buf))
				continue;
		}

		if (folder_exists(DDNS_SERVICES_BACKUP)) {
			snprintf(buf, sizeof(buf), "%s/%s", DDNS_SERVICES_BACKUP, file_name);
			if (file_exists(buf))
				continue;
		}

		deleted_file_count++;
		dmuci_delete_by_section(s, NULL, NULL);

		if (nbr_deleted_file == deleted_file_count)
			break;
	}

	update_supported_services();
}

static void fill_dmmap_ddns_services(const char *ddns_path, const char *last_update,
		long int *last_file_count, long int *file_count,
		bool is_enabled, bool is_custom)
{
	struct uci_section *dmmap_s = NULL;
	DIR *dirp = NULL;
	struct dirent *entry = NULL;
	struct stat stats = {0};
	char buf[512] = {0};

	if (!folder_exists(ddns_path))
		return;

	dirp = opendir(ddns_path);
	if (!dirp)
		return;

	while ((entry = readdir(dirp)) != NULL) {

		if (!strstr(entry->d_name, ".json"))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", ddns_path, entry->d_name);

		if (stat(buf, &stats))
			continue;

		(*file_count)++;

		if (strcmp(ddns_path, DDNS_SERVICES_BACKUP) == 0)
			continue;

		if (DM_STRLEN(last_update)) {

			if (DM_STRTOL(last_update) >= stats.st_ctime)
				continue;

			if (service_exists(entry->d_name))
				continue;

			(*last_file_count)++;
			update_dmmap_ddns_global_settings(*last_file_count);
		}

		json_object *json = json_object_from_file(buf);
		if (!json)
			continue;

		char *service_name = dmjson_get_value(json, 1, "name");
		char *ipv4_url = dmjson_get_value(json, 2, "ipv4", "url");

		dmuci_add_section_bbfdm("dmmap_ddns", "server", &dmmap_s);
		dmuci_set_value_by_section(dmmap_s, "enabled", is_enabled ? "1" : "0");
		dmuci_set_value_by_section(dmmap_s, "service_name", service_name);
		dmuci_set_value_by_section(dmmap_s, "file_name", entry->d_name);
		dmuci_set_value_by_section(dmmap_s, "server_name", service_name);
		dmuci_set_value_by_section(dmmap_s, "server_address", ipv4_url);
		dmuci_set_value_by_section(dmmap_s, "is_https", !strncmp(ipv4_url, "https", 5) ? "1" : "0");
		dmuci_set_value_by_section(dmmap_s, "is_custom", is_custom ? "1" : "0");

		json_object_put(json);
	}

	closedir(dirp);
}

static void dmmap_synchronizeDynamicDNSServer(void)
{
	struct uci_section *dmmap_s = NULL;
	char *last_update = NULL;
	char *filecount = NULL;
	long int file_count = 0;

	dmuci_get_option_value_string_bbfdm("dmmap_ddns", "global", "last_update", &last_update);
	dmuci_get_option_value_string_bbfdm("dmmap_ddns", "global", "file_count", &filecount);

	if (!DM_STRLEN(last_update)) {
		dmuci_add_section_bbfdm("dmmap_ddns", "ddns", &dmmap_s);
		dmuci_rename_section_by_section(dmmap_s, "global");
	}

	long int last_file_count = DM_STRTOL(filecount);

	fill_dmmap_ddns_services(DDNS_SERVICES_DEFAULT, last_update, &last_file_count, &file_count, true, false);
	fill_dmmap_ddns_services(DDNS_SERVICES_CUSTOM, last_update, &last_file_count, &file_count, true, true);
	fill_dmmap_ddns_services(DDNS_SERVICES_BACKUP, last_update, &last_file_count, &file_count, false, false);

	if (DM_STRLEN(filecount)) {

		long int nbr_deleted_file = last_file_count - file_count;
		if (nbr_deleted_file == 0)
			return;

		check_deleted_files(nbr_deleted_file);
	}

	update_dmmap_ddns_global_settings(file_count);
}

static char *get_server_perm(char *refparam, struct dmctx *dmctx, void *data, char *instance)
{
	char *server_perm = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "is_custom", &server_perm);
	return server_perm;
}

struct dm_permession_s DMServer = {"1", &get_server_perm};
/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.DynamicDNS.Client.{i}.!UCI:ddns/service/dmmap_ddns*/
static int browseDynamicDNSClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ddns", "service", "dmmap_ddns", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "client_instance", "client_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseDynamicDNSServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeDynamicDNSServer();
	uci_path_foreach_sections(bbfdm, "dmmap_ddns", "server", s) {

		inst = handle_instance(dmctx, parent_node, s, "server_instance", "server_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDynamicDNSClientHostnameInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *hostname = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)prev_data)->config_section, "domain", &hostname);
	if (DM_STRLEN(hostname) != 0) {
		DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	}

	return 0;
}

/*************************************************************
* ADD & DEL OBJ
*************************************************************/
static int addObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char s_name[16];

	snprintf(s_name, sizeof(s_name), "ddns_%s", *instance);

	dmuci_add_section("ddns", "service", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enabled", "0");
	dmuci_set_value_by_section(s, "domain", "yourhost.example.com");

	dmuci_add_section_bbfdm("dmmap_ddns", "service", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_s, "client_instance", *instance);
	return 0;
}

static int delObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("ddns", "service", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDynamicDNSClientHostname(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *hostname = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "domain", &hostname);
	if (DM_STRLEN(hostname) != 0)
		return FAULT_9003;

	dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "domain", "yourhost.example.com");
	return 0;
}

static int delObjDynamicDNSClientHostname(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, "domain", NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, "lookup_host", NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("ddns", "service", s) {
				dmuci_delete_by_section(s, "domain", NULL);
				dmuci_delete_by_section(s, "lookup_host", NULL);
			}
			break;
	}
	return 0;
}

static int addObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_s = NULL;
	char custom_service_path[128];
	char file_name[40];
	char service_name[32];
	char *file_count = NULL;

	snprintf(service_name, sizeof(service_name), "custom_service_%s", *instance);
	snprintf(file_name, sizeof(file_name), "%s.json", service_name);
	snprintf(custom_service_path, sizeof(custom_service_path), "%s/%s", DDNS_SERVICES_CUSTOM, file_name);

	if (!folder_exists(DDNS_SERVICES_CUSTOM))
		mkdir(DDNS_SERVICES_CUSTOM, S_IRWXU);

	struct json_object *service_obj = json_object_new_object();
	struct json_object *ipv4_obj = json_object_new_object();

	json_object_object_add(ipv4_obj, "url", json_object_new_string("http://"));
	json_object_object_add(service_obj, "name", json_object_new_string(service_name));
	json_object_object_add(service_obj, "ipv4", ipv4_obj);

	int res = json_object_to_file_ext(custom_service_path, service_obj, JSON_C_TO_STRING_PRETTY);

	json_object_put(service_obj);

	dmuci_add_section_bbfdm("dmmap_ddns", "server", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "enabled", "1");
	dmuci_set_value_by_section(dmmap_s, "service_name", service_name);
	dmuci_set_value_by_section(dmmap_s, "file_name", file_name);
	dmuci_set_value_by_section(dmmap_s, "server_name", service_name);
	dmuci_set_value_by_section(dmmap_s, "server_address", "http://");
	dmuci_set_value_by_section(dmmap_s, "is_https", "0");
	dmuci_set_value_by_section(dmmap_s, "is_custom", "1");

	dmuci_get_option_value_string_bbfdm("dmmap_ddns", "global", "file_count", &file_count);
	long int filecount = DM_STRTOL(file_count) + 1;
	update_dmmap_ddns_global_settings(filecount);

	return res;
}

static int delObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	char *is_custom = NULL;
	char *enabled = NULL;
	char *file_name = NULL;
	char file_path[128] = {0};

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "is_custom", &is_custom);
			if (*is_custom == '0')
				break;

			dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enabled);
			dmuci_get_value_by_section_string((struct uci_section *)data, "file_name", &file_name);
			snprintf(file_path, sizeof(file_path), "%s/%s", (*enabled == '1') ? DDNS_SERVICES_CUSTOM : DDNS_SERVICES_BACKUP, file_name);

			if (file_exists(file_path))
				remove(file_path);

			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			return FAULT_9005;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
*************************************************************/
static int get_DynamicDNS_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDynamicDNSClientInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DynamicDNS_ServerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDynamicDNSServerInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DynamicDNS_SupportedServices(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string_bbfdm("dmmap_ddns", "global", "supported_services", value);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "0");
	return 0;
}

static int set_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Status!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClient_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char status[32] = {0}, *enable, *logdir = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enabled", &enable);
	if (*enable == '\0' || DM_LSTRCMP(enable, "0") == 0) {
		DM_STRNCPY(status, "Disabled", sizeof(status));
	} else {
		char path[64] = {0};

		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		if (*logdir == '\0')
			logdir = "/var/log/ddns";
		snprintf(path, sizeof(path), "%s/%s.log", logdir, section_name(((struct dmmap_dup *)data)->config_section));
		FILE *fp = fopen(path, "r");
		if (fp != NULL) {
			char buf[512] = {0};

			DM_STRNCPY(status, "Connecting", sizeof(status));
			while (fgets(buf, 512, fp) != NULL) {
				if (DM_LSTRSTR(buf, "Update successful"))
					DM_STRNCPY(status, "Updated", sizeof(status));
				else if (DM_LSTRSTR(buf, "ERROR") && DM_LSTRSTR(buf, "Please check your configuration"))
					DM_STRNCPY(status, "Error_Misconfigured", sizeof(status));
				else if (DM_LSTRSTR(buf, "Registered IP"))
					DM_STRNCPY(status, "Connecting", sizeof(status));
				else if (DM_LSTRSTR(buf, "failed"))
					DM_STRNCPY(status, "Error", sizeof(status));
			}
			fclose(fp);
		} else
			DM_STRNCPY(status, "Error", sizeof(status));
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Alias!UCI:dmmap_ddns/service,@i-1/clientalias*/
static int get_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "client_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "client_alias", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSClient_LastError(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char last_err[64] = {0}, *enable = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enabled", &enable);
	if (enable && (*enable == '\0' || DM_LSTRCMP(enable, "0") == 0)) {
		DM_STRNCPY(last_err, "NO_ERROR", sizeof(last_err));
	} else {
		char path[128] = {0}, *logdir = NULL;

		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		snprintf(path, sizeof(path), "%s/%s.log", (logdir && *logdir) ? logdir : "/var/log/ddns", section_name(((struct dmmap_dup *)data)->config_section));

		FILE *fp = fopen(path, "r");
		if (fp != NULL) {
			char buf[512] = {0};

			DM_STRNCPY(last_err, "NO_ERROR", sizeof(last_err));
			while (fgets(buf, 512, fp) != NULL) {
				if (DM_LSTRSTR(buf, "ERROR") && DM_LSTRSTR(buf, "Please check your configuration"))
					DM_STRNCPY(last_err, "MISCONFIGURATION_ERROR", sizeof(last_err));
				else if (DM_LSTRSTR(buf, "NO valid IP found"))
					DM_STRNCPY(last_err, "DNS_ERROR", sizeof(last_err));
				else if (DM_LSTRSTR(buf, "Authentication Failed"))
					DM_STRNCPY(last_err, "AUTHENTICATION_ERROR", sizeof(last_err));
				else if (DM_LSTRSTR(buf, "Transfer failed") || (DM_LSTRSTR(buf, "WARN") && DM_LSTRSTR(buf, "failed")))
					DM_STRNCPY(last_err, "CONNECTION_ERROR", sizeof(last_err));
				else if (DM_LSTRSTR(buf, "Registered IP") || DM_LSTRSTR(buf, "Update successful"))
					DM_STRNCPY(last_err, "NO_ERROR", sizeof(last_err));
			}
			fclose(fp);
		} else
			DM_STRNCPY(last_err, "MISCONFIGURATION_ERROR", sizeof(last_err));
	}
	*value = dmstrdup(last_err);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Server!UCI:ddns/service,@i-1/service_name*/
static int get_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *service_name = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "service_name", &service_name);
	adm_entry_get_linker_param(ctx, "Device.DynamicDNS.Server.", service_name, value);
	return 0;
}

static int set_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.DynamicDNS.Server.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "service_name", linker ? linker : "");
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Interface!UCI:ddns/service,@i-1/interface*/
static int get_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *interface = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface", &interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", interface, value);
	return 0;
}

static int set_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "interface", linker ? linker : "");
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ip_network", linker ? linker : "");
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Username!UCI:ddns/service,@i-1/username*/
static int get_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "username", value);
	return 0;
}

static int set_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "username", value);
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Password!UCI:ddns/service,@i-1/password*/
static int get_DynamicDNSClient_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_DynamicDNSClient_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "password", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSClient_HostnameNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDynamicDNSClientHostnameInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "0");
	return 0;
}

static int set_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Status!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClientHostname_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char status[32] = {0}, *enable = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enabled", &enable);
	if (enable && (*enable == '\0' || DM_LSTRCMP(enable, "0") == 0)) {
		DM_STRNCPY(status, "Disabled", sizeof(status));
	} else {
		char path[128] = {0}, *logdir = NULL;

		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		snprintf(path, sizeof(path), "%s/%s.log", (logdir && *logdir) ? logdir : "/var/log/ddns", section_name(((struct dmmap_dup *)data)->config_section));
		FILE *fp = fopen(path, "r");
		if (fp != NULL) {
			char buf[512] = {0};

			DM_STRNCPY(status, "Registered", sizeof(status));
			while (fgets(buf, 512, fp) != NULL) {
				if (DM_LSTRSTR(buf, "Registered IP") || DM_LSTRSTR(buf, "Update successful"))
					DM_STRNCPY(status, "Registered", sizeof(status));
				else if (DM_LSTRSTR(buf, "Update needed"))
					DM_STRNCPY(status, "UpdateNeeded", sizeof(status));
				else if (DM_LSTRSTR(buf, "NO valid IP found"))
					DM_STRNCPY(status, "Error", sizeof(status));
			}
			fclose(fp);
		} else
			DM_STRNCPY(status, "Error", sizeof(status));
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Name!UCI:ddns/service,@i-1/domain*/
static int get_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "lookup_host", value);
	return 0;
}

static int set_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "lookup_host", value);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "domain", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSClientHostname_LastUpdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tm *ts;
	time_t epoch_time, now = time(NULL);
	FILE* fp = NULL;
	char *pch = NULL, *spch = NULL, *last_time = NULL, *uptime = NULL, *rundir = NULL;
	char current_time[32] = "", buf[16] = "", path[64] = "";
	*value = "0001-01-01T00:00:00Z";

	dmuci_get_option_value_string("ddns", "global", "ddns_rundir", &rundir);
	if (*rundir == '\0')
		rundir = "/var/run/ddns";
	snprintf(path, sizeof(path), "%s/%s.update", rundir, section_name(((struct dmmap_dup *)data)->config_section));

	fp = fopen(path, "r");
	if (fp != NULL) {
		if (fgets(buf, 16, fp) != NULL) {
			pch = strtok_r(buf, "\n", &spch);
			last_time = (pch) ? dmstrdup(pch) : "0";
		}
		fclose(fp);
	} else
		last_time = "0";

	fp = fopen("/proc/uptime", "r");
	if (fp != NULL) {
		if (fgets(buf, 16, fp) != NULL) {
			pch = strtok_r(buf, ".", &spch);
			uptime = (pch) ? dmstrdup(pch) : "0";
		}
		fclose(fp);
	} else
		uptime = "0";

	epoch_time = now - DM_STRTOL(uptime) + DM_STRTOL(last_time);
	if ((ts = gmtime(&epoch_time)) == NULL)
		return -1;

	if (strftime(current_time, sizeof(current_time), "%Y-%m-%dT%H:%M:%SZ", ts) == 0)
		return -1;

	*value = dmstrdup(current_time);
	return 0;
}

static int get_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", value);
	return 0;
}

static int set_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *enabled = NULL;
	char *file_name = NULL;
	char *is_custom = NULL;
	char old_path[512] = {0};
	char new_path[512] = {0};
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enabled);
			if ((*enabled == '1' && b) || (*enabled == '0' && !b))
				break;

			dmuci_get_value_by_section_string((struct uci_section *)data, "file_name", &file_name);
			dmuci_get_value_by_section_string((struct uci_section *)data, "is_custom", &is_custom);

			if (b) {
				snprintf(old_path, sizeof(old_path), "%s/%s", DDNS_SERVICES_BACKUP, file_name);
				snprintf(new_path, sizeof(old_path), "%s/%s", (*is_custom == '1') ? DDNS_SERVICES_CUSTOM : DDNS_SERVICES_DEFAULT, file_name);

				if (!folder_exists(DDNS_SERVICES_CUSTOM))
					mkdir(DDNS_SERVICES_CUSTOM, S_IRWXU);
			} else {
				snprintf(old_path, sizeof(old_path), "%s/%s", (*is_custom == '1') ? DDNS_SERVICES_CUSTOM : DDNS_SERVICES_DEFAULT, file_name);
				snprintf(new_path, sizeof(old_path), "%s/%s", DDNS_SERVICES_BACKUP, file_name);

				if (!folder_exists(DDNS_SERVICES_BACKUP))
					mkdir(DDNS_SERVICES_BACKUP, S_IRWXU);
			}

			if (rename(old_path, new_path))
				return FAULT_9007;

			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "server_name", value);
	return 0;
}

static int set_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "server_name", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "server_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "server_alias", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", value);
	return 0;
}

static int set_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct json_object *service_obj = NULL;
	struct json_object *ipv4_obj = NULL;
	char *enabled = NULL;
	char *file_name = NULL;
	char *server_address = NULL;
	char file_path[128] = {0};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enabled);
			dmuci_get_value_by_section_string((struct uci_section *)data, "file_name", &file_name);
			dmuci_get_value_by_section_string((struct uci_section *)data, "server_address", &server_address);

			snprintf(file_path, sizeof(file_path), "%s/%s", (*enabled == '1') ? DDNS_SERVICES_CUSTOM : DDNS_SERVICES_BACKUP, file_name);
			if (file_exists(file_path))
				remove(file_path);

			service_obj = json_object_new_object();
			ipv4_obj = json_object_new_object();

			json_object_object_add(ipv4_obj, "url", json_object_new_string(server_address));
			json_object_object_add(service_obj, "name", json_object_new_string(value));
			json_object_object_add(service_obj, "ipv4", ipv4_obj);
			json_object_to_file_ext(file_path, service_obj, JSON_C_TO_STRING_PRETTY);
			json_object_put(service_obj);

			dmuci_set_value_by_section((struct uci_section *)data, "service_name", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "server_address", value);
	return 0;
}

static int set_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct json_object *service_obj = NULL;
	struct json_object *ipv4_obj = NULL;
	char *enabled = NULL;
	char *file_name = NULL;
	char *service_name = NULL;
	char file_path[128] = {0};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enabled);
			dmuci_get_value_by_section_string((struct uci_section *)data, "file_name", &file_name);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);

			snprintf(file_path, sizeof(file_path), "%s/%s", (*enabled == '1') ? DDNS_SERVICES_CUSTOM : DDNS_SERVICES_BACKUP, file_name);
			if (file_exists(file_path))
				remove(file_path);

			service_obj = json_object_new_object();
			ipv4_obj = json_object_new_object();

			json_object_object_add(ipv4_obj, "url", json_object_new_string(value));
			json_object_object_add(service_obj, "name", json_object_new_string(service_name));
			json_object_object_add(service_obj, "ipv4", ipv4_obj);
			json_object_to_file_ext(file_path, service_obj, JSON_C_TO_STRING_PRETTY);
			json_object_put(service_obj);

			dmuci_set_value_by_section((struct uci_section *)data, "server_address", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_SupportedProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,HTTPS";
	return 0;
}

static int get_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *is_https = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "is_https", &is_https);
	*value = (*is_https == '1') ? "HTTPS" : "HTTP";
	return 0;
}

static int set_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, SupportedProtocols, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DynamicDNS. *** */
DMOBJ tDynamicDNSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Client", &DMWRITE, addObjDynamicDNSClient, delObjDynamicDNSClient, NULL, browseDynamicDNSClientInst, NULL, NULL, tDynamicDNSClientObj, tDynamicDNSClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Server", "Username", "Alias", NULL}, "2.10"},
{"Server", &DMWRITE, addObjDynamicDNSServer, delObjDynamicDNSServer, NULL, browseDynamicDNSServerInst, NULL, NULL, NULL, tDynamicDNSServerParams, get_linker_dynamicdns_server, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.10"},
{0}
};

DMLEAF tDynamicDNSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNS_ClientNumberOfEntries, NULL, BBFDM_BOTH, "2.10"},
{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNS_ServerNumberOfEntries, NULL, BBFDM_BOTH, "2.10"},
{"SupportedServices", &DMREAD, DMT_STRING, get_DynamicDNS_SupportedServices, NULL, BBFDM_BOTH, "2.10"},
{0}
};

/* *** Device.DynamicDNS.Client.{i}. *** */
DMOBJ tDynamicDNSClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Hostname", &DMWRITE, addObjDynamicDNSClientHostname, delObjDynamicDNSClientHostname, NULL, browseDynamicDNSClientHostnameInst, NULL, NULL, NULL, tDynamicDNSClientHostnameParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", NULL}, "2.10"},
{0}
};

DMLEAF tDynamicDNSClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DynamicDNSClient_Enable, set_DynamicDNSClient_Enable, BBFDM_BOTH, "2.10"},
{"Status", &DMREAD, DMT_STRING, get_DynamicDNSClient_Status, NULL, BBFDM_BOTH, "2.10"},
{"Alias", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Alias, set_DynamicDNSClient_Alias, BBFDM_BOTH, "2.10"},
{"LastError", &DMREAD, DMT_STRING, get_DynamicDNSClient_LastError, NULL, BBFDM_BOTH, "2.10"},
{"Server", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Server, set_DynamicDNSClient_Server, BBFDM_BOTH, "2.10"},
{"Interface", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Interface, set_DynamicDNSClient_Interface, BBFDM_BOTH, "2.10"},
{"Username", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Username, set_DynamicDNSClient_Username, BBFDM_BOTH, "2.10"},
{"Password", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Password, set_DynamicDNSClient_Password, BBFDM_BOTH, "2.10"},
{"HostnameNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNSClient_HostnameNumberOfEntries, NULL, BBFDM_BOTH, "2.10"},
{0}
};

/* *** Device.DynamicDNS.Client.{i}.Hostname.{i}. *** */
DMLEAF tDynamicDNSClientHostnameParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DynamicDNSClientHostname_Enable, set_DynamicDNSClientHostname_Enable, BBFDM_BOTH, "2.10"},
{"Status", &DMREAD, DMT_STRING, get_DynamicDNSClientHostname_Status, NULL, BBFDM_BOTH, "2.10"},
{"Name", &DMWRITE, DMT_STRING, get_DynamicDNSClientHostname_Name, set_DynamicDNSClientHostname_Name, BBFDM_BOTH, "2.10"},
{"LastUpdate", &DMREAD, DMT_TIME, get_DynamicDNSClientHostname_LastUpdate, NULL, BBFDM_BOTH, "2.10"},
{0}
};

/* *** Device.DynamicDNS.Server.{i}. *** */
DMLEAF tDynamicDNSServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Enable, set_DynamicDNSServer_Enable, BBFDM_BOTH, "2.10"},
{"Name", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Name, set_DynamicDNSServer_Name, BBFDM_BOTH, "2.10"},
{"Alias", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Alias, set_DynamicDNSServer_Alias, BBFDM_BOTH, "2.10"},
{"ServiceName", &DMServer, DMT_STRING, get_DynamicDNSServer_ServiceName, set_DynamicDNSServer_ServiceName, BBFDM_BOTH, "2.10"},
{"ServerAddress", &DMServer, DMT_STRING, get_DynamicDNSServer_ServerAddress, set_DynamicDNSServer_ServerAddress, BBFDM_BOTH, "2.10"},
//{"ServerPort", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_ServerPort, set_DynamicDNSServer_ServerPort, BBFDM_BOTH, "2.10"},
{"SupportedProtocols", &DMREAD, DMT_STRING, get_DynamicDNSServer_SupportedProtocols, NULL, BBFDM_BOTH, "2.10"},
{"Protocol", &DMServer, DMT_STRING, get_DynamicDNSServer_Protocol, set_DynamicDNSServer_Protocol, BBFDM_BOTH, "2.10"},
//{"CheckInterval", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_CheckInterval, set_DynamicDNSServer_CheckInterval, BBFDM_BOTH, "2.10"},
//{"RetryInterval", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_RetryInterval, set_DynamicDNSServer_RetryInterval, BBFDM_BOTH, "2.10"},
//{"MaxRetries", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_MaxRetries, set_DynamicDNSServer_MaxRetries, BBFDM_BOTH, "2.10"},
{0}
};
