/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dmentry.h"
#include "dynamicdns.h"

#define DDNS_PROVIDERS_FILE "/etc/ddns/services"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_dynamicdns_server(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	char *service_name;
	if (data) {
		dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
		dmasprintf(linker, "%s", service_name);
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.DynamicDNS.Client.{i}.!UCI:ddns/service/dmmap_ddns*/
static int browseDynamicDNSClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ddns", "service", "dmmap_ddns", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "clientinstance", "clientalias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int dmmap_synchronizeDynamicDNSServer(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *sddns = NULL, *stmp = NULL, *ss = NULL;
	char *service_name = NULL, *dmmap_service_name = NULL, *retry_interval = NULL, *retry_unit = NULL;
	char *enabled = NULL, *dns_server = NULL, *use_https = NULL, *check_interval = NULL, *check_unit = NULL, *retry_count = NULL;
	int found;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_ddns", "ddns_server", stmp, s) {
		dmuci_get_value_by_section_string(s, "service_name", &dmmap_service_name);
		found = 0;
		uci_foreach_sections("ddns", "service", ss) {
			dmuci_get_value_by_section_string(ss, "service_name", &service_name);
			if (strcmp(service_name, dmmap_service_name) == 0) {
				found = 1;
				break;
			}
			if (found)
				break;
		}
		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_sections("ddns", "service", s) {
		dmuci_get_value_by_section_string(s, "service_name", &service_name);
		if (*service_name == '\0')
			continue;
		dmuci_get_value_by_section_string(s, "enabled", &enabled);
		dmuci_get_value_by_section_string(s, "dns_server", &dns_server);
		dmuci_get_value_by_section_string(s, "use_https", &use_https);
		dmuci_get_value_by_section_string(s, "check_interval", &check_interval);
		dmuci_get_value_by_section_string(s, "check_unit", &check_unit);
		dmuci_get_value_by_section_string(s, "retry_interval", &retry_interval);
		dmuci_get_value_by_section_string(s, "retry_unit", &retry_unit);
		dmuci_get_value_by_section_string(s, "retry_count", &retry_count);
		found = 0;
		uci_path_foreach_sections(bbfdm, "dmmap_ddns", "ddns_server", ss) {
			dmuci_get_value_by_section_string(ss, "service_name", &dmmap_service_name);
			if (strcmp(service_name, dmmap_service_name) == 0) {
				found = 1;
				//Update dmmap with ddns config
				dmuci_set_value_by_section(ss, "section_name", section_name(s));
				dmuci_set_value_by_section(ss, "enabled", enabled);
				dmuci_set_value_by_section(ss, "service_name", service_name);
				dmuci_set_value_by_section(ss, "dns_server", dns_server);
				dmuci_set_value_by_section(ss, "use_https", use_https);
				dmuci_set_value_by_section(ss, "check_interval", check_interval);
				dmuci_set_value_by_section(ss, "check_unit", check_unit);
				dmuci_set_value_by_section(ss, "retry_interval", retry_interval);
				dmuci_set_value_by_section(ss, "retry_unit", retry_unit);
				dmuci_set_value_by_section(ss, "retry_count", retry_count);
				break;
			}
		}
		if (found)
			continue;

		dmuci_add_section_bbfdm("dmmap_ddns", "ddns_server", &sddns);
		dmuci_set_value_by_section(sddns, "section_name", section_name(s));
		dmuci_set_value_by_section(sddns, "enabled", enabled);
		dmuci_set_value_by_section(sddns, "service_name", service_name);
		dmuci_set_value_by_section(sddns, "dns_server", dns_server);
		dmuci_set_value_by_section(sddns, "use_https", use_https);
		dmuci_set_value_by_section(sddns, "check_interval", check_interval);
		dmuci_set_value_by_section(sddns, "check_unit", check_unit);
		dmuci_set_value_by_section(sddns, "retry_interval", retry_interval);
		dmuci_set_value_by_section(sddns, "retry_unit", retry_unit);
		dmuci_set_value_by_section(sddns, "retry_count", retry_count);
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.!UCI:ddns/service/dmmap_ddns*/
static int browseDynamicDNSServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	struct uci_section *s = NULL;

	dmmap_synchronizeDynamicDNSServer(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_ddns", "ddns_server", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   s, "serverinstance", "serveralias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDynamicDNSClientHostnameInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
*************************************************************/
static int addObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;
	char s_name[32];

	char *last_inst = get_last_instance_bbfdm("dmmap_ddns", "service", "clientinstance");
	snprintf(s_name, sizeof(s_name), "Ddns_%s", last_inst ? last_inst : "1");

	dmuci_add_section("ddns", "service", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enabled", "1");
	dmuci_set_value_by_section(s, "use_syslog", "0");
	dmuci_set_value_by_section(s, "use_https", "0");
	dmuci_set_value_by_section(s, "force_interval", "72");
	dmuci_set_value_by_section(s, "force_unit", "hours");
	dmuci_set_value_by_section(s, "check_interval", "10");
	dmuci_set_value_by_section(s, "check_unit", "minutes");
	dmuci_set_value_by_section(s, "retry_interval", "60");
	dmuci_set_value_by_section(s, "retry_unit", "value");
	dmuci_set_value_by_section(s, "ip_source", "interface");

	dmuci_add_section_bbfdm("dmmap_ddns", "service", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(last_inst, 2, dmmap, "clientinstance");
	return 0;
}

static int delObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name((struct uci_section *)data), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("ddns", "service", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap = NULL, *s = NULL;
	char s_name[16];

	char *last_inst = get_last_instance_bbfdm("dmmap_ddns", "ddns_server", "serverinstance");
	snprintf(s_name, sizeof(s_name), "server_%s", last_inst ? last_inst : "1");

	dmuci_add_section("ddns", "service", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "service_name", s_name);
	dmuci_set_value_by_section(s, "enabled", "1");
	dmuci_set_value_by_section(s, "use_syslog", "0");
	dmuci_set_value_by_section(s, "use_https", "0");
	dmuci_set_value_by_section(s, "force_interval", "72");
	dmuci_set_value_by_section(s, "force_unit", "hours");
	dmuci_set_value_by_section(s, "check_interval", "10");
	dmuci_set_value_by_section(s, "check_unit", "minutes");
	dmuci_set_value_by_section(s, "retry_interval", "60");
	dmuci_set_value_by_section(s, "retry_unit", "value");
	dmuci_set_value_by_section(s, "ip_source", "interface");

	dmuci_add_section_bbfdm("dmmap_ddns", "ddns_server", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance(last_inst, 2, dmmap, "serverinstance");
	return 0;
}

static int delObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL, *dmmap_section= NULL;
	int found = 0;
	char *service_name;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq_safe("ddns", "service", "service_name", service_name, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("ddns", "service", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_ddns", "ddns_server", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_ddns", "ddns_server", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
*************************************************************/
static int get_DynamicDNS_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("ddns", "service", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DynamicDNS_ServerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	dmmap_synchronizeDynamicDNSServer(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_ddns", "ddns_server", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DynamicDNS_SupportedServices(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pch = NULL, *spch = NULL;

	*value = "";
	FILE *fp = fopen(DDNS_PROVIDERS_FILE, "r");
	if ( fp != NULL) {
		char line[256] = {0};
		char buf[1028] = {0};
		char buf_tmp[1024] = {0};

		while (fgets(line, 256, fp) != NULL) {
			if (line[0] == '#')
				continue;

			pch = strtok_r(line, "\t", &spch);
			pch = strstr(pch, "\"") + 1;
			pch[strchr(pch, '\"')-pch] = 0;
			if (strcmp(buf, "") == 0) {
				snprintf(buf, sizeof(buf), "%s", pch);
			} else {
				DM_STRNCPY(buf_tmp, buf, sizeof(buf_tmp));
				snprintf(buf, sizeof(buf), "%s,%s", buf_tmp, pch);
			}
		}
		fclose(fp);
		*value = dmstrdup(buf);
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enabled", "0");
	return 0;
}

static int set_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.DynamicDNS.Client.{i}.Status!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClient_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char status[32] = {0}, *enable, *logdir = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enable);
	if (*enable == '\0' || strcmp(enable, "0") == 0) {
		strcpy(status, "Disabled");
	} else {
		char path[64] = {0};

		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		if (*logdir == '\0')
			logdir = "/var/log/ddns";
		snprintf(path, sizeof(path), "%s/%s.log", logdir, section_name((struct uci_section *)data));
		FILE *fp = fopen(path, "r");
		if (fp != NULL) {
			char buf[512] = {0};

			strcpy(status, "Connecting");
			while (fgets(buf, 512, fp) != NULL) {
				if (strstr(buf, "Update successful"))
					strcpy(status, "Updated");
				else if (strstr(buf, "ERROR") && strstr(buf, "Please check your configuration"))
					strcpy(status, "Error_Misconfigured");
				else if (strstr(buf, "Registered IP"))
					strcpy(status, "Connecting");
				else if (strstr(buf, "failed"))
					strcpy(status, "Error");
			}
			fclose(fp);
		} else
			strcpy(status, "Error");
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Alias!UCI:dmmap_ddns/service,@i-1/clientalias*/
static int get_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "clientalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "clientalias", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSClient_LastError(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char status[64] = {0}, *enable = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enable);
	if (enable && (*enable == '\0' || strcmp(enable, "0") == 0)) {
		strcpy(status, "NO_ERROR");
	} else {
		char path[128] = {0}, *logdir = NULL;

		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		snprintf(path, sizeof(path), "%s/%s.log", (logdir && *logdir) ? logdir : "/var/log/ddns", section_name((struct uci_section *)data));

		FILE *fp = fopen(path, "r");
		if (fp != NULL) {
			char buf[512] = {0};

			strcpy(status, "NO_ERROR");
			while (fgets(buf, 512, fp) != NULL) {
				if (strstr(buf, "ERROR") && strstr(buf, "Please check your configuration"))
					strcpy(status, "MISCONFIGURATION_ERROR");
				else if (strstr(buf, "NO valid IP found"))
					strcpy(status, "DNS_ERROR");
				else if (strstr(buf, "Authentication Failed"))
					strcpy(status, "AUTHENTICATION_ERROR");
				else if (strstr(buf, "Transfer failed") || (strstr(buf, "WARN") && strstr(buf, "failed")))
					strcpy(status, "CONNECTION_ERROR");
				else if (strstr(buf, "Registered IP") || strstr(buf, "Update successful"))
					strcpy(status, "NO_ERROR");
			}
			fclose(fp);
		} else
			strcpy(status, "MISCONFIGURATION_ERROR");
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Server!UCI:ddns/service,@i-1/service_name*/
static int get_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *service_name;
	dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
	adm_entry_get_linker_param(ctx, "Device.DynamicDNS.Server.", service_name, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section((struct uci_section *)data, "service_name", linker);
				dmfree(linker);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Interface!UCI:ddns/service,@i-1/interface*/
static int get_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *interface;
	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", interface, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section((struct uci_section *)data, "interface", linker);
				dmfree(linker);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Username!UCI:ddns/service,@i-1/username*/
static int get_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "username", value);
	return 0;
}

static int set_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "username", value);
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
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "password", value);
			break;
	}
	return 0;
}

static int get_DynamicDNSClient_HostnameNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enabled", "0");
	return 0;
}

static int set_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Status!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSClientHostname_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char status[32] = {0}, *enable = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enable);
	if (enable && (*enable == '\0' || strcmp(enable, "0") == 0)) {
		strcpy(status, "Disabled");
	} else {
		char path[128] = {0}, *logdir = NULL;

		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		snprintf(path, sizeof(path), "%s/%s.log", (logdir && *logdir) ? logdir : "/var/log/ddns", section_name((struct uci_section *)data));
		FILE *fp = fopen(path, "r");
		if (fp != NULL) {
			char buf[512] = {0};

			strcpy(status, "Registered");
			while (fgets(buf, 512, fp) != NULL) {
				if (strstr(buf, "Registered IP") || strstr(buf, "Update successful"))
					strcpy(status, "Registered");
				else if (strstr(buf, "Update needed"))
					strcpy(status, "UpdateNeeded");
				else if (strstr(buf, "NO valid IP found"))
					strcpy(status, "Error");
			}
			fclose(fp);
		} else
			strcpy(status, "Error");
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Name!UCI:ddns/service,@i-1/domain*/
static int get_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "domain", value);
	return 0;
}

static int set_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "domain", value);
			dmuci_set_value_by_section((struct uci_section *)data, "lookup_host", value);
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
	snprintf(path, sizeof(path), "%s/%s.update", rundir, section_name((struct uci_section *)data));

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

	epoch_time = now - atoi(uptime) + atoi(last_time);
	if ((ts = localtime(&epoch_time)) == NULL)
		return -1;

	if (strftime(current_time, sizeof(current_time), "%Y-%m-%dT%H:%M:%SZ", ts) == 0)
		return -1;

	*value = dmstrdup(current_time);
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
static int get_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enabled", "0");
	return 0;
}

static int set_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", value);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "enabled", value);
			}
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", value);
	return 0;
}

static int set_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "section_name", value);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_rename_section_by_section(s, value);
				break;
			}
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "serveralias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "serveralias", value);
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.ServiceName!UCI:ddns/service,@i-1/service_name*/
static int get_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", value);
	return 0;
}

static int set_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "service_name", value);
			}
			dmuci_set_value_by_section((struct uci_section *)data, "service_name", value);
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.ServerAddress!UCI:ddns/service,@i-1/dns_server*/
static int get_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dns_server;

	dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server", &dns_server);
	if (*dns_server == '\0') {
		dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", value);
	} else {
		char *addr = strchr(dns_server, ':');
		if (addr)
			*addr = '\0';
		*value = dmstrdup(dns_server);
	}
	return 0;
}

static void set_server_address(struct uci_section *section, char *value)
{
	char *dns_server = NULL;

	dmuci_get_value_by_section_string(section, "dns_server", &dns_server);
	if (dns_server && *dns_server == '\0') {
		dmuci_set_value_by_section(section, "dns_server", value);
	} else {
		char new[64] = {0};

		char *addr = dns_server ? strchr(dns_server, ':') : NULL;
		if (addr)
			snprintf(new, sizeof(new), "%s%s", value, addr);
		else
			DM_STRNCPY(new, value, sizeof(new));
		dmuci_set_value_by_section(section, "dns_server", new);
	}
}

static int set_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_address((struct uci_section *)data, value);

			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				set_server_address(s, value);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.ServerPort!UCI:ddns/service,@i-1/dns_server*/
static int get_DynamicDNSServer_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dns_server;
	*value = "0";

	dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server", &dns_server);
	if (*dns_server == '\0')
		return 0;

	char *port = strchr(dns_server, ':');
	if (port)
		*value = dmstrdup(port+1);
	return 0;
}

static void set_server_port(struct uci_section *section, char *value)
{
	char new[64], *dns_server;

	dmuci_get_value_by_section_string(section, "dns_server", &dns_server);
	if (*dns_server == '\0') {
		snprintf(new, sizeof(new), ":%s", value);
	} else {
		char *addr = strchr(dns_server, ':');
		if (addr) *addr = '\0';
		snprintf(new, sizeof(new), "%s:%s", dns_server, value);
	}
	dmuci_set_value_by_section(section, "dns_server", new);
}

static int set_DynamicDNSServer_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			set_server_port((struct uci_section *)data, value);

			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				set_server_port(s, value);
			}
			break;
	}
	return 0;
}

static int get_DynamicDNSServer_SupportedProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,HTTPS";
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.Protocol!UCI:ddns/service,@i-1/use_https*/
static int get_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "use_https", value);
	if (*value[0] == '\0' || strcmp(*value, "0") == 0)
		*value = "HTTP";
	else
		*value = "HTTPS";
	return 0;
}

static int set_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedProtocols, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "use_https", (strcmp(value, "HTTPS") == 0) ? "1" : "0");
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "use_https", (strcmp(value, "HTTPS") == 0) ? "1" : "0");
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.CheckInterval!UCI:ddns/service,@i-1/check_interval*/
static int get_DynamicDNSServer_CheckInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "check_interval", "600");
	return 0;
}

static int set_DynamicDNSServer_CheckInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char buf[16] = "", *check_unit, *service_name;
	int check_interval = 0;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "check_unit", &check_unit);
			if (strcmp(check_unit, "hours") == 0)
				check_interval = atoi(value) * 3600;
			else if (strcmp(check_unit, "minutes") == 0)
				check_interval = atoi(value) * 60;
			else
				check_interval = atoi(value);
			snprintf(buf, sizeof(buf), "%d", check_interval);
			dmuci_set_value_by_section((struct uci_section *)data, "check_interval", buf);

			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "check_interval", buf);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.RetryInterval!UCI:ddns/service,@i-1/retry_interval*/
static int get_DynamicDNSServer_RetryInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "retry_interval", "259200");
	return 0;
}

static int set_DynamicDNSServer_RetryInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char buf[16] = "", *retry_unit, *service_name;
	int retry_interval = 0;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "retry_unit", &retry_unit);
			if (strcmp(retry_unit, "hours") == 0)
				retry_interval = atoi(value) * 3600;
			else if (strcmp(retry_unit, "minutes") == 0)
				retry_interval = atoi(value) * 60;
			else
				retry_interval = atoi(value);
			snprintf(buf, sizeof(buf), "%d", retry_interval);
			dmuci_set_value_by_section((struct uci_section *)data, "retry_interval", buf);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "retry_interval", buf);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.MaxRetries!UCI:ddns/service,@i-1/retry_count*/
static int get_DynamicDNSServer_MaxRetries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "retry_count", "5");
	return 0;
}

static int set_DynamicDNSServer_MaxRetries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "retry_count", value);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "retry_count", value);
			}
			break;
	}
	return 0;
}

/* *** Device.DynamicDNS. *** */
DMOBJ tDynamicDNSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Client", &DMWRITE, addObjDynamicDNSClient, delObjDynamicDNSClient, NULL, browseDynamicDNSClientInst, NULL, tDynamicDNSClientObj, tDynamicDNSClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Server", "Username", "Alias", NULL}},
{"Server", &DMWRITE, addObjDynamicDNSServer, delObjDynamicDNSServer, NULL, browseDynamicDNSServerInst, NULL, NULL, tDynamicDNSServerParams, get_linker_dynamicdns_server, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

DMLEAF tDynamicDNSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNS_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNS_ServerNumberOfEntries, NULL, BBFDM_BOTH},
{"SupportedServices", &DMREAD, DMT_STRING, get_DynamicDNS_SupportedServices, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DynamicDNS.Client.{i}. *** */
DMOBJ tDynamicDNSClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Hostname", &DMREAD, NULL, NULL, NULL, browseDynamicDNSClientHostnameInst, NULL, NULL, tDynamicDNSClientHostnameParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", NULL}},
{0}
};

DMLEAF tDynamicDNSClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DynamicDNSClient_Enable, set_DynamicDNSClient_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DynamicDNSClient_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Alias, set_DynamicDNSClient_Alias, BBFDM_BOTH},
{"LastError", &DMREAD, DMT_STRING, get_DynamicDNSClient_LastError, NULL, BBFDM_BOTH},
{"Server", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Server, set_DynamicDNSClient_Server, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Interface, set_DynamicDNSClient_Interface, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Username, set_DynamicDNSClient_Username, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Password, set_DynamicDNSClient_Password, BBFDM_BOTH},
{"HostnameNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNSClient_HostnameNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DynamicDNS.Client.{i}.Hostname.{i}. *** */
DMLEAF tDynamicDNSClientHostnameParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DynamicDNSClientHostname_Enable, set_DynamicDNSClientHostname_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DynamicDNSClientHostname_Status, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_DynamicDNSClientHostname_Name, set_DynamicDNSClientHostname_Name, BBFDM_BOTH},
{"LastUpdate", &DMREAD, DMT_TIME, get_DynamicDNSClientHostname_LastUpdate, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DynamicDNS.Server.{i}. *** */
DMLEAF tDynamicDNSServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Enable, set_DynamicDNSServer_Enable, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Name, set_DynamicDNSServer_Name, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Alias, set_DynamicDNSServer_Alias, BBFDM_BOTH},
{"ServiceName", &DMWRITE, DMT_STRING, get_DynamicDNSServer_ServiceName, set_DynamicDNSServer_ServiceName, BBFDM_BOTH},
{"ServerAddress", &DMWRITE, DMT_STRING, get_DynamicDNSServer_ServerAddress, set_DynamicDNSServer_ServerAddress, BBFDM_BOTH},
{"ServerPort", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_ServerPort, set_DynamicDNSServer_ServerPort, BBFDM_BOTH},
{"SupportedProtocols", &DMREAD, DMT_STRING, get_DynamicDNSServer_SupportedProtocols, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Protocol, set_DynamicDNSServer_Protocol, BBFDM_BOTH},
{"CheckInterval", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_CheckInterval, set_DynamicDNSServer_CheckInterval, BBFDM_BOTH},
{"RetryInterval", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_RetryInterval, set_DynamicDNSServer_RetryInterval, BBFDM_BOTH},
{"MaxRetries", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_MaxRetries, set_DynamicDNSServer_MaxRetries, BBFDM_BOTH},
{0}
};
