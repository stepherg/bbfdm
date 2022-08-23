/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dmdiagnostics.h"
#include "dmbbfcommon.h"
#include "dns.h"

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static unsigned char is_dns_server_in_dmmap(char *chk_ip, char *chk_interface)
{
	struct uci_section *s = NULL;
	char *ip, *interface;

	uci_path_foreach_sections(bbfdm, "dmmap_dns", "dns_server", s) {
		dmuci_get_value_by_section_string(s, "ip", &ip);
		dmuci_get_value_by_section_string(s, "interface", &interface);
		if (DM_STRCMP(interface, chk_interface) == 0 && DM_STRCMP(ip, chk_ip) == 0) {
			return 1;
		}
	}
	return 0;
}

static int dmmap_synchronizeDNSClientRelayServer(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *jobj = NULL, *arrobj = NULL;
	struct uci_list *dns_list;
	struct uci_element *e = NULL;
	struct uci_section *s = NULL, *stmp = NULL;
	char *ipdns = NULL;
	int j = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_dns", "dns_server", stmp, s) {
		struct uci_section *ss = NULL;
		char *added_by_controller = NULL;
		char *ip = NULL;
		char *iface = NULL;
		bool found = false;

		dmuci_get_value_by_section_string(s, "added_by_controller", &added_by_controller);
		if (DM_LSTRCMP(added_by_controller, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "ip", &ip);
		dmuci_get_value_by_section_string(s, "interface", &iface);

		uci_foreach_sections("network", "interface", ss) {

			if (strcmp(section_name(ss), iface) != 0)
				continue;

			dmuci_get_value_by_section_list(ss, "dns", &dns_list);
			if (dns_list != NULL) {
				uci_foreach_element(dns_list, e) {
					if (DM_STRCMP(e->name, ip) == 0) {
						found = true;
						break;
					}
				}
			}

			if (found)
				break;

			char *if_name = section_name(ss);
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &jobj);
			if (!jobj) break;
			dmjson_foreach_value_in_array(jobj, arrobj, ipdns, j, 1, "dns-server") {
				if (DM_STRCMP(ipdns, ip) == 0) {
					found = true;
					break;
				}
			}
			if (found)
				break;
		}
		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_sections("network", "interface", s) {
		struct uci_section *dns_s = NULL;
		char *peerdns = NULL;

		dmuci_get_value_by_section_list(s, "dns", &dns_list);
		if (dns_list != NULL) {
			uci_foreach_element(dns_list, e) {

				if (is_dns_server_in_dmmap(e->name, section_name(s)))
					continue;

				dmuci_add_section_bbfdm("dmmap_dns", "dns_server", &dns_s);
				dmuci_set_value_by_section(dns_s, "ip", e->name);
				dmuci_set_value_by_section(dns_s, "interface", section_name(s));
				dmuci_set_value_by_section(dns_s, "enable", "1");
			}
		}

		dmuci_get_value_by_section_string(s, "peerdns", &peerdns);
		if (peerdns[0] == '0')
			continue;

		char *if_name = section_name(s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &jobj);
		if (!jobj) break;
		dmjson_foreach_value_in_array(jobj, arrobj, ipdns, j, 1, "dns-server") {

			if (ipdns[0] == '\0' || is_dns_server_in_dmmap(ipdns, section_name(s)))
				continue;

			dmuci_add_section_bbfdm("dmmap_dns", "dns_server", &dns_s);
			dmuci_set_value_by_section(dns_s, "ip", ipdns);
			dmuci_set_value_by_section(dns_s, "interface", section_name(s));
			dmuci_set_value_by_section(dns_s, "enable", "1");
			dmuci_set_value_by_section(dns_s, "peerdns", "1");
		}
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseDNSServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeDNSClientRelayServer(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap_dns", "dns_server", s) {

		inst = handle_instance(dmctx, parent_node, s, "dns_server_instance", "dns_server_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "NSLookupResult", s) {

		inst = handle_instance(dmctx, parent_node, s, "nslookup_res_instance", "nslookup_res_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int add_dns_server(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL;

	dmuci_add_section_bbfdm("dmmap_dns", "dns_server", &s);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "ip", "0.0.0.0");
	dmuci_set_value_by_section(s, "added_by_controller", "1");
	dmuci_set_value_by_section(s, "dns_server_instance", *instance);
	return 0;
}

static int delete_dns_server(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;
	char *interface, *ip, *str;
	struct uci_list *v;
	struct uci_element *e = NULL, *tmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "peerdns", &str);
			if (str[0] == '1')
				return 0;
			dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
			dmuci_get_value_by_section_string((struct uci_section *)data, "ip", &ip);
			dmuci_del_list_value("network", interface, "dns", ip);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("network", "interface", s) {
				dmuci_get_value_by_section_string(s, "peerdns", &str);
				if (str[0] == '1')
					continue;
				dmuci_get_value_by_section_list(s, "dns", &v);
				if (v != NULL) {
					uci_foreach_element_safe(v, e, tmp) {
						uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dns", "dns_server", "ip", tmp->name, stmp, ss) {
							dmuci_delete_by_section(ss, NULL, NULL);
						}
						dmuci_del_list_value_by_section(s, "dns", tmp->name);
					}
				}
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_dns_supported_record_types(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "A,AAAA,PTR";
	return 0;
}

static int get_client_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_client_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

static int get_client_server_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDNSServerInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_server_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enable", "1");
    return 0;
}

static int get_server_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &v);
	*value = (*v == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_server_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int get_server_dns_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip", value);
	return 0;
}

static int get_dns_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &linker);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	if (!(*value) || (*value)[0] == 0) {
		char *device = NULL;

		dmuci_get_option_value_string("network", linker, "device", &device);
		if (DM_STRLEN(device)) {
			char *sec_name = DM_STRCHR(device, '@');
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", sec_name ? sec_name + 1 : "", value);
		}
	}
	return 0;
}

static int get_dns_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	*value = "Static";
	dmuci_get_value_by_section_string((struct uci_section *)data, "peerdns", &v);
	if (*v == '1') {
		dmuci_get_value_by_section_string((struct uci_section *)data, "ip", &v);
		if (DM_STRCHR(v, ':') == NULL)
			*value = "DHCPv4";
		else
			*value = "DHCPv6";
	}
	return 0;
}

static int get_relay_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*dnsmasq";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int get_relay_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (check_file("/etc/rc.d/*dnsmasq")) ? "Enabled" : "Disabled";
	return 0;
}

static int get_relay_forward_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDNSServerInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enable", "1");
    return 0;
}

static int get_forwarding_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &v);
	*value = (*v == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int get_forwarding_dns_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip", value);
	return 0;
}

static int get_nslookupdiagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("nslookup", "DiagnosticState", "None");
	return 0;
}

static int get_nslookupdiagnostics_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = get_diagnostics_option("nslookup", "interface");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int get_nslookupdiagnostics_host_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("nslookup", "HostName");
	return 0;
}

static int get_nslookupdiagnostics_d_n_s_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option("nslookup", "DNSServer");
	return 0;
}

static int get_nslookupdiagnostics_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("nslookup", "Timeout", "5000");
	return 0;
}

static int get_nslookupdiagnostics_number_of_repetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("nslookup", "NumberOfRepetitions", "1");
	return 0;
}

static int get_nslookupdiagnostics_success_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_diagnostics_option_fallback_def("nslookup", "SuccessCount", "0");
	return 0;
}

static int get_nslookupdiagnostics_result_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseResultInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_result_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "Status", "Error_Other");
	return 0;
}

static int get_result_answer_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "AnswerType", value);
	return 0;
}

static int get_result_host_name_returned(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "HostNameReturned", value);
	return 0;
}

static int get_result_i_p_addresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "IPAddresses", value);
	return 0;
}

static int get_result_d_n_s_server_i_p(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "DNSServerIP", value);
	return 0;
}

static int get_result_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ResponseTime", "0");
	return 0;
}

static int set_client_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int set_dns_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *interface = NULL;
	char *peerdns = NULL;
	char *ip = NULL;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;

			// If peerdns = '1' then it is a dynamic dns and not allowed to disable it
			dmuci_get_value_by_section_string((struct uci_section *)data, "peerdns", &peerdns);
			if (peerdns && peerdns[0] == '1')
				return FAULT_9008;

			break;
		case VALUESET:
			string_to_bool(value, &b);

			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");

			dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
			dmuci_get_value_by_section_string((struct uci_section *)data, "ip", &ip);
			if (DM_STRLEN(interface) && DM_STRLEN(ip)) {
				if (b == true)
					dmuci_add_list_value("network", interface, "dns", ip);
				else
					dmuci_del_list_value("network", interface, "dns", ip);
			}
			break;
	}
	return 0;
}

static int set_server_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dns_server_alias", value);
			break;
	}
	return 0;
}

static int set_dns_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_list *dns_list = NULL;
	char *interface = NULL;
	char *peerdns = NULL;
	char *oip = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;

			// If peerdns = '1' then it is a dynamic dns and not allowed to set this parameter
			dmuci_get_value_by_section_string((struct uci_section *)data, "peerdns", &peerdns);
			if (peerdns && peerdns[0] == '1')
				return FAULT_9008;

			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "ip", &oip);
			if (DM_STRCMP(oip, value) == 0)
				return 0;

			dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
			if (DM_STRLEN(interface)) {
				dmuci_get_option_value_list("network", interface, "dns", &dns_list);
				if (value_exists_in_uci_list(dns_list, oip)) {
					dmuci_del_list_value("network", interface, "dns", oip);
					dmuci_add_list_value("network", interface, "dns", value);
				}
			}

			dmuci_set_value_by_section((struct uci_section *)data, "ip", value);
			break;
	}
	return 0;
}

static int set_dns_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct uci_list *dns_list = NULL;
	char *interface = NULL;
	char *peerdns = NULL;
	char *linker = NULL;
	char *oip = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			// If peerdns = '1' then it is a dynamic dns and not allowed to set this parameter
			dmuci_get_value_by_section_string((struct uci_section *)data, "peerdns", &peerdns);
			if (peerdns && peerdns[0] == '1')
				return FAULT_9008;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);

			dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
			dmuci_get_value_by_section_string((struct uci_section *)data, "ip", &oip);

			if (!linker || linker[0] == 0) {
				dmuci_del_list_value("network", interface, "dns", oip);
				dmuci_set_value_by_section((struct uci_section *)data, "interface", "");
				return 0;
			}

			if (DM_STRCMP(interface, linker) == 0)
				return 0;

			if (DM_STRLEN(interface)) {
				dmuci_get_option_value_list("network", interface, "dns", &dns_list);
				if (value_exists_in_uci_list(dns_list, oip)) {
					dmuci_del_list_value("network", interface, "dns", oip);
					dmuci_add_list_value("network", linker, "dns", oip);
				}
			}

			dmuci_set_value_by_section((struct uci_section *)data, "interface", linker);
			break;
	}
	return 0;
}

static int set_relay_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmcmd("/etc/init.d/dnsmasq", 1, b ? "enable" : "disable");
			break;
	}
	return 0;
}

static int set_forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dns_server_alias", value);
			break;
	}
	return 0;
}

static int set_nslookupdiagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Requested") == 0) {
				NSLOOKUP_STOP
				set_diagnostics_option("nslookup", "DiagnosticState", value);
				bbf_set_end_session_flag(ctx, BBF_END_SESSION_NSLOOKUP_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int set_nslookupdiagnostics_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			NSLOOKUP_STOP
			reset_diagnostic_state("nslookup");
			set_diagnostics_interface_option(ctx, "nslookup", value);
			return 0;
	}
	return 0;
}

static int set_nslookupdiagnostics_host_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			NSLOOKUP_STOP
			reset_diagnostic_state("nslookup");
			set_diagnostics_option("nslookup", "HostName", value);
			return 0;
	}
	return 0;
}

static int set_nslookupdiagnostics_d_n_s_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			NSLOOKUP_STOP
			reset_diagnostic_state("nslookup");
			set_diagnostics_option("nslookup", "DNSServer", value);
			return 0;
	}
	return 0;
}

static int set_nslookupdiagnostics_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			NSLOOKUP_STOP
			reset_diagnostic_state("nslookup");
			set_diagnostics_option("nslookup", "Timeout", value);
			return 0;
	}
	return 0;
}

static int set_nslookupdiagnostics_number_of_repetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			NSLOOKUP_STOP
			reset_diagnostic_state("nslookup");
			set_diagnostics_option("nslookup", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static operation_args dns_diagnostics_nslookup_args = {
	.in = (const char *[]) {
		"HostName",
		"Interface",
		"DNSServer",
		"Timeout",
		"NumberOfRepetitions",
		NULL
	},
	.out = (const char *[]) {
		"Status",
		"SuccessCount",
		"Result.{i}.Status",
		"Result.{i}.AnswerType",
		"Result.{i}.HostNameReturned",
		"Result.{i}.IPAddresses",
		"Result.{i}.DNSServerIP",
		"Result.{i}.ResponseTime",
		NULL
	}
};

static int get_operate_args_DNSDiagnostics_NSLookupDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (char *)&dns_diagnostics_nslookup_args;
	return 0;
}

static int operate_DNSDiagnostics_NSLookupDiagnostics(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *nslookup_status[2] = {0};
	char *nslookup_answer_type[2] = {0};
	char *nslookup_hostname_returned[2] = {0};
	char *nslookup_ip_addresses[2] = {0};
	char *nslookup_dns_server_ip[2] = {0};
	char *nslookup_response_time[2] = {0};
	int i = 1;

	init_diagnostics_operation("NSLookupResult", NSLOOKUP_PATH);
	init_diagnostics_operation("nslookup", NSLOOKUP_PATH);

	char *hostname = dmjson_get_value((json_object *)value, 1, "HostName");
	if (hostname[0] == '\0')
		return CMD_INVALID_ARGUMENTS;
	char *interface = dmjson_get_value((json_object *)value, 1, "Interface");
	char *dnsserver = dmjson_get_value((json_object *)value, 1, "DNSServer");
	char *timeout = dmjson_get_value((json_object *)value, 1, "Timeout");
	char *nbofrepetition = dmjson_get_value((json_object *)value, 1, "NumberOfRepetitions");

	set_diagnostics_option("nslookup", "HostName", hostname);
	set_diagnostics_interface_option(ctx, "nslookup", interface);
	set_diagnostics_option("nslookup", "DNSServer", dnsserver);
	set_diagnostics_option("nslookup", "Timeout", timeout);
	set_diagnostics_option("nslookup", "NumberOfRepetitions", nbofrepetition);

	// Commit and Free uci_ctx_bbfdm
	commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

	dmcmd("/bin/sh", 2, NSLOOKUP_PATH, "run");

	// Allocate uci_ctx_bbfdm
	dmuci_init_bbfdm();

	char *status = get_diagnostics_option("nslookup", "DiagnosticState");
	char *success_count = get_diagnostics_option("nslookup", "SuccessCount");
	add_list_parameter(ctx, dmstrdup("Status"), status, DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("SuccessCount"), success_count, DMT_TYPE[DMT_UNINT], NULL);

	uci_path_foreach_sections(bbfdm, DMMAP_DIAGNOSTIGS, "NSLookupResult", s) {
		dmasprintf(&nslookup_status[0], "Result.%d.Status", i);
		dmasprintf(&nslookup_answer_type[0], "Result.%d.AnswerType", i);
		dmasprintf(&nslookup_hostname_returned[0], "Result.%d.HostNameReturned", i);
		dmasprintf(&nslookup_ip_addresses[0], "Result.%d.IPAddresses", i);
		dmasprintf(&nslookup_dns_server_ip[0], "Result.%d.DNSServerIP", i);
		dmasprintf(&nslookup_response_time[0], "Result.%d.ResponseTime", i);

		dmuci_get_value_by_section_string(s, "Status", &nslookup_status[1]);
		dmuci_get_value_by_section_string(s, "AnswerType", &nslookup_answer_type[1]);
		dmuci_get_value_by_section_string(s, "HostNameReturned", &nslookup_hostname_returned[1]);
		dmuci_get_value_by_section_string(s, "IPAddresses", &nslookup_ip_addresses[1]);
		dmuci_get_value_by_section_string(s, "DNSServerIP", &nslookup_dns_server_ip[1]);
		dmuci_get_value_by_section_string(s, "ResponseTime", &nslookup_response_time[1]);

		add_list_parameter(ctx, nslookup_status[0], nslookup_status[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, nslookup_answer_type[0], nslookup_answer_type[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, nslookup_hostname_returned[0], nslookup_hostname_returned[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, nslookup_ip_addresses[0], nslookup_ip_addresses[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, nslookup_dns_server_ip[0], nslookup_dns_server_ip[1], DMT_TYPE[DMT_STRING], NULL);
		add_list_parameter(ctx, nslookup_response_time[0], nslookup_response_time[1], DMT_TYPE[DMT_UNINT], NULL);
		i++;
	}

	return CMD_SUCCESS;
}

/**********************************************************************************************************************************
*                                            OBJ & LEAF DEFINITION
***********************************************************************************************************************************/
/* *** Device.DNS. *** */
DMOBJ tDNSObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Client", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDNSClientObj, tDNSClientParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Relay", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDNSRelayObj, tDNSRelayParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{"Diagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDNSDiagnosticsObj, tDNSDiagnosticsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tDNSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"SupportedRecordTypes", &DMREAD, DMT_STRING, get_dns_supported_record_types, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.DNS.Client. *** */
DMOBJ tDNSClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Server", &DMWRITE, add_dns_server, delete_dns_server, NULL, browseDNSServerInst, NULL, NULL, NULL, tDNSClientServerParams, NULL, BBFDM_BOTH, LIST_KEY{"DNSServer", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tDNSClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_client_enable, set_client_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_client_status, NULL, BBFDM_BOTH, "2.0"},
{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_client_server_number_of_entries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DNS.Client.Server.{i}. *** */
DMLEAF tDNSClientServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_server_enable, set_dns_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_server_status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_server_alias, set_server_alias, BBFDM_BOTH, "2.0"},
{"DNSServer", &DMWRITE, DMT_STRING, get_server_dns_server, set_dns_server, BBFDM_BOTH, "2.0"},
{"Interface", &DMWRITE, DMT_STRING, get_dns_interface, set_dns_interface, BBFDM_BOTH, "2.0"},
{"Type", &DMREAD, DMT_STRING, get_dns_type, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DNS.Relay. *** */
DMOBJ tDNSRelayObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Forwarding", &DMWRITE, add_dns_server, delete_dns_server, NULL, browseDNSServerInst, NULL, NULL, NULL, tDNSRelayForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"DNSServer", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tDNSRelayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_relay_enable, set_relay_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_relay_status, NULL, BBFDM_BOTH, "2.0"},
{"ForwardNumberOfEntries", &DMREAD, DMT_UNINT, get_relay_forward_number_of_entries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DNS.Relay.Forwarding.{i}. *** */
DMLEAF tDNSRelayForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_forwarding_enable, set_dns_enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_forwarding_status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_forwarding_alias, set_forwarding_alias, BBFDM_BOTH, "2.0"},
{"DNSServer", &DMWRITE, DMT_STRING, get_forwarding_dns_server, set_dns_server, BBFDM_BOTH, "2.0"},
{"Interface", &DMWRITE, DMT_STRING, get_dns_interface, set_dns_interface, BBFDM_BOTH, "2.0"},
{"Type", &DMREAD, DMT_STRING, get_dns_type, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/* *** Device.DNS.Diagnostics. *** */
DMOBJ tDNSDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"NSLookupDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDNSDiagnosticsNSLookupDiagnosticsObj, tDNSDiagnosticsNSLookupDiagnosticsParams, NULL, BBFDM_CWMP, NULL, "2.0"},
{0}
};

DMLEAF tDNSDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version, version*/
{"NSLookupDiagnostics()", &DMASYNC, DMT_COMMAND, get_operate_args_DNSDiagnostics_NSLookupDiagnostics, operate_DNSDiagnostics_NSLookupDiagnostics, BBFDM_USP, "2.12"},
{0}
};

/* *** Device.DNS.Diagnostics.NSLookupDiagnostics. *** */
DMOBJ tDNSDiagnosticsNSLookupDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Result", &DMREAD, NULL, NULL, NULL, browseResultInst, NULL, NULL, NULL, tDNSDiagnosticsNSLookupDiagnosticsResultParams, NULL, BBFDM_CWMP, NULL, "2.0"},
{0}
};

DMLEAF tDNSDiagnosticsNSLookupDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_nslookupdiagnostics_diagnostics_state, set_nslookupdiagnostics_diagnostics_state, BBFDM_CWMP, "2.0"},
{"Interface", &DMWRITE, DMT_STRING, get_nslookupdiagnostics_interface, set_nslookupdiagnostics_interface, BBFDM_CWMP, "2.0"},
{"HostName", &DMWRITE, DMT_STRING, get_nslookupdiagnostics_host_name, set_nslookupdiagnostics_host_name, BBFDM_CWMP, "2.0"},
{"DNSServer", &DMWRITE, DMT_STRING, get_nslookupdiagnostics_d_n_s_server, set_nslookupdiagnostics_d_n_s_server, BBFDM_CWMP, "2.0"},
{"Timeout", &DMWRITE, DMT_UNINT, get_nslookupdiagnostics_timeout, set_nslookupdiagnostics_timeout, BBFDM_CWMP, "2.0"},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_nslookupdiagnostics_number_of_repetitions, set_nslookupdiagnostics_number_of_repetitions, BBFDM_CWMP, "2.0"},
{"SuccessCount", &DMREAD, DMT_UNINT, get_nslookupdiagnostics_success_count, NULL, BBFDM_CWMP, "2.0"},
{"ResultNumberOfEntries", &DMREAD, DMT_UNINT, get_nslookupdiagnostics_result_number_of_entries, NULL, BBFDM_CWMP, "2.0"},
{0}
};

/* *** Device.DNS.Diagnostics.NSLookupDiagnostics.Result.{i}. *** */
DMLEAF tDNSDiagnosticsNSLookupDiagnosticsResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Status", &DMREAD, DMT_STRING, get_result_status, NULL, BBFDM_CWMP, "2.0"},
{"AnswerType", &DMREAD, DMT_STRING, get_result_answer_type, NULL, BBFDM_CWMP, "2.0"},
{"HostNameReturned", &DMREAD, DMT_STRING, get_result_host_name_returned, NULL, BBFDM_CWMP, "2.0"},
{"IPAddresses", &DMREAD, DMT_STRING, get_result_i_p_addresses, NULL, BBFDM_CWMP, "2.0"},
{"DNSServerIP", &DMREAD, DMT_STRING, get_result_d_n_s_server_i_p, NULL, BBFDM_CWMP, "2.0"},
{"ResponseTime", &DMREAD, DMT_UNINT, get_result_response_time, NULL, BBFDM_CWMP, "2.0"},
{0}
};
