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

#include "firewall.h"

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static void create_portmapping_section(bool b)
{
	struct uci_section *s = NULL;

	dmuci_add_section("firewall", "include", &s);
	dmuci_rename_section_by_section(s, "portmapping");
	dmuci_set_value_by_section(s, "enabled", b ? "0" : "1");
	dmuci_set_value_by_section(s, "path", "/etc/firewall.portmapping");
	dmuci_set_value_by_section(s, "reload", "1");
}

static char *get_rule_perm(char *refparam, struct dmctx *dmctx, void *data, char *instance)
{
	char *rule_perm = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "is_rule", &rule_perm);
	return rule_perm;
}

struct dm_permession_s DMRule = {"1", &get_rule_perm};

/*************************************************************
* ENTRY METHOD
**************************************************************/
static int browseLevelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = is_dmmap_section_exist("dmmap_firewall", "level");
	if (!s) dmuci_add_section_bbfdm("dmmap_firewall", "level", &s);
	handle_instance(dmctx, parent_node, s, "firewall_level_instance", "firewall_level_alias");
	DM_LINK_INST_OBJ(dmctx, parent_node, s, "1");
	return 0;
}

static int browseChainInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = is_dmmap_section_exist("dmmap_firewall", "chain");
	if (!s) dmuci_add_section_bbfdm("dmmap_firewall", "chain", &s);
	handle_instance(dmctx, parent_node, s, "firewall_chain_instance", "firewall_chain_alias");
	DM_LINK_INST_OBJ(dmctx, parent_node, s, "1");
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.!UCI:firewall/rule/dmmap_firewall*/
static int browseRuleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	// Forwarding sections
	synchronize_specific_config_sections_with_dmmap("firewall", "forwarding", "dmmap_firewall", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_set_value_by_section(p->dmmap_section, "is_rule", "0");

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "firewall_chain_rule_instance", "firewall_chain_rule_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

	// Rule sections
	synchronize_specific_config_sections_with_dmmap("firewall", "rule", "dmmap_firewall", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_set_value_by_section(p->dmmap_section, "is_rule", "1");

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "firewall_chain_rule_instance", "firewall_chain_rule_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			goto end;
	}
	free_dmmap_config_dup_list(&dup_list);

end:
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int add_firewall_rule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_firewall_rule = NULL;
	char creation_date[32] = {0};
	char s_name[16] = {0};
	time_t now = time(NULL);

	strftime(creation_date, sizeof(creation_date), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	snprintf(s_name, sizeof(s_name), "rule_%s", *instance);

	dmuci_add_section("firewall", "rule", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enabled", "0");
	dmuci_set_value_by_section(s, "target", "DROP");
	dmuci_set_value_by_section(s, "proto", "0");

	dmuci_add_section_bbfdm("dmmap_firewall", "rule", &dmmap_firewall_rule);
	dmuci_set_value_by_section(dmmap_firewall_rule, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_firewall_rule, "creation_date", creation_date);
	dmuci_set_value_by_section(dmmap_firewall_rule, "firewall_chain_rule_instance", *instance);
	return 0;
}

static int delete_firewall_rule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("firewall", "rule", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name(s), &dmmap_section);
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
static int get_firewall_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("firewall", "globals", "enabled", "1");
	return 0;
}

static int get_firewall_config(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Advanced";
    return 0;
}

static int get_firewall_advanced_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Device.Firewall.Level.1";
    return 0;
}

static int get_firewall_level_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_firewall_chain_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
    return 0;
}

static int get_level_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "firewall_level_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

static int get_level_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

static int get_level_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    dmuci_get_value_by_section_string((struct uci_section *)data, "description", value);
    return 0;
}

static int get_level_chain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Device.Firewall.Chain.1";
    return 0;
}

static int get_level_port_mapping_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	bool portmapping_sec_exists = false;
	char *enable = NULL;

	uci_foreach_sections("firewall", "include", s) {
		if (strncmp(section_name(s), "portmapping", 11) == 0) {
			portmapping_sec_exists = true ;

			dmuci_get_value_by_section_string(s, "enabled", &enable);
			if (*enable == '0') {
				*value = "1";
				break;
			}
		}
	}

	if (portmapping_sec_exists == false)
		*value = "1";

	return 0;
}

static int get_level_default_log_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *v;

	uci_foreach_sections("firewall", "zone", s) {
		dmuci_get_value_by_section_string(s, "log", &v);
		if (*v == '1') {
			*value = "1";
			return 0;
		}
	}
	*value = "0";
	return 0;
}

static int get_level_default_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *input = NULL;

	dmuci_get_option_value_string("firewall", "@defaults[0]", "input", &input);
	if (!input || *input == 0) {
		*value = "Drop";
		return 0;
	}

	*value = (*input == 'A') ? "Accept" : (*input == 'R') ? "Reject" : "Drop";
	return 0;
}

static int get_chain_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_chain_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "firewall_chain_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

static int get_chain_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
    return 0;
}

static int get_chain_creator(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Defaults";
    return 0;
}

/*#Device.Firewall.Chain.{i}.RuleNumberOfEntries!UCI:firewall/rule/*/
static int get_chain_rule_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseRuleInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Enable!UCI:firewall/rule,@i-1/enabled*/
static int get_rule_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enabled", &v);
	*value = (*v == 'n' || *v == '0' ) ? "0" : "1";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Status!UCI:firewall/rule,@i-1/enabled*/
static int get_rule_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "enabled", &v);
	*value = (*v == 'n' || *v == '0') ? "Disabled" : "Enabled";
	return 0;
}

static int get_rule_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "firewall_chain_rule_instance", value);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Alias!UCI:dmmap_firewall/rule,@i-1/firewall_chain_rule_alias*/
static int get_rule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "firewall_chain_rule_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Description!UCI:firewall/rule,@i-1/name*/
static int get_rule_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", value);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Target!UCI:firewall/rule,@i-1/target*/
static int get_rule_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *target;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "target", &target);
	if (DM_STRLEN(target) == 0) {
		char *rule_perm = NULL;

		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "is_rule", &rule_perm);
		*value = (DM_LSTRCMP(rule_perm, "1") == 0) ? "Drop" : "Accept";
	} else {
		if (strcasecmp(target, "Accept") == 0)
			*value = "Accept";
		else if (strcasecmp(target, "Reject") == 0)
			*value = "Reject";
		else if (strcasecmp(target, "Drop") == 0)
			*value = "Drop";
		else if (strcasecmp(target, "MARK") == 0)
			*value = "Return";
		else
			*value = target;
	}
    return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Log!UCI:firewall/rule,@i-1/log*/
static int get_rule_log(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "log", &v);
	*value = (*v == '1' ) ? "1" : "0";
	return 0;
}

static int get_FirewallChainRule_CreationDate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->dmmap_section, "creation_date", "0001-01-01T00:00:00Z");
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.ExpiryDate!UCI:firewall/rule,@i-1/expiry*/
static int get_FirewallChainRule_ExpiryDate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *expiry_date = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "expiry", &expiry_date);
	if (expiry_date && *expiry_date != '\0' && DM_STRTOL(expiry_date) > 0) {
		char expiry[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		time_t time_value = DM_STRTOL(expiry_date);

		strftime(expiry, sizeof expiry, "%Y-%m-%dT%H:%M:%SZ", gmtime(&time_value));
		*value = dmstrdup(expiry);
	} else {
		*value = "9999-12-31T23:59:59Z";
	}
	return 0;
}

static int set_FirewallChainRule_ExpiryDate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char expiry_date[16];
	struct tm tm;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			strptime(value, "%Y-%m-%dT%H:%M:%SZ", &tm);
			snprintf(expiry_date, sizeof(expiry_date), "%lld", (long long)timegm(&tm));
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "expiry", expiry_date);
			break;
	}
	return 0;
}

static int get_rule_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifaceobj = NULL, *src = NULL, src_iface[256] = {0};
	struct uci_list *net_list = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src", &src);
	if (src == NULL || *src == '\0')
		return 0;

	if (DM_LSTRCMP(src, "*") == 0) {
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "src", &src);
	} else {
		struct uci_section *s = NULL;
		char *zone_name = NULL;

		uci_foreach_sections("firewall", "zone", s) {
			dmuci_get_value_by_section_string(s, "name", &zone_name);
			if (zone_name && DM_STRCMP(zone_name, src) == 0) {
				dmuci_get_value_by_section_list(s, "network", &net_list);
				break;
			}
		}
	}

	if (net_list != NULL) {
		struct uci_element *e = NULL;
		unsigned pos = 0;

		src_iface[0] = 0;
		uci_foreach_element(net_list, e) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", e->name, &ifaceobj);
			if (ifaceobj && *ifaceobj)
				pos += snprintf(&src_iface[pos], sizeof(src_iface) - pos, "%s,", ifaceobj);
		}

		if (pos)
			src_iface[pos - 1] = 0;
	} else {
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", src, &ifaceobj);
		if (ifaceobj && *ifaceobj)
			DM_STRNCPY(src_iface, ifaceobj, sizeof(src_iface));
	}

	*value = dmstrdup(src_iface);
	return 0;
}

static int get_rule_source_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src", &v);
	*value = (*v == '*') ? "1" : "0";
	return 0;
}

static int get_rule_dest_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifaceobj = NULL, *dest = NULL, dst_iface[256] = {0};
	struct uci_list *net_list = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest", &dest);
	if (dest == NULL || *dest == '\0')
		return 0;

	if (DM_LSTRCMP(dest, "*") == 0) {
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "dest", &dest);
	} else {
		struct uci_section *s = NULL;
		char *zone_name = NULL;

		uci_foreach_sections("firewall", "zone", s) {
			dmuci_get_value_by_section_string(s, "name", &zone_name);
			if (zone_name && DM_STRCMP(zone_name, dest) == 0) {
				dmuci_get_value_by_section_list(s, "network", &net_list);
				break;
			}
		}
	}

	if (net_list != NULL) {
		struct uci_element *e = NULL;
		unsigned pos = 0;

		dst_iface[0] = 0;
		uci_foreach_element(net_list, e) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", e->name, &ifaceobj);
			if (ifaceobj && *ifaceobj)
				pos += snprintf(&dst_iface[pos], sizeof(dst_iface) - pos, "%s,", ifaceobj);
		}

		if (pos)
			dst_iface[pos - 1] = 0;
	} else {
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", dest, &ifaceobj);
		if (ifaceobj && *ifaceobj)
			DM_STRNCPY(dst_iface, ifaceobj, sizeof(dst_iface));
	}

	*value = dmstrdup(dst_iface);
	return 0;
}

static int get_rule_dest_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest", &v);
	*value = (*v == '*') ? "1" : "0";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.IPVersion!UCI:firewall/rule,@i-1/family*/
static int get_rule_i_p_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipversion;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "family", &ipversion);
	if (strcasecmp(ipversion, "ipv4") == 0) {
		*value = "4";
	} else if (strcasecmp(ipversion, "ipv6") == 0) {
		*value = "6";
	} else {
		*value = "-1";
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestIp!UCI:firewall/rule,@i-1/dest_ip*/
static int get_rule_dest_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[64], *pch, *destip;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_ip", &destip);
	DM_STRNCPY(buf, destip, sizeof(buf));
	pch = DM_STRCHR(buf, '/');
	if (pch) *pch = '\0';
	*value = dmstrdup(buf);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestMask!UCI:firewall/rule,@i-1/dest_ip*/
static int get_rule_dest_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pch, *destip;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_ip", &destip);
	if (*destip == '\0')
		return 0;

	pch = DM_STRCHR(destip, '/');
	if (pch) {
		*value = destip;
	} else {
		char *family;

		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "family", &family);
		dmasprintf(value, "%s/%s", destip, DM_LSTRCMP(family, "ipv6") == 0 ? "128" : "32");
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourceIp!UCI:firewall/rule,@i-1/src_ip*/
static int get_rule_source_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[64], *pch, *srcip;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_ip", &srcip);
	DM_STRNCPY(buf, srcip, sizeof(buf));
	pch = DM_STRCHR(buf, '/');
	if (pch)
		*pch = '\0';
	*value = dmstrdup(buf);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourceMask!UCI:firewall/rule,@i-1/src_ip*/
static int get_rule_source_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pch, *srcip;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_ip", &srcip);
	if (*srcip == '\0')
		return 0;

	pch = DM_STRCHR(srcip, '/');
	if (pch) {
		*value = srcip;
	} else {
		char *family;

		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "family", &family);
		dmasprintf(value, "%s/%s", srcip, DM_LSTRCMP(family, "ipv6") == 0 ? "128" : "32");
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Protocol!UCI:firewall/rule,@i-1/proto*/
static int get_rule_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto = NULL, buf[256], protocol[32], protocol_nbr[16];

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "proto", &proto);

	if (!proto || *proto == 0 || strchr(proto, ' ')) {
		*value = "255";
		return 0;
	}

	if (*proto == '0' || strcmp(proto, "all") == 0) {
		*value = "-1";
		return 0;
	}

	if (isdigit_str(proto)) {
		*value = proto;
		return 0;
	}

	FILE *fp = fopen("/etc/protocols", "r");
	if (fp == NULL)
		return 0;

	while (fgets (buf , 256 , fp) != NULL) {
		sscanf(buf, "%31s %15s", protocol, protocol_nbr);
		if (DM_STRCMP(protocol, proto) == 0) {
			*value = dmstrdup(protocol_nbr);
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestPort!UCI:firewall/rule,@i-1/dest_port*/
static int get_rule_dest_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp,*v;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_port", &v);
	v = dmstrdup(v);
	tmp = DM_STRCHR(v, ':');
	if (tmp == NULL)
		tmp = DM_STRCHR(v, '-');
	if (tmp)
		*tmp = '\0';
	if (*v == '\0') {
		*value = "-1";
		return 0;
	}
	*value = v;
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestPortRangeMax!UCI:firewall/rule,@i-1/dest_port*/
static int get_rule_dest_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp, *v;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_port", &v);
	tmp = DM_STRCHR(v, ':');
	if (tmp == NULL)
		tmp = DM_STRCHR(v, '-');
	*value = (tmp) ? tmp+1 : "-1";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourcePort!UCI:firewall/rule,@i-1/src_port*/
static int get_rule_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp, *v;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_port", &v);
	v = dmstrdup(v);
	tmp = DM_STRCHR(v, ':');
	if (tmp == NULL)
		tmp = DM_STRCHR(v, '-');
	if (tmp)
		*tmp = '\0';
	if (*v == '\0') {
		*value = "-1";
		return 0;
	}
	*value = v;
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourcePortRangeMax!UCI:firewall/rule,@i-1/src_port*/
static int get_rule_source_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp, *v;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_port", &v);
	tmp = DM_STRCHR(v, ':');
	if (tmp == NULL)
		tmp = DM_STRCHR(v, '-');
	*value = (tmp) ? tmp+1 : "-1";
	return 0;
}

static int set_firewall_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("firewall", "globals", "enabled", b ? "1" : "0");
			break;
	}
        return 0;
}

static int set_firewall_config(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, Config, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Advanced") != 0)
				return FAULT_9007;
			break;
	}
        return 0;
}

static int set_firewall_advanced_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Device.Firewall.Level.1.") != 0)
				return FAULT_9007;
			break;
	}
        return 0;
}

static int set_level_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm((struct uci_section *)data, "firewall_level_alias", value);
			return 0;
	}
	return 0;
}

static int set_level_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm((struct uci_section *)data, "name", value);
			break;
	}
        return 0;
}

static int set_level_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm((struct uci_section *)data, "description", value);
			break;
	}
        return 0;
}

static int set_level_port_mapping_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b, portmapping_sec_exists = false;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			uci_foreach_sections("firewall", "include", s) {
				if (strncmp(section_name(s), "portmapping", 11) == 0) {
					portmapping_sec_exists = true;
					break;
				}
			}

			if (portmapping_sec_exists == true) {
				dmuci_set_value_by_section(s, "enabled", b ? "0" : "1");
			} else {
				create_portmapping_section(b);
			}
			break;
	}
	return 0;
}

static int set_level_default_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *DefaultPolicy[] = {"Drop", "Accept", "Reject", NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DefaultPolicy, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "Drop") == 0) {
				dmuci_set_value("firewall", "@defaults[0]", "input", "DROP");
				dmuci_set_value("firewall", "@defaults[0]", "output", "DROP");
			} else if (DM_LSTRCMP(value, "Accept") == 0) {
				dmuci_set_value("firewall", "@defaults[0]", "input", "ACCEPT");
				dmuci_set_value("firewall", "@defaults[0]", "output", "ACCEPT");
			} else {
				dmuci_set_value("firewall", "@defaults[0]", "input", "REJECT");
				dmuci_set_value("firewall", "@defaults[0]", "output", "REJECT");
			}
			break;
	}
	return 0;
}

static int set_level_default_log_policy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				uci_foreach_sections("firewall", "zone", s) {
					dmuci_set_value_by_section(s, "log", "1");
				}
			} else {
				uci_foreach_sections("firewall", "zone", s) {
					dmuci_set_value_by_section(s, "log", "");
				}
			}
			break;
	}
	return 0;
}

static int set_chain_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int set_chain_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm((struct uci_section *)data, "firewall_chain_alias", value);
			return 0;
	}
	return 0;
}

static int set_chain_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm((struct uci_section *)data, "name", value);
			break;
	}
        return 0;
}

static int set_rule_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int set_rule_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
        return 0;
}

static int set_rule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "firewall_chain_rule_alias", value);
			return 0;
	}
	return 0;
}

static int set_rule_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", value);
			break;
	}
        return 0;
}

static int set_rule_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, Target, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Accept") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "target", "ACCEPT");
			else if (strcasecmp(value, "Reject") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "target", "REJECT");
			else if (strcasecmp(value, "Drop") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "target", "DROP");
			else if (strcasecmp(value, "Return") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "target", "MARK");
			break;
	}
        return 0;
}

static int set_rule_log(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "log", b ? "1" : "");
			break;
	}
        return 0;
}

static int set_rule_interface(struct dmctx *ctx, void *data, char *type, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *iface = NULL, *option = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, type, &option);

			if (*value == '\0') {
				dmuci_set_value_by_section((option && DM_LSTRCMP(option, "*") == 0) ? ((struct dmmap_dup *)data)->dmmap_section : ((struct dmmap_dup *)data)->config_section, type, "");
			} else {
				adm_entry_get_linker_value(ctx, value, &iface);
				if (iface && iface[0] != '\0') {
					struct uci_section *s = NULL;
					char *net;

					uci_foreach_sections("firewall", "zone", s) {
						dmuci_get_value_by_section_string(s, "network", &net);
						if (dm_strword(net, iface)) {
							char *zone_name;

							dmuci_get_value_by_section_string(s, "name", &zone_name);
							dmuci_set_value_by_section((option && DM_LSTRCMP(option, "*") == 0) ? ((struct dmmap_dup *)data)->dmmap_section : ((struct dmmap_dup *)data)->config_section, type, zone_name);
							break;
						}
					}
					dmfree(iface);
				}
			}
			break;
	}
	return 0;
}

static int set_rule_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_rule_interface(ctx, data, "src", value, action);
}

static int set_rule_source_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				// Get the current 'src' option
				dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src", &src);

				// Save 'src' option in the associated dmmap rule section
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "src", src);

				// Set the current 'src' option
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src", "*");
			} else {
				// Get 'src' option from the associated dmmap rule section
				dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "src", &src);

				// Set the current 'src' option
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src", src);
			}
			break;
	}
	return 0;
}

static int set_rule_dest_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_rule_interface(ctx, data, "dest", value, action);
}

static int set_rule_dest_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dest;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				// Get the current 'dest' option
				dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest", &dest);

				// Save 'dest' option in the associated dmmap rule section
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "dest", dest);

				// Set the current 'dest' option
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest", "*");
			} else {
				// Get 'dest' option from the associated dmmap rule section
				dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "dest", &dest);

				// Set the current 'dest' option
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest", dest);
			}
			break;
	}
	return 0;
}

static int set_rule_i_p_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","15"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "4") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "family", "ipv4");
			else if (DM_LSTRCMP(value, "6") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "family", "ipv6");
			else if (DM_LSTRCMP(value, "-1") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "family", "");
			break;
	}
        return 0;
}

static int set_rule_dest_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[64], *pch, *destip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_ip", &destip);
			DM_STRNCPY(buf, destip, sizeof(buf));
			pch = DM_STRCHR(buf, '/');
			if (pch)
				snprintf(new, sizeof(new), "%s%s", value, pch);
			else
				DM_STRNCPY(new, value, sizeof(new));
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", new);
			break;
	}
    return 0;
}

static int set_rule_dest_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char new[64], *pch, *destip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, IPPrefix))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_ip", &destip);
			pch = DM_STRCHR(destip, '/');
			if (pch)
				*pch = '\0';

			pch = DM_STRCHR(value, '/');
			if (pch == NULL)
				return FAULT_9007;

			snprintf(new, sizeof(new), "%s%s", destip, pch);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", new);
			break;
	}
        return 0;
}

static int set_rule_source_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[64], *pch, *srcip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_ip", &srcip);
			DM_STRNCPY(buf, srcip, sizeof(buf));
			pch = DM_STRCHR(buf, '/');
			if (pch)
				snprintf(new, sizeof(new), "%s%s", value, pch);
			else
				DM_STRNCPY(new, value, sizeof(new));
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_ip", new);
			break;
	}
        return 0;
}

static int set_rule_source_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char new[64], *pch, *srcip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, IPPrefix))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_ip", &srcip);
			pch = DM_STRCHR(srcip, '/');
			if (pch)
				*pch = '\0';

			pch = DM_STRCHR(value, '/');
			if (pch == NULL)
				return FAULT_9007;

			snprintf(new, sizeof(new), "%s%s", srcip, pch);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_ip", new);
			break;
	}
        return 0;
}

static int set_rule_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "proto", (*value == '-') ? "0" : value);
			break;
	}
        return 0;
}

static int set_rule_dest_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buffer[64], *v, *tmp = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (*value == '-')
				value = "";
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_port", &v);
			tmp = DM_STRCHR(v, ':');
			if (tmp == NULL)
				tmp = DM_STRCHR(v, '-');
			if (tmp == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, tmp);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_port", buffer);
			break;
	}
        return 0;
}

static int set_rule_dest_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *v, *tmp, *buf, buffer[64];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_port", &v);
			buf = dmstrdup(v);
			v = buf;
			tmp = DM_STRCHR(buf, ':');
			if (tmp == NULL)
				tmp = DM_STRCHR(v, '-');
			if (tmp)
				*tmp = '\0';
			if (*value == '-')
				snprintf(buffer, sizeof(buffer), "%s", v);
			else
				snprintf(buffer, sizeof(buffer), "%s:%s", v, value);
			dmfree(buf);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_port", buffer);
			break;
	}
	return 0;
}

static int set_rule_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buffer[64], *v, *tmp = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (*value == '-')
				value = "";
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_port", &v);
			tmp = DM_STRCHR(v, ':');
			if (tmp == NULL)
				tmp = DM_STRCHR(v, '-');
			if (tmp == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, tmp);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_port", buffer);
			break;
	}
    return 0;
}

static int set_rule_source_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *v, *tmp, *buf, buffer[64];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "src_port", &v);
			buf = dmstrdup(v);
			v = buf;
			tmp = DM_STRCHR(buf, ':');
			if (tmp == NULL)
				tmp = DM_STRCHR(buf, '-');
			if (tmp)
				*tmp = '\0';
			if (*value == '-')
				snprintf(buffer, sizeof(buffer), "%s", v);
			else
				snprintf(buffer, sizeof(buffer), "%s:%s", v, value);
			dmfree(buf);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_port", buffer);
			break;
	}
        return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Firewall. *** */
DMOBJ tFirewallObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Level", &DMREAD, NULL, NULL, NULL, browseLevelInst, NULL, NULL, NULL, tFirewallLevelParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.2"},
{"Chain", &DMREAD, NULL, NULL, NULL, browseChainInst, NULL, NULL, tFirewallChainObj, tFirewallChainParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.2"},
{0}
};

DMLEAF tFirewallParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_firewall_enable, set_firewall_enable, BBFDM_BOTH, "2.2"},
{"Config", &DMWRITE, DMT_STRING, get_firewall_config, set_firewall_config, BBFDM_BOTH, "2.0"},
{"AdvancedLevel", &DMWRITE, DMT_STRING, get_firewall_advanced_level, set_firewall_advanced_level, BBFDM_BOTH, "2.2"},
{"LevelNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_level_number_of_entries, NULL, BBFDM_BOTH, "2.2"},
{"ChainNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_chain_number_of_entries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Firewall.Level.{i}. *** */
DMLEAF tFirewallLevelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_level_alias, set_level_alias, BBFDM_BOTH, "2.2"},
{"Name", &DMWRITE, DMT_STRING, get_level_name, set_level_name, BBFDM_BOTH, "2.2"},
{"Description", &DMWRITE, DMT_STRING, get_level_description, set_level_description, BBFDM_BOTH, "2.2"},
{"Chain", &DMREAD, DMT_STRING, get_level_chain, NULL, BBFDM_BOTH, "2.2"},
{"PortMappingEnabled", &DMWRITE, DMT_BOOL, get_level_port_mapping_enabled, set_level_port_mapping_enabled, BBFDM_BOTH, "2.2"},
{"DefaultPolicy", &DMWRITE, DMT_STRING, get_level_default_policy, set_level_default_policy, BBFDM_BOTH, "2.2"},
{"DefaultLogPolicy", &DMWRITE, DMT_BOOL, get_level_default_log_policy, set_level_default_log_policy, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Firewall.Chain.{i}. *** */
DMOBJ tFirewallChainObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Rule", &DMWRITE, add_firewall_rule, delete_firewall_rule, NULL, browseRuleInst, NULL, NULL, NULL, tFirewallChainRuleParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tFirewallChainParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_chain_enable, set_chain_enable, BBFDM_BOTH, "2.2"},
{"Alias", &DMWRITE, DMT_STRING, get_chain_alias, set_chain_alias, BBFDM_BOTH, "2.2"},
{"Name", &DMWRITE, DMT_STRING, get_chain_name, set_chain_name, BBFDM_BOTH, "2.2"},
{"Creator", &DMREAD, DMT_STRING, get_chain_creator, NULL, BBFDM_BOTH, "2.2"},
{"RuleNumberOfEntries", &DMREAD, DMT_UNINT, get_chain_rule_number_of_entries, NULL, BBFDM_BOTH, "2.2"},
{0}
};

/* *** Device.Firewall.Chain.{i}.Rule.{i}. *** */
DMLEAF tFirewallChainRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMRule, DMT_BOOL, get_rule_enable, set_rule_enable, BBFDM_BOTH, "2.2"},
{"Status", &DMRule, DMT_STRING, get_rule_status, NULL, BBFDM_BOTH, "2.2"},
{"Order", &DMWRITE, DMT_UNINT, get_rule_order, set_rule_order, BBFDM_BOTH, "2.2"},
{"Alias", &DMWRITE, DMT_STRING, get_rule_alias, set_rule_alias, BBFDM_BOTH, "2.2"},
{"Description", &DMRule, DMT_STRING, get_rule_description, set_rule_description, BBFDM_BOTH, "2.2"},
{"Target", &DMRule, DMT_STRING, get_rule_target, set_rule_target, BBFDM_BOTH, "2.2"},
//{"TargetChain", &DMRule, DMT_STRING, get_rule_target_chain, set_rule_target_chain, BBFDM_BOTH, "2.2"},
{"Log", &DMRule, DMT_BOOL, get_rule_log, set_rule_log, BBFDM_BOTH, "2.2"},
{"CreationDate", &DMRule, DMT_TIME, get_FirewallChainRule_CreationDate, NULL, BBFDM_BOTH, "2.2"},
{"ExpiryDate", &DMRule, DMT_TIME, get_FirewallChainRule_ExpiryDate, set_FirewallChainRule_ExpiryDate, BBFDM_BOTH, "2.2"},
{"SourceInterface", &DMRule, DMT_STRING, get_rule_source_interface, set_rule_source_interface, BBFDM_BOTH, "2.2"},
{"SourceAllInterfaces", &DMRule, DMT_BOOL, get_rule_source_all_interfaces, set_rule_source_all_interfaces, BBFDM_BOTH, "2.2"},
{"DestInterface", &DMRule, DMT_STRING, get_rule_dest_interface, set_rule_dest_interface, BBFDM_BOTH, "2.2"},
{"DestAllInterfaces", &DMWRITE, DMT_BOOL, get_rule_dest_all_interfaces, set_rule_dest_all_interfaces, BBFDM_BOTH, "2.2"},
{"IPVersion", &DMRule, DMT_INT, get_rule_i_p_version, set_rule_i_p_version, BBFDM_BOTH, "2.2"},
{"DestIP", &DMRule, DMT_STRING, get_rule_dest_ip, set_rule_dest_ip, BBFDM_BOTH, "2.2"},
{"DestMask", &DMRule, DMT_STRING, get_rule_dest_mask, set_rule_dest_mask, BBFDM_BOTH, "2.2"},
{"SourceIP", &DMRule, DMT_STRING, get_rule_source_ip, set_rule_source_ip, BBFDM_BOTH, "2.2"},
{"SourceMask", &DMRule, DMT_STRING, get_rule_source_mask, set_rule_source_mask, BBFDM_BOTH, "2.2"},
{"Protocol", &DMRule, DMT_INT, get_rule_protocol, set_rule_protocol, BBFDM_BOTH, "2.2"},
{"DestPort", &DMRule, DMT_INT, get_rule_dest_port, set_rule_dest_port, BBFDM_BOTH, "2.2"},
{"DestPortRangeMax", &DMRule, DMT_INT, get_rule_dest_port_range_max, set_rule_dest_port_range_max, BBFDM_BOTH, "2.2"},
{"SourcePort", &DMRule, DMT_INT, get_rule_source_port, set_rule_source_port, BBFDM_BOTH, "2.2"},
{"SourcePortRangeMax", &DMRule, DMT_INT, get_rule_source_port_range_max, set_rule_source_port_range_max, BBFDM_BOTH, "2.2"},
{0}
};
