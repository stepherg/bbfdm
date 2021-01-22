/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "dmentry.h"
#include "firewall.h"


/***************************** Browse Functions ***********************************/
static int browseLevelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *max_inst = NULL;

	s = is_dmmap_section_exist("dmmap_firewall", "level");
	if (!s) dmuci_add_section_bbfdm("dmmap_firewall", "level", &s);
	handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			s, "firewall_level_instance", "firewall_level_alias");
	DM_LINK_INST_OBJ(dmctx, parent_node, s, "1");
	return 0;
}

static int browseChainInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *max_inst = NULL;

	s = is_dmmap_section_exist("dmmap_firewall", "chain");
	if (!s) dmuci_add_section_bbfdm("dmmap_firewall", "chain", &s);
	handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			s, "firewall_chain_instance", "firewall_chain_alias");
	DM_LINK_INST_OBJ(dmctx, parent_node, s, "1");
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.!UCI:firewall/rule/dmmap_firewall*/
static int browseRuleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst, *max_inst = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "rule", "dmmap_firewall", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "firewall_chain_rule_instance", "firewall_chain_rule_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_firewall_rule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_firewall_rule = NULL;
	char creation_date[32] = {0};
	char s_name[16] = {0};
	time_t now = time(NULL);

	strftime(creation_date, sizeof(creation_date), "%Y-%m-%dT%H:%M:%SZ", localtime(&now));

	char *last_inst = get_last_instance_bbfdm("dmmap_firewall", "rule", "firewall_chain_rule_instance");
	snprintf(s_name, sizeof(s_name), "rule_%s", last_inst ? last_inst : "1");

	dmuci_add_section("firewall", "rule", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "name", "-");
	dmuci_set_value_by_section(s, "enabled", "0");
	dmuci_set_value_by_section(s, "dest", "");
	dmuci_set_value_by_section(s, "src", "");
	dmuci_set_value_by_section(s, "target", "DROP");

	dmuci_add_section_bbfdm("dmmap_firewall", "rule", &dmmap_firewall_rule);
	dmuci_set_value_by_section(dmmap_firewall_rule, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_firewall_rule, "creation_date", creation_date);
	*instance = update_instance(last_inst, 2, dmmap_firewall_rule, "firewall_chain_rule_instance");
	return 0;
}

static int delete_firewall_rule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name((struct uci_section *)data))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_firewall", "rule", "firewall_chain_rule_instance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "firewall_chain_rule_instance", "dmmap_firewall", "rule");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
				if (dmmap_section)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("firewall", "rule", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name(ss), &dmmap_section);
					if (dmmap_section)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name(ss), &dmmap_section);
				if (dmmap_section)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
	}
	return 0;
}

/***************************************** Set/Get Parameter functions ***********************/
static int get_firewall_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*firewall";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
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
	char *v;

	uci_foreach_sections("firewall", "zone", s) {
		dmuci_get_value_by_section_string(s, "masq", &v);
		if (*v == '1') {
			*value = "1";
			return 0;
		}
	}
	*value = "0";
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
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("firewall", "rule", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Enable!UCI:firewall/rule,@i-1/enabled*/
static int get_rule_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &v);
	*value = (*v == 'n' || *v == '0' ) ? "0" : "1";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Status!UCI:firewall/rule,@i-1/enabled*/
static int get_rule_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &v);
	*value = (*v == 'n' || *v == '0') ? "Disabled" : "Enabled";
	return 0;
}

static int get_rule_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dms = NULL;
	get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dms);
	dmuci_get_value_by_section_string(dms, "firewall_chain_rule_instance", value);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Alias!UCI:dmmap_firewall/rule,@i-1/firewall_chain_rule_alias*/
static int get_rule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "firewall_chain_rule_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Description!UCI:firewall/rule,@i-1/name*/
static int get_rule_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Target!UCI:firewall/rule,@i-1/target*/
static int get_rule_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;

	dmuci_get_value_by_section_string((struct uci_section *)data, "target", &v);
	if (strcasecmp(v, "Accept") == 0)
		*value = "Accept";
	else if (strcasecmp(v, "Reject") == 0)
		*value = "Reject";
	else if (strcasecmp(v, "Drop") == 0)
		*value = "Drop";
	else if (strcasecmp(v, "MARK") == 0)
		*value = "Return";
	else
		*value = v;
    return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Log!UCI:firewall/rule,@i-1/log*/
static int get_rule_log(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "log", &v);
	*value = (*v == '1' ) ? "1" : "0";
	return 0;
}

static int get_FirewallChainRule_CreationDate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
	*value = dmuci_get_value_by_section_fallback_def(dmmap_section, "creation_date", "0001-01-01T00:00:00Z");
	return 0;
}

static int get_rule_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifaceobj = NULL, *src = NULL, buf[256] = "";
	struct uci_list *net_list = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "src", &src);
	if (src == NULL || *src == '\0')
		return 0;

	if (strcmp(src, "*") == 0) {
		struct uci_section *dmmap_section = NULL;

		get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "src", &src);
	} else {
		struct uci_section *s = NULL;
		char *zone_name = NULL;

		uci_foreach_sections("firewall", "zone", s) {
			dmuci_get_value_by_section_string(s, "name", &zone_name);
			if (zone_name && strcmp(zone_name, src) == 0) {
				dmuci_get_value_by_section_list(s, "network", &net_list);
				break;
			}
		}
	}

	if (net_list != NULL) {
		struct uci_element *e;

		uci_foreach_element(net_list, e) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", e->name, &ifaceobj);
			if (ifaceobj == NULL)
				continue;
			if (*buf != '\0')
				strcat(buf, ",");
			strcat(buf, ifaceobj);
		}
	} else {
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", src, &ifaceobj);
		if (ifaceobj)
			strcpy(buf, ifaceobj);
	}

	*value = dmstrdup(buf);
	return 0;
}

static int get_rule_source_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "src", &v);
	*value = (*v == '*') ? "1" : "0";
	return 0;
}

static int get_rule_dest_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifaceobj = NULL, *dest = NULL, buf[256] = "";
	struct uci_list *net_list = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "dest", &dest);
	if (dest == NULL || *dest == '\0')
		return 0;

	if (strcmp(dest, "*") == 0) {
		struct uci_section *dmmap_section = NULL;

		get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "dest", &dest);
	} else {
		struct uci_section *s = NULL;
		char *zone_name = NULL;

		uci_foreach_sections("firewall", "zone", s) {
			dmuci_get_value_by_section_string(s, "name", &zone_name);
			if (zone_name && strcmp(zone_name, dest) == 0) {
				dmuci_get_value_by_section_list(s, "network", &net_list);
				break;
			}
		}
	}

	if (net_list != NULL) {
		struct uci_element *e;

		uci_foreach_element(net_list, e) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", e->name, &ifaceobj);
			if (ifaceobj == NULL)
				continue;
			if (*buf != '\0')
				strcat(buf, ",");
			strcat(buf, ifaceobj);
		}
	} else {
		adm_entry_get_linker_param(ctx, "Device.IP.Interface.", dest, &ifaceobj);
		if (ifaceobj)
			strcpy(buf, ifaceobj);
	}

	*value = dmstrdup(buf);
	return 0;
}

static int get_rule_dest_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "dest", &v);
	*value = (*v == '*') ? "1" : "0";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.IPVersion!UCI:firewall/rule,@i-1/family*/
static int get_rule_i_p_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipversion;

	dmuci_get_value_by_section_string((struct uci_section *)data, "family", &ipversion);
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

	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_ip", &destip);
	strcpy(buf, destip);
	pch = strchr(buf, '/');
	if (pch) *pch = '\0';
	*value = dmstrdup(buf);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestMask!UCI:firewall/rule,@i-1/dest_ip*/
static int get_rule_dest_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pch, *destip;

	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_ip", &destip);
	if (*destip == '\0')
		return 0;

	pch = strchr(destip, '/');
	if (pch) {
		*value = pch+1;
	} else {
		*value = "";
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourceIp!UCI:firewall/rule,@i-1/src_ip*/
static int get_rule_source_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[64], *pch, *srcip;

	dmuci_get_value_by_section_string((struct uci_section *)data, "src_ip", &srcip);
	strcpy(buf, srcip);
	pch = strchr(buf, '/');
	if (pch)
		*pch = '\0';
	*value = dmstrdup(buf);
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourceMask!UCI:firewall/rule,@i-1/src_ip*/
static int get_rule_source_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pch, *srcip;
	*value = "";

	dmuci_get_value_by_section_string((struct uci_section *)data, "src_ip", &srcip);
	if (*srcip == '\0')
		return 0;

	pch = strchr(srcip, '/');
	if (pch) {
		*value = pch+1;
	} else {
		*value = "";
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Protocol!UCI:firewall/rule,@i-1/proto*/
static int get_rule_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE *fp;
	char *v, buf[256], protocol[32], protocol_nbr[16];

	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &v);
	*value = "-1";
	if (*v == '\0' || *v == '0') {
		return 0;
	}
	if (isdigit_str(v)) {
		*value = v;
		return 0;
	}
	fp = fopen("/etc/protocols", "r");
	if (fp == NULL)
		return 0;
	while (fgets (buf , 256 , fp) != NULL) {
		sscanf(buf, "%31s %15s", protocol, protocol_nbr);
		if (strcmp(protocol, v) == 0) {
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

	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port", &v);
	v = dmstrdup(v);
	tmp = strchr(v, ':');
	if (tmp == NULL)
		tmp = strchr(v, '-');
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

	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port", &v);
	tmp = strchr(v, ':');
	if (tmp == NULL)
		tmp = strchr(v, '-');
	*value = (tmp) ? tmp+1 : "-1";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourcePort!UCI:firewall/rule,@i-1/src_port*/
static int get_rule_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp, *v;

	dmuci_get_value_by_section_string((struct uci_section *)data, "src_port", &v);
	v = dmstrdup(v);
	tmp = strchr(v, ':');
	if (tmp == NULL)
		tmp = strchr(v, '-');
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

	dmuci_get_value_by_section_string((struct uci_section *)data, "src_port", &v);
	tmp = strchr(v, ':');
	if (tmp == NULL)
		tmp = strchr(v, '-');
	*value = (tmp) ? tmp+1 : "-1";
	return 0;
}

static int get_rule_icmp_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *v= NULL;
	struct uci_element *e;
	char *ptr;

	dmasprintf(value, "%s", "");
	dmuci_get_value_by_section_list((struct uci_section *)data, "icmp_type", &v);
	if (v != NULL) {
		uci_foreach_element(v, e) {
			ptr = dmstrdup(*value);
			dmfree(*value);

			if (strlen(ptr) == 0)
				dmasprintf(value, "%s", e->name);
			else {
				dmasprintf(value, "%s %s", ptr, e->name);
				dmfree(ptr);
			}
		}
	}
	return 0;
}

static int get_rule_source_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_mac", &v);
	*value = (v) ? v : "";
	return 0;
}

static int get_time_span_supported_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "mon tue wed thu fri sat sun";
	return 0;
}

static int get_time_span_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "weekdays", &v);
	*value = (v) ? v : "";
	return 0;
}

static int get_time_span_start_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "start_time", &v);
	*value = (v) ? v : "";
	return 0;
}

static int get_time_span_stop_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string((struct uci_section *)data, "stop_time", &v);
	*value = (v) ? v : "";
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
			dmcmd("/etc/init.d/firewall", 1, b ? "enable" : "disable");
			break;
	}
        return 0;
}

static int set_firewall_config(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, Config, 4, NULL, 0))
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
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
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
	bool b;
	struct uci_section *s = NULL;
	char *v, *v2;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				uci_foreach_sections("firewall", "zone", s) {
					dmuci_get_value_by_section_string(s, "src", &v);
					dmuci_get_value_by_section_string(s, "name", &v2);
					if (strcasestr(v, "wan") || strcasestr(v2, "wan")) {
						dmuci_set_value_by_section(s, "masq", "1");
						return 0;
					}
				}
			} else {
				uci_foreach_sections("firewall", "zone", s) {
					dmuci_set_value_by_section(s, "masq", "");
				}
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "" : "0");
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
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "firewall_chain_rule_alias", value);
			return 0;
	}
	return 0;
}

static int set_rule_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "name", value);
			break;
	}
        return 0;
}

static int set_rule_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, Target, 5, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Accept") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "target", "ACCEPT");
			else if (strcasecmp(value, "Reject") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "target", "REJECT");
			else if (strcasecmp(value, "Drop") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "target", "DROP");
			else if (strcasecmp(value, "Return") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "target", "MARK");
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
			dmuci_set_value_by_section((struct uci_section *)data, "log", b ? "1" : "");
			break;
	}
        return 0;
}

static int set_rule_interface(struct dmctx *ctx, void *data, char *type, char *value, int action)
{
	char *iface = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			adm_entry_get_linker_value(ctx, value, &iface);
			if (iface == NULL ||  iface[0] == '\0')
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &iface);
			if (iface && iface[0] != '\0') {
				struct uci_section *s = NULL;
				char *net;

				uci_foreach_sections("firewall", "zone", s) {
					dmuci_get_value_by_section_string(s, "network", &net);
					if (dm_strword(net, iface)) {
						char *zone_name, *option = NULL;

						dmuci_get_value_by_section_string(s, "name", &zone_name);
						dmuci_get_value_by_section_string((struct uci_section *)data, type, &option);
						if (option && strcmp(option, "*") == 0) {
							struct uci_section *dmmap_section = NULL;

							get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
							dmuci_set_value_by_section(dmmap_section, type, zone_name);
						} else {
							dmuci_set_value_by_section((struct uci_section *)data, type, zone_name);
						}
						break;
					}
				}
				dmfree(iface);
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
	struct uci_section *dmmap_section = NULL;
	char *src;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
			string_to_bool(value, &b);
			if (b) {
				// Get the current 'src' option
				dmuci_get_value_by_section_string((struct uci_section *)data, "src", &src);

				// Save 'src' option in the associated dmmap rule section
				dmuci_set_value_by_section(dmmap_section, "src", src);

				// Set the current 'src' option
				dmuci_set_value_by_section((struct uci_section *)data, "src", "*");
			} else {
				// Get 'src' option from the associated dmmap rule section
				dmuci_get_value_by_section_string(dmmap_section, "src", &src);

				// Set the current 'src' option
				dmuci_set_value_by_section((struct uci_section *)data, "src", src);
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
	struct uci_section *dmmap_section = NULL;
	char *dest;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_firewall", "rule", section_name((struct uci_section *)data), &dmmap_section);
			string_to_bool(value, &b);
			if (b) {
				// Get the current 'dest' option
				dmuci_get_value_by_section_string((struct uci_section *)data, "dest", &dest);

				// Save 'dest' option in the associated dmmap rule section
				dmuci_set_value_by_section(dmmap_section, "dest", dest);

				// Set the current 'dest' option
				dmuci_set_value_by_section((struct uci_section *)data, "dest", "*");
			} else {
				// Get 'dest' option from the associated dmmap rule section
				dmuci_get_value_by_section_string(dmmap_section, "dest", &dest);

				// Set the current 'dest' option
				dmuci_set_value_by_section((struct uci_section *)data, "dest", dest);
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
			if (strcmp(value, "4") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "family", "ipv4");
			else if (strcmp(value, "6") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "family", "ipv6");
			else if (strcmp(value, "-1") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "family", "");
			break;
	}
        return 0;
}

static int set_rule_dest_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[64], *pch, *destip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "dest_ip", &destip);
			strcpy(buf, destip);
			pch = strchr(buf, '/');
			if (pch)
				snprintf(new, sizeof(new), "%s%s", value, pch);
			else
				strcpy(new, value);
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", new);
			break;
	}
    return 0;
}

static int set_rule_dest_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[70], *pch, *destip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPPrefix, 3))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "dest_ip", &destip);
			strcpy(buf, destip);
			pch = strchr(buf, '/');
			if (pch)
				*pch = '\0';
			snprintf(new, sizeof(new), "%s/%s", buf, value);
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", new);
			break;
	}
        return 0;
}

static int set_rule_source_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[64], *pch, *srcip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "src_ip", &srcip);
			strcpy(buf, srcip);
			pch = strchr(buf, '/');
			if (pch)
				snprintf(new, sizeof(new), "%s%s", value, pch);
			else
				strcpy(new, value);
			dmuci_set_value_by_section((struct uci_section *)data, "src_ip", new);
			break;
	}
        return 0;
}

static int set_rule_source_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[70], *pch, *srcip;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPPrefix, 3))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "src_ip", &srcip);
			strcpy(buf, srcip);
			pch = strchr(buf, '/');
			if (pch)
				*pch = '\0';
			snprintf(new, sizeof(new), "%s/%s", buf, value);
			dmuci_set_value_by_section((struct uci_section *)data, "src_ip", new);
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
			dmuci_set_value_by_section((struct uci_section *)data, "proto", (*value == '-') ? "" : value);
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
			dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port", &v);
			tmp = strchr(v, ':');
			if (tmp == NULL)
				tmp = strchr(v, '-');
			if (tmp == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, tmp);
			dmuci_set_value_by_section((struct uci_section *)data, "dest_port", buffer);
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
			dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port", &v);
			buf = dmstrdup(v);
			v = buf;
			tmp = strchr(buf, ':');
			if (tmp == NULL)
				tmp = strchr(v, '-');
			if (tmp)
				*tmp = '\0';
			if (*value == '-')
				snprintf(buffer, sizeof(buffer), "%s", v);
			else
				snprintf(buffer, sizeof(buffer), "%s:%s", v, value);
			dmfree(buf);
			dmuci_set_value_by_section((struct uci_section *)data, "dest_port", buffer);
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
			dmuci_get_value_by_section_string((struct uci_section *)data, "src_port", &v);
			tmp = strchr(v, ':');
			if (tmp == NULL)
				tmp = strchr(v, '-');
			if (tmp == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, tmp);
			dmuci_set_value_by_section((struct uci_section *)data, "src_port", buffer);
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
			dmuci_get_value_by_section_string((struct uci_section *)data, "src_port", &v);
			buf = dmstrdup(v);
			v = buf;
			tmp = strchr(buf, ':');
			if (tmp == NULL)
				tmp = strchr(buf, '-');
			if (tmp)
				*tmp = '\0';
			if (*value == '-')
				snprintf(buffer, sizeof(buffer), "%s", v);
			else
				snprintf(buffer, sizeof(buffer), "%s:%s", v, value);
			dmfree(buf);
			dmuci_set_value_by_section((struct uci_section *)data, "src_port", buffer);
			break;
	}
        return 0;
}

static int set_rule_icmp_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int i;
	size_t length;
	char **devices = NULL;

	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "icmp_type", "");
			devices = strsplit(value, " ", &length);
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section((struct uci_section *)data, "icmp_type", devices[i]);
			break;
	}
	return 0;
}

static int set_rule_source_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "src_mac", value);
			break;
	}
	return 0;
}

static int set_time_span_supported_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int set_time_span_days(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "weekdays", value);
			break;
	}
	return 0;
}

static int set_time_span_start_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "start_time", value);
			break;
	}
	return 0;
}

static int set_time_span_stop_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "stop_time", value);
			break;
	}
	return 0;
}

/* *** Device.Firewall. *** */
DMOBJ tFirewallObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Level", &DMREAD, NULL, NULL, NULL, browseLevelInst, NULL, NULL, tFirewallLevelParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"Chain", &DMREAD, NULL, NULL, NULL, browseChainInst, NULL, tFirewallChainObj, tFirewallChainParams, NULL, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{0}
};

DMLEAF tFirewallParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_firewall_enable, set_firewall_enable, BBFDM_BOTH},
{"Config", &DMWRITE, DMT_STRING, get_firewall_config, set_firewall_config, BBFDM_BOTH},
{"AdvancedLevel", &DMWRITE, DMT_STRING, get_firewall_advanced_level, set_firewall_advanced_level, BBFDM_BOTH},
{"LevelNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_level_number_of_entries, NULL, BBFDM_BOTH},
{"ChainNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_chain_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.Level.{i}. *** */
DMLEAF tFirewallLevelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_level_alias, set_level_alias, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_level_name, set_level_name, BBFDM_BOTH},
{"Description", &DMWRITE, DMT_STRING, get_level_description, set_level_description, BBFDM_BOTH},
{"Chain", &DMREAD, DMT_STRING, get_level_chain, NULL, BBFDM_BOTH},
{"PortMappingEnabled", &DMWRITE, DMT_BOOL, get_level_port_mapping_enabled, set_level_port_mapping_enabled, BBFDM_BOTH},
{"DefaultLogPolicy", &DMWRITE, DMT_BOOL, get_level_default_log_policy, set_level_default_log_policy, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.Chain.{i}. *** */
DMOBJ tFirewallChainObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Rule", &DMWRITE, add_firewall_rule, delete_firewall_rule, NULL, browseRuleInst, NULL, tFirewallChainRuleObj, tFirewallChainRuleParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tFirewallChainParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_chain_enable, set_chain_enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_chain_alias, set_chain_alias, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_chain_name, set_chain_name, BBFDM_BOTH},
{"Creator", &DMREAD, DMT_STRING, get_chain_creator, NULL, BBFDM_BOTH},
{"RuleNumberOfEntries", &DMREAD, DMT_UNINT, get_chain_rule_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.Chain.{i}.Rule.{i}. *** */
DMOBJ tFirewallChainRuleObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{CUSTOM_PREFIX"TimeSpan", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tTimeSpanParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tFirewallChainRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_rule_enable, set_rule_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_rule_status, NULL, BBFDM_BOTH},
{"Order", &DMWRITE, DMT_UNINT, get_rule_order, set_rule_order, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_rule_alias, set_rule_alias, BBFDM_BOTH},
{"Description", &DMWRITE, DMT_STRING, get_rule_description, set_rule_description, BBFDM_BOTH},
{"Target", &DMWRITE, DMT_STRING, get_rule_target, set_rule_target, BBFDM_BOTH},
//{"TargetChain", &DMWRITE, DMT_STRING, get_rule_target_chain, set_rule_target_chain, BBFDM_BOTH},
{"Log", &DMWRITE, DMT_BOOL, get_rule_log, set_rule_log, BBFDM_BOTH},
{"CreationDate", &DMREAD, DMT_TIME, get_FirewallChainRule_CreationDate, NULL, BBFDM_BOTH},
{"SourceInterface", &DMWRITE, DMT_STRING, get_rule_source_interface, set_rule_source_interface, BBFDM_BOTH},
{"SourceAllInterfaces", &DMWRITE, DMT_BOOL, get_rule_source_all_interfaces, set_rule_source_all_interfaces, BBFDM_BOTH},
{"DestInterface", &DMWRITE, DMT_STRING, get_rule_dest_interface, set_rule_dest_interface, BBFDM_BOTH},
{"DestAllInterfaces", &DMWRITE, DMT_BOOL, get_rule_dest_all_interfaces, set_rule_dest_all_interfaces, BBFDM_BOTH},
{"IPVersion", &DMWRITE, DMT_INT, get_rule_i_p_version, set_rule_i_p_version, BBFDM_BOTH},
{"DestIP", &DMWRITE, DMT_STRING, get_rule_dest_ip, set_rule_dest_ip, BBFDM_BOTH},
{"DestMask", &DMWRITE, DMT_STRING, get_rule_dest_mask, set_rule_dest_mask, BBFDM_BOTH},
{"SourceIP", &DMWRITE, DMT_STRING, get_rule_source_ip, set_rule_source_ip, BBFDM_BOTH},
{"SourceMask", &DMWRITE, DMT_STRING, get_rule_source_mask, set_rule_source_mask, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_INT, get_rule_protocol, set_rule_protocol, BBFDM_BOTH},
{"DestPort", &DMWRITE, DMT_INT, get_rule_dest_port, set_rule_dest_port, BBFDM_BOTH},
{"DestPortRangeMax", &DMWRITE, DMT_INT, get_rule_dest_port_range_max, set_rule_dest_port_range_max, BBFDM_BOTH},
{"SourcePort", &DMWRITE, DMT_INT, get_rule_source_port, set_rule_source_port, BBFDM_BOTH},
{"SourcePortRangeMax", &DMWRITE, DMT_INT, get_rule_source_port_range_max, set_rule_source_port_range_max, BBFDM_BOTH},
{CUSTOM_PREFIX"ICMPType", &DMWRITE, DMT_STRING, get_rule_icmp_type, set_rule_icmp_type, BBFDM_BOTH},
{CUSTOM_PREFIX"SourceMACAddress", &DMWRITE, DMT_STRING, get_rule_source_mac, set_rule_source_mac, BBFDM_BOTH},
{0}
};

DMLEAF tTimeSpanParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"SupportedDays", &DMWRITE, DMT_STRING, get_time_span_supported_days, set_time_span_supported_days, BBFDM_BOTH},
{"Days", &DMWRITE, DMT_STRING, get_time_span_days, set_time_span_days, BBFDM_BOTH},
{"StartTime", &DMWRITE, DMT_STRING, get_time_span_start_time, set_time_span_start_time, BBFDM_BOTH},
{"StopTime", &DMWRITE, DMT_STRING, get_time_span_stop_time, set_time_span_stop_time, BBFDM_BOTH},
{0}
};
