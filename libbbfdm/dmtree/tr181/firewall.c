/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *      Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#include "firewall.h"

struct rule_sec
{
	struct list_head list;
	struct uci_section *config_section;
	struct uci_section *dmmap_section;
	char **dynamic_rule;
	char *creator;
	bool is_dynamic_rule;
};

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
void firewall__create_zone_section(char *s_name)
{
	struct uci_section *s = NULL;
	char *input = NULL;
	char *output = NULL;
	char *forward = NULL;

	dmuci_get_option_value_string("firewall", "@defaults[0]", "input", &input);
	dmuci_get_option_value_string("firewall", "@defaults[0]", "output", &output);
	dmuci_get_option_value_string("firewall", "@defaults[0]", "forward", &forward);

	dmuci_add_section("firewall", "zone", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "name", s_name);
	dmuci_set_value_by_section(s, "input", input);
	dmuci_set_value_by_section(s, "output", output);
	dmuci_set_value_by_section(s, "forward", forward);

	dmuci_add_list_value_by_section(s, "network", s_name);
}

static bool firewall_zone_exists(char *s_name)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("firewall", "zone", "name", s_name, s) {
		return true;
	}

	return false;
}

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
	struct rule_sec *rule_args = (struct rule_sec *)data;

	return (!rule_args || rule_args->is_dynamic_rule) ? "0" : "1";
}

struct dm_permession_s DMRule = {"1", &get_rule_perm};

static void add_firewall_config_dup_list(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section, bool is_dynamic_rule)
{
	struct rule_sec *rule_args;

	rule_args = dmcalloc(1, sizeof(struct rule_sec));
	list_add_tail(&rule_args->list, dup_list);

	rule_args->config_section = config_section;
	rule_args->dmmap_section = dmmap_section;
	rule_args->is_dynamic_rule = is_dynamic_rule;
}

static void free_firewall_config_dup_list(struct list_head *dup_list)
{
	struct rule_sec *rule_args = NULL, *tmp = NULL;

	list_for_each_entry_safe(rule_args, tmp, dup_list, list) {
		list_del(&rule_args->list);
		dmfree(rule_args);
	}
}

void synchronize_firewall_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, bool is_dynamic_rule, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	char *v;

	uci_foreach_sections(package, section_type, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 */
		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, section_type, section_name(s))) == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section_type, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(s));
		}

		/*
		 * Add system and dmmap sections to the list
		 */
		add_firewall_config_dup_list(dup_list, s, dmmap_sect, is_dynamic_rule);
	}

	/*
	 * Delete unused dmmap sections
	 */
	uci_path_foreach_sections_safe(bbfdm, dmmap_package, section_type, stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &v);
		if (get_origin_section_from_config(package, section_type, v) == NULL)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static void fill_rules_info(struct uci_section *s)
{
	struct uci_context *fw_ctx = NULL;
	struct uci_package *fw_pkg = NULL;
	struct uci_element *fw_elmnt = NULL;
	char rule_start_pos[8], rules_num[8];
	unsigned int pos = 0, num = 0, idx = 0;

	fw_ctx = uci_alloc_context();
	if (!fw_ctx)
		return;

	uci_load(fw_ctx, "firewall", &fw_pkg);
	if (!fw_pkg)
		goto end;


	uci_foreach_element(&fw_pkg->sections, fw_elmnt) {
		struct uci_section *uci_sec = uci_to_section(fw_elmnt);

		if (DM_STRCMP(uci_sec->type, "forwarding") == 0) {
			pos = idx;
			num++;
		}

		if (DM_STRCMP(uci_sec->type, "rule") == 0)
			num++;

		idx++;
	}

	uci_unload(fw_ctx, fw_pkg);

	snprintf(rule_start_pos, sizeof(rule_start_pos), "%u", pos);
	snprintf(rules_num, sizeof(rules_num), "%u", num);

	dmuci_set_value_by_section(s, "rule_start_pos", rule_start_pos);
	dmuci_set_value_by_section(s, "rules_num", rules_num);

end:
	uci_free_context(fw_ctx);
}

static void update_rule_order(const char *start_order, const char *stop_order, bool incr)
{
	struct uci_section *s = NULL;
	char *order = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_firewall", "forwarding", s) {

		dmuci_get_value_by_section_string(s, "order", &order);

		if ((DM_STRTOUL(order) >= DM_STRTOUL(start_order)) && (DM_STRTOUL(order) <= DM_STRTOUL(stop_order))) {
			char buf[8] = {0};

			snprintf(buf, sizeof(buf), "%lu", incr ? (DM_STRTOUL(order) + 1) : (DM_STRTOUL(order) - 1));
			dmuci_set_value_by_section(s, "order", buf);
		}
	}

	uci_path_foreach_sections(bbfdm, "dmmap_firewall", "rule", s) {

		dmuci_get_value_by_section_string(s, "order", &order);

		if ((DM_STRTOUL(order) >= DM_STRTOUL(start_order)) && (DM_STRTOUL(order) <= DM_STRTOUL(stop_order))) {
			char buf[8] = {0};

			snprintf(buf, sizeof(buf), "%lu", incr ? (DM_STRTOUL(order) + 1) : (DM_STRTOUL(order) - 1));
			dmuci_set_value_by_section(s, "order", buf);
		}
	}
}

/*************************************************************
* ADD & DEL OBJ
*************************************************************/
static int addService(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char s_name[16];

	snprintf(s_name, sizeof(s_name), "service_%s", *instance);

	dmuci_add_section("firewall", "service", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "interface", "");
	dmuci_add_list_value_by_section(s, "dest_port", "-1");
	dmuci_set_value_by_section(s, "family", "-1");
	dmuci_add_list_value_by_section(s, "proto", "-1");
	dmuci_set_value_by_section(s, "icmp_type", "-1");
	dmuci_set_value_by_section(s, "target", "Accept");

	dmuci_add_section_bbfdm("dmmap_firewall", "service", &dmmap_s);
	dmuci_set_value_by_section(dmmap_s, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_s, "service_instance", *instance);

	return 0;
}

static int delService(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("firewall", "service", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_firewall", "service", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

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
	struct uci_section *s = NULL;
	char *inst = NULL;

	s = is_dmmap_section_exist_eq("dmmap_firewall", "chain", "creator", "Defaults");
	if (!s) {
		dmuci_add_section_bbfdm("dmmap_firewall", "chain", &s);
		dmuci_set_value_by_section(s, "name", "Defaults Configuration");
		dmuci_set_value_by_section(s, "creator", "Defaults");
		fill_rules_info(s);
	}

	inst = handle_instance(dmctx, parent_node, s, "firewall_chain_instance", "firewall_chain_alias");
	if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
		return 0;

	if (file_exists("/etc/config/upnpd")) {
		s = is_dmmap_section_exist_eq("dmmap_firewall", "chain", "creator", "PortMapping");
		if (!s) {
			dmuci_add_section_bbfdm("dmmap_firewall", "chain", &s);
			dmuci_set_value_by_section(s, "name", "UPnP Port Mapping (dynamic rules)");
			dmuci_set_value_by_section(s, "creator", "PortMapping");
		}

		inst = handle_instance(dmctx, parent_node, s, "firewall_chain_instance", "firewall_chain_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			return 0;
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.!UCI:firewall/rule/dmmap_firewall*/
static int browseRuleInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *chain_args = (struct uci_section *)prev_data;
	struct rule_sec *p = NULL;
	LIST_HEAD(dup_list);
	char *creator = NULL;
	char *order = NULL;
	char *inst = NULL;

	dmuci_get_value_by_section_string(chain_args, "creator", &creator);

	if (DM_STRCMP(creator, "Defaults") == 0) {

		// Forwarding sections
		synchronize_firewall_sections_with_dmmap("firewall", "forwarding", "dmmap_firewall", true, &dup_list);
		list_for_each_entry(p, &dup_list, list) {

			inst = handle_instance(dmctx, parent_node, p->dmmap_section, "firewall_chain_rule_instance", "firewall_chain_rule_alias");

			dmuci_get_value_by_section_string(p->dmmap_section, "order", &order);
			if (DM_STRLEN(order) == 0) {
				// Fill order only first time
				dmuci_set_value_by_section(p->dmmap_section, "order", inst);
			}

			p->creator = creator;

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP) {
				free_firewall_config_dup_list(&dup_list);
				return 0;
			}
		}
		free_firewall_config_dup_list(&dup_list);

		// Rule sections
		synchronize_firewall_sections_with_dmmap("firewall", "rule", "dmmap_firewall", false, &dup_list);
		list_for_each_entry(p, &dup_list, list) {

			inst = handle_instance(dmctx, parent_node, p->dmmap_section, "firewall_chain_rule_instance", "firewall_chain_rule_alias");

			dmuci_get_value_by_section_string(p->dmmap_section, "order", &order);
			if (DM_STRLEN(order) == 0) {
				// Fill order only first time
				dmuci_set_value_by_section(p->dmmap_section, "order", inst);
			}

			p->creator = creator;

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
				break;
		}
		free_firewall_config_dup_list(&dup_list);
	} else if (DM_STRCMP(creator, "PortMapping") == 0) {
#define UPNP_LEASE_FILE "/var/run/miniupnpd.leases"
#define UPNP_RULE_ARG_NUMBER 6
		char *pch = NULL, *spch = NULL;
		char *upnp_lease_file = NULL;
		char line[2048];
		int i = 0, idx = 0;

		dmuci_get_option_value_string("upnpd", "config", "upnp_lease_file", &upnp_lease_file);

		upnp_lease_file = DM_STRLEN(upnp_lease_file) ? upnp_lease_file : UPNP_LEASE_FILE;

		FILE *fp = fopen(upnp_lease_file, "r");
		if (fp == NULL)
			return 0;

		while (fgets(line, sizeof(line), fp) != NULL) {
			remove_new_line(line);

			if (DM_STRLEN(line) == 0)
				continue;

			// This is an example of rule:
			// TCP:45678:X.X.X.X:3000:1678270810:forward_test
			// Proto:external_port:internal_ip:internal_port:expiry_date:description
			// Number of arguments: 6
			char **dynamic_rule = dmcalloc(UPNP_RULE_ARG_NUMBER, sizeof(char *));

			for (idx = 0, pch = strtok_r(line, ":", &spch);
				 idx < UPNP_RULE_ARG_NUMBER && pch != NULL;
				 idx++, pch = strtok_r(NULL, ":", &spch)) {
				dynamic_rule[idx] = dmstrdup(pch);
			}

			p = dmcalloc(1, sizeof(struct rule_sec));
			list_add_tail(&p->list, &dup_list);

			p->is_dynamic_rule = true;
			p->dynamic_rule = dynamic_rule;
			p->creator = creator;

			inst = handle_instance_without_section(dmctx, parent_node, ++i);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
				break;
		}

		free_firewall_config_dup_list(&dup_list);
		fclose(fp);
	}

	return 0;
}

/*#Device.Firewall.DMZ.{i}.!UCI:firewall/dmz/dmmap_dmz*/
static int browseFirewallDMZInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "dmz", "dmmap_dmz", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "dmz_instance", "dmz_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseServiceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "service", "dmmap_firewall", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "service_instance", "service_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int add_firewall_rule(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *chain_args = (struct uci_section *)data;
	struct uci_section *s = NULL, *dmmap_firewall_rule = NULL;
	char creation_date[32] = {0};
	char s_name[16] = {0};
	char buf[8] = {0};
	char *creator = NULL;
	char *rule_start_pos = NULL, *rules_num = NULL;
	time_t now = time(NULL);

	dmuci_get_value_by_section_string(chain_args, "creator", &creator);
	if (DM_STRCMP(creator, "PortMapping") == 0) {
		bbfdm_set_fault_message(ctx, "This is a dynamic 'Chain' instance which is created by 'Port Mapping', so it's not permitted to add a static 'Rule'.");
		return FAULT_9003;
	}

	dmuci_get_value_by_section_string(chain_args, "rule_start_pos", &rule_start_pos);
	dmuci_get_value_by_section_string(chain_args, "rules_num", &rules_num);

	strftime(creation_date, sizeof(creation_date), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	snprintf(s_name, sizeof(s_name), "rule_%s", *instance);

	dmuci_add_section("firewall", "rule", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enabled", "0");
	dmuci_set_value_by_section(s, "target", "DROP");
	dmuci_set_value_by_section(s, "proto", "0");

	// Update rule section order
	snprintf(buf, sizeof(buf), "%lu", DM_STRTOUL(rule_start_pos) + DM_STRTOUL(rules_num));
	dmuci_reoder_section_by_section(s, buf);

	// Update rules number
	snprintf(buf, sizeof(buf), "%lu", DM_STRTOUL(rules_num) + 1);
	dmuci_set_value_by_section(chain_args, "rules_num", buf);

	dmuci_add_section_bbfdm("dmmap_firewall", "rule", &dmmap_firewall_rule);
	dmuci_set_value_by_section(dmmap_firewall_rule, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_firewall_rule, "creation_date", creation_date);
	dmuci_set_value_by_section(dmmap_firewall_rule, "firewall_chain_rule_instance", *instance);
	return 0;
}

static int delete_firewall_rule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *order = NULL, *rules_num = NULL;
	char buf[8] = {0};

	switch (del_action) {
		case DEL_INST:
			if (((struct rule_sec *)data)->is_dynamic_rule) {
				bbfdm_set_fault_message(ctx, "This is a dynamic 'Rule' instance, therefore it's not permitted to delete it.");
				return FAULT_9003;
			}

			s = get_dup_section_in_dmmap_opt("dmmap_firewall", "chain", "creator", "Defaults");
			dmuci_get_value_by_section_string(s, "rules_num", &rules_num);

			dmuci_get_value_by_section_string(((struct rule_sec *)data)->dmmap_section, "order", &order);
			update_rule_order(order, rules_num, false);

			// Update rules number
			snprintf(buf, sizeof(buf), "%lu", DM_STRTOUL(rules_num) - 1);
			dmuci_set_value_by_section(s, "rules_num", buf);

			dmuci_delete_by_section(((struct rule_sec *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct rule_sec *)data)->dmmap_section, NULL, NULL);
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

static int addObjFirewallDMZ(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char s_name[16] = {0};

	snprintf(s_name, sizeof(s_name), "dmz_%s", *instance);

	dmuci_add_section("firewall", "dmz", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enabled", "0");

	dmuci_add_section_bbfdm("dmmap_dmz", "dmz", &dmmap);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "dmz_instance", *instance);
	return 0;
}

static int delObjFirewallDMZ(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("firewall", "dmz", stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_dmz", "dmz", section_name(s), &dmmap_section);
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

static int get_firewall_service_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseServiceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_level_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (struct uci_section *)data, "firewall_level_alias", instance, value);
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
	return bbf_get_alias(ctx, (struct uci_section *)data, "firewall_chain_alias", instance, value);
}

static int get_chain_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

static int get_chain_creator(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "creator", value);
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
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "1";
	} else {
		char *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "enabled", &v);
		*value = (*v == 'n' || *v == '0' ) ? "0" : "1";
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Status!UCI:firewall/rule,@i-1/enabled*/
static int get_rule_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "Enabled";
	} else {
		char *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "enabled", &v);
		*value = (*v == 'n' || *v == '0') ? "Disabled" : "Enabled";
	}

	return 0;
}

static int get_rule_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule && DM_STRCMP(rule_args->creator, "Defaults") != 0) {
		*value = instance;
	} else {
		dmuci_get_value_by_section_string(rule_args->dmmap_section, "order", value);
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Alias!UCI:dmmap_firewall/rule,@i-1/firewall_chain_rule_alias*/
static int get_rule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (!rule_args->is_dynamic_rule)
		dmuci_get_value_by_section_string(rule_args->dmmap_section, "firewall_chain_rule_alias", value);

	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Description!UCI:firewall/rule,@i-1/name*/
static int get_rule_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = (rule_args->dynamic_rule && rule_args->dynamic_rule[5]) ? rule_args->dynamic_rule[5] : "";
	} else {
		dmuci_get_value_by_section_string(rule_args->config_section, "name", value);
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Target!UCI:firewall/rule,@i-1/target*/
static int get_rule_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "Accept";
	} else {
		char *target;

		dmuci_get_value_by_section_string(rule_args->config_section, "target", &target);
		if (DM_STRLEN(target) == 0) {
			*value = "Accept";
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
	}

    return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Log!UCI:firewall/rule,@i-1/log*/
static int get_rule_log(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "0";
	} else {
		char *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "log", &v);
		*value = (*v == '1' ) ? "1" : "0";
	}

	return 0;
}

static int get_FirewallChainRule_CreationDate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "0001-01-01T00:00:00Z";
	} else {
		*value = dmuci_get_value_by_section_fallback_def(rule_args->dmmap_section, "creation_date", "0001-01-01T00:00:00Z");
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.ExpiryDate!UCI:firewall/rule,@i-1/expiry*/
static int get_FirewallChainRule_ExpiryDate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *expiry_date = NULL;

	if (rule_args->is_dynamic_rule) {
		expiry_date = (rule_args->dynamic_rule && rule_args->dynamic_rule[4]) ? rule_args->dynamic_rule[4] : "";
	} else {
		dmuci_get_value_by_section_string(rule_args->config_section, "expiry", &expiry_date);
	}

	if (DM_STRLEN(expiry_date) != 0 && DM_STRTOL(expiry_date) > 0) {
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
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char expiry_date[16];
	struct tm tm;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_dateTime(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			strptime(value, "%Y-%m-%dT%H:%M:%SZ", &tm);
			snprintf(expiry_date, sizeof(expiry_date), "%lld", (long long)timegm(&tm));
			dmuci_set_value_by_section(rule_args->config_section, "expiry", expiry_date);
			break;
	}
	return 0;
}

static int get_rule_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *src = NULL;

	if (rule_args->is_dynamic_rule) {
		dmuci_get_option_value_string("upnpd", "config", "internal_iface", &src);
	} else {
		char *ifaceobj = NULL, src_iface[256] = {0};
		struct uci_list *net_list = NULL;

		dmuci_get_value_by_section_string(rule_args->config_section, "src", &src);
		if (src == NULL || *src == '\0')
			return 0;

		if (DM_LSTRCMP(src, "*") == 0) {
			dmuci_get_value_by_section_string(rule_args->dmmap_section, "src", &src);
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
				adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", e->name, &ifaceobj);
				if (ifaceobj && *ifaceobj)
					pos += snprintf(&src_iface[pos], sizeof(src_iface) - pos, "%s,", ifaceobj);
			}

			if (pos)
				src_iface[pos - 1] = 0;

			*value = dmstrdup(src_iface);
			return 0;
		}
	}

	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", src, value);
	return 0;
}

static int get_rule_source_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "0";
	} else {
		char *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "src", &v);
		*value = (*v == '*') ? "1" : "0";
	}

	return 0;
}

static int get_rule_dest_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *dest = NULL;

	if (rule_args->is_dynamic_rule) {
		dmuci_get_option_value_string("upnpd", "config", "external_iface", &dest);
	} else {
		char *ifaceobj = NULL, dst_iface[256] = {0};
		struct uci_list *net_list = NULL;

		dmuci_get_value_by_section_string(rule_args->config_section, "dest", &dest);
		if (dest == NULL || *dest == '\0')
			return 0;

		if (DM_LSTRCMP(dest, "*") == 0) {
			dmuci_get_value_by_section_string(rule_args->dmmap_section, "dest", &dest);
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
				adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", e->name, &ifaceobj);
				if (ifaceobj && *ifaceobj)
					pos += snprintf(&dst_iface[pos], sizeof(dst_iface) - pos, "%s,", ifaceobj);
			}

			if (pos)
				dst_iface[pos - 1] = 0;

			*value = dmstrdup(dst_iface);
			return 0;
		}
	}

	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", dest, value);
	return 0;
}

static int get_rule_dest_all_interfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "0";
	} else {
		char *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "dest", &v);
		*value = (*v == '*') ? "1" : "0";
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.IPVersion!UCI:firewall/rule,@i-1/family*/
static int get_rule_i_p_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = "-1";
	} else {
		char *ipversion;

		dmuci_get_value_by_section_string(rule_args->config_section, "family", &ipversion);
		if (strcasecmp(ipversion, "ipv4") == 0) {
			*value = "4";
		} else if (strcasecmp(ipversion, "ipv6") == 0) {
			*value = "6";
		} else {
			*value = "-1";
		}
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestIp!UCI:firewall/rule,@i-1/dest_ip*/
static int get_rule_dest_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = (rule_args->dynamic_rule && rule_args->dynamic_rule[2]) ? rule_args->dynamic_rule[2] : "";
	} else {
		char buf[64], *pch, *destip;

		dmuci_get_value_by_section_string(rule_args->config_section, "dest_ip", &destip);
		DM_STRNCPY(buf, destip, sizeof(buf));
		pch = DM_STRCHR(buf, '/');
		if (pch) *pch = '\0';
		*value = dmstrdup(buf);
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestMask!UCI:firewall/rule,@i-1/dest_ip*/
static int get_rule_dest_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *pch, *destip;

	if (rule_args->is_dynamic_rule) {
		*value = "";
		return 0;
	}

	dmuci_get_value_by_section_string(rule_args->config_section, "dest_ip", &destip);
	if (*destip == '\0')
		return 0;

	pch = DM_STRCHR(destip, '/');
	if (pch) {
		*value = destip;
	} else {
		char *family;

		dmuci_get_value_by_section_string(rule_args->config_section, "family", &family);
		dmasprintf(value, "%s/%s", destip, DM_LSTRCMP(family, "ipv6") == 0 ? "128" : "32");
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourceIp!UCI:firewall/rule,@i-1/src_ip*/
static int get_rule_source_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char buf[64], *pch, *srcip;

	if (rule_args->is_dynamic_rule) {
		*value = "";
		return 0;
	}

	dmuci_get_value_by_section_string(rule_args->config_section, "src_ip", &srcip);
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
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *pch, *srcip;

	if (rule_args->is_dynamic_rule) {
		*value = "";
		return 0;
	}

	dmuci_get_value_by_section_string(rule_args->config_section, "src_ip", &srcip);
	if (*srcip == '\0')
		return 0;

	pch = DM_STRCHR(srcip, '/');
	if (pch) {
		*value = srcip;
	} else {
		char *family;

		dmuci_get_value_by_section_string(rule_args->config_section, "family", &family);
		dmasprintf(value, "%s/%s", srcip, DM_LSTRCMP(family, "ipv6") == 0 ? "128" : "32");
	}
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.Protocol!UCI:firewall/rule,@i-1/proto*/
static int get_rule_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *proto = NULL, buf[256], protocol[32], protocol_nbr[16];

	if (rule_args->is_dynamic_rule) {
		proto = (rule_args->dynamic_rule && rule_args->dynamic_rule[0]) ? rule_args->dynamic_rule[0] : "255";
	} else {
		dmuci_get_value_by_section_string(rule_args->config_section, "proto", &proto);

		if (DM_STRLEN(proto) == 0 || strchr(proto, ' ')) {
			*value = "255";
			return 0;
		}

		if (*proto == '0' || strcmp(proto, "all") == 0) {
			*value = "-1";
			return 0;
		}
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
		if (DM_STRCASECMP(protocol, proto) == 0) {
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
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = (rule_args->dynamic_rule && rule_args->dynamic_rule[1]) ? rule_args->dynamic_rule[1] : "-1";
	} else {
		char *tmp, *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "dest_port", &v);
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
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.DestPortRangeMax!UCI:firewall/rule,@i-1/dest_port*/
static int get_rule_dest_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *tmp, *v;

	if (rule_args->is_dynamic_rule) {
		*value = "-1";
		return 0;
	}

	dmuci_get_value_by_section_string(rule_args->config_section, "dest_port", &v);
	tmp = DM_STRCHR(v, ':');
	if (tmp == NULL)
		tmp = DM_STRCHR(v, '-');
	*value = (tmp) ? tmp+1 : "-1";
	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourcePort!UCI:firewall/rule,@i-1/src_port*/
static int get_rule_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;

	if (rule_args->is_dynamic_rule) {
		*value = (rule_args->dynamic_rule && rule_args->dynamic_rule[3]) ? rule_args->dynamic_rule[3] : "-1";
	} else {
		char *tmp, *v;

		dmuci_get_value_by_section_string(rule_args->config_section, "src_port", &v);
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
	}

	return 0;
}

/*#Device.Firewall.Chain.{i}.Rule.{i}.SourcePortRangeMax!UCI:firewall/rule,@i-1/src_port*/
static int get_rule_source_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct rule_sec *rule_args = (struct rule_sec *)data;
	char *tmp, *v;

	if (rule_args->is_dynamic_rule) {
		*value = "-1";
		return 0;
	}

	dmuci_get_value_by_section_string(rule_args->config_section, "src_port", &v);
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, Config, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Advanced") != 0) {
				bbfdm_set_fault_message(ctx, "The current Firewall implementation supports only 'Advanced' config.");
				return FAULT_9007;
			}
			break;
	}
        return 0;
}

static int set_firewall_advanced_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Device.Firewall.Level.1.") != 0) {
				bbfdm_set_fault_message(ctx, "The current Firewall implementation supports only one Level. So the value should be 'Device.Firewall.Level.1'.");
				return FAULT_9007;
			}
			break;
	}
        return 0;
}

static int set_level_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (struct uci_section *)data, "firewall_level_alias", instance, value);
}

static int set_level_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_string(ctx, value, -1, -1, DefaultPolicy, NULL))
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
			if (bbfdm_validate_boolean(ctx, value))
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int set_chain_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (struct uci_section *)data, "firewall_chain_alias", instance, value);
}

static int set_chain_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "enabled", b ? "1" : "0");
			break;
	}
        return 0;
}

static int set_rule_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *rule_start_pos = NULL;
	char *rules_num = NULL;
	char *curr_order = NULL;
	char buf[8] = {0};

	s = get_dup_section_in_dmmap_opt("dmmap_firewall", "chain", "creator", "Defaults");

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_string(s, "rules_num", &rules_num);
			if (DM_STRTOUL(value) > DM_STRTOUL(rules_num)) {
				bbfdm_set_fault_message(ctx, "The order value '%s' should be lower than the greater order value '%s'.", value, rules_num);
				return FAULT_9007;
			}

			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->dmmap_section, "order", &curr_order);
			if (DM_STRTOUL(curr_order) > DM_STRTOUL(value))
				update_rule_order(value, curr_order, true);
			else
				update_rule_order(curr_order, value, false);

			dmuci_get_value_by_section_string(s, "rule_start_pos", &rule_start_pos);
			snprintf(buf, sizeof(buf), "%lu", DM_STRTOUL(rule_start_pos) + DM_STRTOUL(value) - 1);

			dmuci_reoder_section_by_section(((struct rule_sec *)data)->config_section, buf);
			dmuci_set_value_by_section(((struct rule_sec *)data)->dmmap_section, "order", value);
			break;
	}
        return 0;
}

static int set_rule_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct rule_sec *)data)->dmmap_section, "firewall_chain_rule_alias", instance, value);
}

static int set_rule_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "name", value);
			break;
	}
        return 0;
}

static int set_rule_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, Target, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Accept") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "target", "ACCEPT");
			else if (strcasecmp(value, "Reject") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "target", "REJECT");
			else if (strcasecmp(value, "Drop") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "target", "DROP");
			else if (strcasecmp(value, "Return") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "target", "MARK");
			break;
	}
        return 0;
}

static int set_rule_log(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "log", b ? "1" : "");
			break;
	}
        return 0;
}

static int set_rule_interface(struct dmctx *ctx, void *data, char *type, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};
	char *option = NULL;

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, type, &option);

			if (DM_STRLEN(reference.path) == 0) {
				dmuci_set_value_by_section((option && DM_LSTRCMP(option, "*") == 0) ? ((struct rule_sec *)data)->dmmap_section : ((struct rule_sec *)data)->config_section, type, "");
			} else {
				if (DM_STRLEN(reference.value)) {

					// check if firewall zone exists
					if (!firewall_zone_exists(reference.value))
						firewall__create_zone_section(reference.value);

					dmuci_set_value_by_section((option && DM_LSTRCMP(option, "*") == 0) ? ((struct rule_sec *)data)->dmmap_section : ((struct rule_sec *)data)->config_section, type, reference.value);
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				// Get the current 'src' option
				dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "src", &src);

				// Save 'src' option in the associated dmmap rule section
				dmuci_set_value_by_section(((struct rule_sec *)data)->dmmap_section, "src", src);

				// Set the current 'src' option
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "src", "*");
			} else {
				// Get 'src' option from the associated dmmap rule section
				dmuci_get_value_by_section_string(((struct rule_sec *)data)->dmmap_section, "src", &src);

				// Set the current 'src' option
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "src", src);
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
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				// Get the current 'dest' option
				dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "dest", &dest);

				// Save 'dest' option in the associated dmmap rule section
				dmuci_set_value_by_section(((struct rule_sec *)data)->dmmap_section, "dest", dest);

				// Set the current 'dest' option
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "dest", "*");
			} else {
				// Get 'dest' option from the associated dmmap rule section
				dmuci_get_value_by_section_string(((struct rule_sec *)data)->dmmap_section, "dest", &dest);

				// Set the current 'dest' option
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "dest", dest);
			}
			break;
	}
	return 0;
}

static int set_rule_i_p_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","15"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (DM_LSTRCMP(value, "4") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "family", "ipv4");
			else if (DM_LSTRCMP(value, "6") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "family", "ipv6");
			else if (DM_LSTRCMP(value, "-1") == 0)
				dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "family", "");
			break;
	}
        return 0;
}

static int set_rule_dest_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[64], *pch, *destip;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "dest_ip", &destip);
			DM_STRNCPY(buf, destip, sizeof(buf));
			pch = DM_STRCHR(buf, '/');
			if (pch)
				snprintf(new, sizeof(new), "%s%s", value, pch);
			else
				DM_STRNCPY(new, value, sizeof(new));
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "dest_ip", new);
			break;
	}
    return 0;
}

static int set_rule_dest_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char new[64], *pch, *destip;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 49, NULL, IPPrefix))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "dest_ip", &destip);
			pch = DM_STRCHR(destip, '/');
			if (pch)
				*pch = '\0';

			pch = DM_STRCHR(value, '/');
			if (pch == NULL)
				return 0;

			snprintf(new, sizeof(new), "%s%s", destip, pch);
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "dest_ip", new);
			break;
	}
        return 0;
}

static int set_rule_source_ip(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[64], new[64], *pch, *srcip;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "src_ip", &srcip);
			DM_STRNCPY(buf, srcip, sizeof(buf));
			pch = DM_STRCHR(buf, '/');
			if (pch)
				snprintf(new, sizeof(new), "%s%s", value, pch);
			else
				DM_STRNCPY(new, value, sizeof(new));
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "src_ip", new);
			break;
	}
        return 0;
}

static int set_rule_source_mask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char new[64], *pch, *srcip;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 49, NULL, IPPrefix))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "src_ip", &srcip);
			pch = DM_STRCHR(srcip, '/');
			if (pch)
				*pch = '\0';

			pch = DM_STRCHR(value, '/');
			if (pch == NULL)
				return 0;

			snprintf(new, sizeof(new), "%s%s", srcip, pch);
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "src_ip", new);
			break;
	}
        return 0;
}

static int set_rule_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "proto", (*value == '-') ? "0" : value);
			break;
	}
        return 0;
}

static int set_rule_dest_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buffer[64], *v, *tmp = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (*value == '-')
				value = "";
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "dest_port", &v);
			tmp = DM_STRCHR(v, ':');
			if (tmp == NULL)
				tmp = DM_STRCHR(v, '-');
			if (tmp == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, tmp);
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "dest_port", buffer);
			break;
	}
        return 0;
}

static int set_rule_dest_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *v, *tmp, *buf, buffer[64];

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "dest_port", &v);
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
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "dest_port", buffer);
			break;
	}
	return 0;
}

static int set_rule_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buffer[64], *v, *tmp = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (*value == '-')
				value = "";
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "src_port", &v);
			tmp = DM_STRCHR(v, ':');
			if (tmp == NULL)
				tmp = DM_STRCHR(v, '-');
			if (tmp == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, tmp);
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "src_port", buffer);
			break;
	}
    return 0;
}

static int set_rule_source_port_range_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *v, *tmp, *buf, buffer[64];

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct rule_sec *)data)->config_section, "src_port", &v);
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
			dmuci_set_value_by_section(((struct rule_sec *)data)->config_section, "src_port", buffer);
			break;
	}
	return 0;
}

static int get_firewall_dmz_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseFirewallDMZInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Firewall.DMZ.{i}.Alias!UCI:dmmap_dmz/DMZ,@i-1/alias*/
static int get_FirewallDMZ_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "dmz_alias", instance, value);
}

static int set_FirewallDMZ_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "dmz_alias", instance, value);
}

/*#Device.Firewall.DMZ.{i}.Enable!UCI:firewall/dmz,@i-1/enabled*/
static int get_FirewallDMZ_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "0");
	return 0;
}

static int set_FirewallDMZ_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b = 0;

	switch (action) {
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

/*#Device.Firewall.DMZ.{i}.Status!UCI:firewall/dmz,@i-1/status*/
static int get_FirewallDMZ_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *dmz_args = (struct dmmap_dup *)data;
	char *v, *destip, *interface;

	dmuci_get_value_by_section_string(dmz_args->config_section, "interface", &interface);
	dmuci_get_value_by_section_string(dmz_args->config_section, "dest_ip", &destip);
	if (DM_STRLEN(destip) == 0 || DM_STRLEN(interface) == 0) {
		*value = "Error_Misconfigured";
		return 0;
	}

	dmuci_get_value_by_section_string(dmz_args->config_section, "enabled", &v);
	*value = (dmuci_string_to_boolean(v)) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.Firewall.DMZ.{i}.Origin!UCI:firewall/dmz,@i-1/origin*/
static int get_FirewallDMZ_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "origin", "Controller");
	return 0;
}

static int set_FirewallDMZ_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *Origin[] = {"User", "System", "Controller", NULL};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, Origin, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "origin", value);
			break;
	}
	return 0;
}

/*#Device.Firewall.DMZ.{i}.Description!UCI:firewall/dmz,@i-1/description*/
static int get_FirewallDMZ_Description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "description", value);
	return 0;
}

static int set_FirewallDMZ_Description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "description", value);
			break;
	}
	return 0;
}

/*#Device.Firewall.DMZ.{i}.Interface!UCI:firewall/dmz,@i-1/interface*/
static int get_FirewallDMZ_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *interf = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface", &interf);

	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", interf, value);
	return 0;
}

static int set_FirewallDMZ_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "interface", reference.value);
			break;
	}
	return 0;
}

/*#Device.Firewall.DMZ.{i}.DestIP!UCI:firewall/dmz,@i-1/dest_ip*/
static int get_FirewallDMZ_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "dest_ip", value);
	return 0;
}

static int set_FirewallDMZ_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_ip", value);
			break;
	}
	return 0;
}

/*#Device.Firewall.DMZ.{i}.SourcePrefix!UCI:firewall/dmz,@i-1/source_prefix*/
static int get_FirewallDMZ_SourcePrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "source_prefix", value);
	return 0;
}

static int set_FirewallDMZ_SourcePrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 18, NULL, IPv4Prefix))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "source_prefix", value);
			break;
	}
	return 0;
}

static int get_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "service_alias", instance, value);
}

static int set_service_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "service_alias", instance, value);
}

static int get_service_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enable", "0");
	return 0;
}

static int set_service_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "enable", b ? "1" : "0");
			break;
	}

	return 0;
}

static int get_service_intf(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *intf = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "interface", &intf);

	if (intf == NULL || *intf == '\0')
		return 0;

	adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", intf, value);

	return 0;
}

static int set_service_intf(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			if (DM_STRLEN(reference.value)) {
				// check if firewall zone exists
				if (!firewall_zone_exists(reference.value))
					firewall__create_zone_section(reference.value);

				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "interface", reference.value);
			}
			break;
	}

	return 0;
}

static int get_service_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val = NULL;
	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "dest_port", &val);
	*value = dmuci_list_to_string(val, ",");
	return 0;
}

static int set_service_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length, i;
	char **arr;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int_list(ctx, value, 1, 65537, 0, RANGE_ARGS{{"-1", "65535"}},1))
				return FAULT_9007;

			break;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_port", "");
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "dest_port", arr[i]);
			break;
	}

	return 0;
}

static int get_service_ipver(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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

static int set_service_ipver(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","15"}}, 1))
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

static int get_service_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val = NULL;
	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "proto", &val);
	*value = dmuci_list_to_string(val, ",");
	return 0;
}

static int set_service_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length, i;
	char **arr;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int_list(ctx, value, 1, 257, 0, RANGE_ARGS{{"-1", "255"}},1))
				return FAULT_9007;

			break;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "proto", "");
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "proto", arr[i]);
			break;
	}

	return 0;
}

static int get_service_icmp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "icmp_type", value);
	return 0;
}

static int set_service_icmp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "icmp_type", value);
			break;
	}
        return 0;
}

static int get_service_src_prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val = NULL;
	dmuci_get_value_by_section_list(((struct dmmap_dup *)data)->config_section, "src_prefix", &val);
	*value = dmuci_list_to_string(val, ",");
	return 0;
}

static int set_service_src_prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length, i;
	char **arr = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, -1, -1, 49, NULL, IPPrefix))
				return FAULT_9007;
			break;
		case VALUESET:
			arr = strsplit(value, ",", &length);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "src_prefix", "");
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct dmmap_dup *)data)->config_section, "src_prefix", arr[i]);
			break;
	}
        return 0;
}

static int get_service_action(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "target", value);
	return 0;
}

static int set_service_action(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_params[] = {"Drop", "Accept", "Reject", NULL};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, allowed_params, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "target", value);
			break;
	}
        return 0;
}

static int get_service_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *enable = NULL, *intf = NULL;

	get_service_enable(refparam, ctx, data, instance, &enable);

	if (DM_STRCMP(enable, "1") != 0) {
		*value = "Disabled";
		return 0;
	}

	get_service_intf(refparam, ctx, data, instance, &intf);

	if (DM_STRLEN(intf) == 0) {
		*value = "Error_Misconfigured";
		return 0;
	}

	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "status", "Enabled");

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Firewall. *** */
DMOBJ tFirewallObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Level", &DMREAD, NULL, NULL, NULL, browseLevelInst, NULL, NULL, NULL, tFirewallLevelParams, NULL, BBFDM_BOTH, NULL},
{"Chain", &DMREAD, NULL, NULL, NULL, browseChainInst, NULL, NULL, tFirewallChainObj, tFirewallChainParams, NULL, BBFDM_BOTH, NULL},
{"DMZ", &DMWRITE, addObjFirewallDMZ, delObjFirewallDMZ, NULL, browseFirewallDMZInst, NULL, NULL, NULL, tFirewallDMZParams, NULL, BBFDM_BOTH, NULL},
{"Service", &DMWRITE, addService, delService, NULL, browseServiceInst, NULL, NULL, NULL, tFirewallServiceParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tFirewallParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_firewall_enable, set_firewall_enable, BBFDM_BOTH},
{"Config", &DMWRITE, DMT_STRING, get_firewall_config, set_firewall_config, BBFDM_BOTH},
{"AdvancedLevel", &DMWRITE, DMT_STRING, get_firewall_advanced_level, set_firewall_advanced_level, BBFDM_BOTH},
{"LevelNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_level_number_of_entries, NULL, BBFDM_BOTH},
{"ChainNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_chain_number_of_entries, NULL, BBFDM_BOTH},
{"DMZNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_dmz_number_of_entries, NULL, BBFDM_BOTH},
{"ServiceNumberOfEntries", &DMREAD, DMT_UNINT, get_firewall_service_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.Level.{i}. *** */
DMLEAF tFirewallLevelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_level_alias, set_level_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMWRITE, DMT_STRING, get_level_name, set_level_name, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Description", &DMWRITE, DMT_STRING, get_level_description, set_level_description, BBFDM_BOTH},
{"Chain", &DMREAD, DMT_STRING, get_level_chain, NULL, BBFDM_BOTH},
{"PortMappingEnabled", &DMWRITE, DMT_BOOL, get_level_port_mapping_enabled, set_level_port_mapping_enabled, BBFDM_BOTH},
{"DefaultPolicy", &DMWRITE, DMT_STRING, get_level_default_policy, set_level_default_policy, BBFDM_BOTH},
{"DefaultLogPolicy", &DMWRITE, DMT_BOOL, get_level_default_log_policy, set_level_default_log_policy, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.Chain.{i}. *** */
DMOBJ tFirewallChainObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Rule", &DMWRITE, add_firewall_rule, delete_firewall_rule, NULL, browseRuleInst, NULL, NULL, NULL, tFirewallChainRuleParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tFirewallChainParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_chain_enable, set_chain_enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_chain_alias, set_chain_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMWRITE, DMT_STRING, get_chain_name, set_chain_name, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Creator", &DMREAD, DMT_STRING, get_chain_creator, NULL, BBFDM_BOTH},
{"RuleNumberOfEntries", &DMREAD, DMT_UNINT, get_chain_rule_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.Chain.{i}.Rule.{i}. *** */
DMLEAF tFirewallChainRuleParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMRule, DMT_BOOL, get_rule_enable, set_rule_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_rule_status, NULL, BBFDM_BOTH},
{"Order", &DMRule, DMT_UNINT, get_rule_order, set_rule_order, BBFDM_BOTH},
{"Alias", &DMRule, DMT_STRING, get_rule_alias, set_rule_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Description", &DMRule, DMT_STRING, get_rule_description, set_rule_description, BBFDM_BOTH},
{"Target", &DMRule, DMT_STRING, get_rule_target, set_rule_target, BBFDM_BOTH},
//{"TargetChain", &DMRule, DMT_STRING, get_rule_target_chain, set_rule_target_chain, BBFDM_BOTH},
{"Log", &DMRule, DMT_BOOL, get_rule_log, set_rule_log, BBFDM_BOTH},
{"CreationDate", &DMREAD, DMT_TIME, get_FirewallChainRule_CreationDate, NULL, BBFDM_BOTH},
{"ExpiryDate", &DMRule, DMT_TIME, get_FirewallChainRule_ExpiryDate, set_FirewallChainRule_ExpiryDate, BBFDM_BOTH},
{"SourceInterface", &DMRule, DMT_STRING, get_rule_source_interface, set_rule_source_interface, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"SourceAllInterfaces", &DMRule, DMT_BOOL, get_rule_source_all_interfaces, set_rule_source_all_interfaces, BBFDM_BOTH},
{"DestInterface", &DMRule, DMT_STRING, get_rule_dest_interface, set_rule_dest_interface, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"DestAllInterfaces", &DMRule, DMT_BOOL, get_rule_dest_all_interfaces, set_rule_dest_all_interfaces, BBFDM_BOTH},
{"IPVersion", &DMRule, DMT_INT, get_rule_i_p_version, set_rule_i_p_version, BBFDM_BOTH},
{"DestIP", &DMRule, DMT_STRING, get_rule_dest_ip, set_rule_dest_ip, BBFDM_BOTH},
{"DestMask", &DMRule, DMT_STRING, get_rule_dest_mask, set_rule_dest_mask, BBFDM_BOTH},
{"SourceIP", &DMRule, DMT_STRING, get_rule_source_ip, set_rule_source_ip, BBFDM_BOTH},
{"SourceMask", &DMRule, DMT_STRING, get_rule_source_mask, set_rule_source_mask, BBFDM_BOTH},
{"Protocol", &DMRule, DMT_INT, get_rule_protocol, set_rule_protocol, BBFDM_BOTH},
{"DestPort", &DMRule, DMT_INT, get_rule_dest_port, set_rule_dest_port, BBFDM_BOTH},
{"DestPortRangeMax", &DMRule, DMT_INT, get_rule_dest_port_range_max, set_rule_dest_port_range_max, BBFDM_BOTH},
{"SourcePort", &DMRule, DMT_INT, get_rule_source_port, set_rule_source_port, BBFDM_BOTH},
{"SourcePortRangeMax", &DMRule, DMT_INT, get_rule_source_port_range_max, set_rule_source_port_range_max, BBFDM_BOTH},
{0}
};

/* *** Device.Firewall.DMZ.{i}. *** */
DMLEAF tFirewallDMZParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version */
{"Alias", &DMWRITE, DMT_STRING, get_FirewallDMZ_Alias, set_FirewallDMZ_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Enable", &DMWRITE, DMT_BOOL, get_FirewallDMZ_Enable, set_FirewallDMZ_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_FirewallDMZ_Status, NULL, BBFDM_BOTH},
{"Origin", &DMWRITE, DMT_STRING, get_FirewallDMZ_Origin, set_FirewallDMZ_Origin, BBFDM_BOTH},
{"Description", &DMWRITE, DMT_STRING, get_FirewallDMZ_Description, set_FirewallDMZ_Description, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_FirewallDMZ_Interface, set_FirewallDMZ_Interface, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"DestIP", &DMWRITE, DMT_STRING, get_FirewallDMZ_DestIP, set_FirewallDMZ_DestIP, BBFDM_BOTH},
{"SourcePrefix", &DMWRITE, DMT_STRING, get_FirewallDMZ_SourcePrefix, set_FirewallDMZ_SourcePrefix, BBFDM_BOTH, DM_FLAG_UNIQUE},
{0}
};

/* *** Device.Firewall.Service.{i}. *** */
DMLEAF tFirewallServiceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_service_alias, set_service_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Enable", &DMWRITE, DMT_BOOL, get_service_enable, set_service_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_service_status, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_service_intf, set_service_intf, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"DestPort", &DMWRITE, DMT_STRING, get_service_port, set_service_port, BBFDM_BOTH},
{"IPVersion", &DMWRITE, DMT_INT, get_service_ipver, set_service_ipver, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_service_protocol, set_service_protocol, BBFDM_BOTH},
{"ICMPType", &DMWRITE, DMT_INT, get_service_icmp, set_service_icmp, BBFDM_BOTH},
{"SourcePrefixes", &DMWRITE, DMT_STRING, get_service_src_prefix, set_service_src_prefix, BBFDM_BOTH},
{"Action", &DMWRITE, DMT_STRING, get_service_action, set_service_action, BBFDM_BOTH},
{0}
};
