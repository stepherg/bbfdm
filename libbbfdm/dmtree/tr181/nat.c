/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "nat.h"

static int get_nat_port_mapping_external_port_end_range(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.NAT.InterfaceSetting.{i}.!UCI:firewall/zone/dmmap_firewall*/
static int browseInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dm_data *curr_data = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "zone", "dmmap_firewall", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "interface_setting_instance", "interface_setting_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.NAT.PortMapping.{i}.!UCI:firewall/redirect/dmmap_firewall*/
static int browsePortMappingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *target = NULL;
	struct dm_data *curr_data = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "redirect", "dmmap_firewall", &dup_list);

	list_for_each_entry(curr_data, &dup_list, list) {
		dmuci_get_value_by_section_string(curr_data->config_section, "target", &target);
		if (*target != '\0' && DM_LSTRCMP(target, "DNAT") != 0)
			continue;

		/*
		 * Add port range end in dmmap section if needed
		 */
		char *src_dport = NULL;
		dmuci_get_value_by_section_string(curr_data->config_section, "src_dport", &src_dport);
		if (DM_STRLEN(src_dport) != 0) {
			char *tmp = DM_STRCHR(src_dport, '-');
			if (tmp)
				dmuci_set_value_by_section(curr_data->dmmap_section, "src_dport_end", tmp + 1);
		}

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "port_mapping_instance", "port_mapping_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)curr_data, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_NAT_InterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_firewall = NULL;
	char zone_name[16] = {0};
	char name[16] = {0};

	snprintf(zone_name, sizeof(zone_name), "zone_iface_%s", *instance);
	snprintf(name, sizeof(name), "iface_%s", *instance);

	dmuci_add_section("firewall", "zone", &s);
	dmuci_rename_section_by_section(s, zone_name);
	dmuci_set_value_by_section(s, "input", "REJECT");
	dmuci_set_value_by_section(s, "output", "ACCEPT");
	dmuci_set_value_by_section(s, "forward", "REJECT");
	dmuci_set_value_by_section(s, "name", name);

	dmuci_add_section_bbfdm("dmmap_firewall", "zone", &dmmap_firewall);
	dmuci_set_value_by_section(dmmap_firewall, "section_name", zone_name);
	dmuci_set_value_by_section(dmmap_firewall, "interface_setting_instance", *instance);
	return 0;
}

static int delete_NAT_InterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dm_data *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dm_data *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("firewall", "zone", stmp, s) {
				struct uci_section *dmmap_firewall = NULL;

				get_dmmap_section_of_config_section("dmmap_firewall", "zone", section_name(s), &dmmap_firewall);
				dmuci_delete_by_section(dmmap_firewall, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int add_NAT_PortMapping(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_firewall = NULL;
	char s_name[32];

	snprintf(s_name, sizeof(s_name), "port_map_%s", *instance);

	dmuci_add_section("firewall", "redirect", &s);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "target", "DNAT");
	dmuci_set_value_by_section(s, "enabled", "0");
	dmuci_set_value_by_section(s, "proto", "tcp");

	dmuci_add_section_bbfdm("dmmap_firewall", "redirect", &dmmap_firewall);
	dmuci_set_value_by_section(dmmap_firewall, "section_name", s_name);
	dmuci_set_value_by_section(dmmap_firewall, "port_mapping_instance", *instance);
	dmuci_set_value_by_section(dmmap_firewall, "enabled", "0");
	return 0;
}

static int delete_NAT_PortMapping(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dm_data *)data)->config_section, NULL, NULL);
			dmuci_delete_by_section(((struct dm_data *)data)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("firewall", "redirect", stmp, s) {
				struct uci_section *dmmap_firewall = NULL;

				get_dmmap_section_of_config_section("dmmap_firewall", "redirect", section_name(s), &dmmap_firewall);
				dmuci_delete_by_section(dmmap_firewall, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.NAT.InterfaceSettingNumberOfEntries!UCI:firewall/zone/*/
static int get_nat_interface_setting_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseInterfaceSettingInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.NAT.PortMappingNumberOfEntries!UCI:firewall/redirect/*/
static int get_nat_port_mapping_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browsePortMappingInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.NAT.InterfaceSetting.{i}.Enable!UCI:firewall/zone,@i-1/masq*/
static int get_nat_interface_setting_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "masq", &val);
	*value = (*val == '1') ? "1" : "0";
	return 0;
}

static int set_nat_interface_setting_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "masq", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.NAT.InterfaceSetting.{i}.Status!UCI:firewall/zone,@i-1/masq*/
static int get_nat_interface_setting_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "masq", &val);
	*value = (*val == '1') ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.NAT.InterfaceSetting.{i}.Alias!UCI:dmmap_firewall/zone,@i-1/interface_setting_alias*/
static int get_nat_interface_setting_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "interface_setting_alias", instance, value);
}

static int set_nat_interface_setting_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "interface_setting_alias", instance, value);
}

static int get_nat_interface_setting_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *v = NULL;
	char buf[256];
	unsigned pos = 0;

	buf[0] = 0;
	dmuci_get_value_by_section_list(((struct dm_data *)data)->config_section, "network", &v);
	if (v) {
		struct uci_element *e = NULL;
		char *ifaceobj = NULL;

		uci_foreach_element(v, e) {
			adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", e->name, &ifaceobj);
			if (ifaceobj && *ifaceobj)
				pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", ifaceobj);
		}
	}

	/* cut tailing ',' */
	if (pos)
		buf[pos - 1] = 0;

	*value = dmstrdup(buf);
	return 0;
}

static int set_nat_interface_setting_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "network", "");
			dmuci_add_list_value_by_section(((struct dm_data *)data)->config_section, "network", reference.value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Enable!UCI:firewall/redirect,@i-1/enabled*/
static int get_nat_port_mapping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->dmmap_section, "enabled", "1");
	return 0;
}

static int set_nat_port_mapping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->dmmap_section, "enabled", b ? "1" : "0");
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "enabled", b ? "1" : "0");
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Status!UCI:firewall/redirect,@i-1/enabled*/
static int get_nat_port_mapping_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_nat_port_mapping_enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Alias!UCI:dmmap_firewall/redirect,@i-1/port_mapping_alias*/
static int get_nat_port_mapping_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "port_mapping_alias", instance, value);
}

static int set_nat_port_mapping_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "port_mapping_alias", instance, value);
}

static int get_nat_port_mapping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	struct uci_list *v = NULL;
	char *zone_name = NULL, *name = NULL, *src_dip = NULL, buf[256];
	unsigned pos = 0;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "src_dip", &src_dip);
	if (src_dip && DM_LSTRCMP(src_dip, "*") == 0)
		return 0;

	buf[0] = 0;
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "src", &zone_name);
	uci_foreach_sections("firewall", "zone", s) {
		dmuci_get_value_by_section_string(s, "name", &name);
		if (zone_name && name && DM_STRCMP(zone_name, name) == 0) {
			dmuci_get_value_by_section_list(s, "network", &v);
			break;
		}
	}

	if (v) {
		struct uci_element *e = NULL;
		char *ifaceobj = NULL;

		uci_foreach_element(v, e) {
			adm_entry_get_reference_param(ctx, "Device.IP.Interface.*.Name", e->name, &ifaceobj);
			if (ifaceobj && *ifaceobj)
				pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", ifaceobj);
		}
	}

	/* cut tailing ',' */
	if (pos)
		buf[pos - 1] = 0;

	*value = dmstrdup(buf);
	return 0;
}

static int set_nat_port_mapping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			if (DM_STRLEN(reference.value)) {
				struct uci_section *s = NULL;
				bool zone_enable, sect_enable;

				uci_foreach_sections("firewall", "zone", s) {
					char *network = NULL;

					dmuci_get_value_by_section_string(s, "network", &network);
					if (is_strword_in_optionvalue(network, reference.value)) {
						char *zone_name = NULL;
						char *zone_masq = NULL;
						char *val = NULL;

						dmuci_get_value_by_section_string(s, "name", &zone_name);
						dmuci_get_value_by_section_string(s, "masq", &zone_masq);
						dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src", zone_name);

						// set this section enable parameter based on the configured zone masq value
						dmuci_get_value_by_section_string(((struct dm_data *)data)->dmmap_section, "enabled", &val);
						sect_enable = (*val == '1') ? true : false;
						zone_enable = (*zone_masq == '1') ? true : false;

						sect_enable = sect_enable && zone_enable;
						dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "enabled", sect_enable ? "1" : "0");
						break;
					}
				}
			} else {
				dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src", "");
			}
			break;
	}
	return 0;
}

static int get_nat_port_mapping_all_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *src_dip = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "src_dip", &src_dip);
	*value = (src_dip && *src_dip == '*') ? "1" : "0";
	return 0;
}

static int set_nat_port_mapping_all_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src_dip", b ? "*" : "");
			if (b) {
				dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "src", &src);
				if (src == NULL || *src == '\0')
					dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src", "wan");
			}
			break;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.LeaseDuration!UCI:firewall/redirect,@i-1/expiry*/
static int get_nat_port_mapping_lease_duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *expiry_date = NULL;

	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "expiry", &expiry_date);
	if (expiry_date && *expiry_date != '\0' && DM_STRTOL(expiry_date) > 0) {
		dmasprintf(value, "%lld", (long long)(DM_STRTOL(expiry_date) - time(NULL)));
	} else {
		*value = "0";
	}
	return 0;
}

static int set_nat_port_mapping_lease_duration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char expiry_date[16];

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (!value || DM_STRTOL(value) == 0)
				break;

			snprintf(expiry_date, sizeof(expiry_date), "%lld", (long long)(DM_STRTOL(value) + time(NULL)));
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "expiry", expiry_date);
			break;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.RemoteHost!UCI:firewall/redirect,@i-1/src_dip*/
static int get_nat_port_mapping_remote_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "src_ip", value);
	return 0;
}

static int set_nat_port_mapping_remote_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src_ip", value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.ExternalPort!UCI:firewall/redirect,@i-1/src_dport*/
static int get_nat_port_mapping_external_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *src_dport = NULL;
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "src_dport", &src_dport);
	if (src_dport && *src_dport == '\0') {
		*value = "0";
		return 0;
	}

	char *tmp = src_dport ? DM_STRCHR(src_dport, '-') : NULL;
	if (tmp)
		*tmp = '\0';
	*value = src_dport;
	return 0;
}

static int set_nat_port_mapping_external_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dport_end = NULL, buffer[64];
	uint16_t start_port, end_port;

	get_nat_port_mapping_external_port_end_range(refparam, ctx, data, instance, &dport_end);
	end_port = DM_STRTOL(dport_end);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;

			start_port = DM_STRTOL(value);
			if (start_port && end_port && start_port > end_port) {
				bbfdm_set_fault_message(ctx, "The start port value '%s' should be lower than the end port value '%s'.", value, dport_end);
				return FAULT_9007;
			}

			return 0;
		case VALUESET:
			if (strcmp(value, "0") == 0) { /* 0 means no external port */
				dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src_dport", "");
				return 0;
			}

			start_port = DM_STRTOL(value);
			if (!end_port) // if end range is 0
				snprintf(buffer, sizeof(buffer), "%d", start_port);
			else
				snprintf(buffer, sizeof(buffer), "%d-%d", start_port, end_port);

			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src_dport", buffer);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.ExternalPortEndRange!UCI:firewall/redirect,@i-1/src_dport*/
static int get_nat_port_mapping_external_port_end_range(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->dmmap_section, "src_dport_end", "0");
	return 0;
}

static int set_nat_port_mapping_external_port_end_range(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src_dport = NULL, buffer[64];
	uint16_t sport, dport;

	get_nat_port_mapping_external_port(refparam, ctx, data, instance, &src_dport);
	sport = DM_STRTOL(src_dport);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;

			dport = DM_STRTOL(value);

			// Add check to check if the endrange > src_dport
			if (dport != 0 && dport < sport) {
				bbfdm_set_fault_message(ctx, "The end port value '%s' should be greater than the start port value '%s'.", value, src_dport);
				return FAULT_9007;
			}

			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->dmmap_section, "src_dport_end", value);

			dport = DM_STRTOL(value);

			if (sport) { // if not 0
				if (dport) // if not 0
					snprintf(buffer, sizeof(buffer), "%d-%d", sport, dport);
				else
					snprintf(buffer, sizeof(buffer), "%d", sport);

				dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "src_dport", buffer);
			}

			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.InternalPort!UCI:firewall/redirect,@i-1/dest_port*/
static int get_nat_port_mapping_internal_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dm_data *)data)->config_section, "dest_port", "0");
	return 0;
}

static int set_nat_port_mapping_internal_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "dest_port", value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Protocol!UCI:firewall/redirect,@i-1/proto*/
static int get_nat_port_mapping_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto = NULL;
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "proto", &proto);
	*value = (proto && DM_LSTRCMP(proto, "udp") == 0) ? "UDP" : "TCP";
	return 0;
}

static int set_nat_port_mapping_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *NAT_Protocol[] = {"TCP", "UDP", NULL};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NAT_Protocol, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "proto", (DM_LSTRCMP(value, "UDP") == 0) ? "udp" : "tcp");
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.InternalClient!UCI:firewall/redirect,@i-1/dest_ip*/
static int get_nat_port_mapping_internal_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "dest_ip", value);
	return 0;
}

static int set_nat_port_mapping_internal_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "dest_ip", value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Description!UCI:firewall/redirect,@i-1/name*/
static int get_nat_port_mapping_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_data *)data)->config_section, "name", value);
	return 0;
}

static int set_nat_port_mapping_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_data *)data)->config_section, "name", value);
			return 0;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.NAT. *** */
DMOBJ tNATObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"InterfaceSetting", &DMWRITE, add_NAT_InterfaceSetting, delete_NAT_InterfaceSetting, NULL, browseInterfaceSettingInst, NULL, NULL, NULL, tNATInterfaceSettingParams, NULL, BBFDM_BOTH, NULL},
{"PortMapping", &DMWRITE, add_NAT_PortMapping, delete_NAT_PortMapping, NULL, browsePortMappingInst, NULL, NULL, NULL, tNATPortMappingParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tNATParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_nat_interface_setting_number_of_entries, NULL, BBFDM_BOTH},
{"PortMappingNumberOfEntries", &DMREAD, DMT_UNINT, get_nat_port_mapping_number_of_entries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.NAT.InterfaceSetting.{i}. *** */
DMLEAF tNATInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_nat_interface_setting_enable, set_nat_interface_setting_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_nat_interface_setting_status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_nat_interface_setting_alias, set_nat_interface_setting_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Interface", &DMWRITE, DMT_STRING, get_nat_interface_setting_interface, set_nat_interface_setting_interface, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_REFERENCE},
{0}
};

/* *** Device.NAT.PortMapping.{i}. *** */
DMLEAF tNATPortMappingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_nat_port_mapping_enable, set_nat_port_mapping_enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_nat_port_mapping_status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_nat_port_mapping_alias, set_nat_port_mapping_alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Interface", &DMWRITE, DMT_STRING, get_nat_port_mapping_interface, set_nat_port_mapping_interface, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"AllInterfaces", &DMWRITE, DMT_BOOL, get_nat_port_mapping_all_interface, set_nat_port_mapping_all_interface, BBFDM_BOTH},
{"LeaseDuration", &DMWRITE, DMT_UNINT, get_nat_port_mapping_lease_duration, set_nat_port_mapping_lease_duration, BBFDM_BOTH},
{"RemoteHost", &DMWRITE, DMT_STRING, get_nat_port_mapping_remote_host, set_nat_port_mapping_remote_host, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ExternalPort", &DMWRITE, DMT_UNINT, get_nat_port_mapping_external_port, set_nat_port_mapping_external_port, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"ExternalPortEndRange", &DMWRITE, DMT_UNINT, get_nat_port_mapping_external_port_end_range, set_nat_port_mapping_external_port_end_range, BBFDM_BOTH},
{"InternalPort", &DMWRITE, DMT_UNINT, get_nat_port_mapping_internal_port, set_nat_port_mapping_internal_port, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_nat_port_mapping_protocol, set_nat_port_mapping_protocol, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"InternalClient", &DMWRITE, DMT_STRING, get_nat_port_mapping_internal_client, set_nat_port_mapping_internal_client, BBFDM_BOTH},
{"Description", &DMWRITE, DMT_STRING, get_nat_port_mapping_description, set_nat_port_mapping_description, BBFDM_BOTH},
{0}
};
