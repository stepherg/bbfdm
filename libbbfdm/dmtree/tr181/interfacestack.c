/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#include "interfacestack.h"

struct interfacestack_data
{
	char *HigherLayer;
	char *LowerLayer;
	char *HigherAlias;
	char *LowerAlias;
};

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static struct uci_section *get_bridge_management_port_section(char *instance)
{
	struct uci_section *s = NULL;
	char *management = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", instance, s) {

		dmuci_get_value_by_section_string(s, "management", &management);
		if (DM_STRCMP(management, "1") == 0)
			return s;
	}

	return NULL;
}

static char *get_lower_alias_value(const char *path)
{
	struct uci_section *s = NULL;
	char *alias_value = "";

	if (DM_STRLEN(path) == 0)
		return "";

	char *instance = DM_STRRCHR(path, '.');
	if (!instance)
		return "";

	if (DM_STRNCMP(path, "Device.IP.Interface.", strlen("Device.IP.Interface.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_network", "interface", "ip_int_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "ip_int_alias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.Ethernet.Link.", strlen("Device.Ethernet.Link.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_ethernet", "link", "link_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "link_alias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.Ethernet.Interface.", strlen("Device.Ethernet.Interface.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_ethernet", "device", "eth_iface_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "eth_iface_alias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.Bridging.Bridge.", strlen("Device.Bridging.Bridge.")) == 0 ||
			DM_STRNCMP(path, "Device.GRE.Tunnel.", strlen("Device.GRE.Tunnel.")) == 0) {
		regmatch_t pmatch[1] = {0};
		char first_inst[8] = {0};
		char *second_inst = NULL;

		bool res = match(path, "([0-9]+)", 1, pmatch);
		if (res) {
			DM_STRNCPY(first_inst, &path[pmatch[0].rm_so], pmatch[0].rm_eo - pmatch[0].rm_so + 1);
			if (DM_STRLEN(first_inst) == 0)
				return "";

			if (DM_STRNCMP(path, "Device.Bridging.Bridge.", strlen("Device.Bridging.Bridge.")) == 0) {
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", first_inst, s) {
					dmuci_get_value_by_section_string(s, "bridge_port_instance", &second_inst);
					if (DM_STRCMP(second_inst, instance + 1) == 0) {
						dmuci_get_value_by_section_string(s, "bridge_port_alias", &alias_value);
						break;
					}
				}
			} else if (DM_STRNCMP(path, "Device.GRE.Tunnel.", strlen("Device.GRE.Tunnel.")) == 0) {
				uci_path_foreach_option_eq(bbfdm, "dmmap_gre", "interface", "tunnel_instance", first_inst, s) {
					dmuci_get_value_by_section_string(s, "gre_iface_instance", &second_inst);
					if (DM_STRCMP(second_inst, instance + 1) == 0) {
						dmuci_get_value_by_section_string(s, "gre_iface_alias", &alias_value);
						break;
					}
				}
			}
		}
	} else if (DM_STRNCMP(path, "Device.WiFi.SSID.", strlen("Device.WiFi.SSID.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_wireless", "ssid", "ssid_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "ssid_alias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.WiFi.Radio.", strlen("Device.WiFi.Radio.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_wireless", "wifi-device", "radioinstance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "radioalias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.Ethernet.VLANTermination.", strlen("Device.Ethernet.VLANTermination.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_network", "device", "vlan_term_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "vlan_term_alias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.PPP.Interface.", strlen("Device.PPP.Interface.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_ppp", "interface", "ppp_int_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "ppp_int_alias", &alias_value);
	} else if (DM_STRNCMP(path, "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN.", strlen("Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN.")) == 0) {
		get_dmmap_section_of_config_section_eq("dmmap_network", "device", "mac_vlan_instance", instance + 1, &s);
		dmuci_get_value_by_section_string(s, "mac_vlan_alias", &alias_value);
	}

	return alias_value;
}

static int create_interface_stack_instance(struct dmctx *dmctx, DMNODE *parent_node,
		struct interfacestack_data *data, struct uci_section *s,
		char *path, char *inst_number, char *inst_alias, int *curr_inst)
{
	struct dm_data curr_data = {0};
	char *instance = NULL, *inst = NULL;
	char *LowerLayer = NULL;

	if (!s || !data || !path || !inst_number || !inst_alias)
		goto end;

	dmuci_get_value_by_section_string(s, inst_number, &instance);
	if (DM_STRLEN(instance) == 0)
		goto end;

	dmasprintf(&data->HigherLayer, "%s%s", path, instance);
	dmuci_get_value_by_section_string(s, inst_alias, &data->HigherAlias);
	dmuci_get_value_by_section_string(s, "LowerLayers", &LowerLayer);

	data->LowerLayer = get_value_by_reference(dmctx, LowerLayer);
	data->LowerAlias = get_lower_alias_value(data->LowerLayer);

	inst = handle_instance_without_section(dmctx, parent_node, ++(*curr_inst));

	curr_data.additional_data = (void *)data;

	if (DM_LINK_INST_OBJ(dmctx, parent_node, &curr_data, inst) == DM_STOP)
		return -1;

end:
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
int browseInterfaceStackInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct interfacestack_data curr_interfacestack_data = {0};
	struct uci_section *s = NULL;
	int idx = 0;

	/* Higher Layer is Device.IP.Interface.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_network", "interface", s) {

		if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, s,
				"Device.IP.Interface.", "ip_int_instance", "ip_int_alias", &idx))
			goto end;
	}

	/* Higher Layer is Device.GRE.Tunnel.{i}.Interface.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_gre", "interface", s) {
		char *tunnel_inst = NULL;
		char path[128] = {0};

		dmuci_get_value_by_section_string(s, "tunnel_instance", &tunnel_inst);

		snprintf(path, sizeof(path), "Device.GRE.Tunnel.%s.Interface.", tunnel_inst);

		if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, s,
				path, "gre_iface_instance", "gre_iface_alias", &idx))
			goto end;
	}

	/* Higher Layer is Device.PPP.Interface.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_ppp", "interface", s) {

		if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, s,
				"Device.PPP.Interface.", "ppp_int_instance", "ppp_int_alias", &idx))
			goto end;
	}

	/* Higher Layer is Device.Ethernet.X_IOPSYS_EU_MACVLAN.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_network", "device", s) {

		if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, s,
				"Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN.", "mac_vlan_instance", "mac_vlan_alias", &idx))
			goto end;
	}

	/* Higher Layer is Device.Ethernet.VLANTermination.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_network", "device", s) {

		if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, s,
				"Device.Ethernet.VLANTermination.", "vlan_term_instance", "vlan_term_alias", &idx))
			goto end;
	}

	/* Higher Layer is Device.Ethernet.Link.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_ethernet", "link", s) {

		if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, s,
				"Device.Ethernet.Link.", "link_instance", "link_alias", &idx))
			goto end;
	}

	/* Higher Layer is Device.Bridging.Bridge.{i}.Port.{i}.*/
	uci_path_foreach_sections(bbfdm, "dmmap_bridge", "device", s) {
		struct uci_section *port_s = NULL;
		char *br_instance = NULL;
		char *mg_port_instnace = NULL;
		char *mg_port_alias = NULL;
		char *inst = NULL;

		dmuci_get_value_by_section_string(s, "bridge_instance", &br_instance);
		if (DM_STRLEN(br_instance) == 0)
			continue;

		struct uci_section *mg_port_s = get_bridge_management_port_section(br_instance);
		if (!mg_port_s)
			continue;

		dmuci_get_value_by_section_string(mg_port_s, "bridge_port_instance", &mg_port_instnace);
		dmuci_get_value_by_section_string(mg_port_s, "bridge_port_alias", &mg_port_alias);

		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_instance, port_s) {
			struct dm_data curr_data = {0};
			char *management = NULL;
			char *instance_value = NULL;
			char *alias_value = NULL;
			char *config = NULL;
			char path[128] = {0};

			dmuci_get_value_by_section_string(port_s, "management", &management);
			if (DM_STRCMP(management, "1") == 0)
				continue;

			dmuci_get_value_by_section_string(port_s, "bridge_port_instance", &instance_value);
			dmuci_get_value_by_section_string(port_s, "bridge_port_alias", &alias_value);

			dmasprintf(&curr_interfacestack_data.HigherLayer, "Device.Bridging.Bridge.%s.Port.%s", br_instance, mg_port_instnace);
			curr_interfacestack_data.HigherAlias = mg_port_alias;
			dmasprintf(&curr_interfacestack_data.LowerLayer, "Device.Bridging.Bridge.%s.Port.%s", br_instance, instance_value);
			curr_interfacestack_data.LowerAlias = alias_value;

			inst = handle_instance_without_section(dmctx, parent_node, ++idx);
			curr_data.additional_data = (void *)&curr_interfacestack_data;
			if (DM_LINK_INST_OBJ(dmctx, parent_node, &curr_data, inst) == DM_STOP)
				goto end;

			/* Higher Layer is Device.Bridging.Bridge.{i}.Port.{i}.*/
			snprintf(path, sizeof(path), "Device.Bridging.Bridge.%s.Port.", br_instance);

			if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, port_s,
					path, "bridge_port_instance", "bridge_port_alias", &idx))
				goto end;

			/* Higher Layer is Device.WiFi.SSID.{i}.*/
			dmuci_get_value_by_section_string(port_s, "config", &config);
			if (DM_STRCMP(config, "wireless") == 0) {
				struct uci_section *wl_s = NULL;
				char *port = NULL;

				dmuci_get_value_by_section_string(port_s, "port", &port);
				wl_s = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", port);
				wl_s = get_dup_section_in_dmmap_opt("dmmap_wireless", "ssid", "ap_section_name", section_name(wl_s));

				if (create_interface_stack_instance(dmctx, parent_node, &curr_interfacestack_data, wl_s,
						"Device.WiFi.SSID.", "ssid_instance", "ssid_alias", &idx))
					goto end;
			}
		}
	}

end:
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_InterfaceStack_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_InterfaceStack_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return 0;
}

static int get_InterfaceStack_HigherLayer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct interfacestack_data *)((struct dm_data *)data)->additional_data)->HigherLayer;
	return 0;
}

static int get_InterfaceStack_LowerLayer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct interfacestack_data *)((struct dm_data *)data)->additional_data)->LowerLayer;
	return 0;
}

static int get_InterfaceStack_HigherAlias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct interfacestack_data *)((struct dm_data *)data)->additional_data)->HigherAlias;
	return 0;
}

static int get_InterfaceStack_LowerAlias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct interfacestack_data *)((struct dm_data *)data)->additional_data)->LowerAlias;
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.InterfaceStack.{i}. *** */
DMLEAF tInterfaceStackParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_InterfaceStack_Alias, set_InterfaceStack_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"HigherLayer", &DMREAD, DMT_STRING, get_InterfaceStack_HigherLayer, NULL, BBFDM_BOTH},
{"LowerLayer", &DMREAD, DMT_STRING, get_InterfaceStack_LowerLayer, NULL, BBFDM_BOTH},
{"HigherAlias", &DMREAD, DMT_STRING, get_InterfaceStack_HigherAlias, NULL, BBFDM_BOTH},
{"LowerAlias", &DMREAD, DMT_STRING, get_InterfaceStack_LowerAlias, NULL, BBFDM_BOTH},
{0}
};
