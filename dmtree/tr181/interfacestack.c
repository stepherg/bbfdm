/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "ethernet.h"
#include "ip.h"
#include "interfacestack.h"

struct interfacestack_data {
	char *lowerlayer;
	char *higherlayer;
	char *loweralias;
	char *higheralias;
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
static char *get_instance_by_section(int mode, char *dmmap_config, char *section, char *option, char *value, char *instance_option, char *alias_option)
{
	struct uci_section *dmmap_section = NULL;
	char *instance = "";

	get_dmmap_section_of_config_section_eq(dmmap_config, section, option, value, &dmmap_section);

	if (mode == INSTANCE_MODE_NUMBER)
		dmuci_get_value_by_section_string(dmmap_section, instance_option, &instance);
	else
		dmuci_get_value_by_section_string(dmmap_section, alias_option, &instance);

	return instance;
}

static char *get_instance_by_section_option_condition(int mode, char *dmmap_config, char *section, struct uci_section *s, char *option, char *value, char *instance_option, char *alias_option)
{
	struct uci_section *dmmap_section = NULL;
	char *instance = "";

	get_dmmap_section_of_config_section_cont(dmmap_config, section, option, value, &dmmap_section);

	if (mode == INSTANCE_MODE_NUMBER)
		dmuci_get_value_by_section_string(dmmap_section, instance_option, &instance);
	else
		dmuci_get_value_by_section_string(dmmap_section, alias_option, &instance);

	return instance;
}

static char *get_alias_by_section(char *dmmap_config, char *section, struct uci_section *s, char *alias_option)
{
	struct uci_section *dmmap_section = NULL;
	char *alias = "";

	get_dmmap_section_of_config_section(dmmap_config, section, section_name(s), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, alias_option, &alias);
	return alias;
}

static char *get_alias_by_section_option_condition(char *dmmap_config, char *section, char *option, char *value, char *alias_option)
{
	struct uci_section *dmmap_section = NULL;
	char *alias = "";

	get_dmmap_section_of_config_section_cont(dmmap_config, section, option, value, &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, alias_option, &alias);

	return alias;
}
static struct uci_section *create_dmmap_interface_stack_section(char *curr_inst)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", curr_inst, s) {
		return s;
	}

	if (!s) {
		dmuci_add_section_bbfdm("dmmap_interface_stack", "interface_stack", &s);
		dmuci_set_value_by_section_bbfdm(s, "interface_stack_instance", curr_inst);
	}

	return s;
}

static int create_and_link_interface_stack_instance(struct dmctx *dmctx, DMNODE *parent_node, char *higherlayer, char *lowerlayer, char *higheralias, char *loweralias, int *instance)
{
	struct interfacestack_data intf_stack_data = {0};
	char buf_instance[16] = {0};

	// fill interface stack data
	intf_stack_data.higherlayer = higherlayer ? higherlayer : "";
	intf_stack_data.lowerlayer = lowerlayer ? lowerlayer : "";
	intf_stack_data.higheralias = higheralias ? higheralias : "";
	intf_stack_data.loweralias = loweralias ? loweralias : "";

	// create dmmap section
	snprintf(buf_instance, sizeof(buf_instance), "%d", ++(*instance));
	struct uci_section *dmmap_s = create_dmmap_interface_stack_section(buf_instance);

	// link instance to interface stack data
	char *inst = handle_instance(dmctx, parent_node, dmmap_s, "interface_stack_instance", "interface_stack_alias");

	if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, inst) == DM_STOP)
		return -1;

	return 0;
}

int browseInterfaceStackInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *layer_inst = "", *loweralias = "", *higheralias = "";
	char buf_lowerlayer[128] = {0};
	char buf_higherlayer[128] = {0};
	char buf_higheralias[64] = {0};
	char buf_loweralias[64] = {0};
	int instance = 0;

	/* Higher layers are Device.IP.Interface.{i}. */
	uci_foreach_sections("network", "interface", s) {
		char *proto, *device_s;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "device", &device_s);

		if (strcmp(section_name(s), "loopback") == 0 ||
			*proto == '\0' ||
			DM_STRCHR(device_s, '@') ||
			ip___is_ipinterface_exists(section_name(s), device_s))
			continue;

		// The higher layer is Device.IP.Interface.{i}.
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", "section_name", section_name(s), "ip_int_instance", "ip_int_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.IP.Interface.%s", layer_inst);

		higheralias = get_alias_by_section("dmmap_network", "interface", s, "ip_int_alias");
		snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *higheralias ? higheralias : *layer_inst ? "cpe-" : "", (*higheralias == '\0' && *layer_inst) ? layer_inst : "");

		if (DM_LSTRSTR(proto, "ppp")) {
			// The lower layer is Device.PPP.Interface.{i}.
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", "section_name", section_name(s), "ppp_int_instance", "ppp_int_alias");
			if (*layer_inst == '\0')
				continue;
			snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "Device.PPP.Interface.%s", layer_inst);
			loweralias = get_alias_by_section("dmmap_network", "interface", s, "ppp_int_alias");
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : "cpe-", (*loweralias == '\0') ? layer_inst : "");
		} else {
			// The lower layer is Device.Ethernet.VLANTermination.{i}.
			char *value = NULL;
			int found = 0;
			char *device = get_device(section_name(s));

			/* If the device value is empty, then get its value directly from device option */
			if (*device == '\0')
				dmuci_get_value_by_section_string(s, "device", &device);

			if (device[0] != '\0') {
				struct uci_section *vlan_sect = NULL;
				adm_entry_get_linker_param(dmctx, "Device.Ethernet.VLANTermination.", device, &value);
				uci_foreach_option_eq("network", "device", "name", device, vlan_sect) {
					loweralias = get_alias_by_section("dmmap_network", "device", vlan_sect, "vlan_term_alias");
					layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", "section_name", section_name(vlan_sect), "vlan_term_instance", "vlan_term_alias");
					break;
				}
				if (value != NULL)
					found = 1;
			}

			if (found == 0) {
				// The lower layer is Device.Ethernet.Link.{i}.
				char linker[32] = {0};

				if (device[0] != '\0') {
					DM_STRNCPY(linker, device, sizeof(linker));
					char *vid = DM_STRCHR(linker, '.');
					if (vid) *vid = '\0';
				} else {
					struct uci_section *ss = NULL;

					get_dmmap_section_of_config_section_eq("dmmap", "link", "section_name", section_name(s), &ss);
					dmuci_get_value_by_section_string(ss, "linker", &device);
					DM_STRNCPY(linker, device, sizeof(linker));
				}

				adm_entry_get_linker_param(dmctx, "Device.Ethernet.Link.", linker, &value);
				loweralias = get_alias_by_section_option_condition("dmmap", "link", "section_name", section_name(s), "link_alias");
				layer_inst = get_instance_by_section_option_condition(dmctx->instance_mode, "dmmap", "link", s, "section_name", section_name(s), "link_instance", "link_alias");
				if (value == NULL)
					value = "";
			}

			snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value ? value : "");
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *layer_inst ? "cpe-" : "", (*loweralias == '\0' && *layer_inst) ? layer_inst : "");
		}

		if (create_and_link_interface_stack_instance(dmctx, parent_node, buf_higherlayer, buf_lowerlayer, buf_higheralias, buf_loweralias, &instance))
			goto end;
	}

	/* Higher layers are Device.PPP.Interface.{i}. */
	uci_foreach_sections("network", "interface", s) {
		char *proto;
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (!DM_LSTRSTR(proto, "ppp"))
			continue;

		// The higher layer is Device.PPP.Interface.{i}.
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", "section_name", section_name(s), "ppp_int_instance", "ppp_int_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.PPP.Interface.%s", layer_inst);

		higheralias = get_alias_by_section("dmmap_network", "interface", s, "ppp_int_alias");
		snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *higheralias ? higheralias : *layer_inst ? "cpe-" : "", (*higheralias == '\0' && *layer_inst) ? layer_inst : "");

		char *value = NULL;
		int found = 0;
		// The lower layer is Device.Ethernet.VLANTermination.{i}.
		char *ppp_device = get_device(section_name(s));

		/* If the device value is empty, then get its value directly from device option */
		if (*ppp_device == '\0')
			dmuci_get_value_by_section_string(s, "device", &ppp_device);

		if (ppp_device[0] != '\0') {
			struct uci_section *vlan_sect = NULL;
			adm_entry_get_linker_param(dmctx, "Device.Ethernet.VLANTermination.", ppp_device, &value);
			uci_foreach_option_eq("network", "device", "name", ppp_device, vlan_sect) {
				loweralias = get_alias_by_section("dmmap_network", "device", vlan_sect, "vlan_term_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", "section_name", section_name(vlan_sect), "vlan_term_instance", "vlan_term_alias");
				break;
			}
			if (value != NULL)
				found = 1;
		}

		if (found == 0) {
			// The lower layer is Device.Ethernet.Link.{i}.
			char linker[32] = {0};
			DM_STRNCPY(linker, ppp_device, sizeof(linker));
			char *vid = DM_STRCHR(linker, '.');
			if (vid) *vid = '\0';
			adm_entry_get_linker_param(dmctx, "Device.Ethernet.Link.", linker, &value);
			loweralias = get_alias_by_section("dmmap", "link", s, "link_alias");
			layer_inst = get_instance_by_section_option_condition(dmctx->instance_mode, "dmmap", "link", s, "section_name", section_name(s), "link_instance", "link_alias");
			if (value == NULL)
				value = "";
		}

		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value);
		snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *layer_inst ? "cpe-" : "", (*loweralias == '\0' && *layer_inst) ? layer_inst : "");

		if (create_and_link_interface_stack_instance(dmctx, parent_node, buf_higherlayer, buf_lowerlayer, buf_higheralias, buf_loweralias, &instance))
			goto end;
	}

	/* Higher layers are Device.Ethernet.VLANTermination.{i}. */
	uci_foreach_sections("network", "device", s) {
		struct uci_section *dmmap_section = NULL;
		char *type, *name, *ifname, *is_vlan, *value = NULL;

		get_dmmap_section_of_config_section("dmmap_network", "device", section_name(s), &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "is_vlan_ter", &is_vlan);

		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "name", &name);
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (DM_LSTRCMP(type, "bridge") == 0 ||
			(*name == 0 && DM_LSTRCMP(is_vlan, "1") != 0) ||
			(*name != 0 && !ethernet___check_vlan_termination_section(name)))
			continue;

		// The higher layer is Device.Ethernet.VLANTermination.{i}.
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", "section_name", section_name(s), "vlan_term_instance", "vlan_term_alias");
		if (*layer_inst == '\0')
			continue;

		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.Ethernet.VLANTermination.%s", layer_inst);

		higheralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
		snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *higheralias ? higheralias : *layer_inst ? "cpe-" : "", (*higheralias == '\0' && *layer_inst) ? layer_inst : "");

		// The lower layer can be Device.Ethernet.VLANTermination.{i}. or Device.Ethernet.Link.{i}.
		if (DM_LSTRNCMP(type, "8021ad", 6) == 0) {
			// The lower layer is Device.Ethernet.VLANTermination.{i}.
			struct uci_section *vlan_sect = NULL;

			adm_entry_get_linker_param(dmctx, "Device.Ethernet.VLANTermination.", ifname, &value);

			uci_foreach_option_eq("network", "device", "name", ifname, vlan_sect) {
				loweralias = get_alias_by_section("dmmap_network", "device", vlan_sect, "vlan_term_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", "section_name", section_name(vlan_sect), "vlan_term_instance", "vlan_term_alias");
				break;
			}
		} else {
			// The lower layer is Device.Ethernet.Link.{i}.
			struct uci_section *link_s = NULL;
			bool is_ifname = false;

			adm_entry_get_linker_param(dmctx, "Device.Ethernet.Link.", name, &value);
			if (!value || *value == 0) {
				is_ifname = true;
				adm_entry_get_linker_param(dmctx, "Device.Ethernet.Link.", ifname, &value);
			}

			get_dmmap_section_of_config_section_eq("dmmap", "link", "device", is_ifname ? ifname : name, &link_s);
			dmuci_get_value_by_section_string(link_s, "link_instance", &layer_inst);
			dmuci_get_value_by_section_string(link_s, "link_alias", &loweralias);
		}

		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value ? value : "");
		snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *layer_inst ? "cpe-" : "", (*loweralias == '\0' && *layer_inst) ? layer_inst : "");

		if (create_and_link_interface_stack_instance(dmctx, parent_node, buf_higherlayer, buf_lowerlayer, buf_higheralias, buf_loweralias, &instance))
			goto end;
	}

	/* Higher layers are Device.Ethernet.Link.{i}. */
	uci_path_foreach_sections(bbfdm, "dmmap_ethernet", "link", s) {

		// The higher layer is Device.Ethernet.Link.{i}.
		dmuci_get_value_by_section_string(s, "link_instance", &layer_inst);
		if (*layer_inst == '\0')
			continue;

		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.Ethernet.Link.%s", layer_inst);

		dmuci_get_value_by_section_string(s, "link_alias", &higheralias);
		snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *higheralias ? higheralias : *layer_inst ? "cpe-" : "", (*higheralias == '\0' && *layer_inst) ? layer_inst : "");

		char *linker, *value = NULL, *device_s_type = NULL;

		dmuci_get_value_by_section_string(s, "device", &linker);
		struct uci_section *br_device_s = ethernet___get_device_section(linker);
		if (br_device_s) dmuci_get_value_by_section_string(br_device_s, "type", &device_s_type);

		if (br_device_s && DM_LSTRCMP(device_s_type, "bridge") == 0) {
			// The lower layer is Device.Bridging.Bridge.{i}.Port.{i}.
			struct uci_section *port = get_dup_section_in_dmmap_opt("dmmap_bridge_port", "bridge_port", "port", linker);
			if (port != NULL) {
				adm_entry_get_linker_param(dmctx, "Device.Bridging.Bridge.", linker, &value);
				dmuci_get_value_by_section_string(port, "bridge_port_alias", &loweralias);
				dmuci_get_value_by_section_string(port, "bridge_port_instance", &layer_inst);
			}
		} else {
			// The lower layer is Device.Ethernet.Interface.{i}.
			char *vid = DM_STRCHR(linker, '.');
			if (vid) *vid = '\0';
			char *macvlan = DM_STRCHR(linker, '_');
			if (macvlan)
				*macvlan = '\0';
			struct uci_section *eth_port_sect = NULL, *eth_port_dmms = NULL;
			uci_foreach_option_eq("ports", "ethport", "ifname", linker, eth_port_sect) {
				break;
			}
			if (eth_port_sect != NULL) {
				get_dmmap_section_of_config_section_eq("dmmap_ports", "ethport", "section_name", section_name(eth_port_sect), &eth_port_dmms);
				if (eth_port_dmms) {
					dmuci_get_value_by_section_string(eth_port_dmms, "eth_port_alias", &loweralias);
					dmuci_get_value_by_section_string(eth_port_dmms, "eth_port_instance", &layer_inst);
				}
			}
			adm_entry_get_linker_param(dmctx, "Device.Ethernet.Interface.", linker, &value);
		}

		if (value == NULL)
			value = "";

		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value);
		snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *layer_inst ? "cpe-" : "", (*loweralias == '\0' && *layer_inst) ? layer_inst : "");

		if (create_and_link_interface_stack_instance(dmctx, parent_node, buf_higherlayer, buf_lowerlayer, buf_higheralias, buf_loweralias, &instance))
			goto end;
	}

	/* Higher layers are Device.Bridging.Bridge.{i}.Port.{i}.*/
	uci_path_foreach_sections(bbfdm, "dmmap_bridge", "device", s) {
		char *br_inst = NULL;

		dmuci_get_value_by_section_string(s, "bridge_instance", &br_inst);

		if (br_inst && *br_inst == '\0')
			continue;

		// The higher layer is Device.Bridging.Bridge.{i}.Port.{i}.
		char *bridge_port_inst, *mg_value = NULL,*value = NULL;
		char buf_mngr[64] = {0};
		struct uci_section *port = NULL;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port) {
			char *mg = NULL;

			dmuci_get_value_by_section_string(port, "management", &mg);
			if (DM_LSTRCMP(mg, "1") == 0) {
				char *device = NULL;

				dmuci_get_value_by_section_string(port, "port", &device);

				adm_entry_get_linker_param(dmctx, "Device.Bridging.Bridge.", device, &mg_value);
				dmuci_get_value_by_section_string(port, "bridge_port_alias", &higheralias);
				dmuci_get_value_by_section_string(port, "bridge_port_instance", &bridge_port_inst);

				snprintf(buf_mngr, sizeof(buf_mngr), "%s%s", *higheralias ? higheralias : *bridge_port_inst ? "cpe-" : "", (*higheralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");
				break;
			}
		}

		struct uci_section *sd = NULL;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, sd) {
			char *mg = NULL, *vb = NULL, *device = NULL;
			dmuci_get_value_by_section_string(sd, "management", &mg);
			if (DM_LSTRCMP(mg, "1") == 0)
				continue;

			dmuci_get_value_by_section_string(sd, "port", &device);

			// The lower layer is Device.Bridging.Bridge.{i}.Port.{i}.
			adm_entry_get_linker_param(dmctx, "Device.Bridging.Bridge.", section_name(sd), &vb);
			dmuci_get_value_by_section_string(sd, "bridge_port_alias", &loweralias);
			dmuci_get_value_by_section_string(sd, "bridge_port_instance", &bridge_port_inst);

			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

			if (create_and_link_interface_stack_instance(dmctx, parent_node, mg_value, vb, buf_mngr, buf_loweralias, &instance))
				goto end;

			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

			char package[32] = {0};
			int found = 0;
			// The lower layer is Device.Ethernet.Interface.{i}.
			adm_entry_get_linker_param(dmctx, "Device.Ethernet.Interface.", device, &value);
			if (value != NULL) {
				DM_STRNCPY(package, "ports", sizeof(package));
				struct uci_section *port_s = NULL;
				uci_foreach_option_eq("ports", "ethport", "ifname", device, port_s) {
					loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", "section_name", section_name(port_s), "eth_port_instance", "eth_port_alias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.WiFi.SSID.{i}.
			if (!found && value == NULL)
				adm_entry_get_linker_param(dmctx, "Device.WiFi.SSID.", device, &value);

			if (!found && value != NULL) {
				DM_STRNCPY(package, "wireless", sizeof(package));
				struct uci_section *wl_s = NULL;
				uci_foreach_option_eq("wireless", "wifi-iface", "ifname", device, wl_s) {
					loweralias = get_alias_by_section("dmmap_wireless", "wifi-iface", wl_s, "ssidalias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_wireless", "wifi-iface", "section_name", section_name(wl_s), "ssidinstance", "ssidalias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.ATM.Link.{i}.
			if (!found && value == NULL) {
				char *tag = DM_STRCHR(device, '.');
				if (tag) *tag = '\0';
				adm_entry_get_linker_param(dmctx, "Device.ATM.Link.", device, &value);
			}

			if (!found && value != NULL) {
				DM_STRNCPY(package, "dsl:atm", sizeof(package));
				struct uci_section *dsl_s = NULL;
				uci_foreach_option_eq("dsl", "atm-device", "device", device, dsl_s) {
					loweralias = get_alias_by_section("dmmap_dsl", "atm-device", dsl_s, "atmlinkalias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_dsl", "atm-device", "section_name", section_name(dsl_s), "atmlinkinstance", "atmlinkalias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.PTM.Link.{i}.
			if (!found && value == NULL) {
				char *tag = DM_STRCHR(device, '.');
				if (tag) *tag = '\0';
				adm_entry_get_linker_param(dmctx, "Device.PTM.Link.", device, &value);
			}

			if (!found && value != NULL) {
				DM_STRNCPY(package, "dsl:ptm", sizeof(package));
				struct uci_section *dsl_s = NULL;
				uci_foreach_option_eq("dsl", "ptm-device", "device", device, dsl_s) {
					loweralias = get_alias_by_section("dmmap_dsl", "ptm-device", dsl_s, "ptmlinkalias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_dsl", "ptm-device", "section_name", section_name(dsl_s), "ptmlinkinstance", "ptmlinkalias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.Ethernet.Interface.{i}.
			if (!found && value == NULL) {
				char *tag = DM_STRCHR(device, '.');
				if (tag) *tag = '\0';
				adm_entry_get_linker_param(dmctx, "Device.Ethernet.Interface.", device, &value);
			}

			if (!found && value != NULL) {
				DM_STRNCPY(package, "ports", sizeof(package));
				struct uci_section *port_s = NULL;
				uci_foreach_option_eq("ports", "ethport", "ifname", device, port_s) {
					loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", "section_name", section_name(port_s), "eth_port_instance", "eth_port_alias");
					break;
				}
			}

			if (value == NULL)
				value = "";

			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

			if (create_and_link_interface_stack_instance(dmctx, parent_node, vb, value, buf_higheralias, buf_loweralias, &instance))
				goto end;

			// The lower layer is Device.WiFi.Radio.{i}.
			if(DM_LSTRCMP(package, "wireless") == 0) {

				snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

				struct uci_section *wl_s = NULL;
				char *wl_device = NULL;
				uci_foreach_option_eq("wireless", "wifi-iface", "ifname", device, wl_s) {
					dmuci_get_value_by_section_string(wl_s, "device", &wl_device);
					break;
				}

				if (wl_device && wl_device[0] != '\0') {
					adm_entry_get_linker_param(dmctx, "Device.WiFi.Radio.", wl_device, &vb);
					struct uci_section *ss = NULL;
					uci_foreach_sections("wireless", "wifi-device", ss) {
						if(strcmp(section_name(ss), wl_device) == 0) {
							loweralias = get_alias_by_section("dmmap_wireless", "wifi-device", ss, "radioalias");
							bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_wireless", "wifi-device", "section_name", section_name(ss), "radioinstance", "radioalias");
							break;
						}
					}
				}

				if (vb == NULL)
					vb = "";

				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

				if (create_and_link_interface_stack_instance(dmctx, parent_node, value, vb, buf_higheralias, buf_loweralias, &instance))
					goto end;
			}

			// The lower layer is Device.DSL.Channel.{i}.
			if(DM_LSTRCMP(package, "dsl:atm") == 0) {

				snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

				char *link_channel = "channel_1";
				adm_entry_get_linker_param(dmctx, "Device.DSL.Channel.", link_channel, &vb);
				if (vb == NULL)
					vb = "";

				struct uci_section *dsl_s = NULL;
				uci_path_foreach_sections(bbfdm, "dmmap", "dsl_channel", dsl_s) {
					dmuci_get_value_by_section_string(dsl_s, "dsl_channel_alias", &loweralias);
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "dsl_channel", "section_name", section_name(dsl_s), "dsl_channel_instance", "dsl_channel_alias");
				}

				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

				if (create_and_link_interface_stack_instance(dmctx, parent_node, value, vb, buf_higheralias, buf_loweralias, &instance))
					goto end;
			}

			// The lower layer is Device.DSL.Line.{i}.
			if(DM_LSTRCMP(package, "dsl:ptm") == 0) {

				snprintf(buf_higheralias, sizeof(buf_higheralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

				char *link_line = "line_1";
				adm_entry_get_linker_param(dmctx, "Device.DSL.Line.", link_line, &value);
				if (value == NULL)
					value = "";

				struct uci_section *dsl_s = NULL;
				uci_path_foreach_sections(bbfdm, "dmmap", "dsl_line", dsl_s) {
					dmuci_get_value_by_section_string(dsl_s, "dsl_line_alias", &loweralias);
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "dsl_line", "id", "1", "dsl_line_instance", "dsl_line_alias");
				}

				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s%s", *loweralias ? loweralias : *bridge_port_inst ? "cpe-" : "", (*loweralias == '\0' && *bridge_port_inst) ? bridge_port_inst : "");

				if (create_and_link_interface_stack_instance(dmctx, parent_node, vb, value, buf_higheralias, buf_loweralias, &instance))
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
	struct uci_section *s = NULL;
	uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", instance, s) {
		dmuci_get_value_by_section_string(s, "interface_stack_alias", value);
		if ((*value)[0] == '\0')
			dmasprintf(value, "cpe-%s", instance);
	}
	return 0;
}

static int set_InterfaceStack_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			// cppcheck-suppress unknownMacro
			uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", instance, s)
				dmuci_set_value_by_section(s, "interface_stack_alias", value);
			break;
	}
	return 0;
}

static int get_InterfaceStack_HigherLayer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->higherlayer);
	return 0;
}

static int get_InterfaceStack_LowerLayer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->lowerlayer);
	return 0;
}

static int get_InterfaceStack_HigherAlias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->higheralias);
	return 0;
}

static int get_InterfaceStack_LowerAlias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->loweralias);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.InterfaceStack.{i}. *** */
DMLEAF tInterfaceStackParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING, get_InterfaceStack_Alias, set_InterfaceStack_Alias, BBFDM_BOTH, "2.3"},
{"HigherLayer", &DMREAD, DMT_STRING, get_InterfaceStack_HigherLayer, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayer", &DMREAD, DMT_STRING, get_InterfaceStack_LowerLayer, NULL, BBFDM_BOTH, "2.0"},
{"HigherAlias", &DMREAD, DMT_STRING, get_InterfaceStack_HigherAlias, NULL, BBFDM_BOTH, "2.0"},
{"LowerAlias", &DMREAD, DMT_STRING, get_InterfaceStack_LowerAlias, NULL, BBFDM_BOTH, "2.0"},
{0}
};
