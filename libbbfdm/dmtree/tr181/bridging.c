/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "dmlayer.h"
#include "bridging.h"

struct bridge_args
{
	struct uci_section *bridge_sec;
	struct uci_section *bridge_dmmap_sec;
	char *br_inst;
};

struct bridge_vlanport_args
{
	struct uci_section *bridge_sec;
	struct uci_section *bridge_dmmap_sec;
	struct uci_section *bridge_vlanport_sec;
	struct uci_section *bridge_vlanport_dmmap_sec;
	char *br_inst;
};

struct bridge_vlan_args
{
	struct uci_section *bridge_sec;
	struct uci_section *bridge_dmmap_sec;
	struct uci_section *bridge_vlan_sec;
	char *br_inst;
};

struct provider_bridge_args
{
	struct uci_section *provider_bridge_sec;
	char *pr_br_inst;
};

/**************************************************************************
* INIT FUNCTIONS
***************************************************************************/
static inline int init_bridging_args(struct bridge_args *args, struct uci_section *br_s, struct uci_section *br_dmmap_s, char *br_inst)
{
	args->bridge_sec = br_s;
	args->bridge_dmmap_sec = br_dmmap_s;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_port_args(struct bridge_port_args *args, struct uci_section *br_s, struct uci_section *br_dmmap_s, struct uci_section *port_s, struct uci_section *port_dmmap_s, bool is_mng_port, char *br_inst)
{
	args->bridge_sec = br_s;
	args->bridge_dmmap_sec = br_dmmap_s;
	args->bridge_port_sec = port_s;
	args->bridge_port_dmmap_sec = port_dmmap_s;
	args->is_management_port = is_mng_port;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_vlanport_args(struct bridge_vlanport_args *args, struct uci_section *br_s, struct uci_section *br_dmmap_s, struct uci_section *vlanport_s, struct uci_section *vlanport_dmmap_s, char *br_inst)
{
	args->bridge_sec = br_s;
	args->bridge_dmmap_sec = br_dmmap_s;
	args->bridge_vlanport_sec = vlanport_s;
	args->bridge_vlanport_dmmap_sec = vlanport_dmmap_s;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_vlan_args(struct bridge_vlan_args *args, struct uci_section *br_s, struct uci_section *br_dmmap_s, struct uci_section *vlan_s, char *br_inst)
{
	args->bridge_sec = br_s;
	args->bridge_dmmap_sec = br_dmmap_s;
	args->bridge_vlan_sec = vlan_s;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_provider_bridge_args(struct provider_bridge_args *args, struct uci_section *pr_br_s, char *pr_br_inst)
{
	args->provider_bridge_sec = pr_br_s;
	args->pr_br_inst = pr_br_inst;
	return 0;
}

/**************************************************************************
* COMMON FUNCTIONS
***************************************************************************/
static unsigned long bridging_get_new_vid(char *br_instance)
{
	struct uci_section *s = NULL;
	unsigned long max = 0;
	char *vid = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_instance, s) {
		dmuci_get_value_by_section_string(s, "vid", &vid);
		unsigned long vid_tol = DM_STRTOL(vid);
		if (vid_tol > max)
			max = vid_tol;
	}

	return max + 1;
}

static void remove_device_from_bridge_interface(struct uci_section *br_sec)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *device = NULL;

	if (!br_sec)
		return;

	dmuci_get_value_by_section_string(br_sec, "name", &device);
	if (DM_STRLEN(device) == 0 )
		return;

	uci_foreach_option_eq_safe("network", "interface", "device", device, stmp, s) {
		char *proto = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_delete_by_section(s, (proto && *proto == 0) ? NULL : "device", NULL);
		break;
	}
}

static void add_port_to_bridge_sections(struct uci_section *br_sec, struct uci_section *br_dmmap_sec, char *device_port)
{
	struct uci_list *uci_list = NULL;

	if (DM_STRLEN(device_port) == 0)
		return;

	if (br_sec) {
		dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
		if (!value_exists_in_uci_list(uci_list, device_port))
			dmuci_add_list_value_by_section(br_sec, "ports", device_port);
	}

	if (br_dmmap_sec) {
		dmuci_get_value_by_section_list(br_dmmap_sec, "ports", &uci_list);
		if (!value_exists_in_uci_list(uci_list, device_port))
			dmuci_add_list_value_by_section(br_dmmap_sec, "ports", device_port);
	}
}

static void remove_port_from_bridge_sections(struct uci_section *br_sec, struct uci_section *br_dmmap_sec, char *device_port)
{
	struct uci_list *uci_list = NULL;

	if (DM_STRLEN(device_port) == 0)
		return;

	if (br_sec) {
		dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
		if (value_exists_in_uci_list(uci_list, device_port))
			dmuci_del_list_value_by_section(br_sec, "ports", device_port);
	}

	if (br_dmmap_sec) {
		dmuci_get_value_by_section_list(br_dmmap_sec, "ports", &uci_list);
		if (value_exists_in_uci_list(uci_list, device_port))
			dmuci_del_list_value_by_section(br_dmmap_sec, "ports", device_port);
	}
}

static void set_Provider_bridge_component(char *refparam, struct dmctx *ctx, void *data, char *instance, char *linker, char *component)
{
	/* *value=Device.Bridging.Bridge.{i}.
	 * In file dmmap_provider_bridge set "option svlan_br_inst {i}" or "list cvlan_br_inst {i}" in this(refered "provider_bridge" section)
	 */
	struct uci_section *s = NULL, *tmp_s = NULL, *dmmap_bridge_section = NULL;
	struct uci_section *network_bridge_sec_from = NULL, *network_bridge_sec_to = NULL;
	char pr_br_sec_name[64] = {0};
	char *br_sec_name = NULL;

	if (DM_STRLEN(linker) == 0) // Linker should be like "bridge-X"
		return;

	char *br_inst = DM_STRCHR(linker, '-'); // Get bridge instance 'X' which is linker from Name parameter 'bridge-X'
	if (!br_inst)
		return;

	// section name of bridge in network file
	snprintf(pr_br_sec_name, sizeof(pr_br_sec_name), "pr_br_%s", instance);

	/*
	 * check if provider bridge instance of this provider bridge is present in network uci file
	 * if present add candidate bridge to this provider bridge instance.
	 * if not present, create a provider bridge instance in network uci file,
	 * i.e. just update the candidate bridge section name to pr_br_{i} | {i} = instance of provider bridge
	 */
	uci_foreach_option_eq("network", "device", "type", "bridge", s) {
		if (strcmp(pr_br_sec_name, section_name(s)) == 0) {
			network_bridge_sec_to = s;
			break;
		}
	}

	if (DM_LSTRCMP(component, "CVLAN") == 0) {
		// Set svlan_br_inst in dmmap_provider_bridge->provider_bridge section

		dmuci_add_list_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "cvlan_br_inst", br_inst + 1);
	} else if (DM_LSTRCMP(component, "SVLAN") == 0) {
		// Set svlan_br_inst in dmmap_provider_bridgei->provider_bridge section

		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "svlan_br_inst", br_inst + 1);
	}

	/* Add candidate bridge to this provider bridge instance(network->device->pr_br_{i}) */
	// Get network->device(bridge) section name from dmmap_bridge_port->bridge_port->device_section_name
	dmmap_bridge_section = get_dup_section_in_dmmap_opt("dmmap_bridge", "device", "bridge_instance", br_inst + 1);
	dmuci_get_value_by_section_string(dmmap_bridge_section, "section_name", &br_sec_name);

	if (!dmmap_bridge_section || DM_STRLEN(br_sec_name) == 0)
		return;

	// Find the network->device(candidate bridge) section
	network_bridge_sec_from = get_origin_section_from_config("network", "device", br_sec_name);
	if (!network_bridge_sec_from)
		return;

	if (DM_LSTRCMP(component, "SVLAN") == 0) {
		struct uci_list *uci_list = NULL;
		struct uci_element *e = NULL;

		dmuci_get_value_by_section_list(network_bridge_sec_from, "ports", &uci_list);
		if (uci_list != NULL) {
			uci_foreach_element(uci_list, e) {
				char *dev_ifname = NULL;

				s = get_dup_section_in_config_opt("network", "device", "name", e->name);
				if (s == NULL)
					continue;

				if (dmuci_is_option_value_empty(s, "type"))
					continue;

				dmuci_get_value_by_section_string(s, "ifname", &dev_ifname);
				if (DM_STRLEN(dev_ifname) == 0)
					continue;

				uci_foreach_option_eq_safe("network", "device", "type", "bridge", tmp_s, s) {
					struct uci_list *br_list = NULL;
					struct uci_element *br_e = NULL;

					dmuci_get_value_by_section_list(s, "ports", &br_list);
					if (br_list == NULL)
						continue;

					uci_foreach_element(br_list, br_e) {
						if (DM_STRCMP(dev_ifname, br_e->name) == 0) {
							struct uci_section *dev_s = NULL;
							char *dev_name = NULL;

							dmuci_get_value_by_section_string(s, "name", &dev_name);

							dev_s = get_dup_section_in_config_opt("network", "interface", "device", dev_name);
							dmuci_delete_by_section(dev_s, NULL, NULL);

							dmuci_delete_by_section(s, NULL, NULL);
							break;
						}
					}
				}
			}
		}
	}

	if (network_bridge_sec_to) {
		/*
		 * The provider bridge secion has already been created(as a result of previous call to this function) in network uci file.
		 * Just need to find config section of candidate bridge and add it to the existing provider bridge configuration.
		 * And delete the candidate bridge section from network uci file.
		 *
		 */
		char *dev_name = NULL;
		dmuci_get_value_by_section_string(network_bridge_sec_from, "name", &dev_name);
		s = get_dup_section_in_config_opt("network", "interface", "device", dev_name);

		// Append ports from candidate bridge to provider bridge instance in network uci
		struct uci_list *ports_list = NULL;
		dmuci_get_value_by_section_list(network_bridge_sec_from, "ports", &ports_list);
		if (ports_list != NULL) {
			struct uci_element *e = NULL;
			uci_foreach_element(ports_list, e) {
				dmuci_add_list_value_by_section(network_bridge_sec_to, "ports", e->name);
			}
		}

		// Delete the candidate bridge config from network uci file.
		dmuci_delete_by_section(network_bridge_sec_from, NULL, NULL);
		dmuci_delete_by_section(s, NULL, NULL);
	} else {
		/*
		 * This is the first vlan component of this provider bridge instance.
		 * Need to create a porvider bridge instance in network uci file.
		 * To create a new provider bridge instance just rename candidate bridge config section name to pr_br_{i}
		 *
		 */

		// Rename network->device(bridge) section as pr_br_{i}
		dmuci_rename_section_by_section(network_bridge_sec_from, pr_br_sec_name);

		// Add option section_name to dmmap provider bridge section
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "section_name", pr_br_sec_name);
	}
}

static void synchronize_bridge_config_sections_with_dmmap_bridge_eq(char *package, char *section_type, char *dmmap_package, char *option_name, char *option_value, struct list_head *dup_list)
{
	struct uci_section *s = NULL, *dmmap_sect = NULL;

	uci_foreach_option_eq(package, section_type, option_name, option_value, s) {

		// Skip Provider Bridge sections
		if (strncmp(section_name(s), "pr_br_", 6) == 0)
			continue;

		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, "device", section_name(s))) == NULL) {
			struct uci_list *ports_list = NULL;

			dmuci_add_section_bbfdm(dmmap_package, "device", &dmmap_sect);
			dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));

			dmuci_get_value_by_section_list(s, "ports", &ports_list);
			if (ports_list != NULL) {
				struct uci_element *e = NULL;

				uci_foreach_element(ports_list, e) {
					dmuci_add_list_value_by_section(dmmap_sect, "ports", e->name);
				}
			}
		}
	}

	/*
	 * Add system and dmmap sections to the list
	 */
	uci_path_foreach_sections(bbfdm, dmmap_package, "device", dmmap_sect) {
		char *section_name = NULL;

		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &section_name);
		struct uci_section *origin_s = get_origin_section_from_config(package, section_type, section_name);
		add_dmmap_config_dup_list(dup_list, origin_s, dmmap_sect);
	}
}

static bool is_bridge_section_exist(char *device)
{
	struct uci_section *s = NULL;

	if (DM_STRLEN(device) == 0)
		return false;

	uci_path_foreach_sections(bbfdm, "dmmap_bridge", "device", s) {
		struct uci_list *ports_list = NULL;
		struct uci_element *e = NULL;

		dmuci_get_value_by_section_list(s, "ports", &ports_list);
		if (ports_list == NULL)
			continue;

		uci_foreach_element(ports_list, e) {
			if (DM_STRCMP(e->name, device) == 0)
				return true;
		}
	}

	return false;
}

static int get_last_instance_bridge(char *package, char *section, char *opt_inst)
{
	struct uci_section *s;
	int inst = 0;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		char *opt_val = NULL;

		dmuci_get_value_by_section_string(s, opt_inst, &opt_val);
		if (DM_STRLEN(opt_val) != 0 && DM_STRTOL(opt_val) > inst)
			inst = DM_STRTOL(opt_val);
	}

	return inst;
}

static char *create_dmmap_bridge_section(char *port)
{
	struct uci_section *dmmap_br_sec = NULL;
	char bridge_name[64] = {0};
	char *current_inst = NULL;

	int last_inst_dmmap = get_last_instance_bridge("dmmap_bridge", "device", "bridge_instance");
	dmasprintf(&current_inst, "%d", (last_inst_dmmap == 0) ? 1 : last_inst_dmmap+1);
	snprintf(bridge_name, sizeof(bridge_name), "dev_br%d", (last_inst_dmmap == 0) ? 1 : last_inst_dmmap+1);

	dmuci_add_section_bbfdm("dmmap_bridge", "device", &dmmap_br_sec);
	dmuci_set_value_by_section(dmmap_br_sec, "section_name", bridge_name);
	dmuci_set_value_by_section(dmmap_br_sec, "bridge_instance", current_inst);
	dmuci_add_list_value_by_section(dmmap_br_sec, "ports", port);

	return current_inst;
}

static void dmmap_synchronizeBridgingProviderBridge(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "device", "type", "bridge", s) {
		struct uci_section *dmmap_pr_br_sec = NULL;
		struct uci_list *ports_list = NULL;
		struct uci_element *e = NULL;
		char current_inst[16] = {0};

		if (strncmp(section_name(s), "pr_br_", 6) != 0)
			continue;

		if ((dmmap_pr_br_sec = get_dup_section_in_dmmap("dmmap_provider_bridge", "provider_bridge", section_name(s))) != NULL)
			continue;

		int last_inst_dmmap = get_last_instance_bridge("dmmap_provider_bridge", "provider_bridge", "provider_bridge_instance");
		dmuci_add_section_bbfdm("dmmap_provider_bridge", "provider_bridge", &dmmap_pr_br_sec);
		snprintf(current_inst, sizeof(current_inst), "%d", (last_inst_dmmap == 0) ? 1 : last_inst_dmmap+1);
		dmuci_set_value_by_section(dmmap_pr_br_sec, "provider_bridge_instance", current_inst);
		dmuci_set_value_by_section(dmmap_pr_br_sec, "section_name", section_name(s));
		dmuci_set_value_by_section(dmmap_pr_br_sec, "enable", "1");

		dmuci_get_value_by_section_list(s, "ports", &ports_list);
		if (ports_list == NULL)
			continue;

		uci_foreach_element(ports_list, e) {
			struct uci_section *ss = NULL;
			bool found = false;

			uci_foreach_option_eq("network", "device", "name", e->name, ss) {
				char *type = NULL;

				found = true;
				dmuci_get_value_by_section_string(ss, "type", &type);

				// If type is 8021ad, add to svlan
				if (DM_LSTRCMP(type,"8021ad") == 0 && !is_bridge_section_exist(e->name)) {
					char *ifname = NULL;

					dmuci_get_value_by_section_string(ss, "ifname", &ifname);
					create_dmmap_bridge_section(ifname);

					// Create device bridge dmmap section
					char *svlan_br_inst = create_dmmap_bridge_section(e->name);

					// Add svlan instance to provider bridge
					dmuci_set_value_by_section(dmmap_pr_br_sec, "svlan_br_inst", svlan_br_inst);
				}

				// If type is 8021q, add to cvlan
				if (DM_LSTRCMP(type,"8021q") == 0 && !is_bridge_section_exist(e->name)) {

					// Create device bridge dmmap section
					char *cvlan_br_inst = create_dmmap_bridge_section(e->name);

					// Add cvlan instance to provider bridge
					dmuci_add_list_value_by_section(dmmap_pr_br_sec, "cvlan_br_inst", cvlan_br_inst);
				}
			}

			if (!found) {
				// Create device bridge dmmap section
				char *cvlan_br_inst = create_dmmap_bridge_section(e->name);

				// Add cvlan instance to provider bridge
				dmuci_add_list_value_by_section(dmmap_pr_br_sec, "cvlan_br_inst", cvlan_br_inst);
			}
		}
	}
}

static void dmmap_synchronizeBridgingBridgeVLAN(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_list *br_ports_list = NULL;
	struct uci_element *e = NULL;

	if (!args->bridge_sec)
		return;

	dmuci_get_value_by_section_list(args->bridge_sec, "ports", &br_ports_list);
	if (!br_ports_list)
		return;

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user = NULL;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (DM_LSTRCMP(s_user, "1") == 0)
			continue;

		// vid is available in ports list ==> skip it
		char *vid = NULL;
		bool vid_found = false;

		dmuci_get_value_by_section_string(s, "vid", &vid);
		uci_foreach_element(br_ports_list, e) {
			if (DM_STRSTR(e->name, vid)) {
				vid_found = true;
				break;
			}
		}

		if (vid_found)
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_element(br_ports_list, e) {
		char *lower_layer = NULL;

		s = get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "port", e->name);
		dmuci_get_value_by_section_string(s, "LowerLayers", &lower_layer);

		if (!s || DM_STRNCMP(lower_layer, "Device.Bridging.Bridge.", strlen("Device.Bridging.Bridge.")) == 0)
			continue;

		uci_foreach_option_eq("network", "device", "name", e->name, s) {
			struct uci_section *br_vlan_s = NULL;
			char *vid = NULL;

			if (dmuci_is_option_value_empty(s, "type"))
				continue;

			dmuci_get_value_by_section_string(s, "vid", &vid);

			if (DM_STRLEN(vid) == 0) {
				char *ifname = (!ethernet___get_ethernet_interface_section(e->name)) ? DM_STRRCHR(e->name, '.') : NULL;
				if (ifname) vid = dmstrdup(ifname+1);
			}

			if (DM_STRLEN(vid) == 0)
				break;

			if (get_section_in_dmmap_with_options_eq("dmmap_bridge_vlan", "bridge_vlan", "br_inst", args->br_inst, "vid", vid))
				break;

			// Create a new VLAN instance
			dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &br_vlan_s);
			dmuci_set_value_by_section(br_vlan_s, "vid", vid);
			dmuci_set_value_by_section(br_vlan_s, "br_inst", args->br_inst);
		}

	}
}

static void dmmap_synchronizeBridgingBridgeVLANPort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_list *br_ports_list = NULL;
	struct uci_element *e = NULL;

	if (!args->bridge_sec)
		return;

	dmuci_get_value_by_section_list(args->bridge_sec, "ports", &br_ports_list);
	if (!br_ports_list)
		return;

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user = NULL;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (s_user && DM_LSTRCMP(s_user, "1") == 0)
			continue;

		// port device is available in network config ==> skip it
		char *sec_name;
		dmuci_get_value_by_section_string(s, "section_name", &sec_name);
		if (get_origin_section_from_config("network", "device", sec_name))
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_element(br_ports_list, e) {
		char *lower_layer = NULL;

		s = get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "port", e->name);
		dmuci_get_value_by_section_string(s, "LowerLayers", &lower_layer);

		if (!s || DM_STRNCMP(lower_layer, "Device.Bridging.Bridge.", strlen("Device.Bridging.Bridge.")) == 0)
			continue;

		uci_foreach_option_eq("network", "device", "name", e->name, s) {

			if (dmuci_is_option_value_empty(s, "type"))
				continue;

			if (get_section_in_dmmap_with_options_eq("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", args->br_inst, "section_name", section_name(s)))
				break;

			struct uci_section *br_vlanport_s = NULL;

			dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &br_vlanport_s);
			dmuci_set_value_by_section(br_vlanport_s, "br_inst", args->br_inst);
			dmuci_set_value_by_section(br_vlanport_s, "section_name", section_name(s));
		}

	}
}

static bool is_wireless_ifname_exist(char *dev_sec_name, char *ifname)
{
	if (DM_STRLEN(dev_sec_name) == 0 || DM_STRLEN(ifname) == 0)
		return false;

	struct uci_section *interface_s = get_dup_section_in_config_opt("network", "interface", "device", dev_sec_name);
	if (interface_s == NULL)
		return false;

	struct uci_section *s = NULL;
	uci_foreach_option_eq("wireless", "wifi-iface", "network", section_name(interface_s), s) {
		char *curr_ifname = NULL;

		dmuci_get_value_by_section_string(s, "ifname", &curr_ifname);
		if (DM_STRCMP(curr_ifname, ifname) == 0)
			return true;
	}

	return false;
}

static void create_new_bridge_port_section(char *config, char *port, char *br_inst, char *management_port)
{
	struct uci_section *br_port_s = NULL;

	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);

	dmuci_set_value_by_section(br_port_s, "config", config);
	dmuci_set_value_by_section(br_port_s, "port", port);
	dmuci_set_value_by_section(br_port_s, "br_inst", br_inst);
	dmuci_set_value_by_section(br_port_s, "management", management_port);
	dmuci_set_value_by_section(br_port_s, "enabled", "1");
}

static void dmmap_synchronizeBridgingBridgePort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_element *e = NULL;
	char *s_user = NULL;

	if (!args->bridge_sec)
		return;

	struct uci_list *br_ports_list = NULL;
	dmuci_get_value_by_section_list(args->bridge_sec, "ports", &br_ports_list);

	// get name option from network/device section
	char *dev_name = NULL;
	dmuci_get_value_by_section_string(args->bridge_sec, "name", &dev_name);

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, stmp, s) {

		// section added by user ==> skip it
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (DM_LSTRCMP(s_user, "1") == 0)
			continue;

		// section for management ==> skip it
		char *management = NULL;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (DM_LSTRCMP(management, "1") == 0)
			continue;

		// port is disbaled ==> if yes, skip it
		char *enabled = NULL;
		dmuci_get_value_by_section_string(s, "enabled", &enabled);
		if (DM_LSTRCMP(enabled, "0") == 0)
			continue;

		// port device is available in ports list ==> skip it
		char *port_device = NULL;
		dmuci_get_value_by_section_string(s, "port", &port_device);
		if (value_exists_in_uci_list(br_ports_list, port_device))
			continue;

		// check for wireless ==> skip it
		if (is_wireless_ifname_exist(dev_name, port_device))
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	// section added by user ==> skip it
	dmuci_get_value_by_section_string(args->bridge_dmmap_sec, "added_by_user", &s_user);

	if (DM_LSTRCMP(s_user, "1") != 0 && !get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "management", "1"))
		create_new_bridge_port_section("network", dev_name, args->br_inst, "1");

	if (br_ports_list) {
		uci_foreach_element(br_ports_list, e) {

			if (get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "port", e->name))
				continue;

			create_new_bridge_port_section("network", e->name, args->br_inst, "0");
		}
	}

	// get interface section mapped to this device name
	struct uci_section *interface_s = get_dup_section_in_config_opt("network", "interface", "device", dev_name);
	if (interface_s == NULL)
		return;

	uci_foreach_option_eq("wireless", "wifi-iface", "network", section_name(interface_s), s) {
		char *ifname = NULL;

		// get ifname from wireless/wifi-iface section
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (DM_STRLEN(ifname) == 0)
			continue;

		if (get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "port", ifname))
			continue;

		create_new_bridge_port_section("wireless", ifname, args->br_inst, "0");
	}
}

static void get_bridge_vlanport_device_section(struct uci_section *bridge_vlanport_dmmap_sec, struct uci_section **device_section)
{
	char *dev_sec_name = NULL;

	*device_section = NULL;

	if (!bridge_vlanport_dmmap_sec)
		return;

	/* Get section_name from dmmap section */
	dmuci_get_value_by_section_string(bridge_vlanport_dmmap_sec, "section_name", &dev_sec_name);
	if (DM_STRLEN(dev_sec_name) == 0)
		return;

	/* Find the device network section corresponding to this device_name */
	*device_section = get_origin_section_from_config("network", "device", dev_sec_name);
}

static void get_bridge_port_device_section(struct uci_section *bridge_port_dmmap_sec, struct uci_section **device_section)
{
	struct uci_section *s = NULL;
	char *port = NULL;

	*device_section = NULL;

	if (!bridge_port_dmmap_sec)
		return;

	/* Getting device from dmmap section */
	dmuci_get_value_by_section_string(bridge_port_dmmap_sec, "port", &port);
	if (DM_STRLEN(port) == 0)
		return;

	/* Find the device port section corresponding to this device */
	if ((s = ethernet___get_ethernet_interface_section(port))) {
		*device_section = s;
		return;
	}

	/* Find the wifi-iface wireless section corresponding to this device */
	uci_foreach_option_eq("wireless", "wifi-iface", "ifname", port, s) {
		*device_section = s;
		return;
	}

	/* Find the device network section corresponding to this device */
	uci_foreach_option_eq("network", "device", "name", port, s) {
		*device_section = s;
		return;
	}
}

static void restore_bridge_config(char *br_inst)
{
	struct uci_section *s = NULL, *dmmap_br_sec = NULL;
	struct uci_list *br_ports_list = NULL;
	struct uci_element *e = NULL;
	char *device_section_name = NULL;
	char iface_s_name[16];
	char device_name[16];

	// Get bridge config section of vlan bridge from dmmap_bridge_port
	dmmap_br_sec = get_dup_section_in_dmmap_opt("dmmap_bridge", "device", "bridge_instance", br_inst);
	if (dmmap_br_sec == NULL)
		return;

	dmuci_get_value_by_section_string(dmmap_br_sec, "section_name", &device_section_name);
	dmuci_get_value_by_section_list(dmmap_br_sec, "ports", &br_ports_list);

	snprintf(iface_s_name, sizeof(iface_s_name), "iface_br%s", br_inst);
	snprintf(device_name, sizeof(device_name), "br-dev%s", br_inst);

	// Restore bridge config
	dmuci_add_section("network", "interface", &s);
	dmuci_rename_section_by_section(s, iface_s_name);
	dmuci_set_value_by_section(s, "device", device_name);

	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_section_name);
	dmuci_set_value_by_section(s, "name", device_name);
	dmuci_set_value_by_section(s, "type", "bridge");
	dmuci_set_value_by_section(s, "bridge_empty", "1");
	if (br_ports_list) {
		uci_foreach_element(br_ports_list, e) {
			dmuci_add_list_value_by_section(s, "ports", e->name);
		}
	}
}

static void delete_provider_bridge(struct uci_section *data)
{
	struct uci_list *cvlan_list = NULL;
	struct uci_section *s = NULL;
	char *svlan_br_inst = NULL;
	char pr_br_inst[32] = {0};
	char *br_inst = NULL;

	/*
	 * Get cvlan/svlan bridge instance from the provider_bridge config and re-create all member bridge config section in network file.
	 * Delete all bridge_port config from dmmap_bridge_port which are member of this provider bridge.
	 * Delete provider bridge config. from network file corresponding to this provider bridge instance => config pr_br_{i}
	 * Delete this provider bridge section from dmmap_provider_bridge file.
	 *
	 */

	// Get provider bridge instance
	dmuci_get_value_by_section_string(data, "provider_bridge_instance", &br_inst);
	if (!br_inst || *br_inst != '\0')
		return;

	snprintf(pr_br_inst, sizeof(pr_br_inst), "pr_br_%s", br_inst); //name of provider bridge configuration in network file

	// Get svlan component bridge instance from dmmap section
	dmuci_get_value_by_section_string(data, "svlan_br_inst", &svlan_br_inst);

	if (svlan_br_inst && svlan_br_inst[0] != '\0') {

		// Restore bridge section in network uci file
		restore_bridge_config(svlan_br_inst);
	}

	// Get cvlan component bridge instance list from dmmap section
	dmuci_get_value_by_section_list(data, "cvlan_br_inst", &cvlan_list);
	if (cvlan_list != NULL) {
		struct uci_element *e = NULL;

		/* traverse each list value and delete all bridge section */
		uci_foreach_element(cvlan_list, e) {

			// Restore bridge section in network uci file
			restore_bridge_config(e->name);
		}
	}

	// Get provider bridge section from network file and delete
	s = get_origin_section_from_config("network", "device", pr_br_inst);
	dmuci_delete_by_section(s, NULL, NULL);

	// Delete dmmap bridge section.
	dmuci_delete_by_section_bbfdm(data, NULL, NULL);
}

void remove_bridge_from_provider_bridge(char *bridge_inst)
{
	struct uci_section *pr_br_sec = NULL;

	// Traverse each provider bridge section and remove the passed bridge instance.
	// Also restore bridge in network file.
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", pr_br_sec) {
		struct uci_list *cvlan_list = NULL;
		char *svlan = NULL;

		// Check if the passed bridge section is svlan
		dmuci_get_value_by_section_string(pr_br_sec, "svlan_br_inst", &svlan);
		if (DM_STRCMP(svlan, bridge_inst) == 0) {
			dmuci_set_value_by_section(pr_br_sec, "svlan_br_inst", "");
		}

		// Check if the passed bridge section is cvlan
		dmuci_get_value_by_section_list(pr_br_sec, "cvlan_br_inst", &cvlan_list);
		if (cvlan_list != NULL) {
			struct uci_element *e = NULL;

			uci_foreach_element(cvlan_list, e) {
				if (DM_STRCMP(e->name, bridge_inst) == 0) {
					dmuci_del_list_value_by_section(pr_br_sec, "cvlan_br_inst", bridge_inst);
					break;
				}
			}
		}
	}
}

static void Update_BridgePort_Port_Layer(char *path, struct uci_section *bridge_vlanport_sec, struct uci_section *bridge_sec, struct uci_section *bridge_dmmap_sec, char *bridge_intsance, char *old_linker, char *new_linker)
{
	struct uci_section *dmmap_s = NULL;

	char *p = DM_STRRCHR(path, '.');
	if (!p)
		return;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", bridge_intsance, dmmap_s) {
		char *instance = NULL;
		char *enable = NULL;
		char *type = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "bridge_port_instance", &instance);
		if (DM_STRCMP(instance, p + 1) != 0)
			continue;

		dmuci_set_value_by_section(dmmap_s, "port", new_linker);

		dmuci_get_value_by_section_string(dmmap_s, "enabled", &enable);
		if (DM_STRCMP(enable, "1") == 0) {
			/* Update ports list */
			remove_port_from_bridge_sections(bridge_sec, bridge_dmmap_sec, old_linker);
			add_port_to_bridge_sections(bridge_sec, bridge_dmmap_sec, new_linker);
		}

		dmuci_get_value_by_section_string(dmmap_s, "type", &type);
		if (DM_STRLEN(type)) {
			if (DM_LSTRCMP(type, "33024") == 0)
				dmuci_set_value_by_section(bridge_vlanport_sec, "type", "8021q");
			else if (DM_LSTRCMP(type, "34984") == 0)
				dmuci_set_value_by_section(bridge_vlanport_sec, "type", "8021ad");
		}

		break;
	}
}

static void Update_BridgeVLANPort_Port_Layer(char *path, struct uci_section *bridge_sec, struct uci_section *bridge_dmmap_sec, char *bridge_intsance, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", bridge_intsance, dmmap_s) {
		struct uci_section *device_s = NULL;
		char *sec_name = NULL;
		char *port_ref = NULL;
		char *instance = NULL;
		char *vid = NULL;
		char new_name[32] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "Port", &port_ref);
		if (DM_STRCMP(port_ref, path) != 0)
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "bridge_vlanport_instance", &instance);
		if (!DM_STRLEN(instance))
			return;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			return;

		device_s = get_origin_section_from_config("network", "device", sec_name);
		if (!device_s)
			return;

		dmuci_get_value_by_section_string(device_s, "vid", &vid);

		snprintf(new_name, sizeof(new_name), "%s%s%s", DM_STRLEN(linker) ? linker : "",
								(DM_STRLEN(linker) && DM_STRLEN(vid)) ? "." : "",
								(DM_STRLEN(linker) && DM_STRLEN(vid)) ? vid : "");

		// Set ifname and name options
		dmuci_set_value_by_section(device_s, "ifname", linker);
		dmuci_set_value_by_section(device_s, "name", new_name);

		// Update Bridge Port instance if exists
		Update_BridgePort_Port_Layer(port_ref, device_s, bridge_sec, bridge_dmmap_sec, bridge_intsance, linker, new_name);
	}
}

static void Update_BridgeVLANPort_VLAN_Layer(char *path, struct uci_section *bridge_sec, struct uci_section *bridge_dmmap_sec, char *bridge_intsance, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", bridge_intsance, dmmap_s) {
		struct uci_section *device_s = NULL;
		char *sec_name = NULL;
		char *vlan_ref = NULL;
		char *port_ref = NULL;
		char *instance = NULL;
		char *ifname = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "VLAN", &vlan_ref);
		if (DM_STRCMP(vlan_ref, path) != 0)
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "bridge_vlanport_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		device_s = get_origin_section_from_config("network", "device", sec_name);

		dmuci_set_value_by_section(device_s, "vid", linker);

		dmuci_get_value_by_section_string(dmmap_s, "Port", &port_ref);
		if (!DM_STRLEN(port_ref))
			continue;

		dmuci_get_value_by_section_string(device_s, "ifname", &ifname);
		if (DM_STRLEN(ifname)) {
			char *old_name = NULL;
			char new_name[32] = {0};

			dmuci_get_value_by_section_string(device_s, "name", &old_name);

			snprintf(new_name, sizeof(new_name), "%s%s%s", ifname, DM_STRLEN(linker) ? "." : "", DM_STRLEN(linker) ? linker : "");

			dmuci_set_value_by_section(device_s, "name", new_name);

			Update_BridgePort_Port_Layer(port_ref, device_s, bridge_sec, bridge_dmmap_sec, bridge_intsance, old_name, new_name);
		}
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Bridging.Bridge.{i}.!UCI:network/device/dmmap_bridge*/
static int browseBridgingBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args curr_bridging_args = {0};
	struct dm_data *curr_data = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_bridge_config_sections_with_dmmap_bridge_eq("network", "device", "dmmap_bridge", "type", "bridge", &dup_list);
	list_for_each_entry(curr_data, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, curr_data->dmmap_section, "bridge_instance", "bridge_alias");

		init_bridging_args(&curr_bridging_args, curr_data->config_section ? curr_data->config_section : curr_data->dmmap_section, curr_data->dmmap_section, inst);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseBridgingProviderBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct provider_bridge_args curr_bridging_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeBridgingProviderBridge(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", s) {

		inst = handle_instance(dmctx, parent_node, s, "provider_bridge_instance", "provider_bridge_alias");

		init_provider_bridge_args(&curr_bridging_args, s, inst);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgePortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct bridge_port_args curr_bridge_port_args = {0};
	struct uci_section *br_port_dmmap_s = NULL;
	char *inst = NULL, *mng_port = NULL;
	bool is_mng_port = false;

	dmmap_synchronizeBridgingBridgePort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, br_port_dmmap_s) {
		struct uci_section *br_port_s = NULL;

		dmuci_get_value_by_section_string(br_port_dmmap_s, "management", &mng_port);
		is_mng_port = (DM_LSTRCMP(mng_port, "1") == 0) ? true : false;

		/* Getting the corresponding port device section */
		get_bridge_port_device_section(br_port_dmmap_s, &br_port_s);

		init_bridge_port_args(&curr_bridge_port_args, br_args->bridge_sec, br_args->bridge_dmmap_sec, br_port_s, br_port_dmmap_s, is_mng_port, br_args->br_inst);

		inst = handle_instance(dmctx, parent_node, br_port_dmmap_s, "bridge_port_instance", "bridge_port_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_port_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgeVLANInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct bridge_vlan_args curr_bridge_vlan_args = {0};
	struct uci_section *br_vlan_dmmap_s = NULL;
	char *inst = NULL;

	dmmap_synchronizeBridgingBridgeVLAN(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_args->br_inst, br_vlan_dmmap_s) {

		init_bridge_vlan_args(&curr_bridge_vlan_args, br_args->bridge_sec, br_args->bridge_dmmap_sec, br_vlan_dmmap_s, br_args->br_inst);

		inst = handle_instance(dmctx, parent_node, br_vlan_dmmap_s, "bridge_vlan_instance", "bridge_vlan_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlan_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgeVLANPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct bridge_vlanport_args curr_bridge_vlanport_args = {0};
	struct uci_section *br_vlanport_dmmap_s = NULL;
	char *inst = NULL;

	dmmap_synchronizeBridgingBridgeVLANPort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_args->br_inst, br_vlanport_dmmap_s) {
		struct uci_section *br_vlanport_s = NULL;

		get_bridge_vlanport_device_section(br_vlanport_dmmap_s, &br_vlanport_s);

		init_bridge_vlanport_args(&curr_bridge_vlanport_args, br_args->bridge_sec, br_args->bridge_dmmap_sec, br_vlanport_s, br_vlanport_dmmap_s, br_args->br_inst);

		inst = handle_instance(dmctx, parent_node, br_vlanport_dmmap_s, "bridge_vlanport_instance", "bridge_vlanport_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlanport_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD DELETE OBJECT
**************************************************************/
static int addObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_bridge = NULL;
	char iface_s_name[16];
	char dev_s_name[16];
	char device_name[16];

	snprintf(iface_s_name, sizeof(iface_s_name), "iface_br%s", *instance);
	snprintf(dev_s_name, sizeof(dev_s_name), "dev_br%s", *instance);
	snprintf(device_name, sizeof(device_name), "br-dev%s", *instance);

	// Add network bridge section
	dmuci_add_section("network", "interface", &s);
	dmuci_rename_section_by_section(s, iface_s_name);
	dmuci_set_value_by_section(s, "device", device_name);

	// Add device bridge section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, dev_s_name);
	dmuci_set_value_by_section(s, "name", device_name);
	dmuci_set_value_by_section(s, "type", "bridge");
	dmuci_set_value_by_section(s, "bridge_empty", "1");

	// Add dmmap bridge section
	dmuci_add_section_bbfdm("dmmap_bridge", "device", &dmmap_bridge);
	dmuci_set_value_by_section(dmmap_bridge, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_bridge, "added_by_user", "1");
	dmuci_set_value_by_section(dmmap_bridge, "bridge_instance", *instance);
	return 0;
}

static int delObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			// Remove all bridge port sections related to this device bridge section
			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			// Remove all bridge vlan sections related to this device bridge section
			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			// Remove all bridge vlanport sections related to this device bridge section
			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
				char *sec_name = NULL;

				dmuci_get_value_by_section_string(s, "section_name", &sec_name);
				if (DM_STRLEN(sec_name)) {
					struct uci_section *device_s = get_origin_section_from_config("network", "device", sec_name);
					dmuci_delete_by_section(device_s, NULL, NULL);
				}

				dmuci_delete_by_section(s, NULL, NULL);
			}

			// Remove cvlan/svaln from dmmap_provider_bridge section if this bridge instance is a part of it
			remove_bridge_from_provider_bridge(((struct bridge_args *)data)->br_inst);

			// Remove interface bridge that maps to this device
			remove_device_from_bridge_interface(((struct bridge_args *)data)->bridge_sec);

			// Remove device bridge section
			dmuci_delete_by_section(((struct bridge_args *)data)->bridge_sec, NULL, NULL);

			// Remove dmmap device bridge section
			dmuci_delete_by_section(((struct bridge_args *)data)->bridge_dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			break;
	}
	return 0;
}

static int addObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_port_s = NULL;
	char buf[32];

	snprintf(buf, sizeof(buf), "br_%s_port_%s", ((struct bridge_args *)data)->br_inst, *instance);

	// Add dmmap section for devices
	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);
	dmuci_rename_section_by_section(br_port_s, buf);

	dmuci_set_value_by_section(br_port_s, "config", "network");
	dmuci_set_value_by_section(br_port_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
	dmuci_set_value_by_section(br_port_s, "management", "0");
	dmuci_set_value_by_section(br_port_s, "enabled", "0");
	dmuci_set_value_by_section(br_port_s, "added_by_user", "1");
	return 0;
}

static int delObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	switch (del_action) {
	case DEL_INST:
		if (!args->is_management_port) {
			char *enable = NULL;
			char *port = NULL;

			// Get enabled and port options
			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "enabled", &enable);
			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);

			if (DM_STRCMP(enable, "1") == 0) {
				// Remove port from port list interface
				remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port);
			}

			// Update Bridge VLANPort instance if exists
			Update_BridgeVLANPort_Port_Layer(refparam, args->bridge_sec, args->bridge_dmmap_sec, args->br_inst, "");
		}

		// Remove dmmap section
		dmuci_delete_by_section_bbfdm(args->bridge_port_dmmap_sec, NULL, NULL);
		break;
	case DEL_ALL:
		break;
	}
	return 0;
}

static int addObjBridgingBridgeVLANPort(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *br_vlanport_s = NULL;
	char device_name[32];

	snprintf(device_name, sizeof(device_name), "br_%s_port_%s", ((struct bridge_args *)data)->br_inst, *instance);

	// Add device section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");
	dmuci_set_value_by_section(s, "enabled", "0");

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &br_vlanport_s);
	dmuci_set_value_by_section(br_vlanport_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_vlanport_s, "bridge_vlanport_instance", *instance);
	dmuci_set_value_by_section(br_vlanport_s, "section_name", device_name);
	dmuci_set_value_by_section(br_vlanport_s, "added_by_user", "1");

	return 0;
}

static int delObjBridgingBridgeVLANPort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	char *port_ref = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "Port", &port_ref);
		if (DM_STRLEN(port_ref)) {
			char *ifname = NULL;
			char *name = NULL;

			// Get ifname and name options
			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "ifname", &ifname);
			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "name", &name);

			// Update Bridge Port instance if exists
			Update_BridgePort_Port_Layer(port_ref, args->bridge_vlanport_sec, args->bridge_sec, args->bridge_dmmap_sec, args->br_inst, name, ifname);
		}

		// Remove config section
		dmuci_delete_by_section_bbfdm(args->bridge_vlanport_sec, NULL, NULL);

		// Remove dmmap section
		dmuci_delete_by_section_bbfdm(args->bridge_vlanport_dmmap_sec, NULL, NULL);
		break;
	case DEL_ALL:
		break;
	}
	return 0;
}

static int addObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_vlan_s = NULL;
	char vlan_name[32]= {0};
	char vid_str[32] = {0};

	unsigned long vid_ul = bridging_get_new_vid(((struct bridge_args *)data)->br_inst);
	DM_ULTOSTR(vid_str, vid_ul, sizeof(vid_str));

	snprintf(vlan_name, sizeof(vlan_name), "br_%s_vlan_%s", ((struct bridge_args *)data)->br_inst, *instance);

	dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &br_vlan_s);
	dmuci_set_value_by_section(br_vlan_s, "name", vlan_name);
	dmuci_set_value_by_section(br_vlan_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_vlan_s, "bridge_vlan_instance", *instance);
	dmuci_set_value_by_section(br_vlan_s, "added_by_user", "1");
	dmuci_set_value_by_section(br_vlan_s, "vid", vid_str);
	return 0;
}

static int delObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct bridge_vlan_args *args = (struct bridge_vlan_args *)data;

	switch (del_action) {
	case DEL_INST:
		// Remove all vid from device sections
		Update_BridgeVLANPort_VLAN_Layer(refparam, args->bridge_sec, args->bridge_dmmap_sec, args->br_inst, "");

		// Remove dmmap section
		dmuci_delete_by_section_bbfdm(args->bridge_vlan_sec, NULL, NULL);
		break;
	case DEL_ALL:
		break;
	}
	return 0;
}

static int addObjBridgingProviderBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *pr_br_sec = NULL;

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_provider_bridge", "provider_bridge", &pr_br_sec);
	dmuci_set_value_by_section(pr_br_sec, "enable", "1");
	dmuci_set_value_by_section(pr_br_sec, "provider_bridge_instance", *instance);
	return 0;
}

static int delObjBridgingProviderBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
	case DEL_INST:
		delete_provider_bridge(((struct provider_bridge_args *)data)->provider_bridge_sec);
		break;
	case DEL_ALL:
		break;
	}
	return 0;
}

/**************************************************************************
*SET & GET PARAMETERS
***************************************************************************/
static int get_Bridging_MaxBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxDBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxQBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxVLANEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxProviderBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_get_Bridging_MaxFilterEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

/*#Device.Bridging.ProviderBridgeNumberOfEntries!UCI:network/device/*/
static int get_Bridging_ProviderBridgeNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseBridgingProviderBridgeInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Bridging.BridgeNumberOfEntries!UCI:network/device/*/
static int get_Bridging_BridgeNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseBridgingBridgeInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Enable!UCI:network/device,@i-1/enabled*/
static int get_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_args *)data)->bridge_sec, "enabled", "1");
	return 0;
}

static int set_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Status!UCI:network/device,@i-1/enabled*/
static int get_BridgingBridge_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name = NULL;

	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "name", &name);
	get_net_device_status(name, value);
	if (DM_STRCMP(*value, "Up") == 0) {
		*value = "Enabled";
	} else {
		*value = "Disabled";
	}
	return 0;
}

static int get_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct bridge_args *)data)->bridge_dmmap_sec, "bridge_alias", instance, value);
}

static int set_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct bridge_args *)data)->bridge_dmmap_sec, "bridge_alias", instance, value);
}

static int get_BridgingBridge_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "bridge-%s", ((struct bridge_args *)data)->br_inst);
	return 0;
}

static int get_BridgingBridge_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "802.1Q-2011";
	return 0;
}

static int set_BridgingBridge_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *Bridge_Standard[] = {"802.1D-2004", "802.1Q-2005", "802.1Q-2011", NULL};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, Bridge_Standard, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridge_PortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseBridgingBridgePortInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridge_VLANNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
int cnt = get_number_of_entries(ctx, data, instance, browseBridgingBridgeVLANInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridge_VLANPortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseBridgingBridgeVLANPortInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}


static int get_BridgingBridgeSTP_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_args *)data)->bridge_sec, "stp", "0");
	return 0;
}

static int set_BridgingBridgeSTP_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "stp", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeSTP_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name = NULL;

	*value = "Disabled";
	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "name", &name);
	if (DM_STRLEN(name) == 0) {
		return 0;
	}

	char *enable = NULL;
	get_net_device_sysfs(name, "bridge/stp_state", &enable);
	if (DM_STRCMP(enable, "1") == 0)
		*value = "Enabled";

	return 0;
}

static int get_BridgingBridgeSTP_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "STP";
	return 0;
}

static int set_BridgingBridgeSTP_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *Protocol[] = {"STP", NULL};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, Protocol, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeSTP_BridgePriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_args *)data)->bridge_sec, "priority", "32767");
	return 0;
}

static int set_BridgingBridgeSTP_BridgePriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","61440"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "priority", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeSTP_HelloTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "hello_time", value);

	// Value defined in system is in seconds but in datamodel this is in centiseconds, convert the value to centiseconds
	int hello_time = DM_STRLEN(*value) ? DM_STRTOL(*value) * 100 : 200;

	dmasprintf(value, "%d", hello_time);
	return 0;
}

static int set_BridgingBridgeSTP_HelloTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[16] = {0};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"100","1000"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			// Value defined in system is in seconds but in datamodel this is in centiseconds, convert the value to seconds
			snprintf(buf, sizeof(buf), "%u", (uint32_t)DM_STRTOL(value) / 100);
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "hello_time", buf);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeSTP_MaxAge(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "max_age", value);

	// Value defined in system is in seconds but in datamodel this is in centiseconds, convert the value to centiseconds
	int max_age = DM_STRLEN(*value) ? DM_STRTOL(*value) * 100 : 2000;

	dmasprintf(value, "%d", max_age);
	return 0;
}

static int set_BridgingBridgeSTP_MaxAge(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[16] = {0};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"600","4000"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			// Value defined in system is in seconds but in datamodel this is in centiseconds, convert the value to seconds
			snprintf(buf, sizeof(buf), "%u", (uint32_t)DM_STRTOL(value) / 100);
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "max_age", buf);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeSTP_ForwardingDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_args *)data)->bridge_sec, "forward_delay", "4");
	return 0;
}

static int set_BridgingBridgeSTP_ForwardingDelay(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"4","30"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "forward_delay", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "enabled", value);
	return 0;
}

static int set_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	char *config = NULL, *device = NULL;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			string_to_bool(value, &b);

			if (args->is_management_port)
				return 0;

			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "enabled", b ? "1" : "0");

			dmuci_get_value_by_section_string(args->bridge_sec, "name", &device);
			if (DM_STRLEN(device) == 0)
				return 0;

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "config", &config);
			if (DM_LSTRCMP(config, "wireless") == 0) {
				struct uci_section *wifi_iface_s = get_dup_section_in_config_opt("network", "interface", "device", device);
				dmuci_set_value_by_section(args->bridge_port_sec, "network", b ? section_name(wifi_iface_s) : "");
			} else {
				char *port = NULL;

				dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);
				if (DM_STRLEN(port) == 0)
					return 0;

				if (b)
					add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port);
				else
					remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port);
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	char *port = NULL;

	dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);
	return get_net_device_status(port, value);
}

static int get_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "bridge_port_alias", instance, value);
}

static int set_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "bridge_port_alias", instance, value);
}

static int get_BridgingBridgePort_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", value);
	return 0;
}

static int get_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	struct uci_section *port_s = NULL;

	if (args->is_management_port) {
		char buf[1024] = {0};
		unsigned pos = 0;

		buf[0] = 0;

		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, port_s) {
			char *mg_port = NULL;
			char *port = NULL;
			char br_buf[64] = {0};

			snprintf(br_buf, sizeof(br_buf), "Device.Bridging.Bridge.%s.Port.*.Name", args->br_inst);

			dmuci_get_value_by_section_string(port_s, "management", &mg_port);
			if (DM_LSTRCMP(mg_port, "1") == 0)
				continue;

			dmuci_get_value_by_section_string(port_s, "port", &port);

			adm_entry_get_reference_param(ctx, br_buf, port, value);
			if (DM_STRLEN(*value))
				pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s,", *value);
		}

		if (pos)
			buf[pos - 1] = 0;

		*value = dmstrdup(buf);
	} else {
		dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "LowerLayers", value);

		if ((*value)[0] == '\0') {
			char *type = NULL, *port = NULL, *config = NULL;

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "type", &type);
			if (DM_STRCMP(type, "34984") == 0)
				return 0;

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);
			if (DM_STRLEN(port) == 0)
				return 0;

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "config", &config);

			if (DM_LSTRCMP(config, "network") == 0) {
				struct uci_section *eth_iface_s = ethernet___get_ethernet_interface_section(port);
				if (!eth_iface_s) {
					char *tag = DM_STRRCHR(port, '.');
					if (tag) tag[0] = '\0';
				}

				adm_entry_get_reference_param(ctx, "Device.Ethernet.Interface.*.Name", port, value);
			} else {
				struct uci_section *iface_s = get_dup_section_in_config_opt("wireless", "wifi-iface", "ifname", port);
				adm_entry_get_reference_param(ctx, "Device.WiFi.SSID.*.Name", section_name(iface_s), value);
			}

			// Store LowerLayers value
			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "LowerLayers", *value);
		} else {
			if (!adm_entry_object_exists(ctx, *value))
				*value = "";
		}
	}

	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	char *allowed_objects[] = {
			"Device.Ethernet.Interface.",
			"Device.WiFi.SSID.",
			"Device.Bridging.Bridge.*.Port.",
			NULL
	};
	struct dm_reference reference = {0};
	char *enable = NULL, *port = NULL, *type = NULL;

	bbf_get_reference_args(value, &reference);

	if (args->is_management_port)
		return 0;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, reference.path, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "type", &type);
			if (DM_LSTRNCMP(value, "Device.Bridging.Bridge.", 23) == 0 && DM_STRCMP(type, "34984") != 0)
				return FAULT_9007;

			return 0;
		case VALUESET:
			// Store LowerLayers value under dmmap section
			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "LowerLayers", reference.path);

			// Update config section on dmmap_bridge_port if the linker is wirelss port or network port
			if (DM_LSTRNCMP(reference.path, "Device.WiFi.SSID.", 17) == 0) {
				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "config", "wireless");
			} else {
				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "config", "network");
			}

			// Get current port and enable options
			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);
			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "enabled", &enable);

			if (DM_STRCMP(enable, "1") == 0) {
				// Remove port from port list interface
				remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port);
			}

			// Update port option in dmmap
			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "port", reference.value);

			if (DM_STRCMP(enable, "1") == 0) {
				// Add port to ports list
				add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, reference.value);
			}

			// Update Bridge VLANPort instance if exists
			Update_BridgeVLANPort_Port_Layer(refparam, args->bridge_sec, args->bridge_dmmap_sec, args->br_inst, reference.value);
			return 0;
		}
	return 0;
}

static int get_BridgingBridgePort_ManagementPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", value);
	return 0;
}

static int set_BridgingBridgePort_ManagementPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	char *bridge_name = NULL;
	bool b;

	string_to_bool(value, &b);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			if (b && get_section_in_dmmap_with_options_eq("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "management", "1"))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "name", &bridge_name);

			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", b ? "1" : "0");
			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", b ? bridge_name : "");

			// Update Ethernet Link instance if exists
			if (b) ethernet___Update_Link_Layer(refparam, bridge_name);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bridging___get_priority_list(((struct bridge_port_args *)data)->bridge_port_sec, "ingress_qos_mapping", data, value);
	return 0;
}

static int set_BridgingBridgePort_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = ((struct bridge_port_args *)data);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt_list(ctx, value, 8, 8, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;

			if (args->is_management_port)
				return 0;

			if (dmuci_is_option_value_empty(args->bridge_port_sec, "type"))
				return FAULT_9007;

			break;
		case VALUESET:
			if (args->is_management_port)
				return 0;

			bridging___set_priority_list(((struct bridge_port_args *)data)->bridge_port_sec, "ingress_qos_mapping", data, value);
			break;
	}
	return 0;
}

static int get_BridgingBridgePort_PVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_port_args *)data)->bridge_port_sec, "vid", "1");
	return 0;
}

static int set_BridgingBridgePort_PVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = ((struct bridge_port_args *)data);
	char *ifname = NULL, *name = NULL, *type = NULL, *enable = NULL;
	char new_name[32] = {0};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;

			if (args->is_management_port)
				return 0;

			dmuci_get_value_by_section_string(args->bridge_port_sec, "type", &type);
			if (DM_LSTRCMP(type, "8021q") != 0)
				return FAULT_9007;

			return 0;
		case VALUESET:
			if (args->is_management_port)
				return 0;

			dmuci_set_value_by_section(args->bridge_port_sec, "vid", value);

			dmuci_get_value_by_section_string(args->bridge_port_sec, "ifname", &ifname);
			if (DM_STRLEN(ifname) == 0)
				return 0;

			dmuci_get_value_by_section_string(args->bridge_port_sec, "enabled", &enable);
			dmuci_get_value_by_section_string(args->bridge_port_sec, "name", &name);

			snprintf(new_name, sizeof(new_name), "%s.%s", ifname, value);

			if (DM_STRCMP(enable, "1") == 0) {
				// Remove port from ports list
				remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, name);
			}

			/* Update Port dmmap section */
			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "port", new_name);

			/* Update name option in network config */
			dmuci_set_value_by_section(args->bridge_port_sec, "name", new_name);

			if (DM_STRCMP(enable, "1") == 0) {
				// Add new port to ports list
				add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, new_name);
			}

			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
	if (DM_LSTRCMP(type, "8021q") == 0)
		*value = "33024";
	else if (DM_LSTRCMP(type, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;

			return 0;
		case VALUESET:
			if (args->is_management_port)
				return 0;

			if (DM_LSTRCMP(value, "33024") == 0)
				dmuci_set_value_by_section(args->bridge_port_sec, "type", "8021q");
			else if (DM_LSTRCMP(value, "34984") == 0)
				dmuci_set_value_by_section(args->bridge_port_sec, "type", "8021ad");

			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "type", value);
			return 0;
	}
	return 0;
}

static int br_get_sysfs(const struct bridge_port_args *br, const char *name, char **value)
{
	char *device = NULL;

	dmuci_get_value_by_section_string(br->bridge_port_sec, "ifname", &device);
	return get_net_device_sysfs(device, name, value);
}

static int br_get_ubus_eth(const struct bridge_port_args *br, const char *name, char **value)
{
	json_object *res = NULL;
	char *device = NULL;
	char *config = NULL;

	DM_ASSERT(br, *value = "0");
	dmuci_get_value_by_section_string(br->bridge_port_sec, "ifname", &device);
	dmuci_get_value_by_section_string(br->bridge_port_dmmap_sec, "config", &config);

	if (DM_LSTRCMP(config, "network") == 0) {
		dmubus_call("ethernet", "ifstats", UBUS_ARGS{{"ifname", device, String}}, 1, &res);
	} else {
		char object[32];

		snprintf(object, sizeof(object), "wifi.radio.%s", device);
		dmubus_call(object, "stats", UBUS_ARGS{0}, 0, &res);
	}

	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_BridgingBridgePortStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_BridgingBridgePortStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_BridgingBridgePortStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_BridgingBridgePortStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_BridgingBridgePortStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_BridgingBridgePortStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_errors", value);
}

static int get_BridgingBridgePortStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_ubus_eth(data, "tx_unicast_packets", value);
}

static int get_BridgingBridgePortStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_ubus_eth(data, "rx_unicast_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_BridgingBridgePortStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_BridgingBridgePortStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_dropped", value);
}

static int get_BridgingBridgePortStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_ubus_eth(data, "tx_multicast_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_BridgingBridgePortStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/multicast", value);
}

static int get_BridgingBridgePortStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_ubus_eth(data, "tx_broadcast_packets", value);
}

static int get_BridgingBridgePortStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_ubus_eth(data, "rx_broadcast_packets", value);
}

static int get_BridgingBridgePortStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_ubus_eth(data, "rx_unknown_packets", value);
}

static int get_BridgingBridgeVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_BridgingBridgeVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct bridge_vlan_args *)data)->bridge_vlan_sec, "bridge_vlan_alias", instance, value);
}

static int set_BridgingBridgeVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct bridge_vlan_args *)data)->bridge_vlan_sec, "bridge_vlan_alias", instance, value);
}

static int get_BridgingBridgeVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", value);
	return 0;
}

static int set_BridgingBridgeVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLAN_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", value);
	return 0;
}

static int set_BridgingBridgeVLAN_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			// Update vid option
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", value);

			// Update Bridge VLANPort instance if exists
			Update_BridgeVLANPort_VLAN_Layer(refparam, ((struct bridge_vlan_args *)data)->bridge_sec, ((struct bridge_vlan_args *)data)->bridge_dmmap_sec, ((struct bridge_vlan_args *)data)->br_inst, value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "enabled", "1");
	return 0;
}

static int set_BridgingBridgeVLANPort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "bridge_vlanport_alias", instance, value);
}

static int set_BridgingBridgeVLANPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "bridge_vlanport_alias", instance, value);
}

static int get_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;

	dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "VLAN", value);

	if ((*value)[0] == '\0') {
		char br_vlan_path[64] = {0};
		char *vid = NULL;

		snprintf(br_vlan_path, sizeof(br_vlan_path), "Device.Bridging.Bridge.%s.VLAN.*.VLANID", args->br_inst);

		dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "vid", &vid);

		adm_entry_get_reference_param(ctx, br_vlan_path, vid, value);

		// Store Port value
		dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "VLAN", *value);
	} else {
		if (!adm_entry_object_exists(ctx, *value))
			*value = "";
	}

	return 0;
}

static int set_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	char lower_layer_path[256] = {0};
	char *allowed_objects[] = {
			lower_layer_path,
			NULL
	};
	struct dm_reference reference = {0};
	char *port_ref = NULL;

	bbf_get_reference_args(value, &reference);

	snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLAN.", args->br_inst);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			// Store VLAN value under dmmap section
			dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "VLAN", reference.path);

			// Update vid option
			dmuci_set_value_by_section(args->bridge_vlanport_sec, "vid", reference.value);

			// Update Port instance
			dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "Port", &port_ref);
			if (DM_STRLEN(port_ref)) {
				char *ifname = NULL;
				char *old_name = NULL;
				char new_name[32] = {0};

				dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "ifname", &ifname);
				if (!DM_STRLEN(ifname))
					break;

				dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "name", &old_name);

				snprintf(new_name, sizeof(new_name), "%s%s%s", ifname, DM_STRLEN(reference.value) ? "." : "", DM_STRLEN(reference.value) ? reference.value : "");

				dmuci_set_value_by_section(args->bridge_vlanport_sec, "name", new_name);

				// Update Bridge Port instance if exists
				Update_BridgePort_Port_Layer(port_ref, args->bridge_vlanport_sec, args->bridge_sec, args->bridge_dmmap_sec, args->br_inst, old_name, new_name);
			}

			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;

	dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "Port", value);

	if ((*value)[0] == '\0') {
		char br_port_path[128] = {0};
		char *name = NULL;

		snprintf(br_port_path, sizeof(br_port_path), "Device.Bridging.Bridge.%s.Port.*.Name", args->br_inst);

		dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "name", &name);

		adm_entry_get_reference_param(ctx, br_port_path, name, value);

		// Store Port value
		dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "Port", *value);
	} else {
		if (!adm_entry_object_exists(ctx, *value))
			*value = "";
	}

	return 0;
}

static int set_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	char lower_layer_path[64] = {0};
	char *allowed_objects[] = {
			lower_layer_path,
			NULL
	};
	struct dm_reference reference = {0};
	char *old_name = NULL;
	char new_name[32] = {0};
	char *vid = NULL;

	bbf_get_reference_args(value, &reference);

	snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", args->br_inst);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, reference.path, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			// Store Port value under dmmap section
			dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "Port", reference.path);

			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "vid", &vid);
			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "name", &old_name);

			snprintf(new_name, sizeof(new_name), "%s%s%s", DM_STRLEN(reference.value) ? reference.value : "",
									(DM_STRLEN(reference.value) && DM_STRLEN(vid)) ? "." : "",
									(DM_STRLEN(reference.value) && DM_STRLEN(vid)) ? vid : "");

			// Set ifname and name options
			dmuci_set_value_by_section(args->bridge_vlanport_sec, "ifname", reference.value);
			dmuci_set_value_by_section(args->bridge_vlanport_sec, "name", new_name);

			// Update Bridge Port instance if exists
			Update_BridgePort_Port_Layer(reference.path, args->bridge_vlanport_sec, args->bridge_sec, args->bridge_dmmap_sec, args->br_inst, DM_STRLEN(old_name) ? old_name : reference.value, new_name);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type;
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "type", &type);
	*value = (DM_STRLEN(type) == 0) ? "1" : "0";
	return 0;
}

static int set_BridgingBridgeVLANPort_Untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "type", (!b) ? "8021q" : "");
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct provider_bridge_args *)data)->provider_bridge_sec, "enable", "0");
	return 0;
}

static int set_BridgingBridgeProviderBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
	case VALUECHECK:
		if (bbfdm_validate_boolean(ctx, value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "enable", b ? "1" : "0");
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name = NULL;

	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->provider_bridge_sec, "name", &name);
	get_net_device_status(name, value);
	if (DM_STRCMP(*value, "Up") == 0) {
		*value = "Enabled";
	} else {
		*value = "Disabled";
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct provider_bridge_args *)data)->provider_bridge_sec, "provider_bridge_alias", instance, value);
}

static int set_BridgingBridgeProviderBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "provider_bridge_alias", value);
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *br_inst = NULL;

	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->provider_bridge_sec, "svlan_br_inst", &br_inst);
	if (DM_STRLEN(br_inst))
		dmasprintf(value, "Device.Bridging.Bridge.%s", br_inst);
	return 0;
}

static int set_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Bridging.Bridge.", NULL};
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
		set_Provider_bridge_component(refparam, ctx, data, instance, reference.value, "SVLAN");
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_CVLANcomponents(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *cvlan_list = NULL;
	struct uci_element *e = NULL;
	char cvlan_buf[2048] = {0};
	unsigned pos = 0;

	dmuci_get_value_by_section_list(((struct provider_bridge_args *)data)->provider_bridge_sec, "cvlan_br_inst", &cvlan_list);
	if (cvlan_list == NULL)
		return 0;

	cvlan_buf[0] = 0;
	/* Traverse each list value and create comma separated bridge path */
	uci_foreach_element(cvlan_list, e) {
		pos += snprintf(&cvlan_buf[pos], sizeof(cvlan_buf) - pos, "Device.Bridging.Bridge.%s,", e->name);
	}

	if (pos)
		cvlan_buf[pos - 1] = 0;

	*value = dmstrdup(cvlan_buf);
	return 0;
}

static int set_BridgingBridgeProviderBridge_CVLANcomponents(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Bridging.Bridge.", NULL};
	struct dm_reference reference = {0};
	char *pch = NULL, *pchr = NULL;
	char buf[512] = {0};

	DM_STRNCPY(buf, value, sizeof(buf));

	switch (action)	{
		case VALUECHECK:
			// Validate each item in list and Check if bridge is present
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				// Parse each Bridge path and validate:

				bbf_get_reference_args(pch, &reference);

				if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
					return FAULT_9007;
			}

			break;
		case VALUESET:
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {

				bbf_get_reference_args(pch, &reference);

				set_Provider_bridge_component(refparam, ctx, data, instance, reference.value, "CVLAN");
			}
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Bridging. *** */
DMOBJ tBridgingObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Bridge", &DMWRITE, addObjBridgingBridge, delObjBridgingBridge, NULL, browseBridgingBridgeInst, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, NULL, BBFDM_BOTH, NULL},
{"ProviderBridge", &DMWRITE, addObjBridgingProviderBridge, delObjBridgingProviderBridge, NULL, browseBridgingProviderBridgeInst, NULL, NULL, NULL, tBridgingProviderBridgeParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tBridgingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MaxBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxBridgeEntries, NULL, BBFDM_BOTH},
{"MaxDBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxDBridgeEntries, NULL, BBFDM_BOTH},
{"MaxQBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxQBridgeEntries, NULL, BBFDM_BOTH},
{"MaxVLANEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxVLANEntries, NULL, BBFDM_BOTH},
{"MaxProviderBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxProviderBridgeEntries, NULL, BBFDM_BOTH},
{"ProviderBridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridging_ProviderBridgeNumberOfEntries, NULL, BBFDM_BOTH},
{"MaxFilterEntries", &DMREAD, DMT_UNINT, get_Bridging_get_Bridging_MaxFilterEntries, NULL, BBFDM_BOTH},
{"BridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridging_BridgeNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}. ***/
DMOBJ tBridgingBridgeObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"STP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgeSTPParams, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, addObjBridgingBridgePort, delObjBridgingBridgePort, NULL, browseBridgingBridgePortInst, NULL, NULL, tBridgingBridgePortObj, tBridgingBridgePortParams, NULL, BBFDM_BOTH, NULL},
{"VLAN", &DMWRITE, addObjBridgingBridgeVLAN, delObjBridgingBridgeVLAN, NULL, browseBridgingBridgeVLANInst, NULL, NULL, NULL, tBridgingBridgeVLANParams, NULL, BBFDM_BOTH, NULL},
{"VLANPort", &DMWRITE, addObjBridgingBridgeVLANPort, delObjBridgingBridgeVLANPort, NULL, browseBridgingBridgeVLANPortInst, NULL, NULL, NULL, tBridgingBridgeVLANPortParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tBridgingBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridge_Enable, set_BridgingBridge_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridge_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridge_Alias, set_BridgingBridge_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_BridgingBridge_Name, NULL, BBFDM_BOTH, DM_FLAG_LINKER},
{"Standard", &DMWRITE, DMT_STRING, get_BridgingBridge_Standard, set_BridgingBridge_Standard, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_PortNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANPortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANPortNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.STP. ***/
DMLEAF tBridgingBridgeSTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeSTP_Enable, set_BridgingBridgeSTP_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgeSTP_Status, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_BridgingBridgeSTP_Protocol, set_BridgingBridgeSTP_Protocol, BBFDM_BOTH},
{"BridgePriority", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_BridgePriority, set_BridgingBridgeSTP_BridgePriority, BBFDM_BOTH},
{"HelloTime", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_HelloTime, set_BridgingBridgeSTP_HelloTime, BBFDM_BOTH},
{"MaxAge", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_MaxAge, set_BridgingBridgeSTP_MaxAge, BBFDM_BOTH},
{"ForwardingDelay", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_ForwardingDelay, set_BridgingBridgeSTP_ForwardingDelay, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}. ***/
DMOBJ tBridgingBridgePortObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgePortStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tBridgingBridgePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_Enable, set_BridgingBridgePort_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgePort_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Alias, set_BridgingBridgePort_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_BridgingBridgePort_Name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
//{"LastChange", &DMREAD, DMT_UNINT, get_BridgingBridgePort_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_BridgingBridgePort_LowerLayers, set_BridgingBridgePort_LowerLayers, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"ManagementPort", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_ManagementPort, set_BridgingBridgePort_ManagementPort, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Type, set_BridgingBridgePort_Type, BBFDM_BOTH},
//{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_DefaultUserPriority, set_BridgingBridgePort_DefaultUserPriority, BBFDM_BOTH},
{"PriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_PriorityRegeneration, set_BridgingBridgePort_PriorityRegeneration, BBFDM_BOTH},
//{"PortState", &DMREAD, DMT_STRING, get_BridgingBridgePort_PortState, NULL, BBFDM_BOTH},
{"PVID", &DMWRITE, DMT_INT, get_BridgingBridgePort_PVID, set_BridgingBridgePort_PVID, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_TPID, set_BridgingBridgePort_TPID, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}.Stats. ***/
DMLEAF tBridgingBridgePortStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLAN.{i}. ***/
DMLEAF tBridgingBridgeVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLAN_Enable, set_BridgingBridgeVLAN_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Alias, set_BridgingBridgeVLAN_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Name, set_BridgingBridgeVLAN_Name, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_INT, get_BridgingBridgeVLAN_VLANID, set_BridgingBridgeVLAN_VLANID, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{0}
};

/*** Bridging.Bridge.{i}.VLANPort.{i}. ***/
DMLEAF tBridgingBridgeVLANPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Enable, set_BridgingBridgeVLANPort_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_Alias, set_BridgingBridgeVLANPort_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"VLAN", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_VLAN, set_BridgingBridgeVLANPort_VLAN, BBFDM_BOTH, DM_FLAG_REFERENCE|DM_FLAG_UNIQUE},
{"Port", &DMWRITE, DMT_STRING, get_BridgingBridgeVLANPort_Port, set_BridgingBridgeVLANPort_Port, BBFDM_BOTH, DM_FLAG_REFERENCE|DM_FLAG_UNIQUE},
{"Untagged", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Untagged, set_BridgingBridgeVLANPort_Untagged, BBFDM_BOTH},
{0}
};

/*** Bridging.ProviderBridge.{i}. ***/
DMLEAF tBridgingProviderBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeProviderBridge_Enable, set_BridgingBridgeProviderBridge_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgeProviderBridge_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_Alias, set_BridgingBridgeProviderBridge_Alias, BBFDM_BOTH},
{"SVLANcomponent", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_SVLANcomponent, set_BridgingBridgeProviderBridge_SVLANcomponent, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"CVLANcomponents", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_CVLANcomponents, set_BridgingBridgeProviderBridge_CVLANcomponents, BBFDM_BOTH, DM_FLAG_REFERENCE},
{0}
};
