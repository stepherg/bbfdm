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
* LINKER FUNCTIONS
***************************************************************************/
static int get_linker_br_port(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	struct bridge_port_args *data_args = (struct bridge_port_args *)data;

	if (!data_args)
		return -1;

	if (data_args->is_management_port)
		dmuci_get_value_by_section_string(data_args->bridge_port_dmmap_sec, "port", linker);
	else
		*linker = dmstrdup(section_name(data_args->bridge_port_dmmap_sec));
	return 0;
}

static int get_linker_br_vlan(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	struct bridge_vlan_args *data_args = (struct bridge_vlan_args *)data;

	if (!data_args)
		return -1;

	dmuci_get_value_by_section_string(data_args->bridge_vlan_sec, "vid", linker);
	return 0;
}

static int get_linker_bridge(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmasprintf(linker, "%s", data ? ((struct bridge_args *)data)->br_inst : "");
	return 0;
}

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
void bridging_get_priority_list(char *uci_opt_name, void *data, char **value)
{
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;
	char uci_value[256] = {0};
	unsigned pos = 0;

	if (!data || !uci_opt_name)
		return;

	dmuci_get_value_by_section_list(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, &uci_opt_list);
	if (uci_opt_list == NULL)
		return;

	uci_value[0] = '\0';
	/* traverse each list value and create comma separated output */
	uci_foreach_element(uci_opt_list, e) {

		//delimiting priority which is in the form of x:y where y is the priority
		char *priority = strchr(e->name, ':');
		if (priority)
			pos += snprintf(&uci_value[pos], sizeof(uci_value) - pos, "%s,", priority + 1);
	}

	if (pos)
		uci_value[pos - 1] = 0;

	dmasprintf(value, "%s", uci_value);
}

void bridging_set_priority_list(char *uci_opt_name, void *data, char *value)
{
	char *pch = NULL, *pchr = NULL;
	int idx = 0;

	if (!data || !uci_opt_name || !value)
		return;

	/* delete current list values */
	dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, "");

	/* tokenize each value from received comma separated string and add it to uci file in the format x:y
	x being priority and y being priority to be mapped to */
	for (pch = strtok_r(value, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr), idx++) {
		char buf[16] = {0};

		/* convert values to uci format (x:y) and add */
		snprintf(buf, sizeof(buf), "%d%c%s", idx, ':', pch);
		dmuci_add_list_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, buf);
	}
}

static void bridge_remove_related_device_section(struct uci_section *bridge_s)
{
	struct uci_list *br_ports_list = NULL;
	struct uci_element *e = NULL;

	if (!bridge_s)
		return;

	dmuci_get_value_by_section_list(bridge_s, "ports", &br_ports_list);
	if (!br_ports_list)
		return;

	uci_foreach_element(br_ports_list, e) {
		struct uci_section *s = NULL, *stmp = NULL;

		uci_foreach_option_eq_safe("network", "device", "name", e->name, stmp, s) {
			dmuci_delete_by_section(s, NULL, NULL);
		}
	}
}

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

static void remove_bridge_sections(char *config, char *section, char *option, char *br_inst)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_path_foreach_option_eq_safe(bbfdm, config, section, option, br_inst, stmp, s) {
		dmuci_delete_by_section(s, NULL, NULL);
	}
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

	if (!device_port)
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

	if (!device_port)
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

static void set_Provider_bridge_component(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, char *component)
{
	/* *value=Device.Bridging.Bridge.{i}.
	 * In file dmmap_provider_bridge set "option svlan_br_inst {i}" or "list cvlan_br_inst {i}" in this(refered "provider_bridge" section)
	 */
	struct uci_section *s = NULL, *tmp_s = NULL, *dmmap_bridge_section = NULL;
	struct uci_section *network_bridge_sec_from = NULL, *network_bridge_sec_to = NULL;
	char pr_br_sec_name[64] = {0};
	char *br_sec_name = NULL;
	char *br_inst = NULL;

	// Get candidate bridge instance
	adm_entry_get_linker_value(ctx, value, &br_inst);
	if (DM_STRLEN(br_inst) == 0)
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

		dmuci_add_list_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "cvlan_br_inst", br_inst);
	} else if (DM_LSTRCMP(component, "SVLAN") == 0) {
		// Set svlan_br_inst in dmmap_provider_bridgei->provider_bridge section

		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "svlan_br_inst", br_inst);
	}

	/* Add candidate bridge to this provider bridge instance(network->device->pr_br_{i}) */
	// Get network->device(bridge) section name from dmmap_bridge_port->bridge_port->device_section_name
	dmmap_bridge_section = get_dup_section_in_dmmap_opt("dmmap_bridge", "device", "bridge_instance", br_inst);
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

	if (!device || DM_STRLEN(device) == 0)
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

static bool is_section_exist(char *dmmap, char *section, char *opt1_name, char *opt1_value, char *opt2_name, char *opt2_value)
{
	struct uci_section *s = NULL;


	uci_path_foreach_option_eq(bbfdm, dmmap, section, opt1_name, opt1_value, s) {
		char *opt_value = NULL;

		dmuci_get_value_by_section_string(s, opt2_name, &opt_value);
		if (DM_STRCMP(opt_value, opt2_value) == 0)
			return true;
	}

	return false;
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

		uci_foreach_option_eq("network", "device", "name", e->name, s) {
			char *vid = NULL;

			dmuci_get_value_by_section_string(s, "vid", &vid);

			if (vid && vid[0] == '\0') {
				char *ifname = DM_STRCHR(e->name, '.');
				if (ifname) vid = dmstrdup(ifname+1);
			}

			if (vid && vid[0] == '\0')
				break;

			if (is_section_exist("dmmap_bridge_vlan", "bridge_vlan", "br_inst", args->br_inst, "vid", vid))
				break;

			if (get_dup_section_in_dmmap_opt("dmmap_bridge_vlan", "bridge_vlan", "vid", vid))
				break;

			struct uci_section *br_vlan_s = NULL;
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

		// port device is available in ports list ==> skip it
		char *name;
		dmuci_get_value_by_section_string(s, "name", &name);
		if (value_exists_in_uci_list(br_ports_list, name))
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_element(br_ports_list, e) {

		uci_foreach_option_eq("network", "device", "name", e->name, s) {

			if (is_section_exist("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", args->br_inst, "name", e->name))
				break;

			if (get_dup_section_in_dmmap_opt("dmmap_bridge_vlanport", "bridge_vlanport", "name", e->name))
				break;

			struct uci_section *br_vlanport_s = NULL;
			struct uci_section *br_port_sec_name = get_dup_section_in_dmmap_opt("dmmap_bridge_port", "bridge_port", "port", e->name);

			dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &br_vlanport_s);
			dmuci_set_value_by_section(br_vlanport_s, "name", e->name);
			dmuci_set_value_by_section(br_vlanport_s, "port_name", br_port_sec_name ? section_name(br_port_sec_name) : "");
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

	if (DM_LSTRCMP(s_user, "1") != 0 && !is_section_exist("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "management", "1"))
		create_new_bridge_port_section("network", dev_name, args->br_inst, "1");

	if (br_ports_list) {
		uci_foreach_element(br_ports_list, e) {

			if (is_section_exist("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "port", e->name))
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

		if (is_section_exist("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "port", ifname))
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

	/* Find the ethport ports section corresponding to this device */
	uci_foreach_option_eq("ports", "ethport", "ifname", port, s) {
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

static void remove_vlanid_from_bridge_secions(struct uci_section *bridge_sec, struct uci_section *bridge_dmmap_sec, char *curr_vid)
{
	struct uci_list *device_ports = NULL;
	struct uci_element *e = NULL, *tmp = NULL;

	if (!bridge_sec || !bridge_dmmap_sec || !curr_vid)
		return;

	dmuci_get_value_by_section_list(bridge_sec, "ports", &device_ports);
	if (device_ports == NULL)
		return;

	uci_foreach_element_safe(device_ports, tmp, e) {
		char *vid = DM_STRCHR(e->name, '.');

		if (vid && curr_vid && DM_STRCMP(vid+1, curr_vid) == 0) {
			struct uci_section *s = NULL;
			char *ifname = NULL;
			char *enable = NULL;

			s = get_dup_section_in_config_opt("network", "device", "name", e->name);
			dmuci_get_value_by_section_string(s, "ifname", &ifname);

			if (!s || DM_STRLEN(ifname) == 0)
				continue;

			/* Update vid and name of device section */
			dmuci_set_value_by_section(s, "vid", "");
			dmuci_set_value_by_section(s, "name", ifname);

			/* Update name option in dmmap_bridge_vlanport if exists */
			s = get_dup_section_in_dmmap_opt("dmmap_bridge_vlanport", "bridge_vlanport", "name", e->name);
			dmuci_set_value_by_section(s, "name", ifname);

			/* Update port option in dmmap_bridge_port if exists */
			s = get_dup_section_in_dmmap_opt("dmmap_bridge_port", "bridge_port", "port", e->name);
			dmuci_set_value_by_section(s, "port", ifname);
			dmuci_get_value_by_section_string(s, "enabled", &enable);

			if (DM_STRCMP(enable, "1") == 0) {
				/* Update bridge sections */
				remove_port_from_bridge_sections(bridge_sec, bridge_dmmap_sec, e->name);
				add_port_to_bridge_sections(bridge_sec, bridge_dmmap_sec, ifname);
			}
		}
	}
}

static void remove_vlanport_section(struct uci_section *bridge_vlanport_sec, struct uci_section *bridge_vlanport_dmmap_sec,
		struct uci_section *bridge_sec, struct uci_section *bridge_dmmap_sec)
{
	char *port_sec_name = NULL;

	if (!bridge_vlanport_sec || !bridge_vlanport_dmmap_sec ||
		!bridge_sec || !bridge_dmmap_sec)
		return;

	// Remove vlan port section
	dmuci_delete_by_section(bridge_vlanport_sec, NULL, NULL);

	// Get port name from dmmap section
	dmuci_get_value_by_section_string(bridge_vlanport_dmmap_sec, "port_name", &port_sec_name);
	if (DM_STRLEN(port_sec_name) == 0)
		return;

	struct uci_section *port_s = get_dup_section_in_dmmap("dmmap_bridge_port", "bridge_port", port_sec_name);
	if (port_s) {
		char *enable = NULL;
		char *port = NULL;

		dmuci_get_value_by_section_string(port_s, "enabled", &enable);
		dmuci_get_value_by_section_string(port_s, "port", &port);

		char *vid = port ? DM_STRCHR(port, '.') : NULL;
		if (vid) {

			if (DM_STRCMP(enable, "1") == 0) {
				/* Remove port from port list */
				remove_port_from_bridge_sections(bridge_sec, bridge_dmmap_sec, port);
			}

			/* Remove vid from port */
			vid[0] = '\0';

			if (DM_STRCMP(enable, "1") == 0) {
				/* Add new port to port list */
				add_port_to_bridge_sections(bridge_sec, bridge_dmmap_sec, port);
			}

			// dmmap_bridge_port: Update port option
			dmuci_set_value_by_section(port_s, "port", port);
		}
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

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Bridging.Bridge.{i}.!UCI:network/device/dmmap_bridge*/
static int browseBridgingBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args curr_bridging_args = {0};
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_bridge_config_sections_with_dmmap_bridge_eq("network", "device", "dmmap_bridge", "type", "bridge", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "bridge_instance", "bridge_alias");

		init_bridging_args(&curr_bridging_args, p->config_section ? p->config_section : p->dmmap_section, p->dmmap_section, inst);

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
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlan sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlanport sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove cvlan/svaln from dmmap_provider_bridge section if this bridge instance is a part of it
			remove_bridge_from_provider_bridge(((struct bridge_args *)data)->br_inst);

			// Remove all related device bridge section
			bridge_remove_related_device_section(((struct bridge_args *)data)->bridge_sec);

			// Remove interface bridge that maps to this device
			remove_device_from_bridge_interface(((struct bridge_args *)data)->bridge_sec);

			// Remove device bridge section
			dmuci_delete_by_section(((struct bridge_args *)data)->bridge_sec, NULL, NULL);

			// Remove dmmap device bridge section
			dmuci_delete_by_section(((struct bridge_args *)data)->bridge_dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("network", "device", "type", "bridge", stmp, s) {
				struct uci_section *dmmap_section = NULL;
				char *bridge_inst = NULL;

				get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(s), &dmmap_section);
				dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &bridge_inst);

				// Remove all bridge port sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", bridge_inst);

				// Remove all bridge vlan sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", bridge_inst);

				// Remove all bridge vlanport sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", bridge_inst);

				// Remove cvlan/svaln from dmmap_provider_bridge section if this bridge instance is a part of it
				remove_bridge_from_provider_bridge(bridge_inst);

				// Remove all related device bridge section
				bridge_remove_related_device_section(s);

				// Remove interface bridge that maps to this device
				remove_device_from_bridge_interface(s);

				// Remove dmmap device bridge section
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove device bridge section
				dmuci_delete_by_section(s, NULL, NULL);
			}
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
	struct uci_section *s = NULL, *stmp = NULL;
	char *port = NULL;

	switch (del_action) {
	case DEL_INST:
		// Get device from dmmap section
		dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);

		if (DM_STRLEN(port) == 0 || args->is_management_port) {
			// Remove only dmmap section
			dmuci_delete_by_section_bbfdm(args->bridge_port_dmmap_sec, NULL, NULL);
		} else if (port && *port) {

			// Remove network option from wireless wifi-iface section
			s = get_dup_section_in_config_opt("wireless", "wifi-iface", "device", port);
			dmuci_set_value_by_section(s, "network", "");

			// Remove dmmap section
			dmuci_delete_by_section_bbfdm(args->bridge_port_dmmap_sec, NULL, NULL);

			// Remove ifname from device section
			s = get_dup_section_in_config_opt("network", "device", "name", port);
			dmuci_set_value_by_section(s, "ifname", "");
			dmuci_set_value_by_section(s, "name", "");

			// Remove port from vlan port section
			s = get_dup_section_in_dmmap_opt("dmmap_bridge_vlanport", "bridge_vlanport", "name", port);
			dmuci_set_value_by_section(s, "name", "");

			// Remove port from port list
			remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
			char *management = NULL;

			dmuci_get_value_by_section_string(s, "management", &management);
			dmuci_get_value_by_section_string(s, "port", &port);

			if (DM_STRLEN(port) && DM_LSTRCMP(management, "0") == 0) {
				struct uci_section *ss = NULL;

				// Remove network option from wireless wifi-iface section
				ss = get_dup_section_in_config_opt("wireless", "wifi-iface", "device", port);
				dmuci_set_value_by_section(ss, "network", "");

				// Remove ifname from device section
				ss = get_dup_section_in_config_opt("network", "device", "name", port);
				dmuci_set_value_by_section(ss, "ifname", "");
				dmuci_set_value_by_section(ss, "name", "");

				// Remove ifname from vlan port section
				ss = get_dup_section_in_dmmap_opt("dmmap_bridge_vlanport", "bridge_vlanport", "name", port);
				dmuci_set_value_by_section(ss, "name", "");

				// Remove port from port list
				remove_port_from_bridge_sections(((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->bridge_dmmap_sec, port);
			}

			dmuci_delete_by_section_bbfdm(s, NULL, NULL);
		}
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
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		remove_vlanport_section(args->bridge_vlanport_sec, args->bridge_vlanport_dmmap_sec, args->bridge_sec, args->bridge_dmmap_sec);

		// Remove dmmap section
		dmuci_delete_by_section_bbfdm(args->bridge_vlanport_dmmap_sec, NULL, NULL);
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
			struct uci_section *vlan_port_sec = NULL;
			char *vlan_port_sec_name = NULL;

			dmuci_get_value_by_section_string(s, "section_name", &vlan_port_sec_name);
			vlan_port_sec = get_origin_section_from_config("network", "device", vlan_port_sec_name);

			remove_vlanport_section(vlan_port_sec, s, ((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->bridge_dmmap_sec);

			// Remove dmmap section
			dmuci_delete_by_section_bbfdm(s, NULL, NULL);
		}
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
	struct uci_section *s = NULL, *stmp = NULL;
	char *vid = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_get_value_by_section_string(args->bridge_vlan_sec, "vid", &vid);

		// Remove all vid from bridge sections
		remove_vlanid_from_bridge_secions(args->bridge_sec, args->bridge_dmmap_sec, vid);

		// Remove dmmap section
		dmuci_delete_by_section_bbfdm(args->bridge_vlan_sec, NULL, NULL);
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
			dmuci_get_value_by_section_string(s, "vid", &vid);

			// Remove all vid from bridge sections
			remove_vlanid_from_bridge_secions(((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->bridge_dmmap_sec, vid);

			// Remove dmmap section
			dmuci_delete_by_section_bbfdm(s, NULL, NULL);
		}
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
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		delete_provider_bridge(((struct provider_bridge_args *)data)->provider_bridge_sec);
		break;
	case DEL_ALL:
		uci_path_foreach_sections_safe(bbfdm, "dmmap_provider_bridge", "provider_bridge", stmp, s) {
			delete_provider_bridge(s);
		}
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
			if (dm_validate_boolean(value))
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

/*#Device.Bridging.Bridge.{i}.Alias!UCI:dmmap_bridge/device,@i-1/bridge_alias*/
static int get_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_dmmap_sec, "bridge_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_dmmap_sec, "bridge_alias", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridge_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "802.1Q-2011";
	return 0;
}

static int set_BridgingBridge_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, BridgeStandard, NULL))
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
			if (dm_validate_boolean(value))
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
			if (dm_validate_string(value, -1, -1, Protocol, NULL))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","61440"}}, 1))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"100","1000"}}, 1))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"600","4000"}}, 1))
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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"4","30"}}, 1))
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
			if (dm_validate_boolean(value))
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
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "bridge_port_alias", value);
	if ((*value)[0] == '\0') {
		if (!args->is_management_port)
			dmuci_get_value_by_section_string(args->bridge_port_sec, "name", value);
		if ((*value)[0] == '\0')
			dmasprintf(value, "cpe-%s", instance);
	}
	return 0;
}

static int set_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "bridge_port_alias", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;

	if (args->is_management_port) {
		*value = "";
	} else {
		dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", value);
	}

	return 0;
}

static int get_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	struct uci_section *port_s = NULL;

	if (args->is_management_port) {
		char lbuf[1024] = {0};
		unsigned pos = 0;

		lbuf[0] = 0;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, port_s) {
			char *curr_port_s = section_name(port_s);

			if (strcmp(curr_port_s, section_name(args->bridge_port_dmmap_sec)) == 0)
				continue;

			adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", curr_port_s, value);
			if (*value && (*value)[0] != 0)
				pos += snprintf(&lbuf[pos], sizeof(lbuf) - pos, "%s,", *value);
		}

		if (pos)
			lbuf[pos - 1] = 0;

		*value = dmstrdup(lbuf);
	} else {
		char *type = NULL;
		char *port = NULL;
		char *config = NULL;

		dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port);
		if (DM_STRLEN(port) == 0)
			return 0;

		dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "type", &type);
		if (DM_STRCMP(type, "34984") == 0) {
			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "LowerLayer", value);
			return 0;
		}

		dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "config", &config);

		if (DM_LSTRCMP(config, "network") == 0) {
			adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", port, value);
			if (!(*value) || (*value)[0] == 0) {
				char *tag = DM_STRCHR(port, '.');
				if (tag) tag[0] = '\0';
			} else {
				return 0;
			}
		}

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", port, value);
		if (!(*value) || (*value)[0] == 0)
			adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", port, value);
	}
	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = (struct bridge_port_args *)data;
	bool is_wireless_config = false;
	char *port_enabled = NULL;
	char *port_device = NULL;
	char *linker = NULL;
	char *type = NULL;
	char *allowed_objects[] = {
			"Device.Ethernet.Interface.",
			"Device.WiFi.SSID.",
			"Device.Bridging.Bridge.*.Port.",
			NULL};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (args->is_management_port)
				return 0;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "type", &type);
			if (DM_LSTRNCMP(value, "Device.Bridging.Bridge.", 23) == 0 && DM_STRCMP(type, "34984") != 0)
				return FAULT_9007;

			return 0;
		case VALUESET:
			if (args->is_management_port)
				return 0;

			adm_entry_get_linker_value(ctx, value, &linker);

			if (!linker || *linker == 0) {
				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "port", "");
				return 0;
			}

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "port", &port_device);
			if (DM_STRCMP(linker, port_device) == 0) // Same as already configured
				return 0;

			// Update config section on dmmap_bridge_port if the linker is wirelss port or network port
			if (DM_LSTRNCMP(value, "Device.WiFi.SSID.", 17) == 0) {
				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "config", "wireless");
				is_wireless_config = true;
			} else
				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "config", "network");

			if (match(value, "Device.Bridging.Bridge.*.Port.")) {
				struct uci_section *s = get_origin_section_from_dmmap("dmmap_bridge_port", "bridge_port", linker);
				dmuci_get_value_by_section_string(s, "port", &linker);

				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "LowerLayer", value);
			}

			dmuci_get_value_by_section_string(args->bridge_port_dmmap_sec, "enabled", &port_enabled);
			if (port_device[0] == '\0') {

				if (DM_STRCMP(port_enabled, "1") == 0) {
					// Add port to ports list
					add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, linker);
				}

				// Update port option in dmmap
				dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "port", linker);
			} else {

				if (DM_STRCMP(port_enabled, "1") == 0) {
					// Remove port from port list interface
					remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port_device);
				}

				char *tag = DM_STRCHR(port_device, '.');
				if (tag && !is_wireless_config) {
					char *cur_vid = dmstrdup(tag+1);
					char new_name[32] = {0};

					snprintf(new_name, sizeof(new_name), "%s.%s", linker, cur_vid);

					if (DM_STRCMP(port_enabled, "1") == 0) {
						// Add port to ports list
						add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, new_name);
					}

					// Update port option in dmmap
					dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "port", new_name);

					// Check if there is a vlan port maps to this port
					if (args->bridge_sec) {
						struct uci_section *s = NULL;

						dmuci_set_value_by_section(args->bridge_sec, "ifname", linker);
						dmuci_set_value_by_section(args->bridge_sec, "name", new_name);
						s = get_dup_section_in_dmmap("dmmap_bridge_vlanport", "bridge_vlanport", section_name(args->bridge_sec));
						dmuci_set_value_by_section(s, "name", new_name);
					}
				} else {
					if (DM_STRCMP(port_enabled, "1") == 0) {
						// Add port to ports list
						add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, linker);
					}

					// Update port option in dmmap
					dmuci_set_value_by_section(args->bridge_port_dmmap_sec, "port", linker);
				}
			}
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

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;

			string_to_bool(value, &b);

			if (args->is_management_port == b)
				return 0;

			if (b && is_section_exist("dmmap_bridge_port", "bridge_port", "br_inst", args->br_inst, "management", "1"))
				return FAULT_9007;

			return 0;
		case VALUESET:
			string_to_bool(value, &b);

			if (args->is_management_port == b)
				return 0;

			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "name", &bridge_name);

			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", b ? "1" : "0");
			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", b ? bridge_name : "");
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bridging_get_priority_list("ingress_qos_mapping", data, value);
	return 0;
}

static int set_BridgingBridgePort_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_port_args *args = ((struct bridge_port_args *)data);
	char *type = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, 8, 8, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;

			if (args->is_management_port)
				return 0;

			dmuci_get_value_by_section_string(args->bridge_port_sec, "type", &type);
			if (DM_STRLEN(type) == 0)
				return FAULT_9007;

			break;
		case VALUESET:
			if (args->is_management_port)
				return 0;

			bridging_set_priority_list("ingress_qos_mapping", data, value);
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
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
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

			// Check if there is a vlan port maps to this port
			struct uci_section *s = get_dup_section_in_dmmap("dmmap_bridge_vlanport", "bridge_vlanport", section_name(args->bridge_port_sec));
			dmuci_set_value_by_section(s, "name", new_name);

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
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
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
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "bridge_vlan_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridgeVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "bridge_vlan_alias", value);
			return 0;
	}
	return 0;
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
			if (dm_validate_string(value, -1, 64, NULL, NULL))
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
	struct bridge_vlan_args *args = (struct bridge_vlan_args *)data;


	struct uci_list *device_ports = NULL;
	struct uci_element *e = NULL, *tmp = NULL;
	char *curr_vid = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(args->bridge_vlan_sec, "vid", &curr_vid);
			if (DM_STRCMP(curr_vid, value) == 0)
				return 0;

			dmuci_set_value_by_section(args->bridge_vlan_sec, "vid", value);

			dmuci_get_value_by_section_list(args->bridge_sec, "ports", &device_ports);
			if (device_ports == NULL)
				return 0;

			uci_foreach_element_safe(device_ports, tmp, e) {
				char *vid = DM_STRCHR(e->name, '.');

				if (vid && curr_vid && DM_STRCMP(vid+1, curr_vid) == 0) {
					struct uci_section *s = NULL;
					char *ifname = NULL;
					char *enable = NULL;
					char name[16] = {0};

					s = get_dup_section_in_config_opt("network", "device", "name", e->name);
					dmuci_get_value_by_section_string(s, "ifname", &ifname);

					if (!s || DM_STRLEN(ifname) == 0)
						continue;

					snprintf(name, sizeof(name), "%s.%s", ifname, value);

					/* Update vid and name of device section */
					dmuci_set_value_by_section(s, "vid", value);
					dmuci_set_value_by_section(s, "name", name);

					/* Update name option in dmmap_bridge_vlanport if exists */
					s = get_dup_section_in_dmmap_opt("dmmap_bridge_vlanport", "bridge_vlanport", "name", e->name);
					dmuci_set_value_by_section(s, "name", name);

					/* Update port option in dmmap_bridge_port if exists */
					s = get_dup_section_in_dmmap_opt("dmmap_bridge_port", "bridge_port", "port", e->name);
					dmuci_set_value_by_section(s, "port", name);
					dmuci_get_value_by_section_string(s, "enabled", &enable);

					if (DM_STRCMP(enable, "1") == 0) {
						/* Update bridge section port list */
						remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, e->name);
						add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, name);
					}
				}
			}
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
			if (dm_validate_boolean(value))
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
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "bridge_vlanport_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridgeVLANPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "bridge_vlanport_alias", value);
			break;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	char *vid = NULL;

	dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "vid", &vid);
	if (DM_STRLEN(vid) == 0) {
		*value = "";
	} else {
		char br_vlan_path[32] = {0};

		snprintf(br_vlan_path, sizeof(br_vlan_path),"Device.Bridging.Bridge.%s.VLAN.", args->br_inst);
		adm_entry_get_linker_param(ctx, br_vlan_path, vid, value);
	}
	return 0;
}

static int set_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	char lower_layer_path[256] = {0};
	char *allowed_objects[] = {
			lower_layer_path,
			NULL};
	char *ifname = NULL, *name = NULL, *vid = NULL;
	char *linker = NULL;
	char new_name[32] = {0};

	snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLAN.", args->br_inst);

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			/* Get the current vid, ifname and name in the device section */
			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "ifname", &ifname);
			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "name", &name);
			dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "vid", &vid);

			adm_entry_get_linker_value(ctx, value, &linker);

			if (DM_STRLEN(linker) == 0 && DM_STRLEN(vid) == 0)
				return 0;

			if (DM_STRLEN(name) != 0) {
				char *enable = NULL;

				/* create name option */
				snprintf(new_name, sizeof(new_name), "%s%s%s", ifname , (DM_STRLEN(linker) == 0) ? "": ".", (DM_STRLEN(linker) == 0) ? "": linker);

				/* Update device network section */
				dmuci_set_value_by_section(args->bridge_vlanport_sec, "name", new_name);

				/* Update port in dmmap bridge_port section */
				char *port_sec_name = NULL;
				dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "port_name", &port_sec_name);
				struct uci_section *s = get_origin_section_from_dmmap("dmmap_bridge_port", "bridge_port", port_sec_name);
				dmuci_set_value_by_section(s, "port", new_name);
				dmuci_get_value_by_section_string(s, "enabled", &enable);

				if (DM_STRCMP(enable, "1") == 0) {
					/* Update ports list */
					remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, name);
					add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, new_name);
				}

				/* Update name dmmap section */
				dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "name", new_name);
			}

			dmuci_set_value_by_section(args->bridge_vlanport_sec, "vid", (DM_STRLEN(linker) == 0) ? "": linker);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	char *port_name = NULL;

	dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "port_name", &port_name);
	if (DM_STRLEN(port_name) == 0) {
		*value = "";
	} else {
		char br_port_path[128] = {0};

		snprintf(br_port_path, sizeof(br_port_path), "Device.Bridging.Bridge.%s.Port.", args->br_inst);
		adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", port_name, value);
	}
	return 0;
}

static int set_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct bridge_vlanport_args *args = (struct bridge_vlanport_args *)data;
	struct uci_section *s = NULL;
	char lower_layer_path[64] = {0};
	char *allowed_objects[] = {
			lower_layer_path,
			NULL};
	char *linker = NULL;

	snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", args->br_inst);

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);

			if (!linker || *linker == '\0') {
				char *ifname = NULL;
				char *name = NULL;
				char *enable = NULL;

				dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "ifname", &ifname);
				dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "name", &name);
				if (DM_STRLEN(name) == 0)
					return 0;

				/* Update device section */
				dmuci_set_value_by_section(args->bridge_vlanport_sec, "name", "");
				dmuci_set_value_by_section(args->bridge_vlanport_sec, "ifname", "");

				/* Update dmmap vlanport section */
				dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "name", "");
				dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "port_name", "");

				/* Update port in dmmap bridge_port section */
				char *port_sec_name = NULL;
				dmuci_get_value_by_section_string(args->bridge_vlanport_dmmap_sec, "port_name", &port_sec_name);
				s = get_origin_section_from_dmmap("dmmap_bridge_port", "bridge_port", port_sec_name);
				dmuci_set_value_by_section(s, "port", ifname);
				dmuci_get_value_by_section_string(s, "enabled", &enable);

				if (DM_STRCMP(enable, "1") == 0) {
					/* Update ports list */
					remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, name);
					add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, ifname);
				}
			} else {
				char *vid = NULL;
				char *port = NULL;
				char *enable = NULL;
				char *type = NULL;

				dmuci_get_value_by_section_string(args->bridge_vlanport_sec, "vid", &vid);

				s = get_origin_section_from_dmmap("dmmap_bridge_port", "bridge_port", linker);
				dmuci_get_value_by_section_string(s, "port", &port);
				dmuci_get_value_by_section_string(s, "enabled", &enable);
				dmuci_get_value_by_section_string(s, "type", &type);

				if (!s || DM_STRLEN(port) == 0)
					return 0;

				if (DM_STRLEN(vid) == 0) {
					/* Update device section */
						dmuci_set_value_by_section(args->bridge_vlanport_sec, "name", port);
						dmuci_set_value_by_section(args->bridge_vlanport_sec, "ifname", port);

						/* Update dmmap vlanport section */
						dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "name", port);
				} else {
					char port_name[32] = {0};

					if (DM_STRCMP(enable, "1") == 0) {
						/* Remove port from ports list */
						remove_port_from_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port);
					}

					if (DM_STRCMP(type, "34984") != 0) { // type:34984=>'8021ad'
						char *tag = DM_STRCHR(port, '.');
						if (tag) tag[0] = '\0';
					} else {
						dmuci_set_value_by_section(args->bridge_vlanport_sec, "type", "8021ad");
					}

					/* Create the new ifname */
					snprintf(port_name, sizeof(port_name), "%s.%s", port, vid);

					/* Update device section */
					dmuci_set_value_by_section(args->bridge_vlanport_sec, "name", port_name);
					dmuci_set_value_by_section(args->bridge_vlanport_sec, "ifname", port);

					if (DM_STRCMP(enable, "1") == 0) {
						/* Add new port to ports list */
						add_port_to_bridge_sections(args->bridge_sec, args->bridge_dmmap_sec, port_name);
					}

					/* Update dmmap section */
					dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "name", port_name);

					/* Update port in dmmap bridge_port section */
					dmuci_set_value_by_section(s, "port", port_name);
				}

				dmuci_set_value_by_section(args->bridge_vlanport_dmmap_sec, "port_name", linker);
			}
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
			if (dm_validate_boolean(value))
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
		if (dm_validate_boolean(value))
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
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->provider_bridge_sec, "provider_bridge_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridgeProviderBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 64, NULL, NULL))
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

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, NULL))
			return FAULT_9007;

		if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
			return FAULT_9007;

		break;
	case VALUESET:
		set_Provider_bridge_component(refparam, ctx, data, instance, value, "SVLAN");
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
	char *pch = NULL, *pchr = NULL;
	char buf[512] = {0};

	DM_STRNCPY(buf, value, sizeof(buf));

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 256, NULL, NULL))
				return FAULT_9007;

			// Validate each item in list and Check if bridge is present
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				// Parse each Bridge path and validate:

				if (dm_entry_validate_allowed_objects(ctx, pch, allowed_objects))
					return FAULT_9007;
			}

			break;
		case VALUESET:
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr))
				set_Provider_bridge_component(refparam, ctx, data, instance, pch, "CVLAN");
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
{"Bridge", &DMWRITE, addObjBridgingBridge, delObjBridgingBridge, NULL, browseBridgingBridgeInst, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, get_linker_bridge, BBFDM_BOTH, LIST_KEY{"Alias", NULL}, "2.0"},
{"ProviderBridge", &DMWRITE, addObjBridgingProviderBridge, delObjBridgingProviderBridge, NULL, browseBridgingProviderBridgeInst, NULL, NULL, NULL, tBridgingProviderBridgeParams, NULL, BBFDM_BOTH, NULL, "2.7"},
{0}
};

DMLEAF tBridgingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"MaxBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxBridgeEntries, NULL, BBFDM_BOTH, "2.0"},
{"MaxDBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxDBridgeEntries, NULL, BBFDM_BOTH, "2.0"},
{"MaxQBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxQBridgeEntries, NULL, BBFDM_BOTH, "2.0"},
{"MaxVLANEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxVLANEntries, NULL, BBFDM_BOTH, "2.0"},
{"MaxProviderBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxProviderBridgeEntries, NULL, BBFDM_BOTH, "2.7"},
{"ProviderBridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridging_ProviderBridgeNumberOfEntries, NULL, BBFDM_BOTH, "2.7"},
{"MaxFilterEntries", &DMREAD, DMT_UNINT, get_Bridging_get_Bridging_MaxFilterEntries, NULL, BBFDM_BOTH, "2.0"},
{"BridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridging_BridgeNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/*** Bridging.Bridge.{i}. ***/
DMOBJ tBridgingBridgeObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"STP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgeSTPParams, NULL, BBFDM_BOTH, NULL, "2.16"},
{"Port", &DMWRITE, addObjBridgingBridgePort, delObjBridgingBridgePort, NULL, browseBridgingBridgePortInst, NULL, NULL, tBridgingBridgePortObj, tBridgingBridgePortParams, get_linker_br_port, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}, "2.0"},
{"VLAN", &DMWRITE, addObjBridgingBridgeVLAN, delObjBridgingBridgeVLAN, NULL, browseBridgingBridgeVLANInst, NULL, NULL, NULL, tBridgingBridgeVLANParams, get_linker_br_vlan, BBFDM_BOTH, LIST_KEY{"VLANID", "Alias", NULL}, "2.0"},
{"VLANPort", &DMWRITE, addObjBridgingBridgeVLANPort, delObjBridgingBridgeVLANPort, NULL, browseBridgingBridgeVLANPortInst, NULL, NULL, NULL, tBridgingBridgeVLANPortParams, NULL, BBFDM_BOTH, LIST_KEY{"VLAN", "Port", "Alias", NULL}, "2.0"},
{0}
};

DMLEAF tBridgingBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridge_Enable, set_BridgingBridge_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridge_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridge_Alias, set_BridgingBridge_Alias, BBFDM_BOTH, "2.0"},
{"Standard", &DMWRITE, DMT_STRING, get_BridgingBridge_Standard, set_BridgingBridge_Standard, BBFDM_BOTH, "2.0"},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_PortNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"VLANNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{"VLANPortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANPortNumberOfEntries, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/*** Bridging.Bridge.{i}.STP. ***/
DMLEAF tBridgingBridgeSTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeSTP_Enable, set_BridgingBridgeSTP_Enable, BBFDM_BOTH, "2.16"},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgeSTP_Status, NULL, BBFDM_BOTH, "2.16"},
{"Protocol", &DMWRITE, DMT_STRING, get_BridgingBridgeSTP_Protocol, set_BridgingBridgeSTP_Protocol, BBFDM_BOTH, "2.16"},
{"BridgePriority", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_BridgePriority, set_BridgingBridgeSTP_BridgePriority, BBFDM_BOTH, "2.16"},
{"HelloTime", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_HelloTime, set_BridgingBridgeSTP_HelloTime, BBFDM_BOTH, "2.16"},
{"MaxAge", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_MaxAge, set_BridgingBridgeSTP_MaxAge, BBFDM_BOTH, "2.16"},
{"ForwardingDelay", &DMWRITE, DMT_UNINT, get_BridgingBridgeSTP_ForwardingDelay, set_BridgingBridgeSTP_ForwardingDelay, BBFDM_BOTH, "2.16"},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}. ***/
DMOBJ tBridgingBridgePortObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgePortStatsParams, NULL, BBFDM_BOTH, NULL, "2.0"},
{0}
};

DMLEAF tBridgingBridgePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_Enable, set_BridgingBridgePort_Enable, BBFDM_BOTH, "2.0"},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgePort_Status, NULL, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Alias, set_BridgingBridgePort_Alias, BBFDM_BOTH, "2.0"},
{"Name", &DMREAD, DMT_STRING, get_BridgingBridgePort_Name, NULL, BBFDM_BOTH, "2.0"},
//{"LastChange", &DMREAD, DMT_UNINT, get_BridgingBridgePort_LastChange, NULL, BBFDM_BOTH, "2.0"},
{"LowerLayers", &DMWRITE, DMT_STRING, get_BridgingBridgePort_LowerLayers, set_BridgingBridgePort_LowerLayers, BBFDM_BOTH, "2.0"},
{"ManagementPort", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_ManagementPort, set_BridgingBridgePort_ManagementPort, BBFDM_BOTH, "2.0"},
//{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Type, set_BridgingBridgePort_Type, BBFDM_BOTH, "2.7"},
//{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_DefaultUserPriority, set_BridgingBridgePort_DefaultUserPriority, BBFDM_BOTH, "2.0"},
{"PriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_PriorityRegeneration, set_BridgingBridgePort_PriorityRegeneration, BBFDM_BOTH, "2.0"},
//{"PortState", &DMREAD, DMT_STRING, get_BridgingBridgePort_PortState, NULL, BBFDM_BOTH, "2.0"},
{"PVID", &DMWRITE, DMT_INT, get_BridgingBridgePort_PVID, set_BridgingBridgePort_PVID, BBFDM_BOTH, "2.0"},
{"TPID", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_TPID, set_BridgingBridgePort_TPID, BBFDM_BOTH, "2.7"},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}.Stats. ***/
DMLEAF tBridgingBridgePortStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesSent, NULL, BBFDM_BOTH, "2.0"},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesReceived, NULL, BBFDM_BOTH, "2.0"},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsSent, NULL, BBFDM_BOTH, "2.0"},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsReceived, NULL, BBFDM_BOTH, "2.0"},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{0}
};

/*** Bridging.Bridge.{i}.VLAN.{i}. ***/
DMLEAF tBridgingBridgeVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLAN_Enable, set_BridgingBridgeVLAN_Enable, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Alias, set_BridgingBridgeVLAN_Alias, BBFDM_BOTH, "2.0"},
{"Name", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Name, set_BridgingBridgeVLAN_Name, BBFDM_BOTH, "2.0"},
{"VLANID", &DMWRITE, DMT_INT, get_BridgingBridgeVLAN_VLANID, set_BridgingBridgeVLAN_VLANID, BBFDM_BOTH, "2.0"},
{0}
};

/*** Bridging.Bridge.{i}.VLANPort.{i}. ***/
DMLEAF tBridgingBridgeVLANPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Enable, set_BridgingBridgeVLANPort_Enable, BBFDM_BOTH, "2.0"},
{"Alias", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_Alias, set_BridgingBridgeVLANPort_Alias, BBFDM_BOTH, "2.0"},
{"VLAN", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_VLAN, set_BridgingBridgeVLANPort_VLAN, BBFDM_BOTH, "2.0"},
{"Port", &DMWRITE, DMT_STRING, get_BridgingBridgeVLANPort_Port, set_BridgingBridgeVLANPort_Port, BBFDM_BOTH, "2.0"},
{"Untagged", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Untagged, set_BridgingBridgeVLANPort_Untagged, BBFDM_BOTH, "2.0"},
{0}
};

/*** Bridging.ProviderBridge.{i}. ***/
DMLEAF tBridgingProviderBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeProviderBridge_Enable, set_BridgingBridgeProviderBridge_Enable, BBFDM_BOTH, "2.7"},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgeProviderBridge_Status, NULL, BBFDM_BOTH, "2.7"},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_Alias, set_BridgingBridgeProviderBridge_Alias, BBFDM_BOTH, "2.7"},
{"SVLANcomponent", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_SVLANcomponent, set_BridgingBridgeProviderBridge_SVLANcomponent, BBFDM_BOTH, "2.7"},
{"CVLANcomponents", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_CVLANcomponents, set_BridgingBridgeProviderBridge_CVLANcomponents, BBFDM_BOTH, "2.7"},
{0}
};
