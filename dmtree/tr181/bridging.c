/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */
#include "dmentry.h"
#include "bridging.h"

struct bridge_args
{
	struct uci_section *bridge_sec;
	struct uci_list *br_ports_list;
	char *bridge_sec_name;
	char *br_inst;
};

struct bridge_port_args
{
	struct uci_section *bridge_port_sec;
	struct uci_section *bridge_port_dmmap_sec;
	struct uci_section *bridge_sec;
	char *br_inst;
	char *br_port_device;
};

struct bridge_vlanport_args
{
	struct uci_section *bridge_vlanport_sec;
	struct uci_section *bridge_vlanport_dmmap_sec;
	struct uci_section *bridge_sec;
	char *br_inst;
};

struct bridge_vlan_args
{
	struct uci_section *bridge_vlan_sec;
	struct uci_section *bridge_sec;
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
	if (data && ((struct bridge_port_args *)data)->bridge_port_dmmap_sec)
		dmasprintf(linker, "br_%s:%s+%s", ((struct bridge_port_args *)data)->br_inst, section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), ((struct bridge_port_args *)data)->br_port_device);
	else
		*linker = "";
	return 0;
}

static int get_linker_br_vlan(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct bridge_vlan_args *)data)->bridge_vlan_sec) {
		char *vid = NULL;

		dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &vid);
		dmasprintf(linker, "br_%s:vlan_%s", ((struct bridge_vlan_args *)data)->br_inst, vid ? vid : "");
	} else
		*linker = "";
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
static inline int init_bridging_args(struct bridge_args *args, struct uci_section *br_s, char *br_inst, struct uci_list *br_ports_list, char *br_sec_name)
{
	args->bridge_sec = br_s;
	args->br_inst = br_inst;
	args->br_ports_list = br_ports_list;
	args->bridge_sec_name = br_sec_name;
	return 0;
}

static inline int init_bridge_port_args(struct bridge_port_args *args, struct uci_section *br_port_s, struct uci_section *dmmap_s, struct uci_section *br_s, char *br_inst, char *br_port_dev)
{
	args->bridge_port_sec = br_port_s;
	args->bridge_port_dmmap_sec = dmmap_s;
	args->bridge_sec = br_s;
	args->br_inst = br_inst;
	args->br_port_device = br_port_dev;
	return 0;
}

static inline int init_bridge_vlanport_args(struct bridge_vlanport_args *args, struct uci_section *device_s, struct uci_section *dmmap_s, struct uci_section *br_s, char *br_inst)
{
	args->bridge_vlanport_sec = device_s;
	args->bridge_vlanport_dmmap_sec = dmmap_s;
	args->bridge_sec = br_s;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_vlan_args(struct bridge_vlan_args *args, struct uci_section *s, struct uci_section *br_s, char *br_inst)
{
	args->bridge_vlan_sec = s;
	args->bridge_sec = br_s;
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

	dmuci_get_value_by_section_list(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, &uci_opt_list);
	if (uci_opt_list == NULL)
		return;

	uci_value[0] = '\0';
	/* traverse each list value and create comma separated output */
	uci_foreach_element(uci_opt_list, e) {
		size_t length;

		//delimiting priority which is in the form of x:y where y is the priority
		char **priority = strsplit(e->name, ":", &length);
		if (length > 1)
			pos += snprintf(&uci_value[pos], sizeof(uci_value) - pos, "%s,", priority[1]);
	}

	if (pos)
		uci_value[pos - 1] = 0;

	dmasprintf(value, "%s", uci_value);
}

void bridging_set_priority_list(char *uci_opt_name, void *data, char *value)
{
	char *pch = NULL, *pchr = NULL;
	int idx = 0;

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

void bridging_get_vlan_tvid(char *uci_opt_name, void *data, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, uci_opt_name, value);
}

void bridging_set_vlan_tvid(char *uci_opt_name, void *data, char *value)
{
	dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_sec, uci_opt_name, !strcmp(value, "0") ? "" : value);
	dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, uci_opt_name, !strcmp(value, "0") ? "" : value);
}

static void bridge_remove_related_device_section(struct uci_list *br_ports_list)
{
	struct uci_element *e = NULL;

	if (!br_ports_list)
		return;

	uci_foreach_element(br_ports_list, e) {
		struct uci_section *s = NULL, *stmp = NULL;

		uci_foreach_option_eq_safe("network", "device", "name", e->name, stmp, s) {
			dmuci_delete_by_section(s, NULL, NULL);
		}
	}
}

static int get_last_inst(char *config, char *section, char *option1, char *option2, char *br_inst)
{
	struct uci_section *s = NULL;
	int instance, max = 0;
	char *tmp;

	uci_path_foreach_option_eq(bbfdm, config, section, option1, br_inst, s) {
		dmuci_get_value_by_section_string(s, option2, &tmp);
		if (tmp[0] == '\0')
			continue;
		instance = atoi(tmp);
		if (instance > max) max = instance;
	}
	return max;
}

static void remove_bridge_sections(char *config, char *section, char *option, char *br_inst)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_path_foreach_option_eq_safe(bbfdm, config, section, option, br_inst, stmp, s) {
		dmuci_delete_by_section(s, NULL, NULL);
	}
}

static void add_port_to_bridge_section(struct uci_section *br_sec, char *device_port)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
	if (!value_exists_in_uci_list(uci_list, device_port))
		dmuci_add_list_value_by_section(br_sec, "ports", device_port);
}

static void replace_existing_port_to_bridge_section(struct uci_section *br_sec, char *new_port, char* existing_port)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
	if (value_exists_in_uci_list(uci_list, existing_port)) {
		dmuci_del_list_value_by_section(br_sec, "ports", existing_port);
		dmuci_add_list_value_by_section(br_sec, "ports", new_port);
	}
}

static void remove_port_from_bridge_section(struct uci_section *br_sec, char *device_port)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
	if (value_exists_in_uci_list(uci_list, device_port))
		dmuci_del_list_value_by_section(br_sec, "ports", device_port);
}

static void set_Provider_bridge_component(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, char *component)
{
	/* *value=Device.Bridging.Bridge.{i}.
	 * In file dmmap_provider_bridge set "option svlan_br_inst {i}" or "list cvlan_br_inst {i}" in this(refered "provider_bridge" section)
	 * In file dmmap_bridge_port traverse all bridge_port section with option br_inst {i} and add option  provider_br_inst {i}
	 */
	struct uci_section *s = NULL, *dmmap_bridge_section = NULL;
	struct uci_section *network_bridge_sec_from = NULL, *network_bridge_sec_to = NULL;
	char pr_br_sec_name[64] = {0};
	char *br_sec_name = NULL;
	bool found = false;

	// Get candidate bridge instance
	if (value[strlen(value) - 1] == '.')
		value[strlen(value) - 1] = 0;

	char *br_inst = strrchr(value, '.');

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
			found = true;
			network_bridge_sec_to = s;
			break;
		}
	}

	if (strcmp(component, "CVLAN") == 0) {
		// Set svlan_br_inst in dmmap_provider_bridge->provider_bridge section

		dmuci_add_list_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "cvlan_br_inst", br_inst ? br_inst+1 : "");
	} else if (strcmp(component, "SVLAN") == 0) {
		// Set svlan_br_inst in dmmap_provider_bridgei->provider_bridge section

		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "svlan_br_inst", br_inst ? br_inst+1 : "");
	}

	// For all ports of candidate bridge  add provider_br_inst {i} | {i} = provider bridge instance
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst ? br_inst+1 : "", s) {
		char *management = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "1") == 0)
			dmmap_bridge_section = s;// later used to find network->device(bridge) section name
		dmuci_set_value_by_section(s, "provider_br_inst", instance);
	}

	/* Add candidate bridge to this provider bridge instance(network->device->pr_br_{i}) */
	// Get network->device(bridge) section name from dmmap_bridge_port->bridge_port->device_section_name
	dmuci_get_value_by_section_string(dmmap_bridge_section, "device_section_name", &br_sec_name);

	if (found) {
		/*
		 * The provider bridge secion has already been created(as a result of previous call to this function) in network uci file.
		 * Just need to find config section of candidate bridge and add it to the existing provider bridge configuration.
		 * And delete the candidate bridge section from network uci file.
		 *
		 */

		// Find the network->device(candidate bridge) section
		uci_foreach_option_eq("network", "device", "type", "bridge", s) {
			if (strcmp(br_sec_name, section_name(s)) == 0) {
				network_bridge_sec_from = s;
				break;
			}
		}

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
	} else {
		/*
		 * This is the first vlan component of this provider bridge instance.
		 * Need to create a porvider bridge instance in network uci file.
		 * To create a new provider bridge instance just rename candidate bridge config section name to pr_br_{i}
		 *
		 */

		// Find the network->device(bridge) section and rename it as pr_br_{i}
		uci_foreach_option_eq("network", "device", "type", "bridge", s) {
			if (strcmp(br_sec_name, section_name(s)) == 0) {
				dmuci_rename_section_by_section(s, pr_br_sec_name);
				break;
			}
		}

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

	uci_path_foreach_sections(bbfdm, "dmmap_bridge", "device", s) {
		struct uci_list *ports_list = NULL;
		struct uci_element *e = NULL;

		dmuci_get_value_by_section_list(s, "ports", &ports_list);
		if (ports_list == NULL)
			continue;

		uci_foreach_element(ports_list, e) {
			if (strcmp(e->name, device) == 0)
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
		if (opt_val && *opt_val != '\0' && atoi(opt_val) > inst)
			inst = atoi(opt_val);
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
	snprintf(bridge_name, sizeof(bridge_name), "bridge_%d", (last_inst_dmmap == 0) ? 1 : last_inst_dmmap+1);

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
		dmuci_set_value_by_section(dmmap_pr_br_sec, "type", "S-VLAN");

		dmuci_get_value_by_section_list(s, "ports", &ports_list);
		if (ports_list == NULL)
			continue;

		uci_foreach_element(ports_list, e) {
			struct uci_section *ss = NULL;

			uci_foreach_option_eq("network", "device", "name", e->name, ss) {
				char *type = NULL;

				dmuci_get_value_by_section_string(ss, "type", &type);

				// If type is 8021ad, add to svlan
				if (type && strcmp(type,"8021ad") == 0 && !is_bridge_section_exist(e->name)) {

					// Create device bridge dmmap section
					char *svlan_br_inst = create_dmmap_bridge_section(e->name);

					// Add svlan instance to provider bridge
					dmuci_set_value_by_section(dmmap_pr_br_sec, "svlan_br_inst", svlan_br_inst);
				}

				// If type is 8021q, add to cvlan
				if (type && strcmp(type,"8021q") == 0 && !is_bridge_section_exist(e->name)) {

					// Create device bridge dmmap section
					char *cvlan_br_inst = create_dmmap_bridge_section(e->name);

					// Add cvlan instance to provider bridge
					dmuci_add_list_value_by_section(dmmap_pr_br_sec, "cvlan_br_inst", cvlan_br_inst);
				}

			}
		}
	}
}

static bool is_bridge_vlan_exist(char *br_inst, char *vid)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_inst, s) {
		char *s_vid = NULL;

		dmuci_get_value_by_section_string(s, "vid", &s_vid);
		if (s_vid && strcmp(s_vid, vid) == 0)
			return true;
	}
	return false;
}

static void dmmap_synchronizeBridgingBridgeVLAN(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_element *e = NULL;

	if (!br_args->bridge_sec || !br_args->br_ports_list)
		return;

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user = NULL;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (s_user && strcmp(s_user, "1") == 0)
			continue;

		// vid is available in ports list ==> skip it
		char *vid = NULL;
		bool vid_found = false;
		dmuci_get_value_by_section_string(s, "vid", &vid);
		uci_foreach_element(br_args->br_ports_list, e) {
			if (vid && strstr(e->name, vid)) {
				vid_found = true;
				break;
			}
		}

		if (vid_found)
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_element(br_args->br_ports_list, e) {

		uci_foreach_option_eq("network", "device", "name", e->name, s) {
			char *vid = NULL;

			dmuci_get_value_by_section_string(s, "vid", &vid);

			if (vid && vid[0] == '\0') {
				char *ifname = strchr(e->name, '.');
				if (ifname) vid = dmstrdup(ifname+1);
			}

			if (vid && vid[0] == '\0') break;

			if (is_bridge_vlan_exist(br_args->br_inst, vid)) break;

			struct uci_section *br_vlan_s = NULL;
			dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &br_vlan_s);
			dmuci_set_value_by_section(br_vlan_s, "vid", vid);
			dmuci_set_value_by_section(br_vlan_s, "br_inst", br_args->br_inst);
			dmuci_set_value_by_section(br_vlan_s, "device", br_args->bridge_sec_name);
		}

	}
}

static bool is_bridge_vlanport_exist(char *br_inst, char *name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_inst, s) {
		char *s_name = NULL;

		dmuci_get_value_by_section_string(s, "name", &s_name);
		if (strcmp(s_name, name) == 0)
			return true;
	}
	return false;
}

static struct uci_section *get_bridge_port_dmmap_section(char *dev_port)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "port", dev_port, s) {
		return s;
	}
	return NULL;
}

static void dmmap_synchronizeBridgingBridgeVLANPort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_element *e = NULL;

	if (!br_args->bridge_sec || !br_args->br_ports_list)
			return;

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user = NULL;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (s_user && strcmp(s_user, "1") == 0)
			continue;

		// port device is available in ports list ==> skip it
		char *name;
		dmuci_get_value_by_section_string(s, "name", &name);
		if (value_exists_in_uci_list(br_args->br_ports_list, name))
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_element(br_args->br_ports_list, e) {

		uci_foreach_option_eq("network", "device", "name", e->name, s) {

			if (is_bridge_vlanport_exist(br_args->br_inst, e->name))
				break;

			struct uci_section *br_vlanport_s = NULL;
			struct uci_section *br_port_sec_name = get_bridge_port_dmmap_section(e->name);

			dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &br_vlanport_s);
			dmuci_set_value_by_section(br_vlanport_s, "name", e->name);
			dmuci_set_value_by_section(br_vlanport_s, "port_name", br_port_sec_name ? section_name(br_port_sec_name) : "");
			dmuci_set_value_by_section(br_vlanport_s, "br_inst", br_args->br_inst);
			dmuci_set_value_by_section(br_vlanport_s, "device_name", section_name(s));
		}

	}
}

static int is_bridge_pr_br_member(char *br_inst, char **pr_br_inst)
{
	struct uci_section *pr_br_sec = NULL;

	// Return provider bridge inst. if passed bridge inst. is a member of provider bridge
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", pr_br_sec) {
		struct uci_list *cvlan_list = NULL;
		char *svlan = NULL;

		// Check if the passed bridge section is svlan
		dmuci_get_value_by_section_string(pr_br_sec, "svlan_br_inst", &svlan);
		if (svlan && br_inst && strcmp(svlan, br_inst) == 0) {
			// Get provider bridge instance
			dmuci_get_value_by_section_string(pr_br_sec, "provider_bridge_instance", pr_br_inst);
			return true;
		}

		// Check if the passed bridge section is cvlan
		dmuci_get_value_by_section_list(pr_br_sec, "cvlan_br_inst", &cvlan_list);
		if (cvlan_list != NULL) {
			struct uci_element *e = NULL;

			uci_foreach_element(cvlan_list, e) {
				if (br_inst && strcmp(e->name, br_inst) == 0) {
					// Get provider bridge instance
					dmuci_get_value_by_section_string(pr_br_sec, "provider_bridge_instance", pr_br_inst);
					return true;
				}
			}
		}
	}
	return false;
}

static bool is_bridge_port_exist(char *br_inst, char *port, struct uci_section **dmmap_br_port)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *curr_port = NULL;

		dmuci_get_value_by_section_string(s, "port", &curr_port);
		if (curr_port && strcmp(curr_port, port) == 0) {
			*dmmap_br_port = s;
			return true;
		}
	}
	return false;
}

static bool is_bridge_management_port_exist(char *br_inst)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "1") == 0)
			return true;
	}
	return false;
}

static struct uci_section *get_interface_section(char *dev_name)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "interface", "device", dev_name, s) {
		return s;
	}
	return NULL;
}

static bool is_wireless_ifname_exist(char *dev_sec_name, char *ifname)
{
	struct uci_section *interface_s = get_interface_section(dev_sec_name);
	if (interface_s == NULL)
		return false;

	struct uci_section *s = NULL;
	uci_foreach_option_eq("wireless", "wifi-iface", "network", section_name(interface_s), s) {
		char *curr_ifname = NULL;

		dmuci_get_value_by_section_string(s, "ifname", &curr_ifname);
		if (curr_ifname && strcmp(curr_ifname, ifname) == 0)
			return true;
	}
	return false;
}

static void update_bridge_management_port(char *br_inst, char *linker)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "1") == 0) {
			dmuci_set_value_by_section(s, "port", linker);
			return;
		}
	}
}

static struct uci_section *create_new_bridge_port_section(char *config, char *port, char *br_inst, char *device, char *device_s_name, char *management_port)
{
	struct uci_section *br_port_s = NULL;
	char *pr_br_inst = NULL;

	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);
	dmuci_set_value_by_section(br_port_s, "config", config);
	dmuci_set_value_by_section(br_port_s, "port", port);
	dmuci_set_value_by_section(br_port_s, "br_inst", br_inst);
	dmuci_set_value_by_section(br_port_s, "device", device);
	dmuci_set_value_by_section(br_port_s, "device_section_name", device_s_name);
	dmuci_set_value_by_section(br_port_s, "management", management_port);
	if (is_bridge_pr_br_member(br_inst, &pr_br_inst))
		dmuci_set_value_by_section(br_port_s, "provider_br_inst", pr_br_inst);

	return br_port_s;
}

static void dmmap_synchronizeBridgingBridgePort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL, *br_port_s = NULL;
	struct uci_element *e = NULL;
	char linker_buf[2048], *s_user = NULL;
	unsigned pos = 0;

	if (!br_args->bridge_sec)
		return;

	// get name option from network/device section
	char *dev_name = NULL;
	dmuci_get_value_by_section_string(br_args->bridge_sec, "name", &dev_name);

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (s_user && strcmp(s_user, "1") == 0)
			continue;

		// section for management ==> skip it
		char *management = NULL;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "1") == 0)
			continue;

		// port device is available in ports list ==> skip it
		char *port_device;
		dmuci_get_value_by_section_string(s, "port", &port_device);
		if (br_args->br_ports_list && value_exists_in_uci_list(br_args->br_ports_list, port_device))
			continue;

		// check for wireless ==> skip it
		if (is_wireless_ifname_exist(dev_name, port_device))
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	// section added by user ==> skip it
	get_dmmap_section_of_config_section("dmmap_bridge", "device", br_args->bridge_sec_name, &s);
	dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
	if (s_user && strcmp(s_user, "1") != 0 && !is_bridge_management_port_exist(br_args->br_inst))
		create_new_bridge_port_section("network", "", br_args->br_inst, dev_name, br_args->bridge_sec_name, "1");

	linker_buf[0] = 0;

	if (br_args->br_ports_list) {
		uci_foreach_element(br_args->br_ports_list, e) {

			if (is_bridge_port_exist(br_args->br_inst, e->name, &br_port_s)) {
				pos += snprintf(&linker_buf[pos], sizeof(linker_buf) - pos, "br_%s:%s+%s,", br_args->br_inst, section_name(br_port_s), e->name);
				continue;
			}

			br_port_s = create_new_bridge_port_section("network", e->name, br_args->br_inst, dev_name, br_args->bridge_sec_name, "0");
			pos += snprintf(&linker_buf[pos], sizeof(linker_buf) - pos, "br_%s:%s+%s,", br_args->br_inst, section_name(br_port_s), e->name);
		}
	}

	// get interface section mapped to this device name
	struct uci_section *interface_s = get_interface_section(dev_name);
	if (interface_s == NULL)
		goto end;

	uci_foreach_option_eq("wireless", "wifi-iface", "network", section_name(interface_s), s) {
		char *ifname = NULL;

		// get ifname from wireless/wifi-iface section
		dmuci_get_value_by_section_string(s, "ifname", &ifname);

		if (is_bridge_port_exist(br_args->br_inst, ifname, &br_port_s)) {
			pos += snprintf(&linker_buf[pos], sizeof(linker_buf) - pos, "br_%s:%s+%s,", br_args->br_inst, section_name(br_port_s), ifname);
			continue;
		}

		br_port_s = create_new_bridge_port_section("wireless", ifname, br_args->br_inst, dev_name, br_args->bridge_sec_name, "0");
		pos += snprintf(&linker_buf[pos], sizeof(linker_buf) - pos, "br_%s:%s+%s,", br_args->br_inst, section_name(br_port_s), ifname);
	}

end:
	if (pos)
		linker_buf[pos - 1] = 0;

	// Update the device linker for management port if it is not added by user
	if (s_user && strcmp(s_user, "1") != 0)
		update_bridge_management_port(br_args->br_inst, linker_buf);
}

static void get_bridge_vlanport_device_section(struct uci_section *dmmap_section, struct uci_section **device_section)
{
	struct uci_section *s = NULL;
	char *name = NULL, *device_name = NULL;

	/* Get name from dmmap section */
	dmuci_get_value_by_section_string(dmmap_section, "name", &name);

	if (name && name[0] != '\0') {
		/* Find the device network section corresponding to this name */
		uci_foreach_option_eq("network", "device", "name", name, s) {
			*device_section = s;
			return;
		}
	}

	/* Get section_name from dmmap section */
	dmuci_get_value_by_section_string(dmmap_section, "device_name", &device_name);

	if (device_name && device_name[0] != '\0') {
		/* Find the device network section corresponding to this device_name */
		uci_foreach_sections("network", "device", s) {
			if (strcmp(section_name(s), device_name) == 0) {
				*device_section = s;
				return;
			}
		}
	}

	*device_section = NULL;
}

static void get_bridge_port_device_section(char *port, struct uci_section **device_section)
{
	struct uci_section *s = NULL;

	if (port && port[0] != '\0') {
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

	*device_section = NULL;
}

static void remove_vlanid_from_ifname_list(struct uci_section *bridge_sec, char *br_inst, char *curr_vid)
{
	struct uci_list *device_ports = NULL;
	struct uci_element *e = NULL;

	dmuci_get_value_by_section_list(bridge_sec, "ports", &device_ports);
	if (device_ports == NULL)
		return;

	uci_foreach_element(device_ports, e) {
		char *vid = strchr(e->name, '.');

		if (vid && strcmp(vid+1, curr_vid) == 0) {

			// Update  port section if vid != 0
			struct uci_section *port_s = NULL;
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port_s) {
				char *device = NULL;

				// Get device from dmmap section
				dmuci_get_value_by_section_string(port_s, "port", &device);
				if (device && strcmp(device, e->name) == 0) {
					// Remove vid from device
					vid[0] = '\0';
					// Update device in dmmap
					dmuci_set_value_by_section(port_s, "port", e->name);
					break;
				}
			}

		}
	}
}

static int set_lowerlayers_management_port(struct dmctx *ctx, void *data, char *value)
{
	char *pch = NULL, *spch = NULL, new_device[1024] = { 0, 0 };
	unsigned pos = 0;

	new_device[0] = 0;
	for (pch = strtok_r(value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
		char lower_layer_path[256] = {0};

		snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", ((struct bridge_port_args *)data)->br_inst);

		if (strncmp(pch, lower_layer_path, strlen(lower_layer_path)) == 0) {
			/* check linker is available */
			char *linker = NULL;
			adm_entry_get_linker_value(ctx, pch, &linker);
			if (!linker || linker[0] == '\0')
				continue;

			pos += snprintf(&new_device[pos], sizeof(new_device) - pos, "%s,", linker);
		} else {
			return FAULT_9007;
		}
	}

	if (pos)
		new_device[pos - 1] = 0;

	dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", new_device);
	return 0;
}

static void update_device_management_port(char *old_name, char *new_name, char *br_inst)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management = NULL, *port = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "0") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "port", &port);

		char new_port[512] = {0}, *pch = NULL, *spch = NULL;
		unsigned pos = 0;

		new_port[0] = 0;
		for (pch = strtok_r(port, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
			if (!strstr(pch, old_name)) {
				pos += snprintf(&new_port[pos], sizeof(new_port) - pos, "%s,", pch);
			} else {
				char *sec = strchr(pch, '+');
				if (sec) sec[0] = '\0';
				pos += snprintf(&new_port[pos], sizeof(new_port) - pos, "%s+%s,", pch, new_name);
			}
		}

		if (pos)
			new_port[pos - 1] = 0;

		dmuci_set_value_by_section(s, "port", new_port);
		break;
	}
}

static void remove_device_from_management_port(const struct bridge_port_args *data, char *port)
{
	struct uci_section *s = NULL;
	char curr_linker[128] = {0};

	snprintf(curr_linker, sizeof(curr_linker), "br_%s:%s+%s", data->br_inst, section_name(data->bridge_port_dmmap_sec), port);

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", data->br_inst, s) {
		char *management = NULL, *port_linker = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "0") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "port", &port_linker);

		char new_port[512] = {0}, *pch = NULL, *spch = NULL;
		unsigned pos = 0;

		new_port[0] = 0;
		for (pch = strtok_r(port_linker, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

			if (strcmp(pch, curr_linker) == 0)
				continue;

			pos += snprintf(&new_port[pos], sizeof(new_port) - pos, "%s,", pch);
		}

		if (pos)
			new_port[pos - 1] = 0;

		dmuci_set_value_by_section(s, "port", new_port);
		break;
	}
}

static void update_vlanport_and_device_section(void *data, char *linker, char **new_linker)
{
	struct uci_section *br_vlan_port_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_port_args *)data)->br_inst, br_vlan_port_s) {
		char *port_name = NULL;

		dmuci_get_value_by_section_string(br_vlan_port_s, "port_name", &port_name);
		if (port_name && strcmp(section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), port_name) == 0) {
			char *device_name = NULL;

			dmuci_get_value_by_section_string(br_vlan_port_s, "device_name", &device_name);

			// Update device section
			struct uci_section *s = NULL;
			uci_foreach_sections("network", "device", s) {

				if (device_name && strcmp(section_name(s), device_name) == 0) {
					char *vid = NULL;
					dmuci_get_value_by_section_string(s, "vid", &vid);
					if (vid && *vid) {
						char new_name[32] = {0};

						snprintf(new_name, sizeof(new_name), "%s.%s", linker, vid);
						dmuci_set_value_by_section(s, "ifname", linker);
						dmuci_set_value_by_section(s, "name", new_name);
						*new_linker = dmstrdup(new_name);
					} else {
						dmuci_set_value_by_section(s, "ifname", linker);
						dmuci_set_value_by_section(s, "name", linker);
					}
					break;
				}
			}

			// Update vlan port section in dmmap
			dmuci_set_value_by_section(br_vlan_port_s, "name", *new_linker);
			break;
		}
	}
}

static void remove_vlanid_from_device_and_vlanport(char *vid)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "device", "vid", vid, s) {
		struct uci_section *port_s = NULL;
		char *name = NULL;

		dmuci_get_value_by_section_string(s, "name", &name);

		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "name", name, port_s) {
			char *curr_vid = strchr(name, '.');
			if (curr_vid) curr_vid[0] = '\0';
			dmuci_set_value_by_section(port_s, "name", name);
		}

		dmuci_set_value_by_section(s, "name", name);
		dmuci_set_value_by_section(s, "vid", "");
	}

	// Check if this vid is set as inner_vid for any device, then delete it.
	uci_foreach_option_eq("network", "device", "inner_vid", vid, s) {
		dmuci_set_value_by_section(s, "inner_vid", "");
	}
}

static void remove_vlanport_section(struct uci_section *vlanport_dmmap_sec, struct uci_section *bridge_sec, char *br_inst)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *device_name = NULL, *port_name = NULL;

	// Get port name from dmmap section
	dmuci_get_value_by_section_string(vlanport_dmmap_sec, "port_name", &port_name);

	// Update  port section if vid != 0
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		if (port_name && strcmp(section_name(s), port_name) == 0) {
			char curr_port[32] = {0};
			char *port = NULL;

			// Get port device from dmmap section
			dmuci_get_value_by_section_string(s, "port", &port);
			DM_STRNCPY(curr_port, port, sizeof(curr_port));

			char *vid = port ? strchr(port, '.') : NULL;
			if (vid) {
				// network: Remove curr port from ports list of bridge section
				remove_port_from_bridge_section(bridge_sec, curr_port);

				// Remove vid from device
				vid[0] = '\0';

				// network: Add new port to ports list
				add_port_to_bridge_section(bridge_sec, port);

				// dmmap_bridge: Add new port to ports list
				struct uci_section *dmmap_bridge_s = NULL;
				get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(bridge_sec), &dmmap_bridge_s);
				replace_existing_port_to_bridge_section(dmmap_bridge_s, port, curr_port);

				// dmmap_bridge_port: Update port option
				dmuci_set_value_by_section(s, "port", port);
			}
			break;
		}
	}

	// Get device name from dmmap section
	dmuci_get_value_by_section_string(vlanport_dmmap_sec, "device_name", &device_name);

	// Remove ifname from device section
	uci_foreach_sections_safe("network", "device", stmp, s) {
		if (strcmp(section_name(s), device_name) == 0) {
			dmuci_delete_by_section(s, NULL, NULL);
			break;
		}
	}
}

static char *fetch_and_configure_inner_vid(char *br_inst, char *type_val, char *vid)
{
	struct uci_section *dev_s = NULL;
	char *cur_vid = NULL;

	// Get the vid under device section with type 8021q of port under same br_inst.
	uci_foreach_option_eq("network", "device", "type", type_val, dev_s) {
		struct uci_section *br_port_s = NULL;
		char *instance = NULL;
		char *dev_name = NULL;

		dmuci_get_value_by_section_string(dev_s, "name", &dev_name);

		//find out the bridge instance of device section
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "device", dev_name, br_port_s) {
			dmuci_get_value_by_section_string(br_port_s, "br_inst", &instance);
			break;
		}

		//Check if the bridge instances are same or not, if yes, then get the vid.
		if (instance && br_inst && strcmp(br_inst, instance) == 0) {
			if (type_val && strcmp(type_val, "8021ad") == 0)
				dmuci_set_value_by_section(dev_s, "inner_vid", vid);
			else
				dmuci_get_value_by_section_string(dev_s, "vid", &cur_vid);
			break;
		}
	}

	return cur_vid;
}

static int handle_inner_vid(void)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("network", "device", s) {
		struct uci_section *br_port_s = NULL;
		char *br_inst = NULL;

		// Get the bridge instance.
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "device_section_name", section_name(s), br_port_s) {
			dmuci_get_value_by_section_string(br_port_s, "br_inst", &br_inst);
			break;
		}

		if (br_inst != NULL && br_inst[0] != '\0') {
			char *cur_vid = NULL;

			cur_vid = fetch_and_configure_inner_vid(br_inst, "8021q", "");
			cur_vid = (!cur_vid) ? fetch_and_configure_inner_vid(br_inst, "untagged", "") : NULL;

			//loop device section with type 8021ad and fetch the br_inst of it,
			//if same br_inst then add vid as inner_vid
			if (cur_vid != NULL && cur_vid[0] != '\0')
				fetch_and_configure_inner_vid(br_inst, "8021ad", cur_vid);
		}
	}
	return 0;
}

static int configure_device_type(const struct bridge_port_args *data, char *type_value)
{
	struct uci_section *s = NULL;

	dmuci_set_value_by_section(data->bridge_port_sec, "type", type_value);

	if (strncmp(type_value, "8021q", 5) == 0) {

		//Check if the device has inner-vid if so then delete
		uci_foreach_sections("network", "device", s) {
			if (strcmp(section_name(data->bridge_port_sec), section_name(s)) == 0) {
				char *inner_vid = NULL;

				dmuci_get_value_by_section_string(s, "inner_vid", &inner_vid);
				if (inner_vid && inner_vid[0] != '\0') {
					dmuci_delete_by_section(s, "inner_vid", NULL);
					break;
				}
			}
		}

		//fetch the vid of the 8021q interface.
		char *vid = NULL;
		uci_foreach_option_eq("network", "device", "name", data->br_port_device, s) {
			dmuci_get_value_by_section_string(s, "vid", &vid);
			break;
		}

		if (vid != NULL && vid[0] != '\0')
			fetch_and_configure_inner_vid(data->br_inst, "8021ad", vid);

	} else if (strncmp(type_value, "8021ad", 6) == 0) {
		char *cur_vid = NULL;

		cur_vid = fetch_and_configure_inner_vid(data->br_inst, "8021q", "");
		cur_vid = (!cur_vid) ? fetch_and_configure_inner_vid(data->br_inst, "untagged", "") : NULL;

		//apply the vid of the interface as the inner_vid of 8021ad port
		if (cur_vid != NULL && cur_vid[0] != '\0')
			dmuci_set_value_by_section(data->bridge_port_sec, "inner_vid", cur_vid);

	}
	return 0;
}

static void restore_bridge_config(char *vlan_br_inst)
{
	struct uci_section *s = NULL, *dmmap_br_sec = NULL;
	char *device_section_name = NULL;
	char *port = NULL;
	size_t length_comma = 0, tmp_length = 0;

	// Get bridge config section of vlan bridge from dmmap_bridge_port
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", vlan_br_inst, s) {
		char *management = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "1") == 0) {
			dmmap_br_sec = s;
			break;
		}
	}

	if (dmmap_br_sec == NULL)
		return;

	dmuci_get_value_by_section_string(dmmap_br_sec, "device_section_name", &device_section_name);
	dmuci_get_value_by_section_string(dmmap_br_sec, "port", &port);

	// Restore bridge config
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_section_name);
	dmuci_set_value_by_section(s, "type", "bridge");

	// Restore vlan bridge of this provider bridge
	// Get devices list
	char **device_comma = strsplit(port, ",", &length_comma);
	for(int i = 0; i < length_comma; i++) {
		char **tmp_list = strsplit(device_comma[i], "+", &tmp_length);
		add_port_to_bridge_section(s, tmp_list[1]);
	}
}

static void delete_provider_bridge(struct uci_section *data)
{
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_list *cvlan_list = NULL;
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

		// Remove dmmap bridge section
		remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", svlan_br_inst);
	}

	// Get cvlan component bridge instance list from dmmap section
	dmuci_get_value_by_section_list(data, "cvlan_br_inst", &cvlan_list);
	if (cvlan_list != NULL) {
		struct uci_element *e = NULL;

		/* traverse each list value and delete all bridge section */
		uci_foreach_element(cvlan_list, e) {

			// Restore bridge section in network uci file
			restore_bridge_config(e->name);

			// Remove dmmap bridge section
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", e->name);
		}
	}

	// Get provider bridge section from network file and delete
	uci_foreach_option_eq_safe("network", "device", "type", "bridge", stmp, s) {
		if (strcmp(pr_br_inst, section_name(s)) == 0) {
			dmuci_delete_by_section(s, NULL, NULL);
			break;
		}
	}

	// Delete dmmap bridge section.
	dmuci_delete_by_section_bbfdm(data, NULL, NULL);
}

void static get_rem_pr_br_instance(struct uci_section *pr_br_sec, char *bridge_inst)
{
	struct uci_section *network_bridge_sec = NULL, *dmmap_br_port_sec = NULL, *s = NULL;
	size_t length = 0, tmp_length = 0;
	char *pr_br_inst = NULL;
	char *ports;
	char ifname[50] = {0};
	char *ptr = ifname;
	char new_ifname[50] = {0};
	char pr_br_inst_buf[32] = {0};
	int i;

	// Get provider bridge instance | will be used to track and remove this bridge inst in network file
	dmuci_get_value_by_section_string(pr_br_sec, "provider_bridge_instance", &pr_br_inst);

	snprintf(pr_br_inst_buf, sizeof(pr_br_inst_buf), "pr_br_%s", pr_br_inst); //name of provider bridge configuration in network file

	// Get provider bridge section from network file and delete
	uci_foreach_option_eq("network", "device", "type", "bridge", s) {
		if (strcmp(pr_br_inst_buf, section_name(s)) == 0) {
			network_bridge_sec = s; // This id the provider bridge config in network file
			break;
		}
	}

	if (network_bridge_sec == NULL)
		return;

	/* Remove bridge from provider bridge config in network file */
	// Get bridge config section from dmmap_bridge_port file
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", bridge_inst, s) {
		char *management = NULL;

		dmuci_get_value_by_section_string(s, "management", &management);
		if (management && strcmp(management, "1") == 0) {
			dmmap_br_port_sec = s;
			break;
		}
	}

	if (dmmap_br_port_sec == NULL)
		return;

	// Construct ifname list from dmmap_bridge_port management section of passed bridge instance
	dmuci_get_value_by_section_string(dmmap_br_port_sec, "port", &ports);
	char **port_comma = strsplit(ports, ",", &length);
	for(i = 0; i < length; i++) {
		char **tmp_list = strsplit(port_comma[i], "+", &tmp_length);
		dmstrappendstr(ptr, tmp_list[1]);
		dmstrappendchr(ptr, ' ');
	}
	ptr = ptr - 1;
	dmstrappendend(ptr);

	struct uci_list *ports_list = NULL;
	dmuci_get_value_by_section_list(network_bridge_sec, "ports", &ports_list);
	if (ports_list != NULL) {
		struct uci_element *e = NULL;

		/* traverse each list value and delete all bridge section */
		ptr = new_ifname;
		uci_foreach_element(ports_list, e) {
			if (strstr(ifname, e->name))
				continue;

			dmstrappendstr(ptr, e->name);
			dmstrappendchr(ptr, ' ');
		}

		if (ptr != NULL) {
			ptr = ptr - 1;
			dmstrappendend(ptr);
		}
	}

	if (new_ifname[0] == '\0') {
		dmuci_delete_by_section(network_bridge_sec, NULL, NULL);
	} else {
		char **new_port = strsplit(new_ifname, " ", &length);
		for(i = 0; i < length; i++) {
			dmuci_add_list_value_by_section(network_bridge_sec, "ports", new_port[i]);
		}
	}
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
		if (svlan && strcmp(svlan, bridge_inst) == 0) {
			restore_bridge_config(svlan);
			dmuci_set_value_by_section(pr_br_sec, "svlan_br_inst", "");
			get_rem_pr_br_instance(pr_br_sec, bridge_inst);
		}

		// Check if the passed bridge section is cvlan
		dmuci_get_value_by_section_list(pr_br_sec, "cvlan_br_inst", &cvlan_list);
		if (cvlan_list != NULL) {
			struct uci_element *e = NULL;

			uci_foreach_element(cvlan_list, e) {
				if (strcmp(e->name, bridge_inst) == 0) {
					restore_bridge_config(bridge_inst);
					dmuci_del_list_value_by_section(pr_br_sec, "cvlan_br_inst", bridge_inst);
					get_rem_pr_br_instance(pr_br_sec, bridge_inst);
					break;
				}
			}
		}
	}
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
	dmuci_set_value_by_section(s, "bridge_empty", "1");

	// Add device bridge section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, dev_s_name);
	dmuci_set_value_by_section(s, "name", device_name);
	dmuci_set_value_by_section(s, "type", "bridge");

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
	char *curr_device = NULL;

	switch (del_action) {
		case DEL_INST:
			// Remove all related device bridge section
			bridge_remove_related_device_section(((struct bridge_args *)data)->br_ports_list);

			// Remove all bridge sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge", "device", "bridge_instance", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge port sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlan sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlanport sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove cvlan/svaln from dmmap_provider_bridge section if this bridge instance is a part of it
			remove_bridge_from_provider_bridge(((struct bridge_args *)data)->br_inst);

			// Remove interface bridge that maps to this device
			dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "name", &curr_device);
			if (curr_device && *curr_device) {
				uci_foreach_sections("network", "interface", s) {
					char *device = NULL;
					char *proto = NULL;

					dmuci_get_value_by_section_string(s, "proto", &proto);
					dmuci_get_value_by_section_string(s, "device", &device);
					if (device && strcmp(device, curr_device) == 0) {
						dmuci_delete_by_section(s, (proto && *proto == 0) ? NULL : "device", NULL);
						break;
					}
				}
			}

			// Remove device bridge section
			dmuci_delete_by_section(((struct bridge_args *)data)->bridge_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("network", "device", "type", "bridge", stmp, s) {
				struct uci_section *ss = NULL;
				struct uci_list *br_ports_list = NULL;
				struct uci_section *dmmap_section = NULL;
				char *bridge_inst = NULL;

				get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(s), &dmmap_section);
				dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &bridge_inst);
				dmuci_get_value_by_section_list(dmmap_section, "ports", &br_ports_list);

				// Remove all related device bridge section
				bridge_remove_related_device_section(br_ports_list);

				// Remove all bridge port sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", bridge_inst);

				// Remove all bridge vlan sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", bridge_inst);

				// Remove all bridge vlanport sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", bridge_inst);

				// Remove cvlan/svaln from dmmap_provider_bridge section if this bridge instance is a part of it
				remove_bridge_from_provider_bridge(bridge_inst);

				// Remove dmmap device bridge section
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				// Remove interface bridge that maps to this device
				dmuci_get_value_by_section_string(s, "name", &curr_device);
				if (curr_device && *curr_device) {
					uci_foreach_sections("network", "interface", ss) {
						char *device = NULL;
						char *proto = NULL;

						dmuci_get_value_by_section_string(ss, "proto", &proto);
						dmuci_get_value_by_section_string(ss, "device", &device);
						if (device && strcmp(device, curr_device) == 0) {
							dmuci_delete_by_section(ss, (proto && *proto == 0) ? NULL : "device", NULL);
							break;
						}
					}
				}

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
	char *dev_name = NULL;
	char buf[32];

	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "name", &dev_name);
	int inst = get_last_inst("dmmap_bridge_port", "bridge_port", "br_inst", "bridge_port_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);

	snprintf(buf, sizeof(buf), "br_%s_port_%s", ((struct bridge_args *)data)->br_inst, *instance);

	// Add dmmap section for devices
	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);
	dmuci_rename_section_by_section(br_port_s, buf);
	dmuci_set_value_by_section(br_port_s, "config", "network");
	dmuci_set_value_by_section(br_port_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
	dmuci_set_value_by_section(br_port_s, "device", dev_name);
	dmuci_set_value_by_section(br_port_s, "device_section_name", ((struct bridge_args *)data)->bridge_sec_name);
	dmuci_set_value_by_section(br_port_s, "management", "0");
	dmuci_set_value_by_section(br_port_s, "added_by_user", "1");
	return 0;
}

static int delObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *port = NULL, *management = NULL;

	switch (del_action) {
	case DEL_INST:
		// Get device from dmmap section
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", &port);
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);

		if ((port && port[0] == '\0') || (management && strcmp(management, "1") == 0)) {
			// Remove only dmmap section
			dmuci_delete_by_section_bbfdm(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, NULL, NULL);
		} else if (port && *port) {
			// Remove device from management port section
			remove_device_from_management_port((struct bridge_port_args *)data, port);

			// Remove dmmap section
			dmuci_delete_by_section_bbfdm(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, NULL, NULL);

			// Remove ifname from device section
			uci_foreach_option_eq("network", "device", "name", port, s) {
				dmuci_set_value_by_section(s, "name", "");
				dmuci_set_value_by_section(s, "ifname", "");
			}

			// Remove port from vlan port section
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "name", port, s) {
				dmuci_set_value_by_section(s, "name", "");
			}

			// Remove port from port list dmmap_bridge/device section
			get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_port_args *)data)->bridge_sec), &s);
			remove_port_from_bridge_section(s, port);

			// Remove port from port list network/device section
			remove_port_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, port);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {

			// Get device from dmmap section
			dmuci_get_value_by_section_string(s, "port", &port);
			dmuci_get_value_by_section_string(s, "management", &management);

			if ((port && port[0] != '\0') && (management && strcmp(management, "0") == 0)) {
				struct uci_section *ss = NULL;

				// Remove ifname from device section
				uci_foreach_option_eq("network", "device", "name", port, ss) {
					dmuci_set_value_by_section(ss, "name", "");
					dmuci_set_value_by_section(ss, "ifname", "");
				}

				// Remove ifname from vlan port section
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "name", port, ss) {
					dmuci_set_value_by_section(ss, "name", "");
				}

				// Get bridge/device section name
				char *device_s_name = NULL;
				dmuci_get_value_by_section_string(s, "device_section_name", &device_s_name);

				// Remove port from port list dmmap_bridge/device section
				get_dmmap_section_of_config_section("dmmap_bridge", "device", device_s_name, &ss);
				remove_port_from_bridge_section(ss, port);

				// Remove port from port list network/device section
				remove_port_from_bridge_section(((struct bridge_args *)data)->bridge_sec, port);
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

	int inst = get_last_inst("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", "bridge_vlanport_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);
	snprintf(device_name, sizeof(device_name), "br_%s_port_%s", ((struct bridge_args *)data)->br_inst, *instance);

	// Add device section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &br_vlanport_s);
	dmuci_set_value_by_section(br_vlanport_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_vlanport_s, "bridge_vlanport_instance", *instance);
	dmuci_set_value_by_section(br_vlanport_s, "device_name", device_name);
	dmuci_set_value_by_section(br_vlanport_s, "added_by_user", "1");

	return 0;
}

static int delObjBridgingBridgeVLANPort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		remove_vlanport_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, ((struct bridge_vlanport_args *)data)->bridge_sec,
								((struct bridge_vlanport_args *)data)->br_inst);

		// Remove dmmap section
		dmuci_delete_by_section_bbfdm(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, NULL, NULL);
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {

			remove_vlanport_section(s, ((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->br_inst);

			// Remove all dmmap section
			dmuci_delete_by_section_bbfdm(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_vlan_s = NULL;

	int inst = get_last_inst("dmmap_bridge_vlan", "bridge_vlan", "br_inst", "bridge_vlan_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);

	dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &br_vlan_s);
	dmuci_set_value_by_section(br_vlan_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_vlan_s, "bridge_vlan_instance", *instance);
	dmuci_set_value_by_section(br_vlan_s, "device", ((struct bridge_args *)data)->bridge_sec_name);
	dmuci_set_value_by_section(br_vlan_s, "added_by_user", "1");
	dmuci_set_value_by_section(br_vlan_s, "vid", "1");
	return 0;
}

static int delObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *vid = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &vid);
		if (vid && vid[0] == '\0') {
			// Remove only dmmap section
			dmuci_delete_by_section_bbfdm(((struct bridge_vlan_args *)data)->bridge_vlan_sec, NULL, NULL);
		} else {
			// Remove all vid from ifname list of bridge section
			remove_vlanid_from_ifname_list(((struct bridge_vlan_args *)data)->bridge_sec, ((struct bridge_vlan_args *)data)->br_inst, vid);

			// Remove all vid from device and vlanport sections in dmmap
			remove_vlanid_from_device_and_vlanport(vid);

			// Remove only dmmap section
			dmuci_delete_by_section_bbfdm(((struct bridge_vlan_args *)data)->bridge_vlan_sec, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst, stmp, s) {
			dmuci_get_value_by_section_string(s, "vid", &vid);

			if (vid && vid[0] != '\0') {
				// Remove all vid from ifname list of bridge section
				remove_vlanid_from_ifname_list(((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->br_inst, vid);

				// Remove all vid from device and vlanport sections in dmmap
				remove_vlanid_from_device_and_vlanport(vid);
			}

			// Remove all dmmap section
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
	dmuci_set_value_by_section(pr_br_sec, "type", "S-VLAN");
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
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("network", "device", "type", "bridge", s) {
		if (strncmp(section_name(s), "pr_br_", 6) == 0)
			cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Bridging.BridgeNumberOfEntries!UCI:network/device/*/
static int get_Bridging_BridgeNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("network", "device", "type", "bridge", s) {
		cnt++;
	}
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
	get_BridgingBridge_Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Alias!UCI:dmmap_bridge/device,@i-1/bridge_alias*/
static int get_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge", "device", ((struct bridge_args *)data)->bridge_sec_name, &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "bridge_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_bridge", "device", ((struct bridge_args *)data)->bridge_sec_name, &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "bridge_alias", value);
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
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridge_VLANNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridge_VLANPortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *management = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	if (management && strcmp(management, "1") == 0) {
		*value = "1";
	} else {
		char *eth_ports = NULL;
		char *device = NULL;
		char *config = NULL;

		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &device);
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", &config);
		db_get_value_string("hw", "board", "ethernetLanPorts", &eth_ports);

		if (dm_strword(eth_ports, device)) {
			// ports config => ethport sections

			*value = dmuci_get_value_by_section_fallback_def(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", "1");
		} else if (config && !strcmp(config, "wireless")) {
			// wireless config => wifi-iface sections

			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "disabled", value);
			*value = ((*value)[0] == '1') ? "0" : "1";
		} else {
			// network config => device sections

			json_object *res = NULL;
			dmubus_call("network.device", "status", UBUS_ARGS{{"name", device ? device : "", String}}, 1, &res);
			DM_ASSERT(res, *value = "0");
			char *up = dmjson_get_value(res, 1, "up");
			*value = up ? "1" :"0";
		}
	}
	return 0;
}

static int set_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *management = NULL;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
			if (management && strcmp(management, "1") == 0) {
				break;
			} else {
				char *eth_ports = NULL;
				char *device = NULL;
				char *config = NULL;

				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &device);
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", &config);
				db_get_value_string("hw", "board", "ethernetLanPorts", &eth_ports);

				if (dm_strword(eth_ports, device)) {
					// ports config => ethport sections

					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", b ? "1" : "0");
				} else if (config && !strcmp(config, "wireless")) {
					// wireless config => wifi-iface sections

					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "disabled", b ? "0" : "1");
				}
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_BridgingBridgePort_Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "1") == 0) ? "Up" : "Down";
	return 0;
}

static int get_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "bridge_port_alias", value);
	if ((*value)[0] == '\0') {
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "name", value);
		if ((*value)[0] != '\0')
			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "bridge_port_alias", *value);
		else
			dmasprintf(value, "cpe-%s", instance);
	}
	return 0;
}

static int set_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "bridge_port_alias", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *management = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	if (management && strcmp(management, "1") !=  0)
		*value = dmstrdup(((struct bridge_port_args *)data)->br_port_device);
	return 0;
}

static int get_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *management = NULL, *port_device = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", &port_device);

	if (management && strcmp(management, "1") ==  0) {
		char *pch = NULL, *spch = NULL;
		char lbuf[1024] = { 0, 0 };
		unsigned pos = 0;

		lbuf[0] = 0;
		for (pch = strtok_r(port_device, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
			adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", pch, value);
			if (*value && (*value)[0] != 0)
				pos += snprintf(&lbuf[pos], sizeof(lbuf) - pos, "%s,", *value);
		}

		if (pos)
			lbuf[pos - 1] = 0;

		*value = dmstrdup(lbuf);
	} else {
		char *config = NULL;

		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", &config);

		if (config && strcmp(config, "network") == 0) {
			char *tag = port_device ? strchr(port_device, '.') : NULL;
			if (tag) tag[0] = '\0';
		}

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", port_device ? port_device : "", value);
		if (!(*value) || (*value)[0] == 0)
			adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", port_device ? port_device : "", value);
		if (!(*value) || (*value)[0] == 0)
			adm_entry_get_linker_param(ctx, "Device.ATM.Link.", port_device ? port_device : "", value);
		if (!(*value) || (*value)[0] == 0)
			adm_entry_get_linker_param(ctx, "Device.PTM.Link.", port_device ? port_device : "", value);
	}
	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.Ethernet.Interface.",
			"Device.WiFi.SSID.",
			"Device.ATM.Link.",
			"Device.PTM.Link.",
			NULL};
	char *management = NULL, *linker = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (management && strcmp(management, "1") == 0)
				break;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			if (management && strcmp(management, "1") == 0) {
				/* Management Port ==> true */
				return set_lowerlayers_management_port(ctx, data, value);
			} else {
				/* Management Port ==> false */
				bool is_wireless_config = false;

				adm_entry_get_linker_value(ctx, value, &linker);

				if (!linker || *linker == 0) {
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", "");
					return 0;
				}

				// Update config section on dmmap_bridge_port if the linker is wirelss port or network port
				if (strncmp(value, "Device.WiFi.SSID.", 17) == 0) {
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", "wireless");
					is_wireless_config = true;
				} else
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", "network");

				struct uci_section *dmmap_bridge_s = NULL;
				char *port_device;

				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", &port_device);
				if (port_device[0] == '\0') {
					// Check if there is a vlan port pointed at me
					char *new_linker = NULL;
					update_vlanport_and_device_section(data, linker, &new_linker);
					if (new_linker) linker = new_linker;

					// network config: add port to ports list
					add_port_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

					// dmmap_bridge: add port to ports list
					get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_port_args *)data)->bridge_sec), &dmmap_bridge_s);
					add_port_to_bridge_section(dmmap_bridge_s, linker);

					// Update port option in dmmap
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", linker);

					update_device_management_port(section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), linker, ((struct bridge_port_args *)data)->br_inst);
				} else {
					char *tag = strchr(port_device, '.');
					if (tag && !is_wireless_config) {
						char *cur_vid = dmstrdup(tag+1);
						char new_name[32] = {0};

						snprintf(new_name, sizeof(new_name), "%s.%s", linker, cur_vid);

						// Remove name from ifname list interface
						remove_port_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, port_device);

						// Check if there is a vlan port pointed at me
						struct uci_section *ss = NULL;
						uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_port_args *)data)->br_inst, ss) {
							char *port_name = NULL;

							dmuci_get_value_by_section_string(ss, "port_name", &port_name);
							if (port_name && strcmp(section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), port_name) == 0) {
								char *device_name = NULL;

								dmuci_get_value_by_section_string(ss, "device_name", &device_name);

								// Update device section
								struct uci_section *s = NULL;
								uci_foreach_sections("network", "device", s) {
									if (device_name && strcmp(section_name(s), device_name) == 0) {
										dmuci_set_value_by_section(s, "ifname", linker);
										dmuci_set_value_by_section(s, "name", new_name);
										break;
									}
								}
								// Update vlan port section in dmmap
								dmuci_set_value_by_section(ss, "name", new_name);
								break;
							}
						}

						// network config: add name to ifname option
						add_port_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, new_name);

						// dmmap_bridge: add port to ports list
						get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_port_args *)data)->bridge_sec), &dmmap_bridge_s);
						replace_existing_port_to_bridge_section(dmmap_bridge_s, new_name, port_device);

						// Update port option in dmmap
						dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", new_name);

						update_device_management_port(port_device, new_name, ((struct bridge_port_args *)data)->br_inst);
					} else {
						// Remove port from ports list network/device
						remove_port_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, port_device);

						if (!is_wireless_config) {
							// Check if there is a vlan port pointed at me
							char *new_linker = NULL;
							update_vlanport_and_device_section(data, linker, &new_linker);
							if (new_linker) linker = new_linker;
						}

						// Add new port to ports list network/device
						add_port_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

						// Update port option in dmmap
						dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", linker);

						// dmmap_bridge: add port to ports list
						get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_port_args *)data)->bridge_sec), &dmmap_bridge_s);
						replace_existing_port_to_bridge_section(dmmap_bridge_s, linker, port_device);

						update_device_management_port(port_device, linker, ((struct bridge_port_args *)data)->br_inst);
					}
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
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", b ? "1" : "0");
			if (b) dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", "");
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_DefaultUserPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct bridge_port_args *)data)->bridge_port_sec, "priority", "0");
	return 0;
}

static int set_BridgingBridgePort_DefaultUserPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *type;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
			if (type[0] != '\0' && (strcmp(type, "untagged") == 0 || strcmp(type, "8021q") == 0))
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "priority", value);
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
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, 8, 8, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			break;

		case VALUESET:
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
	char *type = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
			if (type && type[0] != '\0' && (strcmp(type, "untagged") == 0 || strcmp(type, "8021q") == 0)) {
				char new_name[32] = {0};
				char *ifname = NULL;

				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &ifname);
				snprintf(new_name, sizeof(new_name), "%s.%s", ifname, value);

				/* Update VLANPort dmmap section if exist */
				struct uci_section *vlanport_s = NULL;
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_port_args *)data)->br_inst, vlanport_s) {
					char *vlan_name = NULL, *name = NULL;

					dmuci_get_value_by_section_string(vlanport_s, "name", &vlan_name);
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "name", &name);
					if (vlan_name && name && strcmp(vlan_name, name) == 0) {
						dmuci_set_value_by_section(vlanport_s, "name", new_name);
						break;
					}
				}

				/* Update Port dmmap section */
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", new_name);

				/* Update interface and device section */
				remove_port_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->br_port_device);
				add_port_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, new_name);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "name", new_name);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "vid", value);
				handle_inner_vid();
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
	if (type && (strcmp(type, "8021q") == 0 || strcmp(type, "untagged") == 0))
		*value = "33024";
	else if (type && strcmp(type, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "33024") == 0)
				configure_device_type((struct bridge_port_args *)data, "8021q");
			else if (strcmp(value, "34984") == 0)
				configure_device_type((struct bridge_port_args *)data, "8021ad");
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

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_BridgingBridgePortStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/multicast", value);
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
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "device", value);
	return 0;
}

static int set_BridgingBridgeVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_rename_section_by_section(((struct bridge_vlan_args *)data)->bridge_sec, value);

			// Update name in dmmap_bridge section of this bridge instance
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge", "device", "bridge_instance", ((struct bridge_vlan_args *)data)->br_inst, s) {
				dmuci_set_value_by_section(s, "section_name", value);
			}

			// Update name in dmmap_bridge_port sections of this bridge instance
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, s) {
				dmuci_set_value_by_section(s, "device_section_name", value);
			}

			// Update name in dmmap_bridge_vlan section of this bridge instance
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "device", value);
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
	struct uci_list *device_ports = NULL;
	struct uci_element *e = NULL, *tmp = NULL;
	char *curr_vid = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &curr_vid);
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", value);
			dmuci_get_value_by_section_list(((struct bridge_vlan_args *)data)->bridge_sec, "ports", &device_ports);
			if (device_ports == NULL)
				return 0;

			uci_foreach_element_safe(device_ports, tmp, e) {
				char *vid = strchr(e->name, '.');

				if (vid && curr_vid && strcmp(vid+1, curr_vid) == 0) {
					struct uci_section *s = NULL;
					char new_name[16] = {0};

					/* Update vid and name of device section */
					uci_foreach_option_eq("network", "device", "name", e->name, s) {
						char *ifname = NULL;

						dmuci_get_value_by_section_string(s, "ifname", &ifname);
						if (ifname && *ifname == '\0') {
							dmuci_get_value_by_section_string(s, "name", &ifname);
							char *name = strchr(ifname, '.');
							if (name) *name = '\0';
						}

						snprintf(new_name, sizeof(new_name), "%s.%s", ifname, value);
						dmuci_set_value_by_section(s, "name", new_name);
						dmuci_set_value_by_section(s, "vid", value);
					}

					/* Update vlan port section in dmmap */
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, s) {
						char *vlan_name = NULL;

						dmuci_get_value_by_section_string(s, "name", &vlan_name);
						if (vlan_name && strcmp(vlan_name, e->name) == 0) {
							dmuci_set_value_by_section(s, "name", new_name);
							break;
						}
					}

					/* Update port section in dmmap */
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, s) {
						char *port = NULL;

						dmuci_get_value_by_section_string(s, "port", &port);
						if (port && strcmp(port, e->name) == 0) {
							dmuci_set_value_by_section(s, "port", new_name);
							update_device_management_port(port, new_name, ((struct bridge_vlan_args *)data)->br_inst);
							break;
						}
					}

					/* Update bridge section in dmmap_bridge */
					get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_vlan_args *)data)->bridge_sec), &s);
					remove_port_from_bridge_section(s, e->name);
					add_port_to_bridge_section(s, new_name);

					/* Update bridge section in network */
					remove_port_from_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, e->name);
					add_port_to_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, new_name);
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
	char linker[32] = {0};
	char *vid = NULL;

	/* Get vid from device network section */
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);

	/* Get linker */
	snprintf(linker, sizeof(linker),"br_%s:vlan_%s", ((struct bridge_vlanport_args *)data)->br_inst, vid);
	adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", linker, value);
	return 0;
}

static int set_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer_path[256] = {0};
	char *allowed_objects[] = {
			lower_layer_path,
			NULL};

	snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLAN.", ((struct bridge_vlanport_args *)data)->br_inst);

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			/* Check the path object is correct or no */
			if (strncmp(value, lower_layer_path, strlen(lower_layer_path)) == 0) {
				/* Check linker exist */
				char *linker = NULL;
				adm_entry_get_linker_value(ctx, value, &linker);
				if (!linker || *linker == '\0')
					return 0;

				char *br = strstr(linker, ":vlan_");
				if (br) {
					char *curr_name = NULL, *new_vid = dmstrdup(br+6);

					/* Check the current ifname in the device section */
					dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", &curr_name);

					if (curr_name && curr_name[0] != '\0') {
						// the current ifname is not empty in device section

						char new_name[32] = {0};
						char *curr_ifname = NULL;

						dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", &curr_ifname);

						/* create the new name */
						snprintf(new_name, sizeof(new_name), "%s.%s", curr_ifname ? curr_ifname : "", new_vid);

						/* Update interface and device network section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", new_name);
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", new_vid);
						remove_port_from_bridge_section(((struct bridge_vlanport_args *)data)->bridge_sec, curr_name);
						add_port_to_bridge_section(((struct bridge_vlanport_args *)data)->bridge_sec, new_name);

						/* Update port section in dmmap */
						struct uci_section *s = NULL;
						uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, s) {
							char *port = NULL;

							dmuci_get_value_by_section_string(s, "port", &port);
							if (port && strcmp(port, curr_name) == 0) {
								dmuci_set_value_by_section(s, "port", new_name);
								update_device_management_port(port, new_name, ((struct bridge_vlanport_args *)data)->br_inst);
								break;
							}
						}

						/* Update ports list  in dmmap_bridge */
						get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_vlanport_args *)data)->bridge_sec), &s);
						remove_port_from_bridge_section(s, curr_ifname);
						add_port_to_bridge_section(s, new_name);

						 /* Update the name dmmap section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
					} else {
						// the current ifname is empty in device section

						/* Update only vid option in device section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", new_vid);
					}
					dmfree(new_vid);

					/* Update tvid, read from dmmap_bridge_vlan, set in vlanport_sec */
					struct uci_section *vlan_s = NULL;

					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, vlan_s) {
						char *vlan_inst = NULL;

						dmuci_get_value_by_section_string(vlan_s, "bridge_vlan_instance", &vlan_inst);
						if (vlan_inst && strcmp(vlan_inst, instance) == 0) {
							char *tvid;
							dmuci_get_value_by_section_string(vlan_s, "tvid", &tvid);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "tvid", tvid);
							break;
						}
					}
				}
			}
			handle_inner_vid();
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name = NULL, *port_name = NULL;
	char linker[128] = {0};

	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", &name);
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", &port_name);

	snprintf(linker, sizeof(linker), "br_%s:%s+%s", ((struct bridge_vlanport_args *)data)->br_inst, port_name, name);
	adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", linker, value);
	return 0;
}

static int set_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer_path[256] = {0};
	char *allowed_objects[] = {
			lower_layer_path,
			NULL};

	snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", ((struct bridge_vlanport_args *)data)->br_inst);

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			if (strncmp(value, lower_layer_path, strlen(lower_layer_path)) == 0) {

				char *linker = NULL;
				adm_entry_get_linker_value(ctx, value, &linker);
				if (!linker || *linker == '\0')
					return 0;

				char *br = strchr(linker, ':');
				if (br) {

					char *section_name = dmstrdup(br+1);
					char *br_link = strchr(section_name, '+');
					if (br_link) {
						char *port_linker = dmstrdup(br_link+1);
						*br_link = '\0';

						char *vid = NULL;
						dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);
						if (vid && vid[0] == '\0') {

							/* Update device section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", port_linker);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", port_linker);

							/* Update dmmap vlanport section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", port_linker);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", section_name);
						} else if (vid && *vid) {
							struct uci_section *s = NULL;
							char new_name[32] = {0};

							/* Create the new ifname */
							if (port_linker[0] != '\0'){
								char *tag = strchr(port_linker, '.');
								if (tag) tag[0] = '\0';
								snprintf(new_name, sizeof(new_name), "%s.%s", port_linker, vid);
							}

							/* Update device section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", new_name);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", port_linker);

							/* network->device : Update ports list */
							remove_port_from_bridge_section(((struct bridge_vlanport_args *)data)->bridge_sec, port_linker);
							add_port_to_bridge_section(((struct bridge_vlanport_args *)data)->bridge_sec, new_name);

							/* dmmap_bridge->device : Update ports list */
							get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_vlanport_args *)data)->bridge_sec), &s);
							remove_port_from_bridge_section(s, port_linker);
							add_port_to_bridge_section(s, new_name);

							/* Update dmmap section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", section_name);

							/* Update dmmap bridge_port section */
							uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, s) {
								if (strcmp(section_name(s), section_name) == 0) {
									dmuci_set_value_by_section(s, "port", new_name);
									update_device_management_port(port_linker, new_name, ((struct bridge_vlanport_args *)data)->br_inst);
									break;
								}
							}
						}
					}
				}
			}
			handle_inner_vid();
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type;
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "type", &type);
	*value = (strcmp(type, "untagged") == 0) ? "1" : "0";
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
			dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "type", (b) ? "untagged" : "8021q");
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
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->provider_bridge_sec, "enable", value);
	*value = (strcmp(*value, "1") == 0) ? "Enabled" : "Disabled";
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

static int get_BridgingBridgeProviderBridge_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct provider_bridge_args *)data)->provider_bridge_sec, "type", "S-VLAN");
	return 0;
}

int set_BridgingBridgeProviderBridge_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, Provider_Bridge_Type, NULL))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->provider_bridge_sec, "type", value);
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *br_inst = NULL;

	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->provider_bridge_sec, "svlan_br_inst", &br_inst);
	if (br_inst && *br_inst)
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

				if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
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

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Bridging.Bridge.{i}.!UCI:network/device/dmmap_bridge*/
static int browseBridgingBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args curr_bridging_args = {0};
	struct dmmap_dup *p = NULL;
	struct uci_list *ports_list = NULL;
	char *inst = NULL, *sec_name = NULL;
	LIST_HEAD(dup_list);

	synchronize_bridge_config_sections_with_dmmap_bridge_eq("network", "device", "dmmap_bridge", "type", "bridge", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "bridge_instance", "bridge_alias");

		dmuci_get_value_by_section_list(p->dmmap_section, "ports", &ports_list);
		dmuci_get_value_by_section_string(p->dmmap_section, "section_name", &sec_name);

		init_bridging_args(&curr_bridging_args, p->config_section ? p->config_section : p->dmmap_section, inst, ports_list, p->config_section ? section_name(p->config_section) : sec_name);

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
	struct bridge_port_args curr_bridge_port_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *dmmap_s = NULL, *br_port_s = NULL;
	char *inst = NULL, *port_device = NULL;

	dmmap_synchronizeBridgingBridgePort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, dmmap_s) {

		/* Getting device from dmmap section */
		dmuci_get_value_by_section_string(dmmap_s, "port", &port_device);

		/* Getting the corresponding port device section */
		get_bridge_port_device_section(port_device, &br_port_s);

		init_bridge_port_args(&curr_bridge_port_args, br_port_s, dmmap_s, br_args->bridge_sec, br_args->br_inst, port_device);

		inst = handle_instance(dmctx, parent_node, dmmap_s, "bridge_port_instance", "bridge_port_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_port_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgeVLANInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_vlan_args curr_bridge_vlan_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeBridgingBridgeVLAN(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_args->br_inst, s) {

		init_bridge_vlan_args(&curr_bridge_vlan_args, s, br_args->bridge_sec, br_args->br_inst);

		inst = handle_instance(dmctx, parent_node, s, "bridge_vlan_instance", "bridge_vlan_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlan_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgeVLANPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_vlanport_args curr_bridge_vlanport_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *device_s = NULL;
	char *inst = NULL;

	dmmap_synchronizeBridgingBridgeVLANPort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_args->br_inst, s) {

		get_bridge_vlanport_device_section(s, &device_s);

		init_bridge_vlanport_args(&curr_bridge_vlanport_args, device_s, s, br_args->bridge_sec, br_args->br_inst);

		inst = handle_instance(dmctx, parent_node, s, "bridge_vlanport_instance", "bridge_vlanport_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlanport_args, inst) == DM_STOP)
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
{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_DefaultUserPriority, set_BridgingBridgePort_DefaultUserPriority, BBFDM_BOTH, "2.0"},
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
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsSent, NULL, BBFDM_BOTH, "2.0"},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH, "2.0"},
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
{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_Type, set_BridgingBridgeProviderBridge_Type, BBFDM_BOTH, "2.7"},
{"SVLANcomponent", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_SVLANcomponent, set_BridgingBridgeProviderBridge_SVLANcomponent, BBFDM_BOTH, "2.7"},
{"CVLANcomponents", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_CVLANcomponents, set_BridgingBridgeProviderBridge_CVLANcomponents, BBFDM_BOTH, "2.7"},
{0}
};
