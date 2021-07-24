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

/**************************************************************************
* INIT FUNCTIONS
***************************************************************************/
static inline int init_bridging_args(struct bridge_args *args, struct uci_section *br_s, char *br_inst, struct uci_list *br_ports_list)
{
	args->bridge_sec = br_s;
	args->br_inst = br_inst;
	args->br_ports_list = br_ports_list;
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

static int remove_bridge_sections(char *config, char *section, char *option, char *br_inst)
{
	struct uci_section *s = NULL, *prev_s = NULL;

	uci_path_foreach_option_eq(bbfdm, config, section, option, br_inst, s) {
		if (prev_s)
			dmuci_delete_by_section(prev_s, NULL, NULL);
		prev_s = s;
	}
	if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
	return 0;
}

static void add_port_to_bridge_section(struct uci_section *br_sec, char *device_port)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
	if (!value_exists_in_uci_list(uci_list, device_port))
		dmuci_add_list_value_by_section(br_sec, "ports", device_port);
}

static void remove_port_from_bridge_section(struct uci_section *br_sec, char *device_port)
{
	struct uci_list *uci_list = NULL;

	dmuci_get_value_by_section_list(br_sec, "ports", &uci_list);
	if (value_exists_in_uci_list(uci_list, device_port))
		dmuci_del_list_value_by_section(br_sec, "ports", device_port);
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

	if (br_args->br_ports_list == NULL)
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
			dmuci_set_value_by_section(br_vlan_s, "device", section_name(br_args->bridge_sec));
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

	if (br_args->br_ports_list == NULL)
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

	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);
	dmuci_set_value_by_section(br_port_s, "config", config);
	dmuci_set_value_by_section(br_port_s, "port", port);
	dmuci_set_value_by_section(br_port_s, "br_inst", br_inst);
	dmuci_set_value_by_section(br_port_s, "device", device);
	dmuci_set_value_by_section(br_port_s, "device_section_name", device_s_name);
	dmuci_set_value_by_section(br_port_s, "management", management_port);

	return br_port_s;
}

static void dmmap_synchronizeBridgingBridgePort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL, *br_port_s = NULL;
	struct uci_element *e = NULL;
	char linker_buf[2048], *s_user = NULL;
	unsigned pos = 0;

	// get name option from network/device section
	char *dev_name = NULL;
	dmuci_get_value_by_section_string(br_args->bridge_sec, "name", &dev_name);

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user = NULL;
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
	get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(br_args->bridge_sec), &s);
	dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
	if (s_user && strcmp(s_user, "1") != 0 && !is_bridge_management_port_exist(br_args->br_inst))
		create_new_bridge_port_section("network", "", br_args->br_inst, dev_name, section_name(br_args->bridge_sec), "1");

	linker_buf[0] = 0;

	if (br_args->br_ports_list) {
		uci_foreach_element(br_args->br_ports_list, e) {

			if (is_bridge_port_exist(br_args->br_inst, e->name, &br_port_s)) {
				pos += snprintf(&linker_buf[pos], sizeof(linker_buf) - pos, "br_%s:%s+%s,", br_args->br_inst, section_name(br_port_s), e->name);
				continue;
			}

			br_port_s = create_new_bridge_port_section("network", e->name, br_args->br_inst, dev_name, section_name(br_args->bridge_sec), "0");
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

		br_port_s = create_new_bridge_port_section("wireless", ifname, br_args->br_inst, dev_name, section_name(br_args->bridge_sec), "0");
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

static void set_lowerlayers_management_port(struct dmctx *ctx, void *data, char *value)
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
		}
	}

	if (pos)
		new_device[pos - 1] = 0;

	dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", new_device);
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
					if (vid && vid [0] == '\0') {
						dmuci_set_value_by_section(s, "ifname", linker);
						dmuci_set_value_by_section(s, "name", linker);
					} else {
						char new_name[32] = {0};

						snprintf(new_name, sizeof(new_name), "%s.%s", linker, vid);
						dmuci_set_value_by_section(s, "ifname", linker);
						dmuci_set_value_by_section(s, "name", new_name);
						*new_linker = dmstrdup(new_name);
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
			char *port = NULL;

			// Get port device from dmmap section
			dmuci_get_value_by_section_string(s, "port", &port);
			char *vid = port ? strchr(port, '.') : NULL;
			if (vid) {
				// Remove curr port from port list of bridge section
				remove_port_from_bridge_section(bridge_sec, port);

				// Remove vid from device
				vid[0] = '\0';

				// Add new device to ifname list
				add_port_to_bridge_section(bridge_sec, port);

				// Update device in dmmap
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

/*************************************************************
* ADD DELETE OBJECT
**************************************************************/
static int addObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_bridge = NULL;

	char *last_inst = get_last_instance_bbfdm("dmmap_bridge", "device", "bridge_instance");

	// Add interface bridge section
	dmuci_add_section("network", "device", &s);
	dmuci_set_value_by_section(s, "type", "bridge");

	// Add dmmap bridge section
	dmuci_add_section_bbfdm("dmmap_bridge", "device", &dmmap_bridge);
	dmuci_set_value_by_section(dmmap_bridge, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_bridge, "added_by_user", "1");
	*instance = update_instance(last_inst, 2, dmmap_bridge, "bridge_instance");
	return 0;
}

static int delObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			// Remove all bridge sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge", "device", "bridge_instance", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge port sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlan sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlanport sections related to this device bridge section
			remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove device bridge section
			dmuci_delete_by_section(((struct bridge_args *)data)->bridge_sec, NULL, NULL);
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

	dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "name", &dev_name);
	int inst = get_last_inst("dmmap_bridge_port", "bridge_port", "br_inst", "bridge_port_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);

	// Add dmmap section for devices
	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);
	dmuci_set_value_by_section(br_port_s, "config", "network");
	dmuci_set_value_by_section(br_port_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
	dmuci_set_value_by_section(br_port_s, "device", dev_name);
	dmuci_set_value_by_section(br_port_s, "device_section_name", section_name(((struct bridge_args *)data)->bridge_sec));
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
		} else {
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
	dmuci_set_value_by_section(br_vlan_s, "device", section_name(((struct bridge_args *)data)->bridge_sec));
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
	//TODO
	return 0;
}

static int delObjBridgingProviderBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
	case DEL_INST:
		//TODO
		break;
	case DEL_ALL:
		//TODO
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

/*#Device.Bridging.ProviderBridgeNumberOfEntries!UCI:network/interface/*/
static int get_Bridging_ProviderBridgeNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		if (strncmp(section_name(s), "pr_br_", 6) == 0)
			cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Bridging.BridgeNumberOfEntries!UCI:network/interface/*/
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

/*#Device.Bridging.Bridge.{i}.Enable!UBUS:network.interface/status/interface,@Name/up*/
static int get_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridge_args *)data)->bridge_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
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
			dmubus_call_set("network.interface", b ? "up" : "down", UBUS_ARGS{{"interface", section_name(((struct bridge_args *)data)->bridge_sec), String}}, 1);
			return 0;
	}
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Status!UBUS:network.interface/status/interface,@Name/up*/
static int get_BridgingBridge_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_BridgingBridge_Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "true") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Alias!UCI:dmmap_network/interface,@i-1/bridge_alias*/
static int get_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_sect);
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
			get_dmmap_section_of_config_section("dmmap_bridge", "device", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_sect);
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
			pos += snprintf(&lbuf[pos], sizeof(lbuf) - pos, "%s,", *value ? *value : "");
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
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", port_device ? port_device : "", value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, "Device.ATM.Link.", port_device ? port_device : "", value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, "Device.PTM.Link.", port_device ? port_device : "", value);

		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *management = NULL, *linker = NULL;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (management && strcmp(management, "1") == 0)
				break;

			if (strncmp(value, "Device.Ethernet.Interface.", 26) != 0 &&
				strncmp(value, "Device.WiFi.SSID.", 17) != 0 &&
				strncmp(value, "Device.ATM.Link.", 16) != 0 &&
				strncmp(value, "Device.PTM.Link.", 16) != 0)
				return FAULT_9007;

			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker == NULL || *linker == '\0')
				return FAULT_9007;

			return 0;
		case VALUESET:
			if (management && strcmp(management, "1") == 0) {
				/* Management Port ==> true */
				set_lowerlayers_management_port(ctx, data, value);
			} else {
				/* Management Port ==> false */

				adm_entry_get_linker_value(ctx, value, &linker);

				char *port_device;
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", &port_device);
				if (port_device[0] == '\0') {
					// Check if there is a vlan port pointed at me
					char *new_linker = NULL;
					update_vlanport_and_device_section(data, linker, &new_linker);
					if (new_linker) linker = new_linker;

					// network config: add name to ifname option
					add_port_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

					// Update port option in dmmap
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", linker);

					update_device_management_port(port_device, linker, ((struct bridge_port_args *)data)->br_inst);
				} else {
					char *tag = strchr(port_device, '.');
					if (tag) {
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

						// Update port option in dmmap
						dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", new_name);

						update_device_management_port(port_device, new_name, ((struct bridge_port_args *)data)->br_inst);
					} else {
						// Remove port from ports list network/device
						remove_port_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, port_device);

						// Check if there is a vlan port pointed at me
						char *new_linker = NULL;
						update_vlanport_and_device_section(data, linker, &new_linker);
						if (new_linker) linker = new_linker;

						// Add new port to ports list network/device
						add_port_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

						// Update port option in dmmap
						dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "port", linker);

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
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "type", "8021q");
			else if (strcmp(value, "34984") == 0)
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "type", "8021ad");
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
	struct uci_element *e = NULL;
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

			uci_foreach_element(device_ports, e) {
				char *vid = strchr(e->name, '.');

				if (vid && curr_vid && strcmp(vid+1, curr_vid) == 0) {
					struct uci_section *s = NULL;
					char new_name[16] = {0};

					remove_port_from_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, e->name);

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

					add_port_to_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, new_name);
				}

			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char *device;

	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", &device);
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &res);
	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
	return 0;
}

static int set_BridgingBridgeVLANPort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
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
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer_path[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLAN.", ((struct bridge_vlanport_args *)data)->br_inst);

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

						/* Update the name dmmap section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
					} else {
						// the current ifname is empty in device section

						/* Update only vid option in device section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", new_vid);
					}
					dmfree(new_vid);
				}
			}
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
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer_path[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", ((struct bridge_vlanport_args *)data)->br_inst);

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
						} else {
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

							/* Update dmmap section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", section_name);

							/* Update dmmap bridge_port section */
							struct uci_section *s = NULL;
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

static int get_BridgingBridgeProviderBridge_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
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
		//TODO
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
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
		//TODO
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_BridgingBridgeProviderBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
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
		//TODO
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		//TODO
		break;
	case VALUESET:
		//TODO
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_CVLANcomponents(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_BridgingBridgeProviderBridge_CVLANcomponents(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 256, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
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
	char *inst = NULL, *max_inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("network", "device", "dmmap_bridge", "type", "bridge", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
				p->dmmap_section, "bridge_instance", "bridge_alias");

		dmuci_get_value_by_section_list(p->config_section, "ports", &ports_list);

		init_bridging_args(&curr_bridging_args, p->config_section, inst, ports_list);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseBridgingProviderBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

static int browseBridgingBridgePortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_port_args curr_bridge_port_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct browse_args browse_args = {0};
	struct uci_section *dmmap_s = NULL, *br_port_s = NULL;
	char *inst = NULL, *max_inst = NULL, *port_device = NULL;

	dmmap_synchronizeBridgingBridgePort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, dmmap_s) {

		/* Getting device from dmmap section */
		dmuci_get_value_by_section_string(dmmap_s, "port", &port_device);

		/* Getting the corresponding port device section */
		get_bridge_port_device_section(port_device, &br_port_s);

		init_bridge_port_args(&curr_bridge_port_args, br_port_s, dmmap_s, br_args->bridge_sec, br_args->br_inst, port_device);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
				dmmap_s, "bridge_port_instance", "bridge_port_alias",
			   check_browse_section, (void *)&browse_args);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_port_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgeVLANInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_vlan_args curr_bridge_vlan_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct browse_args browse_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL, *max_inst = NULL;

	dmmap_synchronizeBridgingBridgeVLAN(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_args->br_inst, s) {

		init_bridge_vlan_args(&curr_bridge_vlan_args, s, br_args->bridge_sec, br_args->br_inst);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   s, "bridge_vlan_instance", "bridge_vlan_alias",
			   check_browse_section, (void *)&browse_args);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlan_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseBridgingBridgeVLANPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_vlanport_args curr_bridge_vlanport_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct browse_args browse_args = {0};
	struct uci_section *s = NULL, *device_s = NULL;
	char *inst = NULL, *max_inst = NULL;

	dmmap_synchronizeBridgingBridgeVLANPort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_args->br_inst, s) {

		get_bridge_vlanport_device_section(s, &device_s);

		init_bridge_vlanport_args(&curr_bridge_vlanport_args, device_s, s, br_args->bridge_sec, br_args->br_inst);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   s, "bridge_vlanport_instance", "bridge_vlanport_alias",
			   check_browse_section, (void *)&browse_args);

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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Bridge", &DMWRITE, addObjBridgingBridge, delObjBridgingBridge, NULL, browseBridgingBridgeInst, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{"ProviderBridge", &DMWRITE, addObjBridgingProviderBridge, delObjBridgingProviderBridge, NULL, browseBridgingProviderBridgeInst, NULL, NULL, NULL, tBridgingProviderBridgeParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Port", &DMWRITE, addObjBridgingBridgePort, delObjBridgingBridgePort, NULL, browseBridgingBridgePortInst, NULL, NULL, tBridgingBridgePortObj, tBridgingBridgePortParams, get_linker_br_port, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"VLAN", &DMWRITE, addObjBridgingBridgeVLAN, delObjBridgingBridgeVLAN, NULL, browseBridgingBridgeVLANInst, NULL, NULL, NULL, tBridgingBridgeVLANParams, get_linker_br_vlan, BBFDM_BOTH, LIST_KEY{"VLANID", "Alias", NULL}},
{"VLANPort", &DMWRITE, addObjBridgingBridgeVLANPort, delObjBridgingBridgeVLANPort, NULL, browseBridgingBridgeVLANPortInst, NULL, NULL, NULL, tBridgingBridgeVLANPortParams, NULL, BBFDM_BOTH, LIST_KEY{"VLAN", "Port", "Alias", NULL}},
{0}
};

DMLEAF tBridgingBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridge_Enable, set_BridgingBridge_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridge_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridge_Alias, set_BridgingBridge_Alias, BBFDM_BOTH},
{"Standard", &DMWRITE, DMT_STRING, get_BridgingBridge_Standard, set_BridgingBridge_Standard, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_PortNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANPortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANPortNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}. ***/
DMOBJ tBridgingBridgePortObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgePortStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingBridgePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_Enable, set_BridgingBridgePort_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgePort_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Alias, set_BridgingBridgePort_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_BridgingBridgePort_Name, NULL, BBFDM_BOTH},
//{"LastChange", &DMREAD, DMT_UNINT, get_BridgingBridgePort_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_BridgingBridgePort_LowerLayers, set_BridgingBridgePort_LowerLayers, BBFDM_BOTH},
{"ManagementPort", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_ManagementPort, set_BridgingBridgePort_ManagementPort, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Type, set_BridgingBridgePort_Type, BBFDM_BOTH},
{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_DefaultUserPriority, set_BridgingBridgePort_DefaultUserPriority, BBFDM_BOTH},
{"PriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_PriorityRegeneration, set_BridgingBridgePort_PriorityRegeneration, BBFDM_BOTH},
//{"PortState", &DMREAD, DMT_STRING, get_BridgingBridgePort_PortState, NULL, BBFDM_BOTH},
{"PVID", &DMWRITE, DMT_INT, get_BridgingBridgePort_PVID, set_BridgingBridgePort_PVID, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_TPID, set_BridgingBridgePort_TPID, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}.Stats. ***/
DMLEAF tBridgingBridgePortStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLAN.{i}. ***/
DMLEAF tBridgingBridgeVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLAN_Enable, set_BridgingBridgeVLAN_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Alias, set_BridgingBridgeVLAN_Alias, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Name, set_BridgingBridgeVLAN_Name, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_INT, get_BridgingBridgeVLAN_VLANID, set_BridgingBridgeVLAN_VLANID, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLANPort.{i}. ***/
DMLEAF tBridgingBridgeVLANPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Enable, set_BridgingBridgeVLANPort_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_Alias, set_BridgingBridgeVLANPort_Alias, BBFDM_BOTH},
{"VLAN", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_VLAN, set_BridgingBridgeVLANPort_VLAN, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_STRING, get_BridgingBridgeVLANPort_Port, set_BridgingBridgeVLANPort_Port, BBFDM_BOTH},
{"Untagged", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Untagged, set_BridgingBridgeVLANPort_Untagged, BBFDM_BOTH},
{0}
};

/*** Bridging.ProviderBridge.{i}. ***/
DMLEAF tBridgingProviderBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeProviderBridge_Enable, set_BridgingBridgeProviderBridge_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgeProviderBridge_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_Alias, set_BridgingBridgeProviderBridge_Alias, BBFDM_BOTH},
{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_Type, set_BridgingBridgeProviderBridge_Type, BBFDM_BOTH},
{"SVLANcomponent", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_SVLANcomponent, set_BridgingBridgeProviderBridge_SVLANcomponent, BBFDM_BOTH},
{"CVLANcomponents", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_CVLANcomponents, set_BridgingBridgeProviderBridge_CVLANcomponents, BBFDM_BOTH},
{0}
};
