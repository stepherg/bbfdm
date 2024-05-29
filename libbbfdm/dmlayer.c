/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "dmlayer.h"

void ppp___update_sections(struct uci_section *s_from, struct uci_section *s_to)
{
	char *proto = NULL;
	char *device = NULL;
	char *username = NULL;
	char *password = NULL;
	char *pppd_options = NULL;
	char *service = NULL;
	char *ac = NULL;

	dmuci_get_value_by_section_string(s_from, "proto", &proto);
	dmuci_get_value_by_section_string(s_from, "device", &device);
	dmuci_get_value_by_section_string(s_from, "username", &username);
	dmuci_get_value_by_section_string(s_from, "password", &password);
	dmuci_get_value_by_section_string(s_from, "pppd_options", &pppd_options);
	dmuci_get_value_by_section_string(s_from, "service", &service);
	dmuci_get_value_by_section_string(s_from, "ac", &ac);

	dmuci_set_value_by_section(s_to, "proto", proto);
	dmuci_set_value_by_section(s_to, "device", DM_STRLEN(device) ? device : section_name(s_to));
	dmuci_set_value_by_section(s_to, "username", username);
	dmuci_set_value_by_section(s_to, "password", password);
	dmuci_set_value_by_section(s_to, "pppd_options", pppd_options);
	dmuci_set_value_by_section(s_to, "service", service);
	dmuci_set_value_by_section(s_to, "ac", ac);
}

void ppp___reset_options(struct uci_section *ppp_s)
{
	dmuci_set_value_by_section(ppp_s, "device", section_name(ppp_s));
	dmuci_set_value_by_section(ppp_s, "username", "");
	dmuci_set_value_by_section(ppp_s, "password", "");
	dmuci_set_value_by_section(ppp_s, "pppd_options", "");
	dmuci_set_value_by_section(ppp_s, "service", "");
	dmuci_set_value_by_section(ppp_s, "ac", "");
}

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

/* get the name that linux generates based on ifname of tunnel */
void gre___get_tunnel_system_name(struct uci_section *iface_section, char *device_str, size_t device_str_size)
{
	char *proto = NULL;

	if (!iface_section || !device_str_size)
		return;

	dmuci_get_value_by_section_string(iface_section, "proto", &proto);

	// to generate appropriate device name
	if (proto && !DM_LSTRCMP(proto, "grev6")) {
		snprintf(device_str, device_str_size, "gre6-%s", section_name(iface_section));
	} else {
		snprintf(device_str, device_str_size, "gre4-%s", section_name(iface_section));
	}
}

bool ip___is_gre_protocols(const char *proto)
{
	if (!DM_LSTRCMP(proto, "gre"))
		return true;

	if (!DM_LSTRCMP(proto, "grev6"))
		return true;

	if (!DM_LSTRCMP(proto, "gretap"))
		return true;

	if (!DM_LSTRCMP(proto, "grev6tap"))
		return true;

	return false;
}

bool ip___is_ip_interface_instance_exists(const char *sec_name, const char *device)
{
	struct uci_section *s = NULL;
	char *curr_dev = NULL;

	if (DM_STRLEN(sec_name) == 0 ||
		DM_STRLEN(device) == 0)
		return false;

	uci_foreach_sections("network", "interface", s) {

		dmuci_get_value_by_section_string(s, "device", &curr_dev);
		if (DM_STRLEN(curr_dev) == 0 ||
			DM_STRCMP(curr_dev, device) != 0)
			continue;

		struct uci_section *dmmap_s = NULL;
		char *ip_inst = NULL;

		if ((dmmap_s = get_dup_section_in_dmmap("dmmap_network", "interface", section_name(s))) != NULL) {
			dmuci_get_value_by_section_string(dmmap_s, "ip_int_instance", &ip_inst);

			if (strcmp(sec_name, section_name(s)) != 0 &&
				DM_STRLEN(ip_inst) != 0)
				return true;
		}
	}

	return false;
}

void ip___update_child_interfaces(char *device, char *option_name, char *option_value)
{
	struct uci_section *s = NULL;

	if (DM_STRLEN(device) == 0)
		return;

	uci_foreach_option_eq("network", "interface", "device", device, s) {
		dmuci_set_value_by_section(s, option_name, option_value);
	}
}

static void ip___Update_IP_Interface_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "LowerLayers", path, dmmap_s) {
		struct uci_section *iface_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char *curr_device = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "ip_int_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		iface_s = get_origin_section_from_config("network", "interface", sec_name);
		if (!iface_s)
			continue;

		dmuci_get_value_by_section_string(iface_s, "device", &curr_device);

		ip___update_child_interfaces(curr_device, "device", DM_STRLEN(linker) ? linker : section_name(iface_s));
	}
}

static void ppp___Update_PPP_Interface_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_ppp", "interface", "LowerLayers", path, dmmap_s) {
		struct uci_section *iface_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char curr_path[128] = {0};
		char proto[8] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "ppp_int_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "iface_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		iface_s = get_origin_section_from_config("network", "interface", sec_name);

		snprintf(proto, sizeof(proto), "ppp%s", (DM_STRLEN(linker)) ? (!DM_LSTRNCMP(linker, "atm", 3) || !DM_LSTRNCMP(linker, "ptm", 3)) ? "oa" : "oe" : "");

		// Update proto option
		dmuci_set_value_by_section(dmmap_s, "proto", proto);
		if (iface_s) dmuci_set_value_by_section(iface_s, "proto", proto);

		// Update device option
		dmuci_set_value_by_section(dmmap_s, "device", linker);
		if (iface_s) dmuci_set_value_by_section(iface_s, "device", linker);

		snprintf(curr_path, sizeof(curr_path), "Device.PPP.Interface.%s", instance);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, linker);
	}
}

void ppp___Update_PPP_Interface_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

static void ethernet___Update_MAC_VLAN_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "LowerLayers", path, dmmap_s) {
		struct uci_section *dev_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char curr_path[128] = {0};
		char name[32] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "mac_vlan_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		dev_s = get_origin_section_from_config("network", "device", sec_name);
		if (!dev_s)
			continue;

		if (DM_STRLEN(linker)) {
			char *dev_name = ethernet___get_ethernet_interface_name(linker);

			snprintf(name, sizeof(name), "%s_%s", dev_name, instance);
		}

		dmuci_set_value_by_section(dev_s, "ifname", linker);
		dmuci_set_value_by_section(dev_s, "name", name);

		snprintf(curr_path, sizeof(curr_path), "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN.%s", instance);

		// Update PPP Interface instance if exists
		ppp___Update_PPP_Interface_Layer(curr_path, name);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, name);
	}
}

void ethernet___Update_MAC_VLAN_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update PPP Interface instance if exists
	ppp___Update_PPP_Interface_Layer(path, linker);

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

static void ethernet___Update_VLAN_Termination_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "LowerLayers", path, dmmap_s) {
		struct uci_section *dev_s = NULL;
		char *sec_name = NULL;
		char *instance = NULL;
		char curr_path[128] = {0};
		char name[32] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "vlan_term_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
		if (!DM_STRLEN(sec_name))
			continue;

		dev_s = get_origin_section_from_config("network", "device", sec_name);
		if (!dev_s)
			continue;

		if (DM_STRLEN(linker)) {
			char *vid = NULL;

			dmuci_get_value_by_section_string(dev_s, "vid", &vid);

			snprintf(name, sizeof(name), "%s%s%s", linker, DM_STRLEN(vid) ? "." : "", DM_STRLEN(vid) ? vid : "");
		}

		dmuci_set_value_by_section(dev_s, "ifname", linker);
		dmuci_set_value_by_section(dev_s, "name", name);

		snprintf(curr_path, sizeof(curr_path), "Device.Ethernet.VLANTermination.%s", instance);

		// Update VLAN Termination instance if exists
		ethernet___Update_VLAN_Termination_Layer(curr_path, name);

		// Update MACVLAN instance if exists
		ethernet___Update_MAC_VLAN_Layer(curr_path, name);

		// Update PPP Interface instance if exists
		ppp___Update_PPP_Interface_Layer(curr_path, name);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, name);
	}
}

void ethernet___Update_VLAN_Termination_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update VLAN Termination instance if exists
	ethernet___Update_VLAN_Termination_Layer(path, linker);

	// Update MACVLAN instance if exists
	ethernet___Update_MAC_VLAN_Layer(path, linker);

	// Update PPP Interface instance if exists
	ppp___Update_PPP_Interface_Layer(path, linker);

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

void ethernet___Update_Link_Layer(char *path, char *linker)
{
	struct uci_section *dmmap_s = NULL;

	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_ethernet", "link", "LowerLayers", path, dmmap_s) {
		char *instance = NULL;
		char curr_path[128] = {0};

		dmuci_get_value_by_section_string(dmmap_s, "link_instance", &instance);
		if (!DM_STRLEN(instance))
			continue;

		dmuci_set_value_by_section(dmmap_s, "device", linker);

		if (match(path, "Device.Bridging.Bridge.*.Port.", 0, NULL)) {
			// Remove unused Interface section created by Bridge Object if it exists
			struct uci_section *s = get_dup_section_in_config_opt("network", "interface", "device", linker);
			dmuci_delete_by_section(s, NULL, NULL);
		}

		snprintf(curr_path, sizeof(curr_path), "Device.Ethernet.Link.%s", instance);

		// Update IP Interface instance if exists
		ip___Update_IP_Interface_Layer(curr_path, linker);
	}
}

void ethernet___Update_Link_Top_Layers(char *path, char *linker)
{
	char *p = DM_STRRCHR(path, '.');
	if (p) *p = 0;

	// Update VLAN Termination instance if exists
	ethernet___Update_VLAN_Termination_Layer(path, linker);

	// Update MACVLAN instance if exists
	ethernet___Update_MAC_VLAN_Layer(path, linker);

	// Update PPP Interface instance if exists
	ppp___Update_PPP_Interface_Layer(path, linker);

	// Update IP Interface instance if exists
	ip___Update_IP_Interface_Layer(path, linker);
}

void bridging___get_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char **value)
{
	struct uci_list *uci_opt_list = NULL;
	struct uci_element *e = NULL;
	char uci_value[256] = {0};
	unsigned pos = 0;

	if (!data || !uci_opt_name)
		return;

	dmuci_get_value_by_section_list(device_sec, uci_opt_name, &uci_opt_list);
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

void bridging___set_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char *value)
{
	char *pch = NULL, *pchr = NULL;
	int idx = 0;

	if (!data || !uci_opt_name || !value)
		return;

	/* delete current list values */
	dmuci_set_value_by_section(device_sec, uci_opt_name, "");

	/* tokenize each value from received comma separated string and add it to uci file in the format x:y
	x being priority and y being priority to be mapped to */
	for (pch = strtok_r(value, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr), idx++) {
		char buf[16] = {0};

		/* convert values to uci format (x:y) and add */
		snprintf(buf, sizeof(buf), "%d%c%s", idx, ':', pch);
		dmuci_add_list_value_by_section(device_sec, uci_opt_name, buf);
	}
}

struct uci_section *ethernet___get_ethernet_interface_section(const char *device_name)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("network", "device", s) {
		char *name = NULL;

		if (!dmuci_is_option_value_empty(s, "type"))
			continue;

		dmuci_get_value_by_section_string(s, "name", &name);

		if (DM_STRCMP(name, device_name) == 0)
			return s;
	}

	return NULL;
}

char *ethernet___get_ethernet_interface_name(char *device_name)
{
	char *dev_name = dmstrdup(device_name);

	if (!ethernet___get_ethernet_interface_section(dev_name)) {
		struct uci_section *dev_s = NULL;

		dev_s = get_dup_section_in_config_opt("network", "device", "name", dev_name);

		char *has_vid = DM_STRRCHR(dev_name, '.');
		if (has_vid)
			*has_vid = '\0';

		if (dev_s) { // Verify if the device has dual tags
			char *type = NULL;

			dmuci_get_value_by_section_string(dev_s, "type", &type);
			if (DM_STRCMP(type, "8021ad") == 0) {
				has_vid = DM_STRRCHR(dev_name, '.');
				if (has_vid)
					*has_vid = '\0';
			}
		}
	}

	return dev_name;
}
