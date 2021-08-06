/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "ethernet.h"

struct eth_port_args
{
	struct uci_section *eth_port_sec;
	char *ifname;
};

struct eth_rmon_args
{
	struct uci_section *eth_rmon_sec;
	json_object *eth_rmon_obj;
};

/*************************************************************
* INIT
**************************************************************/
static inline int init_eth_port(struct eth_port_args *args, struct uci_section *s, char *ifname)
{
	args->eth_port_sec = s;
	args->ifname = ifname;
	return 0;
}

static inline int init_eth_rmon(struct eth_rmon_args *args, struct uci_section *s, json_object *obj)
{
	args->eth_rmon_sec = s;
	args->eth_rmon_obj = obj;
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
struct uci_section *get_device_section(char *dev_name)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "device", "name", dev_name, s) {
		return s;
	}
	return NULL;
}

static void get_bridge_port_linker(struct dmctx *ctx, char *device_s_name, char **value)
{
	struct uci_section *dmmap_section = NULL, *bridge_port = NULL;

	*value = NULL;
	get_dmmap_section_of_config_section("dmmap_bridge", "device", device_s_name, &dmmap_section);
	if (dmmap_section != NULL) {
		char *br_inst = NULL;

		dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, bridge_port) {
			char *management = NULL;

			dmuci_get_value_by_section_string(bridge_port, "management", &management);
			if (management && strcmp(management, "1") == 0) {
				char linker[512] = {0};
				char *port = NULL;

				dmuci_get_value_by_section_string(bridge_port, "port", &port);
				snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, section_name(bridge_port), port);
				adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", linker, value);
				break;
			}
		}
	}
}

static int eth_iface_sysfs(const struct uci_section *data, const char *name, char **value)
{
	char *device;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
	return get_net_device_sysfs(device, name, value);
}

static int eth_port_sysfs(const struct eth_port_args *args, const char *name, char **value)
{
	return get_net_device_sysfs(args->ifname, name, value);
}

static struct uci_section *is_device_section_exist(char *device)
{
	struct uci_section *s = NULL;
	char *dev;

	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		dmuci_get_value_by_section_string(s, "device", &dev);
		if (strcmp(dev, device) == 0)
			return s;
	}
	return s;
}

bool ethernet_check_section_in_curr_section(char *curr_section, char *section)
{
	char *pch = NULL, *pchr = NULL, section_list[256] = {0};

	DM_STRNCPY(section_list, curr_section, sizeof(section_list));
	for (pch = strtok_r(section_list, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
		if (strcmp(pch, section) == 0)
			return true;
	}
	return false;
}

static void add_section_in_curr_section(struct uci_section *dmmap_section, char *curr_section, char *section)
{
	char section_list[256] = {0}, *p = section_list;
	dmstrappendstr(p, curr_section);
	dmstrappendchr(p, ',');
	dmstrappendstr(p, section);
	dmstrappendend(p);

	dmuci_set_value_by_section(dmmap_section, "section_name", section_list);
}

bool ethernet_name_exists_in_devices(char *name)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "device", "name", name, s) {
		return true;
	}
	return false;
}

static void add_new_dmmap_section(char *macaddr, char*interface, char *section_name)
{
	struct uci_section *dmmap = NULL;

	dmuci_add_section_bbfdm(DMMAP, "link", &dmmap);
	dmuci_set_value_by_section(dmmap, "mac", macaddr);
	dmuci_set_value_by_section(dmmap, "device", interface);
	dmuci_set_value_by_section(dmmap, "section_name", section_name);
}

static void create_link(char *sec_name, char *mac_addr)
{
	char *macaddr = (*mac_addr != '\0') ? mac_addr : get_macaddr(sec_name);
	if (macaddr[0] == '\0')
		return;

	char *device = get_device(sec_name);
	if (device[0] == '\0')
		return;

	/* For all the Ethernet link objects pointing to same Ethernet Interface, only one ethernet link */
	char intf[32] = {0};
	DM_STRNCPY(intf, device, sizeof(intf));
	char *vid = strchr(intf, '.');
	char *macvlan = strchr(intf, '_');
	if (vid != NULL || !macvlan) {
		if (vid) *vid = '\0';
		struct uci_section *dmmap_section = is_device_section_exist(intf);
		if (dmmap_section) {
			char *section_name;
			dmuci_get_value_by_section_string(dmmap_section, "section_name", &section_name);

			/* Check section name exist => if yes, return*/
			if (ethernet_check_section_in_curr_section(section_name, sec_name))
				return;

			/* Update only section name */
			add_section_in_curr_section(dmmap_section, section_name, sec_name);

		} else {
			/* Add new dmmap section */
			add_new_dmmap_section(macaddr, intf, sec_name);
		}
		return;
	}

	struct uci_section *s = NULL;
	char *dev_sec_name;
	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		dmuci_get_value_by_section_string(s, "section_name", &dev_sec_name);
		if (strcmp(sec_name, dev_sec_name) == 0) {
			dmuci_set_value_by_section(s, "mac", macaddr);
			return;
		}
	}

	/* Add new dmmap section */
	add_new_dmmap_section(macaddr, intf, sec_name);
}

static int dmmap_synchronizeEthernetLink(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *device, *macaddr;

	uci_foreach_sections("network", "interface", s) {

		// Skip this interface section if its name=loopback
		if (strcmp(section_name(s), "loopback") == 0)
			continue;

		// Skip this interface section if its ifname option contains '@'
		dmuci_get_value_by_section_string(s, "device", &device);
		if (strchr(device, '@'))
			continue;

		dmuci_get_value_by_section_string(s, "macaddr", &macaddr);
		create_link(section_name(s), macaddr);
	}
	return 0;
}

static char *get_vlan_last_instance_bbfdm(char *package, char *section, char *opt_inst)
{
	struct uci_section *s = NULL, *confsect;
	char *inst = NULL, *last_inst = NULL, *type, *sect_name, *name;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		dmuci_get_value_by_section_string(s, "section_name", &sect_name);
		get_config_section_of_dmmap_section("network", "device", sect_name, &confsect);
		dmuci_get_value_by_section_string(confsect, "type", &type);
		dmuci_get_value_by_section_string(confsect, "name", &name);
		if (strcmp(type, "bridge") == 0 || strcmp(type, "untagged") == 0) {
			dmuci_set_value_by_section(s, "vlan_term_instance", "");
			continue;
		}
		inst = update_instance(last_inst, 2, s, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(inst);
	}
	return inst;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Ethernet.Interface.{i}.!UCI:ports/ethport/dmmap_ports*/
static int browseEthernetInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *ifname;
	struct eth_port_args curr_eth_port_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ports", "ethport", "dmmap_ports", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);

		init_eth_port(&curr_eth_port_args, p->config_section, ifname);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "eth_port_instance", "eth_port_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_eth_port_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL, *max_inst = NULL;

	dmmap_synchronizeEthernetLink(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   s, "link_instance", "link_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.!UCI:network/device/dmmap_network*/
static int browseEthernetVLANTerminationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *type, *name, *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "device", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "type", &type);
		dmuci_get_value_by_section_string(p->config_section, "name", &name);
		if (strcmp(type, "bridge") == 0 || strcmp(type, "untagged") == 0)
			continue;

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "vlan_term_instance", "vlan_term_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetRMONStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *ifname;
	struct eth_rmon_args curr_eth_rmon_args = {0};
	struct dmmap_dup *p = NULL;
	json_object *res = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ports", "ethport", "dmmap_eth_rmon", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);

		dmubus_call("ethernet", "rmonstats", UBUS_ARGS{{"ifname", ifname, String}}, 1, &res);
		if (!res) continue;

		init_eth_rmon(&curr_eth_rmon_args, p->config_section, res);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "eth_rmon_instance", "eth_rmon_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_eth_rmon_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* LINKER
**************************************************************/
static int get_linker_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct eth_port_args *)data)->ifname)
		*linker = ((struct eth_port_args *)data)->ifname;
	else
		*linker = "";
	return 0;
}

static int get_linker_link(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", linker);
	if ((*linker)[0] == '\0')
		dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", linker);
	return 0;
}

static int get_linker_vlan_term(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", linker);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_link = NULL;
	char interface_name[32];

	char *inst = get_last_instance_bbfdm(DMMAP, "link", "link_instance");
	snprintf(interface_name, sizeof(interface_name), "link_%d", inst ? atoi(inst)+1 : 1);

	/* Add device section */
	dmuci_add_section("network", "interface", &s);
	dmuci_rename_section_by_section(s, interface_name);

	/* Add link section in dmmap file */
	dmuci_add_section_bbfdm(DMMAP, "link", &dmmap_link);
	dmuci_set_value_by_section(dmmap_link, "section_name", interface_name);
	*instance = update_instance(inst, 2, dmmap_link, "link_instance");
	return 0;
}

static int delObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *ss = NULL, *sstmp = NULL;
	char *sect_name = NULL, *section_list = NULL, *pch = NULL, *pchr = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", &sect_name);
			// Remove dmmap section
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);

			// Check each network section in the list of sections
			if (*sect_name == '\0')
				return -1;

			section_list = dmstrdup(sect_name);
			for (pch = strtok_r(section_list, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				// Remove network and device section
				uci_foreach_sections_safe("network", "interface", stmp, s) {
					if (strcmp(section_name(s), pch) == 0) {
						// Remove the device section corresponding to this interface if exists
						char *device = get_device(pch);
						uci_foreach_option_eq_safe("network", "device", "name", device, sstmp, ss) {
							char *type;
							dmuci_get_value_by_section_string(s, "type", &type);
							if (strcmp(type, "untagged") == 0) dmuci_delete_by_section(ss, NULL, NULL);
							break;
						}

						// Remove network section
						dmuci_delete_by_section(s, NULL, NULL);
						break;
					}
				}
			}
			dmfree(section_list);
			return 0;
		case DEL_ALL:
			return FAULT_9005;
	}
	return 0;
}

static int addObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_network = NULL;
	char device_name[32];

	char *inst = get_vlan_last_instance_bbfdm("dmmap_network", "device", "vlan_term_instance");
	snprintf(device_name, sizeof(device_name), "vlan_ter_%d", inst ? atoi(inst)+1 : 1);

	// Add device section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");

	// Add device section in dmmap_network file
	dmuci_add_section_bbfdm("dmmap_network", "device", &dmmap_network);
	dmuci_set_value_by_section(dmmap_network, "section_name", device_name);
	*instance = update_instance(inst, 2, dmmap_network, "vlan_term_instance");
	return 0;
}

static int delObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section = NULL, *s_dev = NULL, *sdevtmp = NULL;
	char *name, *type;

	switch (del_action) {
	case DEL_INST:
		// Remove device section
		dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);

		// Remove device section in dmmap_network file
		get_dmmap_section_of_config_section("dmmap_network", "device", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_delete_by_section(dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("network", "device", sdevtmp, s_dev) {
			dmuci_get_value_by_section_string(s_dev, "type", &type);
			dmuci_get_value_by_section_string(s_dev, "name", &name);
			if (strcmp(type, "bridge") == 0 || strcmp(type, "untagged") == 0)
				continue;

			// Remove device section in dmmap_network file
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name(s_dev), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove device section
			dmuci_delete_by_section(s_dev, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Ethernet.InterfaceNumberOfEntries!UCI:ports/ethport/*/
static int get_Ethernet_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("ports", "ethport", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_LinkNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	dmmap_synchronizeEthernetLink(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Ethernet.VLANTerminationNumberOfEntries!UCI:network/device/*/
static int get_Ethernet_VLANTerminationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *type, *name;
	int cnt = 0;

	uci_foreach_sections("network", "device", s) {
		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(type, "bridge") == 0 || strcmp(type, "untagged") == 0)
			continue;
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_RMONStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	json_object *res = NULL;
	char *ifname;
	int cnt = 0;

	uci_foreach_sections("ports", "ethport", s) {
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		dmubus_call("ethernet", "rmonstats", UBUS_ARGS{{"ifname", ifname, String}}, 1, &res);
		if (!res) continue;
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Enable!UCI:ports/ethport,@i-1/enabled*/
static int get_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct eth_port_args *)data)->eth_port_sec, "enabled", "1");
	return 0;
}

static int set_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Status!SYSFS:/sys/class/net/@Name/operstate*/
static int get_EthernetInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_net_device_status(((struct eth_port_args *)data)->ifname, value);
}

/*#Device.Ethernet.Interface.{i}.Alias!UCI:dmmap_ports/ethport,@i-1/eth_port_alias*/
static int get_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_ports", "ethport", section_name(((struct eth_port_args *)data)->eth_port_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "eth_port_alias", value);
	if ((*value)[0] == '\0') {
		dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "name", value);
		dmuci_set_value_by_section(dmmap_section, "eth_port_alias", *value);
	}
	return 0;
}

static int set_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_ports", "ethport", section_name(((struct eth_port_args *)data)->eth_port_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "eth_port_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Name!UCI:ports/ethport,@i-1/ifname*/
static int get_EthernetInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "ifname", value);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_EthernetInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	struct uci_section *s = NULL;
	char *device;

	*value ="0";
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "device", &device);
		if (strstr(device, ((struct eth_port_args *)data)->ifname)) {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			DM_ASSERT(res, *value = "0");
			*value = dmjson_get_value(res, 1, "uptime");
			if((*value)[0] == '\0')
				*value = "0";
			break;
		}
	}
	return 0;
}

static int get_EthernetInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_EthernetInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (*value != '\0')
				return FAULT_9007;

			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Upstream!UCI:ports/ethport,@i-1/uplink*/
static int get_EthernetInterface_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct eth_port_args *)data)->eth_port_sec, "uplink", "0");
	return 0;
}

/*#Device.Ethernet.Interface.{i}.MACAddress!SYSFS:/sys/class/net/@Name/address*/
static int get_EthernetInterface_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "address", value);
}

/*#Device.Ethernet.Interface.{i}.MaxBitRate!UCI:ports/ethport,@i-1/speed*/
static int get_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *autoneg = NULL;

	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "autoneg", &autoneg);

	if (autoneg && strcmp(autoneg, "0") == 0)
		dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "speed", value);
	else
		*value = "-1";

	return 0;
}

static int set_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "-1") == 0)
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "1");
			else {
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "0");
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "speed", value);
			}
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.CurrentBitRate!UBUS:network.device/status/name,@Name/speed*/
static int get_EthernetInterface_CurrentBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	int speed = 0;

	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct eth_port_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "speed");
	sscanf(*value, "%d%*c", &speed);
	dmasprintf(value, "%d", speed);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.DuplexMode!UCI:ports/ethport,@i-1/duplex*/
static int get_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *autoneg = NULL;

	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "autoneg", &autoneg);

	if (autoneg && strcmp(autoneg, "0") == 0) {
		char *duplex = NULL;

		dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "duplex", &duplex);
		*value = (duplex && strcmp(duplex, "full") == 0) ? "Full" : "Half";
	} else {
		*value = "Auto";
	}
	return 0;
}

static int set_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DuplexMode, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Auto") == 0)
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "1");
			else {
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "0");
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "duplex", (*value == 'F') ? "full" : "half");
			}
			return 0;
	}
	return 0;
}

static int get_EthernetInterface_EEECapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.Ethernet.Interface.{i}.EEEEnable!UCI:ports/ethport,@i-1/eee*/
static int get_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct eth_port_args *)data)->eth_port_sec, "eee", "1");
	return 0;
}

static int set_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "eee", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_EthernetInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_EthernetInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_EthernetInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_EthernetInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_EthernetInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_EthernetInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_EthernetInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_EthernetInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_dropped", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_EthernetInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/multicast", value);
}

static int eth_port_ubus(const struct eth_port_args *args, const char *name, char **value)
{
	json_object *res = NULL;

	dmubus_call("ethernet", "ifstats", UBUS_ARGS{{"ifname", args->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Stats.MulticastPacketsSent!UBUS:ethernet/ifstats/ifname,ifname/tx_multicast_packets*/
static int get_EthernetInterfaceStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_ubus(data, "tx_multicast_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.UnicastPacketsSent!UBUS:ethernet/ifstats/ifname,ifname/tx_unicast_packets*/
static int get_EthernetInterfaceStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_ubus(data, "tx_unicast_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.UnicastPacketsReceived!UBUS:ethernet/ifstats/ifname,ifname/rx_unicast_packets*/
static int get_EthernetInterfaceStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_ubus(data, "rx_unicast_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.BroadcastPacketsSent!UBUS:ethernet/ifstats/ifname,ifname/tx_broadcast_packets*/
static int get_EthernetInterfaceStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_ubus(data, "tx_broadcast_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.BroadcastPacketsReceived!UBUS:ethernet/ifstats/ifname,ifname/rx_broadcast_packets*/
static int get_EthernetInterfaceStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_ubus(data, "rx_broadcast_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.UnknownProtoPacketsReceived!UBUS:ethernet/ifstats/ifname,ifname/rx_unknown_packets*/
static int get_EthernetInterfaceStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_ubus(data, "rx_unknown_packets", value);
}

static int get_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetLink_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

static int get_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "link_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "link_alias", value);
			break;
	}
	return 0;
}

static int get_EthernetLink_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", value);
	return 0;
}

static int get_EthernetLink_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *interface;

	dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", &interface);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	if((*value)[0] == '\0')
		*value = "0";
	return 0;
}

static int get_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;
	char *device_s_type = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &linker);
	if (linker && *linker == '\0')
		return 0;

	// get device section mapped to this device name
	struct uci_section *br_device_s = get_device_section(linker);

	if (br_device_s) dmuci_get_value_by_section_string(br_device_s, "type", &device_s_type);

	if (br_device_s && strcmp(device_s_type, "bridge") == 0) {
		get_bridge_port_linker(ctx, section_name(br_device_s), value);
	} else {
		char *vid = strchr(linker, '.');
		if (vid) *vid = '\0';
		char *macvlan = strchr(linker, '_');
		if (macvlan) *macvlan = '\0';
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
	}

	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *link_linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &link_linker);
			if (link_linker == NULL || *link_linker == '\0')
				return -1;

			if (strncmp(value, "Device.Ethernet.Interface.", 26) == 0) {
				struct uci_section *s = NULL;
				char *int_name = NULL;

				dmuci_set_value_by_section((struct uci_section *)data, "device", link_linker);
				dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", &int_name);

				uci_foreach_sections("network", "interface", s) {
					if (strcmp(section_name(s), int_name) == 0) {
						dmuci_set_value_by_section(s, "device", link_linker);
						break;
					}
				}
			} else if (strncmp(value, "Device.Bridging.Bridge.", 23) == 0) {
				char br_linker[250] = {0};

				DM_STRNCPY(br_linker, link_linker, sizeof(br_linker));

				char *bridge = strchr(br_linker, ':');
				if (bridge) {
					struct uci_section *s = NULL;
					char br_inst[8] = {0};
					char device[32] = {0};
					char *int_name = NULL;
					char *dev_s_name = NULL;

					*bridge = '\0';
					DM_STRNCPY(br_inst, br_linker+3, sizeof(br_inst));

					dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", &int_name);

					//Generate the device name for bridge as br-<NETWORK>
					snprintf(device, sizeof(device), "br-%s", int_name);

					uci_foreach_sections("network", "interface", s) {
						if (int_name && strcmp(section_name(s), int_name) == 0) {
							dmuci_set_value_by_section(s, "device", device);
							break;
						}
					}

					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {

						if (dev_s_name == NULL || *dev_s_name == '\0')
							dmuci_get_value_by_section_string(s, "device_section_name", &dev_s_name);

						dmuci_set_value_by_section(s, "device", device);
					}

					if (dev_s_name && *dev_s_name) {
						uci_foreach_sections("network", "device", s) {
							if (dev_s_name && strcmp(section_name(s), dev_s_name) == 0) {
								dmuci_set_value_by_section(s, "name", device);
								break;
							}
						}
					}

					dmuci_set_value_by_section((struct uci_section *)data, "device", device);
				}
			}
			break;
	}
	return 0;
}

static int get_EthernetLink_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mac_addr;
	char address[64] = {0};
	int i;

	dmuci_get_value_by_section_string((struct uci_section *)data, "mac", &mac_addr);
	DM_STRNCPY(address, mac_addr, sizeof(address));
	for (i = 0; address[i] != '\0'; i++) {
		if(address[i] >= 'a' && address[i] <= 'z') {
			address[i] = address[i] - 32;
		}
	}

	*value = dmstrdup(address);
	return 0;
}

static int get_EthernetLinkStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_bytes", value);
}

static int get_EthernetLinkStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_bytes", value);
}

static int get_EthernetLinkStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_packets", value);
}

static int get_EthernetLinkStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_packets", value);
}

static int get_EthernetLinkStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_errors", value);
}

static int get_EthernetLinkStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_errors", value);
}

static int get_EthernetLinkStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_dropped", value);
}

static int get_EthernetLinkStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_dropped", value);
}

static int get_EthernetLinkStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/multicast", value);
}

static int eth_iface_ubus(struct uci_section *iface_s, const char *name, char **value)
{
	json_object *res = NULL;
	char *sec_name;

	dmuci_get_value_by_section_string(iface_s, "section_name", &sec_name);
	char *device = get_device(sec_name);

	dmubus_call("ethernet", "ifstats", UBUS_ARGS{{"ifname", device, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

static int get_EthernetLinkStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_ubus(data, "tx_multicast_packets", value);
}

static int get_EthernetLinkStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_ubus(data, "tx_unicast_packets", value);
}

static int get_EthernetLinkStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_ubus(data, "rx_unicast_packets", value);
}

static int get_EthernetLinkStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_ubus(data, "tx_broadcast_packets", value);
}

static int get_EthernetLinkStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_ubus(data, "rx_broadcast_packets", value);
}

static int get_EthernetLinkStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_ubus(data, "rx_unknown_packets", value);
}

static int get_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_EthernetVLANTermination_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.Alias!UCI:dmmap_network/device,@i-1/vlan_term_alias*/
static int get_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "device", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "vlan_term_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "vlan_term_alias", value);
			return 0;
	}
	return 0;
}

static int get_EthernetVLANTermination_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name((struct uci_section *)data));
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_EthernetVLANTermination_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	struct uci_section *s = NULL;
	char *devname;

	*value = "0";
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", &devname);
	uci_foreach_option_eq("network", "interface", "device", devname, s) {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
		DM_ASSERT(res, *value = "0");
		*value = dmjson_get_value(res, 1, "uptime");
		if((*value)[0] == '\0')
			*value = "0";
		break;
	}
	return 0;
}

static int get_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name, *type, *inner_vid, *dev_name;

	dmuci_get_value_by_section_string((struct uci_section *)data, "name", &name);
	dmuci_get_value_by_section_string((struct uci_section *)data, "type", &type);
	char *vid = strchr(name, '.');
	if (vid) *vid = '\0';

	if (strncmp(type, "8021ad", 6) == 0) {
		// 8021ad device, will have a vlan termination object as its lowerlayer
		dmuci_get_value_by_section_string((struct uci_section *)data, "inner_vid", &inner_vid);
		dmasprintf(&dev_name, "%s.%s", name, inner_vid);
		adm_entry_get_linker_param(ctx, "Device.Ethernet.VLANTermination.", dev_name, value);
	} else {
		adm_entry_get_linker_param(ctx, "Device.Ethernet.Link.", name, value);
	}

	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *vlan_linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &vlan_linker);
			if (vlan_linker == NULL || *vlan_linker == '\0')
				return -1;

			if (strncmp(value, "Device.Ethernet.Link.", 21) == 0) {
				char new_name[16] = {0}, *type;

				// Get type option from device section
				dmuci_get_value_by_section_string((struct uci_section *)data, "type", &type);

				if ((strcmp(type, "macvlan") == 0)) {
					/* type == macvlan */

					struct uci_section *s = NULL, *dmmap_s = NULL;
					char link_inst[8] = {0}, sec_name[32] = {0};

					snprintf(link_inst, sizeof(link_inst), "%c", value[21]);
					snprintf(new_name, sizeof(new_name), "%s_%s", vlan_linker, link_inst);

					if (ethernet_name_exists_in_devices(new_name))
						return -1;

					uci_foreach_option_eq("network", "interface", "device", vlan_linker, s) {
						dmuci_set_value_by_section(s, "device", new_name);
						DM_STRNCPY(sec_name, section_name(s), sizeof(sec_name));
						break;
					}

					get_dmmap_section_of_config_section_eq("dmmap", "link", "link_instance", link_inst, &dmmap_s);
					dmuci_set_value_by_section(dmmap_s, "device", new_name);
					dmuci_set_value_by_section(dmmap_s, "section_name", sec_name);

				} else {
					/* type != macvlan */
					struct uci_section *s = NULL;
					char *vid, *old_name;

					dmuci_get_value_by_section_string((struct uci_section *)data, "name", &old_name);
					dmuci_get_value_by_section_string((struct uci_section *)data, "vid", &vid);
					if (*vid != '\0')
						snprintf(new_name, sizeof(new_name), "%s.%s", vlan_linker, vid);
					else
						snprintf(new_name, sizeof(new_name), "%s", vlan_linker);

					if (ethernet_name_exists_in_devices(new_name))
						return -1;

					// if device is lowerlayer to an ip interface, then
					// the ifname of the ip interface also needs to be updated
					uci_foreach_option_eq("network", "interface", "device", old_name, s) {
						dmuci_set_value_by_section(s, "device", new_name);
					}

				}

				// Set ifname and name options of device section
				dmuci_set_value_by_section((struct uci_section *)data, "ifname", vlan_linker);
				dmuci_set_value_by_section((struct uci_section *)data, "name", new_name);

			} else if (strncmp(value, "Device.Ethernet.VLANTermination.", 32) == 0) {
				struct uci_section *ss = NULL;
				char *dev_name, *inner_vid, *vid, new_name[16] = {0};

				dmuci_get_value_by_section_string((struct uci_section *)data, "vid", &vid);

				uci_foreach_option_eq("network", "device", "name", vlan_linker, ss) {
					dmuci_get_value_by_section_string(ss, "vid", &inner_vid);
					dmuci_get_value_by_section_string(ss, "ifname", &dev_name);
					break;
				}
				snprintf(new_name, sizeof(new_name), "%s.%s.%s", dev_name, inner_vid, vid);
				if (ethernet_name_exists_in_devices(new_name))
					return -1;

				dmuci_set_value_by_section((struct uci_section *)data, "ifname", dev_name);
				dmuci_set_value_by_section((struct uci_section *)data, "name", new_name);
				dmuci_set_value_by_section((struct uci_section *)data, "inner_vid", inner_vid);
			}
			break;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.VLANID!UCI:network/device,@i-1/vid*/
static int get_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "vid", "1");
	return 0;
}

static int set_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *ifname, *name, *curr_ifname, *type, *inner_vid, *old_vid, *old_name, *sec_name, *ad_vid;
	char *ad_itf_ifname;
	struct uci_section *s = NULL, *d_sec = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			// Get type option from device section
			dmuci_get_value_by_section_string((struct uci_section *)data, "type", &type);

			if (strcmp(type, "macvlan") != 0) {
				/* only when type != macvlan */

				dmuci_get_value_by_section_string((struct uci_section *)data, "ifname", &ifname);
				if (*ifname != '\0') {
					if (strcmp(type, "8021ad") == 0) {
						dmuci_get_value_by_section_string((struct uci_section *)data, "inner_vid", &inner_vid);
						dmasprintf(&name, "%s.%s.%s", ifname, inner_vid, value);
					} else {
						dmuci_get_value_by_section_string((struct uci_section *)data, "vid", &old_vid);
						dmasprintf(&old_name, "%s.%s.", ifname, old_vid);
						dmasprintf(&name, "%s.%s", ifname, value);
					}

					if (ethernet_name_exists_in_devices(name))
						return -1;

					// set ifname option of the corresponding interface section
					dmuci_get_value_by_section_string((struct uci_section *)data, "name", &curr_ifname);
					uci_foreach_option_eq("network", "interface", "device", curr_ifname, s) {
						dmuci_set_value_by_section(s, "device", name);
					}

					if (strncmp(type, "8021q", 5) == 0) {
						// Update the 8021ad instance with vid of lower layer
						uci_foreach_sections("network", "device", d_sec) {
							// We do not need to get the type here since we have the name
							// already with us, we  can use that as a key
							dmuci_get_value_by_section_string(d_sec, "name", &sec_name);
							if (strncmp(sec_name, old_name, strlen(old_name)) == 0) {
								dmuci_get_value_by_section_string(d_sec, "vid", &ad_vid);
								dmasprintf(&ad_itf_ifname, "%s.%s.%s", ifname, value, ad_vid);
								dmasprintf(&old_name, "%s.%s.%s", ifname, old_vid, ad_vid);

								dmuci_set_value_by_section(d_sec, "inner_vid", value);
								dmuci_set_value_by_section(d_sec, "name", ad_itf_ifname);
								// if this 8021ad instance is lowerlayer to an ip interface, then
								// the ifname of the ip interface also needs to be updated
								uci_foreach_option_eq("network", "interface", "device", old_name, s) {
									dmuci_set_value_by_section(s, "device", ad_itf_ifname);
								}
								break;
							}
						}

					}

					// set name option of the device section
					dmuci_set_value_by_section((struct uci_section *)data, "name", name);
					dmfree(name);
				}
			}

			// set vid option of the device section
			dmuci_set_value_by_section((struct uci_section *)data, "vid", value);
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.TPID!UCI:network/device,@i-1/type*/
static int get_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "type", value);
	if (strcmp(*value, "8021q") == 0)
		*value = "33024";
	else if (strcmp(*value, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "33024") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "type", "8021q");
			else if (strcmp(value, "34984") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "type", "8021ad");
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_EthernetVLANTerminationStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_EthernetVLANTerminationStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_EthernetVLANTerminationStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_EthernetVLANTerminationStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_EthernetVLANTerminationStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_EthernetVLANTerminationStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_EthernetVLANTerminationStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_EthernetVLANTerminationStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_dropped", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_EthernetVLANTerminationStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/multicast", value);
}

/*#Device.Ethernet.RMONStats.{i}.Enable!UCI:ports/ethport,@i-1/rmon*/
static int get_EthernetRMONStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct eth_rmon_args *)data)->eth_rmon_sec, "rmon", "1");
	return 0;
}

static int set_EthernetRMONStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct eth_rmon_args *)data)->eth_rmon_sec, "rmon", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_EthernetRMONStats_Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Alias!UCI:dmmap_eth_rmon/ethport,@i-1/eth_rmon_alias*/
static int get_EthernetRMONStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_eth_rmon", "ethport", section_name(((struct eth_rmon_args *)data)->eth_rmon_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "eth_rmon_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_EthernetRMONStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_eth_rmon", "ethport", section_name(((struct eth_rmon_args *)data)->eth_rmon_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "eth_rmon_alias", value);
			break;
	}
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Name!UCI:ports/ethport,@i-1/ifname*/
static int get_EthernetRMONStats_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "ifname");
	return 0;
}

static int get_EthernetRMONStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;

	dmuci_get_value_by_section_string(((struct eth_rmon_args *)data)->eth_rmon_sec, "ifname", &linker);
	adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_EthernetRMONStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int set_EthernetRMONStats_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","4094"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_AllQueues(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_EthernetRMONStats_AllQueues(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.Ethernet.RMONStats.{i}.Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_bytes*/
static int get_EthernetRMONStats_Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_bytes");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets*/
static int get_EthernetRMONStats_Packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.BroadcastPackets!UBUS:ethernet/rmonstats/ifname,ifname/rx_broadcast_packets*/
static int get_EthernetRMONStats_BroadcastPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_broadcast_packets");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.MulticastPackets!UBUS:ethernet/rmonstats/ifname,ifname/rx_multicast_packets*/
static int get_EthernetRMONStats_MulticastPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_multicast_packets");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.CRCErroredPackets!UBUS:ethernet/rmonstats/ifname,ifname/rx_crc_error_packets*/
static int get_EthernetRMONStats_CRCErroredPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_crc_error_packets");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.UndersizePackets!UBUS:ethernet/rmonstats/ifname,ifname/rx_undersize_packets*/
static int get_EthernetRMONStats_UndersizePackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_undersize_packets");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.OversizePackets!UBUS:ethernet/rmonstats/ifname,ifname/rx_oversize_packets*/
static int get_EthernetRMONStats_OversizePackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_oversize_packets");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets64Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets_64bytes*/
static int get_EthernetRMONStats_Packets64Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets_64bytes");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets65to127Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets_65to127bytes*/
static int get_EthernetRMONStats_Packets65to127Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets_65to127bytes");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets128to255Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets_128to255bytes*/
static int get_EthernetRMONStats_Packets128to255Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets_128to255bytes");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets256to511Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets_256to511bytes*/
static int get_EthernetRMONStats_Packets256to511Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets_256to511bytes");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets512to1023Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets_512to1023bytes*/
static int get_EthernetRMONStats_Packets512to1023Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets_512to1023bytes");
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Packets1024to1518Bytes!UBUS:ethernet/rmonstats/ifname,ifname/rx_packets_1024to1518bytes*/
static int get_EthernetRMONStats_Packets1024to1518Bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "rx_packets_1024to1518bytes");
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Ethernet. *** */
DMOBJ tEthernetObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseEthernetInterfaceInst, NULL, NULL, tEthernetInterfaceObj, tEthernetInterfaceParams, get_linker_interface, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"Link", &DMWRITE, addObjEthernetLink, delObjEthernetLink, NULL, browseEthernetLinkInst, NULL, NULL, tEthernetLinkObj, tEthernetLinkParams, get_linker_link, BBFDM_BOTH, LIST_KEY{"Name", "Alias", "MACAddress", NULL}},
{"VLANTermination", &DMWRITE, addObjEthernetVLANTermination, delObjEthernetVLANTermination, NULL, browseEthernetVLANTerminationInst, NULL, NULL, tEthernetVLANTerminationObj, tEthernetVLANTerminationParams, get_linker_vlan_term, BBFDM_BOTH, LIST_KEY{"Name", "Alias", NULL}},
{"RMONStats", &DMREAD, NULL, NULL, "file:/etc/config/ports;ubus:ethernet->rmonstats", browseEthernetRMONStatsInst, NULL, NULL, NULL, tEthernetRMONStatsParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Interface", "VLANID", "Queue", NULL}},
{0}
};

DMLEAF tEthernetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"LinkNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_LinkNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANTerminationNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_VLANTerminationNumberOfEntries, NULL, BBFDM_BOTH},
{"RMONStatsNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_RMONStatsNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}. *** */
DMOBJ tEthernetInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetInterface_Enable, set_EthernetInterface_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetInterface_Alias, set_EthernetInterface_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetInterface_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetInterface_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetInterface_LowerLayers, set_EthernetInterface_LowerLayers, BBFDM_BOTH},
{"Upstream", &DMREAD, DMT_BOOL, get_EthernetInterface_Upstream, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetInterface_MACAddress, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMWRITE, DMT_INT, get_EthernetInterface_MaxBitRate, set_EthernetInterface_MaxBitRate, BBFDM_BOTH},
{"CurrentBitRate", &DMREAD, DMT_UNINT, get_EthernetInterface_CurrentBitRate, NULL, BBFDM_BOTH},
{"DuplexMode", &DMWRITE, DMT_STRING, get_EthernetInterface_DuplexMode, set_EthernetInterface_DuplexMode, BBFDM_BOTH},
{"EEECapability", &DMREAD, DMT_BOOL, get_EthernetInterface_EEECapability, NULL, BBFDM_BOTH},
{"EEEEnable", &DMWRITE, DMT_BOOL, get_EthernetInterface_EEEEnable, set_EthernetInterface_EEEEnable, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}.Stats. *** */
DMLEAF tEthernetInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}. *** */
DMOBJ tEthernetLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetLinkStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetLink_Enable, set_EthernetLink_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetLink_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetLink_Alias, set_EthernetLink_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetLink_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetLink_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetLink_LowerLayers, set_EthernetLink_LowerLayers, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetLink_MACAddress, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}.Stats. *** */
DMLEAF tEthernetLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetLinkStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_ErrorsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetLinkStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}. *** */
DMOBJ tEthernetVLANTerminationObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetVLANTerminationStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetVLANTerminationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetVLANTermination_Enable, set_EthernetVLANTermination_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_Alias, set_EthernetVLANTermination_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetVLANTermination_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_LowerLayers, set_EthernetVLANTermination_LowerLayers, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_VLANID, set_EthernetVLANTermination_VLANID, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_TPID, set_EthernetVLANTermination_TPID, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}.Stats. *** */
DMLEAF tEthernetVLANTerminationStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.RMONStats.{i}. *** */
DMLEAF tEthernetRMONStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetRMONStats_Enable, set_EthernetRMONStats_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetRMONStats_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Alias, set_EthernetRMONStats_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetRMONStats_Name, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Interface, set_EthernetRMONStats_Interface, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetRMONStats_VLANID, set_EthernetRMONStats_VLANID, BBFDM_BOTH},
//{"Queue", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Queue, set_EthernetRMONStats_Queue, BBFDM_BOTH},
{"AllQueues", &DMWRITE, DMT_BOOL, get_EthernetRMONStats_AllQueues, set_EthernetRMONStats_AllQueues, BBFDM_BOTH},
//{"DropEvents", &DMREAD, DMT_UNINT, get_EthernetRMONStats_DropEvents, NULL, BBFDM_BOTH},
{"Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Bytes, NULL, BBFDM_BOTH},
{"Packets", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets, NULL, BBFDM_BOTH},
{"BroadcastPackets", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_BroadcastPackets, NULL, BBFDM_BOTH},
{"MulticastPackets", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_MulticastPackets, NULL, BBFDM_BOTH},
{"CRCErroredPackets", &DMREAD, DMT_UNINT, get_EthernetRMONStats_CRCErroredPackets, NULL, BBFDM_BOTH},
{"UndersizePackets", &DMREAD, DMT_UNINT, get_EthernetRMONStats_UndersizePackets, NULL, BBFDM_BOTH},
{"OversizePackets", &DMREAD, DMT_UNINT, get_EthernetRMONStats_OversizePackets, NULL, BBFDM_BOTH},
{"Packets64Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets64Bytes, NULL, BBFDM_BOTH},
{"Packets65to127Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets65to127Bytes, NULL, BBFDM_BOTH},
{"Packets128to255Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets128to255Bytes, NULL, BBFDM_BOTH},
{"Packets256to511Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets256to511Bytes, NULL, BBFDM_BOTH},
{"Packets512to1023Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets512to1023Bytes, NULL, BBFDM_BOTH},
{"Packets1024to1518Bytes", &DMREAD, DMT_UNLONG, get_EthernetRMONStats_Packets1024to1518Bytes, NULL, BBFDM_BOTH},
{0}
};
