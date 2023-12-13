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

#include "ethernet.h"

struct eth_port_args
{
	struct dmmap_dup *sections;
	char *ifname;
};

struct eth_rmon_args
{
	struct dmmap_dup *sections;
	json_object *eth_rmon_obj;
};

/*************************************************************
* INIT
**************************************************************/
static inline int init_eth_port(struct eth_port_args *args, struct dmmap_dup *s, char *ifname)
{
	args->sections = s;
	args->ifname = ifname;
	return 0;
}

static inline int init_eth_rmon(struct eth_rmon_args *args, struct dmmap_dup *s, json_object *obj)
{
	args->sections = s;
	args->eth_rmon_obj = obj;
	return 0;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static bool check_vlan_termination_section(const char *name)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "device", "type", "bridge", s) {
		struct uci_list *uci_list = NULL;

		dmuci_get_value_by_section_list(s, "ports", &uci_list);

		if (uci_list == NULL)
			continue;

		if (value_exists_in_uci_list(uci_list, name))
			return false;
	}

	return true;
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

static struct uci_section *is_ethernet_link_exist(char *device)
{
	struct uci_section *s = NULL;
	char *dev = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_ethernet", "link", s) {
		dmuci_get_value_by_section_string(s, "device", &dev);
		if (DM_STRCMP(dev, device) == 0)
			return s;
	}

	return NULL;
}

static bool is_mac_vlan_interface(char *device_name)
{
	struct uci_section *s = NULL;
	char *type = NULL, *name = NULL;

	uci_foreach_sections("network", "device", s) {

		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "name", &name);

		if (DM_STRCMP(type, "macvlan") == 0 && DM_STRCMP(name, device_name) == 0)
			return true;
	}

	return false;
}

static void add_ethernet_link_section(char *device, char *macaddr)
{
	struct uci_section *dmmap_s = NULL;

	dmuci_add_section_bbfdm("dmmap_ethernet", "link", &dmmap_s);

	dmuci_set_value_by_section(dmmap_s, "mac", macaddr);
	dmuci_set_value_by_section(dmmap_s, "device", device);
}

static void dmmap_synchronizeEthernetLink(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char *ip_instance = NULL;
	char *proto = NULL;
	char *macaddr = NULL;
	char *device = NULL;
	char *dev_name = NULL;

	uci_foreach_sections("network", "interface", s) {

		// Skip this interface section if its proto option is empty
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (DM_STRLEN(proto) == 0)
			continue;

		// Skip this interface section if its name is equal to loopback
		if (strcmp(section_name(s), "loopback") == 0)
			continue;

		// Skip this interface section if there is no IP.Interface instance map on it
		dmmap_s = get_dup_section_in_dmmap("dmmap_network", "interface", section_name(s));
		dmuci_get_value_by_section_string(dmmap_s, "ip_int_instance", &ip_instance);
		if (!dmmap_s || DM_STRLEN(ip_instance) == 0)
			continue;

		// Skip this interface section if its device option has the section_name value
		dmuci_get_value_by_section_string(s, "device", &device);
		if (strcmp(section_name(s), device) == 0)
			continue;

		// Skip this interface section if its device is empty
		device = get_device(section_name(s));
		if (DM_STRLEN(device) == 0)
			continue;

		get_net_device_sysfs(device, "address", &macaddr);

		dev_name = ethernet___get_ethernet_interface_name(device);

		if (is_mac_vlan_interface(dev_name)) {
			char *p = DM_STRRCHR(dev_name, '_');
			if (p)
				*p = '\0';
		}

		if (is_ethernet_link_exist(dev_name))
			continue;

		/* Add new ethernet link section */
		add_ethernet_link_section(dev_name, macaddr);
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Ethernet.Interface.{i}.!UCI:network/device/dmmap_ethernet*/
static int browseEthernetInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct eth_port_args curr_eth_port_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "device", "dmmap_ethernet", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *name = NULL;

		if (!dmuci_is_option_value_empty(p->config_section, "type"))
			continue;

		dmuci_get_value_by_section_string(p->config_section, "name", &name);

		init_eth_port(&curr_eth_port_args, p, name);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "eth_iface_instance", "eth_iface_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_eth_port_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeEthernetLink(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_ethernet", "link", s) {

		inst = handle_instance(dmctx, parent_node, s, "link_instance", "link_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.!UCI:network/device/dmmap_network*/
static int browseEthernetVLANTerminationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *type, *name, *inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "device", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "type", &type);
		dmuci_get_value_by_section_string(p->config_section, "name", &name);
		if (DM_STRLEN(type) == 0 ||
			DM_LSTRCMP(type, "bridge") == 0 ||
			DM_LSTRCMP(type, "macvlan") == 0 ||
			(*name != 0 && !check_vlan_termination_section(name)) ||
			(*name == 0 && strncmp(section_name(p->config_section), "br_", 3) == 0))
			continue;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "vlan_term_instance", "vlan_term_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetRMONStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct eth_rmon_args curr_eth_rmon_args = {0};
	struct dmmap_dup *p = NULL;
	char *inst = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "device", "dmmap_eth_rmon", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		json_object *res = NULL;
		char *name = NULL;

		if (!dmuci_is_option_value_empty(p->config_section, "type"))
			continue;

		dmuci_get_value_by_section_string(p->config_section, "name", &name);

		dmubus_call("ethernet", "rmonstats", UBUS_ARGS{{"ifname", name, String}}, 1, &res);
		if (!res)
			continue;

		init_eth_rmon(&curr_eth_rmon_args, p, res);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "eth_rmon_instance", "eth_rmon_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_eth_rmon_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_link = NULL;
	char eth_linker[32];

	snprintf(eth_linker, sizeof(eth_linker), "link_%s", *instance);

	/* Add link section in dmmap_ethernet file */
	dmuci_add_section_bbfdm("dmmap_ethernet", "link", &dmmap_link);
	dmuci_set_value_by_section(dmmap_link, "link_instance", *instance);
	return 0;
}

static int delObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			// Update Ethernet Link Top Layers
			ethernet___Update_Link_Top_Layers(refparam, "");

			// Remove link section
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			return 0;
		case DEL_ALL:
			break;
	}
	return 0;
}

static int addObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_network = NULL;
	char device_name[32];

	snprintf(device_name, sizeof(device_name), "vlan_ter_%s", *instance);

	// Add device section
	dmuci_add_section("network", "device", &s);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");

	// Add device section in dmmap_network file
	dmuci_add_section_bbfdm("dmmap_network", "device", &dmmap_network);
	dmuci_set_value_by_section(dmmap_network, "section_name", device_name);
	dmuci_set_value_by_section(dmmap_network, "vlan_term_instance", *instance);
	return 0;
}

static int delObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
	case DEL_INST:
		// Update Ethernet VLAN Termination Top Layers
		ethernet___Update_VLAN_Termination_Top_Layers(refparam, "");

		// Remove device section
		dmuci_delete_by_section(((struct dmmap_dup *)data)->config_section, NULL, NULL);

		// Remove device section in dmmap_network file
		dmuci_delete_by_section(((struct dmmap_dup *)data)->dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Ethernet_FlowControlSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.Ethernet.InterfaceNumberOfEntries!UCI:network/device/*/
static int get_Ethernet_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_LinkNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetLinkInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Ethernet.VLANTerminationNumberOfEntries!UCI:network/device/*/
static int get_Ethernet_VLANTerminationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetVLANTerminationInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_RMONStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseEthernetRMONStatsInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Enable!UCI:network/device,@i-1/enabled*/
static int get_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct eth_port_args *)data)->sections)->config_section, "enabled", "1");
	return 0;
}

static int set_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Status!SYSFS:/sys/class/net/@Name/operstate*/
static int get_EthernetInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_net_device_status(((struct eth_port_args *)data)->ifname, value);
}

/*#Device.Ethernet.Interface.{i}.Alias!UCI:dmmap_ethernet/device,@i-1/eth_port_alias*/
static int get_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->dmmap_section, "eth_iface_alias", value);
	if ((*value)[0] == '\0') {
		dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->config_section, "name", value);
		dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->dmmap_section, "eth_iface_alias", *value);
	}
	return 0;
}

static int set_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->dmmap_section, "eth_iface_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Name!UCI:network/device,@i-1/ifname*/
static int get_EthernetInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->config_section, "name", value);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_EthernetInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	struct uci_section *s = NULL, *dev_s = NULL;
	struct uci_list *uci_list = NULL;
	char *device;
	int intf_found = 0;

	*value ="0";
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "device", &device);
		if (0 == DM_LSTRNCMP(device, "br-", 3)) {
			uci_foreach_option_eq("network", "device", "name", device, dev_s) {
				dmuci_get_value_by_section_list(dev_s, "ports", &uci_list);
				if (value_exists_in_uci_list(uci_list, ((struct eth_port_args *)data)->ifname)) {
					intf_found = 1;
				}
			}
		} else {
			if (DM_STRSTR(device, ((struct eth_port_args *)data)->ifname)) {
				intf_found = 1;
			}
		}

		if (1 == intf_found) {
			char *if_name = section_name(s);
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
			DM_ASSERT(res, *value = "0");
			*value = dmjson_get_value(res, 1, "uptime");
			if((*value)[0] == '\0')
				*value = "0";
			return 0;
		}
	}

	if((*value)[0] == '\0')
		*value = "0";

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
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (*value != '\0')
				return FAULT_9007;

			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_EthernetInterface_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";

	if (!file_exists(BOARD_JSON_FILE))
		return 0;

	json_object *json_obj = json_object_from_file(BOARD_JSON_FILE);
	if (!json_obj)
		return 0;

	char *device = dmjson_get_value(json_obj, 3, "network", "wan", "device");
	if (DM_STRLEN(device) == 0)
		goto end;

	*value = (DM_STRCMP(device, ((struct eth_port_args *)data)->ifname) == 0) ? "1" : "0";

end:
	json_object_put(json_obj);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.MACAddress!SYSFS:/sys/class/net/@Name/address*/
static int get_EthernetInterface_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "address", value);
}

/*#Device.Ethernet.Interface.{i}.MaxBitRate!UCI:network/device,@i-1/speed*/
static int get_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *autoneg = NULL;

	dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->config_section, "autoneg", &autoneg);

	if (autoneg && DM_LSTRCMP(autoneg, "0") == 0)
		dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->config_section, "speed", value);
	else
		*value = "-1";

	return 0;
}

static int set_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "-1") == 0)
				dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "autoneg", "1");
			else {
				dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "autoneg", "0");
				dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "speed", value);
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

/*#Device.Ethernet.Interface.{i}.DuplexMode!UCI:network/device,@i-1/duplex*/
static int get_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *autoneg = NULL;

	dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->config_section, "autoneg", &autoneg);

	if (autoneg && DM_LSTRCMP(autoneg, "0") == 0) {
		char *duplex = NULL;

		dmuci_get_value_by_section_string((((struct eth_port_args *)data)->sections)->config_section, "duplex", &duplex);
		*value = (duplex && DM_LSTRCMP(duplex, "full") == 0) ? "Full" : "Half";
	} else {
		*value = "Auto";
	}
	return 0;
}

static int set_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, DuplexMode, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "Auto") == 0)
				dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "autoneg", "1");
			else {
				dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "autoneg", "0");
				dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "duplex", (*value == 'F') ? "full" : "half");
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

/*#Device.Ethernet.Interface.{i}.EEEEnable!UCI:network/device,@i-1/eee*/
static int get_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct eth_port_args *)data)->sections)->config_section, "eee", "1");
	return 0;
}

static int set_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct eth_port_args *)data)->sections)->config_section, "eee", b ? "1" : "0");
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

	if (args == NULL)
		DM_ASSERT(res, *value = "0");

	char *if_name = args->ifname;
	dmubus_call("ethernet", "ifstats", UBUS_ARGS{{"ifname", if_name, String}}, 1, &res);
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
	*value = "1";
	return 0;
}

static int set_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			break;
	}
	return 0;
}

static int get_EthernetLink_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
	return get_net_device_status(device, value);
}

static int get_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (struct uci_section *)data, "link_alias", instance, value);
}

static int set_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (struct uci_section *)data, "link_alias", instance, value);
}

static int get_EthernetLink_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", value);
	return 0;
}

static int get_EthernetLink_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *device = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
	if (DM_STRLEN(device) == 0)
		return 0;

	uci_foreach_option_cont("network", "interface", "device", device, s) {
		json_object *res = NULL;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
		DM_ASSERT(res, *value = "0");
		*value = dmjson_get_value(res, 1, "uptime");
		break;
	}
	return 0;
}

static int get_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		char *linker = NULL;

		dmuci_get_value_by_section_string((struct uci_section *)data, "device", &linker);
		if (DM_STRLEN(linker) == 0)
			return 0;

		adm_entry_get_reference_param(ctx, "Device.ATM.Link.*.Name", linker, value);
		if (DM_STRLEN(*value))
			goto end;

		adm_entry_get_reference_param(ctx, "Device.PTM.Link.*.Name", linker, value);
		if (DM_STRLEN(*value))
			goto end;

		adm_entry_get_reference_param(ctx, "Device.Bridging.Bridge.*.Port.*.Name", linker, value);
		if (DM_STRLEN(*value))
			goto end;

		adm_entry_get_reference_param(ctx, "Device.Ethernet.Interface.*.Name", linker, value);

end:
		// Store LowerLayers value
		dmuci_set_value_by_section((struct uci_section *)data, "LowerLayers", *value);
	} else {
		if (!adm_entry_object_exists(ctx, *value))
			*value = "";
	}

	return 0;
}

static int set_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.Ethernet.Interface.",
			"Device.Bridging.Bridge.*.Port.",
			"Device.ATM.Link.",
			"Device.PTM.Link.",
			NULL};
	struct dm_reference reference = {0};

	bbf_get_reference_args(value, &reference);

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, reference.path, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			// Store LowerLayers value under dmmap section
			dmuci_set_value_by_section((struct uci_section *)data, "LowerLayers", reference.path);

			// Update device option
			dmuci_set_value_by_section((struct uci_section *)data, "device", reference.value);

			if (match(reference.path, "Device.Bridging.Bridge.*.Port.", 0, NULL)) {
				// Remove unused Interface section created by Bridge Object if it exists
				struct uci_section *s = get_dup_section_in_config_opt("network", "interface", "device", reference.value);
				dmuci_delete_by_section(s, NULL, NULL);
			}

			// Update Ethernet Link Top Layers
			ethernet___Update_Link_Top_Layers(refparam, reference.value);
			break;
	}
	return 0;
}

static int get_EthernetLink_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "mac", value);
	return 0;
}

static int get_EthernetLink_FlowControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *port_s = NULL;
	char *device = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
	if (!DM_STRLEN(device))
		goto end;

	if (!DM_LSTRNCMP(device, "atm", 3) || !DM_LSTRNCMP(device, "ptm", 3))
		goto end;

	char *is_bridge = DM_LSTRSTR(device, "br-");
	if (is_bridge) {
		/* Ethernet.Link.{i}. ---> Bridging.Bridge.{i}.Port.{i}. */
		struct uci_list *ports_list = NULL;

		struct uci_section *dev_s = get_dup_section_in_config_opt("network", "device", "name", device);
		if (!dev_s)
			goto end;

		dmuci_get_value_by_section_list(dev_s, "ports", &ports_list);
		if (ports_list != NULL) {
			struct uci_element *e = NULL;
			char *default_value = "0";

			uci_foreach_element(ports_list, e) {
				char buf[16] = {0};

				DM_STRNCPY(buf, e->name, sizeof(buf));

				if (!ethernet___get_ethernet_interface_section(buf)) {
					char *is_tagged = DM_STRRCHR(buf, '.');
					if (is_tagged)
						*is_tagged = 0;
				}

				port_s = ethernet___get_ethernet_interface_section(buf);
				char *pause = port_s ? dmuci_get_value_by_section_fallback_def(port_s, "pause", "0") : "0";
				char *curr_value = dmuci_string_to_boolean(pause) ? "1" : "0";

				if (DM_STRCMP(curr_value, default_value) != 0) {
					*value = "1";
					return 0;
				}
			}

			*value = default_value;
			return 0;
		}
	} else {
		/* Ethernet.Link.{i}. ---> Ethernet.Interface.{i}. */

		port_s = ethernet___get_ethernet_interface_section(device);
		char *pause = port_s ? dmuci_get_value_by_section_fallback_def(port_s, "pause", "0") : "0";
		*value = dmuci_string_to_boolean(pause) ? "1" : "0";
		return 0;
	}

end:
	*value = "0";
	return 0;
}

static int set_EthernetLink_FlowControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *port_s = NULL;
	char *device = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
			if (!DM_STRLEN(device))
				break;

			if (!DM_LSTRNCMP(device, "atm", 3) || !DM_LSTRNCMP(device, "ptm", 3))
				break;

			char *is_bridge = DM_LSTRSTR(device, "br-");
			if (is_bridge) {
				/* Ethernet.Link.{i}. ---> Bridging.Bridge.{i}.Port.{i}. */

				struct uci_section *dev_s = get_dup_section_in_config_opt("network", "device", "name", device);
				if (dev_s) {
					struct uci_list *ports_list = NULL;

					dmuci_get_value_by_section_list(dev_s, "ports", &ports_list);
					if (ports_list != NULL) {
						struct uci_element *e = NULL;

						uci_foreach_element(ports_list, e) {
							char buf[16] = {0};

							DM_STRNCPY(buf, e->name, sizeof(buf));

							if (!ethernet___get_ethernet_interface_section(buf)) {
								char *is_tagged = DM_STRRCHR(buf, '.');
								if (is_tagged)
									*is_tagged = 0;
							}

							port_s = ethernet___get_ethernet_interface_section(buf);
							if (port_s) {
								dmuci_set_value_by_section(port_s, "pause", b ? "1" : "0");
								dmuci_set_value_by_section(port_s, "rxpause", b ? "1" : "0");
								dmuci_set_value_by_section(port_s, "txpause", b ? "1" : "0");
							}
						}
					}
				}
			} else {
				/* Ethernet.Link.{i}. ---> Ethernet.Interface.{i}. */

				port_s = ethernet___get_ethernet_interface_section(device);
				if (port_s) {
					dmuci_set_value_by_section(port_s, "pause", b ? "1" : "0");
					dmuci_set_value_by_section(port_s, "rxpause", b ? "1" : "0");
					dmuci_set_value_by_section(port_s, "txpause", b ? "1" : "0");
				}
			}
			break;
	}
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
	char *device = NULL;

	dmuci_get_value_by_section_string(iface_s, "device", &device);

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
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "enabled", "1");
	return 0;
}

static int set_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
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

static int get_EthernetVLANTermination_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name = NULL;

	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", &name);
	return get_net_device_status(name, value);
}

/*#Device.Ethernet.VLANTermination.{i}.Alias!UCI:dmmap_network/device,@i-1/vlan_term_alias*/
static int get_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "vlan_term_alias", instance, value);
}

static int set_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dmmap_dup *)data)->dmmap_section, "vlan_term_alias", instance, value);
}

static int get_EthernetVLANTermination_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", value);
	return 0;
}

static int get_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->dmmap_section, "LowerLayers", value);

	if (DM_STRLEN(*value) == 0) {
		char *type = NULL, *ifname = NULL;

		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "type", &type);
		dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ifname", &ifname);

		if (DM_LSTRCMP(type, "8021ad") == 0) {
			adm_entry_get_reference_param(ctx, "Device.Ethernet.VLANTermination.*.Name", ifname, value);
		} else {
			adm_entry_get_reference_param(ctx, "Device.Ethernet.Link.*.Name", ifname, value);
		}

		// Store LowerLayers value
		dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "LowerLayers", *value);
	} else {
		if (!adm_entry_object_exists(ctx, *value))
			*value = "";
	}

	return 0;
}

static int set_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {
			"Device.Ethernet.VLANTermination.",
			"Device.Ethernet.Link.",
			NULL};
	struct dm_reference reference = {0};
	char name[32] = {0};

	bbf_get_reference_args(value, &reference);

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, reference.path, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_validate_allowed_objects(ctx, &reference, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			// Store LowerLayers value under dmmap section
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->dmmap_section, "LowerLayers", reference.path);

			if (DM_STRLEN(reference.value)) {
				char *vid = NULL;

				dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "vid", &vid);

				snprintf(name, sizeof(name), "%s%s%s", reference.value, DM_STRLEN(vid) ? "." : "", DM_STRLEN(vid) ? vid : "");
			}

			// Update ifname and name options
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "ifname", reference.value);
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", name);

			// Update Ethernet VLAN Termination Top Layers
			ethernet___Update_VLAN_Termination_Top_Layers(refparam, name);
			break;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.VLANID!UCI:network/device,@i-1/vid*/
static int get_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct dmmap_dup *)data)->config_section, "vid", "1");
	return 0;
}

static int set_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *ifname = NULL;
	char name[32] = {0};

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			// Update vid option
			dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "vid", value);

			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ifname", &ifname);

			snprintf(name, sizeof(name), "%s%s%s", DM_STRLEN(ifname) ? ifname : "", DM_STRLEN(ifname) ? "." : "", DM_STRLEN(ifname) ? value : "");

			// Update Ethernet VLAN Termination Top Layers
			ethernet___Update_VLAN_Termination_Top_Layers(refparam, name);
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.TPID!UCI:network/device,@i-1/type*/
static int get_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "type", value);
	if (DM_LSTRCMP(*value, "8021q") == 0)
		*value = "33024";
	else if (DM_LSTRCMP(*value, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (DM_LSTRCMP(value, "33024") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "type", "8021q");
			else if (DM_LSTRCMP(value, "34984") == 0)
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "type", "8021ad");
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_EthernetVLANTerminationStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_bytes", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_EthernetVLANTerminationStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_bytes", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_EthernetVLANTerminationStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_packets", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_EthernetVLANTerminationStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_packets", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_EthernetVLANTerminationStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_errors", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_EthernetVLANTerminationStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_errors", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_EthernetVLANTerminationStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/tx_dropped", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_EthernetVLANTerminationStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/rx_dropped", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_EthernetVLANTerminationStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(((struct dmmap_dup *)data)->config_section, "statistics/multicast", value);
}

/*#Device.Ethernet.RMONStats.{i}.Enable!UCI:network/device,@i-1/rmon*/
static int get_EthernetRMONStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct eth_rmon_args *)data)->sections)->config_section, "rmon", "1");
	return 0;
}

static int set_EthernetRMONStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct eth_rmon_args *)data)->sections)->config_section, "rmon", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_EthernetRMONStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name = NULL, *status = NULL;

	dmuci_get_value_by_section_string((((struct eth_rmon_args *)data)->sections)->config_section, "name", &name);
	get_net_device_status(name, &status);

	if (strncmp(status, "Up", 2) == 0) {
		*value = "Enabled";
	} else if (strncmp(status, "Down", 4) == 0) {
		*value = "Disabled";
	} else {
		*value = "Error";
	}
	return 0;
}

/*#Device.Ethernet.RMONStats.{i}.Alias!UCI:dmmap_eth_rmon/device,@i-1/eth_rmon_alias*/
static int get_EthernetRMONStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (((struct eth_rmon_args *)data)->sections)->dmmap_section, "eth_rmon_alias", instance, value);
}

static int set_EthernetRMONStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (((struct eth_rmon_args *)data)->sections)->dmmap_section, "eth_rmon_alias", instance, value);
}

/*#Device.Ethernet.RMONStats.{i}.Name!UCI:network/device,@i-1/ifname*/
static int get_EthernetRMONStats_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct eth_rmon_args *)data)->eth_rmon_obj, 1, "ifname");
	return 0;
}

static int get_EthernetRMONStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string((((struct eth_rmon_args *)data)->sections)->config_section, "name", &linker);
	adm_entry_get_reference_param(ctx, "Device.Ethernet.Interface.*.Name", linker, value);
	return 0;
}

static int set_EthernetRMONStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, NULL, NULL))
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
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"0","4094"}}, 1))
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
			if (bbfdm_validate_boolean(ctx, value))
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseEthernetInterfaceInst, NULL, NULL, tEthernetInterfaceObj, tEthernetInterfaceParams, NULL, BBFDM_BOTH, NULL},
{"Link", &DMWRITE, addObjEthernetLink, delObjEthernetLink, NULL, browseEthernetLinkInst, NULL, NULL, tEthernetLinkObj, tEthernetLinkParams, NULL, BBFDM_BOTH, NULL},
{"VLANTermination", &DMWRITE, addObjEthernetVLANTermination, delObjEthernetVLANTermination, NULL, browseEthernetVLANTerminationInst, NULL, NULL, tEthernetVLANTerminationObj, tEthernetVLANTerminationParams, NULL, BBFDM_BOTH, NULL},
{"RMONStats", &DMREAD, NULL, NULL, "ubus:ethernet->rmonstats", browseEthernetRMONStatsInst, NULL, NULL, NULL, tEthernetRMONStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"FlowControlSupported", &DMREAD, DMT_BOOL, get_Ethernet_FlowControlSupported, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{"LinkNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_LinkNumberOfEntries, NULL, BBFDM_BOTH},
{"VLANTerminationNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_VLANTerminationNumberOfEntries, NULL, BBFDM_BOTH},
{"RMONStatsNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_RMONStatsNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}. *** */
DMOBJ tEthernetInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetInterfaceStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetInterface_Enable, set_EthernetInterface_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetInterface_Alias, set_EthernetInterface_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_EthernetInterface_Name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetLinkStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetLink_Enable, set_EthernetLink_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetLink_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetLink_Alias, set_EthernetLink_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_EthernetLink_Name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetLink_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetLink_LowerLayers, set_EthernetLink_LowerLayers, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetLink_MACAddress, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"FlowControl", &DMWRITE, DMT_BOOL, get_EthernetLink_FlowControl, set_EthernetLink_FlowControl, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}.Stats. *** */
DMLEAF tEthernetLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetVLANTerminationStatsParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tEthernetVLANTerminationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetVLANTermination_Enable, set_EthernetVLANTermination_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_Alias, set_EthernetVLANTermination_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Name, NULL, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_LINKER},
//{"LastChange", &DMREAD, DMT_UNINT, get_EthernetVLANTermination_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_LowerLayers, set_EthernetVLANTermination_LowerLayers, BBFDM_BOTH, DM_FLAG_REFERENCE},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_VLANID, set_EthernetVLANTermination_VLANID, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_TPID, set_EthernetVLANTermination_TPID, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}.Stats. *** */
DMLEAF tEthernetVLANTerminationStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetRMONStats_Enable, set_EthernetRMONStats_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetRMONStats_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Alias, set_EthernetRMONStats_Alias, BBFDM_BOTH, DM_FLAG_UNIQUE},
{"Name", &DMREAD, DMT_STRING, get_EthernetRMONStats_Name, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_EthernetRMONStats_Interface, set_EthernetRMONStats_Interface, BBFDM_BOTH, DM_FLAG_UNIQUE|DM_FLAG_REFERENCE},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetRMONStats_VLANID, set_EthernetRMONStats_VLANID, BBFDM_BOTH, DM_FLAG_UNIQUE},
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
