/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "ip.h"
#include "dmentry.h"
#ifdef BBF_TR143
#include "diagnostics.h"
#endif

struct intf_ip_args
{
	struct uci_section *interface_sec;
	struct uci_section *dmmap_sec;
	json_object *interface_obj;
};

/*************************************************************
* INIT
**************************************************************/
static int init_interface_ip_args(struct intf_ip_args *args, struct uci_section *intf_s, struct uci_section *dmmap_s, json_object *intf_obj)
{
	args->interface_sec = intf_s;
	args->dmmap_sec = dmmap_s;
	args->interface_obj = intf_obj;
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_ip_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = (data) ? dmstrdup(section_name((struct uci_section *)data)) : "";
	return 0;
}

static int get_linker_ipv6_prefix(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "0") == 0) {
		char *address = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 3, "assigned", "lan", "address");
		char *mask = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 3, "assigned", "lan", "mask");
		dmasprintf(linker, "%s/%s", address, mask);
	} else {
		*linker = "";
	}
	return 0;
}

/*************************************************************
* COMMON Functions
**************************************************************/
static int get_ip_iface_sysfs(const struct uci_section *data, const char *name, char **value)
{
	return get_net_iface_sysfs(section_name((struct uci_section *)data), name, value);
}

static void create_firewall_zone_config(char *iface)
{
	struct uci_section *s;
	char name[16];

	snprintf(name, sizeof(name), "fwl_%s", iface);

	dmuci_add_section("firewall", "zone", &s);
	dmuci_set_value_by_section(s, "name", name);
	dmuci_set_value_by_section(s, "input", "DROP");
	dmuci_set_value_by_section(s, "forward", "DROP");
	dmuci_set_value_by_section(s, "output", "ACCEPT");
	dmuci_set_value_by_section(s, "network", iface);
}

static struct uci_section *update_dmmap_network_interface(char *dmmap_file_name, char *dmmap_sec_name, char *parent_section, char *section_name, char *option, char *value, bool assign)
{
	struct uci_section *dmmap_section = NULL;
	char *sec_name, *opt_value;

	uci_path_foreach_option_eq(bbfdm, dmmap_file_name, dmmap_sec_name, "parent_section", parent_section, dmmap_section) {
		dmuci_get_value_by_section_string(dmmap_section, "section_name", &sec_name);
		dmuci_get_value_by_section_string(dmmap_section, option, &opt_value);
		if (strcmp(sec_name, section_name) == 0 && strcmp(opt_value, value) == 0)
			return dmmap_section;
	}

	if (!dmmap_section) {
		dmuci_add_section_bbfdm(dmmap_file_name, dmmap_sec_name, &dmmap_section);
		dmuci_set_value_by_section_bbfdm(dmmap_section, "parent_section", parent_section);
		dmuci_set_value_by_section_bbfdm(dmmap_section, "section_name", section_name);
		dmuci_set_value_by_section_bbfdm(dmmap_section, option, value);
		if (assign) dmuci_set_value_by_section_bbfdm(dmmap_section, "assign", "1");
	}

	return dmmap_section;
}

static void synchronize_intf_ipv4_sections_with_dmmap(void)
{
	json_object *res = NULL, *ipv4_obj = NULL, *arrobj = NULL;
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;
	char *dmmap_intf_s, *dmmap_address, *ipaddr = NULL;
	bool found = false;
	int i = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv4", "intf_ipv4", stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &dmmap_intf_s);
		dmuci_get_value_by_section_string(s, "address", &dmmap_address);
		found = false;

		ss = get_origin_section_from_config("network", "interface", dmmap_intf_s);
		dmuci_get_value_by_section_string(ss, "ipaddr", &ipaddr);

		if (ipaddr && *ipaddr != '\0' && strcmp(ipaddr, dmmap_address) == 0)
			continue;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dmmap_intf_s, String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv4_obj, i, 1, "ipv4-address") {

			char *address = dmjson_get_value(ipv4_obj, 1, "address");
			if (address && *address && strcmp(address, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static void synchronize_intf_ipv6_sections_with_dmmap(void)
{
	json_object *res = NULL, *ipv6_obj = NULL, *arrobj = NULL;
	struct uci_section *s = NULL, *stmp = NULL;
	char *dmmap_intf_s, *dmmap_address;
	bool found = false;
	int i = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv6", "intf_ipv6", stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &dmmap_intf_s);
		dmuci_get_value_by_section_string(s, "address", &dmmap_address);
		found = false;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dmmap_intf_s, String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-address") {

			char *address = dmjson_get_value(ipv6_obj, 1, "address");
			if (address && *address && strcmp(address, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (found)
			continue;

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-prefix-assignment") {

			char *address = dmjson_get_value(ipv6_obj, 2, "local-address", "address");
			if (address && *address && strcmp(address, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static void synchronize_intf_ipv6_prefix_sections_with_dmmap(void)
{
	json_object *res = NULL, *ipv6_prefix_obj = NULL, *arrobj = NULL;
	struct uci_section *s = NULL, *stmp = NULL;
	char *dmmap_intf_s, *dmmap_address, ipv6_prefix[256] = {0};
	bool found = false;
	int i = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &dmmap_intf_s);
		dmuci_get_value_by_section_string(s, "address", &dmmap_address);
		found = false;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dmmap_intf_s, String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix") {

			char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
			char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
			if (*address == '\0' || *mask == '\0')
				continue;

			snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);
			if (strcmp(ipv6_prefix, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (found)
			continue;

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix-assignment") {

			char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
			char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
			if (*address == '\0' || *mask == '\0')
				continue;

			snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);
			if (strcmp(ipv6_prefix, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static char *get_ip_interface_last_instance(char *package, char *section, char* dmmap_package, char *opt_inst)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;
	char *instance = NULL, *last_inst = NULL, *proto, *ifname;

	uci_foreach_sections(package, section, s) {

		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ifname", &ifname);

		if (strcmp(section_name(s), "loopback") == 0 ||
			*proto == '\0' ||
			strchr(ifname, '@'))
			continue;

		get_dmmap_section_of_config_section(dmmap_package, section, section_name(s), &dmmap_section);
		if (dmmap_section == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "section_name", section_name(s));
		}
		instance = update_instance(last_inst, 4, dmmap_section, opt_inst, dmmap_package, section);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(instance);
	}
	return instance;
}

static int delete_ip_intertace_instance(struct uci_section *s)
{
	struct uci_section *int_ss = NULL, *int_stmp = NULL;
	char buf[32], *ifname, *int_sec_name = dmstrdup(section_name(s));

	snprintf(buf, sizeof(buf), "@%s", int_sec_name);

	uci_foreach_sections_safe("network", "interface", int_stmp, int_ss) {

		dmuci_get_value_by_section_string(int_ss, "ifname", &ifname);
		if (strcmp(section_name(int_ss), int_sec_name) != 0 && strcmp(ifname, buf) != 0)
			continue;

		// Get dmmap section related to this interface section
		struct uci_section *dmmap_section = NULL;
		get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(int_ss), &dmmap_section);

		// Read the type option from interface section
		char *type;
		dmuci_get_value_by_section_string(int_ss, "type", &type);

		// Check the type value ==> if bridge : there is a Bridging.Bridge. object mapped to this interface, remove only proto option from the section
		// Check the type value ==> else : there is no Bridging.Bridge. object mapped to this interface, remove the section
		if (strcmp(type, "bridge") == 0) {
			/* type is bridge */

			/* remove only proto option from the interface section and ip instance option from dmmap section */
			dmuci_set_value_by_section(int_ss, "proto", "");
			dmuci_set_value_by_section(dmmap_section, "ip_int_instance", "");
		} else {
			/* type is not bridge */

			/* Remove the device section corresponding to this interface if exists and no interface used it */
			char *device = get_device( section_name(int_ss));
			struct uci_section *ss = NULL, *stmp = NULL;

			if (device && *device) {
				bool device_found = false;

				uci_foreach_sections("network", "interface", ss) {
					dmuci_get_value_by_section_string(ss, "ifname", &ifname);
					if (strcmp(section_name(ss), section_name(int_ss)) != 0 && strcmp(ifname, buf) != 0 && strstr(ifname, device)) {
						device_found = true;
						break;
					}
				}

				if (!device_found) {
					uci_foreach_option_eq_safe("network", "device", "name", device, stmp, ss) {
						char *device_type;
						dmuci_get_value_by_section_string(ss, "type", &device_type);
						if (strcmp(device_type, "untagged") == 0) dmuci_delete_by_section(ss, NULL, NULL);
						break;
					}
				}
			}

			/* remove dmmap section related to this interface */
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			/* Remove "IPv4Address" child section related to this "IP.Interface." object */
			uci_foreach_option_eq_safe("dmmap_network_ipv4", "intf_ipv4", "parent_section", section_name(int_ss), stmp, ss) {
				dmuci_delete_by_section(ss, NULL, NULL);
			}

			/* Remove "IPv6Address" child section related to this "IP.Interface." object */
			uci_foreach_option_eq_safe("dmmap_network_ipv6", "intf_ipv6", "parent_section", section_name(int_ss), stmp, ss) {
				dmuci_delete_by_section(ss, NULL, NULL);
			}

			/* Remove "IPv6PrefixAddress" child section related to this "IP.Interface." object */
			uci_foreach_option_eq_safe("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "parent_section", section_name(int_ss), stmp, ss) {
				dmuci_delete_by_section(ss, NULL, NULL);
			}

			/* remove interface section */
			dmuci_delete_by_section(int_ss, NULL, NULL);
		}

	}
	return 0;
}

static bool interface_section_with_dhcpv6_exists(const char *sec_name)
{
	struct uci_section *s = NULL;
	char buf[32] = {0};

	snprintf(buf, sizeof(buf), "@%s", sec_name);

	uci_foreach_sections("network", "interface", s) {

		char *ifname;
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (strcmp(ifname, buf) == 0) {
			char *proto;
			dmuci_get_value_by_section_string(s, "proto", &proto);
			if (strcmp(proto, "dhcpv6") == 0)
				return true;
		}
	}

	return false;
}

static void set_ip_interface_ifname_option(struct uci_section *section, char *linker, char *instance)
{
	struct uci_section *s = NULL;
	bool device_exists = false;
	char ifname[64];

	snprintf(ifname, sizeof(ifname), "%s.1", linker);

	// Check if device exists
	uci_foreach_option_eq("network", "device", "name", ifname, s) {
		device_exists = true;
		break;
	}

	// if device dosn't exist ==> create a new device section
	if (!device_exists) {
		char device_name[32];

		snprintf(device_name, sizeof(device_name), "dev_ip_int_%s", instance);

		dmuci_add_section("network", "device", &s);
		dmuci_rename_section_by_section(s, device_name);
		dmuci_set_value_by_section(s, "type", "untagged");
		dmuci_set_value_by_section(s, "ifname", linker);
		dmuci_set_value_by_section(s, "name", ifname);
	}

	dmuci_set_value_by_section(section, "ifname", ifname);
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.IP.Interface.{i}.!UCI:network/interface/dmmap_network*/
static int browseIPInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL;
	char *proto, *ifname;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "interface", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "proto", &proto);
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);

		if (strcmp(section_name(p->config_section), "loopback") == 0 ||
			*proto == '\0' ||
			strchr(ifname, '@'))
			continue;

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
			   p->dmmap_section, "ip_int_instance", "ip_int_alias", "dmmap_network", "interface");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseIPInterfaceIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *parent_sec = (struct uci_section *)prev_data, *intf_s = NULL, *dmmap_s = NULL;
	char *inst = NULL, *max_inst = NULL, *ipaddr, *ifname, buf[32] = {0};
	json_object *res = NULL, *ipv4_obj = NULL, *arrobj = NULL;
	struct intf_ip_args curr_intf_ip_args = {0};
	struct browse_args browse_args = {0};
	int i = 0;

	snprintf(buf, sizeof(buf), "@%s", section_name(parent_sec));

	synchronize_intf_ipv4_sections_with_dmmap();
	uci_foreach_sections("network", "interface", intf_s) {

		dmuci_get_value_by_section_string(intf_s, "ifname", &ifname);
		if (strcmp(section_name(intf_s), section_name(parent_sec)) != 0 && strcmp(ifname, buf) != 0)
			continue;

		dmuci_get_value_by_section_string(intf_s, "ipaddr", &ipaddr);

		if (*ipaddr == '\0') {

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(intf_s), String}}, 1, &res);

			dmjson_foreach_obj_in_array(res, arrobj, ipv4_obj, i, 1, "ipv4-address") {

				char *address = dmjson_get_value(ipv4_obj, 1, "address");
				if (*address == '\0')
					continue;

				dmmap_s = update_dmmap_network_interface("dmmap_network_ipv4", "intf_ipv4", section_name(parent_sec), section_name(intf_s), "address", address, false);

				init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv4_obj);

				browse_args.option = "parent_section";
				browse_args.value = section_name(parent_sec);

				inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
					   dmmap_s, "ipv4_instance", "ipv4_alias", "dmmap_network_ipv4", "intf_ipv4",
					   check_browse_section, (void *)&browse_args);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
					goto end;
			}

		} else {

			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv4", "intf_ipv4", section_name(parent_sec), section_name(intf_s), "address", ipaddr, false);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, NULL);

			browse_args.option = "parent_section";
			browse_args.value = section_name(parent_sec);

			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
				   dmmap_s, "ipv4_instance", "ipv4_alias", "dmmap_network_ipv4", "intf_ipv4",
				   check_browse_section, (void *)&browse_args);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;
		}
	}

end:
	return 0;
}

static int browseIPInterfaceIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *parent_sec = (struct uci_section *)prev_data, *intf_s = NULL, *dmmap_s = NULL;
	char *inst = NULL, *max_inst = NULL, *ifname, buf[32] = {0};
	json_object *res = NULL, *ipv6_obj = NULL, *arrobj = NULL;
	struct intf_ip_args curr_intf_ip_args = {0};
	struct browse_args browse_args = {0};
	int i = 0;

	snprintf(buf, sizeof(buf), "@%s", section_name(parent_sec));

	synchronize_intf_ipv6_sections_with_dmmap();
	uci_foreach_sections("network", "interface", intf_s) {

		dmuci_get_value_by_section_string(intf_s, "ifname", &ifname);
		if (strcmp(section_name(intf_s), section_name(parent_sec)) != 0 && strcmp(ifname, buf) != 0)
			continue;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(intf_s), String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-address") {

			char *address = dmjson_get_value(ipv6_obj, 1, "address");
			if (*address == '\0')
				continue;

			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6", "intf_ipv6", section_name(parent_sec), section_name(intf_s), "address", address, false);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_obj);

			browse_args.option = "parent_section";
			browse_args.value = section_name(parent_sec);

			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
				   dmmap_s, "ipv6_instance", "ipv6_alias", "dmmap_network_ipv6", "intf_ipv6",
				   check_browse_section, (void *)&browse_args);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;
		}

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-prefix-assignment") {

			char *address = dmjson_get_value(ipv6_obj, 2, "local-address", "address");
			if (*address == '\0')
				continue;

			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6", "intf_ipv6", section_name(parent_sec), section_name(intf_s), "address", address, true);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_obj);

			browse_args.option = "parent_section";
			browse_args.value = section_name(parent_sec);

			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
				   dmmap_s, "ipv6_instance", "ipv6_alias", "dmmap_network_ipv6", "intf_ipv6",
				   check_browse_section, (void *)&browse_args);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;
		}
	}

end:
	return 0;
}

static int browseIPInterfaceIPv6PrefixInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *parent_sec = (struct uci_section *)prev_data, *intf_s = NULL, *dmmap_s = NULL;
	char *inst = NULL, *max_inst = NULL, *ifname, buf[32] = {0}, ipv6_prefix[256] = {0};
	json_object *res = NULL, *ipv6_prefix_obj = NULL, *arrobj = NULL;
	struct intf_ip_args curr_intf_ip_args = {0};
	struct browse_args browse_args = {0};
	int i = 0;

	snprintf(buf, sizeof(buf), "@%s", section_name(parent_sec));

	synchronize_intf_ipv6_prefix_sections_with_dmmap();
	uci_foreach_sections("network", "interface", intf_s) {

		dmuci_get_value_by_section_string(intf_s, "ifname", &ifname);
		if (strcmp(section_name(intf_s), section_name(parent_sec)) != 0 && strcmp(ifname, buf) != 0)
			continue;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(intf_s), String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix") {

			char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
			char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
			if (*address == '\0' || *mask == '\0')
				continue;

			snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);
			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6_prefix","intf_ipv6_prefix", section_name(parent_sec), section_name(intf_s), "address", ipv6_prefix, false);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_prefix_obj);

			browse_args.option = "parent_section";
			browse_args.value = section_name(parent_sec);

			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
				   dmmap_s, "ipv6_prefix_instance", "ipv6_prefix_alias", "dmmap_network_ipv6_prefix", "intf_ipv6_prefix",
				   check_browse_section, (void *)&browse_args);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;
		}

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix-assignment") {

			char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
			char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
			if (*address == '\0' || *mask == '\0')
				continue;

			snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);
			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", section_name(parent_sec), section_name(intf_s), "address", ipv6_prefix, true);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_prefix_obj);

			browse_args.option = "parent_section";
			browse_args.value = section_name(parent_sec);

			inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
				   dmmap_s, "ipv6_prefix_instance", "ipv6_prefix_alias", "dmmap_network_ipv6_prefix", "intf_ipv6_prefix",
				   check_browse_section, (void *)&browse_args);

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;
		}
	}

end:
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjIPInterface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_ip_interface;
	char ip_name[32] = {0};

	char *last_inst = get_ip_interface_last_instance("network", "interface", "dmmap_network", "ip_int_instance");
	snprintf(ip_name, sizeof(ip_name), "ip_interface_%d", last_inst ? atoi(last_inst) + 1 : 1);

	dmuci_set_value("network", ip_name, "", "interface");
	dmuci_set_value("network", ip_name, "proto", "static");

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_ip_interface);
	dmuci_set_value_by_section(dmmap_ip_interface, "section_name", ip_name);
	*instance = update_instance(last_inst, 4, dmmap_ip_interface, "ip_int_instance", "dmmap_network", "interface");
	return 0;
}

static int delObjIPInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			delete_ip_intertace_instance((struct uci_section *)data);
			break;
		case DEL_ALL:
			uci_foreach_sections_safe("network", "interface", stmp, s) {
				char *proto, *ifname;
				dmuci_get_value_by_section_string(s, "proto", &proto);
				dmuci_get_value_by_section_string(s, "ifname", &ifname);

				if (strcmp(section_name(s), "loopback") == 0 ||
					*proto == '\0' ||
					strchr(ifname, '@'))
					continue;

				delete_ip_intertace_instance(s);
			}
			break;
	}
	return 0;
}

static int addObjIPInterfaceIPv4Address(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	// check the proto option from the interface section parent, if proto="static" ==> we can add a new object, else return 9001 error
	char *proto;
	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
	if (strcmp(proto, "static") != 0)
		return FAULT_9001;

	char *last_inst = NULL, *ip_inst, ipv4_name[64] = {0}, buf[32] = {0};
	struct uci_section *dmmap_ip_interface = NULL, *dmmap_ip_interface_ipv4;
	struct browse_args browse_args = {0};

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_ip_interface);
	dmuci_get_value_by_section_string(dmmap_ip_interface, "ip_int_instance", &ip_inst);

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_network_ipv4", "intf_ipv4", "ipv4_instance", "parent_section", section_name((struct uci_section *)data));

	if (last_inst) {
		snprintf(ipv4_name, sizeof(ipv4_name), "ip_interface_%s_ipv4_%d", ip_inst, atoi(last_inst) + 1);
		snprintf(buf, sizeof(buf), "@%s", section_name((struct uci_section *)data));

		dmuci_set_value("network", ipv4_name, "", "interface");
		dmuci_set_value("network", ipv4_name, "ifname", buf);
		dmuci_set_value("network", ipv4_name, "proto", "static");
		dmuci_set_value("network", ipv4_name, "ipaddr", "0.0.0.0");
		dmuci_set_value("network", ipv4_name, "netmask", "0.0.0.0");
	} else {
		dmuci_set_value_by_section((struct uci_section *)data, "ipaddr", "0.0.0.0");
		dmuci_set_value_by_section((struct uci_section *)data, "netmask", "0.0.0.0");
	}

	browse_args.option = "parent_section";
	browse_args.value = section_name((struct uci_section *)data);

	dmuci_add_section_bbfdm("dmmap_network_ipv4", "intf_ipv4", &dmmap_ip_interface_ipv4);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "parent_section", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "section_name", last_inst ? ipv4_name : section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "address", "0.0.0.0");

	*instance = update_instance(last_inst, 6, dmmap_ip_interface_ipv4, "ipv4_instance", "dmmap_network_ipv4", "intf_ipv4", check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjIPInterfaceIPv4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_s = NULL;
	char *proto, *ifname, buf[32] = {0};

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (strcmp(proto, "static") != 0)
				return FAULT_9001;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "ifname", &ifname);
			if (strchr(ifname, '@')) {
				dmuci_delete_by_section(((struct intf_ip_args *)data)->interface_sec, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", "");
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", "");
			}

			dmuci_delete_by_section(((struct intf_ip_args *)data)->dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
			if (strcmp(proto, "static") != 0)
				return FAULT_9001;

			snprintf(buf, sizeof(buf), "@%s", section_name((struct uci_section *)data));

			uci_foreach_sections_safe("network", "interface", stmp, s) {

				dmuci_get_value_by_section_string(s, "ifname", &ifname);

				if (strcmp(section_name(s), section_name((struct uci_section *)data)) == 0) {
					dmuci_set_value_by_section(s, "ipaddr", "");
					dmuci_set_value_by_section(s, "netmask", "");

					get_dmmap_section_of_config_section("dmmap_network_ipv4", "intf_ipv4", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);
				} else if (strcmp(ifname, buf) == 0) {
					get_dmmap_section_of_config_section("dmmap_network_ipv4", "intf_ipv4", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);

					dmuci_delete_by_section(s, NULL, NULL);
				} else {
					continue;
				}
			}
			break;
	}
	return 0;
}

static int addObjIPInterfaceIPv6Address(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	// check the proto option from the interface section parent, if proto="static" ==> you can add a new object, else return 9001 error
	char *proto;
	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
	if (strcmp(proto, "static") != 0 || (strcmp(proto, "static") == 0 && interface_section_with_dhcpv6_exists(section_name((struct uci_section *)data))))
		return FAULT_9001;

	char *last_inst = NULL, *ip_inst, ipv6_name[64] = {0}, buf[32] = {0};
	struct uci_section *dmmap_ip_interface = NULL, *dmmap_ip_interface_ipv6;
	struct browse_args browse_args = {0};

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_ip_interface);
	dmuci_get_value_by_section_string(dmmap_ip_interface, "ip_int_instance", &ip_inst);

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_network_ipv6", "intf_ipv6", "ipv6_instance", "parent_section", section_name((struct uci_section *)data));
	snprintf(ipv6_name, sizeof(ipv6_name), "ip_interface_%s_ipv6_%d", ip_inst, last_inst ? atoi(last_inst) + 1 : 1);
	snprintf(buf, sizeof(buf), "@%s", section_name((struct uci_section *)data));

	dmuci_set_value("network", ipv6_name, "", "interface");
	dmuci_set_value("network", ipv6_name, "ifname", buf);
	dmuci_set_value("network", ipv6_name, "proto", "static");
	dmuci_set_value("network", ipv6_name, "ip6addr", "::");

	browse_args.option = "parent_section";
	browse_args.value = section_name((struct uci_section *)data);

	dmuci_add_section_bbfdm("dmmap_network_ipv6", "intf_ipv6", &dmmap_ip_interface_ipv6);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "parent_section", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "section_name", ipv6_name);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "address", "::");

	*instance = update_instance(last_inst, 6, dmmap_ip_interface_ipv6, "ipv6_instance", "dmmap_network_ipv6", "intf_ipv6", check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjIPInterfaceIPv6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_s = NULL;
	char *proto, *ifname, buf[32] = {0};

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (strcmp(proto, "static") != 0 || (strcmp(proto, "static") == 0 && interface_section_with_dhcpv6_exists(section_name(((struct intf_ip_args *)data)->interface_sec))))
				return FAULT_9001;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "ifname", &ifname);
			if (strchr(ifname, '@')) {
				dmuci_delete_by_section(((struct intf_ip_args *)data)->interface_sec, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ip6addr", "");
			}

			dmuci_delete_by_section(((struct intf_ip_args *)data)->dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
			if (strcmp(proto, "static") != 0 || (strcmp(proto, "static") == 0 && interface_section_with_dhcpv6_exists(section_name((struct uci_section *)data))))
				return FAULT_9001;

			snprintf(buf, sizeof(buf), "@%s", section_name((struct uci_section *)data));

			uci_foreach_sections_safe("network", "interface", stmp, s) {

				dmuci_get_value_by_section_string(s, "ifname", &ifname);

				if (strcmp(section_name(s), section_name((struct uci_section *)data)) == 0) {
					dmuci_set_value_by_section(s, "ip6addr", "");

					get_dmmap_section_of_config_section("dmmap_network_ipv6", "intf_ipv6", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);
				} else if (strcmp(ifname, buf) == 0) {
					get_dmmap_section_of_config_section("dmmap_network_ipv6", "intf_ipv6", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);

					dmuci_delete_by_section(s, NULL, NULL);
				} else {
					continue;
				}
			}
			break;
	}
	return 0;
}

static int addObjIPInterfaceIPv6Prefix(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	// check the proto option from the interface section parent, if proto="static" ==> you can add a new object, else return 9001 error
	char *proto;
	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
	if (strcmp(proto, "static") != 0 || (strcmp(proto, "static") == 0 && interface_section_with_dhcpv6_exists(section_name((struct uci_section *)data))))
		return FAULT_9001;

	char *last_inst = NULL, *ip_inst, ipv6_prefix_name[64] = {0}, buf[32] = {0};
	struct uci_section *dmmap_ip_interface = NULL, *dmmap_ip_interface_ipv6_prefix;
	struct browse_args browse_args = {0};

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_ip_interface);
	dmuci_get_value_by_section_string(dmmap_ip_interface, "ip_int_instance", &ip_inst);

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "ipv6_prefix_instance", "parent_section", section_name((struct uci_section *)data));
	snprintf(ipv6_prefix_name, sizeof(ipv6_prefix_name), "ip_interface_%s_ipv6_prefix_%d", ip_inst, last_inst ? atoi(last_inst) + 1 : 1);
	snprintf(buf, sizeof(buf), "@%s", section_name((struct uci_section *)data));

	dmuci_set_value("network", ipv6_prefix_name, "", "interface");
	dmuci_set_value("network", ipv6_prefix_name, "ifname", buf);
	dmuci_set_value("network", ipv6_prefix_name, "proto", "static");
	dmuci_set_value("network", ipv6_prefix_name, "ip6prefix", "::/64");

	browse_args.option = "parent_section";
	browse_args.value = section_name((struct uci_section *)data);

	dmuci_add_section_bbfdm("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", &dmmap_ip_interface_ipv6_prefix);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "parent_section", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "section_name", ipv6_prefix_name);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "address", "::/64");

	*instance = update_instance(last_inst, 6, dmmap_ip_interface_ipv6_prefix, "ipv6_prefix_instance", "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjIPInterfaceIPv6Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_s = NULL;
	char *proto, *ifname, buf[32] = {0};

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (strcmp(proto, "static") != 0 || (strcmp(proto, "static") == 0 && interface_section_with_dhcpv6_exists(section_name(((struct intf_ip_args *)data)->interface_sec))))
				return FAULT_9001;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "ifname", &ifname);
			if (strchr(ifname, '@')) {
				dmuci_delete_by_section(((struct intf_ip_args *)data)->interface_sec, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ip6prefix", "");
			}

			dmuci_delete_by_section(((struct intf_ip_args *)data)->dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
			if (strcmp(proto, "static") != 0 || (strcmp(proto, "static") == 0 && interface_section_with_dhcpv6_exists(section_name((struct uci_section *)data))))
				return FAULT_9001;

			snprintf(buf, sizeof(buf), "@%s", section_name((struct uci_section *)data));
			uci_foreach_sections_safe("network", "interface", stmp, s) {

				dmuci_get_value_by_section_string(s, "ifname", &ifname);

				if (strcmp(section_name(s), section_name((struct uci_section *)data)) == 0) {
					dmuci_set_value_by_section(s, "ip6prefix", "");

					get_dmmap_section_of_config_section("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);
				} else if (strcmp(ifname, buf) == 0) {
					get_dmmap_section_of_config_section("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);

					dmuci_delete_by_section(s, NULL, NULL);
				} else {
					continue;
				}
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_IP_IPv4Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = folder_exists("/proc/sys/net/ipv4") ? "1" : "0";
	return 0;
}

static int get_IP_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_IP_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_IP_IPv4Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

static int get_IP_IPv6Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = folder_exists("/proc/sys/net/ipv6") ? "1" : "0";
	return 0;
}

static int get_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[16] = {0};

	dm_read_sysfs_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", buf, sizeof(buf));
	*value = (strcmp(buf, "1") == 0) ? "0" : "1";
	return 0;
}

static int set_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			fp = fopen("/etc/sysctl.conf", "r+");
			if (!fp)
				return 0;

			snprintf(buf, sizeof(buf), "net.ipv6.conf.all.disable_ipv6=%d", b ? 0 : 1);
			DMCMD("sysctl", 2, "-w", buf);

			fseek(fp, 0, SEEK_END);
			long length = ftell(fp);
			char *buffer = dmcalloc(1, length+1);
			if (buffer) {
				fseek(fp, 0, SEEK_SET);
				size_t len = fread(buffer, 1, length, fp);
				if (len != length) {
					dmfree(buffer);
					fclose(fp);
					break;
				}

				char *ptr = strstr(buffer, "net.ipv6.conf.all.disable_ipv6");
				if (ptr) {
					*(ptr+31) = (b) ? '0' : '1';
					fseek(fp, 0, SEEK_SET);
					fwrite(buffer, sizeof(char), strlen(buffer), fp);
				} else {
					fputs(buf, fp);
				}
				dmfree(buffer);
			}
			fclose(fp);

			break;
	}
	return 0;
}

static int get_IP_IPv6Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_IP_IPv6Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.IP.ULAPrefix!UCI:network/globals,globals/ula_prefix*/
static int get_IP_ULAPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("network", "globals", "ula_prefix", value);
	return 0;
}

static int set_IP_ULAPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPv6Prefix, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("network", "globals", "ula_prefix", value);
			break;
	}
	return 0;
}

static int get_IP_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;
	char *proto, *ifname;

	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		dmuci_get_value_by_section_string(s, "ifname", &ifname);

		if (strcmp(section_name(s), "loopback") == 0 ||
			*proto == '\0' ||
			strchr(ifname, '@'))
			continue;

		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IP.Interface.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled;
	dmuci_get_value_by_section_string((struct uci_section *)data, "disabled", &disabled);
	*value = (*disabled == '1') ? "0" : "1";
	return 0;
}

static int set_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Enable!UCI:network/interface,@i-1/disabled*/
static int get_IPInterface_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled;
	dmuci_get_value_by_section_string((struct uci_section *)data, "disabled", &disabled);
	*value = (*disabled == '1') ? "0" : "1";
	return 0;
}

static int set_IPInterface_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Enable!UCI:network/interface,@i-1/ipv6*/
static int get_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ipv6", "1");
	return 0;
}

static int set_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "ipv6", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_IPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name((struct uci_section *)data), String}}, 1, &res);
	DM_ASSERT(res, *value = "Down");
	char *up = dmjson_get_value(res, 1, "up");
	*value = (strcmp(up, "true") == 0) ? "Up" : "Down";
	return 0;
}

/*#Device.IP.Interface.{i}.Alias!UCI:dmmap_network/interface,@i-1/ip_int_alias*/
static int get_IPInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ip_int_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_IPInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ip_int_alias", value);
			break;
	}
	return 0;
}

static int get_IPInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name((struct uci_section *)data));
	return 0;
}

/*#Device.IP.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_IPInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name((struct uci_section *)data), String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto;

	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
	if (strstr(proto, "ppp")) {
		char linker[64] = {0};
		snprintf(linker, sizeof(linker), "%s", section_name((struct uci_section *)data));
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value != NULL)
			return 0;
	}

	char *device = get_device(section_name((struct uci_section *)data));
	if (device[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cVLANTermination%c", dmroot, dm_delim, dm_delim, dm_delim), device, value);
		if (*value != NULL)
			return 0;
	}

	if (device[0] != '\0') {
		char linker[32] = {0};
		strncpy(linker, device, sizeof(linker) - 1);
		char *vid = strchr(linker, '.');
		if (vid) *vid = '\0';
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value != NULL)
			return 0;
	}

	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;
	char lower_layer[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			append_dot_to_string(lower_layer, value, sizeof(lower_layer));

			if (strncmp(lower_layer, "Device.Ethernet.VLANTermination.", 32) == 0) {
				adm_entry_get_linker_value(ctx, lower_layer, &linker);

				if (linker == NULL || *linker == '\0')
					return -1;

				struct uci_section *s = NULL, *stmp = NULL;

				// Remove the device section corresponding to this interface if exists
				char *device = get_device(section_name((struct uci_section *)data));
				uci_foreach_option_eq_safe("network", "device", "name", device, stmp, s) {
					char *type;
					dmuci_get_value_by_section_string(s, "type", &type);
					if (strcmp(type, "untagged") == 0) dmuci_delete_by_section(s, NULL, NULL);
					break;
				}

				char *mac_vlan = strchr(linker, '_');
				if (mac_vlan) {
					// Check if there is an interface that has the same ifname ==> if yes, remove it
					uci_foreach_option_eq_safe("network", "interface", "ifname", linker, stmp, s) {
						dmuci_delete_by_section(s, NULL, NULL);
					}

					// Check if there is an dmmap link section that has the same device ==> if yes, update section name
					get_dmmap_section_of_config_section_eq("dmmap", "link", "device", linker, &s);
					dmuci_set_value_by_section_bbfdm(s, "section_name", section_name((struct uci_section *)data));

				} else {
					// Check if there is an interface that has the same name of device ==> if yes, remove it
					char device[32] = {0};
					strncpy(device, linker, sizeof(device) - 1);
					char *vid = strchr(device, '.');
					if (vid) {
						*vid = '\0';
						uci_foreach_option_eq_safe("network", "interface", "ifname", device, stmp, s) {
							dmuci_delete_by_section(s, NULL, NULL);
						}
					}
				}

				// Update ifname list
				dmuci_set_value_by_section((struct uci_section *)data, "ifname", linker);

			} else if (strncmp(lower_layer, "Device.Ethernet.Link.", 21) == 0) {
				adm_entry_get_linker_value(ctx, lower_layer, &linker);

				if (linker == NULL || *linker == '\0')
					return -1;

				// Get interface name from Ethernet.Link. object
				struct uci_section *s = NULL;
				char *interface_list;
				get_dmmap_section_of_config_section_eq("dmmap", "link", "device", linker, &s);
				dmuci_get_value_by_section_string(s, "section_name", &interface_list);
				char *interface = strchr(interface_list, ',');

				if (!interface) {
					bool ip_interface_s = false;
					// Update the new interface section with proto=dhcp if its proto is empty
					uci_foreach_sections("network", "interface", s) {
						if (strcmp(section_name(s), interface_list) == 0) {
							char *proto, *type;
							dmuci_get_value_by_section_string(s, "proto", &proto);
							dmuci_get_value_by_section_string(s, "type", &type);
							if (*proto == '\0') {
								dmuci_set_value_by_section(s, "proto", "dhcp");
								if (strcmp(type, "bridge") != 0)
									set_ip_interface_ifname_option(s, linker, instance);
							} else {
								ip_interface_s = true;
							}
							break;
						}
					}

					if (!ip_interface_s) {
						// Get dmmap section related to this interface section and remove it
						struct uci_section *dmmap_section = NULL;
						get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);

						// Get the current ip instance
						char *ip_int_instance;
						dmuci_get_value_by_section_string(dmmap_section, "ip_int_instance", &ip_int_instance);

						// Get the new dmmap section related to the new interface section and update ip instance option
						struct uci_section *new_dmmap_section = NULL;
						get_dmmap_section_of_config_section("dmmap_network", "interface", interface_list, &new_dmmap_section);
						dmuci_set_value_by_section(new_dmmap_section, "ip_int_instance", ip_int_instance);

						// remove dmmap section
						dmuci_delete_by_section(dmmap_section, NULL, NULL);

						// remove the current interface section
						dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
					} else {
						set_ip_interface_ifname_option((struct uci_section *)data, linker, instance);
					}
				} else {
					set_ip_interface_ifname_option((struct uci_section *)data, linker, instance);
				}
			}
			break;
	}
	return 0;
}

static int get_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Device.Routing.Router.1";
	return 0;
}

static int set_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int set_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *ubus_object;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				dmastrcat(&ubus_object, "network.interface.", section_name(((struct uci_section *)data)));
				dmubus_call_set(ubus_object, "down", UBUS_ARGS{}, 0);
				dmubus_call_set(ubus_object, "up", UBUS_ARGS{}, 0);
				dmfree(ubus_object);
			}
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.MaxMTUSize!SYSFS:/sys/class/net/@Name/mtu*/
static int get_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "mtu", value);
}

static int set_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"64","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "mtu", value);
			break;
	}
	return 0;
}

static int get_IPInterface_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (strcmp(section_name((struct uci_section *)data), "loopback") == 0) ? "Loopback" : "Normal";
	return 0;
}

static int get_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = (strcmp(section_name((struct uci_section *)data), "loopback") == 0) ? "1" : "0";
	return 0;
}

static int set_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_IPInterface_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	synchronize_intf_ipv4_sections_with_dmmap();
	uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv4", "intf_ipv4", "parent_section", section_name((struct uci_section *)data), s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPInterface_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	synchronize_intf_ipv6_sections_with_dmmap();
	uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv6", "intf_ipv6", "parent_section", section_name((struct uci_section *)data), s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPInterface_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	synchronize_intf_ipv6_prefix_sections_with_dmmap();
	uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "parent_section", section_name((struct uci_section *)data), s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPInterface_TWAMPReflectorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("twamp", "twamp_reflector", "interface", section_name((struct uci_section *)data), s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_IPInterfaceIPv4Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "disabled", &disabled);
	*value = (disabled && *disabled == '1') ? "0" : "1";
	return 0;
}

static int set_IPInterfaceIPv4Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_IPInterfaceIPv4Address_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_IPInterfaceIPv4Address_Enable(refparam, ctx, data, instance, value);
	*value = ((*value)[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.Alias!UCI:dmmap_network_ipv4/intf_ipv4,@i-1/ipv4_alias*/
static int get_IPInterfaceIPv4Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "ipv4_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_IPInterfaceIPv4Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "ipv4_alias", value);
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.IPAddress!UCI:network/interface,@i-1/ipaddr*/
static int get_IPInterfaceIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ip_addr = "";

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "ipaddr", &ip_addr);

	if (ip_addr[0] == '\0')
		ip_addr = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "address");

	*value = ip_addr;
	return 0;
}

static int set_IPInterfaceIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (proto && strcmp(proto, "static") == 0) {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", value);
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
			}
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.SubnetMask!UCI:network/interface,@i-1/netmask*/
static int get_IPInterfaceIPv4Address_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mask = "";

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "netmask", &mask);

	if (mask[0] == '\0') {
		mask = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "mask");
		mask = (mask && *mask) ? dmstrdup(cidr2netmask(atoi(mask))) : "";
	}

	*value = mask;
	return 0;
}

static int set_IPInterfaceIPv4Address_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (proto && strcmp(proto, "static") == 0)
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", value);
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.AddressingType!UCI:network/interface,@i-1/proto*/
static int get_IPInterfaceIPv4Address_AddressingType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", value);
	*value = (strcmp(*value, "dhcp") == 0) ? "DHCP" : "Static";
	return 0;
}

static int get_IPInterfaceIPv4Address_X_IOPSYS_EU_FirewallEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *input = NULL, *forward = NULL;

	*value = "0";
	uci_foreach_option_cont("firewall", "zone", "network", section_name(((struct intf_ip_args *)data)->interface_sec), s) {
		dmuci_get_value_by_section_string(s, "input", &input);
		dmuci_get_value_by_section_string(s, "forward", &forward);
		if (input && strcmp(input, "ACCEPT") != 0 && forward && strcmp(forward, "ACCEPT") != 0) {
			*value = "1";
			break;
		}
	}

	return 0;
}

static int set_IPInterfaceIPv4Address_X_IOPSYS_EU_FirewallEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	int cnt = 0;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			value = b ? "DROP" : "ACCEPT";
			uci_foreach_option_cont("firewall", "zone", "network", section_name(((struct intf_ip_args *)data)->interface_sec), s) {
				dmuci_set_value_by_section(s, "input", value);
				dmuci_set_value_by_section(s, "forward", value);
				cnt++;
			}
			if (cnt == 0 && b)
				create_firewall_zone_config(section_name(((struct intf_ip_args *)data)->interface_sec));
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.Enable!UCI:network/interface,@i-1/ipv6*/
static int get_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct intf_ip_args *)data)->interface_sec, "ipv6", "1");
	return 0;
}

static int set_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipv6", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.Status!UCI:network/interface,@i-1/ipv6*/
static int get_IPInterfaceIPv6Address_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_IPInterfaceIPv6Address_Enable(refparam, ctx, data, instance, value);
	*value = ((*value)[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_IPInterfaceIPv6Address_IPAddressStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL, *preferred = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "1") == 0)
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 2, "local-address", "preferred");
	else
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");

	*value = (preferred && *preferred != '\0') ? "Preferred" : "Invalid";
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.Alias!UCI:dmmap_network_ipv6/intf_ipv6,@i-1/ipv6_alias*/
static int get_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "ipv6_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "ipv6_alias", value);
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.IPAddress!UCI:network/interface,@i-1/ip6addr*/
static int get_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
	return 0;
}

static int set_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPv6Address, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (proto && strcmp(proto, "static") == 0) {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ip6addr", value);
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
			}
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Address_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "1") == 0) {
		*value = "AutoConfigured";
	} else {
		char *proto;
		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
		*value = (strcmp(proto, "dhcpv6") == 0) ? "DHCPv6" : "Static";
	}
	return 0;
}

static int get_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "1") == 0) {
		struct uci_section *dmmap_section = NULL;
		char *ip_inst = NULL, *ipv6_prefix_inst = NULL, *parent_section, *section_name;

		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "parent_section", &parent_section);
		get_dmmap_section_of_config_section("dmmap_network", "interface", parent_section, &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "ip_int_instance", &ip_inst);

		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "section_name", &section_name);
		get_dmmap_section_of_config_section("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", section_name, &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "ipv6_prefix_instance", &ipv6_prefix_inst);

		if (ip_inst && *ip_inst && ipv6_prefix_inst && *ipv6_prefix_inst)
			dmasprintf(value, "Device.IP.Interface.%s.IPv6Prefix.%s", ip_inst, ipv6_prefix_inst);
	}
	return 0;
}

static int set_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL, *preferred = NULL, local_time[32] = {0};

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "1") == 0)
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 2, "local-address", "preferred");
	else
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");

	if (preferred && *preferred && get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL, *preferred = NULL, local_time[32] = {0};

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "1") == 0)
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 2, "local-address", "preferred");
	else
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");

	if (preferred && *preferred && get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Enable!UCI:network/interface,@i-1/ipv6*/
static int get_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipv6 = NULL;
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "ipv6", &ipv6);
	*value = (ipv6 && *ipv6 != '0') ? "1" : "0";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipv6", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Status!UCI:network/interface,@i-1/ipv6*/
static int get_IPInterfaceIPv6Prefix_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_IPInterfaceIPv6Prefix_Enable(refparam, ctx, data, instance, value);
	*value = ((*value)[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_IPInterfaceIPv6Prefix_PrefixStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");
	*value = (preferred && *preferred) ? "Preferred" : "Invalid";
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Alias!UCI:dmmap_network_ipv6_prefix/intf_ipv6_prefix,@i-1/ipv6_prefix_alias*/
static int get_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "ipv6_prefix_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "ipv6_prefix_alias", value);
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Prefix!UCI:network/interface,@i-1/ip6prefix*/
static int get_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
	return 0;
}

static int set_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPv6Prefix, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (proto && strcmp(proto, "static") == 0) {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ip6prefix", value);
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
			}
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "1") == 0) {
		*value = "AutoConfigured";
	} else {
		char *proto = NULL;
		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
		*value = (proto && strcmp(proto, "dhcpv6") == 0) ? "DHCPv6" : "Static";
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", &linker);
	if (linker && *linker)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (assign && strcmp(assign, "0") == 0) {
		char *address = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 3, "assigned", "lan", "address");
		char *mask = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 3, "assigned", "lan", "mask");
		if (address && *address && mask && *mask)
			dmasprintf(value, "%s/%s", address, mask);
	}
	return 0;
}

static int set_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPv6Prefix, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};

	char *preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");
	if (preferred && *preferred && get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};

	char *valid = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "valid");
	if (valid && *valid && get_shift_time_time(atoi(valid), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_IPInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.IP.Interface.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_IPInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.IP.Interface.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_IPInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.IP.Interface.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_IPInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.IP.Interface.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_IPInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.IP.Interface.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_IPInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.IP.Interface.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_IPInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.IP.Interface.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_IPInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/rx_dropped", value);
}

/*#Device.IP.Interface.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_IPInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_ip_iface_sysfs(data, "statistics/multicast", value);
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.IP. *** */
DMOBJ tIPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Interface", &DMWRITE, addObjIPInterface, delObjIPInterface, NULL, browseIPInterfaceInst, NULL, tIPInterfaceObj, tIPInterfaceParams, get_linker_ip_interface, BBFDM_BOTH, LIST_KEY{"Alias", "Name", NULL}},
#ifdef BBF_TR143
{"Diagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsObj, tIPDiagnosticsParams, NULL, BBFDM_BOTH},
#endif
{0}
};

DMLEAF tIPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IPv4Capable", &DMREAD, DMT_BOOL, get_IP_IPv4Capable, NULL, BBFDM_BOTH},
{"IPv4Enable", &DMWRITE, DMT_BOOL, get_IP_IPv4Enable, set_IP_IPv4Enable, BBFDM_BOTH},
{"IPv4Status", &DMREAD, DMT_STRING, get_IP_IPv4Status, NULL, BBFDM_BOTH},
{"IPv6Capable", &DMREAD, DMT_BOOL, get_IP_IPv6Capable, NULL, BBFDM_BOTH},
{"IPv6Enable", &DMWRITE, DMT_BOOL, get_IP_IPv6Enable, set_IP_IPv6Enable, BBFDM_BOTH},
{"IPv6Status", &DMREAD, DMT_STRING, get_IP_IPv6Status, NULL, BBFDM_BOTH},
{"ULAPrefix", &DMWRITE, DMT_STRING, get_IP_ULAPrefix, set_IP_ULAPrefix, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IP_InterfaceNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}. *** */
DMOBJ tIPInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPv4Address", &DMWRITE, addObjIPInterfaceIPv4Address, delObjIPInterfaceIPv4Address, NULL, browseIPInterfaceIPv4AddressInst, NULL, NULL, tIPInterfaceIPv4AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "IPAddress", "SubnetMask", NULL}},
{"IPv6Address", &DMWRITE, addObjIPInterfaceIPv6Address, delObjIPInterfaceIPv6Address, NULL, browseIPInterfaceIPv6AddressInst, NULL, NULL, tIPInterfaceIPv6AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "IPAddress", NULL}},
{"IPv6Prefix", &DMWRITE, addObjIPInterfaceIPv6Prefix, delObjIPInterfaceIPv6Prefix, NULL, browseIPInterfaceIPv6PrefixInst, NULL, NULL, tIPInterfaceIPv6PrefixParams, get_linker_ipv6_prefix, BBFDM_BOTH, LIST_KEY{"Alias", "Prefix", NULL}},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIPInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterface_Enable, set_IPInterface_Enable, BBFDM_BOTH},
{"IPv4Enable", &DMWRITE, DMT_BOOL, get_IPInterface_IPv4Enable, set_IPInterface_IPv4Enable, BBFDM_BOTH},
{"IPv6Enable", &DMWRITE, DMT_BOOL, get_IPInterface_IPv6Enable, set_IPInterface_IPv6Enable, BBFDM_BOTH},
//{"ULAEnable", &DMWRITE, DMT_BOOL, get_IPInterface_ULAEnable, set_IPInterface_ULAEnable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterface_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterface_Alias, set_IPInterface_Alias, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_IPInterface_Name, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_IPInterface_LastChange, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_IPInterface_LowerLayers, set_IPInterface_LowerLayers, BBFDM_BOTH},
{"Router", &DMWRITE, DMT_STRING, get_IPInterface_Router, set_IPInterface_Router, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_IPInterface_Reset, set_IPInterface_Reset, BBFDM_CWMP},
{"MaxMTUSize", &DMWRITE, DMT_UNINT, get_IPInterface_MaxMTUSize, set_IPInterface_MaxMTUSize, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_IPInterface_Type, NULL, BBFDM_BOTH},
{"Loopback", &DMWRITE, DMT_BOOL, get_IPInterface_Loopback, set_IPInterface_Loopback, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_IPv4AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_IPv6AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"IPv6PrefixNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_IPv6PrefixNumberOfEntries, NULL, BBFDM_BOTH},
//{"AutoIPEnable", &DMWRITE, DMT_BOOL, get_IPInterface_AutoIPEnable, set_IPInterface_AutoIPEnable, BBFDM_BOTH},
{"TWAMPReflectorNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_TWAMPReflectorNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv4Address.{i}. *** */
DMLEAF tIPInterfaceIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv4Address_Enable, set_IPInterfaceIPv4Address_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceIPv4Address_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceIPv4Address_Alias, set_IPInterfaceIPv4Address_Alias, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_IPInterfaceIPv4Address_IPAddress, set_IPInterfaceIPv4Address_IPAddress, BBFDM_BOTH},
{"SubnetMask", &DMWRITE, DMT_STRING, get_IPInterfaceIPv4Address_SubnetMask, set_IPInterfaceIPv4Address_SubnetMask, BBFDM_BOTH},
{"AddressingType", &DMREAD, DMT_STRING, get_IPInterfaceIPv4Address_AddressingType, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"FirewallEnabled", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv4Address_X_IOPSYS_EU_FirewallEnabled, set_IPInterfaceIPv4Address_X_IOPSYS_EU_FirewallEnabled, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv6Address.{i}. *** */
DMLEAF tIPInterfaceIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Address_Enable, set_IPInterfaceIPv6Address_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Address_Status, NULL, BBFDM_BOTH},
{"IPAddressStatus", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Address_IPAddressStatus, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Address_Alias, set_IPInterfaceIPv6Address_Alias, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Address_IPAddress, set_IPInterfaceIPv6Address_IPAddress, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Address_Origin, NULL, BBFDM_BOTH},
{"Prefix", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Address_Prefix, set_IPInterfaceIPv6Address_Prefix, BBFDM_BOTH},
{"PreferredLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Address_PreferredLifetime, set_IPInterfaceIPv6Address_PreferredLifetime, BBFDM_BOTH},
{"ValidLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Address_ValidLifetime, set_IPInterfaceIPv6Address_ValidLifetime, BBFDM_BOTH},
//{"Anycast", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Address_Anycast, set_IPInterfaceIPv6Address_Anycast, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv6Prefix.{i}. *** */
DMLEAF tIPInterfaceIPv6PrefixParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Prefix_Enable, set_IPInterfaceIPv6Prefix_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Prefix_Status, NULL, BBFDM_BOTH},
{"PrefixStatus", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Prefix_PrefixStatus, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_Alias, set_IPInterfaceIPv6Prefix_Alias, BBFDM_BOTH},
{"Prefix", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_Prefix, set_IPInterfaceIPv6Prefix_Prefix, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Prefix_Origin, NULL, BBFDM_BOTH},
//{"StaticType", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_StaticType, set_IPInterfaceIPv6Prefix_StaticType, BBFDM_BOTH},
{"ParentPrefix", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_ParentPrefix, set_IPInterfaceIPv6Prefix_ParentPrefix, BBFDM_BOTH},
{"ChildPrefixBits", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_ChildPrefixBits, set_IPInterfaceIPv6Prefix_ChildPrefixBits, BBFDM_BOTH},
//{"OnLink", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Prefix_OnLink, set_IPInterfaceIPv6Prefix_OnLink, BBFDM_BOTH},
//{"Autonomous", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Prefix_Autonomous, set_IPInterfaceIPv6Prefix_Autonomous, BBFDM_BOTH},
{"PreferredLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Prefix_PreferredLifetime, set_IPInterfaceIPv6Prefix_PreferredLifetime, BBFDM_BOTH},
{"ValidLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Prefix_ValidLifetime, set_IPInterfaceIPv6Prefix_ValidLifetime, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.Stats. *** */
DMLEAF tIPInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_BytesSent, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_BytesReceived, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_PacketsSent, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_PacketsReceived, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_IPInterfaceStats_ErrorsSent, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_IPInterfaceStats_ErrorsReceived, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_UnicastPacketsSent, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_UnicastPacketsReceived, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_IPInterfaceStats_DiscardPacketsSent, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_IPInterfaceStats_DiscardPacketsReceived, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_MulticastPacketsSent, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_MulticastPacketsReceived, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_BroadcastPacketsSent, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_IPInterfaceStats_BroadcastPacketsReceived, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_IPInterfaceStats_UnknownProtoPacketsReceived, NULL, BBFDM_BOTH},
{0}
};
