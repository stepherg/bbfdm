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

#include "ppp.h"
#include "firewall.h"
#include "ip.h"
#if defined(BBF_TR143) || defined(BBF_TR471)
#include "diagnostics.h"
#endif

struct intf_ip_args
{
	struct uci_section *interface_sec;
	struct uci_section *dmmap_sec;
	json_object *interface_obj;
	bool is_main_sec;
};

/*************************************************************
* INIT
**************************************************************/
static int init_interface_ip_args(struct intf_ip_args *args, struct uci_section *intf_s, struct uci_section *dmmap_s, json_object *intf_obj, bool is_main_sec)
{
	args->interface_sec = intf_s;
	args->dmmap_sec = dmmap_s;
	args->interface_obj = intf_obj;
	args->is_main_sec = is_main_sec;
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
	if (assign && DM_LSTRCMP(assign, "0") == 0) {
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
bool ip___is_ipinterface_exists(const char *sec_name, const char *device)
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

static int get_sysctl_disable_ipv6_per_device(const char *device, char **value)
{
	char file[256];
	char val[32] = {0};

	*value = "0";

	if (DM_STRLEN(device) == 0)
		return -1;

	snprintf(file, sizeof(file), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", device);
	dm_read_sysfs_file(file, val, sizeof(val));
	*value = dmstrdup(val);

	return 0;
}

static int set_sysctl_disable_ipv6_per_device(const char *device, bool value)
{
	FILE *fp = NULL;
	char cmd[128] = {0};
	char path[64] = {0};

	fp = fopen("/etc/bbfdm/sysctl.conf", "r+");
	if (!fp)
		return -1;

	int path_len = snprintf(path, sizeof(path), "net.ipv6.conf.%s.disable_ipv6", device);
	int cmd_len = snprintf(cmd, sizeof(cmd), "%s=%d", path, value ? 0 : 1);

	dmcmd("sysctl", 2, "-w", cmd);

	fseek(fp, 0, SEEK_END);
	long length = ftell(fp);

	char *buf = (char *)dmcalloc(1, length + 1);
	if (buf == NULL) {
		fclose(fp);
		return -1;
	}


	fseek(fp, 0, SEEK_SET);
	size_t len = fread(buf, 1, length, fp);
	if (len != length) {
		dmfree(buf);
		fclose(fp);
		return -1;
	}

	char *ptr = DM_STRSTR(buf, path);
	if (ptr) {
		*(ptr + path_len + 1) = (value) ? '0' : '1';
		fseek(fp, 0, SEEK_SET);
		fwrite(buf, sizeof(char), strlen(buf), fp);
	} else {
		cmd[cmd_len] = '\n';
		cmd[cmd_len + 1] = 0;
		fputs(cmd, fp);
	}

	dmfree(buf);
	fclose(fp);

	return 0;
}

static void update_child_interfaces(char *device, char *option_name, char *option_value)
{
	struct uci_section *s = NULL;

	if (DM_STRLEN(device) == 0)
		return;

	uci_foreach_option_eq("network", "interface", "device", device, s) {
		dmuci_set_value_by_section(s, option_name, option_value);
	}
}

static int get_ip_iface_sysfs(const struct uci_section *data, const char *name, char **value)
{
	return get_net_iface_sysfs(section_name((struct uci_section *)data), name, value);
}

static void add_network_to_firewall_zone_network_list(char *zone_name, char *interface_name)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("firewall", "zone", "name", zone_name, s) {
		dmuci_add_list_value_by_section(s, "network", interface_name);
		break;
	}
}

static bool proc_intf6_line_exists(char *parent_section, char *address)
{
	struct uci_section *s = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_network_ipv6", "intf_ipv6", s) {
		char *parent_s = NULL, *addr = NULL;

		dmuci_get_value_by_section_string(s, "parent_section", &parent_s);
		dmuci_get_value_by_section_string(s, "address", &addr);

		if (parent_s && DM_STRCMP(parent_s, parent_section) == 0 &&
			addr && DM_STRCMP(addr, address) == 0)
			return true;
	}
	return false;
}

static void dmmap_synchronize_ipv6_address_link_local(char *parent_section)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char buf[512] = {0}, ipstr[64] = {0};
	FILE *fp = NULL;

	char *device = get_device(parent_section);

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv6", "intf_ipv6", stmp, s) {
		char *link_local = NULL, *parent_s = NULL, *address = NULL;

		dmuci_get_value_by_section_string(s, "parent_section", &parent_s);
		dmuci_get_value_by_section_string(s, "link_local", &link_local);

		if ((parent_s && DM_STRCMP(parent_s, parent_section) != 0) ||
			(link_local && DM_LSTRCMP(link_local, "1") != 0))
			continue;

		dmuci_get_value_by_section_string(s, "address", &address);

		fp = fopen(PROC_INTF6, "r");
		if (fp == NULL)
			return;

		bool found = false;
		while (fgets(buf, 512, fp) != NULL) {

			if (parse_proc_intf6_line(buf, device, ipstr, sizeof(ipstr)))
				continue;

			if (address && DM_STRCMP(address, ipstr) == 0) {
				found = true;
				break;
			}
		}
		fclose(fp);

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	fp = fopen(PROC_INTF6, "r");
	if (fp == NULL)
		return;

	while (fgets(buf , 512 , fp) != NULL) {

		if (parse_proc_intf6_line(buf, device, ipstr, sizeof(ipstr)))
			continue;

		if (proc_intf6_line_exists(parent_section, ipstr))
			continue;

		dmuci_add_section_bbfdm("dmmap_network_ipv6", "intf_ipv6", &s);
		dmuci_set_value_by_section(s, "parent_section", parent_section);
		dmuci_set_value_by_section(s, "section_name", parent_section);
		dmuci_set_value_by_section(s, "link_local", "1");
		dmuci_set_value_by_section(s, "address", ipstr);
	}
	fclose(fp);
}

static struct uci_section *check_dmmap_network_interface_ipv4(char *dmmap_file_name, char *dmmap_sec_name, char *parent_section, char *section_name)
{
	struct uci_section *dmmap_section = NULL;
	char *sec_name;

	uci_path_foreach_option_eq(bbfdm, dmmap_file_name, dmmap_sec_name, "parent_section", parent_section, dmmap_section) {
		dmuci_get_value_by_section_string(dmmap_section, "section_name", &sec_name);
		if (DM_STRCMP(sec_name, section_name) == 0)
			return dmmap_section;
	}

	return NULL;
}

static struct uci_section *add_dmmap_network_interface_ipv4(char *dmmap_file_name, char *dmmap_sec_name, char *parent_section, char *section_name, char *addr, char *mask, char *disabled)
{
	struct uci_section *dmmap_section = NULL;

	dmuci_add_section_bbfdm(dmmap_file_name, dmmap_sec_name, &dmmap_section);
	dmuci_set_value_by_section_bbfdm(dmmap_section, "parent_section", parent_section);
	dmuci_set_value_by_section_bbfdm(dmmap_section, "section_name", section_name);
	dmuci_set_value_by_section_bbfdm(dmmap_section, "address", addr);
	dmuci_set_value_by_section_bbfdm(dmmap_section, "mask", mask);
	dmuci_set_value_by_section_bbfdm(dmmap_section, "enable", (disabled && *disabled == '1') ? "0" : "1");

	return dmmap_section;
}

static struct uci_section *update_dmmap_network_interface(char *dmmap_file_name, char *dmmap_sec_name, char *parent_section, char *section_name, char *option, char *value, bool assign)
{
	struct uci_section *dmmap_section = NULL;
	char *sec_name, *opt_value;

	uci_path_foreach_option_eq(bbfdm, dmmap_file_name, dmmap_sec_name, "parent_section", parent_section, dmmap_section) {
		dmuci_get_value_by_section_string(dmmap_section, "section_name", &sec_name);
		dmuci_get_value_by_section_string(dmmap_section, option, &opt_value);
		if (DM_STRCMP(sec_name, section_name) == 0 && DM_STRCMP(opt_value, value) == 0)
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
	char *dmmap_intf_s = NULL, *enable = NULL, *ipaddr = NULL;
	char *added_by_controller = NULL, *dmmap_address = NULL;
	bool found = false;
	int i = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv4", "intf_ipv4", stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &dmmap_intf_s);
		dmuci_get_value_by_section_string(s, "address", &dmmap_address);
		dmuci_get_value_by_section_string(s, "added_by_controller", &added_by_controller);
		dmuci_get_value_by_section_string(s, "enable", &enable);
		found = false;

		if (DM_LSTRCMP(added_by_controller, "1") == 0)
			continue;

		ss = get_origin_section_from_config("network", "interface", dmmap_intf_s);

		if (DM_STRCMP(enable, "0") == 0 && ss != NULL)
			continue;

		dmuci_get_value_by_section_string(ss, "ipaddr", &ipaddr);

		if (DM_STRLEN(ipaddr) && DM_STRCMP(ipaddr, dmmap_address) == 0)
			continue;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dmmap_intf_s, String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv4_obj, i, 1, "ipv4-address") {

			char *address = dmjson_get_value(ipv4_obj, 1, "address");
			if (DM_STRLEN(address) && DM_STRCMP(address, dmmap_address) == 0) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static void synchronize_intf_ipv6_sections_with_dmmap(void)
{
	json_object *res = NULL, *ipv6_obj = NULL, *arrobj = NULL;
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;
	char *dmmap_intf_s, *dmmap_address, *link_local = NULL, *ip6addr = NULL;
	bool found = false;
	int i = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv6", "intf_ipv6", stmp, s) {
		dmuci_get_value_by_section_string(s, "link_local", &link_local);
		if (link_local && *link_local != '\0' && DM_LSTRCMP(link_local, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "section_name", &dmmap_intf_s);
		dmuci_get_value_by_section_string(s, "address", &dmmap_address);
		found = false;

		ss = get_origin_section_from_config("network", "interface", dmmap_intf_s);
		dmuci_get_value_by_section_string(ss, "ip6addr", &ip6addr);

		if (ip6addr && *ip6addr != '\0' && DM_STRCMP(ip6addr, dmmap_address) == 0)
			continue;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dmmap_intf_s, String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-address") {

			char *address = dmjson_get_value(ipv6_obj, 1, "address");
			if (address && *address && DM_STRCMP(address, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (found)
			continue;

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-prefix-assignment") {

			char *address = dmjson_get_value(ipv6_obj, 2, "local-address", "address");
			if (address && *address && DM_STRCMP(address, dmmap_address) == 0) {
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
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;
	char *dmmap_intf_s, *dmmap_address, *ip6prefix = NULL, ipv6_prefix[256] = {0};
	int i = 0;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", stmp, s) {
		dmuci_get_value_by_section_string(s, "section_name", &dmmap_intf_s);
		dmuci_get_value_by_section_string(s, "address", &dmmap_address);
		bool found = false;

		ss = get_origin_section_from_config("network", "interface", dmmap_intf_s);
		dmuci_get_value_by_section_string(ss, "ip6prefix", &ip6prefix);

		if (ip6prefix && *ip6prefix != '\0' && DM_STRCMP(ip6prefix, dmmap_address) == 0)
			continue;

		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dmmap_intf_s, String}}, 1, &res);

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix") {

			char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
			char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
			if (*address == '\0' || *mask == '\0')
				continue;

			snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);
			if (DM_STRCMP(ipv6_prefix, dmmap_address) == 0) {
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
			if (DM_STRCMP(ipv6_prefix, dmmap_address) == 0) {
				found = true;
				break;
			}

		}

		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}
}

static void delete_ip_intertace_instance(struct uci_section *s)
{
	struct uci_section *int_ss = NULL, *int_stmp = NULL;
	char *iface_dev = NULL;

	dmuci_get_value_by_section_string(s, "device", &iface_dev);
	if (DM_STRLEN(iface_dev) == 0)
		return;

	uci_foreach_sections_safe("network", "interface", int_stmp, int_ss) {
		struct uci_section *ss = NULL;
		struct uci_section *stmp = NULL;
		char *int_device = NULL;
		char *proto = NULL;

		dmuci_get_value_by_section_string(int_ss, "device", &int_device);
		if (strcmp(section_name(int_ss), section_name(s)) != 0 && DM_STRCMP(int_device, iface_dev) != 0)
			continue;

		/* remove dmmap section related to this interface */
		get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(int_ss), &ss);
		dmuci_delete_by_section(ss, NULL, NULL);

		/* Remove "IPv4Address" child section related to this "IP.Interface." object */
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_network_ipv4", "intf_ipv4", "parent_section", section_name(int_ss), stmp, ss) {
			dmuci_delete_by_section(ss, NULL, NULL);
		}

		/* Remove "IPv6Address" child section related to this "IP.Interface." object */
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_network_ipv6", "intf_ipv6", "parent_section", section_name(int_ss), stmp, ss) {
			dmuci_delete_by_section(ss, NULL, NULL);
		}

		/* Remove "IPv6PrefixAddress" child section related to this "IP.Interface." object */
		uci_path_foreach_option_eq_safe(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "parent_section", section_name(int_ss), stmp, ss) {
			dmuci_delete_by_section(ss, NULL, NULL);
		}

		dmuci_get_value_by_section_string(int_ss, "proto", &proto);

		if (DM_LSTRCMP(proto, "dhcp") == 0) {
			struct uci_section *dhcpv4_client_s = get_dup_section_in_dmmap_opt("dmmap_dhcp_client", "interface", "iface_name", section_name(int_ss));

			if (dhcpv4_client_s) {
				dmuci_set_value_by_section_bbfdm(dhcpv4_client_s, "iface_name", "");
			}
		}

		if (DM_LSTRCMP(proto, "dhcpv6") == 0) {
			struct uci_section *dhcpv6_client_s = get_dup_section_in_dmmap_opt("dmmap_dhcpv6", "interface", "iface_name", section_name(int_ss));

			if (dhcpv6_client_s) {
				dmuci_set_value_by_section_bbfdm(dhcpv6_client_s, "iface_name", "");
			}
		}

		if (DM_LSTRNCMP(proto, "ppp", 3) == 0) {
			struct uci_section *ppp_s = get_dup_section_in_dmmap_opt("dmmap_ppp", "interface", "iface_name", section_name(int_ss));

			if (ppp_s) {
				dmuci_set_value_by_section_bbfdm(ppp_s, "iface_name", "");
			}
		}

		/* Remove Firewall zone section related to this "IP.Interface." object */
		uci_foreach_option_eq_safe("firewall", "zone", "name", section_name(int_ss), stmp, ss) {
			dmuci_delete_by_section(ss, NULL, NULL);
		}

		/* remove interface section */
		dmuci_delete_by_section(int_ss, NULL, NULL);
	}
}

static int delObjIPInterfaceIPv6(void *data, unsigned char del_action, char *dmmap_file_name, char *section_type, char *option_name)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_s = NULL;
	char *proto = NULL, *assign = NULL, *link_local = NULL, *device = NULL, *iface_dev = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "link_local", &link_local);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);

			if ((DM_LSTRCMP(assign, "1") == 0) || (DM_LSTRCMP(link_local, "1") == 0) || DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9001;

			if (!((struct intf_ip_args *)data)->is_main_sec) {
				dmuci_delete_by_section(((struct intf_ip_args *)data)->interface_sec, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, option_name, "");
			}

			dmuci_delete_by_section(((struct intf_ip_args *)data)->dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
			if (DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9001;

			dmuci_get_value_by_section_string((struct uci_section *)data, "device", &iface_dev);

			uci_foreach_sections_safe("network", "interface", stmp, s) {

				dmuci_get_value_by_section_string(s, "device", &device);

				if (strcmp(section_name(s), section_name((struct uci_section *)data)) == 0) {
					dmuci_set_value_by_section(s, option_name, "");

					get_dmmap_section_of_config_section(dmmap_file_name, section_type, section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);
				} else if (DM_STRCMP(device, iface_dev) == 0) {
					get_dmmap_section_of_config_section(dmmap_file_name, section_type, section_name(s), &dmmap_s);
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
* ENTRY METHOD
**************************************************************/
/*#Device.IP.Interface.{i}.!UCI:network/interface/dmmap_network*/
static int browseIPInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	char *proto, *device;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "interface", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		dmuci_get_value_by_section_string(p->config_section, "proto", &proto);
		dmuci_get_value_by_section_string(p->config_section, "device", &device);

		if (strcmp(section_name(p->config_section), "loopback") == 0 ||
			*proto == '\0' ||
			DM_STRCHR(device, '@') ||
			ip___is_ipinterface_exists(section_name(p->config_section), device))
			continue;

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "ip_int_instance", "ip_int_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseIPInterfaceIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *parent_sec = (struct uci_section *)prev_data, *intf_s = NULL, *dmmap_s = NULL;
	struct intf_ip_args curr_intf_ip_args = {0};
	char *inst = NULL, *iface_dev = NULL;

	dmuci_get_value_by_section_string(parent_sec, "device", &iface_dev);

	synchronize_intf_ipv4_sections_with_dmmap();
	uci_foreach_sections("network", "interface", intf_s) {
		char *ipaddr = NULL, *mask = NULL, *added_by_controller = NULL, *device = NULL, *disabled;
		json_object *res = NULL;

		dmuci_get_value_by_section_string(intf_s, "device", &device);
		if (strcmp(section_name(intf_s), section_name(parent_sec)) != 0 && DM_STRCMP(device, iface_dev) != 0)
			continue;

		dmuci_get_value_by_section_string(intf_s, "disabled", &disabled);
		dmuci_get_value_by_section_string(intf_s, "netmask", &mask);

		dmmap_s = check_dmmap_network_interface_ipv4("dmmap_network_ipv4", "intf_ipv4", section_name(parent_sec), section_name(intf_s));
		dmuci_get_value_by_section_string(dmmap_s, "added_by_controller", &added_by_controller);

		dmuci_get_value_by_section_string(intf_s, "ipaddr", &ipaddr);
		if (*ipaddr == '\0') {
			json_object *ipv4_obj = NULL;
			char *if_name = section_name(intf_s);

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
			ipv4_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
			ipaddr = dmjson_get_value(ipv4_obj, 1, "address");
			mask = dmjson_get_value(ipv4_obj, 1, "mask");
			mask = DM_STRLEN(mask) ? cidr2netmask(DM_STRTOL(mask)) : "";
		}

		if (*ipaddr == '\0' && dmmap_s)
			dmuci_get_value_by_section_string(dmmap_s, "address", &ipaddr);

		if (*ipaddr == '\0' && DM_LSTRCMP(added_by_controller, "1") != 0)
			continue;

		if (dmmap_s == NULL)
			dmmap_s = add_dmmap_network_interface_ipv4("dmmap_network_ipv4", "intf_ipv4", section_name(parent_sec), section_name(intf_s), ipaddr, mask, disabled);

		init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, res, !strcmp(section_name(parent_sec), section_name(intf_s)));

		inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv4_instance", "ipv4_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPInterfaceIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *parent_sec = (struct uci_section *)prev_data, *intf_s = NULL, *dmmap_s = NULL;
	char *inst = NULL, *device, *ip6addr;
	char *iface_dev = NULL;
	json_object *res = NULL, *ipv6_obj = NULL, *arrobj = NULL;
	struct intf_ip_args curr_intf_ip_args = {0};
	int i = 0;

	dmuci_get_value_by_section_string(parent_sec, "device", &iface_dev);

	synchronize_intf_ipv6_sections_with_dmmap();
	uci_foreach_sections("network", "interface", intf_s) {

		dmuci_get_value_by_section_string(intf_s, "device", &device);
		if (strcmp(section_name(intf_s), section_name(parent_sec)) != 0 && DM_STRCMP(device, iface_dev) != 0)
			continue;

		dmuci_get_value_by_section_string(intf_s, "ip6addr", &ip6addr);

		char *if_name = section_name(intf_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);

		if (*ip6addr == '\0') {

			dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-address") {

				char *address = dmjson_get_value(ipv6_obj, 1, "address");
				if (*address == '\0')
					continue;

				dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6", "intf_ipv6", section_name(parent_sec), section_name(intf_s), "address", address, false);

				init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_obj, !strcmp(section_name(parent_sec), section_name(intf_s)));

				inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_instance", "ipv6_alias");

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
					goto end;
			}

		} else {

			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6", "intf_ipv6", section_name(parent_sec), section_name(intf_s), "address", ip6addr, false);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, NULL, !strcmp(section_name(parent_sec), section_name(intf_s)));

			inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_instance", "ipv6_alias");

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;

		}

		dmjson_foreach_obj_in_array(res, arrobj, ipv6_obj, i, 1, "ipv6-prefix-assignment") {

			char *address = dmjson_get_value(ipv6_obj, 2, "local-address", "address");
			if (*address == '\0')
				continue;

			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6", "intf_ipv6", section_name(parent_sec), section_name(intf_s), "address", address, true);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_obj, !strcmp(section_name(parent_sec), section_name(intf_s)));

			inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_instance", "ipv6_alias");

			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
				goto end;
		}

		// Get ipv6 LinkLocal address
		if (strcmp(section_name(intf_s), section_name(parent_sec)) == 0) {

			dmmap_synchronize_ipv6_address_link_local(section_name(parent_sec));

			uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv6", "intf_ipv6", "parent_section", section_name(parent_sec), dmmap_s) {
				char *link_local = NULL;

				dmuci_get_value_by_section_string(dmmap_s, "link_local", &link_local);
				if (link_local && DM_LSTRCMP(link_local, "1") != 0)
					continue;

				init_interface_ip_args(&curr_intf_ip_args, NULL, dmmap_s, NULL, true);

				inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_instance", "ipv6_alias");

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
					goto end;
			}
		}
	}

end:
	return 0;
}

static int browseIPInterfaceIPv6PrefixInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *parent_sec = (struct uci_section *)prev_data, *intf_s = NULL, *dmmap_s = NULL;
	char *inst = NULL, *device, *ip6prefix, ipv6_prefix[256] = {0};
	char *iface_dev = NULL;
	json_object *res = NULL, *ipv6_prefix_obj = NULL, *arrobj = NULL;
	struct intf_ip_args curr_intf_ip_args = {0};
	int i = 0;

	dmuci_get_value_by_section_string(parent_sec, "device", &iface_dev);

	synchronize_intf_ipv6_prefix_sections_with_dmmap();
	uci_foreach_sections("network", "interface", intf_s) {

		dmuci_get_value_by_section_string(intf_s, "device", &device);
		if (strcmp(section_name(intf_s), section_name(parent_sec)) != 0 && DM_STRCMP(device, iface_dev) != 0)
			continue;

		dmuci_get_value_by_section_string(intf_s, "ip6prefix", &ip6prefix);

		char *if_name = section_name(intf_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);

		if (*ip6prefix == '\0') {

			dmjson_foreach_obj_in_array(res, arrobj, ipv6_prefix_obj, i, 1, "ipv6-prefix") {

				char *address = dmjson_get_value(ipv6_prefix_obj, 1, "address");
				char *mask = dmjson_get_value(ipv6_prefix_obj, 1, "mask");
				if (*address == '\0' || *mask == '\0')
					continue;

				snprintf(ipv6_prefix, sizeof(ipv6_prefix), "%s/%s", address, mask);
				dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6_prefix","intf_ipv6_prefix", section_name(parent_sec), section_name(intf_s), "address", ipv6_prefix, false);

				init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_prefix_obj, !strcmp(section_name(parent_sec), section_name(intf_s)));

				inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_prefix_instance", "ipv6_prefix_alias");

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_intf_ip_args, inst) == DM_STOP)
					goto end;
			}

		} else {

			dmmap_s = update_dmmap_network_interface("dmmap_network_ipv6_prefix","intf_ipv6_prefix", section_name(parent_sec), section_name(intf_s), "address", ip6prefix, false);

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, NULL, !strcmp(section_name(parent_sec), section_name(intf_s)));

			inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_prefix_instance", "ipv6_prefix_alias");

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

			init_interface_ip_args(&curr_intf_ip_args, intf_s, dmmap_s, ipv6_prefix_obj, !strcmp(section_name(parent_sec), section_name(intf_s)));

			inst = handle_instance(dmctx, parent_node, dmmap_s, "ipv6_prefix_instance", "ipv6_prefix_alias");

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

	snprintf(ip_name, sizeof(ip_name), "iface%s", *instance);

	// Network interface section
	dmuci_set_value("network", ip_name, "", "interface");
	dmuci_set_value("network", ip_name, "proto", "none");
	dmuci_set_value("network", ip_name, "disabled", "1");
	dmuci_set_value("network", ip_name, "device", ip_name);

	// Firewall zone section
	firewall__create_zone_section(ip_name);

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_ip_interface);
	dmuci_set_value_by_section(dmmap_ip_interface, "section_name", ip_name);
	dmuci_set_value_by_section(dmmap_ip_interface, "ip_int_instance", *instance);
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
				char *proto, *device;
				dmuci_get_value_by_section_string(s, "proto", &proto);
				dmuci_get_value_by_section_string(s, "device", &device);

				if (strcmp(section_name(s), "loopback") == 0 ||
					*proto == '\0' ||
					DM_STRCHR(device, '@') ||
					ip___is_ipinterface_exists(section_name(s), device))
					continue;

				delete_ip_intertace_instance(s);
			}
			break;
	}
	return 0;
}

static int addObjIPInterfaceIPv4Address(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *ip_inst = NULL, *device = NULL, ipv4_name[64] = {0};
	struct uci_section *dmmap_ip_interface = NULL, *dmmap_ip_interface_ipv4 = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_ip_interface);
	dmuci_get_value_by_section_string(dmmap_ip_interface, "ip_int_instance", &ip_inst);

	snprintf(ipv4_name, sizeof(ipv4_name), "iface%s_ipv4_%s", ip_inst, *instance);
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);

	dmuci_set_value("network", ipv4_name, "", "interface");
	dmuci_set_value("network", ipv4_name, "device", device);
	dmuci_set_value("network", ipv4_name, "proto", "static");
	dmuci_set_value("network", ipv4_name, "disabled", "1");

	// Firewall : add this new interface to zone->network list
	add_network_to_firewall_zone_network_list(section_name((struct uci_section *)data), ipv4_name);

	dmuci_add_section_bbfdm("dmmap_network_ipv4", "intf_ipv4", &dmmap_ip_interface_ipv4);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "parent_section", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "section_name", ipv4_name);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "enable", "0");
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "added_by_controller", "1");
	dmuci_set_value_by_section(dmmap_ip_interface_ipv4, "ipv4_instance", *instance);
	return 0;
}

static int delObjIPInterfaceIPv4Address(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_s = NULL;
	char *proto, *device, *iface_dev;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9001;


			if (!((struct intf_ip_args *)data)->is_main_sec) {
				dmuci_delete_by_section(((struct intf_ip_args *)data)->interface_sec, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", "");
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", "");
			}

			dmuci_delete_by_section(((struct intf_ip_args *)data)->dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
			if (DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9001;

			dmuci_get_value_by_section_string((struct uci_section *)data, "device", &iface_dev);

			uci_foreach_sections_safe("network", "interface", stmp, s) {

				dmuci_get_value_by_section_string(s, "device", &device);

				if (strcmp(section_name(s), section_name((struct uci_section *)data)) == 0) {
					dmuci_set_value_by_section(s, "ipaddr", "");
					dmuci_set_value_by_section(s, "netmask", "");

					get_dmmap_section_of_config_section("dmmap_network_ipv4", "intf_ipv4", section_name(s), &dmmap_s);
					dmuci_delete_by_section(dmmap_s, NULL, NULL);
				} else if (DM_STRCMP(device, iface_dev) == 0) {
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
	char *ip_inst = NULL, *device = NULL, ipv6_name[64] = {0};
	struct uci_section *dmmap_ip_interface = NULL, *dmmap_ip_interface_ipv6 = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_ip_interface);
	dmuci_get_value_by_section_string(dmmap_ip_interface, "ip_int_instance", &ip_inst);

	snprintf(ipv6_name, sizeof(ipv6_name), "iface%s_ipv6_%s", ip_inst, *instance);
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);

	dmuci_set_value("network", ipv6_name, "", "interface");
	dmuci_set_value("network", ipv6_name, "device", device);
	dmuci_set_value("network", ipv6_name, "proto", "static");
	dmuci_set_value("network", ipv6_name, "ip6addr", "::");
	dmuci_set_value("network", ipv6_name, "disabled", "1");

	// Firewall : add this new interface to zone->network list
	add_network_to_firewall_zone_network_list(section_name((struct uci_section *)data), ipv6_name);

	dmuci_add_section_bbfdm("dmmap_network_ipv6", "intf_ipv6", &dmmap_ip_interface_ipv6);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "parent_section", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "section_name", ipv6_name);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "address", "::");
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6, "ipv6_instance", *instance);
	return 0;
}

static int delObjIPInterfaceIPv6Address(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return delObjIPInterfaceIPv6(data, del_action, "dmmap_network_ipv6", "intf_ipv6", "ip6addr");
}

static int addObjIPInterfaceIPv6Prefix(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *ip_inst = NULL, *device = NULL, ipv6_prefix_name[64] = {0};
	struct uci_section *dmmap_ip_interface = NULL, *dmmap_ip_interface_ipv6_prefix = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_ip_interface);
	dmuci_get_value_by_section_string(dmmap_ip_interface, "ip_int_instance", &ip_inst);

	snprintf(ipv6_prefix_name, sizeof(ipv6_prefix_name), "iface%s_ipv6_prefix_%s", ip_inst, *instance);
	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);

	dmuci_set_value("network", ipv6_prefix_name, "", "interface");
	dmuci_set_value("network", ipv6_prefix_name, "device", device);
	dmuci_set_value("network", ipv6_prefix_name, "proto", "static");
	dmuci_set_value("network", ipv6_prefix_name, "ip6prefix", "::/64");
	dmuci_set_value("network", ipv6_prefix_name, "disabled", "1");

	// Firewall : add this new interface to zone->network list
	add_network_to_firewall_zone_network_list(section_name((struct uci_section *)data), ipv6_prefix_name);

	dmuci_add_section_bbfdm("dmmap_network_ipv6_prefix", "intf_ipv6_prefix", &dmmap_ip_interface_ipv6_prefix);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "parent_section", section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "section_name", ipv6_prefix_name);
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "address", "::/64");
	dmuci_set_value_by_section(dmmap_ip_interface_ipv6_prefix, "ipv6_prefix_instance", *instance);
	return 0;
}

static int delObjIPInterfaceIPv6Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return delObjIPInterfaceIPv6(data, del_action, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "ip6prefix");
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_IP_IPv4Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = folder_exists("/proc/sys/net/ipv4") ? "1" : "0";
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
	char *ipv6 = NULL;

	get_sysctl_disable_ipv6_per_device("all", &ipv6);
	*value = (DM_LSTRCMP(ipv6, "1") == 0) ? "0" : "1";
	return 0;
}

static int set_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			set_sysctl_disable_ipv6_per_device("all", b);
			break;
	}
	return 0;
}

static int get_IP_IPv6Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_IP_IPv6Enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Enabled" : "Disabled";
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
			if (bbfdm_validate_string(ctx, value, -1, 49, NULL, IPv6Prefix))
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
	int cnt = get_number_of_entries(ctx, data, instance, browseIPInterfaceInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.IP.Interface.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *device = NULL;

	*value = "0";

	dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);

	uci_foreach_option_eq("network", "interface", "device", device, s) {
		char *disabled = NULL;

		dmuci_get_value_by_section_string(s, "disabled", &disabled);

		if (DM_STRCMP(disabled, "1") != 0) {
			*value = "1";
			break;
		}
	}

	return 0;
}

static int set_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
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
			update_child_interfaces(device, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

static int get_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = get_device(section_name((struct uci_section *)data));
	char *ipv6 = NULL;

	get_sysctl_disable_ipv6_per_device(device, &ipv6);
	*value = (DM_LSTRCMP(ipv6, "1") == 0) ? "0" : "1";
	return 0;
}

static int set_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *device = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			device = get_device(section_name((struct uci_section *)data));
			set_sysctl_disable_ipv6_per_device(device, b);
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.ULAEnable!UCI:network/interface,@i-1/ula*/
static int get_IPInterface_ULAEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ula", "1");
	return 0;
}

static int set_IPInterface_ULAEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "ula", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_IPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device = get_device(section_name((struct uci_section *)data));
	return get_net_device_status(device, value);
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
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
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
	json_object *res = NULL;

	char *if_name = section_name((struct uci_section *)data);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "LowerLayers", value);

	if ((*value)[0] == '\0') {
		char *device = get_device(section_name((struct uci_section *)data));
		if (DM_STRLEN(device) == 0) {
			dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);
			if (DM_STRLEN(device) == 0)
				return 0;
		}

		adm_entry_get_linker_param(ctx, "Device.PPP.Interface.", device, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN", device, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.VLANTermination.", device, value);
		if (*value != NULL && (*value)[0] != 0)
			return 0;

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Link.", device, value);
	} else {
		char *linker = NULL;

		adm_entry_get_linker_value(ctx, *value, &linker);
		if (!linker || *linker == 0)
			*value = "";
	}
	return 0;
}

static int set_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;
	char eth_mac_vlan[] = "Device.Ethernet."BBF_VENDOR_PREFIX"MACVLAN";
	char *allowed_objects[] = {
			"Device.PPP.Interface.",
			eth_mac_vlan,
			"Device.Ethernet.VLANTermination.",
			"Device.Ethernet.Link.",
			NULL};
	char *linker = NULL;
	char *curr_device = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, -1, 1024, -1, -1, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);

			// Store LowerLayers value under dmmap_network section
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "LowerLayers", value);

			if (DM_STRLEN(linker) == 0) {
				char *curr_proto = NULL;

				// Update device option
				dmuci_set_value_by_section((struct uci_section *)data, "device", section_name((struct uci_section *)data));

				dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &curr_proto);
				if (DM_LSTRNCMP(curr_proto, "ppp", 3) == 0) {
					struct uci_section *ppp_s = NULL;

					ppp_s = get_dup_section_in_dmmap_opt("dmmap_ppp", "interface", "iface_name", section_name((struct uci_section *)data));
					dmuci_set_value_by_section_bbfdm(ppp_s, "iface_name", "");

					dmuci_set_value_by_section((struct uci_section *)data, "proto", "none");
					ppp___reset_options((struct uci_section *)data);
				}
				return 0;
			}

			dmuci_get_value_by_section_string((struct uci_section *)data, "device", &curr_device);
			update_child_interfaces(curr_device, "device", linker);

			if (DM_STRNCMP(value, "Device.PPP.Interface.", strlen("Device.PPP.Interface.")) == 0) {
				struct uci_section *ppp_s = get_dup_section_in_dmmap_opt("dmmap_ppp", "interface", "device", linker);
				dmuci_set_value_by_section_bbfdm(ppp_s, "iface_name", section_name((struct uci_section *)data));
				ppp___update_sections(ppp_s, (struct uci_section *)data);
			}
			break;
	}
	return 0;
}

static int get_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "Router", value);

	if ((*value)[0] == '\0') {
		char *ip4table = NULL;

		dmuci_get_value_by_section_string((struct uci_section *)data, "ip4table", &ip4table);
		adm_entry_get_linker_param(ctx, "Device.Routing.Router.", DM_STRLEN(ip4table) ? ip4table : "254", value);
	} else {
		char *linker = NULL;

		adm_entry_get_linker_value(ctx, *value, &linker);
		if (!linker || *linker == 0)
			*value = "Device.Routing.Router.1";
	}
	return 0;
}

static int set_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.Routing.Router.", NULL};
	struct uci_section *s = NULL;
	char *rt_table = NULL;
	char *device = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &rt_table);
			if (!rt_table || *rt_table == 0)
				return FAULT_9007;

			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &s);
			dmuci_set_value_by_section(s, "Router", value);

			dmuci_set_value_by_section((struct uci_section *)data, "ip4table", rt_table);
			dmuci_set_value_by_section((struct uci_section *)data, "ip6table", rt_table);

			dmuci_get_value_by_section_string((struct uci_section *)data, "device", &device);

			uci_foreach_option_eq("network", "interface", "device", device, s) {
				dmuci_set_value_by_section(s, "ip4table", rt_table);
				dmuci_set_value_by_section(s, "ip6table", rt_table);
			}
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
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			/* Reset can disrupt on-going cwmp session, so this parameter must be
			 * taken care by cwmp internally.
			 */
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.MaxMTUSize!SYSFS:/sys/class/net/@Name/mtu*/
static int get_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_ip_iface_sysfs(data, "mtu", value);
	if (*value && **value != '0')
		return 0;

	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "mtu", "1500");
	return 0;
}

static int set_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"64","65535"}}, 1))
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
	*value = "Normal";
	return 0;
}

static int get_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int set_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_IPInterface_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPInterfaceIPv4AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPInterface_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPInterfaceIPv6AddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPInterface_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseIPInterfaceIPv6PrefixInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_IPInterfaceIPv4Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "enable", value);
	return 0;
}

static int set_IPInterfaceIPv4Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (((struct intf_ip_args *)data)->is_main_sec) {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", "");
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", "");

				if (b) {
					char *addr = NULL, *mask = NULL;

					dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", &addr);
					dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "mask", &mask);

					dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", addr);
					dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", mask);
				}
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "disabled", b ? "0" : "1");
			}

			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "enable", b ? "1" : "0");
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
	return bbf_get_alias(ctx, ((struct intf_ip_args *)data)->dmmap_sec, "ipv4_alias", instance, value);
}

static int set_IPInterfaceIPv4Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct intf_ip_args *)data)->dmmap_sec, "ipv4_alias", instance, value);
}

static int get_IPInterfaceIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
	return 0;
}

static int set_IPInterfaceIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			if (((struct intf_ip_args *)data)->is_main_sec) {
				char *enable = NULL;

				dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "enable", &enable);
				if (DM_STRCMP(enable, "1") == 0)
					dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", value);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ipaddr", value);
			}

			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv4Address_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "mask", value);
	return 0;
}

static int set_IPInterfaceIPv4Address_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			if (DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			if (((struct intf_ip_args *)data)->is_main_sec) {
				char *enable = NULL;

				dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "enable", &enable);
				if (DM_STRCMP(enable, "1") == 0)
					dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", value);
			} else {
				dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "netmask", value);
			}

			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "mask", value);
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.AddressingType!UCI:network/interface,@i-1/proto*/
static int get_IPInterfaceIPv4Address_AddressingType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);

	if (DM_LSTRCMP(proto, "static") == 0)
		*value = "Static";
	else if (DM_LSTRNCMP(proto, "ppp", 3) == 0)
		*value = "IPCP";
	else
		*value = "DHCP";
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL, *link_local = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "link_local", &link_local);

	if ((DM_LSTRCMP(assign, "1") == 0) || (DM_LSTRCMP(link_local, "1") == 0)) {
		*value = "1";
	} else {
		char *disabled = NULL;

		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "disabled", &disabled);
		*value = (disabled && *disabled == '1') ? "0" : "1";
	}

	return 0;
}

static int set_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *link_local = NULL, *assign = NULL, *proto = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "link_local", &link_local);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);

			if ((DM_LSTRCMP(assign, "1") == 0) || (DM_LSTRCMP(link_local, "1") == 0) || DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "disabled", b ? "0" : "1");
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
	if (DM_LSTRCMP(assign, "1") == 0)
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 2, "local-address", "preferred");
	else
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");

	*value = (preferred && *preferred != '\0') ? "Preferred" : "Invalid";
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.Alias!UCI:dmmap_network_ipv6/intf_ipv6,@i-1/ipv6_alias*/
static int get_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct intf_ip_args *)data)->dmmap_sec, "ipv6_alias", instance, value);
}

static int set_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct intf_ip_args *)data)->dmmap_sec, "ipv6_alias", instance, value);
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.IPAddress!UCI:network/interface,@i-1/ip6addr*/
static int get_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
	char *mask = DM_STRCHR(*value, '/');
	if (mask) *mask = '\0';
	return 0;
}

static int set_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *link_local = NULL, *assign = NULL, *proto = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 45, NULL, IPv6Address))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "link_local", &link_local);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);

			if ((DM_LSTRCMP(assign, "1") == 0) || (DM_LSTRCMP(link_local, "1") == 0) || DM_LSTRCMP(proto, "static") != 0)
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ip6addr", value);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Address_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL, *link_local = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "link_local", &link_local);

	if ((DM_LSTRCMP(assign, "1") == 0) || (DM_LSTRCMP(link_local, "1") == 0)) {
		*value = "AutoConfigured";
	} else {
		char *proto;
		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
		*value = (DM_LSTRCMP(proto, "dhcpv6") == 0) ? "DHCPv6" : "Static";
	}
	return 0;
}

static int get_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (DM_LSTRCMP(assign, "1") == 0) {
		struct uci_section *dmmap_section = NULL;
		char *ip_inst = NULL, *ipv6_prefix_inst = NULL, *parent_section, *section_name;
		char curr_address[64] = {0}, *address = NULL;

		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "parent_section", &parent_section);
		get_dmmap_section_of_config_section("dmmap_network", "interface", parent_section, &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "ip_int_instance", &ip_inst);

		char *addr = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "address");
		char *mask = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "mask");
		snprintf(curr_address, sizeof(curr_address), "%s/%s", addr, mask);
		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "section_name", &section_name);
		uci_path_foreach_option_eq(bbfdm, "dmmap_network_ipv6_prefix", "intf_ipv6_prefix", "section_name", section_name, dmmap_section) {
			dmuci_get_value_by_section_string(dmmap_section, "address", &address);
			if (address && DM_STRCMP(address, curr_address) == 0) {
				dmuci_get_value_by_section_string(dmmap_section, "ipv6_prefix_instance", &ipv6_prefix_inst);
				break;
			}
		}

		if (ip_inst && *ip_inst && ipv6_prefix_inst && *ipv6_prefix_inst)
			dmasprintf(value, "Device.IP.Interface.%s.IPv6Prefix.%s", ip_inst, ipv6_prefix_inst);
	}
	return 0;
}

static int set_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL, *preferred = NULL, local_time[32] = {0};

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (DM_LSTRCMP(assign, "1") == 0)
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 2, "local-address", "preferred");
	else
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "preferred");

	if (preferred && *preferred && get_shift_utc_time(DM_STRTOL(preferred), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_dateTime(ctx, value))
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
	if (DM_LSTRCMP(assign, "1") == 0)
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 2, "local-address", "valid");
	else
		preferred = dmjson_get_value(((struct intf_ip_args *)data)->interface_obj, 1, "valid");

	if (preferred && *preferred && get_shift_utc_time(DM_STRTOL(preferred), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_dateTime(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "disabled", &disabled);
	*value = (disabled && *disabled == '1') ? "0" : "1";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL, *assign = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);

			if (DM_LSTRCMP(proto, "static") != 0 || DM_LSTRCMP(assign, "1") == 0)
				return FAULT_9007;

			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "disabled", b ? "0" : "1");
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
	return bbf_get_alias(ctx, ((struct intf_ip_args *)data)->dmmap_sec, "ipv6_prefix_alias", instance, value);
}

static int set_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct intf_ip_args *)data)->dmmap_sec, "ipv6_prefix_alias", instance, value);
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Prefix!UCI:network/interface,@i-1/ip6prefix*/
static int get_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
	return 0;
}

static int set_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto = NULL, *assign = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 49, NULL, IPv6Prefix))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
			dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);

			if (DM_LSTRCMP(proto, "static") != 0 || DM_LSTRCMP(assign, "1") == 0)
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->interface_sec, "ip6prefix", value);
			dmuci_set_value_by_section(((struct intf_ip_args *)data)->dmmap_sec, "address", value);
			break;
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (DM_LSTRCMP(assign, "1") == 0) {
		*value = "AutoConfigured";
	} else {
		char *proto = NULL;
		dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->interface_sec, "proto", &proto);
		*value = (DM_LSTRCMP(proto, "dhcpv6") == 0) ? "PrefixDelegation" : "Static";
	}
	return 0;
}

static int get_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "address", &linker);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *assign = NULL;

	dmuci_get_value_by_section_string(((struct intf_ip_args *)data)->dmmap_sec, "assign", &assign);
	if (DM_LSTRCMP(assign, "0") == 0) {
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
			if (bbfdm_validate_string(ctx, value, -1, 49, NULL, IPv6Prefix))
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
	if (DM_STRLEN(preferred) && get_shift_utc_time(DM_STRTOL(preferred), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_dateTime(ctx, value))
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
	if (DM_STRLEN(valid) && get_shift_time_time(DM_STRTOL(valid), local_time, sizeof(local_time)) == -1)
		return 0;

	*value = (*local_time) ? dmstrdup(local_time) : "9999-12-31T23:59:59Z";
	return 0;
}

static int set_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_dateTime(ctx, value))
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

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char interface_obj[64] = {0};

	snprintf(interface_obj, sizeof(interface_obj), "network.interface.%s", section_name(((struct uci_section *)data)));
	dmubus_call_set(interface_obj, "down", UBUS_ARGS{0}, 0);
	dmubus_call_set(interface_obj, "up", UBUS_ARGS{0}, 0);

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.IP. *** */
DMOBJ tIPObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Interface", &DMWRITE, addObjIPInterface, delObjIPInterface, NULL, browseIPInterfaceInst, NULL, NULL, tIPInterfaceObj, tIPInterfaceParams, get_linker_ip_interface, BBFDM_BOTH, LIST_KEY{"Alias", "Name", NULL}},
#if defined(BBF_TR143) || defined(BBF_TR471)
{"Diagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsObj, tIPDiagnosticsParams, NULL, BBFDM_BOTH, NULL},
#endif
{0}
};

DMLEAF tIPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IPv4Capable", &DMREAD, DMT_BOOL, get_IP_IPv4Capable, NULL, BBFDM_BOTH},
//{"IPv4Enable", &DMWRITE, DMT_BOOL, get_IP_IPv4Enable, set_IP_IPv4Enable, BBFDM_BOTH},
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"IPv4Address", &DMWRITE, addObjIPInterfaceIPv4Address, delObjIPInterfaceIPv4Address, NULL, browseIPInterfaceIPv4AddressInst, NULL, NULL, NULL, tIPInterfaceIPv4AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "IPAddress", "SubnetMask", NULL}},
{"IPv6Address", &DMWRITE, addObjIPInterfaceIPv6Address, delObjIPInterfaceIPv6Address, NULL, browseIPInterfaceIPv6AddressInst, NULL, NULL, NULL, tIPInterfaceIPv6AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "IPAddress", NULL}},
{"IPv6Prefix", &DMWRITE, addObjIPInterfaceIPv6Prefix, delObjIPInterfaceIPv6Prefix, NULL, browseIPInterfaceIPv6PrefixInst, NULL, NULL, NULL, tIPInterfaceIPv6PrefixParams, get_linker_ipv6_prefix, BBFDM_BOTH, LIST_KEY{"Alias", "Prefix", NULL}},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterface_Enable, set_IPInterface_Enable, BBFDM_BOTH},
//{"IPv4Enable", &DMWRITE, DMT_BOOL, get_IPInterface_IPv4Enable, set_IPInterface_IPv4Enable, BBFDM_BOTH},
{"IPv6Enable", &DMWRITE, DMT_BOOL, get_IPInterface_IPv6Enable, set_IPInterface_IPv6Enable, BBFDM_BOTH},
{"ULAEnable", &DMWRITE, DMT_BOOL, get_IPInterface_ULAEnable, set_IPInterface_ULAEnable, BBFDM_BOTH},
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
{"Reset()", &DMSYNC, DMT_COMMAND, NULL, operate_IPInterface_Reset, BBFDM_USP},
{0}
};

/* *** Device.IP.Interface.{i}.IPv4Address.{i}. *** */
DMLEAF tIPInterfaceIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv4Address_Enable, set_IPInterfaceIPv4Address_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceIPv4Address_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceIPv4Address_Alias, set_IPInterfaceIPv4Address_Alias, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_IPInterfaceIPv4Address_IPAddress, set_IPInterfaceIPv4Address_IPAddress, BBFDM_BOTH},
{"SubnetMask", &DMWRITE, DMT_STRING, get_IPInterfaceIPv4Address_SubnetMask, set_IPInterfaceIPv4Address_SubnetMask, BBFDM_BOTH},
{"AddressingType", &DMREAD, DMT_STRING, get_IPInterfaceIPv4Address_AddressingType, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv6Address.{i}. *** */
DMLEAF tIPInterfaceIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
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
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
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
