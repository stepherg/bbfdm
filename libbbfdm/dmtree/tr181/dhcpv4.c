/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dhcpv4.h"
#include "dns.h"

#define DHCP_OPTION_VENDORID 60
#define DHCP_OPTION_CLIENTID 61
#define DHCP_OPTION_HOSTNAME 12

struct dhcp_lease {
	uint64_t ts;
	char hwaddr[24];
	char ipaddr[16];
	struct list_head list;
};

struct dhcp_args {
	struct dmmap_dup *sections;
	char *interface;
	struct list_head leases;
	unsigned n_leases;
};

struct dhcp_host_args {
	struct uci_section *dhcp_sec;
	struct dmmap_dup *host_sections;
	char *dhcp_interface;
};

struct client_args {
	const struct dhcp_lease *lease;
};

struct client_options_args {
	char *tag;
	char *value;
};

struct dhcp_client_args {
	struct uci_section *iface_s;
	struct uci_section *dmmap_s;
};

struct dhcp_client_option_args {
	struct uci_section *client_sect;
	struct uci_section *dmmap_sect;
	char *option_tag;
	char *value;
};

static char *allowed_devices[] = {"All", "Known", "UnKnown", NULL};

/**************************************************************************
* LINKER
***************************************************************************/
static int get_dhcp_client_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	const struct client_args *args = data;

	*linker = (char *)args->lease->hwaddr;
	return 0;
}

/*************************************************************
* INIT
**************************************************************/
static inline void init_dhcp_args(struct dhcp_args *args, struct dmmap_dup *s, char *interface)
{
	args->interface = interface;
	args->sections = s;
	INIT_LIST_HEAD(&args->leases);
	args->n_leases = 0;
}

static inline void init_args_dhcp_host(struct dhcp_host_args *args, struct uci_section *dhcp_s, struct dmmap_dup *host_s, char *interface)
{
	args->dhcp_sec = dhcp_s;
	args->host_sections = host_s;
	args->dhcp_interface = interface;
}

static inline void init_dhcp_client_args(struct client_args *args, const struct dhcp_lease *lease)
{
	args->lease = lease;
}

static inline void init_client_options_args(struct client_options_args *args, char *tag, char *val)
{
	args->tag = tag;
	args->value = val;
}

/*************************************************************
* COMMON FUNCTIONS
**************************************************************/
static struct uci_section *exist_other_section_same_order(struct uci_section *dmmap_sect, char *package, char *sect_type, char *order)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, package, sect_type, "order", order, s) {
		if (strcmp(section_name(s), section_name(dmmap_sect)) != 0) {
			return s;
		}
	}
	return NULL;
}

int set_section_order(char *package, char *dmpackage, char *sect_type, struct uci_section *dmmap_sect, struct uci_section *conf, int set_force, char *order)
{
	char *v = NULL, *sect_name, *incrorder;
	struct uci_section *s, *dm;

	dmuci_get_value_by_section_string(dmmap_sect, "order", &v);
	if (DM_STRLEN(v) > 0 && DM_STRCMP(v, order) == 0)
		return 0;
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "order", order);
	if (conf == NULL) {
		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
	} else
		s = conf;

	if (DM_LSTRCMP(order, "1") != 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "");
	}

	if (set_force == 1 && DM_LSTRCMP(order, "1") == 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "1");
	}

	if ((dm = exist_other_section_same_order(dmmap_sect, dmpackage, sect_type, order)) != NULL) {
		dmuci_get_value_by_section_string(dm, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
		dmasprintf(&incrorder, "%ld", DM_STRTOL(order)+1);
		if (s != NULL && DM_LSTRCMP(order, "1") == 0) {
			dmuci_set_value_by_section(s, "force", "");
		}
		set_section_order(package, dmpackage, sect_type, dm, s, set_force, incrorder);
	}
	return 0;
}

int get_value_in_mac_format(struct uci_section *s, char *option_name, bool type, char **value)
{
	char *option_value = NULL, **macarray, buf[32];
	unsigned pos = 0;
	size_t length;

	dmuci_get_value_by_section_string(s, option_name, &option_value);
	if (option_value == NULL || *option_value == '\0')
		return -1;

	buf[0] = 0;
	macarray = strsplit(option_value, ":", &length);

	for (int i = 0; i < 6; i++)
		pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s:", (macarray[i] && DM_LSTRCMP(macarray[i], "*") == 0) ? "00" : type ? "FF" : macarray[i]);

	if (pos)
		buf[pos - 1] = 0;

	*value = dmstrdup(buf);
	return 0;
}

static bool is_dhcp_section_exist(char *dmmap_file, char *sec_name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_file, "interface", "iface_name", sec_name, s) {
		return true;
	}

	return false;
}

static void dmmap_synchronizeDHCPv4Client(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "interface", stmp, s) {

		char *added_by_controller = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(s, "added_by_controller", &added_by_controller);
		if (DM_LSTRCMP(added_by_controller, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name)) {
			struct uci_section *iface_s = NULL;

			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

			if (!iface_s)
				dmuci_delete_by_section(s, NULL, NULL);
		}
	}

	uci_foreach_sections("network", "interface", s) {
		struct uci_section *ppp_s = NULL;
		char *proto = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (DM_LSTRCMP(proto, "dhcp") != 0)
			continue;

		if (is_dhcp_section_exist("dmmap_dhcp_client", section_name(s)))
			continue;

		dmuci_add_section_bbfdm("dmmap_dhcp_client", "interface", &ppp_s);
		dmuci_set_value_by_section(ppp_s, "iface_name", section_name(s));
		dmuci_set_value_by_section(ppp_s, "dhcp_client_key", section_name(s));
	}
}

static void dmmap_synchronizeDHCPv4RelayForwarding(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;

	uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_relay", "interface", stmp, s) {
		struct uci_section *iface_s = NULL;
		char *added_by_controller = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(s, "added_by_controller", &added_by_controller);
		if (DM_LSTRCMP(added_by_controller, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name))
			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

		if (!iface_s)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_sections("network", "interface", s) {
		struct uci_section *ppp_s = NULL;
		char *proto = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (DM_LSTRCMP(proto, "relay") != 0)
			continue;

		if (is_dhcp_section_exist("dmmap_dhcp_relay", section_name(s)))
			continue;

		dmuci_add_section_bbfdm("dmmap_dhcp_relay", "interface", &ppp_s);
		dmuci_set_value_by_section(ppp_s, "iface_name", section_name(s));
	}
}

static void dhcp_leases_load(struct list_head *head)
{
	FILE *f = fopen(DHCP_LEASES_FILE, "r");
	char line[128];

	if (f == NULL)
		return;

	while (fgets(line, sizeof(line) - 1, f)) {
		struct dhcp_lease *lease;

		if (line[0] == '\n')
			continue;

		lease = dmcalloc(1, sizeof(*lease));
		if (lease == NULL)
			break;

		sscanf(line, "%" PRId64 "%19s %15s",
			&lease->ts, lease->hwaddr, lease->ipaddr);

		list_add_tail(&lease->list, head);
	}
	fclose(f);
}

static int interface_get_ipv4(const char *iface, uint32_t *addr, unsigned *bits)
{
	json_object *res = NULL;
	const char *addr_str = NULL;
	int addr_cidr = -1;

	dmubus_call("network.interface", "status", UBUS_ARGS {{"interface", iface, String}}, 1, &res);
	if (res) {
		json_object *jobj;

		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		if (jobj == NULL)
			return -1;

		json_object_object_foreach(jobj, key, val) {
			if (!DM_LSTRCMP(key, "address"))
				addr_str = json_object_get_string(val);
			else if (!DM_LSTRCMP(key, "mask"))
				addr_cidr = json_object_get_int(val);
		}
	}

	if (addr_str == NULL || addr_cidr == -1)
		return -1;

	if (inet_pton(AF_INET, addr_str, addr) != 1)
		return -1;

	*bits = addr_cidr;
	return 0;
}

static void dhcp_leases_assign_to_interface(struct dhcp_args *dhcp,
					struct list_head *src,
					const char *iface)
{
	struct dhcp_lease *lease = NULL, *tmp = NULL;
	unsigned iface_addr;
	unsigned iface_cidr;
	unsigned iface_net;
	unsigned iface_bits;

	if (interface_get_ipv4(iface, &iface_addr, &iface_cidr))
		return;

	iface_bits = 32 - iface_cidr;
	iface_net = ntohl(iface_addr) >> iface_bits;

	list_for_each_entry_safe(lease, tmp, src, list) {
		unsigned addr, net;

		inet_pton(AF_INET, lease->ipaddr, &addr);
		net = ntohl(addr) >> iface_bits;

		if (net == iface_net) {
			list_move_tail(&lease->list, &dhcp->leases);
			dhcp->n_leases += 1;
		}
	}
}

static bool check_dhcp_host_alias_exists(char *dhcp_interface, char *option, char *value)
{
	struct uci_section *s = NULL;
	char *opt_value;

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp", "host", "dhcp", dhcp_interface, s) {

		dmuci_get_value_by_section_string(s, option, &opt_value);

		if (DM_STRCMP(opt_value, value) == 0)
			return true;
	}

	return false;
}

static bool check_dhcp_host_option_exists(char *dhcp_interface, char *option, char *value)
{
	struct uci_section *s = NULL;
	char *opt_value;

	uci_foreach_option_eq("dhcp", "host", "dhcp", dhcp_interface, s) {

		dmuci_get_value_by_section_string(s, option, &opt_value);

		if (DM_STRCMP(opt_value, value) == 0)
			return true;
	}

	return false;
}

static int get_dhcp_iface_range(struct uci_section *dhcp_sec, char *interface, unsigned *iface_addr, unsigned *iface_bits, unsigned *iface_net_start, unsigned *iface_net_end, int *start, int *limit)
{
	char *dhcp_start = NULL, *dhcp_limit = NULL;
	unsigned iface_cidr;

	dmuci_get_value_by_section_string(dhcp_sec, "start", &dhcp_start);
	dmuci_get_value_by_section_string(dhcp_sec, "limit", &dhcp_limit);
	if (!dhcp_start || *dhcp_start == '\0' || !dhcp_limit || *dhcp_limit == '\0')
		return -1;

	if (interface_get_ipv4(interface, iface_addr, &iface_cidr))
		return -1;

	*iface_bits = ~((1 << (32 - iface_cidr)) - 1);
	*iface_net_start = (ntohl(*iface_addr) & *iface_bits) + DM_STRTOL(dhcp_start);
	*iface_net_end = (ntohl(*iface_addr) & *iface_bits) + DM_STRTOL(dhcp_start) + DM_STRTOL(dhcp_limit) - 1;
	*start = DM_STRTOL(dhcp_start);
	*limit = DM_STRTOL(dhcp_limit);

	return 0;
}

static int check_ipv4_in_dhcp_pool(struct uci_section *dhcp_sec, char *interface, char *ip)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end;
	int start = 0, limit = 0;

	if (get_dhcp_iface_range(dhcp_sec, interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
		return -1;

	unsigned addr, net;
	inet_pton(AF_INET, ip, &addr);
	net = ntohl(addr);

	if (net > iface_net_end || net < iface_net_start)
		return -1;

	return 0;
}

static char *get_dhcp_network_from_relay_list(char *net_list)
{
	struct uci_section *s = NULL;
	size_t length = 0;

	if (!net_list || *net_list == 0)
		return "";

	char **net_list_arr = strsplit(net_list, " ", &length);
	uci_foreach_sections("network", "interface", s) {
		char *proto = NULL;

		dmuci_get_value_by_section_string(s, "proto", &proto);
		for (int i = 0; i < length; i++) {
			if (strcmp(net_list_arr[i], section_name(s)) == 0 && DM_LSTRCMP(proto, "dhcp") == 0)
				return net_list_arr[i];
		}
	}

	return "";
}

static struct uci_section *get_dhcp_classifier(char *classifier_name, char *network)
{
	struct uci_section* s = NULL;
	char *networkid;

	uci_foreach_sections("dhcp", classifier_name, s) {
		dmuci_get_value_by_section_string(s, "networkid", &networkid);
		if (DM_STRCMP(networkid, network) == 0)
			return s;
	}

	return NULL;
}

bool tag_option_exists(char *dmmap_package, char *section, char *opt_check, char *value_check, char *tag_name, char *tag_value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section, opt_check, value_check, s) {
		char *curr_tag = NULL;

		dmuci_get_value_by_section_string(s, tag_name, &curr_tag);
		if (curr_tag && tag_value && DM_STRCMP(curr_tag, tag_value) == 0)
			return true;
	}

	return false;
}

char *generate_tag_option(char *dmmap_package, char *section, char *opt_check, char *value_check, char *tag_name)
{
	char *option_tag = "0";
	int i;

	for (i = 1; i <= 254; i++) {

		char tag_value[16] = {0};
		snprintf(tag_value, sizeof(tag_value), "%d", i);

		if (tag_option_exists(dmmap_package, section, opt_check, value_check, tag_name, tag_value))
			continue;

		return dmstrdup(tag_value);
	}

	return option_tag;
}

static int get_DHCPv4ServerPool_Option_Value(struct uci_section *s, const char *option, char **value)
{
	struct uci_list *dhcp_option = NULL;
	struct uci_element *e = NULL;

	dmuci_get_value_by_section_list(s, "dhcp_option", &dhcp_option);
	if (dhcp_option == NULL)
		return -1;

	uci_foreach_element(dhcp_option, e) {
		char *pch = DM_STRCHR(e->name, ',');
		if (pch) {
			char opt_tag[8] = {0};
			unsigned int len = pch - e->name + 1;
			unsigned int opt_size = (len > sizeof(opt_tag)) ? sizeof(opt_tag) : len;

			DM_STRNCPY(opt_tag, e->name, opt_size);
			if (DM_STRCMP(opt_tag, option) == 0) {
				*value = dmstrdup(pch + 1);
				return 0;
			}
		}
	}
	return -1;
}

static int set_DHCPv4ServerPool_Option_Value(struct uci_section *s, const char *option, char *value)
{
	struct uci_list *dhcp_option = NULL;
	char new_dhcp_option[256] = {0};

	if (option == NULL || value == NULL)
		return 0;

	dmuci_get_value_by_section_list(s, "dhcp_option", &dhcp_option);
	if (dhcp_option) {
		struct uci_element *e = NULL, *tmp = NULL;

		uci_foreach_element_safe(dhcp_option, tmp, e) {
			char *pch = DM_STRCHR(e->name, ',');
			if (pch) {
				char opt_tag[8] = {0};
				unsigned int len = pch - e->name + 1;
				unsigned int opt_size = (len > sizeof(opt_tag)) ? sizeof(opt_tag) : len;

				DM_STRNCPY(opt_tag, e->name, opt_size);
				if (DM_STRCMP(opt_tag, option) == 0) {
					dmuci_del_list_value_by_section(s, "dhcp_option", e->name);
					break;
				}
			}
		}
	}

	snprintf(new_dhcp_option, sizeof(new_dhcp_option), "%s,%s", option, value);
	dmuci_add_list_value_by_section(s, "dhcp_option", new_dhcp_option);
	return 0;
}

static char *get_dhcp_option_name(int tag)
{
	switch(tag) {
		case DHCP_OPTION_VENDORID:
			return "vendorid";
		case DHCP_OPTION_CLIENTID:
			return "clientid";
		case DHCP_OPTION_HOSTNAME:
			return "hostname";
		default:
			return "sendopts";
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.DHCPv4.Server.Pool.{i}.!UCI:dhcp/dhcp/dmmap_dhcp*/
static int browseDHCPv4ServerPoolInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ignore = NULL, *interface, *inst = NULL, *v, *instance;
	struct dhcp_args curr_dhcp_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(leases);
	LIST_HEAD(dup_list);

	char *relay_sec = get_dnsmasq_section_name();

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_dhcp", &dup_list);

	if (!list_empty(&dup_list))
		dhcp_leases_load(&leases);

	list_for_each_entry(p, &dup_list, list) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(p->config_section, "ignore", &ignore);
		if (ignore && DM_LSTRCMP(ignore, "1") == 0)
			continue;

		// if dns_relay instance not present, add in the section
		dmuci_get_value_by_section_string(p->config_section, "instance", &instance);
		if (DM_STRLEN(instance) == 0)
			dmuci_set_value_by_section(p->config_section, "instance", relay_sec); 

		dmuci_get_value_by_section_string(p->config_section, "interface", &interface);
		init_dhcp_args(&curr_dhcp_args, p, interface);

		dhcp_leases_assign_to_interface(&curr_dhcp_args, &leases, interface);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "dhcp_instance", "dhcp_alias");

		dmuci_get_value_by_section_string(p->dmmap_section, "order", &v);
		if (v == NULL || DM_STRLEN(v) == 0)
			set_section_order("dhcp", "dmmap_dhcp", "dhcp", p->dmmap_section, p->config_section, 0, inst);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.!UCI:dhcp/host/dmmap_dhcp*/
static int browseDHCPv4ServerPoolStaticAddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL;
	struct dhcp_host_args curr_dhcp_host_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("dhcp", "host", "dmmap_dhcp", "dhcp", ((struct dhcp_args *)prev_data)->interface, &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		// Skip all reserved hosts
		char *host_name = NULL;
		dmuci_get_value_by_section_string(p->config_section, "name", &host_name);
		if (host_name && DM_LSTRCMP(host_name, "reserved") == 0)
			continue;

		dmuci_set_value_by_section(p->dmmap_section, "dhcp", ((struct dhcp_args *)prev_data)->interface);
		init_args_dhcp_host(&curr_dhcp_host_args, (((struct dhcp_args *)prev_data)->sections)->config_section, p, ((struct dhcp_args *)prev_data)->interface);

		inst = handle_instance(dmctx, parent_node, p->dmmap_section, "dhcp_host_instance", "dhcp_host_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_host_args, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseDhcpClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	const struct dhcp_args *dhcp = prev_data;
	const struct dhcp_lease *lease = NULL;
	int id = 0;

	list_for_each_entry(lease, &dhcp->leases, list) {
		struct client_args client_args;
		char *inst;

		init_dhcp_client_args(&client_args, lease);

		inst = handle_instance_without_section(dmctx, parent_node, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&client_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDhcpClientIPv4Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

static int browseDHCPv4ServerPoolClientOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	FILE *f = fopen(DHCP_CLIENT_OPTIONS_FILE, "r");
	if (f == NULL)
		return 0;

	const struct client_args *args = (struct client_args *)prev_data;
	struct client_options_args curr_client_options_args = {0};
	char line[2048], macaddr[24]={0}, vcid[128]={0}, clid[128]={0}, ucid[128]={0}, hostname[128]={0}, paramlist[256]={0};
	char *inst = NULL;
	int id = 0;

	while (fgets(line, sizeof(line), f) != NULL) {
		remove_new_line(line);

		sscanf(line, "%23s vcid=%127s clid=%127s ucid=%127s hostname=%127s paramlist=%255s",
				macaddr, vcid, clid, ucid, hostname, paramlist);

		if (DM_STRNCMP(macaddr, (char *)args->lease->hwaddr, 24) == 0) {

			if (DM_LSTRCMP(vcid, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "60", dmstrdup(vcid));

				inst = handle_instance_without_section(dmctx, parent_node, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}

			if (DM_LSTRCMP(clid, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "61", dmstrdup(clid));

				inst = handle_instance_without_section(dmctx, parent_node, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}


			if (DM_LSTRCMP(ucid, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "77", dmstrdup(ucid));

				inst = handle_instance_without_section(dmctx, parent_node, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}

			if (DM_LSTRCMP(hostname, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "12", dmstrdup(hostname));

				inst = handle_instance_without_section(dmctx, parent_node, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}

			if (DM_LSTRCMP(paramlist, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "55", dmstrdup(paramlist));

				inst = handle_instance_without_section(dmctx, parent_node, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}

			break;
		}
	}
	fclose(f);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.!UCI:network/interface/dmmap_dhcp_client*/
static int browseDHCPv4ClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_client_args curr_dhcp_client_args = {0};
	struct uci_section *s = NULL;
	char *inst = NULL;

	dmmap_synchronizeDHCPv4Client(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap_dhcp_client", "interface", s) {
		struct uci_section *iface_s = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name))
			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

		curr_dhcp_client_args.iface_s = iface_s;
		curr_dhcp_client_args.dmmap_s = s;

		inst = handle_instance(dmctx, parent_node, s, "bbf_dhcpv4client_instance", "bbf_dhcpv4client_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_client_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ClientSentOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *dhcp_client_s = ((struct dhcp_client_args *)prev_data)->iface_s;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};
	struct uci_section *dhcp_client_dmmap_s = NULL;
	char *dhcp_client_key = NULL;
	char *inst = NULL;

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)prev_data)->dmmap_s, "dhcp_client_key", &dhcp_client_key);

	if (dhcp_client_s) {
		size_t length = 0, length2 = 0;
		char **sentopts = NULL;
		char **buf = NULL;
		char *vendorid = NULL;
		char *clientid = NULL;
		char *hostname = NULL;
		char *options = NULL;

		// vendorid option
		dmuci_get_value_by_section_string(dhcp_client_s, "vendorid", &vendorid);
		if (vendorid && *vendorid != '\0') {
			if ((dhcp_client_dmmap_s = get_section_in_dmmap_with_options_eq("dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, "option_tag", "60")) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dhcp_client_dmmap_s);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_tag", "60");
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "dhcp_client_key", dhcp_client_key);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "enable", "1");
			}
			dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_value", vendorid);
		}

		// clienid option
		dmuci_get_value_by_section_string(dhcp_client_s, "clientid", &clientid);
		if (clientid && *clientid != '\0') {
			if ((dhcp_client_dmmap_s = get_section_in_dmmap_with_options_eq("dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, "option_tag", "61")) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dhcp_client_dmmap_s);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_tag", "61");
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "dhcp_client_key", dhcp_client_key);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "enable", "1");
			}
			dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_value", clientid);
		}

		// hostname option
		dmuci_get_value_by_section_string(dhcp_client_s, "hostname", &hostname);
		if (hostname && *hostname != '\0') {
			if ((dhcp_client_dmmap_s = get_section_in_dmmap_with_options_eq("dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, "option_tag", "12")) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dhcp_client_dmmap_s);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_tag", "12");
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "dhcp_client_key", dhcp_client_key);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "enable", "1");
			}
			dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_value", hostname);
		}

		// sendopts option
		dmuci_get_value_by_section_string(dhcp_client_s, "sendopts", &options);

		if (options && *options)
			sentopts = strsplit(options, " ", &length);

		for (int i = 0; i < length; i++) {
			if (sentopts && sentopts[i])
				buf = strsplit(sentopts[i], ":", &length2);

			if ((dhcp_client_dmmap_s = get_section_in_dmmap_with_options_eq("dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, "option_tag", buf[0])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dhcp_client_dmmap_s);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_tag", buf[0]);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "dhcp_client_key", dhcp_client_key);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "enable", "1");
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_value", length2 > 1 ? buf[1] : "");
			}
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, dhcp_client_dmmap_s) {
		char *option_tag = NULL;
		char *option_value = NULL;

		dmuci_get_value_by_section_string(dhcp_client_dmmap_s, "option_tag", &option_tag);
		dmuci_get_value_by_section_string(dhcp_client_dmmap_s, "option_value", &option_value);

		dhcp_client_opt_args.client_sect = dhcp_client_s;
		dhcp_client_opt_args.dmmap_sect = dhcp_client_dmmap_s;
		dhcp_client_opt_args.option_tag = option_tag;
		dhcp_client_opt_args.value = option_value;

		inst = handle_instance(dmctx, parent_node, dhcp_client_dmmap_s, "bbf_dhcpv4_sentopt_instance", "bbf_dhcpv4_sentopt_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ClientReqOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *dhcp_client_s = ((struct dhcp_client_args *)prev_data)->iface_s;
	struct uci_section *dhcp_client_dmmap_s = NULL;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};
	char *dhcp_client_key = NULL;
	char *inst = NULL;

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)prev_data)->dmmap_s, "dhcp_client_key", &dhcp_client_key);

	if (dhcp_client_s) {
		char **reqtopts = NULL;
		char *options = NULL;
		size_t length = 0;

		dmuci_get_value_by_section_string(dhcp_client_s, "reqopts", &options);

		if (options && *options)
			reqtopts = strsplit(options, " ", &length);

		for (int i = 0; i < length; i++) {
			if (reqtopts == NULL)
				continue;

			if ((dhcp_client_dmmap_s = get_section_in_dmmap_with_options_eq("dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, "option_tag", reqtopts[i])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp_client", "req_option", &dhcp_client_dmmap_s);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "option_tag", reqtopts[i]);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "dhcp_client_key", dhcp_client_key);
				dmuci_set_value_by_section_bbfdm(dhcp_client_dmmap_s, "enable", "1");
			}
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, dhcp_client_dmmap_s) {
		char *option_tag = NULL;

		dmuci_get_value_by_section_string(dhcp_client_dmmap_s, "option_tag", &option_tag);

		dhcp_client_opt_args.client_sect = dhcp_client_s;
		dhcp_client_opt_args.dmmap_sect = dhcp_client_dmmap_s;
		dhcp_client_opt_args.option_tag = option_tag;
		dhcp_client_opt_args.value = "";

		inst = handle_instance(dmctx, parent_node, dhcp_client_dmmap_s, "bbf_dhcpv4_reqtopt_instance", "bbf_dhcpv4_reqtopt_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ServerPoolOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_args *curr_dhcp_args = (struct dhcp_args *)prev_data;
	struct uci_list *dhcp_options_list = NULL;
	struct uci_section *dmmap_sect = NULL;
	char *inst = NULL, *dhcpv4_tag, *dhcpv4_value;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};

	dmuci_get_value_by_section_list(curr_dhcp_args->sections->config_section, "dhcp_option", &dhcp_options_list);

	if (dhcp_options_list != NULL) {
		struct uci_element *e = NULL;

		uci_foreach_element(dhcp_options_list, e) {
			char buf[512] = {0};

			snprintf(buf, sizeof(buf), "%s", e->name);
			char *p = strchr(buf, ',');
			if (p)
				*p = 0;

			if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp", "servpool_option", section_name(curr_dhcp_args->sections->config_section), "option_tag", buf)) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp", "servpool_option", &dmmap_sect);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", buf);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(curr_dhcp_args->sections->config_section));
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_value", p ? p + 1 : "");
			}
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp", "servpool_option", "section_name", section_name(curr_dhcp_args->sections->config_section), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &dhcpv4_tag);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &dhcpv4_value);

		dhcp_client_opt_args.client_sect = curr_dhcp_args->sections->config_section;
		dhcp_client_opt_args.dmmap_sect = dmmap_sect;
		dhcp_client_opt_args.option_tag = dhcpv4_tag;
		dhcp_client_opt_args.value = dhcpv4_value;

		inst = handle_instance(dmctx, parent_node, dmmap_sect, "bbf_dhcpv4_servpool_option_instance", "bbf_dhcpv4_servpool_option_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.!UCI:network/interface/dmmap_dhcp_relay*/
static int browseDHCPv4RelayForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_client_args curr_dhcp_relay_args = {0};
	struct uci_section *dmmap_s = NULL;
	char *inst = NULL;

	dmmap_synchronizeDHCPv4RelayForwarding(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_sections(bbfdm, "dmmap_dhcp_relay", "interface", dmmap_s) {
		struct uci_section *iface_s = NULL;
		char *iface_name = NULL;

		dmuci_get_value_by_section_string(dmmap_s, "iface_name", &iface_name);
		if (DM_STRLEN(iface_name))
			get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

		curr_dhcp_relay_args.iface_s = iface_s;
		curr_dhcp_relay_args.dmmap_s = dmmap_s;

		inst = handle_instance(dmctx, parent_node, dmmap_s, "bbf_dhcpv4relay_instance", "bbf_dhcpv4relay_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_relay_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjDHCPv4ServerPool(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_dhcp = NULL;
	char dhcp_sname[32] = {0};

	snprintf(dhcp_sname, sizeof(dhcp_sname), "dhcp_%s", *instance);

	dmuci_add_section("dhcp", "dhcp", &s);
	dmuci_rename_section_by_section(s, dhcp_sname);
	dmuci_set_value_by_section(s, "ignore", "0");
	dmuci_set_value_by_section(s, "dhcpv4", "disabled");
	dmuci_set_value_by_section(s, "instance", get_dnsmasq_section_name());
	// Defaults to uci defaults value
	dmuci_set_value_by_section(s, "start", "100");
	dmuci_set_value_by_section(s, "limit", "150");

	dmuci_add_section_bbfdm("dmmap_dhcp", "dhcp", &dmmap_dhcp);
	dmuci_set_value_by_section(dmmap_dhcp, "section_name", dhcp_sname);
	dmuci_set_value_by_section(dmmap_dhcp, "dhcp_instance", *instance);
	return 0;
}

static int delObjDHCPv4ServerPool(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_delete_by_section((((struct dhcp_args *)data)->sections)->config_section, NULL, NULL);
		dmuci_delete_by_section((((struct dhcp_args *)data)->sections)->dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("dhcp", "dhcp", stmp, s) {
			struct uci_section *dmmap_section = NULL;

			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(s), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section(s, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjDHCPv4ServerPoolStaticAddress(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_dhcp_host = NULL;
	char host_name[32];

	snprintf(host_name, sizeof(host_name), "host_%s", *instance);

	dmuci_add_section("dhcp", "host", &s);
	dmuci_rename_section_by_section(s, host_name);
	dmuci_set_value_by_section(s, "name", host_name);
	dmuci_set_value_by_section(s, "dhcp", ((struct dhcp_args *)data)->interface);
	dmuci_set_value_by_section(s, "enable", "0");

	dmuci_add_section_bbfdm("dmmap_dhcp", "host", &dmmap_dhcp_host);
	dmuci_set_value_by_section(dmmap_dhcp_host, "section_name", host_name);
	dmuci_set_value_by_section(dmmap_dhcp_host, "dhcp", ((struct dhcp_args *)data)->interface);
	dmuci_set_value_by_section(dmmap_dhcp_host, "dhcp_host_instance", *instance);
	return 0;
}

static int delObjDHCPv4ServerPoolStaticAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	
	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section((((struct dhcp_host_args *)data)->host_sections)->config_section, NULL, NULL);
			dmuci_delete_by_section((((struct dhcp_host_args *)data)->host_sections)->dmmap_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, stmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(s), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4Client(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_sect = NULL;
	char dhcp_client_key[32] = {0};

	snprintf(dhcp_client_key, sizeof(dhcp_client_key), "dhcp_client_%s", *instance);

	dmuci_add_section_bbfdm("dmmap_dhcp_client", "interface", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "proto", "dhcp");
	dmuci_set_value_by_section(dmmap_sect, "disabled", "1");
	dmuci_set_value_by_section(dmmap_sect, "dhcp_client_key", dhcp_client_key);
	dmuci_set_value_by_section(dmmap_sect, "added_by_controller", "1");
	dmuci_set_value_by_section(dmmap_sect, "bbf_dhcpv4client_instance", *instance);
	return 0;
}

static int delObjDHCPv4Client(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *dhcp_client_key = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dmmap_s, "dhcp_client_key", &dhcp_client_key);

			if (((struct dhcp_client_args *)data)->iface_s) {
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "proto", "none");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "clientid", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "vendorid", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "hostname", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "sendopts", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "reqopts", "");
			}

			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}

			dmuci_delete_by_section(((struct dhcp_client_args *)data)->dmmap_s, NULL, NULL);
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "interface", stmp, s) {
				struct uci_section *ss = NULL, *sstmp = NULL;
				struct uci_section *iface_s = NULL;
				char *iface_name = NULL;

				dmuci_get_value_by_section_string(s, "dhcp_client_key", &dhcp_client_key);
				dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
				if (DM_STRLEN(iface_name))
					get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

				if (iface_s) {
					dmuci_set_value_by_section(iface_s, "proto", "none");
					dmuci_set_value_by_section(s, "clientid", "");
					dmuci_set_value_by_section(s, "vendorid", "");
					dmuci_set_value_by_section(s, "hostname", "");
					dmuci_set_value_by_section(s, "sendopts", "");
					dmuci_set_value_by_section(s, "reqopts", "");
				}

				uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, sstmp, ss) {
					dmuci_delete_by_section(ss, NULL, NULL);
				}

				uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, sstmp, ss) {
					dmuci_delete_by_section(ss, NULL, NULL);
				}

				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ClientSentOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args *)data;
	struct uci_section *dmmap_sect = NULL;
	char *dhcp_client_key = NULL;

	dmuci_get_value_by_section_string(dhcp_client_args->dmmap_s, "dhcp_client_key", &dhcp_client_key);
	char *option_tag = generate_tag_option("dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, "option_tag");

	dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "enable", "0");
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", option_tag);
	dmuci_set_value_by_section(dmmap_sect, "dhcp_client_key", dhcp_client_key);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "bbf_dhcpv4_sentopt_instance", *instance);
	return 0;
}

static int delObjDHCPv4ClientSentOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *dhcp_client_key = NULL;

	switch (del_action) {
		case DEL_INST:
			if (((struct dhcp_client_option_args *)data)->client_sect) {
				char *option_name = get_dhcp_option_name(DM_STRTOL(((struct dhcp_client_option_args *)data)->option_tag));

				if (DM_LSTRCMP(option_name, "sendopts") == 0) {
					char *sendopts = NULL;

					dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &sendopts);
					if (sendopts && *sendopts) {
						char tag_value[128] = {0};

						snprintf(tag_value, sizeof(tag_value), "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
						remove_elt_from_str_list(&sendopts, tag_value);
						dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", sendopts);
					}
				} else {
					dmuci_set_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, option_name, "");
				}
			}

			dmuci_delete_by_section(((struct dhcp_client_option_args *)data)->dmmap_sect, NULL, NULL);
			break;
		case DEL_ALL:
			if (((struct dhcp_client_args *)data)->iface_s) {
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "clientid", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "vendorid", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "hostname", "");
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "sendopts", "");
			}

			dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dmmap_s, "dhcp_client_key", &dhcp_client_key);

			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ClientReqOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args *)data;
	struct uci_section *dmmap_sect = NULL;
	char *dhcp_client_key = NULL;

	dmuci_get_value_by_section_string(dhcp_client_args->dmmap_s, "dhcp_client_key", &dhcp_client_key);
	char *option_tag = generate_tag_option("dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, "option_tag");

	dmuci_add_section_bbfdm("dmmap_dhcp_client", "req_option", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "enable", "0");
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", option_tag);
	dmuci_set_value_by_section(dmmap_sect, "dhcp_client_key", dhcp_client_key);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "bbf_dhcpv4_sentopt_instance", *instance);
	return 0;
}

static int delObjDHCPv4ClientReqOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *dhcp_client_key = NULL;

	switch (del_action) {
		case DEL_INST:
			if (((struct dhcp_client_option_args *)data)->client_sect) {
				char *reqopts = NULL;

				dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &reqopts);
				if (reqopts && *reqopts) {
					remove_elt_from_str_list(&reqopts, ((struct dhcp_client_option_args*) data)->option_tag);
					dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", reqopts);
				}
			}

			dmuci_delete_by_section(((struct dhcp_client_option_args *)data)->dmmap_sect, NULL, NULL);
			break;
		case DEL_ALL:
			if (((struct dhcp_client_args *)data)->iface_s)
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "reqopts", "");

			dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dmmap_s, "dhcp_client_key", &dhcp_client_key);

			uci_path_foreach_option_eq_safe(bbfdm, "dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_args *dhcp_arg = (struct dhcp_args *)data;
	struct uci_section *dmmap_sect = NULL;

	dmuci_add_section_bbfdm("dmmap_dhcp", "servpool_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_arg->sections->config_section));
	char *option_tag = generate_tag_option("dmmap_dhcp", "servpool_option", "section_name", section_name(dhcp_arg->sections->config_section), "option_tag");
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", option_tag);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "bbf_dhcpv4_servpool_option_instance", *instance);
	return 0;
}

static int delObjDHCPv4ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	struct uci_list *dhcp_options_list = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_list(((struct dhcp_client_option_args*) data)->client_sect, "dhcp_option", &dhcp_options_list);
			if (dhcp_options_list != NULL) {
				char tag_value[128] = {0};

				snprintf(tag_value, sizeof(tag_value), "%s,%s", ((struct dhcp_client_option_args*) data)->option_tag, ((struct dhcp_client_option_args*) data)->value);
				dmuci_del_list_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "dhcp_option", tag_value);
			}

			dmuci_delete_by_section(((struct dhcp_client_option_args*) data)->dmmap_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "dhcp_option", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp", "servpool_option", stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4RelayForwarding(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_sect = NULL;

	dmuci_add_section_bbfdm("dmmap_dhcp_relay", "interface", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "proto", "relay");
	dmuci_set_value_by_section(dmmap_sect, "disabled", "1");
	dmuci_set_value_by_section(dmmap_sect, "added_by_controller", "1");
	dmuci_set_value_by_section(dmmap_sect, "bbf_dhcpv4relay_instance", *instance);
	return 0;
}

static int delObjDHCPv4RelayForwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(((struct dhcp_client_args *)data)->dmmap_s, NULL, NULL);

			if (((struct dhcp_client_args *)data)->iface_s)
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->iface_s, "proto", "none");
			break;
		case DEL_ALL:
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_relay", "interface", stmp, s) {
				struct uci_section *iface_s = NULL;
				char *iface_name = NULL;

				dmuci_get_value_by_section_string(s, "iface_name", &iface_name);
				if (DM_STRLEN(iface_name))
					get_config_section_of_dmmap_section("network", "interface", iface_name, &iface_s);

				dmuci_delete_by_section(s, NULL, NULL);

				if (iface_s)
					dmuci_set_value_by_section(iface_s, "proto", "none");
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.DHCPv4.Server.Pool.{i}.Enable!UCI:dhcp/interface,@i-1/dhcpv4*/
static int get_DHCPv4ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcp_args *)data)->sections)->config_section, "dhcpv4", value);
	*value = (*value && DM_LSTRCMP(*value, "disabled") == 0) ? "0" : "1";
	return 0;
}

static int set_DHCPv4ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "dhcpv4", b ? "server" : "disabled");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.Status!UCI:dhcp/interface,@i-1/dhcpv4*/
static int get_DHCPv4ServerPool_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcp_args *)data)->sections)->config_section, "dhcpv4", value);
	*value = (*value && DM_LSTRCMP(*value, "disabled") == 0) ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.Alias!UCI:dmmap_dhcp/dhcp,@i-1/dhcp_alias*/
static int get_DHCPv4ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (((struct dhcp_args *)data)->sections)->dmmap_section, "dhcp_alias", instance, value);
}

static int set_DHCPv4ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, (((struct dhcp_args *)data)->sections)->dmmap_section, "dhcp_alias", instance, value);
}

static int get_DHCPv4ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcp_args *)data)->sections)->dmmap_section, "order", value);
	return 0;
}

static int set_DHCPv4ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			set_section_order("dhcp", "dmmap_dhcp", "dhcp", (((struct dhcp_args *)data)->sections)->dmmap_section, (((struct dhcp_args *)data)->sections)->config_section, 1, value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmstrdup(((struct dhcp_args *)data)->interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_DHCPv4ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "interface", linker ? linker : "");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.alloweddevices!UCI:dhcp/interface,@i-1/allowed_devices*/
static int get_DHCPv4ServerPool_AllowedDevices(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *allowed_dev = NULL;

	*value = "All";

	dmuci_get_value_by_section_string((((struct dhcp_args *)data)->sections)->config_section, "allowed_devices", &allowed_dev);
	if (DM_STRLEN(allowed_dev)) {
		if (strcasecmp(allowed_dev, "known") == 0)
			*value = "Known";
		else if(strcasecmp(allowed_dev, "unknown") == 0)
			*value = "UnKnown";
	}

	return 0;
}

static int set_DHCPv4ServerPool_AllowedDevices(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *allowed_dev = "";

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, -1, allowed_devices, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcasecmp(value, "Known") == 0)
				allowed_dev = "known";
			else if(strcasecmp(value, "UnKnown") == 0)
				allowed_dev = "unknown";
			else
				allowed_dev = "all";

			dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "allowed_devices", allowed_dev);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.MinAddress!UCI:dhcp/interface,@i-1/start*/
static int get_DHCPv4ServerPool_MinAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end;
	int start = 0, limit = 0;
	char addr_min[32] = {0};

	if (get_dhcp_iface_range((((struct dhcp_args *)data)->sections)->config_section, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit)) {
		*value = "";
		return 0;
	}

	unsigned iface_start_addr = htonl((ntohl(iface_addr) & iface_bits) + start);
	inet_ntop(AF_INET, &iface_start_addr, addr_min, INET_ADDRSTRLEN);

	*value = dmstrdup(addr_min);
	return 0;
}

static int set_DHCPv4ServerPool_MinAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end, value_addr;
	int start = 0, limit = 0;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			break;
		case VALUESET:
			if (get_dhcp_iface_range((((struct dhcp_args *)data)->sections)->config_section, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
				return -1;

			unsigned iface_net = ntohl(iface_addr) & iface_bits;

			inet_pton(AF_INET, value, &value_addr);
			unsigned value_net = ntohl(value_addr) & iface_bits;

			if (value_net == iface_net) {
				char buf[32] = {0};

				unsigned dhcp_start = ntohl(value_addr) - iface_net;
				int dhcp_limit = start + limit - dhcp_start;

				// check if MinAddress > MaxAddress
				if (dhcp_limit < 0)
					return -1;

				snprintf(buf, sizeof(buf), "%u", dhcp_start);
				dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "start", buf);

				snprintf(buf, sizeof(buf), "%d", dhcp_limit);
				dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "limit", buf);

			}

			break;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.MaxAddress!UCI:dhcp/interface,@i-1/limit*/
static int get_DHCPv4ServerPool_MaxAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end;
	int start = 0, limit = 0;
	char addr_max[32] = {0};

	if (get_dhcp_iface_range((((struct dhcp_args *)data)->sections)->config_section, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit)) {
		*value = "";
		return 0;
	}

	unsigned iface_end_addr = htonl((ntohl(iface_addr) & iface_bits) + start + limit - 1);
	inet_ntop(AF_INET, &iface_end_addr, addr_max, INET_ADDRSTRLEN);

	*value = dmstrdup(addr_max);
	return 0;
}

static int set_DHCPv4ServerPool_MaxAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end, value_addr;
	int start = 0, limit = 0;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (get_dhcp_iface_range((((struct dhcp_args *)data)->sections)->config_section, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
				return -1;

			unsigned iface_net = ntohl(iface_addr) & iface_bits;

			inet_pton(AF_INET, value, &value_addr);
			unsigned value_net = ntohl(value_addr) & iface_bits;

			if (value_net == iface_net) {
				char buf_limit[32] = {0};

				unsigned dhcp_limit = ntohl(value_addr) - iface_net - start + 1;

				// check if MaxAddress < MinAddress
				if ((int)dhcp_limit < 0)
					return -1;

				snprintf(buf_limit, sizeof(buf_limit), "%u", dhcp_limit);
				dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "limit", buf_limit);

			}

			break;
	}
	return 0;
}

static int get_DHCPv4ServerPool_ReservedAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end, addr, pos = 0;
	int start = 0, limit = 0;
	char list_val[512];
	struct uci_section *s = NULL;

	if (get_dhcp_iface_range((((struct dhcp_args *)data)->sections)->config_section, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit)) {
		*value = "";
		return 0;
	}

	list_val[0] = 0;
	uci_foreach_option_eq("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, s) {

		char *host_name = NULL;
		dmuci_get_value_by_section_string(s, "name", &host_name);
		if (host_name && DM_LSTRCMP(host_name, "reserved") != 0)
			continue;

		char *ip = NULL;
		dmuci_get_value_by_section_string(s, "ip", &ip);
		if (ip && ip[0] == '\0')
			continue;

		inet_pton(AF_INET, ip, &addr);
		unsigned net = ntohl(addr);

		if (net >= iface_net_start && net <= iface_net_end)
			pos += snprintf(&list_val[pos], sizeof(list_val) - pos, "%s,", ip);
	}

	/* cut tailing ',' */
	if (pos)
		list_val[pos - 1] = 0;

	*value = dmstrdup(list_val);
	return 0;
}

static int set_DHCPv4ServerPool_ReservedAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *local_value, *pch, *spch = NULL;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, 32, -1, -1, 15, NULL, IPv4Address))
				return FAULT_9007;

			local_value = dmstrdup(value);
			for (pch = strtok_r(local_value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

				// Check if ip address is out dhcp pool
				if (check_ipv4_in_dhcp_pool((((struct dhcp_args *)data)->sections)->config_section, ((struct dhcp_args *)data)->interface, pch)) {
					dmfree(local_value);
					return FAULT_9007;
				}
			}
			dmfree(local_value);

			return 0;
		case VALUESET:
			uci_foreach_option_eq_safe("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, stmp, s) {

				char *host_name = NULL;
				dmuci_get_value_by_section_string(s, "name", &host_name);
				if (host_name && DM_LSTRCMP(host_name, "reserved") != 0)
					continue;

				char *ip = NULL;
				dmuci_get_value_by_section_string(s, "ip", &ip);
				if (ip == NULL || *ip == '\0')
					continue;

				// Check if ip exists in the list value : yes -> skip it else delete it
				if (!DM_STRSTR(value, ip))
					dmuci_delete_by_section(s, NULL, NULL);
			}

			local_value = dmstrdup(value);
			for (pch = strtok_r(local_value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

				// Check if host exists
				bool host_exist = check_dhcp_host_option_exists(((struct dhcp_args *)data)->interface, "ip", pch);

				// host exists -> skip it
				if (host_exist)
					continue;

				// host doesn't exist -> create an new one
				struct uci_section *dhcp_host_section = NULL;
				dmuci_add_section("dhcp", "host", &dhcp_host_section);
				dmuci_set_value_by_section(dhcp_host_section, "name", "reserved");
				dmuci_set_value_by_section(dhcp_host_section, "dhcp", ((struct dhcp_args *)data)->interface);
				dmuci_set_value_by_section(dhcp_host_section, "ip", pch);
			}
			dmfree(local_value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.SubnetMask!UCI:dhcp/interface,@i-1/netmask*/
static int get_DHCPv4ServerPool_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "netmask", value);
	if ((*value)[0] == '\0') {
		unsigned iface_addr, iface_cidr;

		if (interface_get_ipv4(((struct dhcp_args *)data)->interface, &iface_addr, &iface_cidr))
			return -1;

		*value = dmstrdup(cidr2netmask(iface_cidr));
	}
	return 0;
}

static int set_DHCPv4ServerPool_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("network", ((struct dhcp_args *)data)->interface, "netmask", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.DNSServers!UBUS:network.interface/status/interface,@Name/dns-server*/
static int get_DHCPv4ServerPool_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (!get_DHCPv4ServerPool_Option_Value((((struct dhcp_args *)data)->sections)->config_section, "6", value))
		return 0;

	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", value);
	return 0;
}

static int set_DHCPv4ServerPool_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, 4, -1, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			set_DHCPv4ServerPool_Option_Value((((struct dhcp_args *)data)->sections)->config_section, "6", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv4ServerPool_DomainName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_DHCPv4ServerPool_Option_Value((((struct dhcp_args *)data)->sections)->config_section, "15", value);
	return 0;
}

static int set_DHCPv4ServerPool_DomainName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			set_DHCPv4ServerPool_Option_Value((((struct dhcp_args *)data)->sections)->config_section, "15", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv4ServerPool_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (!get_DHCPv4ServerPool_Option_Value((((struct dhcp_args *)data)->sections)->config_section, "3", value))
		return 0;

	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", value);
	return 0;
}

static int set_DHCPv4ServerPool_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_string_list(ctx, value, -1, 4, -1, -1, 15, NULL, IPv4Address))
				return FAULT_9007;
			return 0;
		case VALUESET:
			set_DHCPv4ServerPool_Option_Value((((struct dhcp_args *)data)->sections)->config_section, "3", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.LeaseTime!UCI:dhcp/interface,@i-1/leasetime*/
static int get_DHCPv4ServerPool_LeaseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ltime = NULL, *pch = NULL, *pchr = NULL;
	int leasetime = 0;

	*value = "-1";
	dmuci_get_value_by_section_string((((struct dhcp_args *)data)->sections)->config_section, "leasetime", &ltime);
	if (ltime == NULL || *ltime == '\0')
		return 0;

	if (DM_STRCHR(ltime, 'd')) {
		pch = strtok_r(ltime, "d", &pchr);
		leasetime = DM_STRTOL(pch) * 24 * 3600;
	} else if (DM_STRCHR(ltime, 'h')) {
		pch = strtok_r(ltime, "h", &pchr);
		leasetime = DM_STRTOL(pch) * 3600;
	} else if (DM_STRCHR(ltime, 'm')) {
		pch = strtok_r(ltime, "m", &pchr);
		leasetime = DM_STRTOL(pch) * 60;
	} else {
		pch = strtok_r(ltime, "s", &pchr);
		leasetime = DM_STRTOL(pch);
	}

	dmasprintf(value, "%d", leasetime);
	return 0;
}

static int set_DHCPv4ServerPool_LeaseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int leasetime;
	char buf[32];

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_int(ctx, value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			leasetime = DM_STRTOL(value);
			if (leasetime == -1)
				buf[0] = '\0';
			else
				snprintf(buf, sizeof(buf), "%ds", leasetime);

			dmuci_set_value_by_section((((struct dhcp_args *)data)->sections)->config_section, "leasetime", buf);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddressNumberOfEntries!UCI:dhcp/host/*/
static int get_DHCPv4ServerPool_StaticAddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ServerPoolStaticAddressInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv4ServerPool_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ServerPoolOptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv4ServerPool_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct dhcp_args *dhcp = data;

	dmasprintf(value, "%u", dhcp->n_leases);
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Enable!UCI:dhcp/host,@i-1/enable*/
static int get_DHCPv4ServerPoolStaticAddress_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((((struct dhcp_host_args *)data)->host_sections)->config_section, "enable", "1");
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((((struct dhcp_host_args *)data)->host_sections)->config_section, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Alias!UCI:dmmap_dhcp/host,@i-1/dhcp_host_alias*/
static int get_DHCPv4ServerPoolStaticAddress_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, (((struct dhcp_host_args *)data)->host_sections)->dmmap_section, "dhcp_host_alias", instance, value);
}

static int set_DHCPv4ServerPoolStaticAddress_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *curr_alias = NULL, *alias_assigned = NULL;

	switch (action) {
		case VALUECHECK:
			// Validate value string -> length
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;

			// Check if alias is assigned by user
			dmuci_get_value_by_section_string((((struct dhcp_host_args *)data)->host_sections)->dmmap_section, "dhcp_host_alias_assigned", &alias_assigned);
			if (alias_assigned && DM_LSTRCMP(alias_assigned, "1") == 0)
				return FAULT_9007;

			// Check if alias exists
			dmuci_get_value_by_section_string((((struct dhcp_host_args *)data)->host_sections)->dmmap_section, "dhcp_host_alias", &curr_alias);
			if (DM_STRCMP(curr_alias, value) != 0 && check_dhcp_host_alias_exists(((struct dhcp_host_args *)data)->dhcp_interface, "dhcp_host_alias", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct dhcp_host_args *)data)->host_sections)->dmmap_section, "dhcp_host_alias", value);
			dmuci_set_value_by_section((((struct dhcp_host_args *)data)->host_sections)->dmmap_section, "dhcp_host_alias_assigned", "1");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Chaddr!UCI:dhcp/host,@i-1/mac*/
static int get_DHCPv4ServerPoolStaticAddress_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcp_host_args *)data)->host_sections)->config_section, "mac", value);
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *curr_mac = NULL;

	switch (action) {
		case VALUECHECK:
			// Validate value string -> MAC Address
			if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
				return FAULT_9007;

			// Check if mac exists
			dmuci_get_value_by_section_string((((struct dhcp_host_args *)data)->host_sections)->config_section, "mac", &curr_mac);
			if (DM_STRCMP(curr_mac, value) != 0 && check_dhcp_host_option_exists(((struct dhcp_host_args *)data)->dhcp_interface, "mac", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct dhcp_host_args *)data)->host_sections)->config_section, "mac", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Yiaddr!UCI:dhcp/host,@i-1/ip*/
static int get_DHCPv4ServerPoolStaticAddress_Yiaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((((struct dhcp_host_args *)data)->host_sections)->config_section, "ip", value);
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Yiaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_host_args *host_args = (struct dhcp_host_args *)data;
	char *curr_ip = NULL;

	switch (action) {
		case VALUECHECK:
			// Validate value string -> IPv4 Address
			if (bbfdm_validate_string(ctx, value, -1, 15, NULL, IPv4Address))
				return FAULT_9007;

			// Check if ip address is out dhcp pool
			if (check_ipv4_in_dhcp_pool(host_args->dhcp_sec, host_args->dhcp_interface, value))
				return FAULT_9007;

			// Check if ip exists
			dmuci_get_value_by_section_string((((struct dhcp_host_args *)data)->host_sections)->config_section, "ip", &curr_ip);
			if (DM_STRCMP(curr_ip, value) != 0 && check_dhcp_host_option_exists(host_args->dhcp_interface, "ip", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section((((struct dhcp_host_args *)data)->host_sections)->config_section, "ip", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv4ServerPoolClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;
	struct uci_section *s = NULL;

	char *hwaddr = (char *)args->lease->hwaddr;
	uci_path_foreach_sections(bbfdm, "dmmap", "dhcpv4clients", s) {
		char *macaddr;
		dmuci_get_value_by_section_string(s, "macaddr", &macaddr);
		if (DM_STRCMP(hwaddr, macaddr) == 0) {
			dmuci_get_value_by_section_string(s, "alias", value);
			break;
		}
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ServerPoolClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	const struct client_args *args = data;
	struct uci_section *s = NULL, *dmmap = NULL;
	char *macaddr;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 64, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			macaddr = (char *)args->lease->hwaddr;
			uci_path_foreach_option_eq(bbfdm, "dmmap", "dhcpv4clients", "macaddr", macaddr, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "dhcpv4clients", &dmmap);
			dmuci_set_value_by_section(dmmap, "macaddr", macaddr);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolClient_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	*value = (char *)args->lease->hwaddr;
	return 0;
}

static int get_DHCPv4ServerPoolClient_Active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int get_DHCPv4ServerPoolClient_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_DHCPv4ServerPoolClient_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ServerPoolClientOptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv4ServerPoolClientIPv4Address_LeaseTimeRemaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	return dm_time_utc_format(args->lease->ts, value);
}

static int get_DHCPv4ServerPoolClientIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	*value = (char *)args->lease->ipaddr;
	return 0;
}

static int get_DHCPv4ServerPoolClientOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct client_options_args *)data)->tag;
	return 0;
}

static int get_DHCPv4ServerPoolClientOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_option = ((struct client_options_args *)data)->tag;
	const char *tag_value = ((struct client_options_args *)data)->value;
	char hex[256] = {0};

	if (DM_STRLEN(tag_option) && DM_STRLEN(tag_value))
		convert_str_option_to_hex(DM_STRTOL(tag_option), tag_value, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int get_DHCPv4_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ClientInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcp_client_args *dhcpv4_client = (struct dhcp_client_args *)data;
	char *disabled = NULL;

	dmuci_get_value_by_section_string(dhcpv4_client->iface_s ? dhcpv4_client->iface_s : dhcpv4_client->dmmap_s, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "0" : "1";
	return 0;
}

static int set_DHCPv4Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_args *dhcpv4_client = (struct dhcp_client_args *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;

			if (dhcpv4_client->iface_s) {
				struct uci_section *dmmap_s = NULL;
				char *ip_inst = NULL;

				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(dhcpv4_client->iface_s), &dmmap_s);
				dmuci_get_value_by_section_string(dmmap_s, "ip_int_instance", &ip_inst);
				if (DM_STRLEN(ip_inst))
					return FAULT_9007;
			}

			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(dhcpv4_client->dmmap_s, "disabled", b ? "0" : "1");
			if (dhcpv4_client->iface_s)
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

static int get_DHCPv4Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dhcp_client_args *)data)->dmmap_s, "bbf_dhcpv4client_alias", instance, value);
}

static int set_DHCPv4Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dhcp_client_args *)data)->dmmap_s, "bbf_dhcpv4client_alias", instance, value);
}

static int get_DHCPv4Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcp_client_args *dhcpv4_client = (struct dhcp_client_args *)data;
	char *iface_name = NULL;

	dmuci_get_value_by_section_string(dhcpv4_client->dmmap_s, "iface_name", &iface_name);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", iface_name, value);

	if (DM_STRLEN(*value) == 0 && dhcpv4_client->iface_s) {
		struct uci_section *s = NULL;
		char *device = NULL;

		dmuci_get_value_by_section_string(dhcpv4_client->iface_s, "device", &device);
		if (DM_STRLEN(device) == 0)
			return 0;

		uci_foreach_option_eq("network", "interface", "device", device, s) {
			adm_entry_get_linker_param(ctx, "Device.IP.Interface.", section_name(s), value);
			if (DM_STRLEN(*value))
				return 0;
		}
	}
	return 0;
}

static int set_DHCPv4Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_args *dhcpv4_client = (struct dhcp_client_args *)data;
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	char *dhcp_client_key = NULL;
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			// Get linker
			adm_entry_get_linker_value(ctx, value, &linker);

			if (dhcpv4_client->iface_s) {
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "proto", "none");
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "clientid", "");
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "vendorid", "");
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "hostname", "");
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "sendopts", "");
				dmuci_set_value_by_section(dhcpv4_client->iface_s, "reqopts", "");
			}

			if (!linker || *linker == 0) {
				dmuci_set_value_by_section_bbfdm(dhcpv4_client->dmmap_s, "iface_name", "");
			} else {
				struct uci_section *interface_s = NULL;

				get_config_section_of_dmmap_section("network", "interface", linker, &interface_s);
				if (interface_s == NULL)
					return FAULT_9007;

				// Update proto option of config section
				dmuci_set_value_by_section(interface_s, "proto", "dhcp");

				// Update dmmap section
				dmuci_set_value_by_section_bbfdm(dhcpv4_client->dmmap_s, "iface_name", linker);

				dmuci_get_value_by_section_string(dhcpv4_client->dmmap_s, "dhcp_client_key", &dhcp_client_key);
				if (DM_STRLEN(dhcp_client_key)) {
					struct uci_section *option_s = NULL;
					char buf[128] = {0};
					unsigned pos = 0;

					// Added the enabled options for sendopts
					uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, option_s) {
						char *enable = NULL;


						dmuci_get_value_by_section_string(option_s, "enable", &enable);
						if (DM_LSTRCMP(enable, "1") == 0) {
							char *opt_tag = NULL;
							char *opt_value = NULL;

							dmuci_get_value_by_section_string(option_s, "option_tag", &opt_tag);
							dmuci_get_value_by_section_string(option_s, "option_value", &opt_value);
							pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s:%s ", opt_tag, opt_value);
						}
					}

					if (pos) {
						buf[pos - 1] = 0;
						dmuci_set_value_by_section(interface_s, "sendopts", buf);
					}

					// Added the enabled options for reqopts
					pos = 0;
					uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, option_s) {
						char *enable = NULL;

						dmuci_get_value_by_section_string(option_s, "enable", &enable);
						if (DM_LSTRCMP(enable, "1") == 0) {
							char *opt_tag = NULL;

							dmuci_get_value_by_section_string(option_s, "option_tag", &opt_tag);
							pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s ", opt_tag);
						}
					}

					if (pos) {
						buf[pos - 1] = 0;
						dmuci_set_value_by_section(interface_s, "reqopts", buf);
					}
				}
			}
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Client.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4Client_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_DHCPv4Client_Enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

/*#Device.DHCPv4.Client.{i}.DHCPStatus!UBUS:network.interface/status/interface,@Name/ipv4-address[@i-1].address*/
static int get_DHCPv4Client_DHCPStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcpv4_s) {
		json_object *res = NULL;

		char *if_name = section_name(dhcpv4_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "Requesting");
		json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		char *ipaddr = dmjson_get_value(jobj, 1, "address");
		*value = (ipaddr[0] == '\0') ? "Requesting" : "Bound";
	} else {
		*value = "Requesting";
	}
	return 0;
}

static int get_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (!b) break;
			if (dhcpv4_s) {
				char *if_name = section_name(dhcpv4_s);
				dmubus_call_set("network.interface", "renew", UBUS_ARGS{{"interface", if_name, String}}, 1);
			}
			break;
	}
	return 0;
}

static int get_DHCPv4Client_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;
	char *ipaddr = "";

	if (dhcpv4_s) {

		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->iface_s, "ipaddr", &ipaddr);
		if (!ipaddr || *ipaddr == 0) {
			json_object *res = NULL;

			char *if_name = section_name(dhcpv4_s);
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
			if (res) {
				json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
				ipaddr = dmjson_get_value(jobj, 1, "address");
			}
		}
	}

	*value = ipaddr;
	return 0;
}

static int get_DHCPv4Client_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;
	char *mask = "";

	if (dhcpv4_s) {

		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->iface_s, "netmask", &mask);
		if (!mask || *mask == 0) {
			json_object *res = NULL;

			char *if_name = section_name(dhcpv4_s);
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
			if (res) {
				json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
				mask = dmjson_get_value(jobj, 1, "mask");
				mask = (mask && *mask) ? cidr2netmask(DM_STRTOL(mask)) : "";
			}
		}
	}

	*value = mask;
	return 0;
}

/*#Device.DHCPv4.Client.{i}.IPRouters!UBUS:network.interface/status/interface,@Name/route[@i-1].nexthop*/
static int get_DHCPv4Client_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcpv4_s) {
		json_object *res = NULL, *route = NULL, *arrobj = NULL;
		unsigned pos = 0, idx = 0;
		char list_ip[256] = {0};

		char *if_name = section_name(dhcpv4_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");

		list_ip[0] = 0;
		dmjson_foreach_obj_in_array(res, arrobj, route, idx, 1, "route") {
			char *nexthop = dmjson_get_value(route, 1, "nexthop");
			pos += snprintf(&list_ip[pos], sizeof(list_ip) - pos, "%s,", nexthop);
		}

		/* cut tailing ',' */
		if (pos)
			list_ip[pos - 1] = 0;

		*value = dmstrdup(list_ip);
	}
	return 0;
}

/*#Device.DHCPv4.Client.{i}.DNSServers!UBUS:network.interface/status/interface,@Name/dns-server*/
static int get_DHCPv4Client_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcpv4_s) {
		json_object *res = NULL;

		char *if_name = section_name(dhcpv4_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		*value = dmjson_get_value_array_all(res, ",", 1, "dns-server");
	}
	return 0;
}

/*#Device.DHCPv4.Client.{i}.LeaseTimeRemaining!UBUS:network.interface/status/interface,@Name/data.leasetime*/
static int get_DHCPv4Client_LeaseTimeRemaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcpv4_s) {
		json_object *res = NULL;

		char *if_name = section_name(dhcpv4_s);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", if_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "0");
		char *lease_time = dmjson_get_value(res, 2, "data", "leasetime");
		char *uptime_str = dmjson_get_value(res, 2, "data", "uptime");

		if (!DM_STRLEN(uptime_str) || !DM_STRLEN(lease_time) || DM_STRTOL(lease_time) == 0xFFFFFFFF) {
			*value = "-1";
			return 0;
		}

		char *uptime = get_uptime();
		dmasprintf(value, "%ld", DM_STRTOL(lease_time) - (DM_STRTOL(uptime) -  DM_STRTOL(uptime_str)));
	}
	return 0;
}

/*#Device.DHCPv4.Client.{i}.SentOptionNumberOfEntries!UCI:network/interface,@i-1/sendopts*/
static int get_DHCPv4Client_SentOptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ClientSentOptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.ReqOptionNumberOfEntries!UCI:network/interface,@i-1/reqopts*/
static int get_DHCPv4Client_ReqOptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ClientReqOptionInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv4ClientSentOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->dmmap_sect, "enable", value);
	return 0;
}

static int set_DHCPv4ClientSentOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	char *option_name = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			if (dhcp_client_s->client_sect) {
				option_name = get_dhcp_option_name(DM_STRTOL(dhcp_client_s->option_tag));

				if (DM_LSTRCMP(option_name, "sendopts") == 0) {
					char tag_value[128] = {0};
					char *sendopts = NULL;

					snprintf(tag_value, sizeof(tag_value), "%s:%s", dhcp_client_s->option_tag, dhcp_client_s->value);
					dmuci_get_value_by_section_string(dhcp_client_s->client_sect, "sendopts", &sendopts);

					if (b) {
						if (!value_exits_in_str_list(sendopts, " ", tag_value)) {
							add_elt_to_str_list(&sendopts, tag_value);
							dmuci_set_value_by_section(dhcp_client_s->client_sect, "sendopts", sendopts);
						}
					} else {
						remove_elt_from_str_list(&sendopts, tag_value);
						dmuci_set_value_by_section(dhcp_client_s->client_sect, "sendopts", sendopts);
					}
				} else {
					dmuci_set_value_by_section(dhcp_client_s->client_sect, option_name, b ? dhcp_client_s->value : "");
				}
			}

			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->dmmap_sect, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dhcp_client_option_args *)data)->dmmap_sect, "bbf_dhcpv4_sentopt_alias", instance, value);
}

static int set_DHCPv4ClientSentOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dhcp_client_option_args *)data)->dmmap_sect, "bbf_dhcpv4_sentopt_alias", instance, value);
}

static int get_DHCPv4ClientSentOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ClientSentOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	char *new_option_name = NULL;
	char *old_option_name = NULL;
	char *dhcp_client_key = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			if (dhcp_client_s->option_tag && DM_STRCMP(dhcp_client_s->option_tag, value) == 0)
				break;

			dmuci_get_value_by_section_string(dhcp_client_s->dmmap_sect, "dhcp_client_key", &dhcp_client_key);

			new_option_name = get_dhcp_option_name(DM_STRTOL(value));
			if (DM_LSTRCMP(new_option_name ,"sendopts") == 0) {
				if (tag_option_exists("dmmap_dhcp_client", "send_option", "dhcp_client_key", dhcp_client_key, "option_tag", value))
					return FAULT_9007;
			} else {
				if (dhcp_client_s->client_sect) {
					char *option_value = NULL;

					dmuci_get_value_by_section_string(dhcp_client_s->client_sect, new_option_name, &option_value);
					if (option_value && *option_value)
						return FAULT_9007;
				}
			}

			break;
		case VALUESET:
			if (dhcp_client_s->client_sect) {
				old_option_name = get_dhcp_option_name(DM_STRTOL(dhcp_client_s->option_tag));
				new_option_name = get_dhcp_option_name(DM_STRTOL(value));

				if (DM_LSTRCMP(old_option_name, "sendopts") == 0) {
					char old_tag_value[128] = {0};
					char *sendopts = NULL;

					dmuci_get_value_by_section_string(dhcp_client_s->client_sect, "sendopts", &sendopts);
					snprintf(old_tag_value, sizeof(old_tag_value), "%s:%s", dhcp_client_s->option_tag, dhcp_client_s->value);

					if (value_exits_in_str_list(sendopts, " ", old_tag_value)) {
						remove_elt_from_str_list(&sendopts, old_tag_value);
						dmuci_set_value_by_section(dhcp_client_s->client_sect, "sendopts", sendopts);

						if (DM_LSTRCMP(new_option_name, "sendopts") == 0) {
							char new_tag_value[128] = {0};

							snprintf(new_tag_value, sizeof(new_tag_value), "%s:%s", value, dhcp_client_s->value);
							add_elt_to_str_list(&sendopts, new_tag_value);
							dmuci_set_value_by_section(dhcp_client_s->client_sect, "sendopts", sendopts);
						} else {
							dmuci_set_value_by_section(dhcp_client_s->client_sect, new_option_name, dhcp_client_s->value);
						}
					}
				} else {
					char *option_value = NULL;

					dmuci_get_value_by_section_string(dhcp_client_s->client_sect, old_option_name, &option_value);
					if (option_value && *option_value) {
						dmuci_set_value_by_section(dhcp_client_s->client_sect, old_option_name, "");

						if (DM_LSTRCMP(new_option_name, "sendopts") == 0) {
							char new_tag_value[128] = {0};
							char *sendopts = NULL;

							snprintf(new_tag_value, sizeof(new_tag_value), "%s:%s", value, dhcp_client_s->value);
							dmuci_get_value_by_section_string(dhcp_client_s->client_sect, "sendopts", &sendopts);
							add_elt_to_str_list(&sendopts, new_tag_value);
							dmuci_set_value_by_section(dhcp_client_s->client_sect, "sendopts", sendopts);
						} else {
							dmuci_set_value_by_section(dhcp_client_s->client_sect, new_option_name, dhcp_client_s->value);
						}
					}
				}
			}

			dmuci_set_value_by_section_bbfdm(dhcp_client_s->dmmap_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_option = ((struct dhcp_client_option_args *)data)->option_tag;
	const char *tag_value = ((struct dhcp_client_option_args *)data)->value;
	char hex[256] = {0};

	if (DM_STRLEN(tag_option) && DM_STRLEN(tag_value))
		convert_str_option_to_hex(DM_STRTOL(tag_option), tag_value, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv4ClientSentOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	char *option_name = NULL;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_option_to_string(DM_STRTOL(dhcp_client_s->option_tag), value, res, sizeof(res));
			if (dhcp_client_s->client_sect) {
				option_name = get_dhcp_option_name(DM_STRTOL(dhcp_client_s->option_tag));

				if (DM_LSTRCMP(option_name, "sendopts") == 0) {
					char old_tag_value[128] = {0};
					char *sendopts = NULL;

					dmuci_get_value_by_section_string(dhcp_client_s->client_sect, "sendopts", &sendopts);
					snprintf(old_tag_value, sizeof(old_tag_value), "%s:%s", dhcp_client_s->option_tag, dhcp_client_s->value);

					if (value_exits_in_str_list(sendopts, " ", old_tag_value)) {
						char new_tag_value[512] = {0};

						snprintf(new_tag_value, sizeof(new_tag_value), "%s:%s", dhcp_client_s->option_tag, res);

						remove_elt_from_str_list(&sendopts, old_tag_value);
						add_elt_to_str_list(&sendopts, new_tag_value);
						dmuci_set_value_by_section(dhcp_client_s->client_sect, "sendopts", sendopts);
					}
				} else {
					char *option_value = NULL;

					dmuci_get_value_by_section_string(dhcp_client_s->client_sect, option_name, &option_value);
					dmuci_set_value_by_section(dhcp_client_s->client_sect, option_name, (option_value && *option_value) ? res : "");
				}
			}

			dmuci_set_value_by_section_bbfdm(dhcp_client_s->dmmap_sect, "option_value", res);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->dmmap_sect, "enable", value);
	return 0;
}

static int set_DHCPv4ClientReqOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	char *reqopts = NULL;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (dhcp_client_s->client_sect) {
				dmuci_get_value_by_section_string(dhcp_client_s->client_sect, "reqopts", &reqopts);
				if (b) {
					if (!value_exits_in_str_list(reqopts, " ", dhcp_client_s->option_tag)) {
						add_elt_to_str_list(&reqopts, dhcp_client_s->option_tag);
						dmuci_set_value_by_section(dhcp_client_s->client_sect, "reqopts", reqopts);
					}
				} else {
					remove_elt_from_str_list(&reqopts, dhcp_client_s->option_tag);
					dmuci_set_value_by_section(dhcp_client_s->client_sect, "reqopts", reqopts);
				}
			}

			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->dmmap_sect, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dhcp_client_option_args *)data)->dmmap_sect, "bbf_dhcpv4_reqtopt_alias", instance, value);
}

static int set_DHCPv4ClientReqOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dhcp_client_option_args *)data)->dmmap_sect, "bbf_dhcpv4_reqtopt_alias", instance, value);
}

static int get_DHCPv4ClientReqOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ClientReqOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	char *dhcp_client_key = NULL;
	char *reqopts = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			if (dhcp_client_s->option_tag && DM_STRCMP(dhcp_client_s->option_tag, value) == 0)
				break;

			dmuci_get_value_by_section_string(dhcp_client_s->dmmap_sect, "dhcp_client_key", &dhcp_client_key);

			if (tag_option_exists("dmmap_dhcp_client", "req_option", "dhcp_client_key", dhcp_client_key, "option_tag", value))
				return FAULT_9007;

			break;
		case VALUESET:
			if (dhcp_client_s->client_sect) {
				bool tag_enabled = false;

				dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &reqopts);

				if (value_exits_in_str_list(reqopts, " ", dhcp_client_s->option_tag)) {
					remove_elt_from_str_list(&reqopts, dhcp_client_s->option_tag);
					tag_enabled = true;
				}

				if (tag_enabled) {
					add_elt_to_str_list(&reqopts, value);
					dmuci_set_value_by_section(dhcp_client_s->client_sect, "reqopts", reqopts);
				}
			}

			dmuci_set_value_by_section_bbfdm(dhcp_client_s->dmmap_sect, "option_tag", value);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Enable!UCI:dhcp/dnsmasq,@dnsmasq[0]/dhcpv4server*/
static int get_DHCPv4Server_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *sec = get_dnsmasq_section_name();

	if (DM_STRLEN(sec) == 0)
		return 0;

	*value = dmuci_get_option_value_fallback_def("dhcp", sec, "dhcpv4server", "1");
	return 0;
}

static int set_DHCPv4Server_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *sec;

	switch (action) {
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			sec = get_dnsmasq_section_name();
			if (DM_STRLEN(sec) == 0)
				return 0;

			string_to_bool(value, &b);
			dmuci_set_value("dhcp", sec, "dhcpv4server", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_DHCPv4Server_PoolNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4ServerPoolInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_DHCPv4ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;

	dmuci_get_value_by_section_list(dhcp_client_s->client_sect, "dhcp_option", &dhcp_option_list);
	if (dhcp_option_list != NULL) {
		struct uci_element *e = NULL;
		size_t length;

		uci_foreach_element(dhcp_option_list, e) {
			char **buf = strsplit(e->name, ",", &length);
			if (buf && *buf && DM_STRCMP(buf[0], dhcp_client_s->option_tag) == 0) {
				*value = "1";
				return 0;
			}
		}
	}
	*value = "0";
	return 0;
}

static int set_DHCPv4ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;
	char opt_value[128] = {0};
	bool option_enabled = false, b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_list(dhcp_client_s->client_sect, "dhcp_option", &dhcp_option_list);
			snprintf(opt_value, sizeof(opt_value), "%s,%s", dhcp_client_s->option_tag, dhcp_client_s->value);

			if (dhcp_option_list != NULL) {
				struct uci_element *e = NULL;
				size_t length;

				uci_foreach_element(dhcp_option_list, e) {
					char **buf = strsplit(e->name, ",", &length);
					if (buf && *buf && DM_STRCMP(buf[0], dhcp_client_s->option_tag) == 0) {
						option_enabled = true;
						if (!b)
							dmuci_del_list_value_by_section(dhcp_client_s->client_sect, "dhcp_option", opt_value);
						break;
					}
				}
			}

			if(!option_enabled && b)
				dmuci_add_list_value_by_section(dhcp_client_s->client_sect, "dhcp_option", opt_value);
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dhcp_client_option_args *)data)->dmmap_sect, "bbf_dhcpv4_servpool_option_alias", instance, value);
}

static int set_DHCPv4ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dhcp_client_option_args *)data)->dmmap_sect, "bbf_dhcpv4_servpool_option_alias", instance, value);
}

static int get_DHCPv4ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;
	bool option_enabled = false;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_unsignedInt(ctx, value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			if (dhcp_client_s->option_tag && DM_STRCMP(dhcp_client_s->option_tag, value) == 0)
				break;

			if (tag_option_exists("dmmap_dhcp", "servpool_option", "section_name", section_name(dhcp_client_s->client_sect), "option_tag", value))
				return FAULT_9007;

			break;
		case VALUESET:
			dmuci_get_value_by_section_list(dhcp_client_s->client_sect, "dhcp_option", &dhcp_option_list);

			if (dhcp_option_list != NULL) {
				struct uci_element *e = NULL;
				size_t length;

				uci_foreach_element(dhcp_option_list, e) {
					char **buf = strsplit(e->name, ",", &length);
					if (buf && *buf && DM_STRCMP(buf[0], dhcp_client_s->option_tag) == 0) {
						option_enabled = true;
						break;
					}
				}
			}

			if (option_enabled) {
				char new_tag_value[128] = {0}, old_tag_value[128] = {0};

				snprintf(old_tag_value, sizeof(old_tag_value), "%s,%s", dhcp_client_s->option_tag, dhcp_client_s->value);
				snprintf(new_tag_value, sizeof(new_tag_value), "%s,%s", value, dhcp_client_s->value);
				dmuci_del_list_value_by_section(dhcp_client_s->client_sect, "dhcp_option", old_tag_value);
				dmuci_add_list_value_by_section(dhcp_client_s->client_sect, "dhcp_option", new_tag_value);
			}

			dmuci_set_value_by_section_bbfdm(dhcp_client_s->dmmap_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_option = ((struct dhcp_client_option_args *)data)->option_tag;
	const char *tag_value = ((struct dhcp_client_option_args *)data)->value;
	char hex[256] = {0};

	if (DM_STRLEN(tag_option) && DM_STRLEN(tag_value))
		convert_str_option_to_hex(DM_STRTOL(tag_option), tag_value, hex, sizeof(hex));

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv4ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_option_args *dhcp_client_s = (struct dhcp_client_option_args *)data;
	struct uci_list *dhcp_option_list = NULL;
	char res[256] = {0};
	bool option_enabled = false;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_list(dhcp_client_s->client_sect, "dhcp_option", &dhcp_option_list);

			if (dhcp_option_list != NULL) {
				struct uci_element *e = NULL;
				size_t length;

				uci_foreach_element(dhcp_option_list, e) {
					char **buf = strsplit(e->name, ",", &length);
					if (buf && *buf && DM_STRCMP(buf[0], dhcp_client_s->option_tag) == 0) {
						option_enabled = true;
						break;
					}
				}
			}

			convert_hex_option_to_string(DM_STRTOL(dhcp_client_s->option_tag), value, res, sizeof(res));

			if (option_enabled) {
				char new_tag_value[512] = {0}, old_tag_value[128] = {0};

				snprintf(old_tag_value, sizeof(old_tag_value), "%s,%s", dhcp_client_s->option_tag, dhcp_client_s->value);
				snprintf(new_tag_value, sizeof(new_tag_value), "%s,%s", dhcp_client_s->option_tag, res);
				dmuci_del_list_value_by_section(dhcp_client_s->client_sect, "dhcp_option", old_tag_value);
				dmuci_add_list_value_by_section(dhcp_client_s->client_sect, "dhcp_option", new_tag_value);
			}

			dmuci_set_value_by_section_bbfdm(dhcp_client_s->dmmap_sect, "option_value", res);
			break;
	}
	return 0;
}

static int get_DHCPv4Relay_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*relayd";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv4Relay_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmcmd("/etc/init.d/relayd", 1, b ? "enable" : "disable");
			break;
	}
	return 0;
}

static int get_DHCPv4Relay_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*relayd";
	if (check_file(path))
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

static int get_DHCPv4Relay_ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = get_number_of_entries(ctx, data, instance, browseDHCPv4RelayForwardingInst);
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4RelayForwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dhcp_client_args *dhcp_relay = (struct dhcp_client_args *)data;
	char *disabled = NULL;

	dmuci_get_value_by_section_string(dhcp_relay->iface_s ? dhcp_relay->iface_s : dhcp_relay->dmmap_s, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "0" : "1";
	return 0;
}

static int set_DHCPv4RelayForwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_args *dhcp_relay = (struct dhcp_client_args *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_boolean(ctx, value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(dhcp_relay->dmmap_s, "disabled", b ? "0" : "1");
			if (dhcp_relay->iface_s)
				dmuci_set_value_by_section(dhcp_relay->iface_s, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4RelayForwarding_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_DHCPv4RelayForwarding_Enable(refparam, ctx, data, instance, value);
	*value = (DM_LSTRCMP(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

static int get_DHCPv4RelayForwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dhcp_client_args *)data)->dmmap_s, "bbf_dhcpv4relay_alias", instance, value);
}

static int set_DHCPv4RelayForwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dhcp_client_args *)data)->dmmap_s, "bbf_dhcpv4relay_alias", instance, value);
}

static int get_DHCPv4RelayForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *iface_name = NULL;

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dmmap_s, "iface_name", &iface_name);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", iface_name, value);
	return 0;
}

static int set_DHCPv4RelayForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_client_args *dhcp_relay = (struct dhcp_client_args *)data;
	char *allowed_objects[] = {"Device.IP.Interface.", NULL};
	struct uci_section *interface_s = NULL;
	char *curr_iface_name = NULL;
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 256, NULL, NULL))
				return FAULT_9007;

			if (dm_entry_validate_allowed_objects(ctx, value, allowed_objects))
				return FAULT_9007;

			break;
		case VALUESET:
			// Get linker
			adm_entry_get_linker_value(ctx, value, &linker);

			dmuci_get_value_by_section_string(dhcp_relay->dmmap_s, "iface_name", &curr_iface_name);

			// Get the corresponding network config
			if (linker && *linker != 0)
				get_config_section_of_dmmap_section("network", "interface", linker, &interface_s);

			// break if interface section is not found
			if (interface_s && (strcmp(section_name(interface_s), curr_iface_name) == 0))
				break;

			dmuci_set_value_by_section(dhcp_relay->iface_s, "proto", "none");

			if (!linker || *linker == 0) {
				dmuci_set_value_by_section_bbfdm(dhcp_relay->dmmap_s, "added_by_controller", "1");
				dmuci_set_value_by_section_bbfdm(dhcp_relay->dmmap_s, "iface_name", "");
			} else {
				// Update proto option of config section
				dmuci_set_value_by_section(interface_s, "proto", "relay");

				// Update dmmap section
				dmuci_set_value_by_section_bbfdm(dhcp_relay->dmmap_s, "iface_name", linker);
			}
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.VendorClassID!UCI:network/interface,@i-1/vendorclass*/
static int get_DHCPv4RelayForwarding_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_relay_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcp_relay_s) {
		char *relay_network = NULL;

		dmuci_get_value_by_section_string(dhcp_relay_s, "network", &relay_network);
		char *dhcp_network = (DM_STRLEN(relay_network)) ? get_dhcp_network_from_relay_list(relay_network) : NULL;
		struct uci_section *ven_class_s = (DM_STRLEN(dhcp_network)) ? get_dhcp_classifier("vendorclass", dhcp_network) : NULL;

		if (ven_class_s)
			dmuci_get_value_by_section_string(ven_class_s, "vendorclass", value);
	}
	return 0;
}

static int set_DHCPv4RelayForwarding_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcp_relay_s = ((struct dhcp_client_args *)data)->iface_s;

	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 255, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if (dhcp_relay_s) {
				char *relay_network = NULL;

				dmuci_get_value_by_section_string(dhcp_relay_s, "network", &relay_network);
				char *dhcp_network = (DM_STRLEN(relay_network)) ? get_dhcp_network_from_relay_list(relay_network) : NULL;
				struct uci_section *ven_class_s = (DM_STRLEN(dhcp_network)) ? get_dhcp_classifier("vendorclass", dhcp_network) : NULL;

				if (ven_class_s)
					dmuci_set_value_by_section(ven_class_s, "vendorclass", value);
			}
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Chaddr!UCI:network/interface,@i-1/mac*/
static int get_DHCPv4RelayForwarding_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_relay_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcp_relay_s) {
		char *relay_network = NULL;

		dmuci_get_value_by_section_string(dhcp_relay_s, "network", &relay_network);
		char *dhcp_network = (DM_STRLEN(relay_network)) ? get_dhcp_network_from_relay_list(relay_network) : NULL;
		struct uci_section *mac_s = (DM_STRLEN(dhcp_network)) ? get_dhcp_classifier("mac", dhcp_network) : NULL;

		if (mac_s)
			dmuci_get_value_by_section_string(mac_s, "mac", value);
	}
	return 0;
}

static int set_DHCPv4RelayForwarding_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_string(ctx, value, -1, 17, NULL, MACAddress))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.UserClassID!UCI:network/interface,@i-1/userclass*/
static int get_DHCPv4RelayForwarding_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_relay_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcp_relay_s) {
		char *relay_network = NULL;

		dmuci_get_value_by_section_string(dhcp_relay_s, "network", &relay_network);
		char *dhcp_network = (DM_STRLEN(relay_network)) ? get_dhcp_network_from_relay_list(relay_network) : NULL;
		struct uci_section *user_class_s = (DM_STRLEN(dhcp_network)) ? get_dhcp_classifier("userclass", dhcp_network) : NULL;

		if (user_class_s) {
			char hex[256] = {0}, *ucid = NULL;

			dmuci_get_value_by_section_string(user_class_s, "userclass", &ucid);

			if (DM_STRLEN(ucid))
				convert_str_option_to_hex(77, ucid, hex, sizeof(hex));

			*value = (*hex) ? dmstrdup(hex) : "";
		}
	}
	return 0;
}

static int set_DHCPv4RelayForwarding_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcp_relay_s = ((struct dhcp_client_args *)data)->iface_s;


	switch (action)	{
		case VALUECHECK:
			if (bbfdm_validate_hexBinary(ctx, value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if (dhcp_relay_s) {
				char *relay_network = NULL;

				dmuci_get_value_by_section_string(dhcp_relay_s, "network", &relay_network);
				char *dhcp_network = (DM_STRLEN(relay_network)) ? get_dhcp_network_from_relay_list(relay_network) : NULL;
				struct uci_section *user_class_s = (DM_STRLEN(dhcp_network)) ? get_dhcp_classifier("userclass", dhcp_network) : NULL;

				if (user_class_s) {
					char res[256] = {0};

					convert_hex_option_to_string(77, value, res, sizeof(res));
					dmuci_set_value_by_section(user_class_s, "userclass", res);
				}
			}
			break;
	}
	return 0;
}

/*************************************************************
 * OPERATE COMMANDS
 *************************************************************/
static int operate_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcpv4_s = ((struct dhcp_client_args *)data)->iface_s;

	if (dhcpv4_s) {
		char *if_name = section_name(dhcpv4_s);
		dmubus_call_set("network.interface", "renew", UBUS_ARGS{{"interface", if_name, String}}, 1);
	}

	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DHCPv4. *** */
DMOBJ tDHCPv4Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Client", &DMWRITE, addObjDHCPv4Client, delObjDHCPv4Client, NULL, browseDHCPv4ClientInst, NULL, NULL, tDHCPv4ClientObj, tDHCPv4ClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", "Alias", NULL}},
{"Server", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv4ServerObj, tDHCPv4ServerParams, NULL, BBFDM_BOTH, NULL},
{"Relay", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv4RelayObj, tDHCPv4RelayParams, NULL, BBFDM_BOTH, NULL},
{0}
};

DMLEAF tDHCPv4Params[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}. *** */
DMOBJ tDHCPv4ClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"SentOption", &DMWRITE, addObjDHCPv4ClientSentOption, delObjDHCPv4ClientSentOption, NULL, browseDHCPv4ClientSentOptionInst, NULL, NULL, NULL, tDHCPv4ClientSentOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{"ReqOption", &DMWRITE, addObjDHCPv4ClientReqOption, delObjDHCPv4ClientReqOption, NULL, browseDHCPv4ClientReqOptionInst, NULL, NULL, NULL, tDHCPv4ClientReqOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{0}
};

DMLEAF tDHCPv4ClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Client_Enable, set_DHCPv4Client_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4Client_Alias, set_DHCPv4Client_Alias, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv4Client_Interface, set_DHCPv4Client_Interface, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4Client_Status, NULL, BBFDM_BOTH},
{"DHCPStatus", &DMREAD, DMT_STRING, get_DHCPv4Client_DHCPStatus, NULL, BBFDM_BOTH},
{"Renew", &DMWRITE, DMT_BOOL, get_DHCPv4Client_Renew, set_DHCPv4Client_Renew, BBFDM_CWMP},
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv4Client_IPAddress, NULL, BBFDM_BOTH},
{"SubnetMask", &DMREAD, DMT_STRING, get_DHCPv4Client_SubnetMask, NULL, BBFDM_BOTH},
{"IPRouters", &DMREAD, DMT_STRING, get_DHCPv4Client_IPRouters, NULL, BBFDM_BOTH},
{"DNSServers", &DMREAD, DMT_STRING, get_DHCPv4Client_DNSServers, NULL, BBFDM_BOTH},
{"LeaseTimeRemaining", &DMREAD, DMT_INT, get_DHCPv4Client_LeaseTimeRemaining, NULL, BBFDM_BOTH},
//{"DHCPServer", &DMREAD, DMT_STRING, get_DHCPv4Client_DHCPServer, NULL, BBFDM_BOTH},
//{"PassthroughEnable", &DMWRITE, DMT_BOOL, get_DHCPv4Client_PassthroughEnable, set_DHCPv4Client_PassthroughEnable, BBFDM_BOTH},
//{"PassthroughDHCPPool", &DMWRITE, DMT_STRING, get_DHCPv4Client_PassthroughDHCPPool, set_DHCPv4Client_PassthroughDHCPPool, BBFDM_BOTH},
{"SentOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Client_SentOptionNumberOfEntries, NULL, BBFDM_BOTH},
{"ReqOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Client_ReqOptionNumberOfEntries, NULL, BBFDM_BOTH},
{"Renew()", &DMSYNC, DMT_COMMAND, NULL, operate_DHCPv4Client_Renew, BBFDM_USP},
{0}
};

/* *** Device.DHCPv4.Client.{i}.SentOption.{i}. *** */
DMLEAF tDHCPv4ClientSentOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ClientSentOption_Enable, set_DHCPv4ClientSentOption_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ClientSentOption_Alias, set_DHCPv4ClientSentOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ClientSentOption_Tag, set_DHCPv4ClientSentOption_Tag, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv4ClientSentOption_Value, set_DHCPv4ClientSentOption_Value, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}.ReqOption.{i}. *** */
DMLEAF tDHCPv4ClientReqOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ClientReqOption_Enable, set_DHCPv4ClientReqOption_Enable, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_DHCPv4ClientReqOption_Order, set_DHCPv4ClientReqOption_Order, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ClientReqOption_Alias, set_DHCPv4ClientReqOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ClientReqOption_Tag, set_DHCPv4ClientReqOption_Tag, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv4ClientReqOption_Value, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server. *** */
DMOBJ tDHCPv4ServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Pool", &DMWRITE, addObjDHCPv4ServerPool, delObjDHCPv4ServerPool, NULL, browseDHCPv4ServerPoolInst, NULL, NULL, tDHCPv4ServerPoolObj, tDHCPv4ServerPoolParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tDHCPv4ServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Server_Enable, set_DHCPv4Server_Enable, BBFDM_BOTH},
{"PoolNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Server_PoolNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}. *** */
DMOBJ tDHCPv4ServerPoolObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"StaticAddress", &DMWRITE, addObjDHCPv4ServerPoolStaticAddress, delObjDHCPv4ServerPoolStaticAddress, NULL, browseDHCPv4ServerPoolStaticAddressInst, NULL, NULL, NULL, tDHCPv4ServerPoolStaticAddressParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Chaddr", NULL}},
{"Option", &DMWRITE, addObjDHCPv4ServerPoolOption, delObjDHCPv4ServerPoolOption, NULL, browseDHCPv4ServerPoolOptionInst, NULL, NULL, NULL, tDHCPv4ServerPoolOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{"Client", &DMREAD, NULL, NULL, NULL, browseDhcpClientInst, NULL, NULL, tDHCPv4ServerPoolClientObj, tDHCPv4ServerPoolClientParams, get_dhcp_client_linker, BBFDM_BOTH, LIST_KEY{"Chaddr", "Alias", NULL}},
{0}
};

DMLEAF tDHCPv4ServerPoolParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPool_Enable, set_DHCPv4ServerPool_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4ServerPool_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_Alias, set_DHCPv4ServerPool_Alias, BBFDM_BOTH},
{"Order", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPool_Order, set_DHCPv4ServerPool_Order, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_Interface, set_DHCPv4ServerPool_Interface, BBFDM_BOTH},
//{"VendorClassID", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_VendorClassID, set_DHCPv4ServerPool_VendorClassID, BBFDM_BOTH},
//{"VendorClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPool_VendorClassIDExclude, set_DHCPv4ServerPool_VendorClassIDExclude, BBFDM_BOTH},
//{"VendorClassIDMode", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_VendorClassIDMode, set_DHCPv4ServerPool_VendorClassIDMode, BBFDM_BOTH},
//{"ClientID", &DMWRITE, DMT_HEXBIN, get_DHCPv4ServerPool_ClientID, set_DHCPv4ServerPool_ClientID, BBFDM_BOTH},
//{"ClientIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPool_ClientIDExclude, set_DHCPv4ServerPool_ClientIDExclude, BBFDM_BOTH},
//{"UserClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv4ServerPool_UserClassID, set_DHCPv4ServerPool_UserClassID, BBFDM_BOTH},
//{"UserClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPool_UserClassIDExclude, set_DHCPv4ServerPool_UserClassIDExclude, BBFDM_BOTH},
//{"Chaddr", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_Chaddr, set_DHCPv4ServerPool_Chaddr, BBFDM_BOTH},
//{"ChaddrMask", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_ChaddrMask, set_DHCPv4ServerPool_ChaddrMask, BBFDM_BOTH},
//{"ChaddrExclude", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPool_ChaddrExclude, set_DHCPv4ServerPool_ChaddrExclude, BBFDM_BOTH},
{"AllowedDevices", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_AllowedDevices, set_DHCPv4ServerPool_AllowedDevices, BBFDM_BOTH},
{"MinAddress", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_MinAddress, set_DHCPv4ServerPool_MinAddress, BBFDM_BOTH},
{"MaxAddress", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_MaxAddress, set_DHCPv4ServerPool_MaxAddress, BBFDM_BOTH},
{"ReservedAddresses", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_ReservedAddresses, set_DHCPv4ServerPool_ReservedAddresses, BBFDM_BOTH},
{"SubnetMask", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_SubnetMask, set_DHCPv4ServerPool_SubnetMask, BBFDM_BOTH},
{"DNSServers", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_DNSServers, set_DHCPv4ServerPool_DNSServers, BBFDM_BOTH},
{"DomainName", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_DomainName, set_DHCPv4ServerPool_DomainName, BBFDM_BOTH},
{"IPRouters", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_IPRouters, set_DHCPv4ServerPool_IPRouters, BBFDM_BOTH},
{"LeaseTime", &DMWRITE, DMT_INT, get_DHCPv4ServerPool_LeaseTime, set_DHCPv4ServerPool_LeaseTime, BBFDM_BOTH},
{"StaticAddressNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPool_StaticAddressNumberOfEntries, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPool_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPool_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}. *** */
DMLEAF tDHCPv4ServerPoolStaticAddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPoolStaticAddress_Enable, set_DHCPv4ServerPoolStaticAddress_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolStaticAddress_Alias, set_DHCPv4ServerPoolStaticAddress_Alias, BBFDM_BOTH},
{"Chaddr", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolStaticAddress_Chaddr, set_DHCPv4ServerPoolStaticAddress_Chaddr, BBFDM_BOTH},
{"Yiaddr", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolStaticAddress_Yiaddr, set_DHCPv4ServerPoolStaticAddress_Yiaddr, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Option.{i}. *** */
DMLEAF tDHCPv4ServerPoolOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPoolOption_Enable, set_DHCPv4ServerPoolOption_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolOption_Alias, set_DHCPv4ServerPoolOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPoolOption_Tag, set_DHCPv4ServerPoolOption_Tag, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv4ServerPoolOption_Value, set_DHCPv4ServerPoolOption_Value, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}. *** */
DMOBJ tDHCPv4ServerPoolClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseDhcpClientIPv4Inst, NULL, NULL, NULL, tDHCPv4ServerPoolClientIPv4AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"IPAddress", NULL}},
{"Option", &DMREAD, NULL, NULL, NULL, browseDHCPv4ServerPoolClientOptionInst, NULL, NULL, NULL, tDHCPv4ServerPoolClientOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", NULL}},
{0}
};

DMLEAF tDHCPv4ServerPoolClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Alias", &DMWRITE, DMT_STRING,  get_DHCPv4ServerPoolClient_Alias, set_DHCPv4ServerPoolClient_Alias, BBFDM_BOTH},
{"Chaddr", &DMREAD, DMT_STRING,  get_DHCPv4ServerPoolClient_Chaddr, NULL, BBFDM_BOTH},
{"Active", &DMREAD, DMT_BOOL,  get_DHCPv4ServerPoolClient_Active, NULL, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClient_IPv4AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClient_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}. *** */
DMLEAF tDHCPv4ServerPoolClientIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv4ServerPoolClientIPv4Address_IPAddress, NULL, BBFDM_BOTH},
{"LeaseTimeRemaining", &DMREAD, DMT_TIME, get_DHCPv4ServerPoolClientIPv4Address_LeaseTimeRemaining, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}. *** */
DMLEAF tDHCPv4ServerPoolClientOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Tag", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClientOption_Tag, NULL, BBFDM_BOTH},
{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv4ServerPoolClientOption_Value, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Relay. *** */
DMOBJ tDHCPv4RelayObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"Forwarding", &DMWRITE, addObjDHCPv4RelayForwarding, delObjDHCPv4RelayForwarding, NULL, browseDHCPv4RelayForwardingInst, NULL, NULL, NULL, tDHCPv4RelayForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tDHCPv4RelayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Relay_Enable, set_DHCPv4Relay_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4Relay_Status, NULL, BBFDM_BOTH},
{"ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Relay_ForwardingNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Relay.Forwarding.{i}. *** */
DMLEAF tDHCPv4RelayForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_Enable, set_DHCPv4RelayForwarding_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4RelayForwarding_Status, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_Alias, set_DHCPv4RelayForwarding_Alias, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_DHCPv4RelayForwarding_Order, set_DHCPv4RelayForwarding_Order, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_Interface, set_DHCPv4RelayForwarding_Interface, BBFDM_BOTH},
{"VendorClassID", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_VendorClassID, set_DHCPv4RelayForwarding_VendorClassID, BBFDM_BOTH},
//{"VendorClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_VendorClassIDExclude, set_DHCPv4RelayForwarding_VendorClassIDExclude, BBFDM_BOTH},
//{"VendorClassIDMode", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_VendorClassIDMode, set_DHCPv4RelayForwarding_VendorClassIDMode, BBFDM_BOTH},
//{"ClientID", &DMWRITE, DMT_HEXBIN, get_DHCPv4RelayForwarding_ClientID, set_DHCPv4RelayForwarding_ClientID, BBFDM_BOTH},
//{"ClientIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_ClientIDExclude, set_DHCPv4RelayForwarding_ClientIDExclude, BBFDM_BOTH},
{"UserClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv4RelayForwarding_UserClassID, set_DHCPv4RelayForwarding_UserClassID, BBFDM_BOTH},
//{"UserClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_UserClassIDExclude, set_DHCPv4RelayForwarding_UserClassIDExclude, BBFDM_BOTH},
{"Chaddr", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_Chaddr, set_DHCPv4RelayForwarding_Chaddr, BBFDM_BOTH},
//{"ChaddrMask", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_ChaddrMask, set_DHCPv4RelayForwarding_ChaddrMask, BBFDM_BOTH},
//{"ChaddrExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_ChaddrExclude, set_DHCPv4RelayForwarding_ChaddrExclude, BBFDM_BOTH},
//{"LocallyServed", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_LocallyServed, set_DHCPv4RelayForwarding_LocallyServed, BBFDM_BOTH},
//{"DHCPServerIPAddress", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_DHCPServerIPAddress, set_DHCPv4RelayForwarding_DHCPServerIPAddress, BBFDM_BOTH},
{0}
};
