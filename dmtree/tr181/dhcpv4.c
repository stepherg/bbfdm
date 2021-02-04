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

#include "dmentry.h"
#include "dhcpv4.h"


struct dhcp_lease {
	uint64_t ts;
	char hwaddr[20];
	char ipaddr[16];
	struct list_head list;
};

struct dhcp_args {
	struct uci_section *dhcp_sec;
	char *interface;
	struct list_head leases;
	unsigned n_leases;
};

struct dhcp_host_args {
	struct uci_section *dhcp_sec;
	struct uci_section *host_sec;
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
	struct uci_section *dhcp_client_conf;
	struct uci_section *dhcp_client_dm;
	struct uci_section *macclassifier;
	struct uci_section *vendorclassidclassifier;
	struct uci_section *userclassclassifier;
	char *ip;
	char *mask;
};

struct dhcp_client_option_args {
	struct uci_section *opt_sect;
	struct uci_section *client_sect;
	char *option_tag;
	char *value;
};

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
static inline void init_dhcp_args(struct dhcp_args *args, struct uci_section *s, char *interface)
{
	args->interface = interface;
	args->dhcp_sec = s;
	INIT_LIST_HEAD(&args->leases);
	args->n_leases = 0;
}

static inline void init_args_dhcp_host(struct dhcp_host_args *args, struct uci_section *dhcp_s, struct uci_section *host_s, char *interface)
{
	args->dhcp_sec = dhcp_s;
	args->host_sec = host_s;
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
	if (strlen(v) > 0 && strcmp(v, order) == 0)
		return 0;
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "order", order);
	if (conf == NULL) {
		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
	} else
		s = conf;

	if (strcmp(order, "1") != 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "");
	}

	if (set_force == 1 && strcmp(order, "1") == 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "1");
	}

	if ((dm = exist_other_section_same_order(dmmap_sect, dmpackage, sect_type, order)) != NULL) {
		dmuci_get_value_by_section_string(dm, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
		dmasprintf(&incrorder, "%d", atoi(order)+1);
		if (s != NULL && strcmp(order, "1") == 0) {
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
		pos += snprintf(&buf[pos], sizeof(buf) - pos, "%s:", (macarray[i] && strcmp(macarray[i], "*") == 0) ? "00" : type ? "FF" : macarray[i]);

	if (pos)
		buf[pos - 1] = 0;

	*value = dmstrdup(buf);
	return 0;
}

int set_DHCP_Interface(struct dmctx *ctx, char *value, struct uci_section *config_s, struct uci_section *dmmap_s, char *dmmap_name, char *proto, int action)
{
	char *linker = NULL, *added_by_controller = NULL, *curr_proto = NULL;
	struct uci_section *interface_s = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			if (value == NULL || *value == '\0')
				break;

			if (strncmp(value, "Device.IP.Interface.", 20) != 0)
				return FAULT_9007;

			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker == NULL || linker[0] == '\0')
				return FAULT_9007;

			break;
		case VALUESET:
			// Return if the value is empty
			if (value == NULL || *value == '\0')
				break;

			// Get linker
			adm_entry_get_linker_value(ctx, value, &linker);

			// Get the corresponding network config
			get_config_section_of_dmmap_section("network", "interface", linker, &interface_s);

			// break if interface section is not found
			if (interface_s == NULL)
				break;

			// Get the current proto value
			dmuci_get_value_by_section_string(interface_s, "proto", &curr_proto);
			if (curr_proto && strcmp(curr_proto, proto) == 0)
				break;

			// Update proto option of config section
			dmuci_set_value_by_section(interface_s, "proto", proto);

			// Update dmmap section
			dmuci_set_value_by_section_bbfdm(dmmap_s, "section_name", linker);

			dmuci_get_value_by_section_string(dmmap_s, "added_by_controller", &added_by_controller);
			if (added_by_controller && strcmp(added_by_controller, "1") == 0) {
				// Remove added_by_controller option from dmmap section
				dmuci_set_value_by_section_bbfdm(dmmap_s, "added_by_controller", "");

				// Remove the current section
				dmuci_delete_by_section(config_s, NULL, NULL);
			} else {
				dmuci_set_value_by_section(config_s, "proto", "none");
			}

			break;
	}
	return 0;
}

static char *get_last_host_instance(char *package, char *section, char *dmmap_package, char *opt_inst, char *opt_check, char *value_check)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;
	char *instance = NULL, *last_inst = NULL;

	uci_foreach_option_cont(package, section, opt_check, value_check, s) {

		// Skip all reserved hosts
		char *host_name = NULL;
		dmuci_get_value_by_section_string(s, "name", &host_name);
		if (host_name && strcmp(host_name, "reserved") == 0)
			continue;

		get_dmmap_section_of_config_section(dmmap_package, section, section_name(s), &dmmap_section);
		if (dmmap_section == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "section_name", section_name(s));
		}
		instance = update_instance(last_inst, 2, dmmap_section, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(instance);
	}
	return instance;
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
	json_object *res;
	const char *addr_str = NULL;
	int addr_cidr = -1;

	dmubus_call("network.interface", "status", UBUS_ARGS {{"interface", iface, String}}, 1, &res);
	if (res) {
		json_object *jobj;

		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		if (jobj == NULL)
			return -1;

		json_object_object_foreach(jobj, key, val) {
			if (!strcmp(key, "address"))
				addr_str = json_object_get_string(val);
			else if (!strcmp(key, "mask"))
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

		if (strcmp(opt_value, value) == 0)
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

		if (strcmp(opt_value, value) == 0)
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
	*iface_net_start = (ntohl(*iface_addr) & *iface_bits) + atoi(dhcp_start);
	*iface_net_end = (ntohl(*iface_addr) & *iface_bits) + atoi(dhcp_start) + atoi(dhcp_limit) - 1;
	*start = atoi(dhcp_start);
	*limit = atoi(dhcp_limit);

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
	char **net_list_arr, *v;
	int i;
	size_t length;

	net_list_arr = strsplit(net_list, " ", &length);
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &v);
		for (i = 0; i < length; i++) {
			if (strcmp(net_list_arr[i], section_name(s)) == 0 && strcmp(v, "dhcp") == 0)
				return net_list_arr[i];
		}
	}
	return "";
}

static struct uci_section *get_dhcp_classifier(char *classifier_name, char *network)
{
	struct uci_section* s = NULL;
	char *v;

	uci_foreach_sections("dhcp", classifier_name, s) {
		dmuci_get_value_by_section_string(s, "networkid", &v);
		if (strcmp(v, network) == 0)
			return s;
	}
	return NULL;
}

char *get_dhcp_server_pool_last_instance(char *package, char *section, char *dmmap_package, char *opt_inst)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;
	char *instance = NULL, *last_inst = NULL, *ignore = NULL;

	uci_foreach_sections(package, section, s) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(s, "ignore", &ignore);
		if (ignore && strcmp(ignore, "1") == 0)
			continue;

		get_dmmap_section_of_config_section(dmmap_package, section, section_name(s), &dmmap_section);
		if (dmmap_section == NULL) {
			dmuci_add_section_bbfdm(dmmap_package, section, &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "section_name", section_name(s));
		}
		instance = update_instance(last_inst, 2, dmmap_section, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(instance);
	}
	return instance;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjDHCPv4ServerPool(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *s = NULL, *dmmap_dhcp = NULL;
	char dhcp_sname[32] = {0};

	char *instance = get_dhcp_server_pool_last_instance("dhcp", "dhcp", "dmmap_dhcp", "dhcp_instance");
	snprintf(dhcp_sname, sizeof(dhcp_sname), "dhcp_%d", instance ? atoi(instance) + 1 : 1);

	dmuci_add_section("dhcp", "dhcp", &s);
	dmuci_rename_section_by_section(s, dhcp_sname);
	dmuci_set_value_by_section(s, "start", "100");
	dmuci_set_value_by_section(s, "leasetime", "12h");
	dmuci_set_value_by_section(s, "limit", "150");
	dmuci_set_value_by_section(s, "ignore", "0");

	dmuci_add_section_bbfdm("dmmap_dhcp", "dhcp", &dmmap_dhcp);
	dmuci_set_value_by_section(dmmap_dhcp, "section_name", dhcp_sname);
	*instancepara = update_instance(instance, 2, dmmap_dhcp, "dhcp_instance");
	return 0;
}

static int delObjDHCPv4ServerPool(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
	case DEL_INST:
		if(is_section_unnamed(section_name(((struct dhcp_args *)data)->dhcp_sec))){
			LIST_HEAD(dup_list);
			delete_sections_save_next_sections("dmmap_dhcp", "dhcp", "dhcp_instance", section_name(((struct dhcp_args *)data)->dhcp_sec), atoi(instance), &dup_list);
			update_dmmap_sections(&dup_list, "dhcp_instance", "dmmap_dhcp", "dhcp");
			dmuci_delete_by_section_unnamed(((struct dhcp_args *)data)->dhcp_sec, NULL, NULL);
		} else {
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct dhcp_args *)data)->dhcp_sec, NULL, NULL);
		}

		break;
	case DEL_ALL:
		uci_foreach_sections("dhcp", "dhcp", s) {
			if (found != 0){
				get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(s), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL){
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int addObjDHCPv4ServerPoolStaticAddress(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *s = NULL, *dmmap_dhcp_host = NULL;
	struct browse_args browse_args = {0};
	char host_name[32];

	char *instance = get_last_host_instance("dhcp", "host", "dmmap_dhcp", "dhcp_host_instance", "dhcp", ((struct dhcp_args *)data)->interface);
	snprintf(host_name, sizeof(host_name), "host_%d", instance ? atoi(instance) + 1 : 1);

	dmuci_add_section("dhcp", "host", &s);
	dmuci_set_value_by_section(s, "name", host_name);
	dmuci_set_value_by_section(s, "dhcp", ((struct dhcp_args *)data)->interface);

	browse_args.option = "dhcp";
	browse_args.value = ((struct dhcp_args *)data)->interface;

	dmuci_add_section_bbfdm("dmmap_dhcp", "host", &dmmap_dhcp_host);
	dmuci_set_value_by_section(dmmap_dhcp_host, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap_dhcp_host, "dhcp", ((struct dhcp_args *)data)->interface);
	*instancepara = update_instance(instance, 5, dmmap_dhcp_host, "dhcp_host_instance", NULL, check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjDHCPv4ServerPoolStaticAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_section = NULL;
	struct dhcp_host_args *host_args = (struct dhcp_host_args *)data;
	
	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name(host_args->host_sec))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcp", "host", "dhcp_host_instance", section_name(host_args->host_sec), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "dhcp_host_instance", "dmmap_dhcp", "host");
				dmuci_delete_by_section_unnamed(host_args->host_sec, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name((struct uci_section *)data), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(host_args->host_sec, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, stmp, s) {
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
	struct uci_section *s = NULL, *dmmap_sect = NULL;
	char dhcpv4_s[32];

	char *last_inst = get_last_instance_bbfdm("dmmap_dhcp_client", "interface", "bbf_dhcpv4client_instance");
	snprintf(dhcpv4_s, sizeof(dhcpv4_s), "dhcpv4_intf_%d", last_inst ? atoi(last_inst) + 1 : 1);

	dmuci_add_section("network", "interface", &s);
	dmuci_rename_section_by_section(s, dhcpv4_s);
	dmuci_set_value_by_section(s, "proto", "dhcp");
	dmuci_set_value_by_section(s, "disabled", "1");

	dmuci_add_section_bbfdm("dmmap_dhcp_client", "interface", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "section_name", dhcpv4_s);
	dmuci_set_value_by_section(dmmap_sect, "added_by_controller", "1");
	*instance = update_instance(last_inst, 2, dmmap_sect, "bbf_dhcpv4client_instance");
	return 0;
}

static int delObjDHCPv4Client(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *s_tmp = NULL;
	char *added_by_controller = NULL;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(((struct dhcp_client_args*)data)->dhcp_client_dm, "added_by_controller", &added_by_controller);
			if (added_by_controller && strcmp(added_by_controller, "1") == 0) {
				dmuci_delete_by_section(((struct dhcp_client_args*)data)->dhcp_client_conf, NULL, NULL);
			} else {
				dmuci_set_value_by_section(((struct dhcp_client_args*)data)->dhcp_client_conf, "proto", "none");
			}

			dmuci_delete_by_section(((struct dhcp_client_args*)data)->dhcp_client_dm, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq_safe("network", "interface", "proto", "dhcp", s_tmp, s) {
				struct uci_section *dmmap_section = NULL;

				get_dmmap_section_of_config_section("dmmap_dhcp_client", "interface", section_name(s), &dmmap_section);

				dmuci_get_value_by_section_string(dmmap_section, "added_by_controller", &added_by_controller);
				if (added_by_controller && strcmp(added_by_controller, "1") == 0) {
					dmuci_delete_by_section(s, NULL, NULL);
				} else {
					dmuci_set_value_by_section(s, "proto", "none");
				}

				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ClientSentOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)data;
	struct uci_section *dmmap_sect = NULL;
	struct browse_args browse_args = {0};

	char *inst_para = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcp_client", "send_option", "bbf_dhcpv4_sentopt_instance", "section_name", section_name(dhcp_client_args->dhcp_client_conf));

	dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", "0");

	browse_args.option = "section_name";
	browse_args.value = section_name(dhcp_client_args->dhcp_client_conf);

	*instance = update_instance(inst_para, 5, dmmap_sect, "bbf_dhcpv4_sentopt_instance", NULL, check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjDHCPv4ClientSentOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *list= NULL, *opt_value= NULL;

	switch (del_action) {
		case DEL_INST:
			if(strcmp(((struct dhcp_client_option_args*) data)->option_tag, "0") != 0)
			{
				dmasprintf(&opt_value, "%s:%s", ((struct dhcp_client_option_args*) data)->option_tag, ((struct dhcp_client_option_args*) data)->value);
				dmuci_get_value_by_section_string(((struct dhcp_client_option_args*) data)->client_sect, "sendopts", &list);
				if(list != NULL){
					remove_elt_from_str_list(&list, opt_value);
					dmuci_set_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "sendopts", list);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcp_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcp_client_args*) data)->dhcp_client_conf, "sendopts", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "send_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ClientReqOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)data;
	struct uci_section *dmmap_sect = NULL;
	struct browse_args browse_args = {0};

	char *inst_para = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcp_client", "req_option", "bbf_dhcpv4_sentopt_instance", "section_name", section_name(dhcp_client_args->dhcp_client_conf));

	dmuci_add_section_bbfdm("dmmap_dhcp_client", "req_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", "0");

	browse_args.option = "section_name";
	browse_args.value = section_name(dhcp_client_args->dhcp_client_conf);

	*instance = update_instance(inst_para, 5, dmmap_sect, "bbf_dhcpv4_sentopt_instance", NULL, check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjDHCPv4ClientReqOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *list = NULL;

	switch (del_action) {
		case DEL_INST:
			if (strcmp(((struct dhcp_client_option_args*) data)->option_tag, "0") != 0) {
				dmuci_get_value_by_section_string(((struct dhcp_client_option_args*) data)->client_sect, "reqopts", &list);
				if (list != NULL) {
					remove_elt_from_str_list(&list, ((struct dhcp_client_option_args*) data)->option_tag);
					dmuci_set_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "reqopts", list);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcp_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcp_client_args*) data)->dhcp_client_conf, "reqopts", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "req_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_args *dhcp_arg = (struct dhcp_args*)data;
	struct uci_section *dmmap_sect = NULL;
	struct browse_args browse_args = {0};

	char *inst_para = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcp", "servpool_option", "bbf_dhcpv4_servpool_option_instance", "section_name", section_name(dhcp_arg->dhcp_sec));

	dmuci_add_section_bbfdm("dmmap_dhcp", "servpool_option", &dmmap_sect);
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_arg->dhcp_sec));
	dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", "0");

	browse_args.option = "section_name";
	browse_args.value = section_name(dhcp_arg->dhcp_sec);

	*instance = update_instance(inst_para, 5, dmmap_sect, "bbf_dhcpv4_servpool_option_instance", NULL, check_browse_section, (void *)&browse_args);
	return 0;
}

static int delObjDHCPv4ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *stmp = NULL;
	char *opt_value = NULL;
	struct uci_list *dhcp_options_list = NULL;

	switch (del_action) {
		case DEL_INST:
			if (strcmp(((struct dhcp_client_option_args*) data)->option_tag, "0") != 0) {
				dmasprintf(&opt_value, "%s,%s", ((struct dhcp_client_option_args*) data)->option_tag, ((struct dhcp_client_option_args*) data)->value);
				dmuci_get_value_by_section_list(((struct dhcp_client_option_args*) data)->client_sect, "dhcp_option", &dhcp_options_list);
				if (dhcp_options_list != NULL) {
					dmuci_del_list_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "dhcp_option", opt_value);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcp_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcp_args*) data)->dhcp_sec, "dhcp_option", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp", "servpool_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4RelayForwarding(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s = NULL, *dmmap_sect = NULL;

	char *inst_para = get_last_instance_bbfdm("dmmap_dhcp_relay", "interface", "bbf_dhcpv4relay_instance");

	dmuci_add_section("network", "interface", &s);
	dmuci_set_value_by_section(s, "proto", "relay");

	dmuci_add_section_bbfdm("dmmap_dhcp_relay", "interface", &dmmap_sect);
	dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));
	*instance = update_instance(inst_para, 2, dmmap_sect, "bbf_dhcpv4relay_instance");
	return 0;
}

static int delObjDHCPv4RelayForwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dhcp_client_args *dhcp_relay_args = (struct dhcp_client_args*)data;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	char *proto = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name(dhcp_relay_args->dhcp_client_conf))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcp_relay", "interface", "bbf_dhcpv4relay_instance", section_name(dhcp_relay_args->dhcp_client_conf), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "bbf_dhcpv4relay_instance", "dmmap_dhcp_relay", "interface");
				dmuci_delete_by_section_unnamed(dhcp_relay_args->dhcp_client_conf, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcp_relay", "interface", section_name(dhcp_relay_args->dhcp_client_conf), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(dhcp_relay_args->dhcp_client_conf, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("network", "interface", s) {
				if (found != 0) {
					dmuci_get_value_by_section_string(ss, "proto", &proto);
					if (strcmp(proto, "relay") == 0) {
						get_dmmap_section_of_config_section("dmmap_dhcp_relay", "interface", section_name(ss), &dmmap_section);
						if (dmmap_section != NULL)
							dmuci_delete_by_section(dmmap_section, NULL, NULL);
						dmuci_delete_by_section(ss, NULL, NULL);
					}
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				dmuci_get_value_by_section_string(ss, "proto", &proto);
				if (strcmp(proto, "relay") == 0) {
					get_dmmap_section_of_config_section("dmmap_dhcp_relay", "interface", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
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
	dmuci_get_value_by_section_string(((struct dhcp_args *)data)->dhcp_sec, "dhcpv4", value);
	*value = (*value && strcmp(*value, "disabled") == 0) ? "0" : "1";
	return 0;
}

static int set_DHCPv4ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "dhcpv4", b ? "server" : "disabled");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.Status!UCI:dhcp/interface,@i-1/dhcpv4*/
static int get_DHCPv4ServerPool_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_args *)data)->dhcp_sec, "dhcpv4", value);
	*value = (*value && strcmp(*value, "disabled") == 0) ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.Alias!UCI:dmmap_dhcp/dhcp,@i-1/dhcp_alias*/
static int get_DHCPv4ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "dhcp_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "dhcp_alias", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv4ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "order", value);
	return 0;
}

static int set_DHCPv4ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
			if (dmmap_sect)
				set_section_order("dhcp", "dmmap_dhcp", "dhcp", dmmap_sect, ((struct dhcp_args *)data)->dhcp_sec, 1, value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmstrdup(((struct dhcp_args *)data)->interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	if (*value == NULL)
		*value = "";
	dmfree(linker);
	return 0;
}

static int set_DHCPv4ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker && *linker) {
				dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.MinAddress!UCI:dhcp/interface,@i-1/start*/
static int get_DHCPv4ServerPool_MinAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	unsigned iface_addr, iface_bits, iface_net_start, iface_net_end;
	int start = 0, limit = 0;
	char addr_min[32] = {0};

	if (get_dhcp_iface_range(((struct dhcp_args *)data)->dhcp_sec, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
		return -1;

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
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			if (get_dhcp_iface_range(((struct dhcp_args *)data)->dhcp_sec, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
				return -1;

			unsigned iface_net = ntohl(iface_addr) & iface_bits;

			inet_pton(AF_INET, value, &value_addr);
			unsigned value_net = ntohl(value_addr) & iface_bits;

			if (value_net == iface_net) {
				char buf[32] = {0};

				unsigned dhcp_start = ntohl(value_addr) - iface_net;
				unsigned dhcp_limit = start + limit - dhcp_start;

				// check if MinAddress > MaxAddress
				if ((int)dhcp_limit < 0)
					return -1;

				snprintf(buf, sizeof(buf), "%u", dhcp_start);
				dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "start", buf);

				snprintf(buf, sizeof(buf), "%u", dhcp_limit);
				dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "limit", buf);

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

	if (get_dhcp_iface_range(((struct dhcp_args *)data)->dhcp_sec, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
		return -1;

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
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (get_dhcp_iface_range(((struct dhcp_args *)data)->dhcp_sec, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
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
				dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "limit", buf_limit);

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

	if (get_dhcp_iface_range(((struct dhcp_args *)data)->dhcp_sec, ((struct dhcp_args *)data)->interface, &iface_addr, &iface_bits, &iface_net_start, &iface_net_end, &start, &limit))
		return -1;

	list_val[0] = 0;
	uci_foreach_option_eq("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, s) {

		char *host_name = NULL;
		dmuci_get_value_by_section_string(s, "name", &host_name);
		if (host_name && strcmp(host_name, "reserved") != 0)
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
			if (dm_validate_string_list(value, -1, 32, -1, -1, 15, NULL, 0, IPv4Address, 2))
				return FAULT_9007;

			local_value = dmstrdup(value);
			for (pch = strtok_r(local_value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

				// Check if ip address is out dhcp pool
				if (check_ipv4_in_dhcp_pool(((struct dhcp_args *)data)->dhcp_sec, ((struct dhcp_args *)data)->interface, pch)) {
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
				if (host_name && strcmp(host_name, "reserved") != 0)
					continue;

				char *ip = NULL;
				dmuci_get_value_by_section_string(s, "ip", &ip);
				if (ip == NULL || *ip == '\0')
					continue;

				// Check if ip exists in the list value : yes -> skip it else delete it
				if (!strstr(value, ip))
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
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
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
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
	if (res) {
		*value = dmjson_get_value_array_all(res, ",", 1, "dns-server");
	} else
		*value = "";

	if ((*value)[0] == '\0') {
		dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "dns", value);
		*value = dmstrdup(*value);
		char *p = *value;
		while (*p) {
			if (*p == ' ' && p != *value && *(p-1) != ',')
				*p++ = ',';
			else
				p++;
		}
	}

	if ((*value)[0] == '\0')
		dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", value);
	return 0;
}

static int set_DHCPv4ServerPool_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dup, *p;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 4, -1, -1, 15, NULL, 0, IPv4Address, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dup = dmstrdup(value);
			p = dup;
			while (*p) {
				if (*p == ',')
					*p++ = ' ';
				else
					p++;
			}
			dmuci_set_value("network", ((struct dhcp_args *)data)->interface, "dns", dup);
			dmfree(dup);
			return 0;
	}
	return 0;
}

static int get_DHCPv4ServerPool_DomainName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_option = NULL;
	struct uci_element *e = NULL;
	char *str = NULL;

	dmuci_get_value_by_section_list(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", &dhcp_option);
	if (!dhcp_option)
		return 0;

	uci_foreach_element(dhcp_option, e) {
		if ((str = strstr(e->name, "15,"))) {
			*value = dmstrdup(str + sizeof("15,") - 1);
			return 0;
		}
	}

	return 0;
}

static int set_DHCPv4ServerPool_DomainName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_list *dhcp_option = NULL;
	char buf[64];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_list(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", &dhcp_option);
			if (dhcp_option) {
				struct uci_element *e = NULL, *tmp = NULL;

				uci_foreach_element_safe(dhcp_option, e, tmp) {
					if (strstr(tmp->name, "15,"))
						dmuci_del_list_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", tmp->name);
				}
			}

			snprintf(buf, sizeof(buf), "15,%s", value);
			dmuci_add_list_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", buf);
	}
	return 0;
}

static int get_DHCPv4ServerPool_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "gateway", value);
	if ((*value)[0] == '\0')
		dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", value);
	return 0;
}

static int set_DHCPv4ServerPool_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 4, -1, -1, 15, NULL, 0, IPv4Address, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("network", ((struct dhcp_args *)data)->interface, "gateway", value);
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
	dmuci_get_value_by_section_string(((struct dhcp_args *)data)->dhcp_sec, "leasetime", &ltime);
	if (ltime == NULL || *ltime == '\0')
		return 0;

	if (strchr(ltime, 'd')) {
		pch = strtok_r(ltime, "d", &pchr);
		leasetime = atoi(pch) * 24 * 3600;
	} else if (strchr(ltime, 'h')) {
		pch = strtok_r(ltime, "h", &pchr);
		leasetime = atoi(pch) * 3600;
	} else if (strchr(ltime, 'm')) {
		pch = strtok_r(ltime, "m", &pchr);
		leasetime = atoi(pch) * 60;
	} else {
		pch = strtok_r(ltime, "s", &pchr);
		leasetime = atoi(pch);
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
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			leasetime = atoi(value);
			if (leasetime == -1)
				buf[0] = '\0';
			else
				snprintf(buf, sizeof(buf), "%ds", leasetime);

			dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "leasetime", buf);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddressNumberOfEntries!UCI:dhcp/host/*/
static int get_DHCPv4ServerPool_StaticAddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int i = 0;

	uci_foreach_option_eq("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, s) {

		// Skip all reserved hosts
		char *host_name = NULL;
		dmuci_get_value_by_section_string(s, "name", &host_name);
		if (host_name && strcmp(host_name, "reserved") == 0)
			continue;

		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv4ServerPool_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e = NULL;
	int i = 0;

	dmuci_get_value_by_section_list(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			i++;
		}
	}
	dmasprintf(value, "%d", i);
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
	*value = dmuci_get_value_by_section_fallback_def(((struct dhcp_host_args *)data)->host_sec, "enable", "1");
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcp_host_args *)data)->host_sec, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Alias!UCI:dmmap_dhcp/host,@i-1/dhcp_host_alias*/
static int get_DHCPv4ServerPoolStaticAddress_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(((struct dhcp_host_args *)data)->host_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "dhcp_host_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;
	char *curr_alias = NULL, *alias_assigned = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(((struct dhcp_host_args *)data)->host_sec), &dmmap_section);

	switch (action) {
		case VALUECHECK:
			// Validate value string -> length
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;

			// Check if alias is assigned by user
			dmuci_get_value_by_section_string(dmmap_section, "dhcp_host_alias_assigned", &alias_assigned);
			if (alias_assigned && strcmp(alias_assigned, "1") == 0)
				return FAULT_9007;

			// Check if alias exists
			dmuci_get_value_by_section_string(dmmap_section, "dhcp_host_alias", &curr_alias);
			if (strcmp(curr_alias, value) != 0 && check_dhcp_host_alias_exists(((struct dhcp_host_args *)data)->dhcp_interface, "dhcp_host_alias", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section(dmmap_section, "dhcp_host_alias", value);
			dmuci_set_value_by_section(dmmap_section, "dhcp_host_alias_assigned", "1");
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Chaddr!UCI:dhcp/host,@i-1/mac*/
static int get_DHCPv4ServerPoolStaticAddress_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_host_args *)data)->host_sec, "mac", value);
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *curr_mac = NULL;

	switch (action) {
		case VALUECHECK:
			// Validate value string -> MAC Address
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 2))
				return FAULT_9007;

			// Check if mac exists
			dmuci_get_value_by_section_string(((struct dhcp_host_args *)data)->host_sec, "mac", &curr_mac);
			if (strcmp(curr_mac, value) != 0 && check_dhcp_host_option_exists(((struct dhcp_host_args *)data)->dhcp_interface, "mac", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcp_host_args *)data)->host_sec, "mac", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Yiaddr!UCI:dhcp/host,@i-1/ip*/
static int get_DHCPv4ServerPoolStaticAddress_Yiaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_host_args *)data)->host_sec, "ip", value);
	return 0;
}

static int set_DHCPv4ServerPoolStaticAddress_Yiaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dhcp_host_args *host_args = (struct dhcp_host_args *)data;
	char *curr_ip = NULL;

	switch (action) {
		case VALUECHECK:
			// Validate value string -> IPv4 Address
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 2))
				return FAULT_9007;

			// Check if ip address is out dhcp pool
			if (check_ipv4_in_dhcp_pool(host_args->dhcp_sec, host_args->dhcp_interface, value))
				return FAULT_9007;

			// Check if ip exists
			dmuci_get_value_by_section_string(host_args->host_sec, "ip", &curr_ip);
			if (strcmp(curr_ip, value) != 0 && check_dhcp_host_option_exists(host_args->dhcp_interface, "ip", value))
				return FAULT_9007;

			return 0;
		case VALUESET:
			dmuci_set_value_by_section(host_args->host_sec, "ip", value);
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
		if (strcmp(hwaddr, macaddr) == 0) {
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
	FILE *f = fopen(DHCP_CLIENT_OPTIONS_FILE, "r");
	if (f == NULL) {
		*value = "0";
		return 0;
	}

	const struct client_args *args = (struct client_args *)data;
	char line[2048], macaddr[24], vcid[128], clid[128], ucid[128];
	int nbre_options = 0;

	while (fgets(line, sizeof(line), f) != NULL) {
		remove_new_line(line);

		sscanf(line, "%23s vcid=%127s clid=%127s ucid=%127s",
				macaddr, vcid, clid, ucid);

		if (strncmp(macaddr, (char *)args->lease->hwaddr, 24) == 0) {

			if (strcmp(vcid, "-") != 0)
				nbre_options++;

			if (strcmp(clid, "-") != 0)
				nbre_options++;

			if (strcmp(ucid, "-") != 0)
				nbre_options++;

			break;
		}
	}
	fclose(f);

	dmasprintf(value, "%d", nbre_options);
	return 0;
}

static int get_DHCPv4ServerPoolClientIPv4Address_LeaseTimeRemaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	return dm_time_format(args->lease->ts, value);
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
	const char *tag_value = ((struct client_options_args *)data)->value;
	char hex[256] = {0};

	if (tag_value && *tag_value)
		convert_string_to_hex(tag_value, hex);

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int get_DHCPv4_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL, *dmmap_sect = NULL;
	int nbre_confs = 0, nbre_dmmaps = 0;

	uci_foreach_option_eq("network", "interface", "proto", "dhcp", s) {
		nbre_confs++;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_dhcp_client", "interface", dmmap_sect) {
		nbre_dmmaps++;
	}
	if (nbre_dmmaps == 0 || nbre_dmmaps < nbre_confs)
		dmasprintf(value, "%d", nbre_confs);
	else
		dmasprintf(value, "%d", nbre_dmmaps);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "0" : "1";	
	return 0;
}

static int set_DHCPv4Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

static int get_DHCPv4Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4client_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4client_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_s = ((struct dhcp_client_args *)data)->dhcp_client_conf;

	char *linker = dmstrdup(dhcp_s ? section_name(dhcp_s) : "");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_DHCPv4Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_DHCP_Interface(ctx, value, ((struct dhcp_client_args *)data)->dhcp_client_conf, ((struct dhcp_client_args *)data)->dhcp_client_dm, "dmmap_dhcp_client", "dhcp", action);
}

/*#Device.DHCPv4.Client.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4Client_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv4.Client.{i}.DHCPStatus!UBUS:network.interface/status/interface,@Name/ipv4-address[@i-1].address*/
static int get_DHCPv4Client_DHCPStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_s = ((struct dhcp_client_args *)data)->dhcp_client_conf;
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dhcp_s ? section_name(dhcp_s) : "", String}}, 1, &res);
	DM_ASSERT(res, *value = "Requesting");
	json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
	char *ipaddr = dmjson_get_value(jobj, 1, "address");
	*value = (ipaddr[0] == '\0') ? "Requesting" : "Bound";
	return 0;
}

static int get_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dhcp_s = ((struct dhcp_client_args *)data)->dhcp_client_conf;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (!b) break;
			dmubus_call_set("network.interface", "renew", UBUS_ARGS{{"interface", dhcp_s ? section_name(dhcp_s) : "", String}}, 1);
			break;
	}
	return 0;
}

static int get_DHCPv4Client_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_args *)data)->ip);
	return 0;
}

static int get_DHCPv4Client_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_args *)data)->mask);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.IPRouters!UBUS:network.interface/status/interface,@Name/route[@i-1].nexthop*/
static int get_DHCPv4Client_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_s = ((struct dhcp_client_args *)data)->dhcp_client_conf;
	json_object *res = NULL, *route = NULL, *arrobj = NULL;
	unsigned pos = 0, idx = 0;
	char list_ip[256] = {0};

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dhcp_s ? section_name(dhcp_s) : "", String}}, 1, &res);
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
	return 0;
}

/*#Device.DHCPv4.Client.{i}.DNSServers!UBUS:network.interface/status/interface,@Name/dns-server*/
static int get_DHCPv4Client_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_s = ((struct dhcp_client_args *)data)->dhcp_client_conf;
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dhcp_s ? section_name(dhcp_s) : "", String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value_array_all(res, ",", 1, "dns-server");
	return 0;
}

/*#Device.DHCPv4.Client.{i}.LeaseTimeRemaining!UBUS:network.interface/status/interface,@Name/data.leasetime*/
static int get_DHCPv4Client_LeaseTimeRemaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dhcp_s = ((struct dhcp_client_args *)data)->dhcp_client_conf;
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", dhcp_s ? section_name(dhcp_s) : "", String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "data", "leasetime");
	return 0;
}

/*#Device.DHCPv4.Client.{i}.SentOptionNumberOfEntries!UCI:network/interface,@i-1/sendopts*/
static int get_DHCPv4Client_SentOptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *sendopts = NULL;
	size_t length = 0;

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "sendopts", &sendopts);
	if (sendopts && *sendopts)
		strsplit(sendopts, " ", &length);

	dmasprintf(value, "%d", length);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.ReqOptionNumberOfEntries!UCI:network/interface,@i-1/reqopts*/
static int get_DHCPv4Client_ReqOptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *reqopts = NULL;
	size_t length = 0;

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "reqopts", &reqopts);
	if (reqopts && *reqopts)
		strsplit(reqopts, " ", &length);

	dmasprintf(value, "%d", length);
	return 0;
}

static int get_DHCPv4ClientSentOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v, *opttagvalue = NULL;

	if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0) {
		*value = "0";
		return 0;
	}
	dmasprintf(&opttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
	if (elt_exits_in_str_list(v, opttagvalue))
		*value = "1";
	else
		*value = "0";

	return 0;
}

static int set_DHCPv4ClientSentOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *v, *opttagvalue= NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0)
				return 0;
			dmasprintf(&opttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			if (b) {
				if (!elt_exits_in_str_list(v, opttagvalue)) {
					add_elt_to_str_list(&v, opttagvalue);
					dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
				}
			} else {
				remove_elt_from_str_list(&v, opttagvalue);
				dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
			}
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_sentopt_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ClientSentOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_sentopt_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ClientSentOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch = NULL, *list, *v = NULL, *opttagvalue, **sendopts = NULL, *oldopttagvalue;
	size_t length;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			if (v == NULL)
				return 0;
			list = dmstrdup(v);
			for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				sendopts = strsplit(pch, ":", &length);
				if (strcmp(sendopts[0], value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			dmasprintf(&oldopttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			if (v != NULL && strlen(v) > 0)
				remove_elt_from_str_list(&v, oldopttagvalue);
			dmasprintf(&opttagvalue, "%s:%s", value, ((struct dhcp_client_option_args *)data)->value && strlen(((struct dhcp_client_option_args *)data)->value)>0 ? ((struct dhcp_client_option_args *)data)->value:"0");
			add_elt_to_str_list(&v, opttagvalue);
			dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_value = ((struct dhcp_client_option_args *)data)->value;
	char hex[256] = {0};

	if (tag_value && *tag_value)
		convert_string_to_hex(tag_value, hex);

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv4ClientSentOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *v, *opttagvalue, *oldopttagvalue;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			dmasprintf(&oldopttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			remove_elt_from_str_list(&v, oldopttagvalue);

			convert_hex_to_string(value, res);

			dmasprintf(&opttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, res);
			add_elt_to_str_list(&v, opttagvalue);
			dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "option_value", res);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;

	if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0) {
		*value = "0";
		return 0;
	}
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
	if (elt_exits_in_str_list(v, ((struct dhcp_client_option_args *)data)->option_tag))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv4ClientReqOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
			if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0)
				return 0;
			if (b) {
				if (!elt_exits_in_str_list(v, ((struct dhcp_client_option_args *)data)->option_tag)) {
					add_elt_to_str_list(&v,  ((struct dhcp_client_option_args *)data)->option_tag);
					dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", v);
				}
			} else {
				remove_elt_from_str_list(&v, ((struct dhcp_client_option_args *)data)->option_tag);
				dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", v);
			}
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_reqtopt_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ClientReqOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_reqtopt_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ClientReqOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch, *list, *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
			if (v == NULL)
				return 0;
			list = dmstrdup(v);
			for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				if(strcmp(pch, value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
			if (v != NULL && strlen(v) > 0)
				remove_elt_from_str_list(&v, ((struct dhcp_client_option_args *)data)->option_tag);
			add_elt_to_str_list(&v, value);
			dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", v);
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e = NULL;
	char **buf = NULL;
	size_t length;

	if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0) {
		*value = "0";
		return 0;
	}
	dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
	if (dhcp_option_list != NULL) {
		uci_foreach_element(dhcp_option_list, e) {
			buf = strsplit(e->name, ",", &length);
			if (buf && *buf && strcmp(buf[0], ((struct dhcp_client_option_args *)data)->option_tag) == 0) {
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
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e = NULL;
	char **buf = NULL, *opt_value;
	size_t length;
	bool test = false, b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0)
				return 0;
			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmasprintf(&opt_value, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			if (dhcp_option_list != NULL) {
				uci_foreach_element(dhcp_option_list, e) {
					buf = strsplit(e->name, ",", &length);
					if (buf && *buf && strcmp(buf[0], ((struct dhcp_client_option_args *)data)->option_tag) == 0) {
						test = true;
						if (!b)
							dmuci_del_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
						break;
					}
				}
			}
			if(!test && b)
				dmuci_add_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
	}
	return 0;
}

static int get_DHCPv4Server_PoolNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *ignore = NULL;
	int i = 0;

	uci_foreach_sections("dhcp", "dhcp", s) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(s, "ignore", &ignore);
		if (ignore && strcmp(ignore, "1") == 0)
			continue;

		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv4ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_servpool_option_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_servpool_option_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option = NULL, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			if (dhcp_option_list == NULL)
				return 0;
			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (option && *option && strcmp(option[0], value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", value, ((struct dhcp_client_option_args *)data)->value);
			dmuci_del_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const char *tag_value = ((struct dhcp_client_option_args *)data)->value;
	char hex[256] = {0};

	if (tag_value && *tag_value)
		convert_string_to_hex(tag_value, hex);

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv4ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option = NULL, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e = NULL;
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			if (dhcp_option_list == NULL)
				return 0;

			convert_hex_to_string(value, res);

			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (option && *option && strcmp(option[0], res) == 0)
					return FAULT_9007;
			}
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, res);
			dmuci_del_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			dmuci_set_value_by_section_bbfdm(((struct dhcp_client_option_args *)data)->opt_sect, "option_value", res);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4RelayForwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "0" : "1";
	return 0;
}

static int set_DHCPv4RelayForwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

static int get_DHCPv4RelayForwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4relay_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4RelayForwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4relay_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4RelayForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}
	char *linker = dmstrdup(section_name(((struct dhcp_client_args *)data)->dhcp_client_conf));
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", linker, value);
	return 0;
}

static int set_DHCPv4RelayForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return set_DHCP_Interface(ctx, value, ((struct dhcp_client_args *)data)->dhcp_client_conf, ((struct dhcp_client_args *)data)->dhcp_client_dm, "dmmap_dhcp_relay", "relay", action);
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.VendorClassID!UCI:network/interface,@i-1/vendorclass*/
static int get_DHCPv4RelayForwarding_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct dhcp_client_args *)data)->vendorclassidclassifier)
		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->vendorclassidclassifier, "vendorclass", value);
	return 0;
}

static int set_DHCPv4RelayForwarding_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 255, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if(((struct dhcp_client_args *)data)->vendorclassidclassifier)
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->vendorclassidclassifier, "vendorclass", value);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Chaddr!UCI:network/interface,@i-1/mac*/
static int get_DHCPv4RelayForwarding_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct dhcp_client_args *)data)->macclassifier == NULL) {
		*value = "";
		return 0;
	}

	return get_value_in_mac_format(((struct dhcp_client_args *)data)->macclassifier, "mac", false, value);
}

static int set_DHCPv4RelayForwarding_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.ChaddrMask!UCI:network/interface,@i-1/mac*/
static int get_DHCPv4RelayForwarding_ChaddrMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct dhcp_client_args *)data)->macclassifier == NULL) {
		*value= "";
		return 0;
	}

	return get_value_in_mac_format(((struct dhcp_client_args *)data)->macclassifier, "mac", true, value);
}

static int set_DHCPv4RelayForwarding_ChaddrMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_DHCPv4RelayForwarding_ChaddrExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_DHCPv4RelayForwarding_ChaddrExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.DHCPv4.Relay.Forwarding.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4RelayForwarding_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *disabled = NULL;
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &disabled);
	*value = (disabled[0] == '1') ? "Disabled" : "Enabled";
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.UserClassID!UCI:network/interface,@i-1/userclass*/
static int get_DHCPv4RelayForwarding_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char hex[256] = {0}, *ucid = NULL;

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->userclassclassifier, "userclass", &ucid);

	if (ucid && *ucid)
		convert_string_to_hex(ucid, hex);

	*value = (*hex) ? dmstrdup(hex) : "";
	return 0;
}

static int set_DHCPv4RelayForwarding_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char res[256] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			convert_hex_to_string(value, res);
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->userclassclassifier, "userclass", res);
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
			if (dm_validate_boolean(value))
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
	struct uci_section *s = NULL, *dmmap_sect = NULL;
	int nbre_confs = 0, nbre_dmmaps = 0;

	uci_foreach_option_eq("network", "interface", "proto", "relay", s) {
		nbre_confs++;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_dhcp_relay", "interface", dmmap_sect) {
		nbre_dmmaps++;
	}
	if (nbre_dmmaps == 0 || nbre_dmmaps < nbre_confs)
		dmasprintf(value, "%d", nbre_confs);
	else
		dmasprintf(value, "%d", nbre_dmmaps);
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.DHCPv4.Server.Pool.{i}.!UCI:dhcp/dhcp/dmmap_dhcp*/
static int browseDHCPv4ServerPoolInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ignore = NULL, *interface, *inst = NULL, *max_inst = NULL, *v;
	struct dhcp_args curr_dhcp_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(leases);
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_dhcp", &dup_list);

	if (!list_empty(&dup_list))
		dhcp_leases_load(&leases);

	list_for_each_entry(p, &dup_list, list) {

		// skip the section if option ignore = '1'
		dmuci_get_value_by_section_string(p->config_section, "ignore", &ignore);
		if (ignore && strcmp(ignore, "1") == 0)
			continue;

		dmuci_get_value_by_section_string(p->config_section, "interface", &interface);
		init_dhcp_args(&curr_dhcp_args, p->config_section, interface);

		dhcp_leases_assign_to_interface(&curr_dhcp_args, &leases, interface);

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "dhcp_instance", "dhcp_alias");

		dmuci_get_value_by_section_string(p->dmmap_section, "order", &v);
		if (v == NULL || strlen(v) == 0)
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
	char *inst = NULL, *max_inst = NULL;
	struct dhcp_host_args curr_dhcp_host_args = {0};
	struct browse_args browse_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("dhcp", "host", "dmmap_dhcp", "dhcp", ((struct dhcp_args *)prev_data)->interface, &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		// Skip all reserved hosts
		char *host_name = NULL;
		dmuci_get_value_by_section_string(p->config_section, "name", &host_name);
		if (host_name && strcmp(host_name, "reserved") == 0)
			continue;

		dmuci_set_value_by_section(p->dmmap_section, "dhcp", ((struct dhcp_args *)prev_data)->interface);
		init_args_dhcp_host(&curr_dhcp_host_args, ((struct dhcp_args *)prev_data)->dhcp_sec, p->config_section, ((struct dhcp_args *)prev_data)->interface);

		browse_args.option = "dhcp";
		browse_args.value = ((struct dhcp_args *)prev_data)->interface;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   p->dmmap_section, "dhcp_host_instance", "dhcp_host_alias",
			   check_browse_section, (void *)&browse_args);

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
		char *inst, *max_inst = NULL;

		init_dhcp_client_args(&client_args, lease);

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_without_section, 1, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&client_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDhcpClientIPv4Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *max_inst = NULL;

	char *inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, 1);
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, inst);
	return 0;
}

static int browseDHCPv4ServerPoolClientOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	FILE *f = fopen(DHCP_CLIENT_OPTIONS_FILE, "r");
	if (f == NULL)
		return 0;

	const struct client_args *args = (struct client_args *)prev_data;
	struct client_options_args curr_client_options_args = {0};
	char line[2048], macaddr[24], vcid[128], clid[128], ucid[128];
	char *inst = NULL, *max_inst = NULL;
	int id = 0;

	while (fgets(line, sizeof(line), f) != NULL) {
		remove_new_line(line);

		sscanf(line, "%23s vcid=%127s clid=%127s ucid=%127s",
				macaddr, vcid, clid, ucid);

		if (strncmp(macaddr, (char *)args->lease->hwaddr, 24) == 0) {

			if (strcmp(vcid, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "60", dmstrdup(vcid));

				inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}

			if (strcmp(clid, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "61", dmstrdup(clid));

				inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, ++id);

				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_client_options_args, inst) == DM_STOP)
					break;
			}


			if (strcmp(ucid, "-") != 0) {
				init_client_options_args(&curr_client_options_args, "77", dmstrdup(ucid));

				inst = handle_update_instance(3, dmctx, &max_inst, update_instance_without_section, 1, ++id);

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
	struct dhcp_client_args dhcp_client_arg = {0};
	char *inst = NULL, *max_inst = NULL;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_dhcp_client", "proto", "dhcp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		char *ipv4addr = NULL, *mask4 = NULL;

		dmuci_get_value_by_section_string(p->config_section, "ipaddr", &ipv4addr);
		dmuci_get_value_by_section_string(p->config_section, "netmask", &mask4);
		if (ipv4addr && ipv4addr[0] == '\0') {
			json_object *res = NULL;

			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
			if (res) {
				json_object *jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
				ipv4addr = dmjson_get_value(jobj, 1, "address");
				mask4 = dmjson_get_value(jobj, 1, "mask");
				mask4 = (mask4 && *mask4) ? cidr2netmask(atoi(mask4)) : "";
			}
		}

		dhcp_client_arg.dhcp_client_conf = p->config_section;
		dhcp_client_arg.dhcp_client_dm = p->dmmap_section;
		dhcp_client_arg.ip = dmstrdup(ipv4addr ? ipv4addr : "");
		dhcp_client_arg.mask = dmstrdup(mask4 ? mask4 : "");

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "bbf_dhcpv4client_instance", "bbf_dhcpv4client_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_arg, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseDHCPv4ClientSentOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)prev_data;
	struct uci_section *dmmap_sect;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};
	struct browse_args browse_args = {0};
	char *inst = NULL, *max_inst = NULL, *tag, *value, **sentopts = NULL, **buf = NULL, *tmp, *optionvalue, *v = NULL;
	size_t length = 0, lgh2 = 0;
	int i, j;

	if (dhcp_client_args->dhcp_client_conf != NULL)
		dmuci_get_value_by_section_string(dhcp_client_args->dhcp_client_conf, "sendopts", &v);

	if (v) sentopts = strsplit(v, " ", &length);
	for (i = 0; i < length; i++) {
		if (sentopts[i]) buf = strsplit(sentopts[i], ":", &lgh2);
		if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp_client", "send_option", section_name(dhcp_client_args->dhcp_client_conf), "option_tag", buf[0])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", buf[0]);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
		}
		optionvalue = dmstrdup(lgh2 > 1 ? buf[1] : "");
		if (lgh2 > 2) {
			for (j = 2; j < lgh2; j++) {
				tmp = dmstrdup(optionvalue);
				dmfree(optionvalue);
				optionvalue = NULL;
				dmasprintf(&optionvalue, "%s:%s", tmp, buf[j]);
				dmfree(tmp);
				tmp = NULL;
			}
		}
		dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_value", optionvalue);
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "send_option", "section_name", dhcp_client_args->dhcp_client_conf?section_name(dhcp_client_args->dhcp_client_conf):"", dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &tag);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &value);
		dhcp_client_opt_args.client_sect = dhcp_client_args->dhcp_client_conf;
		dhcp_client_opt_args.option_tag = dmstrdup(tag);
		dhcp_client_opt_args.value = dmstrdup(value);
		dhcp_client_opt_args.opt_sect = dmmap_sect;

		browse_args.option = "section_name";
		browse_args.value = section_name(dhcp_client_args->dhcp_client_conf);

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   dmmap_sect, "bbf_dhcpv4_sentopt_instance", "bbf_dhcpv4_sentopt_alias",
			   check_browse_section, (void *)&browse_args);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ClientReqOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)prev_data;
	struct uci_section *dmmap_sect;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};
	struct browse_args browse_args = {0};
	char *inst = NULL, *max_inst = NULL, *tag, **reqtopts = NULL, *v = NULL;
	size_t length = 0;
	int i;

	if (dhcp_client_args->dhcp_client_conf != NULL)
		dmuci_get_value_by_section_string(dhcp_client_args->dhcp_client_conf, "reqopts", &v);
	if (v) reqtopts = strsplit(v, " ", &length);
	for (i = 0; i < length; i++) {
		if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp_client", "req_option", section_name(dhcp_client_args->dhcp_client_conf), "option_tag", reqtopts[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_dhcp_client", "req_option", &dmmap_sect);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", reqtopts[i]);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "req_option", "section_name", dhcp_client_args->dhcp_client_conf?section_name(dhcp_client_args->dhcp_client_conf):"", dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &tag);
		dhcp_client_opt_args.client_sect = dhcp_client_args->dhcp_client_conf;
		dhcp_client_opt_args.option_tag = dmstrdup(tag);
		dhcp_client_opt_args.value = dmstrdup("");
		dhcp_client_opt_args.opt_sect = dmmap_sect;

		browse_args.option = "section_name";
		browse_args.value = section_name(dhcp_client_args->dhcp_client_conf);

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   dmmap_sect, "bbf_dhcpv4_reqtopt_instance", "bbf_dhcpv4_reqtopt_alias",
			   check_browse_section, (void *)&browse_args);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ServerPoolOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e = NULL;
	struct dhcp_args *curr_dhcp_args = (struct dhcp_args*)prev_data;
	struct uci_section *dmmap_sect = NULL;
	struct browse_args browse_args = {0};
	char **tagvalue = NULL, *inst = NULL, *max_inst = NULL, *optionvalue = NULL, *tmp = NULL, *dhcpv4_tag, *dhcpv4_value;
	size_t length = 0;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};

	dmuci_get_value_by_section_list(curr_dhcp_args->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			tagvalue = strsplit(e->name, ",", &length);
			if (!tagvalue)
				continue;

			if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp", "servpool_option", section_name(curr_dhcp_args->dhcp_sec), "option_tag", tagvalue[0])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp", "servpool_option", &dmmap_sect);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_tag", tagvalue[0]);
				dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(curr_dhcp_args->dhcp_sec));
			}
			optionvalue = dmstrdup(length > 1 ? tagvalue[1] : "");
			if (length > 2) {
				int j;

				for (j = 2; j < length; j++) {
					tmp = dmstrdup(optionvalue);
					dmfree(optionvalue);
					optionvalue = NULL;
					dmasprintf(&optionvalue, "%s,%s", tmp, tagvalue[j]);
					dmfree(tmp);
					tmp = NULL;
				}
			}
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "option_value", optionvalue);
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp", "servpool_option", "section_name", section_name(curr_dhcp_args->dhcp_sec), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &dhcpv4_tag);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &dhcpv4_value);

		dhcp_client_opt_args.client_sect = curr_dhcp_args->dhcp_sec;
		dhcp_client_opt_args.opt_sect = dmmap_sect;
		dhcp_client_opt_args.option_tag = dhcpv4_tag;
		dhcp_client_opt_args.value = dhcpv4_value;

		browse_args.option = "section_name";
		browse_args.value = section_name(curr_dhcp_args->dhcp_sec);

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   dmmap_sect, "bbf_dhcpv4_servpool_option_instance", "bbf_dhcpv4_servpool_option_alias",
			   check_browse_section, (void *)&browse_args);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_client_opt_args, inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.!UCI:network/interface/dmmap_dhcp_relay*/
static int browseDHCPv4RelayForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *relay_ipv4addr = NULL, *relay_mask4 = NULL;
	char *inst = NULL, *max_inst = NULL, *relay_network = NULL, *dhcp_network = NULL;
	struct dmmap_dup *p = NULL;
	json_object *res, *jobj;
	struct dhcp_client_args dhcp_relay_arg = {0};
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_dhcp_relay", "proto", "relay", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "ipaddr", &relay_ipv4addr);
		dmuci_get_value_by_section_string(p->config_section, "netmask", &relay_mask4);
		if (relay_ipv4addr && *relay_ipv4addr) {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
			if (res) {
				jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
				relay_ipv4addr = dmjson_get_value(jobj, 1, "address");
				relay_mask4 = dmjson_get_value(jobj, 1, "mask");
				relay_mask4 = (relay_mask4 && *relay_mask4) ? cidr2netmask(atoi(relay_mask4)) : "";
			}
		}

		dhcp_relay_arg.dhcp_client_conf = p->config_section;
		dhcp_relay_arg.dhcp_client_dm = p->dmmap_section;
		dhcp_relay_arg.ip = dmstrdup(relay_ipv4addr ? relay_ipv4addr : "");
		dhcp_relay_arg.mask = dmstrdup(relay_mask4 ? relay_mask4 : "");

		dmuci_get_value_by_section_string(p->config_section, "network", &relay_network);
		dhcp_network = get_dhcp_network_from_relay_list(relay_network);

		dhcp_relay_arg.macclassifier = (dhcp_network && *dhcp_network) ? get_dhcp_classifier("mac", dhcp_network) : NULL;
		dhcp_relay_arg.vendorclassidclassifier = (dhcp_network && *dhcp_network) ? get_dhcp_classifier("vendorclass", dhcp_network) : NULL;
		dhcp_relay_arg.userclassclassifier = (dhcp_network && *dhcp_network) ? get_dhcp_classifier("userclass", dhcp_network) : NULL;

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
			   p->dmmap_section, "bbf_dhcpv4relay_instance", "bbf_dhcpv4relay_alias");

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&dhcp_relay_arg, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.DHCPv4. *** */
DMOBJ tDHCPv4Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Client", &DMWRITE, addObjDHCPv4Client, delObjDHCPv4Client, NULL, browseDHCPv4ClientInst, NULL, tDHCPv4ClientObj, tDHCPv4ClientParams, NULL, BBFDM_BOTH, LIST_KEY{"Interface", "Alias", NULL}},
{"Server", &DMREAD, NULL, NULL, NULL, NULL, NULL, tDHCPv4ServerObj, tDHCPv4ServerParams, NULL, BBFDM_BOTH},
{"Relay", &DMREAD, NULL, NULL, NULL, NULL, NULL, tDHCPv4RelayObj, tDHCPv4RelayParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv4Params[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}. *** */
DMOBJ tDHCPv4ClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"SentOption", &DMWRITE, addObjDHCPv4ClientSentOption, delObjDHCPv4ClientSentOption, NULL, browseDHCPv4ClientSentOptionInst, NULL, NULL, tDHCPv4ClientSentOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{"ReqOption", &DMWRITE, addObjDHCPv4ClientReqOption, delObjDHCPv4ClientReqOption, NULL, browseDHCPv4ClientReqOptionInst, NULL, NULL, tDHCPv4ClientReqOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{0}
};

DMLEAF tDHCPv4ClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
{0}
};

/* *** Device.DHCPv4.Client.{i}.SentOption.{i}. *** */
DMLEAF tDHCPv4ClientSentOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ClientSentOption_Enable, set_DHCPv4ClientSentOption_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ClientSentOption_Alias, set_DHCPv4ClientSentOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ClientSentOption_Tag, set_DHCPv4ClientSentOption_Tag, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv4ClientSentOption_Value, set_DHCPv4ClientSentOption_Value, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}.ReqOption.{i}. *** */
DMLEAF tDHCPv4ClientReqOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ClientReqOption_Enable, set_DHCPv4ClientReqOption_Enable, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_DHCPv4ClientReqOption_Order, set_DHCPv4ClientReqOption_Order, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ClientReqOption_Alias, set_DHCPv4ClientReqOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ClientReqOption_Tag, set_DHCPv4ClientReqOption_Tag, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv4ClientReqOption_Value, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server. *** */
DMOBJ tDHCPv4ServerObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Pool", &DMWRITE, addObjDHCPv4ServerPool, delObjDHCPv4ServerPool, NULL, browseDHCPv4ServerPoolInst, NULL, tDHCPv4ServerPoolObj, tDHCPv4ServerPoolParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tDHCPv4ServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Server_Enable, set_DHCPv4Server_Enable, BBFDM_BOTH},
{"PoolNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Server_PoolNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}. *** */
DMOBJ tDHCPv4ServerPoolObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"StaticAddress", &DMWRITE, addObjDHCPv4ServerPoolStaticAddress, delObjDHCPv4ServerPoolStaticAddress, NULL, browseDHCPv4ServerPoolStaticAddressInst, NULL, NULL, tDHCPv4ServerPoolStaticAddressParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", "Chaddr", NULL}},
{"Option", &DMWRITE, addObjDHCPv4ServerPoolOption, delObjDHCPv4ServerPoolOption, NULL, browseDHCPv4ServerPoolOptionInst, NULL, NULL, tDHCPv4ServerPoolOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", "Alias", NULL}},
{"Client", &DMREAD, NULL, NULL, NULL, browseDhcpClientInst, NULL, tDHCPv4ServerPoolClientObj, tDHCPv4ServerPoolClientParams, get_dhcp_client_linker, BBFDM_BOTH, LIST_KEY{"Chaddr", "Alias", NULL}},
{0}
};

DMLEAF tDHCPv4ServerPoolParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
//{"AllowedDevices", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_AllowedDevices, set_DHCPv4ServerPool_AllowedDevices, BBFDM_BOTH},
{"MinAddress", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_MinAddress, set_DHCPv4ServerPool_MinAddress, BBFDM_BOTH},
{"MaxAddress", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_MaxAddress, set_DHCPv4ServerPool_MaxAddress, BBFDM_BOTH},
{"ReservedAddresses", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_ReservedAddresses, set_DHCPv4ServerPool_ReservedAddresses, BBFDM_BOTH},
{"SubnetMask", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_SubnetMask, set_DHCPv4ServerPool_SubnetMask, BBFDM_BOTH},
{"DNSServers", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_DNSServers, set_DHCPv4ServerPool_DNSServers, BBFDM_BOTH},
{"DomainName", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_DomainName, set_DHCPv4ServerPool_DomainName, BBFDM_BOTH},
{"IPRouters", &DMWRITE, DMT_STRING, get_DHCPv4ServerPool_IPRouters, set_DHCPv4ServerPool_IPRouters, BBFDM_BOTH},
{"LeaseTime", &DMWRITE, DMT_INT, get_DHCPv4ServerPool_LeaseTime, set_DHCPv4ServerPool_LeaseTime, BBFDM_BOTH},
{"StaticAddressNumberOfEntries", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPool_StaticAddressNumberOfEntries, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPool_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{"ClientNumberOfEntries", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPool_ClientNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}. *** */
DMLEAF tDHCPv4ServerPoolStaticAddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPoolStaticAddress_Enable, set_DHCPv4ServerPoolStaticAddress_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolStaticAddress_Alias, set_DHCPv4ServerPoolStaticAddress_Alias, BBFDM_BOTH},
{"Chaddr", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolStaticAddress_Chaddr, set_DHCPv4ServerPoolStaticAddress_Chaddr, BBFDM_BOTH},
{"Yiaddr", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolStaticAddress_Yiaddr, set_DHCPv4ServerPoolStaticAddress_Yiaddr, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Option.{i}. *** */
DMLEAF tDHCPv4ServerPoolOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPoolOption_Enable, set_DHCPv4ServerPoolOption_Enable, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolOption_Alias, set_DHCPv4ServerPoolOption_Alias, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPoolOption_Tag, set_DHCPv4ServerPoolOption_Tag, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv4ServerPoolOption_Value, set_DHCPv4ServerPoolOption_Value, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}. *** */
DMOBJ tDHCPv4ServerPoolClientObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseDhcpClientIPv4Inst, NULL, NULL, tDHCPv4ServerPoolClientIPv4AddressParams, NULL, BBFDM_BOTH, LIST_KEY{"IPAddress", NULL}},
{"Option", &DMREAD, NULL, NULL, NULL, browseDHCPv4ServerPoolClientOptionInst, NULL, NULL, tDHCPv4ServerPoolClientOptionParams, NULL, BBFDM_BOTH, LIST_KEY{"Tag", NULL}},
{0}
};

DMLEAF tDHCPv4ServerPoolClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING,  get_DHCPv4ServerPoolClient_Alias, set_DHCPv4ServerPoolClient_Alias, BBFDM_BOTH},
{"Chaddr", &DMREAD, DMT_STRING,  get_DHCPv4ServerPoolClient_Chaddr, NULL, BBFDM_BOTH},
{"Active", &DMREAD, DMT_BOOL,  get_DHCPv4ServerPoolClient_Active, NULL, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClient_IPv4AddressNumberOfEntries, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClient_OptionNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}. *** */
DMLEAF tDHCPv4ServerPoolClientIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv4ServerPoolClientIPv4Address_IPAddress, NULL, BBFDM_BOTH},
{"LeaseTimeRemaining", &DMREAD, DMT_TIME, get_DHCPv4ServerPoolClientIPv4Address_LeaseTimeRemaining, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}. *** */
DMLEAF tDHCPv4ServerPoolClientOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Tag", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClientOption_Tag, NULL, BBFDM_BOTH},
{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv4ServerPoolClientOption_Value, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Relay. *** */
DMOBJ tDHCPv4RelayObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Forwarding", &DMWRITE, addObjDHCPv4RelayForwarding, delObjDHCPv4RelayForwarding, NULL, browseDHCPv4RelayForwardingInst,  NULL, NULL, tDHCPv4RelayForwardingParams, NULL, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
{0}
};

DMLEAF tDHCPv4RelayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Relay_Enable, set_DHCPv4Relay_Enable, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4Relay_Status, NULL, BBFDM_BOTH},
{"ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Relay_ForwardingNumberOfEntries, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Relay.Forwarding.{i}. *** */
DMLEAF tDHCPv4RelayForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
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
{"ChaddrMask", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_ChaddrMask, set_DHCPv4RelayForwarding_ChaddrMask, BBFDM_BOTH},
{"ChaddrExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_ChaddrExclude, set_DHCPv4RelayForwarding_ChaddrExclude, BBFDM_BOTH},
//{"LocallyServed", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_LocallyServed, set_DHCPv4RelayForwarding_LocallyServed, BBFDM_BOTH},
//{"DHCPServerIPAddress", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_DHCPServerIPAddress, set_DHCPv4RelayForwarding_DHCPServerIPAddress, BBFDM_BOTH},
{0}
};
