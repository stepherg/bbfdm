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
	char *ifname;
	char *br_inst;
	bool is_dmmap_sec;
};

struct bridge_port_args
{
	struct uci_section *bridge_port_sec;
	struct uci_section *bridge_port_dmmap_sec;
	struct uci_section *bridge_sec;
	char *ifname;
	char *br_inst;
	bool is_dmmap_sec;
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
	bool is_dmmap_sec;
};

struct provider_bridge_args
{
	struct uci_section *dmmap_bridge_sec;
	char *br_inst;
};

/**************************************************************************
* LINKER FUNCTIONS
***************************************************************************/
static int get_linker_br_port(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct bridge_port_args *)data)->bridge_port_dmmap_sec)
		dmasprintf(linker, "br_%s:%s+%s", ((struct bridge_port_args *)data)->br_inst, section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), ((struct bridge_port_args *)data)->ifname);
	else
		*linker = "";
	return 0;
}

static int get_linker_br_vlan(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data&& ((struct bridge_vlan_args *)data)->bridge_vlan_sec) {
		char *vid;
		dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &vid);
		dmasprintf(linker, "br_%s:vlan_%s", ((struct bridge_vlan_args *)data)->br_inst, vid);
	} else
		*linker = "";
	return 0;
}

/*
 * The following get_linker_bridge function returns the instance number of bridge if it exists else it returns an empty string.
 * Used to validate the existance of a bridge instance while setting svlan/cvlan components of provider bridge.
 *
 */
static int get_linker_bridge(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct bridge_args *)data)->bridge_sec)
		dmasprintf(linker, "%s", ((struct bridge_args *)data)->br_inst);
	else
		*linker = "";
	return 0;
}

/**************************************************************************
* INIT FUNCTIONS
***************************************************************************/
static inline int init_bridging_args(struct bridge_args *args, struct uci_section *s, char *ifname, char *br_instance, bool is_dmmap_sec)
{
	args->bridge_sec = s;
	args->ifname = ifname;
	args->br_inst = br_instance;
	args->is_dmmap_sec = is_dmmap_sec;
	return 0;
}

static inline int init_bridge_port_args(struct bridge_port_args *args, struct uci_section *device_s, struct uci_section *dmmap_s, struct uci_section *bs, char *ifname, char *br_inst, bool is_dmmap_sec)
{
	args->bridge_port_sec = device_s;
	args->bridge_port_dmmap_sec = dmmap_s;
	args->bridge_sec = bs;
	args->ifname = ifname;
	args->br_inst = br_inst;
	args->is_dmmap_sec = is_dmmap_sec;
	return 0;
}

static inline int init_bridge_vlanport_args(struct bridge_vlanport_args *args, struct uci_section *device_s, struct uci_section *dmmap_s, struct uci_section *bs, char *br_inst)
{
	args->bridge_vlanport_sec = device_s;
	args->bridge_vlanport_dmmap_sec = dmmap_s;
	args->bridge_sec = bs;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_vlan_args(struct bridge_vlan_args *args, struct uci_section *s, struct uci_section *bs, char *br_inst, bool is_dmmap_sec)
{
	args->bridge_vlan_sec = s;
	args->bridge_sec = bs;
	args->br_inst = br_inst;
	args->is_dmmap_sec = is_dmmap_sec;
	return 0;
}

static inline int init_provider_bridge_args(struct provider_bridge_args *args, struct uci_section *s, char *br_instance)
{
	args->dmmap_bridge_sec = s;
	args->br_inst = br_instance;
	return 0;
}

/**************************************************************************
* COMMON FUNCTIONS
***************************************************************************/
static void remove_interface_from_ifname(char *iface, char *ifname, char *new_ifname)
{
	char *pch, *spch, *p = new_ifname;
	new_ifname[0] = '\0';

	ifname = dmstrdup(ifname);
	pch = strtok_r(ifname, " ", &spch);
	while (pch != NULL) {
		if (strcmp(pch, iface) != 0) {
			if (p == new_ifname) {
				dmstrappendstr(p, pch);
			} else {
				dmstrappendchr(p, ' ');
				dmstrappendstr(p, pch);
			}
		}
		pch = strtok_r(NULL, " ", &spch);
	}
	dmstrappendend(p);
	dmfree(ifname);
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

static int check_ifname_exist_in_br_ifname_list(char *ifname, char *s_name)
{
	char *br_ifname_list, *pch, *spch;
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		if (strcmp(section_name(s), s_name) != 0)
			continue;

		dmuci_get_value_by_section_string(s, "ifname", &br_ifname_list);
		if (br_ifname_list[0] == '\0')
			return 0;

		for (pch = strtok_r(br_ifname_list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			if (strncmp(ifname, pch, 4) == 0) {
				return 1;
			}
		}
	}
	return 0;
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

char *get_last_instance_bridge_bbfdm(char* dmmap_package, char *section, char *opt_inst)
{
	struct uci_section *s = NULL;
	char *instance = NULL, *last_inst = NULL;

	// traverse all bridge config and return the last instance of bridge
	uci_path_foreach_sections(bbfdm, dmmap_package, section, s) {
		instance = update_instance(last_inst, 2, s, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(instance);
	}
	return instance;
}

static int update_bridge_ifname(struct uci_section *br_sec, struct uci_section *sec, int status)
{
	char ifname_dup[128], *ptr, *baseifname, *ifname, *start, *end;
	int pos = 0;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	dmuci_get_value_by_section_string(sec, "name", &baseifname);
	ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (status) {
		if (is_strword_in_optionvalue(ifname_dup, baseifname)) return 0;
		if (ifname_dup[0] != '\0') dmstrappendchr(ptr, ' ');
		dmstrappendstr(ptr, baseifname);
		dmstrappendend(ptr);
	} else {
		if (is_strword_in_optionvalue(ifname_dup, baseifname)) {
			start = strstr(ifname_dup, baseifname);
			end = start + strlen(baseifname);
			if (start != ifname_dup) {
				start--;
				pos=1;
			}
			memmove(start, start + strlen(baseifname)+pos, strlen(end) + 1);
		}
	}

	dmuci_set_value_by_section(br_sec, "ifname", ifname_dup);
	return 0;
}

static int remove_ifname_from_bridge_section(struct uci_section *br_sec, char *baseifname)
{
	char ifname_dup[128] = {0}, *ifname = NULL, *start = NULL, *end = NULL;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	char *ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (is_strword_in_optionvalue(ifname_dup, baseifname)) {
		int pos = 0;

		start = strstr(ifname_dup, baseifname);
		end = start + strlen(baseifname);
		if (start != ifname_dup) {
			start--;
			pos=1;
		}
		memmove(start, start + strlen(baseifname)+pos, strlen(end) + 1);
	}

	dmuci_set_value_by_section(br_sec, "ifname", ifname_dup);
	return 0;
}

static int add_new_ifname_to_bridge_section(struct uci_section *br_sec, char *new_ifname)
{
	char ifname_dup[128] = {0}, *ifname = NULL;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	char *ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (is_strword_in_optionvalue(ifname_dup, new_ifname)) return 0;
	if (ifname_dup[0] != '\0') dmstrappendchr(ptr, ' ');
	dmstrappendstr(ptr, new_ifname);
	dmstrappendend(ptr);

	dmuci_set_value_by_section(br_sec, "ifname", ifname_dup);
	return 0;
}

static int is_bridge_vlan_vid_exist(char *br_inst, char *vid)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_inst, s) {
		char *s_vid;
		dmuci_get_value_by_section_string(s, "vid", &s_vid);
		if (strcmp(s_vid, vid) == 0)
			return 1;
	}
	return 0;
}

static int dmmap_synchronizeBridgingBridgeVLAN(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	char *br_ifname = NULL, *pch = NULL, *spch = NULL, *sec_name = NULL;
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (strcmp(s_user, "1") == 0)
			continue;

		// vid is available in ifname list ==> skip it
		char *vid;
		dmuci_get_value_by_section_string(s, "vid", &vid);
		if (dm_strword(br_args->ifname, vid) != NULL)
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	if (br_args->ifname[0] == '\0')
		return 0;

	br_ifname = dmstrdup(br_args->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		uci_foreach_option_eq("network", "device", "name", pch, ss) {
			char *vid;
			dmuci_get_value_by_section_string(ss, "vid", &vid);

			if (vid[0] == '\0') {
				char *ifname = strchr(pch, '.');
				if (ifname) vid = dmstrdup(ifname+1);
			}

			if (vid[0] == '\0') break;

			if (is_bridge_vlan_vid_exist(br_args->br_inst, vid)) break;

			struct uci_section *sbr_vlan = NULL;
			dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &sbr_vlan);
			dmuci_set_value_by_section(sbr_vlan, "vid", vid);
			dmuci_set_value_by_section(sbr_vlan, "br_inst", br_args->br_inst);
			if (br_args->is_dmmap_sec == true) {
				dmuci_get_value_by_section_string(br_args->bridge_sec, "section_name", &sec_name);
				dmuci_set_value_by_section(sbr_vlan, "interface", sec_name);
			} else {
				dmuci_set_value_by_section(sbr_vlan, "interface", section_name(br_args->bridge_sec));
			}
		}
	}
	dmfree(br_ifname);
	return 0;
}

static int is_bridge_vlanport_device_exist(char *br_inst, char *name)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_inst, s) {
		char *s_name;
		dmuci_get_value_by_section_string(s, "name", &s_name);
		if (strcmp(s_name, name) == 0)
			return 1;
	}
	return 0;
}

static int is_bridge_present(char *ifname)
{
	// function to check if a bridge is present or not nased on option ifname.
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge", "bridge", "ifname", ifname, s) {
		return 1;
	}
	return 0;
}

static int dmmap_synchronizeBridgingBridgeVLANPort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	char *br_ifname = NULL, *pch = NULL, *spch = NULL;
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL;

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (strcmp(s_user, "1") == 0)
			continue;

		// device is available in ifname list ==> skip it
		char *name;
		dmuci_get_value_by_section_string(s, "name", &name);
		if (dm_strword(br_args->ifname, name) != NULL)
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	if (br_args->ifname[0] == '\0')
		return 0;

	br_ifname = dmstrdup(br_args->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		uci_foreach_option_eq("network", "device", "name", pch, ss) {

			if (is_bridge_vlanport_device_exist(br_args->br_inst, pch))
				break;

			struct uci_section *sbr_vlanport = NULL;
			dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &sbr_vlanport);
			dmuci_set_value_by_section(sbr_vlanport, "name", pch);
			dmuci_set_value_by_section(sbr_vlanport, "br_inst", br_args->br_inst);
			dmuci_set_value_by_section(sbr_vlanport, "device_name", section_name(ss));
		}
	}
	dmfree(br_ifname);
	return 0;
}

static void sync_bridge_config_sections_with_dmmap_bridge_eq(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list)
{
	/*
	 * In this function;
	 * 1) sync bridges in network uci file to dmmap_bridge file
	 * 2) Don't Delete unused section from dmmap_bridge as it may not be in network uci but the bridge may still exist as cvlan/svaln bridge
	 * 3) Copy ifname of bridges in dmmap_bridge file
	 * 4) Now traverse the dmmap_bridge file and create a link list
	 */
	struct uci_section *s = NULL, *dmmap_sect = NULL, *ss = NULL;
	char *ifname, *section_name;

	uci_foreach_option_eq(package, section_type, option_name, option_value, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 * If the section belong to provider bridge (section name: pr_br_{i}) then skip adding to dmmap_package
		 */
		if (strncmp(section_name(s), "pr_br_", 6) == 0)
			continue;

		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, "bridge", section_name(s))) == NULL) {
			// Update dmmap_bridge
			dmuci_add_section_bbfdm(dmmap_package, "bridge", &dmmap_sect);
			dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));
			dmuci_get_value_by_section_string(s, "ifname", &ifname);
			dmuci_set_value_by_section(dmmap_sect, "ifname", ifname);
		}
	}

	/*
	 * Add system and dmmap sections to the list
	 */
	uci_path_foreach_sections(bbfdm, dmmap_package, "bridge", dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &section_name);
		ss = get_origin_section_from_config(package, section_type, section_name);
		add_dmmap_config_dup_list(dup_list, (ss == NULL) ? dmmap_sect : ss, dmmap_sect, NULL);
	}
}

void dmmap_synchronizeBridgingProviderBridge()
{
	struct uci_section *s = NULL, *dmmap_br_sec, *dmmap_pr_br_sec;
	char *ifname;

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		/*
		 * If the section belong to provider bridge (section name: pr_br_{i}) then proceed, else continue
		 */
		if (strncmp(section_name(s), "pr_br_", 6) != 0)
			continue;
		/*
		 * At this point we have a provider bridge sec from network file.
		 * If corresponding dmmap section is present in dmmap_provider_bridge then continue.
		 *
		 * Else,
		 * 1) Get its ifname - member device(s) of bridges.
		 * 2) Extract svlan and cvlan bridge component.
		 * 3) Sync. dmmap provider bridge section and create svlan/cvlan bridge in dmmap_bridge, if not present.
		 */

		if ((dmmap_pr_br_sec = get_dup_section_in_dmmap("dmmap_provider_bridge", "provider_bridge", section_name(s))) != NULL) {
			continue;
		}

		char *pch, *spch;
		struct uci_section *ss = NULL;
		char svlan_device[128], cvlan_device[128], bridge_name[50];
		char *ptr_cvlan = cvlan_device;
		char *last_inst_dmmap;
		char current_inst[16], pr_br_alias[32];

		// 1) Get its ifname - member device(s) of bridges.
		dmuci_get_value_by_section_string(s, "ifname", &ifname);

		// 2) Extract svlan and cvlan bridge component.
		for (pch = strtok_r(ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			uci_foreach_option_eq("network", "device", "name", pch, ss) {
				char *type;
				dmuci_get_value_by_section_string(ss, "type", &type);

				// If type is 8021ad, add to svlan
				if (strcmp(type,"8021ad") == 0) {
					DM_STRNCPY(svlan_device, pch, sizeof(svlan_device));
				}
				// If type is 8021q, add to cvlan
				if (strcmp(type,"8021q") == 0) {
					dmstrappendstr(ptr_cvlan, pch);
					dmstrappendchr(ptr_cvlan, ' ');
				}
			}
		}
		ptr_cvlan = ptr_cvlan -1;
		dmstrappendend(ptr_cvlan);

		// 3) Sync. dmmap provider bridge section and create svlan/cvlan bridge in dmmap_bridge, if not present.

		last_inst_dmmap = get_last_instance_bridge_bbfdm("dmmap_provider_bridge", "provider_bridge", "provider_bridge_instance");
		dmuci_add_section_bbfdm("dmmap_provider_bridge", "provider_bridge", &dmmap_pr_br_sec);
		snprintf(current_inst, sizeof(current_inst), "%d", last_inst_dmmap ? atoi(last_inst_dmmap)+1 : 1);
		snprintf(pr_br_alias, sizeof(pr_br_alias), "cpe-%d", last_inst_dmmap ? atoi(last_inst_dmmap)+1 : 1);
		dmuci_set_value_by_section(dmmap_pr_br_sec, "provider_bridge_instance", current_inst);
		dmuci_set_value_by_section(dmmap_pr_br_sec, "provider_bridge_alias", pr_br_alias);
		dmuci_set_value_by_section(dmmap_pr_br_sec, "section_name", section_name(s));
		dmuci_set_value_by_section(dmmap_pr_br_sec, "enable", "1");
		dmuci_set_value_by_section(dmmap_pr_br_sec, "type", "S-VLAN");

		if (is_bridge_present(svlan_device) == 0) {
			last_inst_dmmap = get_last_instance_bridge_bbfdm("dmmap_bridge", "bridge", "bridge_instance");
			snprintf(current_inst, sizeof(current_inst), "%d", last_inst_dmmap ? atoi(last_inst_dmmap)+1 : 1);
			snprintf(bridge_name, sizeof(bridge_name), "bridge_%d", last_inst_dmmap ? atoi(last_inst_dmmap)+1 : 1);
			dmuci_add_section_bbfdm("dmmap_bridge", "bridge", &dmmap_br_sec);
			dmuci_set_value_by_section(dmmap_br_sec, "section_name", bridge_name);
			dmuci_set_value_by_section(dmmap_br_sec, "ifname", svlan_device);
			dmuci_set_value_by_section(dmmap_br_sec, "bridge_instance", current_inst);
			// Add svlan instance to provider bridge
			dmuci_set_value_by_section(dmmap_pr_br_sec, "svlan_br_inst", current_inst);
		}
		if (is_bridge_present(cvlan_device) == 0) {
			last_inst_dmmap = get_last_instance_bridge_bbfdm("dmmap_bridge", "bridge", "bridge_instance");
			snprintf(current_inst, sizeof(current_inst), "%d", last_inst_dmmap ? atoi(last_inst_dmmap)+1 : 1);
			snprintf(bridge_name, sizeof(bridge_name), "bridge_%d", last_inst_dmmap ? atoi(last_inst_dmmap)+1 : 1);
			dmuci_add_section_bbfdm("dmmap_bridge", "bridge", &dmmap_br_sec);
			dmuci_set_value_by_section(dmmap_br_sec, "section_name", bridge_name);
			dmuci_set_value_by_section(dmmap_br_sec, "ifname", cvlan_device);
			dmuci_set_value_by_section(dmmap_br_sec, "bridge_instance", current_inst);
			// Add cvlan instance to provider bridge
			dmuci_add_list_value_by_section(dmmap_pr_br_sec, "cvlan_br_inst", current_inst);
		}
	}
}

static int is_bridge_port_device_exist(char *br_inst, char *name, struct uci_section **dmmap_br_port)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *s_name;
		dmuci_get_value_by_section_string(s, "device", &s_name);
		if (strcmp(s_name, name) == 0) {
			*dmmap_br_port = s;
			return 1;
		}
	}
	return 0;
}

static int is_bridge_port_management_in_dmmap(char *br_inst)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "1") == 0)
			return 1;
	}
	return 0;
}

static int is_wireless_ifname_exist(char *br_section_name, char *ifname)
{
	struct uci_section *s = NULL;
	uci_foreach_option_eq("wireless", "wifi-iface", "network", br_section_name, s) {

		// get ifname from wireless/wifi-iface section
		char *curr_ifname;
		dmuci_get_value_by_section_string(s, "ifname", &curr_ifname);
		if (strcmp(curr_ifname, ifname) == 0)
			return 1;
	}
	return 0;
}

static int is_bridge_pr_br_member(char *br_inst, char **pr_br_inst)
{
	struct uci_section *sec = NULL;
	char *svlan;
	struct uci_list *v = NULL;
	struct uci_element *e = NULL;
	// Return provider bridge inst. if passed bridge inst. is a member of provider bridge
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", sec) {
		// Check if the passed bridge section is svlan
		svlan = NULL;
		dmuci_get_value_by_section_string(sec, "svlan_br_inst", &svlan);
		if (svlan != NULL) {
			if (strcmp(svlan, br_inst) == 0) {
				// Get provider bridge instance
				dmuci_get_value_by_section_string(sec, "provider_bridge_instance", pr_br_inst);
				return 1;
			}
		}

		// Check if the passed bridge section is cvlan
		dmuci_get_value_by_section_list(sec, "cvlan_br_inst", &v);
		if (v != NULL) {
			bool found = false;

			uci_foreach_element(v, e) {
				if (strcmp(e->name, br_inst) == 0) {
					found = true;
					break;
				}
			}
			if (found == true) {
				// Get provider bridge instance
				dmuci_get_value_by_section_string(sec, "provider_bridge_instance", pr_br_inst);
				return 1;
			}
		}
	}
	return 0;
}

static void set_linker_bridge_port_management(char *br_inst, char *linker)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "1") == 0) {
			dmuci_set_value_by_section(s, "device", linker);
			return;
		}
	}
}

static int dmmap_synchronizeBridgingBridgePort(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL, *stmp = NULL, *dmmap_br_port = NULL;
	char *br_ifname = NULL, *pch = NULL, *spch = NULL, *p, plinker[32];
	char *linker_buf;
	char *sec_name = "";

	if (br_args->bridge_sec == NULL)
		return 0;

	// if the bridge section is dmmap_sec then get section_name option value
	if (br_args->is_dmmap_sec == true)
		dmuci_get_value_by_section_string(br_args->bridge_sec, "section_name", &sec_name);

	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, stmp, s) {

		// section added by user ==> skip it
		char *s_user;
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (strcmp(s_user, "1") == 0)
			continue;

		// section for management ==> skip it
		char *management;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "1") == 0)
			continue;

		// device is available in ifname list ==> skip it
		char *device;
		dmuci_get_value_by_section_string(s, "device", &device);

		if (dm_strword(br_args->ifname, device) != NULL || is_wireless_ifname_exist(br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec), device))
			continue;

		// else ==> delete section
		dmuci_delete_by_section(s, NULL, NULL);
	}

	// section added by user ==> skip it
	char *s_user = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(br_args->bridge_sec), &s);
	dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
	if (strcmp(s_user, "1") != 0) {
		if (!is_bridge_port_management_in_dmmap(br_args->br_inst)) {
			struct uci_section *sbr_port = NULL;
			dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &sbr_port);
			dmuci_set_value_by_section(sbr_port, "br_inst", br_args->br_inst);
			dmuci_set_value_by_section(sbr_port, "config", "network");
			dmuci_set_value_by_section(sbr_port, "interface", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec));
			dmuci_set_value_by_section(sbr_port, "management", "1");

			/*
			 * Add provider bridge instance number here if this bridge inst. is
			 * a svlan/cvlan bridge of a provider bridge
			 */
			char *pr_br_inst = NULL;
			if (is_bridge_pr_br_member(br_args->br_inst, &pr_br_inst))
				dmuci_set_value_by_section(sbr_port, "provider_br_inst", pr_br_inst ? pr_br_inst : "");
		}
	}

	p = linker_buf = (char *)dmmalloc(2048 * sizeof(char));
	if (p == NULL)
		return 0;

	*p = 0;
	br_ifname = dmstrdup(br_args->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {

		if (is_bridge_port_device_exist(br_args->br_inst, pch, &dmmap_br_port)) {
			if (dmmap_br_port) {
				snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(dmmap_br_port), pch);
				dmstrappendstr(p, plinker);
				dmstrappendchr(p, ',');
			}
			continue;
		}

		struct uci_section *sbr_port = NULL;
		dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &sbr_port);
		dmuci_set_value_by_section(sbr_port, "config", "network");
		dmuci_set_value_by_section(sbr_port, "device", pch);
		dmuci_set_value_by_section(sbr_port, "br_inst", br_args->br_inst);
		dmuci_set_value_by_section(sbr_port, "interface", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec));
		dmuci_set_value_by_section(sbr_port, "management", "0");

		/*
		 * Add provider bridge instance number here if this bridge inst. is
		 * a svlan/cvlan bridge of a provider bridge
		 */
		char *pr_br_inst = NULL;
		if (is_bridge_pr_br_member(br_args->br_inst, &pr_br_inst))
			dmuci_set_value_by_section(sbr_port, "provider_br_inst", pr_br_inst ? pr_br_inst : "");

		snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(sbr_port), pch);
		dmstrappendstr(p, plinker);
		dmstrappendchr(p, ',');
	}
	dmfree(br_ifname);

	uci_foreach_option_eq("wireless", "wifi-iface", "network", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec), s) {

		// get ifname from wireless/wifi-iface section
		char *ifname;
		dmuci_get_value_by_section_string(s, "ifname", &ifname);

		if (is_bridge_port_device_exist(br_args->br_inst, ifname, &dmmap_br_port)) {
			if (dmmap_br_port) {
				snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(dmmap_br_port), ifname);
				dmstrappendstr(p, plinker);
				dmstrappendchr(p, ',');
			}
			continue;
		}

		struct uci_section *sbr_port = NULL;
		dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &sbr_port);
		dmuci_set_value_by_section(sbr_port, "config", "wireless");
		dmuci_set_value_by_section(sbr_port, "device", ifname);
		dmuci_set_value_by_section(sbr_port, "br_inst", br_args->br_inst);
		dmuci_set_value_by_section(sbr_port, "interface", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec));
		dmuci_set_value_by_section(sbr_port, "management", "0");
		snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(sbr_port), ifname);
		dmstrappendstr(p, plinker);
		dmstrappendchr(p, ',');
	}

	if (p > linker_buf)
		p--;
	dmstrappendend(p);

	// Update the device linker for management port if it is not added by user
	if (strcmp(s_user, "1") != 0)
		set_linker_bridge_port_management(br_args->br_inst, linker_buf);

	dmfree(linker_buf);
	return 0;
}

static void get_bridge_vlanport_device_section(struct uci_section *dmmap_section, struct uci_section **device_section)
{
	struct uci_section *s = NULL;
	char *name, *device_name;

	/* Get name from dmmap section */
	dmuci_get_value_by_section_string(dmmap_section, "name", &name);

	if (name[0] != '\0') {
		/* Find the device network section corresponding to this name */
		uci_foreach_option_eq("network", "device", "name", name, s) {
			*device_section = s;
			return;
		}
	}

	/* Get section_name from dmmap section */
	dmuci_get_value_by_section_string(dmmap_section, "device_name", &device_name);

	if (device_name[0] != '\0') {
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

static void get_bridge_port_device_section(char *device, struct uci_section **device_section)
{
	struct uci_section *s = NULL;

	if (device[0] != '\0') {
		/* Find the ethport ports section corresponding to this device */
		uci_foreach_option_eq("ports", "ethport", "ifname", device, s) {
			*device_section = s;
			return;
		}

		/* Find the wifi-iface wireless section corresponding to this device */
		uci_foreach_option_eq("wireless", "wifi-iface", "ifname", device, s) {
			*device_section = s;
			return;
		}

		/* Find the device network section corresponding to this device */
		uci_foreach_option_eq("network", "device", "name", device, s) {
			*device_section = s;
			return;
		}
	}

	*device_section = NULL;
}

static int remove_vlanid_from_ifname_list(struct uci_section *bridge_sec, char *br_inst, char *curr_vid)
{
	char *ifname, *pch, *spch;

	dmuci_get_value_by_section_string(bridge_sec, "ifname", &ifname);
	char *br_ifname = dmstrdup(ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		char *vid = strchr(pch, '.');
		if (vid && strcmp(vid+1, curr_vid) == 0) {
			// Remove device from ifname list
			remove_ifname_from_bridge_section(bridge_sec, pch);

			// Update  port section if vid != 0
			struct uci_section *port_s = NULL;
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port_s) {
				char *device;
				// Get device from dmmap section
				dmuci_get_value_by_section_string(port_s, "device", &device);
				if (strcmp(device, pch) == 0) {
					// Remove vid from device
					vid[0] = '\0';
					// Update device in dmmap
					dmuci_set_value_by_section(port_s, "device", pch);
					break;
				}
			}
			// Add new device to ifname list
			add_new_ifname_to_bridge_section(bridge_sec, pch);
		}
	}
	dmfree(br_ifname);
	return 0;
}

static void set_lowerlayers_management_port(struct dmctx *ctx, void *data, char *value)
{
	char lower_layer_path[256] = {0};
	char *pch = NULL, *spch = NULL, *p, new_device[512] = { 0, 0 };

	p = new_device;
	for (pch = strtok_r(value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

		snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", ((struct bridge_port_args *)data)->br_inst);

		if (strncmp(pch, lower_layer_path, strlen(lower_layer_path)) == 0) {
			/* check linker is available */
			char *linker = NULL;
			adm_entry_get_linker_value(ctx, pch, &linker);
			if (!linker || linker[0] == '\0')
				continue;

			dmstrappendstr(p, linker);
			dmstrappendchr(p, ',');
		}
	}
	p = p -1;
	dmstrappendend(p);

	dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", new_device);
}

static void update_device_management_port(char *old_name, char *new_name, char *br_inst)
{
	struct uci_section *s = NULL;
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "0") == 0)
			continue;

		char *device;
		dmuci_get_value_by_section_string(s, "device", &device);

		char *new_linker, new_device[512], *p, *pch = NULL, *spch = NULL;
		new_device[0] = '\0';
		p = new_device;
		for (pch = strtok_r(device, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
			if (!strstr(pch, old_name)) {
				dmstrappendstr(p, pch);
				dmstrappendchr(p, ',');
			} else {
				char *sec = strchr(pch, '+');
				if (sec) sec[0] = '\0';
				dmasprintf(&new_linker, "%s+%s,", pch, new_name);
				dmstrappendstr(p, new_linker);
			}
		}
		p = p -1;
		dmstrappendend(p);
		dmuci_set_value_by_section(s, "device", new_device);
	}
}

static void remove_device_from_management_port(char *curr_device, char *br_inst)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		char *management;
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "0") == 0)
			continue;

		char *device;
		dmuci_get_value_by_section_string(s, "device", &device);

		char new_device[512], *p, *pch = NULL, *spch = NULL;
		new_device[0] = '\0';
		p = new_device;
		for (pch = strtok_r(device, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

			if (strcmp(pch, curr_device) == 0)
				continue;

			dmstrappendstr(p, pch);
			dmstrappendchr(p, ',');
		}
		p = p -1;
		dmstrappendend(p);

		dmuci_set_value_by_section(s, "device", new_device);
	}
}

static void update_vlanport_and_device_section(void *data, char *linker, char **new_linker)
{
	struct uci_section *br_vlan_port_s = NULL;
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_port_args *)data)->br_inst, br_vlan_port_s) {
		char *port_name;
		dmuci_get_value_by_section_string(br_vlan_port_s, "port_name", &port_name);
		if (strcmp(section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), port_name) == 0) {
			char *device_name;
			dmuci_get_value_by_section_string(br_vlan_port_s, "device_name", &device_name);

			// Update device section
			struct uci_section *s = NULL;
			uci_foreach_sections("network", "device", s) {

				if (strcmp(section_name(s), device_name) == 0) {
					char *vid;
					dmuci_get_value_by_section_string(s, "vid", &vid);
					if (vid [0] == '\0') {
						dmuci_set_value_by_section(s, "ifname", linker);
						dmuci_set_value_by_section(s, "name", linker);
					} else {
						char *new_name;
						dmasprintf(&new_name, "%s.%s", linker, vid);
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
		char *name;
		dmuci_get_value_by_section_string(s, "name", &name);
		struct uci_section *port_s = NULL;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "name", name, port_s) {
			char *curr_vid = strchr(name, '.');
			if (curr_vid) curr_vid[0] = '\0';
			dmuci_set_value_by_section(port_s, "name", name);
		}
		dmuci_set_value_by_section(s, "name", name);
		dmuci_set_value_by_section(s, "vid", "");
	}

	// Check if this vid is set as inner_vid for any interface, then delete it.
	uci_foreach_option_eq("network", "device", "inner_vid", vid, s) {
		dmuci_delete_by_section(s, "inner_vid", NULL);
	}
}

static void remove_vlanport_section(struct uci_section *vlanport_dmmap_sec, struct uci_section *bridge_sec, char *br_inst)
{
	struct uci_section *s = NULL, *ss = NULL;
	char *device_name, *port_name;

	// Get port name from dmmap section
	dmuci_get_value_by_section_string(vlanport_dmmap_sec, "port_name", &port_name);

	// Update  port section if vid != 0
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, s) {
		if (strcmp(section_name(s), port_name) == 0) {
			char *device;
			// Get device from dmmap section
			dmuci_get_value_by_section_string(s, "device", &device);
			char *vid = strchr(device, '.');
			if (vid) {
				// Remove curr device from ifname list of bridge section
				char *ifname = NULL;
				dmuci_get_value_by_section_string(bridge_sec, "ifname", &ifname);
				if (ifname && ifname[0] != '\0') {
					char new_ifname[128] = {0};

					remove_interface_from_ifname(device, ifname, new_ifname);
					dmuci_set_value_by_section(bridge_sec, "ifname", new_ifname);
				}

				// Remove vid from device
				vid[0] = '\0';

				// Add new device to ifname list
				add_new_ifname_to_bridge_section(bridge_sec, device);

				// Update device in dmmap
				dmuci_set_value_by_section(s, "device", device);
			}
			break;
		}
	}

	// Get device name from dmmap section
	dmuci_get_value_by_section_string(vlanport_dmmap_sec, "device_name", &device_name);

	// Remove ifname from device section
	uci_foreach_sections("network", "device", s) {
		if (strcmp(section_name(s), device_name) == 0) {
			ss = s;
			break;
		}
	}
	dmuci_delete_by_section(ss, NULL, NULL);
}

static void set_Provider_bridge_component(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, char *component)
{
	/* *value=Device.Bridging.Bridge.{i}.
	 * In file dmmap_provider_bridge set "option svlan_br_inst {i}" or "list cvlan_br_inst {i}" in this(refered "provider_bridge" section)
	 * In file dmmap_bridge_port traverse all bridge_port section with option br_inst {i} and add option  provider_br_inst {i}
	 */
	struct uci_section *ss = NULL, *stmp = NULL, *dmmap_bridge_section = NULL;
	struct uci_section *network_bridge_sec_from = NULL, *network_bridge_sec_to = NULL;
	char *br_sec_name, *interface_sec_name;
	char *management;
	char **tokens;
	char *br_inst; // candidate bridge_port instance in dmmap_provider_bridge
	size_t length;
	bool found = 0;
	char *option_val1 = NULL;
	char *option_val2 = NULL;
	char buf[50] = {0}; // for storing ifname
	char *ptr = NULL;

	// Get candidate bridge instance
	tokens = strsplit(value, ".", &length);
	br_inst = tokens[3]; //candidate bridge instance no.
	dmasprintf(&interface_sec_name, "pr_br_%s", instance); // section name of bridge in network file

	/*
	 * check if provider bridge instance of this provider bridge is present in network uci file
	 * if present add candidate bridge to this provider bridge instance.
	 * if not present, create a provider bridge instance in network uci file,
	 * i.e. just update the candidate bridge section name to pr_br_{i} | {i} = instance of provider bridge
	 */

	uci_foreach_option_eq("network", "interface", "type", "bridge", ss) {
		if (strcmp(interface_sec_name, section_name(ss)) == 0) {
			found = 1;
			network_bridge_sec_to = ss;
			break;
		}
	}

	if (strncmp(component, "CVLAN", 4) == 0) {
		// Set svlan_br_inst in dmmap_provider_bridge->provider_bridge section
		dmuci_add_list_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "cvlan_br_inst", br_inst);
	} else if (strncmp(component, "SVLAN", 4) == 0) {
		// Set svlan_br_inst in dmmap_provider_bridgei->provider_bridge section
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "svlan_br_inst", br_inst);
	}

	// For all ports of candidate bridge  add provider_br_inst {i} | {i} = provider bridge instance
	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, stmp, ss) {
		dmuci_get_value_by_section_string(ss, "management", &management);
		if (strcmp(management, "1") == 0)
			dmmap_bridge_section = ss;// later used to find network->interface(bridge) section name
		dmuci_set_value_by_section(ss, "provider_br_inst", instance);
	}

	/* Add candidate bridge to this provider bridge instance(network->interface->pr_br_{i}) */
	// Get network->interface(bridge) section name from dmmap_bridge_port->bridge_port->interface
	dmuci_get_value_by_section_string(dmmap_bridge_section, "interface", &br_sec_name);

	if (found) {
		/*
		 * The provider bridge secion has already been created(as a result of previous call to this function) in network uci file.
		 * Just need to find config section of candidate bridge and add it to the existing provider bridge configuration.
		 * And delete the candidate bridge section from network uci file.
		 *
		 */
		// Find the network->interface(candidate bridge) section
		uci_foreach_option_eq("network", "interface", "type", "bridge", ss) {
			if (strcmp(br_sec_name, section_name(ss)) == 0) {
				network_bridge_sec_from = ss;
				break;
			}
		}
		// Append ifname from candidate bridge to provider bridge instance in network uci
		dmuci_get_value_by_section_string(network_bridge_sec_from, "ifname", &option_val1);
		dmuci_get_value_by_section_string(network_bridge_sec_to, "ifname", &option_val2);
		ptr = buf;
		dmstrappendstr(ptr, option_val2);
		dmstrappendchr(ptr, ' ');
		dmstrappendstr(ptr, option_val1);
		dmuci_set_value_by_section(network_bridge_sec_to, "ifname", buf);
		// Delete the candidate bridge config from network uci file.
		dmuci_delete_by_section(network_bridge_sec_from, NULL, NULL);
	} else {
		/*
		 * This is the first vlan component of this provider bridge instance.
		 * Need to create a porvider bridge instance in network uci file.
		 * To create a new provider bridge instance just rename candidate bridge config section name to pr_br_{i}
		 *
		 */
		// Find the network->interface(bridge) section and rename it as pr_br_{i}
		uci_foreach_option_eq("network", "interface", "type", "bridge", ss) {
			if (strcmp(br_sec_name, section_name(ss)) == 0) {
				dmuci_rename_section_by_section(ss, interface_sec_name);
				break;
			}
		}
		// Add option section_name to dmmap provider bridge section
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "section_name", interface_sec_name);
	}
}

static void restore_bridge_config(char *vlan_br_inst)
{
	struct uci_section *stmp = NULL, *s = NULL, *dmmap_br_sec = NULL;
	char *management, *device;
	char **device_comma;
	size_t length_comma, tmp_length;
	char **tmp_list = NULL;
	char ifname[50] = {0};
	char *ptr = ifname;
	char *interface;
	int i;
	// Get bridge config section of vlan bridge from dmmap_bridge_port
	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", vlan_br_inst, stmp, s) {
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "1") == 0)
			dmmap_br_sec = s;
	}
	if (dmmap_br_sec == NULL)
		return;
	// Restore vlan bridge of this provider bridge
	// Get devices list
	dmuci_get_value_by_section_string(dmmap_br_sec, "device", &device);
	device_comma = strsplit(device, ",", &length_comma);
	for(i = 0; i < length_comma; i++) {
		tmp_list = strsplit(device_comma[i], "+", &tmp_length);
		dmstrappendstr(ptr, tmp_list[1]);
		dmstrappendchr(ptr, ' ');
	}
	ptr = ptr -1;
	dmstrappendend(ptr);
	// Restore bridge config
	dmuci_add_section("network", "interface", &s);
	// get old bridge section name and rename newly created bridge
	dmuci_get_value_by_section_string(dmmap_br_sec, "interface", &interface);
	dmuci_rename_section_by_section(s, interface);
	dmuci_set_value_by_section(s, "type", "bridge");
	dmuci_set_value_by_section(s, "ifname", ifname);
}

static void del_provider_bridge(void *data)
{
	struct uci_section *s = NULL, *network_bridge_sec = NULL;
	char *br_inst, *pr_br_inst;
	char *svlan_br_inst;
	struct uci_list *v= NULL;
	struct uci_element *e = NULL;
	/*
	 * Get cvlan/svlan bridge instance from the provider_bridge config and re-create all member bridge config section in network file.
	 * Delete all bridge_port config from dmmap_bridge_port which are member of this provider bridge.
	 * Delete provider bridge config. from network file corresponding to this provider bridge instance => config pr_br_{i}
	 * Delete this provider bridge section from dmmap_provider_bridge file.
	 *
	 */

	// Get provider bridge instance
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "provider_bridge_instance", &br_inst);
	if (!br_inst)
		return;

	dmasprintf(&pr_br_inst, "pr_br_%s", br_inst); //name of provider bridge configuration in network file

	// Get svlan component bridge instance from dmmap section
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "svlan_br_inst", &svlan_br_inst);

	if (svlan_br_inst[0] != '\0') {
		restore_bridge_config(svlan_br_inst);
		// Remove dmmap bridge section
		remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", svlan_br_inst);
	}

	// Get cvlan component bridge instance list from dmmap section
	dmuci_get_value_by_section_list(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "cvlan_br_inst", &v);
	if (v != NULL) {
		/* traverse each list value and delete all bridge section */
		uci_foreach_element(v, e) {
			// Restore bridge section in network uci file
			restore_bridge_config(e->name);
			// Remove dmmap bridge section
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", e->name);
		}
	}

	// Get provider bridge section from network file and delete
	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		if (strcmp(pr_br_inst, section_name(s)) == 0) {
			network_bridge_sec = s;
			break;
		}
	}
	dmuci_delete_by_section(network_bridge_sec, NULL, NULL);

	// Delete dmmap bridge section.
	dmuci_delete_by_section_bbfdm(((struct provider_bridge_args *)data)->dmmap_bridge_sec, NULL, NULL);
}

void static get_rem_pr_br_instance(struct uci_section *sec, char *bridge_inst)
{
	char *br_inst = NULL, *pr_br_inst = NULL;
	struct uci_section *network_bridge_sec = NULL, *dmmap_br_sec = NULL, *s = NULL, *stmp = NULL;
	char *bridges = NULL;
	char *management, *device;
	char **device_comma;
	size_t length, tmp_length;
	char **tmp_list = NULL;
	char ifname[50] = {0};
	char *ptr = ifname;
	int i;
	char **bridge_ifname;
	char new_ifname[50] = {0};

	// Get provider bridge instance | will be used to track and remove this bridge inst in network file
	dmuci_get_value_by_section_string(sec, "provider_bridge_instance", &br_inst);

	dmasprintf(&pr_br_inst, "pr_br_%s", br_inst); //name of provider bridge configuration in network file

	// Get provider bridge section from network file and delete
	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		if (strcmp(pr_br_inst, section_name(s)) == 0) {
			network_bridge_sec = s; // This id the provider bridge config in network file
			break;
		}
	}
	if (network_bridge_sec == NULL)
		return;

	/* Remove bridge from provider bridge config in network file */
	// Get bridge config section from dmmap_bridge_port file
	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", bridge_inst, stmp, s) {
		dmuci_get_value_by_section_string(s, "management", &management);
		if (strcmp(management, "1") == 0) {
			dmmap_br_sec = s;
			break;
		}
	}
	// Construct ifname list from dmmap_bridge_port management section of passed bridge instance
	dmuci_get_value_by_section_string(dmmap_br_sec, "device", &device);
	device_comma = strsplit(device, ",", &length);
	for(i = 0; i < length; i++) {
		tmp_list = strsplit(device_comma[i], "+", &tmp_length);
		dmstrappendstr(ptr, tmp_list[1]);
		dmstrappendchr(ptr, ' ');
	}
	ptr = ptr - 1;
	dmstrappendend(ptr);

	dmuci_get_value_by_section_string(network_bridge_sec, "ifname", &bridges);
	bridge_ifname = strsplit(bridges, " ", &length);

	// Now, remove the ifnames of passed bridge instance from network bridge section - pr_br_{i}
	ptr = new_ifname;
	for(i = 0; i < length; i++) {
		if (strstr(ifname, bridge_ifname[i])) {
			return;
		}
		dmstrappendstr(ptr, bridge_ifname[i]);
		dmstrappendchr(ptr, ' ');
	}
	if (ptr != NULL) {
		ptr = ptr - 1;
		dmstrappendend(ptr);
	}

	if (new_ifname[0] == '\0')
		dmuci_delete_by_section(network_bridge_sec, NULL, NULL);
	else
		dmuci_set_value_by_section(network_bridge_sec, "ifname", new_ifname);
}

// Function to remove a svlan/cvlan instance from Provider bridge
void rem_bridge_from_provider_bridge(char *bridge_inst)
{
	struct uci_section *sec = NULL;
	char *svlan;
	struct uci_list *v = NULL;
	struct uci_element *e = NULL;


	// Traverse each provider bridge section and remove the passed bridge instance.
	// Also restore bridge in network file.
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", sec) {
		// Check if the passed bridge section is svlan
		svlan = NULL;
		dmuci_get_value_by_section_string(sec, "svlan_br_inst", &svlan);
		if (svlan != NULL) {
			if (strcmp(svlan, bridge_inst) == 0) {
				restore_bridge_config(svlan); // This restored bridge will be deleted later
				dmuci_set_value_by_section(sec, "svlan_br_inst", "");
				get_rem_pr_br_instance(sec, bridge_inst);

			}
		}
		// Check if the passed bridge section is cvlan
		dmuci_get_value_by_section_list(sec, "cvlan_br_inst", &v);
		if (v != NULL) {
			bool found = false;

			uci_foreach_element(v, e) {
				if (strcmp(e->name, bridge_inst) == 0) {
					found = true;
					break;
				}
			}
			if (found == true) {
				restore_bridge_config(bridge_inst);
				dmuci_del_list_value_by_section(sec, "cvlan_br_inst", bridge_inst);
				get_rem_pr_br_instance(sec, bridge_inst);
			}
		}
	}
}

/*************************************************************
* ADD DELETE OBJECT
**************************************************************/
static int addObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *dmmap_bridge = NULL;
	char bridge_name[32];

	char *last_inst = get_last_instance_bridge_bbfdm("dmmap_bridge", "bridge", "bridge_instance");
	snprintf(bridge_name, sizeof(bridge_name), "bridge_%d", last_inst ? atoi(last_inst)+1 : 1);

	// Add interface bridge section
	dmuci_set_value("network", bridge_name, "", "interface");
	dmuci_set_value("network", bridge_name, "type", "bridge");
	dmuci_set_value("network", bridge_name, "disabled", "1");

	// Add dmmap bridge section
	dmuci_add_section_bbfdm("dmmap_bridge", "bridge", &dmmap_bridge);
	dmuci_set_value_by_section(dmmap_bridge, "section_name", bridge_name);
	dmuci_set_value_by_section(dmmap_bridge, "added_by_user", "1");
	*instance = update_instance(last_inst, 2, dmmap_bridge, "bridge_instance");
	return 0;
}

static int delObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *bridge_s = NULL, *prev_s = NULL, *ss = NULL;
	char *bridgekey = NULL, *proto, *section_name;

	switch (del_action) {
		case DEL_INST:
			// Remove cvlan/svaln from dmmap_providerbridge section if this bridge instance is a part of it
			rem_bridge_from_provider_bridge(((struct bridge_args *)data)->br_inst);

			// Check if the passed config section is a dmmap_bridge section. If yes get its corresponding config from network file
			if (((struct bridge_args *)data)->is_dmmap_sec == true) {
				dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "section_name", &section_name);
				ss = get_origin_section_from_config("network", "interface", section_name);
				((struct bridge_args *)data)->bridge_sec = ss; // network config section
			}

			// Read the proto option from interface bridge section
			dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "proto", &proto);

			// Check the proto value ==> if empty : there is no IP.Interface. object mapped to this interface bridge, remove the section
			// Check the proto value ==> else : there is an IP.Interface. object mapped to this interface bridge, remove only type option from the section
			if (*proto == '\0') {
				/* proto is empty ==> remove interface bridge and dmmap section */
				dmuci_delete_by_section(((struct bridge_args *)data)->bridge_sec, NULL, NULL);
			} else {
				/* proto is not empty ==> remove only type option from the interface bridge section and bridge instance option from dmmap section  */
				dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "type", "");
			}


			// Remove all bridge port sections related to this interface bridge section
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge sections related to this interface bridge section
			remove_bridge_sections("dmmap_bridge", "bridge", "bridge_instance", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlan sections related to this interface bridge section
			remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst);

			// Remove all bridge vlanport sections related to this interface bridge section
			remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst);

			break;
		case DEL_ALL:
			uci_path_foreach_sections(bbfdm, "dmmap_bridge", "bridge", bridge_s) {

				// Get section name related to this interface bridge section
				dmuci_get_value_by_section_string(bridge_s, "section_name", &section_name);

				// Get bridge instance for each interface bridge section
				dmuci_get_value_by_section_string(bridge_s, "bridge_instance", &bridgekey);

				// Remove cvlan/svaln from dmmap_providerbridge section if this bridge instance is a part of it
				rem_bridge_from_provider_bridge(bridgekey);

				// Read the proto option from interface bridge section
				ss = get_origin_section_from_config("network", "interface", section_name);
				dmuci_get_value_by_section_string(ss, "proto", &proto);

				// Check the proto value ==> if empty : there is no IP.Interface mapped to this interface bridge, remove the section
				// Check the proto value ==> else : there is an IP.Interface mapped to this interface bridge, remove only type option from the section
				if (*proto == '\0') {
					/* proto is empty ==> remove interface bridge and dmmap section */
					dmuci_delete_by_section(ss, NULL, NULL);
				} else {
					/* proto is not empty ==> remove only type option from the interface bridge section and bridge instance option from dmmap section  */
					dmuci_set_value_by_section(ss, "type", "");
				}

				// Remove all bridge port sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_port", "bridge_port", "br_inst", bridgekey);

				// Remove all bridge vlan sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_vlan", "bridge_vlan", "br_inst", bridgekey);

				// Remove all bridge vlanport sections related to this interface bridge section
				remove_bridge_sections("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", bridgekey);

				if (prev_s)
					dmuci_delete_by_section(prev_s, NULL, NULL);
				prev_s = bridge_s;
			}
			if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
			break;
	}
	return 0;
}

static int addObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_port_s = NULL;
	char *sec_name = NULL;

	int inst = get_last_inst("dmmap_bridge_port", "bridge_port", "br_inst", "bridge_port_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);

	// Add dmmap section for devices
	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s);
	dmuci_set_value_by_section(br_port_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
	dmuci_set_value_by_section(br_port_s, "config", "network");
	if (((struct bridge_args *)data)->is_dmmap_sec == true) {
		dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "section_name", &sec_name);
		dmuci_set_value_by_section(br_port_s, "interface", sec_name);
	} else {
		dmuci_set_value_by_section(br_port_s, "interface", section_name(((struct bridge_args *)data)->bridge_sec));
	}
	dmuci_set_value_by_section(br_port_s, "management", "0");
	dmuci_set_value_by_section(br_port_s, "added_by_user", "1");
	return 0;
}

static int delObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *prev_s = NULL;
	char *device, *management;

	switch (del_action) {
	case DEL_INST:
		// Get device from dmmap section
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", &device);
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);

		if (device[0] == '\0' || strcmp(management, "1") == 0) {
			// Remove only dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, NULL, NULL);
		} else {
			char new_ifname[128] = {0};
			char *ifname = NULL;

			// Remove ifname from ifname list of bridge section
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "ifname", &ifname);
			if (ifname && ifname[0] != '\0') {
				remove_interface_from_ifname(device, ifname, new_ifname);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_sec, "ifname", new_ifname);
			}

			// Remove ifname from ifname list of dmmap bridge section
			get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_port_args *)data)->bridge_sec), &s);
			dmuci_get_value_by_section_string(s, "ifname", &ifname);
			if (ifname && ifname[0] != '\0') {
				remove_interface_from_ifname(device, ifname, new_ifname);
				dmuci_set_value_by_section(s, "ifname", new_ifname);
			}

			// Remove device from management port section
			snprintf(new_ifname, sizeof(new_ifname), "br_%s:%s+%s", ((struct bridge_port_args *)data)->br_inst, section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), device);
			remove_device_from_management_port(new_ifname, ((struct bridge_port_args *)data)->br_inst);

			// Remove ifname from device section
			uci_foreach_option_eq("network", "device", "name", device, s) {
				dmuci_set_value_by_section(s, "name", "");
				dmuci_set_value_by_section(s, "ifname", "");
			}

			// Remove ifname from vlan port section
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "name", device, s) {
				dmuci_set_value_by_section(s, "name", "");
			}

			// Remove dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_args *)data)->br_inst, s) {
			// Get device from dmmap section
			dmuci_get_value_by_section_string(s, "device", &device);
			dmuci_get_value_by_section_string(s, "management", &management);
			if (device[0] != '\0' && strcmp(management, "0") == 0) {
				struct uci_section *ss = NULL;
				// Remove ifname from device section
				uci_foreach_option_eq("network", "device", "name", device, ss) {
					dmuci_set_value_by_section(ss, "name", "");
					dmuci_set_value_by_section(ss, "ifname", "");
				}

				// Remove ifname from vlan port section
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "name", device, ss) {
					dmuci_set_value_by_section(ss, "name", "");
				}
			}

			if (prev_s)
				dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
			prev_s = s;
		}
		if (prev_s)
			dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
		dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "ifname", "");
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
	struct uci_section *s = NULL, *prev_s = NULL;

	// Get the vlanid associated with the vlanport
	char *vid = NULL;
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);

	switch (del_action) {
		case DEL_INST:
			remove_vlanport_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, ((struct bridge_vlanport_args *)data)->bridge_sec,
									((struct bridge_vlanport_args *)data)->br_inst);

			// Remove dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_args *)data)->br_inst, s) {

				remove_vlanport_section(s, ((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->br_inst);

				// Remove all dmmap section
				if (prev_s)
					dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
				prev_s = s;
			}
			if (prev_s)
				dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
			break;
		}

	if (vid != NULL && vid[0] != '\0') {
		// Check if this vid is set as inner_vid for any interface, then delete it.
		uci_foreach_option_eq("network", "device", "inner_vid", vid, s) {
			dmuci_delete_by_section(s, "inner_vid", NULL);
		}
	}

	return 0;
}

static int addObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_vlan_s = NULL;
	char *sec_name = NULL;

	int inst = get_last_inst("dmmap_bridge_vlan", "bridge_vlan", "br_inst", "bridge_vlan_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);

	dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &br_vlan_s);
	dmuci_set_value_by_section(br_vlan_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_vlan_s, "bridge_vlan_instance", *instance);
	if (((struct bridge_args *)data)->is_dmmap_sec == true) {
		dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "section_name", &sec_name);
		dmuci_set_value_by_section(br_vlan_s, "interface", sec_name);
	} else {
		dmuci_set_value_by_section(br_vlan_s, "interface", section_name(((struct bridge_args *)data)->bridge_sec));
	}
	dmuci_set_value_by_section(br_vlan_s, "interface", section_name(((struct bridge_args *)data)->bridge_sec));
	dmuci_set_value_by_section(br_vlan_s, "added_by_user", "1");
	dmuci_set_value_by_section(br_vlan_s, "vid", "1");
	return 0;
}

static int delObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *prev_s = NULL;
	char *vid;

	switch (del_action) {
	case DEL_INST:
		dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &vid);
		if (vid[0] == '\0') {
			// Remove only dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_vlan_args *)data)->bridge_vlan_sec, NULL, NULL);
		} else {
			// Remove all vid from ifname list of bridge section
			remove_vlanid_from_ifname_list(((struct bridge_vlan_args *)data)->bridge_sec, ((struct bridge_vlan_args *)data)->br_inst, vid);

			// Remove all vid from device and vlanport sections in dmmap
			remove_vlanid_from_device_and_vlanport(vid);

			// Remove only dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_vlan_args *)data)->bridge_vlan_sec, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_inst, s) {
			dmuci_get_value_by_section_string(s, "vid", &vid);
			if (vid[0] != '\0') {
				// Remove all vid from ifname list of bridge section
				remove_vlanid_from_ifname_list(((struct bridge_args *)data)->bridge_sec, ((struct bridge_args *)data)->br_inst, vid);

				// Remove all vid from device and vlanport sections in dmmap
				remove_vlanid_from_device_and_vlanport(vid);
			}

			// Remove all dmmap section
			if (prev_s)
				dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
			prev_s = s;
		}
		if (prev_s)
			dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
		break;
	}
	return 0;
}

static int addObjBridgingProviderBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *pr_br_sec = NULL;

	char *last_instance = get_last_instance_bbfdm("dmmap_provider_bridge", "provider_bridge", "provider_bridge_instance");

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_provider_bridge", "provider_bridge", &pr_br_sec);
	dmuci_set_value_by_section(pr_br_sec, "enable", "1");
	dmuci_set_value_by_section(pr_br_sec, "type", "S-VLAN");
	*instance = update_instance(last_instance, 2, pr_br_sec, "provider_bridge_instance");
	return 0;
}

static int delObjBridgingProviderBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section = NULL, *prev_s = NULL;
	struct provider_bridge_args pr_br_args = {0};

	switch (del_action) {
	case DEL_INST:
		del_provider_bridge(data);
		break;
	case DEL_ALL:
		uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", dmmap_section) {
			if (prev_s) {
				pr_br_args.dmmap_bridge_sec = prev_s;
				del_provider_bridge((void *)&pr_br_args);
			}
			prev_s = dmmap_section;
		}
		if(prev_s) {
			pr_br_args.dmmap_bridge_sec = prev_s;
			del_provider_bridge((void *)&pr_br_args);
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

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Enable!UBUS:network.interface/status/interface,@Name/up*/
static int get_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *sec_name = NULL;

	if (((struct bridge_args *)data)->is_dmmap_sec == true) {
		dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "section_name", &sec_name);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", sec_name, String}}, 1, &res);
	} else {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridge_args *)data)->bridge_sec), String}}, 1, &res);
	}

	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
	return 0;
}

static int set_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *sec_name = NULL;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);

			if (((struct bridge_args *)data)->is_dmmap_sec == true) {
				dmuci_get_value_by_section_string(((struct bridge_args *)data)->bridge_sec, "section_name", &sec_name);
				dmubus_call_set("network.interface", b ? "up" : "down", UBUS_ARGS{{"interface", sec_name, String}}, 1);
			} else {
				dmubus_call_set("network.interface", b ? "up" : "down", UBUS_ARGS{{"interface", section_name(((struct bridge_args *)data)->bridge_sec), String}}, 1);
			}
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

	get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_sect);
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
			get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_sect);
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
	char *management;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	if (strcmp(management, "1") == 0) {
		*value = "1";
	} else {
		char *device, *eth_ports, *config;

		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &device);
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", &config);
		db_get_value_string("hw", "board", "ethernetLanPorts", &eth_ports);

		if (dm_strword(eth_ports, device)) {
			// ports config => ethport sections

			*value = dmuci_get_value_by_section_fallback_def(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", "1");
		} else if (!strcmp(config, "wireless")) {
			// wireless config => wifi-iface sections

			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "disabled", value);
			*value = ((*value)[0] == '1') ? "0" : "1";
		} else {
			// network config => device sections

			json_object *res = NULL;
			char *up;
			dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &res);
			DM_ASSERT(res, *value = "0");
			up = dmjson_get_value(res, 1, "up");
			*value = up ? "1" :"0";
		}
	}
	return 0;
}

static int set_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *management;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
			if (strcmp(management, "1") == 0) {
				break;
			} else {
				char *device, *eth_ports, *config;

				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &device);
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", &config);
				db_get_value_string("hw", "board", "ethernetLanPorts", &eth_ports);

				if (dm_strword(eth_ports, device)) {
					// ports config => ethport sections

					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", b ? "1" : "0");
				} else if (!strcmp(config, "wireless")) {
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
	char *management;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	if (strcmp(management, "1") !=  0)
		*value = dmstrdup(((struct bridge_port_args *)data)->ifname);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_BridgingBridgePort_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct bridge_port_args *)data)->bridge_sec == NULL) {
		*value = "0";
		return 0;
	}
	json_object *res;
	char *sec_name = NULL;

	if (((struct bridge_port_args *)data)->is_dmmap_sec == true) {
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "section_name", &sec_name);
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", sec_name, String}}, 1, &res);
	} else {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridge_port_args *)data)->bridge_sec), String}}, 1, &res);
	}

	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	if((*value)[0] == '\0')
		*value = "0";
	return 0;
}

static int get_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *management;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	if (strcmp(management, "1") ==  0) {
		char *pch = NULL, *spch = NULL, *device, *p, lbuf[512] = { 0, 0 };
		p = lbuf;
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", &device);
		for (pch = strtok_r(device, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {
			adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", pch, value);
			if (*value == NULL)
				*value = "";
			dmstrappendstr(p, *value);
			dmstrappendchr(p, ',');
		}
		p = p -1;
		dmstrappendend(p);
		*value = dmstrdup(lbuf);
	} else {
		char *linker, *config = NULL;

		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "config", &config);
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", &linker);

		if (config && strcmp(config, "network") == 0) {
			char *tag = strchr(linker, '.');
			if (tag) tag[0] = '\0';
		}

		adm_entry_get_linker_param(ctx, "Device.Ethernet.Interface.", linker, value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, "Device.WiFi.SSID.", linker, value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, "Device.ATM.Link.", linker, value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, "Device.PTM.Link.", linker, value);

		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *management = NULL, *linker = NULL;
	struct uci_section *dmmap_bridge_s = NULL;

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

				if (check_ifname_exist_in_br_ifname_list(linker, section_name(((struct bridge_port_args *)data)->bridge_sec)))
					return 0;

				char *device;
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", &device);
				if (device[0] == '\0') {
					// Check if there is a vlan port pointed at me
					char *new_linker = NULL;
					update_vlanport_and_device_section(data, linker, &new_linker);
					if (new_linker) linker = new_linker;

					// network config: add name to ifname option
					add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

					// dmmap_bridge: add name to ifname option
					get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_port_args *)data)->bridge_sec), &dmmap_bridge_s);
					add_new_ifname_to_bridge_section(dmmap_bridge_s, linker);

					// Update device option in dmmap
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", linker);

					update_device_management_port(section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), linker, ((struct bridge_port_args *)data)->br_inst);
				} else {
					char *tag = strchr(device, '.');
					if (tag) {
						char *cur_vid = dmstrdup(tag+1);
						char *new_name;
						dmasprintf(&new_name, "%s.%s", linker, cur_vid);

						// Remove name from ifname list interface
						remove_ifname_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, device);

						// Check if there is a vlan port pointed at me
						struct uci_section *ss = NULL;
						uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_port_args *)data)->br_inst, ss) {
							char *port_name;
							dmuci_get_value_by_section_string(ss, "port_name", &port_name);
							if (strcmp(section_name(((struct bridge_port_args *)data)->bridge_port_dmmap_sec), port_name) == 0) {
								char *device_name;
								dmuci_get_value_by_section_string(ss, "device_name", &device_name);

								// Update device section
								struct uci_section *s = NULL;
								uci_foreach_sections("network", "device", s) {
									if (strcmp(section_name(s), device_name) == 0) {
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
						add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, new_name);

						// dmmap_bridge: add name to ifname option
						get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_port_args *)data)->bridge_sec), &dmmap_bridge_s);
						add_new_ifname_to_bridge_section(dmmap_bridge_s, new_name);

						// Update device option in dmmap
						dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", new_name);

						update_device_management_port(device, new_name, ((struct bridge_port_args *)data)->br_inst);
					} else {
						// Remove name from ifname list interface
						remove_ifname_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, device);

						// Check if there is a vlan port pointed at me
						char *new_linker = NULL;
						update_vlanport_and_device_section(data, linker, &new_linker);
						if (new_linker) linker = new_linker;

						// network config: add name to ifname option
						add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

						// dmmap_bridge: add name to ifname option
						get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_port_args *)data)->bridge_sec), &dmmap_bridge_s);
						add_new_ifname_to_bridge_section(dmmap_bridge_s, linker);

						// Update device option in dmmap
						dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", linker);

						update_device_management_port(device, linker, ((struct bridge_port_args *)data)->br_inst);
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

void bridging_get_priority_list(char *uci_opt_name, void *data, char **value)
{
	struct uci_list *v= NULL;
	struct uci_element *e = NULL;
	char uci_value[130], **priority = NULL;
	size_t length;
	unsigned pos = 0;

	dmuci_get_value_by_section_list(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, &v);
	if (v == NULL)
		return;

	uci_value[0] = '\0';
	/* traverse each list value and create comma separated output */
	uci_foreach_element(v, e) {
		//delimiting priority which is in the form of x:y where y is the priority
		priority = strsplit(e->name, ":", &length);
		if (length > 1)
			pos += snprintf(&uci_value[pos], sizeof(uci_value) - pos, "%s,", priority[1]);
	}

	if (pos)
		uci_value[pos - 1] = 0;

	dmasprintf(value, "%s", uci_value);
}

void bridging_get_vlan_tvid(char *uci_opt_name, void *data, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, uci_opt_name, value);
}

void bridging_set_vlan_tvid(char *uci_opt_name, void *data, char *value)
{
	char *ifname, *pch, *spch;

	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_sec, "ifname", &ifname);
	char *br_ifname = dmstrdup(ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		struct uci_section *device_s = NULL;

		/* Update tvid in the device section */
		uci_foreach_option_eq("network", "device", "name", pch, device_s) {
			// tvid value 0 means vlan translation disable
			if (strcmp(value, "0") == 0) {
				dmuci_delete_by_section(device_s, uci_opt_name, NULL);
			} else {
				dmuci_set_value_by_section(device_s, uci_opt_name, value);
			}
		}
	}
	dmfree(br_ifname);
	if (strcmp(value, "0") == 0) {
		dmuci_delete_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, uci_opt_name, NULL);
	} else {
		dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, uci_opt_name, value);
	}
}

void bridging_set_priority_list(char *uci_opt_name, void *data, char *value)
{
	char buf[16];
	char *pch, *pchr;
	int i;

	/* delete current list values */
	dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, "");

	/* set new values */
	i = 0;
	buf[0] = '\0';
	/* tokenize each value from received comma separated string and add it to uci file in the format x:y
	x being priority and y being priority to be mapped to */
	for (pch = strtok_r(value, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr), i++) {
		/* convert values to uci format (x:y) and add */
		snprintf(buf, sizeof(buf), "%d%c%s", i, ':', pch);
		dmuci_add_list_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, buf);
	}
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

static int fetch_and_configure_inner_vid(char *br_inst, char *type_val, char **vid) {

	struct uci_section *dev_s = NULL, *sec = NULL;
	char *name, *instance = NULL;

	// Get the vid under device section with type 8021q of port under same br_inst.
	uci_foreach_option_eq("network", "device", "type", type_val, dev_s) {
		dmuci_get_value_by_section_string(dev_s, "name", &name);
		//find out the bridge instance of device section
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "device", name, sec) {
			dmuci_get_value_by_section_string(sec, "br_inst", &instance);
			break;
		}

		//Check if the bridge instances are same or not, if yes, then get the vid.
		if (instance && br_inst && strcmp(br_inst, instance) == 0) {
			if (type_val && strcmp(type_val, "8021ad") == 0) {
				dmuci_set_value_by_section(dev_s, "inner_vid", *vid);
			} else {
				dmuci_get_value_by_section_string(dev_s, "vid", vid);
			}
			break;
		}
	}

	return 0;
}

static int handle_inner_vid() {

	struct uci_section *s = NULL, *sec = NULL;

	uci_foreach_sections("network", "interface", s) {
		char *br_inst = NULL, *vid = NULL;
		// Get the bridge instance.
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "interface", section_name(s), sec) {
			dmuci_get_value_by_section_string(sec, "br_inst", &br_inst);
			break;
		}

		if (br_inst != NULL && br_inst[0] != '\0') {
			fetch_and_configure_inner_vid(br_inst, "8021q", &vid);
			if (vid == NULL) {
				fetch_and_configure_inner_vid(br_inst, "untagged", &vid);
			}
			//loop device section with type 8021ad and fetch the br_inst of it,
			//if same br_inst then add vid as inner_vid
			if (vid != NULL && vid[0] != '\0') {
				fetch_and_configure_inner_vid(br_inst, "8021ad", &vid);
			}
		}
	}

	return 0;
}

static int set_BridgingBridgePort_PVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *type;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
			if (type[0] != '\0' && (strcmp(type, "untagged") == 0 || strcmp(type, "8021q") == 0)) {
				char *ifname, *new_name;
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &ifname);
				dmasprintf(&new_name, "%s.%s", ifname, value);

				/* Update VLANPort dmmap section if exist */
				struct uci_section *vlanport_s = NULL;
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_port_args *)data)->br_inst, vlanport_s) {
					char *vlan_name, *name;
					dmuci_get_value_by_section_string(vlanport_s, "name", &vlan_name);
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "name", &name);
					if (strcmp(vlan_name, name) == 0) {
						dmuci_set_value_by_section(vlanport_s, "name", new_name);
						break;
					}
				}

				/* Update Port dmmap section */
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", new_name);

				/* Update interface and device section */
				update_bridge_ifname(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, 0);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "name", new_name);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "vid", value);
				handle_inner_vid();
				update_bridge_ifname(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, 1);
				dmfree(new_name);
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
	if (strcmp(type, "8021q") == 0 || strcmp(type, "untagged") == 0)
		*value = "33024";
	else if (strcmp(type, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int configure_interface_type(struct uci_section *bridge_sec, struct uci_section *sec, char *interface, char *br_inst, char *value)
{
	struct uci_section *s = NULL, *ss = NULL;
	char *vid = NULL, *inner_vid = NULL;

	dmuci_set_value_by_section(sec, "type", value);

	if (strncmp(value, "8021q", 5) == 0) {
		//Check if the interface has inner-vid if so then delete
		uci_foreach_sections("network", "device", s) {
			if (strcmp(section_name(sec), section_name(s)) == 0) {
				dmuci_get_value_by_section_string(s, "inner_vid", &inner_vid);
				if (inner_vid[0] != '\0') {
					dmuci_delete_by_section(s, "inner_vid", NULL);
					break;
				}
			}
		}

		//fetch the vid of the 8021q interface.
		uci_foreach_option_eq("network", "device", "name", interface, ss) {
			dmuci_get_value_by_section_string(ss, "vid", &vid);
			break;
		}

		if (vid != NULL && vid[0] != '\0') {
			fetch_and_configure_inner_vid(br_inst, "8021ad", &vid);
		}

	} else if (strncmp(value, "8021ad", 6) == 0) {
		fetch_and_configure_inner_vid(br_inst, "8021q", &vid);

		if (vid == NULL) {
			fetch_and_configure_inner_vid(br_inst, "untagged", &vid);
		}

		//apply the vid of the interface as the inner_vid of 8021ad port
		if (vid != NULL && vid[0] != '\0') {
			dmuci_set_value_by_section(sec, "inner_vid", vid);
		}

	}

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
				configure_interface_type(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, ((struct bridge_port_args *)data)->ifname, ((struct bridge_port_args *)data)->br_inst, "8021q");
			else if (strcmp(value, "34984") == 0)
				configure_interface_type(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, ((struct bridge_port_args *)data)->ifname, ((struct bridge_port_args *)data)->br_inst, "8021ad");
			return 0;
	}
	return 0;
}

static int br_get_sysfs(const struct bridge_port_args *br, const char *name, char **value)
{
	char *device;

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
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "interface", value);
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
			// If bridge_sec is network config section: rename it to passed new value.
			if (((struct bridge_vlan_args *)data)->is_dmmap_sec == false) {
				dmuci_rename_section_by_section(((struct bridge_vlan_args *)data)->bridge_sec, value);
			}
			// Update name in dmmap_bridge section of this bridge instance
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge", "bridge", "bridge_instance", ((struct bridge_vlan_args *)data)->br_inst, s) {
				dmuci_set_value_by_section(s, "section_name", value);
			}
			// Update name in dmmap_bridge_port sections of this bridge instance
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, s) {
				dmuci_set_value_by_section(s, "interface", value);
			}
			// Update name in dmmap_bridge_vlan section of this bridge instance
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "interface", value);
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
	char *ifname, *pch, *spch, *curr_vid;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &curr_vid);
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_sec, "ifname", &ifname);
			char *br_ifname = dmstrdup(ifname);
			for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				char *vid = strchr(pch, '.');
				if (vid && strcmp(vid+1, curr_vid) == 0) {
					remove_ifname_from_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, pch);
					struct uci_section *device_s = NULL, *vlanport_s = NULL;
					char *ifname, *new_name = NULL;

					/* Update vid and name of device section */
					uci_foreach_option_eq("network", "device", "name", pch, device_s) {
						dmuci_get_value_by_section_string(device_s, "ifname", &ifname);
						if (*ifname == '\0') {
							dmuci_get_value_by_section_string(device_s, "name", &ifname);
							char *name = strchr(ifname, '.');
							if (name)
								*name = '\0';
						}
						dmasprintf(&new_name, "%s.%s", ifname, value);
						dmuci_set_value_by_section(device_s, "name", new_name);
						dmuci_set_value_by_section(device_s, "vid", value);
					}

					/* Update vlan port section in dmmap */
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, vlanport_s) {
						char *vlan_name;
						dmuci_get_value_by_section_string(vlanport_s, "name", &vlan_name);
						if (strcmp(vlan_name, pch) == 0) {
							dmuci_set_value_by_section(vlanport_s, "name", new_name ? new_name : "");
							break;
						}
					}

					/* Update port section in dmmap */
					struct uci_section *s = NULL;
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, s) {
						char *device;
						dmuci_get_value_by_section_string(s, "device", &device);
						if (strcmp(device, pch) == 0) {
							dmuci_set_value_by_section(s, "device", new_name ? new_name : "");
							update_device_management_port(device, new_name ? new_name : "", ((struct bridge_vlan_args *)data)->br_inst);
							break;
						}
					}

					add_new_ifname_to_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, new_name);

					if (new_name && *new_name)
						dmfree(new_name);
				}
			}
			dmfree(br_ifname);

			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", value);
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
	char *vid = NULL;

	/* Get vid from device network section */
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);
	if (vid && vid[0] != '\0') {
		char linker[32] = {0};

		/* Get linker */
		snprintf(linker, sizeof(linker),"br_%s:vlan_%s", ((struct bridge_vlanport_args *)data)->br_inst, (vid[0] != '\0') ? vid : "1");
		adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", linker, value);
		if (*value == NULL)
			*value = "";
	}
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
					char *curr_name, *new_vid = dmstrdup(br+6);

					/* Check the current ifname in the device section */
					dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", &curr_name);

					if (curr_name[0] != '\0') {
						// the current ifname is not empty in device section

						char *curr_ifname, *new_name;
						dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", &curr_ifname);
						/* create the new name */
						dmasprintf(&new_name, "%s.%s", curr_ifname, new_vid);

						/* Update interface and device network section */
						update_bridge_ifname(((struct bridge_vlanport_args *)data)->bridge_sec, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 0);
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", new_name);
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", new_vid);
						update_bridge_ifname(((struct bridge_vlanport_args *)data)->bridge_sec, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 1);

						/* Update port section in dmmap */
						struct uci_section *s = NULL;
						uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, s) {
							char *device;
							dmuci_get_value_by_section_string(s, "device", &device);
							if (strcmp(device, curr_name) == 0) {
								dmuci_set_value_by_section(s, "device", new_name);
								update_device_management_port(device, new_name, ((struct bridge_vlanport_args *)data)->br_inst);
								break;
							}
						}

						/* Update the name dmmap section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
						dmfree(new_name);
					} else {
						// the current ifname is empty in device section

						/* Update only vid option in device section */
						dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", new_vid);
					}
					dmfree(new_vid);

					/* Update tvid, read from dmmap_bridge_vlan, set in vlanport_sec */
					struct uci_section *vlan_s = NULL;
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, vlan_s) {
						char *vlan_inst;
						dmuci_get_value_by_section_string(vlan_s, "bridge_vlan_instance", &vlan_inst);
						if (strcmp(vlan_inst, instance) == 0) {
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
	char plinker[128], *name, *port_name;

	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", &name);
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", &port_name);
	snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", ((struct bridge_vlanport_args *)data)->br_inst, port_name, name);
	adm_entry_get_linker_param(ctx, "Device.Bridging.Bridge.", plinker, value);
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
						char *new_linker = dmstrdup(br_link+1);
						*br_link = '\0';

						char *vid;
						dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);
						if (vid[0] == '\0') {

							/* Update device section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", new_linker);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", new_linker);

							/* Update dmmap vlanport section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_linker);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", section_name);
						} else {
							/* Create the new ifname */
							char *tag = NULL;
							if(new_linker[0] != '\0'){
								tag = strchr(new_linker, '.');
								if (tag) tag[0] = '\0';
							}

							char *new_name = NULL;
							if(new_linker[0] != '\0')
								dmasprintf(&new_name, "%s.%s", new_linker, vid);
							else
								new_name=dmstrdup(new_linker);

							/* Update device section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", new_name);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", new_linker);

							/* network->interface : Update ifname option */
							char *ifname = NULL;
							dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_sec, "ifname", &ifname);
							if (ifname && ifname[0] != '\0') {
								char new_ifname[128] = {0};

								remove_interface_from_ifname(new_linker, ifname, new_ifname);
								dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_sec, "ifname", new_ifname);
							}
							update_bridge_ifname(((struct bridge_vlanport_args *)data)->bridge_sec, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 1);

							/* dmmap_bridge->bridge : Update ifname option */
							struct uci_section *ss = NULL;
							get_dmmap_section_of_config_section("dmmap_bridge", "bridge", section_name(((struct bridge_vlanport_args *)data)->bridge_sec), &ss);
							dmuci_get_value_by_section_string(ss, "ifname", &ifname);
							if (ifname && ifname[0] != '\0') {
								char new_ifname[128] = {0};

								remove_interface_from_ifname(new_linker, ifname, new_ifname);
								dmuci_set_value_by_section(ss, "ifname", new_ifname);
							}
							update_bridge_ifname(ss, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 1);

							/* Update dmmap section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", section_name);

							/* Update dmmap bridge_port section */
							uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, ss) {
								if (strcmp(section_name(ss), section_name) == 0) {
									dmuci_set_value_by_section(ss, "device", new_name);
									update_device_management_port(new_linker, new_name, ((struct bridge_vlanport_args *)data)->br_inst);
									break;
								}
							}
							dmfree(new_name);
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

static int get_BridgingBridgeProviderBridge_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "type", "S-VLAN");
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
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "type", value);
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "enable", "0");
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
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "enable", b ? "1" : "0");
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "enable", value);
	*value = (strcmp(*value, "1") == 0) ? "Enabled" : "Disabled";
	return 0;
}

static int get_BridgingBridgeProviderBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "provider_bridge_alias", value);
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
		dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "provider_bridge_alias", value);
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *br_inst;
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "svlan_br_inst", &br_inst);
	if (br_inst && *br_inst)
		dmasprintf(value, "Device.Bridging.Bridge.%s", br_inst);
	return 0;
}

static int set_BridgingBridgeProviderBridge_SVLANcomponent(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *bridge_linker = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, NULL))
			return FAULT_9007;

		// Validate input value and Check if bridge is present
		if (strncmp(value, "Device.Bridging.Bridge.", 23) == 0 && strlen(value) > 23) {
			adm_entry_get_linker_value(ctx, value, &bridge_linker);
			if (!bridge_linker)
				return FAULT_9005;
		} else {
			return FAULT_9005;
		}
		break;
	case VALUESET:
		set_Provider_bridge_component(refparam, ctx, data, instance, value, "SVLAN");
		break;
	}
	return 0;
}

static int get_BridgingBridgeProviderBridge_CVLANcomponents(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *v= NULL;
	struct uci_element *e = NULL;
	char buf[1024] = {0}, *ptr, *br_path;
	int n;

	dmuci_get_value_by_section_list(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "cvlan_br_inst", &v);
	if (v == NULL)
		return 0;
	ptr = buf;
	/* Traverse each list value and create comma separated bridge path */
	uci_foreach_element(v, e) {
		dmasprintf(&br_path, "Device.Bridging.Bridge.%s", e->name);
		dmstrappendstr(ptr, br_path);
		dmstrappendstr(ptr, ",");
	}
	n = strlen(buf);
	if (n != 0)
		buf[n-1] = '\0';
	dmasprintf(value, "%s", buf);
	return 0;
}

static int set_BridgingBridgeProviderBridge_CVLANcomponents(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *bridge_linker = NULL;
	char buf[256];
	char *pch, *pchr;

	DM_STRNCPY(buf, value, sizeof(buf));

	switch (action)	{
		case VALUECHECK:
			/* Validate received list */
			if (dm_validate_string_list(value, -1, -1, -1, -1, 256, NULL, NULL))
				return FAULT_9007;

			// Validate each item in list and Check if bridge is present
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				// Parse each Bridge path and validate:
				if (strncmp(pch, "Device.Bridging.Bridge.", 23) == 0 && strlen(value) > 23) {
					adm_entry_get_linker_value(ctx, pch, &bridge_linker);
					if (!bridge_linker)
						return FAULT_9005;
				} else {
					return FAULT_9005;
				}
			}
			break;
		case VALUESET:
			// Set cvlan component(s):
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				set_Provider_bridge_component(refparam, ctx, data, instance, pch, "CVLAN");
			}
			break;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Bridging.Bridge.{i}.!UCI:network/interface/dmmap_network*/
static int browseBridgingBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *max_inst = NULL, *ifname, *section_name;
	struct bridge_args curr_bridging_args = {0};
	struct dmmap_dup *p = NULL;
	struct uci_section *ss = NULL;
	LIST_HEAD(dup_list);

	/* Sync dmmap_bridge with network config */
	sync_bridge_config_sections_with_dmmap_bridge_eq("network", "interface", "dmmap_bridge", "type", "bridge", &dup_list);
	list_for_each_entry(p, &dup_list, list) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
				p->dmmap_section, "bridge_instance", "bridge_alias");

		dmuci_get_value_by_section_string(p->dmmap_section, "ifname", &ifname);
		dmuci_get_value_by_section_string(p->dmmap_section, "section_name", &section_name);

		// get network interface section ==> ss = NULL so it is dmmap_bridge section, otherwise network bridge section
		ss = get_origin_section_from_config("network", "interface", section_name);

		/*
		 * We need three things to pass to next objects:
		 * 1) Bridge instance
		 * 2) network uci bridge config section of the bridge (if exists else dmmap_bridge section)
		 * 3) ifname, containing names of all the ports in bridge
		 */
		init_bridging_args(&curr_bridging_args, p->config_section, ifname, inst, (ss == NULL) ? true : false);

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
	char *inst = NULL, *max_inst = NULL;

	dmmap_synchronizeBridgingProviderBridge();
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 3,
				s, "provider_bridge_instance", "provider_bridge_alias");

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
	struct browse_args browse_args = {0};
	struct uci_section *s = NULL, *deviceport_s = NULL;
	char *inst = NULL, *max_inst = NULL, *device;

	dmmap_synchronizeBridgingBridgePort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, s) {

		/* Getting device from dmmap section */
		dmuci_get_value_by_section_string(s, "device", &device);

		/* Getting the corresponding device section */
		get_bridge_port_device_section(device, &deviceport_s);

		init_bridge_port_args(&curr_bridge_port_args, deviceport_s, s, br_args->bridge_sec, device, br_args->br_inst, br_args->is_dmmap_sec);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 5,
			   s, "bridge_port_instance", "bridge_port_alias",
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
		init_bridge_vlan_args(&curr_bridge_vlan_args, s, br_args->bridge_sec, br_args->br_inst, br_args->is_dmmap_sec);

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
{"Bridge", &DMWRITE, addObjBridgingBridge, delObjBridgingBridge, NULL, browseBridgingBridgeInst, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, get_linker_bridge, BBFDM_BOTH, LIST_KEY{"Alias", NULL}},
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
{"LastChange", &DMREAD, DMT_UNINT, get_BridgingBridgePort_LastChange, NULL, BBFDM_BOTH},
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
