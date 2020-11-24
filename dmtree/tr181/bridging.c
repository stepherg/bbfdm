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

	check_create_dmmap_package(config);
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
	struct uci_section *s;

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
	struct uci_section *s;
	char *instance = NULL, *last_inst = NULL;

	// Check if the dmmap file exists
	check_create_dmmap_package(dmmap_package);
	// traverse all bridge config and return the last instance of bridge
	uci_path_foreach_sections(bbfdm, dmmap_package, section, s) {
		instance = update_instance(last_inst, 4, s, opt_inst, dmmap_package, section);
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
	char ifname_dup[128], *ptr, *ifname, *start, *end;
	int pos = 0;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (is_strword_in_optionvalue(ifname_dup, baseifname)) {
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
	char ifname_dup[128], *ptr, *ifname;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	ptr = ifname_dup;
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
			char *name;
			dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &sbr_vlan, &name);
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
			char *sbr_name;
			dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &sbr_vlanport, &sbr_name);
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
	struct uci_section *s, *dmmap_sect, *ss = NULL;
	char *v, *ifname, *section_name;

	dmmap_file_path_get(dmmap_package);

	uci_foreach_option_eq(package, section_type, option_name, option_value, s) {
		/*
		 * create/update corresponding dmmap section that have same config_section link and using param_value_array
		 * If the section belong to provider bridge (section name: pr_br_{i}) then skip adding to dmmap_package
		 */
		if((strncmp(section_name(s), "pr_br_", 6)) == 0)
			continue;

		if ((dmmap_sect = get_dup_section_in_dmmap(dmmap_package, "bridge", section_name(s))) == NULL) {
			// Update dmmap_bridge
			dmuci_add_section_bbfdm(dmmap_package, "bridge", &dmmap_sect, &v);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "section_name", section_name(s));
			dmuci_get_value_by_section_string(s, "ifname", &ifname);
			dmuci_set_value_by_section_bbfdm(dmmap_sect, "ifname", ifname);
		}
	}
	/*
	 * Add system and dmmap sections to the list
	 */
	uci_path_foreach_sections(bbfdm, dmmap_package, "bridge", dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &section_name);
		ss = get_origin_section_from_config(package, section_type, section_name);
		if (ss == NULL) {
			add_sectons_list_paramameter(dup_list, dmmap_sect, dmmap_sect, NULL);
		} else {
			add_sectons_list_paramameter(dup_list, ss, dmmap_sect, NULL);
		}
	}
}

void dmmap_synchronizeBridgingProviderBridge()
{
	struct uci_section *s, *dmmap_br_sec, *dmmap_pr_br_sec;
	char *v;
	char *ifname;

	dmmap_file_path_get("dmmap_provider_bridge");
	dmmap_file_path_get("dmmap_bridge");

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		/*
		 * If the section belong to provider bridge (section name: pr_br_{i}) then proceed, else continue
		 */
		if((strncmp(section_name(s), "pr_br_", 6)) != 0)
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
		char *ptr_svlan = svlan_device;
		char *ptr_cvlan = cvlan_device;
		char *last_inst_dmmap;
		char current_inst[3], pr_br_alias[10];

		// 1) Get its ifname - member device(s) of bridges.
		dmuci_get_value_by_section_string(s, "ifname", &ifname);

		// 2) Extract svlan and cvlan bridge component.
		for (pch = strtok_r(ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			uci_foreach_option_eq("network", "device", "name", pch, ss) {
				char *type;
				dmuci_get_value_by_section_string(ss, "type", &type);

				// If type is 8021ad, add to svlan
				if (strcmp(type,"8021ad") == 0) {
					strcpy(ptr_svlan, pch);
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
		dmuci_add_section_bbfdm("dmmap_provider_bridge", "provider_bridge", &dmmap_pr_br_sec, &v);
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
			dmuci_add_section_bbfdm("dmmap_bridge", "bridge", &dmmap_br_sec, &v);
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
			dmuci_add_section_bbfdm("dmmap_bridge", "bridge", &dmmap_br_sec, &v);
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
	struct uci_section *sec;
	char *svlan;
	struct uci_list *v = NULL;
	struct uci_element *e;
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
		bool found = false;
		dmuci_get_value_by_section_list(sec, "cvlan_br_inst", &v);
		if (v != NULL) {
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
	char *br_ifname = NULL, *pch = NULL, *spch = NULL, *p, plinker[32], linker_buf[512] = {0};
	char *sec_name;
	if (br_args->bridge_sec == NULL) {
		return 0;
	}

	// if the bridge section is dmmap_sec then get section_name option value
	if (br_args->is_dmmap_sec == true) {
		dmuci_get_value_by_section_string(br_args->bridge_sec, "section_name", &sec_name);
	}

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
	stmp = NULL; s = NULL;
	char *pr_br_inst;
	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_bridge", "bridge", "bridge_instance", br_args->br_inst, stmp, s) {
		dmuci_get_value_by_section_string(s, "added_by_user", &s_user);
		if (strcmp(s_user, "1") != 0) {
			if (!is_bridge_port_management_in_dmmap(br_args->br_inst)) {
				struct uci_section *sbr_port = NULL;
				char *sbr_name;
				dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &sbr_port, &sbr_name);
				dmuci_set_value_by_section(sbr_port, "br_inst", br_args->br_inst);

				/*
				 * Add provider bridge instance number here if this bridge inst. is
				 * a svlan/cvlan bridge of a provider bridge
				 */
				if (is_bridge_pr_br_member(br_args->br_inst, &pr_br_inst)) {
					dmuci_set_value_by_section(sbr_port, "provider_br_inst", pr_br_inst);
				}

				dmuci_set_value_by_section(sbr_port, "interface", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec));
				dmuci_set_value_by_section(sbr_port, "management", "1");
			}
		}
	}

	if (br_args->ifname[0] == '\0')
		return 0;

	p = linker_buf;
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
		char *sbr_name;
		dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &sbr_port, &sbr_name);
		dmuci_set_value_by_section(sbr_port, "device", pch);
		dmuci_set_value_by_section(sbr_port, "br_inst", br_args->br_inst);

		/*
		 * Add provider bridge instance number here if this bridge inst. is
		 * a svlan/cvlan bridge of a provider bridge
		 */
		if (is_bridge_pr_br_member(br_args->br_inst, &pr_br_inst)) {
			dmuci_set_value_by_section(sbr_port, "provider_br_inst", pr_br_inst);
		}

		dmuci_set_value_by_section(sbr_port, "interface", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec));
		dmuci_set_value_by_section(sbr_port, "management", "0");
		snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(sbr_port), pch);
		dmstrappendstr(p, plinker);
		dmstrappendchr(p, ',');
	}
	dmfree(br_ifname);
	struct uci_section *ss = NULL;
	uci_foreach_option_eq("wireless", "wifi-iface", "network", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec), ss) {

		// get ifname from wireless/wifi-iface section
		char *ifname;
		dmuci_get_value_by_section_string(ss, "ifname", &ifname);

		if (is_bridge_port_device_exist(br_args->br_inst, ifname, &dmmap_br_port)) {
			if (dmmap_br_port) {
				snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(dmmap_br_port), ifname);
				dmstrappendstr(p, plinker);
				dmstrappendchr(p, ',');
			}
			continue;
		}

		struct uci_section *sbr_port = NULL;
		char *sbr_name;
		dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &sbr_port, &sbr_name);
		dmuci_set_value_by_section(sbr_port, "device", ifname);
		dmuci_set_value_by_section(sbr_port, "br_inst", br_args->br_inst);
		dmuci_set_value_by_section(sbr_port, "interface", br_args->is_dmmap_sec ? sec_name : section_name(br_args->bridge_sec));
		dmuci_set_value_by_section(sbr_port, "management", "0");
		snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", br_args->br_inst, section_name(sbr_port), ifname);
		dmstrappendstr(p, plinker);
		dmstrappendchr(p, ',');
	}

	p = p -1;
	dmstrappendend(p);

	// Update the device linker for management port
	set_linker_bridge_port_management(br_args->br_inst, linker_buf);
	return 0;
}

static void get_bridge_vlanport_device_section(struct uci_section *dmmap_section, struct uci_section **device_section)
{
	struct uci_section *s;
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

static void get_bridge_port_device_section(struct uci_section *dmmap_section, struct uci_section **device_section)
{
	struct uci_section *s;
	char *device;

	/* Get device from dmmap section */
	dmuci_get_value_by_section_string(dmmap_section, "device", &device);

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
	char lower_layer[256] = {0}, lower_layer_path[256] = {0};
	char *pch = NULL, *spch = NULL, *p, new_device[512] = { 0, 0 };

	p = new_device;
	for (pch = strtok_r(value, ",", &spch); pch != NULL; pch = strtok_r(NULL, ",", &spch)) {

		append_dot_to_string(lower_layer, pch, sizeof(lower_layer));

		snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", ((struct bridge_port_args *)data)->br_inst);

		if (strncmp(lower_layer, lower_layer_path, strlen(lower_layer_path)) == 0) {
			/* check linker is available */
			char *linker = NULL;
			adm_entry_get_linker_value(ctx, lower_layer, &linker);
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

static void update_vlanport_and_device_section(void *data, char *linker, char **new_linker)
{
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
			dmuci_set_value_by_section(ss, "name", *new_linker);
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
				char new_ifname[128], *ifname;
				dmuci_get_value_by_section_string(bridge_sec, "ifname", &ifname);
				if (ifname[0] != '\0') {
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
	char *ptr;

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
	char *management, *device, *s_name;
	char **device_comma;
	size_t length_comma, tmp_length;
	char **tmp_list;
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
	dmuci_add_section("network", "interface", &s, &s_name);
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

// Function to remove a svlan/cvlan instance from Provider bridge
void rem_bridge_from_provider_bridge(char *bridge_inst)
{
	struct uci_section *sec = NULL, *network_bridge_sec = NULL, *dmmap_br_sec = NULL, *s = NULL, *stmp = NULL;
	char *svlan, *pr_br_inst = NULL, *br_inst = NULL, *bridges = NULL;
	struct uci_list *v = NULL;
	struct uci_element *e;
	char *management, *device;
	char **device_comma;
	size_t length, tmp_length;
	char **tmp_list;
	char ifname[50] = {0};
	char *ptr = ifname;
	int i;
	char **bridge_ifname;
	char new_ifname[50] = {0};


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
					continue;

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
						continue;
					}
					dmstrappendstr(ptr, bridge_ifname[i]);
					dmstrappendchr(ptr, ' ');
				}
				if (ptr != NULL) {
					ptr = ptr -1;
					dmstrappendend(ptr);
				}

				if (new_ifname[0] == '\0')
					dmuci_delete_by_section(network_bridge_sec, NULL, NULL);
				else
					dmuci_set_value_by_section(network_bridge_sec, "ifname", new_ifname);
			}
		}
		// Check if the passed bridge section is cvlan
		bool found = false;
		dmuci_get_value_by_section_list(sec, "cvlan_br_inst", &v);
		if (v != NULL) {
			uci_foreach_element(v, e) {
				if (strcmp(e->name, bridge_inst) == 0) {
					found = true;
					break;
				}
			}
			if (found == true) {
				restore_bridge_config(bridge_inst);
				dmuci_del_list_value_by_section(sec, "cvlan_br_inst", bridge_inst);

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
					continue;

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
						continue;
					}
					dmstrappendstr(ptr, bridge_ifname[i]);
					dmstrappendchr(ptr, ' ');
				}
				if (ptr != NULL) {
					ptr = ptr -1;
					dmstrappendend(ptr);
				}

				if (new_ifname[0] == '\0')
					dmuci_delete_by_section(network_bridge_sec, NULL, NULL);
				else
					dmuci_set_value_by_section(network_bridge_sec, "ifname", new_ifname);
			}
		}
	}
}

/*************************************************************
* ADD DELETE OBJECT
**************************************************************/
static int addObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char bridge_name[32], *last_inst, *v;
	struct uci_section *dmmap_bridge = NULL;

	last_inst = get_last_instance_bridge_bbfdm("dmmap_bridge", "bridge", "bridge_instance");
	snprintf(bridge_name, sizeof(bridge_name), "bridge_%d", last_inst ? atoi(last_inst)+1 : 1);

	// Add interface bridge section
	dmuci_set_value("network", bridge_name, "", "interface");
	dmuci_set_value("network", bridge_name, "type", "bridge");

	// Add dmmap bridge section
	dmuci_add_section_bbfdm("dmmap_bridge", "bridge", &dmmap_bridge, &v);
	dmuci_set_value_by_section(dmmap_bridge, "section_name", bridge_name);
	dmuci_set_value_by_section(dmmap_bridge, "added_by_user", "1");
	*instance = update_instance(last_inst, 4, dmmap_bridge, "bridge_instance", "dmmap_bridge", "bridge");
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
	struct uci_section *br_port_s;
	char *v, *sec_name = NULL;

	int inst = get_last_inst("dmmap_bridge_port", "bridge_port", "br_inst", "bridge_port_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);

	// Add dmmap section for devices
	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s, &v);
	dmuci_set_value_by_section(br_port_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
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
			// Remove ifname from ifname list of bridge section
			char new_ifname[128], *ifname;
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "ifname", &ifname);
			if (ifname[0] != '\0') {
				remove_interface_from_ifname(device, ifname, new_ifname);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_sec, "ifname", new_ifname);
			}

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
	char *s_name, *br_vlanport_name, *device_name;

	check_create_dmmap_package("dmmap_bridge_vlanport");
	int inst = get_last_inst("dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", "bridge_vlanport_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);
	dmasprintf(&device_name, "br_%s_port_%s", ((struct bridge_args *)data)->br_inst, *instance);

	// Add device section
	dmuci_add_section("network", "device", &s, &s_name);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_bridge_vlanport", "bridge_vlanport", &br_vlanport_s, &br_vlanport_name);
	dmuci_set_value_by_section(br_vlanport_s, "br_inst", ((struct bridge_args *)data)->br_inst);
	dmuci_set_value_by_section(br_vlanport_s, "bridge_vlanport_instance", *instance);
	dmuci_set_value_by_section(br_vlanport_s, "device_name", device_name);
	dmuci_set_value_by_section(br_vlanport_s, "added_by_user", "1");

	return 0;
}

static int delObjBridgingBridgeVLANPort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *prev_s = NULL;

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

	return 0;
}

static int addObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_vlan_s = NULL;
	char *sec_name = NULL, *v = NULL;

	int inst = get_last_inst("dmmap_bridge_vlan", "bridge_vlan", "br_inst", "bridge_vlan_instance", ((struct bridge_args *)data)->br_inst);
	dmasprintf(instance, "%d", inst+1);
	dmuci_add_section_bbfdm("dmmap_bridge_vlan", "bridge_vlan", &br_vlan_s, &v);
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
	char *last_instance = NULL, *v = NULL;

	check_create_dmmap_package("dmmap_provider_bridge");
	last_instance = get_last_instance_bbfdm("dmmap_provider_bridge", "provider_bridge", "provider_bridge_instance");

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_provider_bridge", "provider_bridge", &pr_br_sec, &v);
	dmuci_set_value_by_section(pr_br_sec, "enable", "1");
	dmuci_set_value_by_section(pr_br_sec, "type", "S-VLAN");
	*instance = update_instance(last_instance, 4, pr_br_sec, "provider_bridge_instance", "dmmap_provider_bridge", "provider_bridge");
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
	*value = "0";
	return 0;
}

static int get_Bridging_get_Bridging_MaxFilterEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
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
	struct uci_section *dmmap_section = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge", "bridge", "bridge_instance", ((struct bridge_args *)data)->br_inst, dmmap_section) {
		dmuci_get_value_by_section_string(dmmap_section, "bridge_alias", value);
		break;
	}

	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge", "bridge", "bridge_instance", ((struct bridge_args *)data)->br_inst, dmmap_section) {
				dmuci_set_value_by_section(dmmap_section, "bridge_alias", value);
				break;
			}
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
			if (dm_validate_string(value, -1, -1, BridgeStandard, 3, NULL, 0))
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
	char *device, *eth_ports, *management;

	*value = "0";
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
	if (strcmp(management, "1") == 0)
		return 0;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &device);
	db_get_value_string("hw", "board", "ethernetLanPorts", &eth_ports);
	if (dm_strword(eth_ports, device)) {
		// ethport ports section
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", value);
	} else {
		// device section
		json_object *res = NULL;
		char *up;
		dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &res);
		DM_ASSERT(res, *value = "0");
		up = dmjson_get_value(res, 1, "up");
		*value = up ? "1" :"0";
	}
	return 0;
}

static int set_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *device, *eth_ports, *management;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
			if (strcmp(management, "1") == 0)
				return 0;

			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &device);
			db_get_value_string("hw", "board", "ethernetLanPorts", &eth_ports);
			if (strstr(eth_ports, device)) {
				// ethport ports section
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", b ? "1" : "0");
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), pch, value);
			if (*value == NULL)
				*value = "";
			dmstrappendstr(p, *value);
			dmstrappendchr(p, ',');
		}
		p = p -1;
		dmstrappendend(p);
		*value = dmstrdup(lbuf);
	} else {
		char *linker = "";
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", &linker);
		char *tag = strchr(linker, '.');
		if (tag) tag[0] = '\0';

		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx,dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cATM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value == NULL)
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cPTM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);

		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0}, *management;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "management", &management);
			if (strcmp(management, "1") == 0) {
				/* Management Port ==> true */
				set_lowerlayers_management_port(ctx, data, value);
			} else {
				/* Management Port ==> false */

				append_dot_to_string(lower_layer, value, sizeof(lower_layer));

				char *linker = NULL;
				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				if (!linker || linker[0] == '\0')
					return 0;

				if (check_ifname_exist_in_br_ifname_list(linker, section_name(((struct bridge_port_args *)data)->bridge_sec)))
					return 0;

				char *device;
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_dmmap_sec, "device", &device);
				if (device[0] == '\0') {
					// Check if there is a vlan port pointed at me
					char *new_linker = NULL;
					update_vlanport_and_device_section(data, linker, &new_linker);
					if (new_linker) linker = new_linker;

					// Add name to ifname list interface
					add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

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

						// Add name to ifname list interface
						add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, new_name);

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

						// Add name to ifname list interface
						add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);

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
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "priority", value);
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

static void get_priority_list(char *uci_opt_name, void *data, char **value)
{
	struct uci_list *v= NULL;
	struct uci_element *e = NULL;
	char uci_value[130], **priority = NULL;
	size_t length;
	int n;

	dmuci_get_value_by_section_list(((struct bridge_port_args *)data)->bridge_port_sec, uci_opt_name, &v);
	if (v == NULL)
		return;

	uci_value[0] = '\0';
	/* traverse each list value and create comma separated output */
	uci_foreach_element(v, e) {
		//delimiting priority which is in the form of x:y where y is the priority
		priority = strsplit(e->name, ":", &length);
		strcat(uci_value, priority[1]);
		strcat(uci_value, ",");
	}
	n = strlen(uci_value);
	if (n != 0)
		uci_value[n-1] = '\0';

	dmasprintf(value, "%s", uci_value);
}

static void set_priority_list(char *uci_opt_name, void *data, char *value)
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
	get_priority_list("ingress_qos_mapping", data, value);
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
			set_priority_list("ingress_qos_mapping", data, value);
			break;
	}
	return 0;
}

static int get_BridgingBridgePort_Egress_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_priority_list("egress_qos_mapping", data, value);
	return 0;
}

static int set_BridgingBridgePort_Egress_PriorityRegeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, 8, 8, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;

		case VALUESET:
			set_priority_list("egress_qos_mapping", data, value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_DSCP_Eth_Priority_Map(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_priority_list("dscp2pbit", data, value);
	return 0;
}

static int set_BridgingBridgePort_DSCP_Eth_Priority_Map(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, 1, 64, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;

		case VALUESET:
			set_priority_list("dscp2pbit", data, value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_PVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "vid", value);
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
				struct uci_section *vlanport_s;
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
					struct uci_section *device_s, *vlanport_s;
					char *ifname, *new_name;

					/* Update vid and name of device section */
					uci_foreach_option_eq("network", "device", "name", pch, device_s) {
						dmuci_get_value_by_section_string(device_s, "ifname", &ifname);
						dmasprintf(&new_name, "%s.%s", ifname, value);
						dmuci_set_value_by_section(device_s, "name", new_name);
						dmuci_set_value_by_section(device_s, "vid", value);
					}

					/* Update vlan port section in dmmap */
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, vlanport_s) {
						char *vlan_name;
						dmuci_get_value_by_section_string(vlanport_s, "name", &vlan_name);
						if (strcmp(vlan_name, pch) == 0) {
							dmuci_set_value_by_section(vlanport_s, "name", new_name);
							break;
						}
					}

					/* Update port section in dmmap */
					struct uci_section *s;
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, s) {
						char *device;
						dmuci_get_value_by_section_string(s, "device", &device);
						if (strcmp(device, pch) == 0) {
							dmuci_set_value_by_section(s, "device", new_name);
							update_device_management_port(device, new_name, ((struct bridge_vlanport_args *)data)->br_inst);
							break;
						}
					}

					add_new_ifname_to_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, new_name);
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
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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

	char linker[32], *vid = "";

	/* Get vid from device network section */
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);
	if (vid[0] != '\0') {
		/* Get linker */
		snprintf(linker, sizeof(linker),"br_%s:vlan_%s", ((struct bridge_vlanport_args *)data)->br_inst, (vid[0] != '\0') ? vid : "1");
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0}, lower_layer_path[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			append_dot_to_string(lower_layer, value, sizeof(lower_layer));
			snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLAN.", ((struct bridge_vlanport_args *)data)->br_inst);

			/* Check the path object is correct or no */
			if (strncmp(lower_layer, lower_layer_path, strlen(lower_layer_path)) == 0) {
				/* Check linker exist */
				char *linker = NULL;
				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				if (!linker)
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
						struct uci_section *s;
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
				}
			}
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
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), plinker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0}, lower_layer_path[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			append_dot_to_string(lower_layer, value, sizeof(lower_layer));
			snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.Port.", ((struct bridge_vlanport_args *)data)->br_inst);

			if (strncmp(lower_layer, lower_layer_path, strlen(lower_layer_path)) == 0) {
				char *linker = NULL;
				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				if (!linker)
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

							/* Update ifname list */
							char new_ifname[128], *ifname;
							dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_sec, "ifname", &ifname);
							if (ifname[0] != '\0') {
								remove_interface_from_ifname(new_linker, ifname, new_ifname);
								dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_sec, "ifname", new_ifname);
							}
							update_bridge_ifname(((struct bridge_vlanport_args *)data)->bridge_sec, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 1);

							/* Update dmmap section */
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "name", new_name);
							dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_dmmap_sec, "port_name", section_name);

							/* Update dmmap bridge_port section */
							struct uci_section *ss = NULL;
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
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "type", value);
	return 0;
}

int set_BridgingBridgeProviderBridge_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, -1, Provider_Bridge_Type, 2, NULL, 0))
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
	dmuci_get_value_by_section_string(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "enable", value);
	if(*value[0] == '\0')
		*value = "0";
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
		if (b)
			dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "enable", "1");
		else
			dmuci_set_value_by_section(((struct provider_bridge_args *)data)->dmmap_bridge_sec, "enable", "0");
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
		if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
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
	char br_inst[256] = {0};

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
			return FAULT_9007;

		// Validate input value and Check if bridge is present
		if (strncmp(value, "Device.Bridging.Bridge.", 23) == 0 && strlen(value) > 23) {
			append_dot_to_string(br_inst, value, sizeof(br_inst));
			adm_entry_get_linker_value(ctx, br_inst, &bridge_linker);
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
	char br_inst[256] = {0};
	char buf[strlen(value)+1];
	char *pch, *pchr;

	strncpy(buf, value, sizeof(buf) - 1);
	buf[strlen(value)] = '\0';

	switch (action)	{
		case VALUECHECK:
			/* Validate received list */
			if (dm_validate_string_list(value, -1, -1, -1, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			// Validate each item in list and Check if bridge is present
			for (pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				// Parse each Bridge path and validate:
				if (strncmp(pch, "Device.Bridging.Bridge.", 23) == 0 && strlen(value) > 23) {
					append_dot_to_string(br_inst, pch, sizeof(br_inst));
					adm_entry_get_linker_value(ctx, br_inst, &bridge_linker);
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
	bool is_dmmap_sec;
	struct uci_section *ss = NULL;
	LIST_HEAD(dup_list);

	/*
	 * Sync network with dmmap_bridge
	 * We need three things to pass to next objects:
	 * 1) Bridge instance
	 * 2) network uci bridge config section of the bridge (if exists else dmmap_bridge section)
	 * 3) ifname, containing names of all the ports in bridge
	 *
	 */

	/* Sync dmmap_bridge with network config */
	sync_bridge_config_sections_with_dmmap_bridge_eq("network", "interface", "dmmap_bridge", "type", "bridge", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
				  p->dmmap_section, "bridge_instance", "bridge_alias", "dmmap_bridge", "bridge");

		dmuci_get_value_by_section_string(p->dmmap_section, "ifname", &ifname);
		ss = NULL;
		// Set is_dmmap_sec flag
		// false -> if p>config_section is network config section
		// true -> if p>config_section is dmmap_bridge config section

		dmuci_get_value_by_section_string(p->dmmap_section, "section_name", &section_name);
		ss = get_origin_section_from_config("network", "interface", section_name);
		if (ss == NULL) {
			is_dmmap_sec = true; // Indicates its a dmmap_bridge section
		} else {
			is_dmmap_sec = false; // Indicate its a network bridge section
		}
		init_bridging_args(&curr_bridging_args, p->config_section, ifname, inst, is_dmmap_sec);
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

	check_create_dmmap_package("dmmap_provider_bridge");
	dmmap_synchronizeBridgingProviderBridge();
	uci_path_foreach_sections(bbfdm, "dmmap_provider_bridge", "provider_bridge", s) {

		inst = handle_update_instance(1, dmctx, &max_inst, update_instance_alias, 5,
				s, "provider_bridge_instance", "provider_bridge_alias", "dmmap_provider_bridge", "Provider_bridge");

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

	check_create_dmmap_package("dmmap_bridge_port");
	dmmap_synchronizeBridgingBridgePort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_args->br_inst, s) {
		get_bridge_port_device_section(s, &deviceport_s);
		dmuci_get_value_by_section_string(s, "device", &device);
		init_bridge_port_args(&curr_bridge_port_args, deviceport_s, s, br_args->bridge_sec, device, br_args->br_inst, br_args->is_dmmap_sec);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
					s, "bridge_port_instance", "bridge_port_alias", "dmmap_bridge_port", "bridge_port",
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

	check_create_dmmap_package("dmmap_bridge_vlan");
	dmmap_synchronizeBridgingBridgeVLAN(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlan", "bridge_vlan", "br_inst", br_args->br_inst, s) {
		init_bridge_vlan_args(&curr_bridge_vlan_args, s, br_args->bridge_sec, br_args->br_inst, br_args->is_dmmap_sec);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
					s, "bridge_vlan_instance", "bridge_vlan_alias", "dmmap_bridge_vlanport", "bridge_vlan",
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

	check_create_dmmap_package("dmmap_bridge_vlanport");
	dmmap_synchronizeBridgingBridgeVLANPort(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_vlanport", "bridge_vlanport", "br_inst", br_args->br_inst, s) {
		get_bridge_vlanport_device_section(s, &device_s);
		init_bridge_vlanport_args(&curr_bridge_vlanport_args, device_s, s, br_args->bridge_sec, br_args->br_inst);

		browse_args.option = "br_inst";
		browse_args.value = br_args->br_inst;

		inst = handle_update_instance(2, dmctx, &max_inst, update_instance_alias, 7,
						s, "bridge_vlanport_instance", "bridge_vlanport_alias", "dmmap_bridge_vlanport", "bridge_vlanport",
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
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{"Bridge", &DMWRITE, addObjBridgingBridge, delObjBridgingBridge, NULL, browseBridgingBridgeInst, NULL, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, get_linker_bridge, BBFDM_BOTH},
{"ProviderBridge", &DMWRITE, addObjBridgingProviderBridge , delObjBridgingProviderBridge, NULL, browseBridgingProviderBridgeInst, NULL, NULL, NULL, NULL, tBridgingProviderBridgeParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MaxBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxDBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxDBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxQBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxQBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxVLANEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxVLANEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxProviderBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxProviderBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxFilterEntries", &DMREAD, DMT_UNINT, get_Bridging_get_Bridging_MaxFilterEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"BridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridging_BridgeNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}. ***/
DMOBJ tBridgingBridgeObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Port", &DMWRITE, addObjBridgingBridgePort, delObjBridgingBridgePort, NULL, browseBridgingBridgePortInst, NULL, NULL, NULL, tBridgingBridgePortObj, tBridgingBridgePortParams, get_linker_br_port, BBFDM_BOTH},
{"VLAN", &DMWRITE, addObjBridgingBridgeVLAN, delObjBridgingBridgeVLAN, NULL, browseBridgingBridgeVLANInst, NULL, NULL, NULL, NULL, tBridgingBridgeVLANParams, get_linker_br_vlan, BBFDM_BOTH},
{"VLANPort", &DMWRITE, addObjBridgingBridgeVLANPort, delObjBridgingBridgeVLANPort, NULL, browseBridgingBridgeVLANPortInst, NULL, NULL, NULL, NULL, tBridgingBridgeVLANPortParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridge_Enable, set_BridgingBridge_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridge_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridge_Alias, set_BridgingBridge_Alias, NULL, NULL, BBFDM_BOTH},
{"Standard", &DMWRITE, DMT_STRING, get_BridgingBridge_Standard, set_BridgingBridge_Standard, NULL, NULL, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_PortNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANPortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANPortNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}. ***/
DMOBJ tBridgingBridgePortObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgePortStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingBridgePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_Enable, set_BridgingBridgePort_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgePort_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Alias, set_BridgingBridgePort_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_BridgingBridgePort_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_BridgingBridgePort_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_BridgingBridgePort_LowerLayers, set_BridgingBridgePort_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"ManagementPort", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_ManagementPort, set_BridgingBridgePort_ManagementPort, NULL, NULL, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Type, set_BridgingBridgePort_Type, NULL, NULL, BBFDM_BOTH},
{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_DefaultUserPriority, set_BridgingBridgePort_DefaultUserPriority, NULL, NULL, BBFDM_BOTH},
{"PriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_PriorityRegeneration, set_BridgingBridgePort_PriorityRegeneration, NULL, NULL, BBFDM_BOTH},
{"X_IOPSYS_EU_EgressPriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Egress_PriorityRegeneration, set_BridgingBridgePort_Egress_PriorityRegeneration, NULL, NULL, BBFDM_BOTH},
{"X_IOPSYS_EU_DSCPEthernetPriorityMapping", &DMWRITE, DMT_STRING, get_BridgingBridgePort_DSCP_Eth_Priority_Map, set_BridgingBridgePort_DSCP_Eth_Priority_Map, NULL, NULL, BBFDM_BOTH},
//{"PortState", &DMREAD, DMT_STRING, get_BridgingBridgePort_PortState, NULL, NULL, NULL, BBFDM_BOTH},
{"PVID", &DMWRITE, DMT_INT, get_BridgingBridgePort_PVID, set_BridgingBridgePort_PVID, NULL, NULL, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_TPID, set_BridgingBridgePort_TPID, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}.Stats. ***/
DMLEAF tBridgingBridgePortStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLAN.{i}. ***/
DMLEAF tBridgingBridgeVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLAN_Enable, set_BridgingBridgeVLAN_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,get_BridgingBridgeVLAN_Alias, set_BridgingBridgeVLAN_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Name, set_BridgingBridgeVLAN_Name, NULL, NULL, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_INT, get_BridgingBridgeVLAN_VLANID, set_BridgingBridgeVLAN_VLANID, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLANPort.{i}. ***/
DMLEAF tBridgingBridgeVLANPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Enable, set_BridgingBridgeVLANPort_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_Alias, set_BridgingBridgeVLANPort_Alias, NULL, NULL, BBFDM_BOTH},
{"VLAN", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_VLAN, set_BridgingBridgeVLANPort_VLAN, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_STRING, get_BridgingBridgeVLANPort_Port, set_BridgingBridgeVLANPort_Port, NULL, NULL, BBFDM_BOTH},
{"Untagged", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Untagged, set_BridgingBridgeVLANPort_Untagged, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.ProviderBridge.{i}. ***/
DMLEAF tBridgingProviderBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeProviderBridge_Enable, set_BridgingBridgeProviderBridge_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgeProviderBridge_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,  get_BridgingBridgeProviderBridge_Alias, set_BridgingBridgeProviderBridge_Alias, NULL, NULL, BBFDM_BOTH},
{"Type", &DMWRITE, DMT_STRING,  get_BridgingBridgeProviderBridge_Type, set_BridgingBridgeProviderBridge_Type, NULL, NULL, BBFDM_BOTH},
{"SVLANcomponent", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_SVLANcomponent, set_BridgingBridgeProviderBridge_SVLANcomponent, NULL, NULL, BBFDM_BOTH},
{"CVLANcomponents", &DMWRITE, DMT_STRING, get_BridgingBridgeProviderBridge_CVLANcomponents, set_BridgingBridgeProviderBridge_CVLANcomponents, NULL, NULL, BBFDM_BOTH},
{0}
};
