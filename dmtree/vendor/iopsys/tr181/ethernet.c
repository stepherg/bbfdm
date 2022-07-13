/*
 * Copyright (C) 2021 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "tr181/ethernet.h"
#include "ethernet.h"

static int get_EthernetVLANTermination_MACVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "type", value);
	*value = (DM_LSTRCMP(*value, "macvlan") == 0) ? "1" : "0";
	return 0;
}

static int set_EthernetVLANTermination_MACVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *name, *ifname;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "ifname", &ifname);
			dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "name", &name);
			struct uci_section *s = NULL, *dmmap_s = NULL;
			if (b && *name != '\0') {
				char *link_instance = NULL, new_name[16] = {0};
				int name_found = 0;

				uci_foreach_option_eq("network", "interface", "device", name, s) {

					get_dmmap_section_of_config_section_eq("dmmap", "link", "device", name, &dmmap_s);
					if (dmmap_s) {
						dmuci_get_value_by_section_string(dmmap_s, "link_instance", &link_instance);
						snprintf(new_name, sizeof(new_name), "%s_%s", ifname, link_instance);

						if (ethernet___name_exists_in_devices(new_name))
							return -1;

						dmuci_set_value_by_section(dmmap_s, "device", new_name);
						dmuci_set_value_by_section(dmmap_s, "section_name", section_name(s));

					}

					dmuci_set_value_by_section(s, "device", new_name);

					name_found = 1;
					break;
				}

				if (name_found == 0) {
					int ifname_found = 0;
					struct uci_section *ss = NULL;

					uci_foreach_option_eq("network", "interface", "device", ifname, ss) {

						uci_path_foreach_option_eq(bbfdm, "dmmap", "link", "device", ifname, dmmap_s) {
							char *sec_name;
							dmuci_get_value_by_section_string(dmmap_s, "section_name", &sec_name);
							/* Check section name exist => if yes, continue*/
							if (!ethernet___check_section_in_curr_section(sec_name, section_name(ss)))
								continue;

							dmuci_get_value_by_section_string(dmmap_s, "link_instance", &link_instance);
							snprintf(new_name, sizeof(new_name), "%s_%s", ifname, link_instance);

							if (ethernet___name_exists_in_devices(new_name))
								return -1;

							dmuci_set_value_by_section(dmmap_s, "device", new_name);
							dmuci_set_value_by_section(dmmap_s, "section_name", section_name(ss));
						}

						dmuci_set_value_by_section(ss, "device", new_name);

						ifname_found = 1;
						break;
					}

					if (ifname_found == 0) {
						get_dmmap_section_of_config_section_eq("dmmap", "link", "device", ifname, &dmmap_s);
						if (dmmap_s) {
							dmuci_get_value_by_section_string(dmmap_s, "link_instance", &link_instance);
							snprintf(new_name, sizeof(new_name), "%s_%s", ifname, link_instance);

							if (ethernet___name_exists_in_devices(new_name))
								return -1;

							dmuci_set_value_by_section(dmmap_s, "device", new_name);
							dmuci_set_value_by_section(dmmap_s, "section_name", "");

						}
					}
				}

				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", new_name);
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "type", "macvlan");
			} else if (!b && *name != '\0') {
				char *vid = NULL, new_name[16] = {0};

				uci_foreach_option_eq("network", "interface", "device", name, s) {

					get_dmmap_section_of_config_section_eq("dmmap", "link", "device", name, &dmmap_s);
					if (dmmap_s) {
						dmuci_get_value_by_section_string(((struct dmmap_dup *)data)->config_section, "vid", &vid);
						if (vid && *vid)
							snprintf(new_name, sizeof(new_name), "%s.%s", ifname, vid);
						else
							snprintf(new_name, sizeof(new_name), "%s", ifname);

						if (ethernet___name_exists_in_devices(new_name))
							return -1;

						dmuci_set_value_by_section(dmmap_s, "device", new_name);
					}

					dmuci_set_value_by_section(s, "device", new_name);
					break;
				}

				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "name", new_name);
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "type", "8021q");
			} else {
				dmuci_set_value_by_section(((struct dmmap_dup *)data)->config_section, "type", b ? "macvlan" : "8021q");
			}
			break;
	}
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
DMLEAF tIOPSYS_EthernetVLANTerminationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{BBF_VENDOR_PREFIX"MACVLAN", &DMWRITE, DMT_BOOL, get_EthernetVLANTermination_MACVLAN, set_EthernetVLANTermination_MACVLAN, BBFDM_BOTH},
{0}
};
