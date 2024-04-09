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

#ifndef __DMLAYER_H__
#define __DMLAYER_H__

#include "libbbfdm-api/dmcommon.h"

void gre___get_tunnel_system_name(struct uci_section *iface_section, char *device_str, size_t device_str_size);

bool ip___is_gre_protocols(const char *proto);
bool ip___is_ip_interface_instance_exists(const char *sec_name, const char *device);
void ip___update_child_interfaces(char *device, char *option_name, char *option_value);

void ppp___update_sections(struct uci_section *s_from, struct uci_section *s_to);
void ppp___reset_options(struct uci_section *ppp_s);
void ppp___Update_PPP_Interface_Top_Layers(char *path, char *linker);

void ethernet___Update_MAC_VLAN_Top_Layers(char *path, char *linker);
void ethernet___Update_VLAN_Termination_Top_Layers(char *path, char *linker);
void ethernet___Update_Link_Layer(char *path, char *linker);
void ethernet___Update_Link_Top_Layers(char *path, char *linker);

void bridging___get_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char **value);
void bridging___set_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char *value);

void firewall__create_zone_section(char *s_name);

struct uci_section *ethernet___get_ethernet_interface_section(const char *device_name);
char *ethernet___get_ethernet_interface_name(char *device_name);

#endif //__DMLAYER_H__
