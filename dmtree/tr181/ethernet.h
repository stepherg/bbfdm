/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __ETHERNET_H
#define __ETHERNET_H

#include "libbbf_api/dmcommon.h"

extern DMOBJ tEthernetObj[];
extern DMLEAF tEthernetParams[];
extern DMOBJ tEthernetInterfaceObj[];
extern DMLEAF tEthernetInterfaceParams[];
extern DMLEAF tEthernetInterfaceStatsParams[];
extern DMOBJ tEthernetLinkObj[];
extern DMLEAF tEthernetLinkParams[];
extern DMLEAF tEthernetLinkStatsParams[];
extern DMOBJ tEthernetVLANTerminationObj[];
extern DMLEAF tEthernetVLANTerminationParams[];
extern DMLEAF tEthernetVLANTerminationStatsParams[];
extern DMLEAF tEthernetRMONStatsParams[];

struct uci_section *ethernet___get_device_section(char *dev_name);
bool ethernet___check_vlan_termination_section(const char *name);
bool ethernet___check_section_in_curr_section(const char *curr_section, const char *section);
bool ethernet___name_exists_in_devices(char *name);

#endif //__ETHERNET_H
