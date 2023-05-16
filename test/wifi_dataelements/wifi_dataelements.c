/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 */

#include "../../libbbfdm/dmtree/tr181/wifi.dataelements.h"

/* *** Device.WiFi. *** */
DMOBJ tDeviceWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version*/
{"DataElements", &DMREAD, NULL, NULL, "file:/etc/init.d/decollector", NULL, NULL, NULL, tWiFiDataElementsObj, NULL, NULL, BBFDM_BOTH, NULL, "2.13"},
{0}
};

/* ********** DynamicObj ********** */
DM_MAP_OBJ tDynamicObj[] = {
/* parentobj, nextobject, parameter */
{"Device.WiFi.", tDeviceWiFiObj, NULL},
{0}
};
