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

#include "device.h"
#include "x_test_com_dropbear.h"

DMOBJ tTEST_DeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys*/
{BBF_VENDOR_PREFIX"Dropbear", &DMWRITE, add_dropbear_instance, delete_dropbear_instance, "file:/etc/config/dropbear", browse_dropbear_instance, NULL, NULL, NULL, X_TEST_COM_DropbearParams, NULL, BBFDM_BOTH},
{0}
};
