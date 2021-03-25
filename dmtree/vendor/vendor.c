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

#include "vendor.h"

#ifdef BBF_VENDOR_IOPSYS
#include "iopsys/tr181/vendor.h"
#endif

#ifdef BBF_VENDOR_OPENWRT
#include "openwrt/tr181/vendor.h"
#endif

#ifdef BBF_VENDOR_TEST
#include "test/tr181/vendor.h"
#endif

/** This table is defined to add a new custom obj/param in the tree **/
DM_MAP_VENDOR tVendorExtension[] = {
/* customer, tableobject */

#ifdef BBF_VENDOR_IOPSYS
{"iopsys", tVendorExtensionIOPSYS},
#endif

#ifdef BBF_VENDOR_TEST
{"test", tVendorExtensionTEST},
#endif

{0}
};

/** This table is defined to overwrite an existing obj/param in the tree **/
DM_MAP_VENDOR tVendorExtensionOverwrite[] = {
/* customer, tableobject */

#ifdef BBF_VENDOR_OPENWRT
{"openwrt", tVendorExtensionOverwriteOPENWRT},
#endif

#ifdef BBF_VENDOR_TEST
{"test", tVendorExtensionOverwriteTEST},
#endif

{0}
};

/** This table is defined to exclude some obj/param from the tree **/
DM_MAP_VENDOR_EXCLUDE tVendorExtensionExclude[] = {
/* customer, tableobject */

#ifdef BBF_VENDOR_OPENWRT
{"openwrt", VendorExtensionExcludeOPENWRT},
#endif

#ifdef BBF_VENDOR_TEST
{"test", VendorExtensionExcludeTEST},
#endif


{0}
};
