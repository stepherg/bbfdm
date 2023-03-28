/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __SECURITY_H
#define __SECURITY_H

#if defined(LOPENSSL) || defined(LWOLFSSL) || defined(LMBEDTLS)
#include "libbbf_api/src/dmcommon.h"

extern DMOBJ tSecurityObj[];
extern DMLEAF tSecurityParams[];
extern DMLEAF tSecurityCertificateParams[];
#endif

#endif //__SECURITY_H

