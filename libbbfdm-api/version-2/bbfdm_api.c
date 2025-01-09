/*
 * Copyright (C) 2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#include "bbfdm_api.h"

int bbfdm_init_ctx(struct bbfdm_ctx *bbfdm_ctx)
{
	memset(bbfdm_ctx, 0, sizeof(struct bbfdm_ctx));

	bbfdm_init_uci_ctx(bbfdm_ctx);
	bbfdm_init_ubus_ctx(bbfdm_ctx);
	bbfdm_init_mem(bbfdm_ctx);

	return 0;
}

int bbfdm_free_ctx(struct bbfdm_ctx *bbfdm_ctx)
{
	bbfdm_free_uci_ctx(bbfdm_ctx);
	bbfdm_free_ubus_ctx(bbfdm_ctx);
	bbfdm_free_mem(bbfdm_ctx);

	return 0;
}
