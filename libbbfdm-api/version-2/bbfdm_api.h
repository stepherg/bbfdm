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

#ifndef __BBFDM_API_H
#define __BBFDM_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <uci.h>
#include <libubus.h>
#include <syslog.h>

struct bbfdm_ctx;

#include "bbfdm_uci.h"
#include "bbfdm_ubus.h"
#include "bbfdm_mem.h"
#include "bbfdm_system.h"

struct bbfdm_ctx {
	struct uci_context *uci_ctx; /**< Pointer to the UCI context. */
	struct ubus_context *ubus_ctx; /**< Pointer to the UBUS context. */
	struct list_head *mem_head; /**< Pointer to the list head for memory management. */

	const char *uci_confdir; /**< Path to the UCI configuration directory. */
	const char *uci_savedir; /**< Path to the UCI save directory. */
};

/**
 * @brief Initialize the BBFDM context.
 *
 * This function initializes the UCI and UBUS contexts and allocates memory required for the BBFDM context.
 *
 * @param[in,out] bbfdm_ctx Pointer to the BBFDM context structure.
 * @return 0 on success, non-zero on failure.
 */
int bbfdm_init_ctx(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Free resources associated with the BBFDM context.
 *
 * This function releases the UCI and UBUS contexts and any allocated memory within the BBFDM context.
 *
 * @param[in,out] bbfdm_ctx Pointer to the BBFDM context structure.
 * @return 0 on success, non-zero on failure.
 */
int bbfdm_free_ctx(struct bbfdm_ctx *bbfdm_ctx);

#ifndef BBFDM_FREE
#define BBFDM_FREE(x) do { if(x) {free(x); x = NULL;} } while (0)
#endif

#define BBFDM_ERR(MESSAGE, ...) \
	do { \
		syslog(LOG_ERR, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
	} while(0)

#define BBFDM_WARNING(MESSAGE, ...) \
	do { \
		syslog(LOG_WARNING, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
	} while(0)

#define BBFDM_INFO(MESSAGE, ...) \
	do { \
		syslog(LOG_INFO, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
	} while(0)

#define BBFDM_DEBUG(MESSAGE, ...) \
	do { \
		syslog(LOG_DEBUG, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
	} while(0)

#ifdef __cplusplus
}
#endif

#endif //__BBFDM_API_H

