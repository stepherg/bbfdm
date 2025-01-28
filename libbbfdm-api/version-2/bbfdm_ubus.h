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

#ifndef __BBFDM_UBUS_H
#define __BBFDM_UBUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*bbfdm_ubus_cb)(struct ubus_request *req, int type, struct blob_attr *msg);
typedef void (*bbfdm_ubus_async_cb)(struct ubus_request *req, int ret);

/**
 * @brief Initializes the UBUS context within the BBFDM context.
 *
 * This function establishes a connection to the UBUS system and assigns the
 * resulting context to the provided `bbfdm_ctx`.
 *
 * @param[in,out] bbfdm_ctx Pointer to the BBFDM context to initialize.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_init_ubus_ctx(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Frees the UBUS context within the BBFDM context.
 *
 * This function releases resources associated with the UBUS context in
 * the provided `bbfdm_ctx`.
 *
 * @param[in,out] bbfdm_ctx Pointer to the BBFDM context to free.
 * @return 0 on success.
 */
int bbfdm_free_ubus_ctx(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Invokes a UBUS method synchronously.
 *
 * Sends a synchronous request to a UBUS object and invokes the provided callback
 * with the result.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context.
 * @param[in] obj Name of the UBUS object to invoke.
 * @param[in] method Name of the method to invoke.
 * @param[in] msg Pointer to a `blob_attr` message to send as input.
 * @param[in] timeout Timeout for the request in milliseconds.
 * @param[in] data_callback Callback function for handling response data.
 * @param[in] callback_args User-provided arguments to pass to the callback.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_ubus_invoke_sync(struct bbfdm_ctx *bbfdm_ctx, const char *obj, const char *method, struct blob_attr *msg, int timeout,
		bbfdm_ubus_cb data_callback, void *callback_args);

/**
 * @brief Invokes a UBUS method asynchronously.
 *
 * Sends an asynchronous request to a UBUS object and sets up the provided callbacks
 * for data and completion handling.
 *
 * @param[in] ubus_ctx Pointer to the UBUS context.
 * @param[in] obj Name of the UBUS object to invoke.
 * @param[in] method Name of the method to invoke.
 * @param[in] msg Pointer to a `blob_attr` message to send as input.
 * @param[in] data_callback Callback function for handling response data.
 * @param[in] complete_callback Callback function to call upon request completion.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_ubus_invoke_async(struct ubus_context *ubus_ctx, const char *obj, const char *method, struct blob_attr *msg,
		bbfdm_ubus_cb data_callback, bbfdm_ubus_async_cb complete_callback);

/**
 * @brief Invokes a synchronous UBUS method.
 *
 * This macro simplifies the process of initializing a context, invoking a UBUS
 * method synchronously, and cleaning up the context.
 *
 * @param obj The name of the UBUS object to invoke.
 * @param method The name of the method to invoke.
 * @param msg Pointer to a `blob_attr` message to send as input.
 * @param data_callback Callback function for handling response data.
 * @param callback_args User-provided arguments to pass to the callback.
 * @return Always returns 0.
 */
#define BBFDM_UBUS_INVOKE_SYNC(obj, method, msg, timeout, data_callback, callback_args) \
	do { \
		struct bbfdm_ctx ctx = {0}; \
		memset(&ctx, 0, sizeof(struct bbfdm_ctx)); \
		bbfdm_init_ctx(&ctx); \
		bbfdm_ubus_invoke_sync(&ctx, obj, method, msg, timeout, data_callback, callback_args); \
		bbfdm_free_ctx(&ctx); \
	} while (0)

/**
 * @brief Sends an event to a UBUS object.
 *
 * This function sends an event to the specified UBUS object with the provided
 * message data. The event is transmitted using the UBUS system.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context.
 * @param[in] obj Name of the UBUS object to send the event to.
 * @param[in] msg Pointer to a `blob_attr` message containing event data.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_ubus_send_event(struct bbfdm_ctx *bbfdm_ctx, const char *obj, struct blob_attr *msg);

/**
 * @brief Sends an event to a UBUS object.
 *
 * This macro simplifies the process of initializing a context, sending an event,
 * and cleaning up the context.
 *
 * @param obj The name of the UBUS object to send the event to.
 * @param msg Pointer to a `blob_attr` message containing event data.
 * @return Always returns 0.
 */
#define BBFDM_UBUS_SEND_EVENT(obj, msg) \
	do { \
		struct bbfdm_ctx ctx = {0}; \
		memset(&ctx, 0, sizeof(struct bbfdm_ctx)); \
		bbfdm_init_ctx(&ctx); \
		bbfdm_ubus_send_event(&ctx, obj, msg); \
		bbfdm_free_ctx(&ctx); \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif //__BBFDM_UBUS_H

