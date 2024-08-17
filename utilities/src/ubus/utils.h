/*
 * utils.c: common function for bbf.config daemon
 *
 * Copyright (C) 2024 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

void dbg_printf(const char *format, ...);

void strncpyt(char *dst, const char *src, size_t n);

int bbf_config_call(struct ubus_context *ctx, const char *object, const char *method, struct blob_buf *data, ubus_data_handler_t callback, void *arg);

void reload_specified_services(struct ubus_context *ctx, const char *conf_dir, const char *save_dir, struct blob_attr *services, bool is_commit,  bool reload);

void reload_all_services(struct ubus_context *ctx, const char *conf_dir, const char *save_dir, bool is_commit,  bool reload);

void uci_apply_changes(const char *conf_dir, const char *save_dir, bool is_commit);

void uci_config_changes(const char *conf_dir, const char *save_dir, struct blob_buf *bb);

#endif //__UTILS_H__
