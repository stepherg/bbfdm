/*
 * utils.c: common function for bbf.config daemon
 *
 * Copyright (C) 2024 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <syslog.h>
#include <stdarg.h>
#include <libubus.h>
#include <uci.h>

#define DEFAULT_UBUS_TIMEOUT 5000

void dbg_printf(const char *format, ...)
{
	va_list arglist;

	va_start(arglist, format);
	vsyslog(LOG_INFO, format, arglist);
	va_end(arglist);
}

void strncpyt(char *dst, const char *src, size_t n)
{
	if (dst == NULL || src == NULL)
		return;

        if (n > 1) {
                strncpy(dst, src, n - 1);
                dst[n - 1] = 0;
        }
}

int bbf_config_call(struct ubus_context *ctx, const char *object, const char *method, struct blob_buf *data, ubus_data_handler_t callback, void *arg)
{
	int fault = 0;
	uint32_t id;

	if (!ctx)
		return -1;

	fault = ubus_lookup_id(ctx, object, &id);
	if (fault)
		return -1;

	fault = ubus_invoke(ctx, id, method, data ? data->head : NULL, callback, arg, DEFAULT_UBUS_TIMEOUT);
	if (fault)
		return -1;

	return 0;
}

static void reload_service(struct ubus_context *ctx, const char *config_name, bool is_commit)
{
	struct blob_buf bb = {0};

	memset(&bb, 0, sizeof(struct blob_buf));

	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "config", config_name);

	bbf_config_call(ctx, "uci", (is_commit) ? "commit" : "revert", &bb, NULL, NULL);

	blob_buf_free(&bb);
}

void reload_specified_services(struct ubus_context *ctx, const char *conf_dir, const char *save_dir, struct blob_attr *services, bool is_commit, bool reload)
{
	struct uci_context *uci_ctx = NULL;
	struct blob_attr *service = NULL;
	size_t rem = 0;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		return;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		uci_set_savedir(uci_ctx, save_dir);
	}

	blobmsg_for_each_attr(service, services, rem) {
		struct uci_ptr ptr = {0};

		char *config_name = blobmsg_get_string(service);

		if (uci_lookup_ptr(uci_ctx, &ptr, config_name, true) != UCI_OK)
			continue;

		if (is_commit) {
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK)
				continue;
		} else {
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				continue;
			}
		}

		if (reload) {
			reload_service(ctx, config_name, is_commit);
		}
	}

	uci_free_context(uci_ctx);
}

void reload_all_services(struct ubus_context *ctx, const char *conf_dir, const char *save_dir, bool is_commit,  bool reload)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		return;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		uci_set_savedir(uci_ctx, save_dir);
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		goto exit;
	}

	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK)
			continue;

		if (uci_list_empty(&ptr.p->saved_delta))
			continue;

		if (is_commit) {
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK)
				continue;
		} else {
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				continue;
			}
		}

		if (reload) {
			reload_service(ctx, *p, is_commit);
		}
	}

	free(configs);

exit:
	uci_free_context(uci_ctx);
}

void uci_apply_changes(const char *conf_dir, const char *save_dir, bool is_commit)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		return;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		uci_set_savedir(uci_ctx, save_dir);
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		goto exit;
	}

	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK)
			continue;

		if (is_commit) {
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK) {
				continue;
			}
		} else {
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				continue;
			}
		}
	}

	free(configs);

exit:
	uci_free_context(uci_ctx);
}

void uci_config_changes(const char *conf_dir, const char *save_dir, struct blob_buf *bb)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		return;
	}

	if (conf_dir) {
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		uci_set_savedir(uci_ctx, save_dir);
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		goto exit;
	}

	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK)
			continue;

		if (uci_list_empty(&ptr.p->saved_delta))
			continue;

		blobmsg_add_string(bb, NULL, *p);
	}

	free(configs);

exit:
	uci_free_context(uci_ctx);
}
