/*
 * utils.c: common function for bbf.config daemon
 *
 * Copyright (C) 2024 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <stdarg.h>
#include <libubus.h>
#include <uci.h>

#include "utils.h"

#define DEFAULT_UBUS_TIMEOUT 5000

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

	if (!ctx) {
		ULOG_ERR("Failed to execute 'bbf_config_call': 'ctx' is NULL.");
		return -1;
	}

	fault = ubus_lookup_id(ctx, object, &id);
	if (fault) {
		ULOG_ERR("Failed to find UBUS object ID for '%s'. Error code: %d", object, fault);
		return -1;
	}

	fault = ubus_invoke(ctx, id, method, data ? data->head : NULL, callback, arg, DEFAULT_UBUS_TIMEOUT);
	if (fault) {
		ULOG_ERR("UBUS invoke failed for method '%s' on object '%s'. Error code: %d", method, object, fault);
		return -1;
	}

	return 0;
}

static void reload_service(struct ubus_context *ctx, const char *config_name, bool is_commit)
{
	struct blob_buf bb = {0};

	if (!ctx || !config_name) {
		ULOG_ERR("Failed to reload service: 'ctx' or 'config_name' is NULL");
		return;
	}

	memset(&bb, 0, sizeof(struct blob_buf));

	blob_buf_init(&bb, 0);

	blobmsg_add_string(&bb, "config", config_name);

	int result = bbf_config_call(ctx, "uci", (is_commit) ? "commit" : "revert", &bb, NULL, NULL);
	if (result != 0) {
		ULOG_ERR("Failed to %s configuration '%s'", (is_commit ? "commit" : "revert"), config_name);
	} else {
		ULOG_DEBUG("Successfully executed %s on configuration '%s'.", (is_commit ? "commit" : "revert"), config_name);
	}

	blob_buf_free(&bb);
}

void reload_specified_services(struct ubus_context *ctx, const char *conf_dir, const char *save_dir, struct blob_attr *services, bool is_commit, bool reload)
{
	struct uci_context *uci_ctx = NULL;
	struct blob_attr *service = NULL;
	size_t rem = 0;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	if (conf_dir) {
		ULOG_DEBUG("Setting UCI configuration directory to '%s'", conf_dir);
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
		uci_set_savedir(uci_ctx, save_dir);
	}

	ULOG_DEBUG("Processing services list...");
	blobmsg_for_each_attr(service, services, rem) {
		struct uci_ptr ptr = {0};

		char *config_name = blobmsg_get_string(service);

		ULOG_DEBUG("Looking up UCI configuration for service '%s'", config_name);

		if (uci_lookup_ptr(uci_ctx, &ptr, config_name, true) != UCI_OK) {
			ULOG_ERR("Failed to lookup UCI pointer for service '%s'. Skipping", config_name);
			continue;
		}

		if (is_commit) {
			ULOG_DEBUG("Committing UCI changes for service '%s'", config_name);
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK) {
				ULOG_ERR("Failed to commit UCI changes for service '%s'", config_name);
				continue;
			}
		} else {
			ULOG_DEBUG("Reverting UCI changes for service '%s'", config_name);
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				ULOG_ERR("Failed to revert UCI changes for service '%s'", config_name);
				continue;
			}
		}

		if (reload) {
			ULOG_INFO("Reloading service '%s'", config_name);
			reload_service(ctx, config_name, is_commit);
		}
	}

	ULOG_DEBUG("Freeing UCI context");
	uci_free_context(uci_ctx);
}

void reload_all_services(struct ubus_context *ctx, const char *conf_dir, const char *save_dir, bool is_commit,  bool reload)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	if (conf_dir) {
		ULOG_DEBUG("Setting UCI configuration directory to '%s'", conf_dir);
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
		uci_set_savedir(uci_ctx, save_dir);
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		ULOG_ERR("Failed to list UCI configurations");
		goto exit;
	}

	ULOG_DEBUG("Processing all configurations...");
	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		ULOG_DEBUG("Looking up UCI configuration for '%s'", *p);

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK) {
			ULOG_ERR("Failed to lookup UCI pointer for config '%s'. Skipping", *p);
			continue;
		}

		if (uci_list_empty(&ptr.p->saved_delta)) {
			ULOG_DEBUG("No changes detected in config '%s'. Skipping", *p);
			continue;
		}

		if (is_commit) {
			ULOG_DEBUG("Committing UCI changes for config '%s'", *p);
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK) {
				ULOG_ERR("Failed to commit changes for config '%s'", *p);
				continue;
			}
		} else {
			ULOG_DEBUG("Reverting UCI changes for config '%s'", *p);
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				ULOG_ERR("Failed to revert changes for config '%s'", *p);
				continue;
			}
		}

		if (reload) {
			ULOG_INFO("Reloading service for config '%s'", *p);
			reload_service(ctx, *p, is_commit);
		}
	}

	FREE(configs);

exit:
	uci_free_context(uci_ctx);
}

void uci_apply_changes(const char *conf_dir, const char *save_dir, bool is_commit)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	if (conf_dir) {
		ULOG_DEBUG("Setting UCI configuration directory to '%s'", conf_dir);
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
		uci_set_savedir(uci_ctx, save_dir);
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		ULOG_ERR("Failed to list UCI configurations");
		goto exit;
	}

	ULOG_DEBUG("Applying changes to all configurations...");
	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		ULOG_DEBUG("Looking up UCI configuration for '%s'", *p);

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK) {
			ULOG_ERR("Failed to lookup UCI pointer for config '%s'. Skipping", *p);
			continue;
		}

		if (is_commit) {
			ULOG_DEBUG("Committing changes for config '%s'", *p);
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK) {
				ULOG_ERR("Failed to commit changes for config '%s'", *p);
				continue;
			}
		} else {
			ULOG_DEBUG("Reverting changes for config '%s'", *p);
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				ULOG_ERR("Failed to revert changes for config '%s'", *p);
				continue;
			}
		}
	}

	FREE(configs);

exit:
	uci_free_context(uci_ctx);
}

void uci_config_changes(const char *conf_dir, const char *save_dir, struct blob_buf *bb)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	if (conf_dir) {
		ULOG_DEBUG("Setting UCI configuration directory to '%s'", conf_dir);
		uci_set_confdir(uci_ctx, conf_dir);
	}

	if (save_dir) {
		ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
		uci_set_savedir(uci_ctx, save_dir);
	}

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		ULOG_ERR("Failed to list UCI configurations");
		goto exit;
	}

	ULOG_DEBUG("Identifying configurations with unsaved changes...");
	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		ULOG_DEBUG("Looking up UCI configuration for '%s'", *p);

		if (uci_lookup_ptr(uci_ctx, &ptr, *p, true) != UCI_OK) {
			ULOG_ERR("Failed to lookup UCI pointer for config '%s'. Skipping.", *p);
			continue;
		}

		if (uci_list_empty(&ptr.p->saved_delta)) {
			ULOG_DEBUG("No unsaved changes in config '%s'. Skipping", *p);
			continue;
		}

		ULOG_INFO("Unsaved changes detected in config '%s', adding to blob buffer", *p);
		blobmsg_add_string(bb, NULL, *p);
	}

	FREE(configs);

exit:
	uci_free_context(uci_ctx);
}
