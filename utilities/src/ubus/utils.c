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
#include <sys/stat.h>

#include "utils.h"

#define DEFAULT_UBUS_TIMEOUT 5000

struct proto_args {
	const char *name;
	const char *config_savedir;
	const char *dmmap_savedir;
	unsigned char index;
};

static struct proto_args supported_protocols[] = {
		{
				"both", "/tmp/bbfdm/.bbfdm/config/", "/tmp/bbfdm/.bbfdm/dmmap/", 0
		},
		{
				"cwmp", "/tmp/bbfdm/.cwmp/config/", "/tmp/bbfdm/.cwmp/dmmap/", 1
		},
		{
				"usp", "/tmp/bbfdm/.usp/config/", "/tmp/bbfdm/.usp/dmmap/", 2
		},
};

static void add_external_action_list(struct list_head *action_list, struct list_head *ext_handler, const char *file_path)
{
	if (file_path == NULL || strlen(file_path) == 0 || action_list == NULL)
		return;

	struct applier_node *app_node = NULL;
	bool ext_exist = false;

	char *config = strrchr(file_path, '/');
	if (config) {
		config = config + 1;
	}

	list_for_each_entry(app_node, ext_handler, list) {
		if (strcmp(app_node->file_path, file_path) != 0) {
			continue;
		}

		ext_exist = true;

		bool node_exist = false;
		bool arg_exist = false;
		struct action_node *act_node = NULL;

		list_for_each_entry(act_node, action_list, list) {
			if (strcmp(app_node->action, act_node->action) == 0) {
				node_exist = true;
				for (int i = 0; i < act_node->idx; i++) {
					if (strcmp(act_node->arg[i], config) == 0) {
						arg_exist = true;
						break;
					}
				}
				break;
			}
		}

		if (node_exist == false) {
			act_node = (struct action_node *)calloc(1, sizeof(struct action_node));
			if (act_node == NULL) {
				ULOG_INFO("Failed to allocate memory for action list");
				return;
			}

			snprintf(act_node->action, sizeof(act_node->action), "%s", app_node->action);
			INIT_LIST_HEAD(&act_node->list);
			list_add_tail(&act_node->list, action_list);
		}

		if (arg_exist == false && act_node->idx < ARG_COUNT) {
			snprintf(act_node->arg[act_node->idx], ARG_LEN, "%s", config);
			act_node->idx = act_node->idx + 1;
			ULOG_DEBUG("Added %s handler for %s config", act_node->action, config);
		}
	}

	if (ext_exist == true || strncmp(file_path, DMMAP_CONFDIR, strlen(DMMAP_CONFDIR)) == 0) {
		/* external handler exist, so already added in list or
		 * the file is a dmmap file so it has no default handler
		 * to add in the action list */
		return;
	}

	/* external handler not exist, add default handler */
	struct action_node *act_node = NULL;
	bool node_exist = false;
	bool arg_exist = false;

	list_for_each_entry(act_node, action_list, list) {
		if (strcmp(app_node->action, DEFAULT_HANDLER_ACT) == 0) {
			node_exist = true;
			for (int i = 0; i < act_node->idx; i++) {
				if (strcmp(act_node->arg[i], config) == 0) {
					arg_exist = true;
					break;
				}
			}
			break;
		}
	}

	if (node_exist == false) {
		act_node = (struct action_node *)calloc(1, sizeof(struct action_node));
		if (act_node == NULL) {
			ULOG_INFO("Failed to allocate memory for action list");
			return;
		}

		snprintf(act_node->action, sizeof(act_node->action), "%s", DEFAULT_HANDLER_ACT);
		INIT_LIST_HEAD(&act_node->list);
		list_add_tail(&act_node->list, action_list);
	}

	if (arg_exist == false && act_node->idx < ARG_COUNT) {
		snprintf(act_node->arg[act_node->idx], ARG_LEN, "%s", config);
		act_node->idx = act_node->idx + 1;
		ULOG_DEBUG("Added default handler for %s config", config);
	}
}

void add_changed_uci_list(struct list_head *changed_uci, const char *file_path)
{
	if (changed_uci == NULL || file_path == NULL || strlen(file_path) == 0)
		return;

	struct modi_uci_node *node = NULL;
	bool exist = false;

	list_for_each_entry(node, changed_uci, list) {
		if (!node->uci || strcmp(node->uci, file_path) != 0)
			continue;

		exist = true;
		break;
	}

	if (exist)
		return;

	node = (struct modi_uci_node *)calloc(1, sizeof(struct modi_uci_node));
	if (!node) {
		ULOG_INFO("Failed to allocate memory for changed uci list");
		return;
	}

	node->uci = strdup(file_path);
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, changed_uci);
}

unsigned char get_idx_by_proto(const char *proto)
{
	for (int i = 0; i < ARRAY_SIZE(supported_protocols); i++) {
		if (strcmp(supported_protocols[i].name, proto) == 0)
			return supported_protocols[i].index;
	}

	return 0;
}

const char *get_proto_conf_savedir_by_idx(int idx)
{
	if (idx < ARRAY_SIZE(supported_protocols)) {
		return supported_protocols[idx].config_savedir;
	}

	return "";
}

const char *get_proto_dmmap_savedir_by_idx(int idx)
{
	if (idx < ARRAY_SIZE(supported_protocols)) {
		return supported_protocols[idx].dmmap_savedir;
	}

	return "";
}

const char *get_proto_name_by_idx(int idx)
{
	if (idx < ARRAY_SIZE(supported_protocols)) {
		return supported_protocols[idx].name;
	}

	return "";
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

bool file_exists(const char *path)
{
	struct stat buffer;

	if (!path)
		return false;

	return stat(path, &buffer) == 0;
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

void reload_specified_services(struct ubus_context *ctx, int idx, struct blob_attr *services,
				bool is_commit, bool reload, struct list_head *action_list,
				struct list_head *handler_list, struct list_head *changed_uci)
{
	struct uci_context *uci_ctx = NULL;
	struct blob_attr *service = NULL;
	size_t rem = 0;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	ULOG_DEBUG("Processing services list...");
	blobmsg_for_each_attr(service, services, rem) {
		struct uci_ptr ptr = {0};
		char conf_dir[64] = {0};
		char save_dir[64] = {0};
		char package[64] = {0};
		bool is_dmmap = false;

		char *config_name = blobmsg_get_string(service);
		if (strncmp(CONFIG_CONFDIR, config_name, strlen(CONFIG_CONFDIR)) == 0) {
			/* standard uci path received */
			snprintf(conf_dir, sizeof(conf_dir), "%s", CONFIG_CONFDIR);
			snprintf(save_dir, sizeof(save_dir), "%s", get_proto_conf_savedir_by_idx(idx));
			snprintf(package, sizeof(package), "%s", config_name + strlen(CONFIG_CONFDIR));
		} else if (strncmp(DMMAP_CONFDIR, config_name, strlen(DMMAP_CONFDIR)) == 0) {
			/* dmmap uci path received */
			snprintf(conf_dir, sizeof(conf_dir), "%s", DMMAP_CONFDIR);
			snprintf(save_dir, sizeof(save_dir), "%s", get_proto_dmmap_savedir_by_idx(idx));
			snprintf(package, sizeof(package), "%s", config_name + strlen(DMMAP_CONFDIR));
			is_dmmap = true;
		} else {
			/* no path default to standard uci */
			snprintf(conf_dir, sizeof(conf_dir), "%s", CONFIG_CONFDIR);
			snprintf(save_dir, sizeof(save_dir), "%s", get_proto_conf_savedir_by_idx(idx));
			snprintf(package, sizeof(package), "%s", config_name);
		}

		ULOG_DEBUG("Setting UCI configuration directory to '%s'", conf_dir);
		uci_set_confdir(uci_ctx, conf_dir);

		ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
		uci_set_savedir(uci_ctx, save_dir);

		ULOG_DEBUG("Looking up UCI configuration for service '%s'", config_name);

		char file_path[1024] = {0};
		snprintf(file_path, sizeof(file_path), "%s%s", conf_dir, package);

		if (uci_lookup_ptr(uci_ctx, &ptr, package, true) != UCI_OK) {
			ULOG_ERR("Failed to lookup UCI pointer for service '%s'. Skipping", config_name);
			continue;
		}

		if (is_commit) {
			ULOG_DEBUG("Committing UCI changes for service '%s'", config_name);
			if (uci_commit(uci_ctx, &ptr.p, false) != UCI_OK) {
				ULOG_ERR("Failed to commit UCI changes for service '%s'", config_name);
				continue;
			}

			if (!is_dmmap) {
				add_changed_uci_list(changed_uci, file_path);
			}
		} else {
			ULOG_DEBUG("Reverting UCI changes for service '%s'", config_name);
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				ULOG_ERR("Failed to revert UCI changes for service '%s'", config_name);
				continue;
			}
		}

		if (is_commit && is_dmmap) {
			add_external_action_list(action_list, handler_list, file_path);
		}

		if (reload && !is_dmmap) {
			add_external_action_list(action_list, handler_list, file_path);
		}
	}

	ULOG_DEBUG("Freeing UCI context");
	uci_free_context(uci_ctx);
}

void reload_all_services(struct ubus_context *ctx, int idx, bool is_commit,
			bool reload, struct list_head *action_list,
			struct list_head *handler_list, struct list_head *changed_uci)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	ULOG_DEBUG("Setting UCI configuration directory to '%s'", CONFIG_CONFDIR);
	uci_set_confdir(uci_ctx, CONFIG_CONFDIR);

	const char *save_dir = get_proto_conf_savedir_by_idx(idx);
	ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
	uci_set_savedir(uci_ctx, save_dir);

	if (uci_list_configs(uci_ctx, &configs) != UCI_OK) {
		ULOG_ERR("Failed to list UCI configurations");
		goto exit;
	}

	ULOG_DEBUG("Processing all configurations...");
	for (p = configs; p && *p; p++) {
		struct uci_ptr ptr = {0};

		ULOG_DEBUG("Looking up UCI configuration for '%s'", *p);
		char file_path[1024] = {0};
		snprintf(file_path, sizeof(file_path), "%s%s", CONFIG_CONFDIR, *p);

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

			add_changed_uci_list(changed_uci, file_path);
		} else {
			ULOG_DEBUG("Reverting UCI changes for config '%s'", *p);
			if (uci_revert(uci_ctx, &ptr) != UCI_OK) {
				ULOG_ERR("Failed to revert changes for config '%s'", *p);
				continue;
			}
		}

		if (reload) {
			add_external_action_list(action_list, handler_list, file_path);
		}
	}

	FREE(configs);

exit:
	uci_free_context(uci_ctx);
}

void exec_apply_handler_script(const char *cmd)
{
	FILE *pp = popen(cmd, "r"); // flawfinder: ignore
	if (pp) {
		pclose(pp);
	}
}

void uci_apply_changes_dmmap(int idx, bool is_commit, struct list_head *action_list, struct list_head *ext_handler)
{
	struct uci_context *uci_ctx = NULL;
	char **configs = NULL, **p = NULL;
	char save_dir[128] = {0};

	uci_ctx = uci_alloc_context();
	if (!uci_ctx) {
		ULOG_ERR("Failed to allocate UCI context");
		return;
	}

	ULOG_DEBUG("Setting UCI configuration directory to '%s'", DMMAP_CONFDIR);
	uci_set_confdir(uci_ctx, DMMAP_CONFDIR);
	snprintf(save_dir, sizeof(save_dir), "%s", get_proto_dmmap_savedir_by_idx(idx));

	ULOG_DEBUG("Setting UCI save directory to '%s'", save_dir);
	uci_set_savedir(uci_ctx, save_dir);

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

			char file_path[1024] = {0};
			snprintf(file_path, sizeof(file_path), "%s%s", DMMAP_CONFDIR, *p);
			add_external_action_list(action_list, ext_handler, file_path);
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

bool regular_file(const char *path)
{
	struct stat buffer;

	if (!path)
		return false;

	return stat(path, &buffer) == 0 && S_ISREG(buffer.st_mode);
}
