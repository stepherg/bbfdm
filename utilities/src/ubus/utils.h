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

#include <libubox/ulog.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef FREE
#define FREE(x) do { if(x) {free(x); x = NULL;} } while (0)
#endif

#ifndef ULOG_DEBUG
#define ULOG_DEBUG(fmt, ...) ulog(LOG_DEBUG, fmt, ## __VA_ARGS__)
#endif

#define CONFIG_CONFDIR "/etc/config/"
#define DMMAP_CONFDIR "/etc/bbfdm/dmmap/"
#define DEFAULT_HANDLER_ACT "/etc/bbfdm/bbf_default_reload.sh"
#define ARG_LEN 64
#define ARG_COUNT 40
#define ACTION_LEN 512

enum wifi_config_flags_enum {
	WIRELESS_CONFIG = 1,
	MAPCONTROLLER_CONFIG = 1<<1,
};

struct applier_node {
	char *file_path;
	char *action;
	struct list_head list;
};

struct action_node {
	struct list_head list;
	char action[ACTION_LEN];
	char arg[ARG_COUNT][ARG_LEN];
	int idx;
};

struct modi_uci_node {
	char *uci;
	struct list_head list;
};

void strncpyt(char *dst, const char *src, size_t n);

int bbf_config_call(struct ubus_context *ctx, const char *object, const char *method, struct blob_buf *data, ubus_data_handler_t callback, void *arg);

void reload_specified_services(struct ubus_context *ctx, int idx, struct blob_attr *services,
		bool is_commit, bool reload, struct list_head *action_list,
		struct list_head *handler_list, struct list_head *changed_uci);

void reload_all_services(struct ubus_context *ctx, int idx, bool is_commit,
		bool reload, struct list_head *action_list,
		struct list_head *handler_list, struct list_head *changed_uci);

void exec_apply_handler_script(const char *cmd);

void uci_apply_changes_dmmap(int idx, bool is_commit, struct list_head *action_list,
			struct list_head *handler_list);

unsigned char get_idx_by_proto(const char *proto);
const char *get_proto_conf_savedir_by_idx(int idx);
const char *get_proto_dmmap_savedir_by_idx(int idx);
const char *get_proto_name_by_idx(int idx);
bool file_exists(const char *path);
bool regular_file(const char *path);
void add_changed_uci_list(struct list_head *changed_uci, const char *file_path);

#endif //__UTILS_H__
