#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <regex.h>
#include <sys/param.h>
#include <string.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/utils.h>
#include <libubox/list.h>

#include <libbbfdm-api/legacy/dmcommon.h>
#include "bbfdm-ubus.h"

#define STRINGIFY(x) #x
#define TO_STR(x) STRINGIFY(x)

#define ROOT_NODE "Device."
#define BBF_ADD_EVENT "AddObj"
#define BBF_DEL_EVENT "DelObj"
#define BBF_EVENT_NAME "event"

#define MAX_DM_KEY_LEN 256
#define MAX_DM_PATH 1024
#define MAX_DM_VALUE 4096
#define DM_VALUE_SEP ","
#define DELIM '.'

#ifdef BBFDM_MAX_MSG_LEN
  #define DEF_IPC_DATA_LEN (BBFDM_MAX_MSG_LEN - 128) // Configured Len - 128 bytes
#else
  #define DEF_IPC_DATA_LEN (10 * 1024 * 1024 - 128) // 10M - 128 bytes
#endif

#define GLOB_CHAR "[[+*]+"
#define GLOB_EXPR "[=><]+"

extern DMOBJ *DEAMON_DM_ROOT_OBJ;
extern DM_MAP_OBJ *INTERNAL_ROOT_TREE;

bool is_node_instance(char *path);
int count_delim(const char *path);

bool get_boolean_string(char *value);
bool validate_msglen(bbfdm_data_t *data);

int get_dm_type(char *dm_type);

int get_resolved_paths(struct dmctx *bbf_ctx, char *qpath, struct list_head *resolved_paths);
void strncpyt(char *dst, const char *src, size_t n);

#endif /* COMMON_H */
