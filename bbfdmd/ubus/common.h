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

#include "dmcommon.h"

#include "bbfdmd.h"

#define ROOT_NODE "Device."
#define BBF_ADD_EVENT "AddObj"
#define BBF_DEL_EVENT "DelObj"
#define BBF_EVENT "event"
#define BBF_UPDATE_SCHEMA_EVENT "UpdateSchema"

#define BBF_JSON_INPUT "/etc/bbfdm/input.json"

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
extern DM_MAP_VENDOR *DEAMON_DM_VENDOR_EXTENSION[2];
extern DM_MAP_VENDOR_EXCLUDE *DEAMON_DM_VENDOR_EXTENSION_EXCLUDE;

bool is_str_eq(const char *s1, const char *s2);
bool is_node_instance(char *path);
int count_delim(const char *path);

void set_debug_level(unsigned char level);
void print_error(const char *format, ...);
void print_warning(const char *format, ...);
void print_info(const char *format, ...);
void print_debug(const char *format, ...);
bool get_boolean_string(char *value);
bool validate_msglen(bbfdm_data_t *data);

int get_dm_type(char *dm_type);
int get_proto_type(const char *proto);
int get_instance_mode(int instance_mode);

#define DEBUG(fmt, args...) \
	print_debug("[%s:%d]"fmt, __func__, __LINE__, ##args)

#define INFO(fmt, args...) \
	print_info(fmt, ##args)

#define ERR(fmt, args...) \
	print_error("[%s:%d] " fmt, __func__, __LINE__, ##args)

#define WARNING(fmt, args...) \
	print_warning("[%s:%d] " fmt, __func__, __LINE__, ##args)

int get_resolved_paths(struct dmctx *bbf_ctx, char *qpath, struct list_head *resolved_paths);
int run_cmd(const char *cmd, char *output, size_t out_len);
void strncpyt(char *dst, const char *src, size_t n);

#endif /* COMMON_H */
