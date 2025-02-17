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

#define MAX_DM_PATH 1024
#define MAX_DM_VALUE 4096

#ifdef BBFDM_MAX_MSG_LEN
  #define DEF_IPC_DATA_LEN (BBFDM_MAX_MSG_LEN - 128) // Configured Len - 128 bytes
#else
  #define DEF_IPC_DATA_LEN (10 * 1024 * 1024 - 128) // 10M - 128 bytes
#endif

extern DMOBJ *DEAMON_DM_ROOT_OBJ;
extern DM_MAP_OBJ *INTERNAL_ROOT_TREE;

bool validate_msglen(bbfdm_data_t *data);

void strncpyt(char *dst, const char *src, size_t n);

#endif /* COMMON_H */
