/*
 * ipc.h: File to handle ipc related functionality
 *
 * Copyright (C) 2020-2023 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#ifndef IPC_H
#define IPC_H

#include <sys/mman.h>

#ifdef BBFDM_MAX_MSG_LEN
  #define DEF_IPC_DATA_LEN (BBFDM_MAX_MSG_LEN - 128) // Configured Len - 128 bytes
#else
  #define DEF_IPC_DATA_LEN (10 * 1024 * 1024 - 128) // 10M - 128 bytes
#endif

#endif /* IPC_H */
