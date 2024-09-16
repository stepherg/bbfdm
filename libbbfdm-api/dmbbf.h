/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Feten Besbes <feten.besbes@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.c>
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DMBBF_H__
#define __DMBBF_H__

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <libubox/list.h>
#include <json-c/json.h>
#include "dmuci.h"
#include "dmmem.h"
#include "dmapi.h"

bool dm_is_micro_service(void);
void dm_set_micro_service(void);

int get_number_of_entries(struct dmctx *ctx, void *data, char *instance, int (*browseinstobj)(struct dmctx *ctx, struct dmnode *node, void *data, char *instance));
char *handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct uci_section *s, char *inst_opt, char *alias_opt);
char *handle_instance_without_section(struct dmctx *dmctx, DMNODE *parent_node, int inst_nbr);
int get_empty(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

void fill_blob_param(struct blob_buf *bb, const char *path, const char *data, const char *type, uint32_t dm_flags);
void fill_blob_event(struct blob_buf *bb, const char *path, const char *type, void *data);
void fill_blob_operate(struct blob_buf *bb, const char *path, const char *data, const char *type, void *in_out);

int string_to_bool(const char *v, bool *b);
char *get_value_by_reference(struct dmctx *ctx, char *value);
int dm_entry_get_value(struct dmctx *dmctx);
int dm_entry_get_name(struct dmctx *ctx);
int dm_entry_get_supported_dm(struct dmctx *ctx);
int dm_entry_get_instances(struct dmctx *ctx);
int dm_entry_add_object(struct dmctx *dmctx);
int dm_entry_delete_object(struct dmctx *dmctx);
int dm_entry_set_value(struct dmctx *dmctx);
int dm_entry_object_exists(struct dmctx *dmctx);
int dm_entry_operate(struct dmctx *dmctx);
int dm_entry_event(struct dmctx *dmctx);
int dm_entry_get_reference_param(struct dmctx *dmctx);
int dm_entry_get_reference_value(struct dmctx *dmctx);
int dm_link_inst_obj(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance);

static inline int DM_LINK_INST_OBJ(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance)
{
	dmctx->faultcode = dm_link_inst_obj(dmctx, parent_node, data, instance);
	if (dmctx->stop || parent_node->num_of_entries >= BBF_MAX_OBJECT_INSTANCES)
		return DM_STOP;
	return DM_OK;
}

#ifndef TRACE
#define TRACE(MESSAGE, ...) do { \
	syslog(LOG_INFO, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
} while(0)
#endif

// Macros for different log levels
#define BBF_ERR(MESSAGE, ...) do { \
	syslog(LOG_ERR, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
} while(0)

#define BBF_WARNING(MESSAGE, ...) do { \
	syslog(LOG_WARNING, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
} while(0)

#define BBF_INFO(MESSAGE, ...) do { \
	syslog(LOG_INFO, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
} while(0)

#define BBF_DEBUG(MESSAGE, ...) do { \
	syslog(LOG_DEBUG, "[%s:%d] " MESSAGE, __FUNCTION__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
} while(0)


#endif //__DMBBF_H__
