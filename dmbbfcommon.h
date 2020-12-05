/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *    Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DMBBFCOMMON_H__
#define __DMBBFCOMMON_H__

#include <libbbf_api/dmcommon.h>
#include "dmentry.h"

extern unsigned int upnp_in_user_mask;
extern struct list_head list_execute_end_session;

void bbf_uci_commit_bbfdm(void);
void bbf_uci_revert_bbfdm(void);
int set_bbfdatamodel_type(int bbf_type);
int get_bbfdatamodel_type(void);
int bbf_set_ip_version(int ipversion);
void del_list_parameter(struct dm_parameter *dm_parameter);
void dmjson_parse_init(char *msg);
void dmjson_parse_fini(void);
json_object *dmjson_select_obj(json_object * jobj, char *argv[]);
void del_list_fault_param(struct param_fault *param_fault);
int copy_temporary_file_to_original_file(char *f1, char *f2);
void dmjson_get_var(char *jkey, char **jval);
void dmjson_get_string(char *jkey, char **jval);
void dm_update_enabled_notify(struct dm_enabled_notify *p, char *new_value);

void apply_end_session(void);
int dm_add_end_session(struct dmctx *ctx, void(*function)(struct execute_end_session *), int action, void *data);
void bbf_set_end_session_flag (struct dmctx *ctx, unsigned int flag);
int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value);
void dmbbf_update_enabled_notify_file(unsigned int dm_type, unsigned int amd_version, int instance_mode);
int get_dm_type(char *dm_str);

#endif //__DMBBFCOMMON_H__
