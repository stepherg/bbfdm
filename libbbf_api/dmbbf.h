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
#include <libubox/list.h>
#include <json-c/json.h>
#include "dmuci.h"
#include "dmmem.h"

#ifdef UNDEF
#undef UNDEF
#endif
#define UNDEF -1

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef FREE
#define FREE(x) do { if(x) {free(x); x = NULL;} } while (0)
#endif

#ifndef BBF_ATTR_UNUSED
#define BBF_ATTR_UNUSED(x) (void)(x)
#endif

#define DEFAULT_DMVERSION "2.14"

#define DM_STRNCPY(DST, SRC, SIZE) \
do { \
	strncpy(DST, SRC, SIZE - 1); \
	DST[SIZE-1] = '\0'; \
} while(0)

extern struct dm_permession_s DMREAD;
extern struct dm_permession_s DMWRITE;
extern struct dm_permession_s DMSYNC;
extern struct dm_permession_s DMASYNC;
extern char *DMT_TYPE[];
extern int bbfdatamodel_type;

#define DMPARAM_ARGS \
	struct dmctx *dmctx, \
	struct dmnode *node, \
	char *lastname, \
	struct dm_permession_s *permission, \
	int type, \
	int (*get_cmd)(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value), \
	int (*set_cmd)(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action), \
	void *data, \
	char *instance

#define DMOBJECT_ARGS \
	struct dmctx *dmctx, \
	struct dmnode *node, \
	struct dm_permession_s *permission, \
	int (*addobj)(char *refparam, struct dmctx *ctx, void *data, char **instance), \
	int (*delobj)(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action), \
	int (*get_linker)(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker), \
	void *data, \
	char *instance

struct dmnode;
struct dmctx;

struct dm_dynamic_obj {
	struct dm_obj_s **nextobj;
	int idx_type;
};

struct dm_dynamic_leaf {
	struct dm_leaf_s **nextleaf;
	int idx_type;
};

struct dm_permession_s {
	char *val;
	char *(*get_permission)(char *refparam, struct dmctx *dmctx, void *data, char *instance);
};

struct dm_notif_s {
	char *val;
	char *(*get_notif)(char *refparam, struct dmctx *dmctx, void *data, char *instance);
};

typedef struct dm_leaf_s {
	/* PARAM, permission, type, getvalue, setvalue, bbfdm_type, version(7)*/
	char *parameter;
	struct dm_permession_s *permission;
	int type;
	int (*getvalue)(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
	int (*setvalue)(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
	int bbfdm_type;
	char version[10];
} DMLEAF;

typedef struct dm_obj_s {
	/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys, version(14)*/
	char *obj;
	struct dm_permession_s *permission;
	int (*addobj)(char *refparam, struct dmctx *ctx, void *data, char **instance);
	int (*delobj)(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
	char *checkdep;
	int (*browseinstobj)(struct dmctx *dmctx, struct dmnode *node, void *data, char *instance);
	struct dm_dynamic_obj *nextdynamicobj;
	struct dm_dynamic_leaf *dynamicleaf;
	struct dm_obj_s *nextobj;
	struct dm_leaf_s *leaf;
	int (*get_linker)(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
	int bbfdm_type;
	const char **unique_keys;
	char version[10];
} DMOBJ;

struct set_tmp {
	struct list_head list;
	char *name;
	char *value;
};

struct param_fault {
	struct list_head list;
	char *name;
	int fault;
};

struct dm_parameter {
	struct list_head list;
	char *name;
	char *data;
	char *type;
	char *additional_data;
};

struct dmctx
{
	bool stop;
	bool match;
	int (*method_param)(DMPARAM_ARGS);
	int (*method_obj)(DMOBJECT_ARGS);
	int (*checkobj)(DMOBJECT_ARGS);
	int (*checkleaf)(DMOBJECT_ARGS);
	struct list_head list_parameter;
	struct list_head set_list_tmp;
	struct list_head list_fault_param;
	struct list_head list_json_parameter;
	DMOBJ *dm_entryobj;
	bool nextlevel;
	int faultcode;
	int setaction;
	char *in_param;
	char *in_value;
	char *addobj_instance;
	char *linker;
	char *linker_param;
	char *dm_version;
	unsigned int alias_register;
	unsigned int nbrof_instance;
	unsigned int instance_mode;
	unsigned char inparam_isparam;
	unsigned char findparam;
	char *inst_buf[16];
	unsigned int end_session_flag;
	bool isgetschema;
	bool iscommand;
	bool isevent;
	bool isinfo;
};

typedef struct dmnode {
	DMOBJ *obj;
	struct dmnode *parent;
	char *current_object;
	void *prev_data;
	char *prev_instance;
	unsigned char instance_level;
	unsigned char matched;
	unsigned char is_instanceobj;
	unsigned char browse_type;
	int max_instance;
	int num_of_entries;
} DMNODE;

typedef struct dm_map_obj {
	char *path;
	struct dm_obj_s *root_obj;
	struct dm_leaf_s *root_leaf;
} DM_MAP_OBJ;

typedef struct dm_map_vendor {
	char *vendor;
	struct dm_map_obj *vendor_obj;
} DM_MAP_VENDOR;

typedef struct dm_map_vendor_exclude {
	char *vendor;
	char **vendor_obj;
} DM_MAP_VENDOR_EXCLUDE;

enum operate_ret_status {
	CMD_SUCCESS,
	CMD_INVALID_ARGUMENTS,
	CMD_FAIL,
	CMD_NOT_FOUND,
	__STATUS_MAX,
};

enum deprecated_operate_ret_status {
	SUCCESS,
	UBUS_INVALID_ARGUMENTS,
	FAIL,
};

typedef struct {
	const char **in;
	const char **out;
} operation_args;

typedef struct {
	const char **param;
} event_args;

typedef enum operate_ret_status opr_ret_t;

typedef opr_ret_t (*operation) (struct dmctx *dmctx, char *p, json_object *input);

typedef struct dm_map_operate {
	char *path;
	operation operate;
	char *type; // sync or async
	operation_args args;
} DM_MAP_OPERATE __attribute__ ((deprecated));

enum set_value_action {
	VALUECHECK,
	VALUESET
};

enum del_action_enum {
	DEL_INST,
	DEL_ALL
};

enum browse_type_enum {
	BROWSE_NORMAL,
	BROWSE_FIND_MAX_INST,
	BROWSE_NUM_OF_ENTRIES
};

enum {
	CMD_GET_VALUE,
	CMD_GET_NAME,
	CMD_SET_VALUE,
	CMD_ADD_OBJECT,
	CMD_DEL_OBJECT,
	CMD_USP_OPERATE,
	CMD_USP_LIST_OPERATE,
	CMD_USP_LIST_EVENT,
	CMD_GET_SCHEMA,
	CMD_GET_INSTANCES,
	CMD_EXTERNAL_COMMAND
};

enum usp_fault_code_enum {
	USP_FAULT_GENERAL_FAILURE = 7000, // general failure
	USP_FAULT_MESSAGE_NOT_UNDERSTOOD = 7001, // message was not understood
	USP_FAULT_REQUEST_DENIED = 7002, // Cannot or will not process message
	USP_FAULT_INTERNAL_ERROR = 7003, // Message failed due to an internal error
	USP_FAULT_INVALID_ARGUMENT = 7004, // invalid values in the request elements
	USP_FAULT_RESOURCES_EXCEEDED = 7005, // Message failed due to memory or processing limitations
	USP_FAULT_PERMISSION_DENIED = 7006, // Source endpoint does not have authorisation to use this message
	USP_FAULT_INVALID_CONFIGURATION = 7007, // invalid or unstable state

	// ParamError codes
	USP_FAULT_INVALID_PATH_SYNTAX = 7008, // Requested path was invalid or a reference was invalid
	USP_FAULT_PARAM_ACTION_FAILED = 7009, // Parameter failed to update for a general reason described in an err_msg element.
	USP_FAULT_UNSUPPORTED_PARAM = 7010, // Requested Path Name associated with this ParamError did not match any instantiated parameters
	USP_FAULT_INVALID_TYPE = 7011, // Unable to convert string value to correct data type
	USP_FAULT_INVALID_VALUE = 7012, // Out of range or invalid enumeration
	USP_FAULT_PARAM_READ_ONLY = 7013, // Attempted to write to a read only parameter
	USP_FAULT_VALUE_CONFLICT = 7014, // Requested value would result in an invalid configuration

	USP_FAULT_CRUD_FAILURE = 7015, // General failure to perform the CRUD operation
	USP_FAULT_OBJECT_DOES_NOT_EXIST = 7016, // Requested object instance does not exist
	USP_FAULT_CREATION_FAILURE = 7017, // General failure to create the object
	USP_FAULT_NOT_A_TABLE = 7018, // The requested pathname was expected to be a multi-instance object, but wasn't
	USP_FAULT_OBJECT_NOT_CREATABLE = 7019, // Attempted to create an object which was non-creatable (for non-writable multi-instance objects)
	USP_FAULT_SET_FAILURE = 7020, // General failure to set a parameter
	USP_FAULT_REQUIRED_PARAM_FAILED = 7021, // The CRUD operation failed because a required parameter failed to update

	USP_FAULT_COMMAND_FAILURE = 7022, // Command failed to operate
	USP_FAULT_COMMAND_CANCELLED = 7023, // Command failed to complete because it was cancelled
	USP_FAULT_OBJECT_NOT_DELETABLE = 7024, // Attempted to delete an object which was non-deletable, or object failed to be deleted
	USP_FAULT_UNIQUE_KEY_CONFLICT = 7025, // unique keys would conflict
	USP_FAULT_INVALID_PATH = 7026, // Path is not present in the data model schema

	// Brokered USP Record Errors
	USP_FAULT_RECORD_NOT_PARSED = 7100, // Record could not be parsed
	USP_FAULT_SECURE_SESS_REQUIRED = 7101, // A secure session must be started before pasing any records
	USP_FAULT_SECURE_SESS_NOT_SUPPORTED = 7102, // Secure session is not supported by this endpoint
	USP_FAULT_SEG_NOT_SUPPORTED = 7103, // Segmentation and reassembly is not supported by this endpoint
	USP_FAULT_RECORD_FIELD_INVALID = 7104, // A USP record field was invalid
};

enum fault_code_enum {
	FAULT_9000 = 9000,// Method not supported
	FAULT_9001,// Request denied
	FAULT_9002,// Internal error
	FAULT_9003,// Invalid arguments
	FAULT_9004,// Resources exceeded
	FAULT_9005,// Invalid parameter name
	FAULT_9006,// Invalid parameter type
	FAULT_9007,// Invalid parameter value
	FAULT_9008,// Attempt to set a non-writable parameter
	FAULT_9009,// Notification request rejected
	FAULT_9010,// Download failure
	FAULT_9011,// Upload failure
	FAULT_9012,// File transfer server authentication failure
	FAULT_9013,// Unsupported protocol for file transfer
	FAULT_9014,// Download failure: unable to join multicast group
	FAULT_9015,// Download failure: unable to contact file server
	FAULT_9016,// Download failure: unable to access file
	FAULT_9017,// Download failure: unable to complete download
	FAULT_9018,// Download failure: file corrupted
	FAULT_9019,// Download failure: file authentication failure
	FAULT_9020,// Download failure: unable to complete download
	FAULT_9021,// Cancelation of file transfer not permitted
	FAULT_9022,// Invalid UUID format
	FAULT_9023,// Unknown Execution Environment
	FAULT_9024,// Disabled Execution Environment
	FAULT_9025,// Diployment Unit to Execution environment mismatch
	FAULT_9026,// Duplicate Deployment Unit
	FAULT_9027,// System Ressources Exceeded
	FAULT_9028,// Unknown Deployment Unit
	FAULT_9029,// Invalid Deployment Unit State
	FAULT_9030,// Invalid Deployment Unit Update: Downgrade not permitted
	FAULT_9031,// Invalid Deployment Unit Update: Version not specified
	FAULT_9032,// Invalid Deployment Unit Update: Version already exist
	__FAULT_MAX
};

enum {
	INSTANCE_UPDATE_NUMBER,
	INSTANCE_UPDATE_ALIAS
};

enum instance_mode {
	INSTANCE_MODE_NUMBER,
	INSTANCE_MODE_ALIAS
};

enum bbf_end_session_enum {
	BBF_END_SESSION_REBOOT = 1,
	BBF_END_SESSION_EXTERNAL_ACTION = 1<<1,
	BBF_END_SESSION_RELOAD = 1<<2,
	BBF_END_SESSION_FACTORY_RESET = 1<<3,
	BBF_END_SESSION_IPPING_DIAGNOSTIC = 1<<4,
	BBF_END_SESSION_DOWNLOAD_DIAGNOSTIC = 1<<5,
	BBF_END_SESSION_UPLOAD_DIAGNOSTIC = 1<<6,
	BBF_END_SESSION_X_FACTORY_RESET_SOFT = 1<<7,
	BBF_END_SESSION_NSLOOKUP_DIAGNOSTIC = 1<<8,
	BBF_END_SESSION_TRACEROUTE_DIAGNOSTIC = 1<<9,
	BBF_END_SESSION_UDPECHO_DIAGNOSTIC = 1<<10,
	BBF_END_SESSION_SERVERSELECTION_DIAGNOSTIC = 1<<11
};

enum dm_browse_enum {
	DM_ERROR = -1,
	DM_OK = 0,
	DM_STOP = 1
};

enum dmt_type_enum {
	DMT_STRING,
	DMT_UNINT,
	DMT_INT,
	DMT_UNLONG,
	DMT_LONG,
	DMT_BOOL,
	DMT_TIME,
	DMT_HEXBIN,
	DMT_BASE64,
	DMT_COMMAND,
	DMT_EVENT,
};

enum amd_version_enum {
	AMD_1 = 1,
	AMD_2,
	AMD_3,
	AMD_4,
	AMD_5,
};

enum bbfdm_type_enum {
	BBFDM_BOTH,
	BBFDM_CWMP,
	BBFDM_USP,
	BBFDM_NONE
};

enum {
	INDX_JSON_MOUNT,
	INDX_LIBRARY_MOUNT,
	INDX_VENDOR_MOUNT,
	__INDX_DYNAMIC_MAX
};

int get_number_of_entries(struct dmctx *ctx, void *data, char *instance, int (*browseinstobj)(struct dmctx *ctx, struct dmnode *node, void *data, char *instance));
char *handle_instance(struct dmctx *dmctx, DMNODE *parent_node, struct uci_section *s, char *inst_opt, char *alias_opt);
char *handle_instance_without_section(struct dmctx *dmctx, DMNODE *parent_node, int inst_nbr);
int get_empty(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
void add_list_parameter(struct dmctx *ctx, char *param_name, char *param_data, char *param_type, char *additional_data);
void free_all_list_parameter(struct dmctx *ctx);
void free_all_set_list_tmp(struct dmctx *ctx);
void add_list_fault_param(struct dmctx *ctx, char *param, int fault);
void bbf_api_del_list_fault_param(struct param_fault *param_fault);
void free_all_list_fault_param(struct dmctx *ctx);
int string_to_bool(char *v, bool *b);
void dmentry_instance_lookup_inparam(struct dmctx *ctx);
int dm_entry_get_value(struct dmctx *dmctx);
int dm_entry_get_name(struct dmctx *ctx);
int dm_entry_get_schema(struct dmctx *ctx);
int dm_entry_get_supported_dm(struct dmctx *ctx);
int dm_entry_get_instances(struct dmctx *ctx);
int dm_entry_add_object(struct dmctx *dmctx);
int dm_entry_delete_object(struct dmctx *dmctx);
int dm_entry_set_value(struct dmctx *dmctx);
int dm_entry_get_linker(struct dmctx *dmctx);
int dm_entry_get_linker_value(struct dmctx *dmctx);
int dm_entry_list_operates(struct dmctx *ctx);
int dm_entry_operate(struct dmctx *dmctx);
int dm_entry_list_events(struct dmctx *dmctx);
int dm_browse_last_access_path(char *path, size_t len);
int dm_link_inst_obj(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance);
void dm_exclude_obj(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, char *data);
void dm_check_dynamic_obj(struct dmctx *dmctx, DMNODE *parent_node, DMOBJ *entryobj, char *full_obj, char *obj, DMOBJ **root_entry, int *obj_found);
bool find_root_entry(struct dmctx *ctx, char *in_param, DMOBJ **root_entry);
int get_obj_idx_dynamic_array(DMOBJ **entryobj);
int get_leaf_idx_dynamic_array(DMLEAF **entryleaf);
void free_dm_browse_node_dynamic_object_tree(DMNODE *parent_node, DMOBJ *entryobj);

char *update_instance_alias(int action, char **last_inst, char **max_inst, void *argv[]);
char *update_instance(char *max_inst, int argc, ...);
__attribute__ ((deprecated)) char *update_instance_without_section(int action, char **last_inst, char **max_inst, void *argv[]);
__attribute__ ((deprecated)) char *get_last_instance(char *package, char *section, char *opt_inst);
__attribute__ ((deprecated)) char *get_last_instance_bbfdm(char *package, char *section, char *opt_inst);
__attribute__ ((deprecated)) char *get_last_instance_lev2_bbfdm_dmmap_opt(char* dmmap_package, char *section,  char *opt_inst, char *opt_check, char *value_check);
__attribute__ ((deprecated)) char *get_last_instance_lev2_bbfdm(char *package, char *section, char* dmmap_package, char *opt_inst, char *opt_check, char *value_check);
__attribute__ ((deprecated)) char *handle_update_instance(int instance_ranck, struct dmctx *ctx, char **max_inst, char * (*up_instance)(int action, char **last_inst, char **max_inst, void *argv[]), int argc, ...);

static inline int DM_LINK_INST_OBJ(struct dmctx *dmctx, DMNODE *parent_node, void *data, char *instance)
{
	dmctx->faultcode = dm_link_inst_obj(dmctx, parent_node, data, instance);
	if (dmctx->stop)
		return DM_STOP;
	return DM_OK;
}

#ifndef TRACE
#define TRACE(MESSAGE, ...) do { \
	fprintf(stderr, "TRACE: %s@%s:%d " MESSAGE, __FUNCTION__,__FILE__,__LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
	fprintf(stderr, "\n"); \
	fflush(stderr); \
} while(0)
#endif

#define ENABLE_BBF_DEBUG 0

#if ENABLE_BBF_DEBUG
#define BBF_DEBUG(fmt, ...) do { \
	FILE *fp = fopen("/tmp/bbfdm.log", "a"); \
	if (fp) { \
		fprintf(fp, "%s@%s:%d: " fmt, __func__, __FILE__, __LINE__, ##__VA_ARGS__); /* Flawfinder: ignore */ \
		fclose(fp); \
	} \
} while(0)
#else
#define BBF_DEBUG(fmt, ...)
#endif

#endif //__DMBBF_H__
