/*
 * Copyright (C) 2021 IOPSYS Software Solutions AB
 *
 * Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef __DMAPI_H__
#define __DMAPI_H__

#include <uci.h>
#include <libubox/list.h>
#include <json-c/json.h>

extern struct dm_permession_s DMREAD;
extern struct dm_permession_s DMWRITE;
extern struct dm_permession_s DMSYNC;
extern struct dm_permession_s DMASYNC;

extern char *DMT_TYPE[];

extern unsigned char gLogLevel;
extern bool is_micro_service;

#ifndef BBF_MAX_OBJECT_INSTANCES
#define BBF_MAX_OBJECT_INSTANCES (255)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef FREE
#define FREE(x) do { if(x) {free(x); x = NULL;} } while (0)
#endif

#define DM_STRNCPY(DST, SRC, SIZE) \
do { \
	strncpy(DST, SRC, SIZE - 1); \
	DST[SIZE-1] = '\0'; \
} while(0)

#define DM_ULTOSTR(DST, SRC, SIZE) \
do { \
	const int n = snprintf(DST, SIZE, "%lu", SRC); \
	DST[n] = '\0'; \
} while(0)

#define DM_STRLEN(SRC) ((SRC != NULL) ? strlen(SRC) : 0)
#define DM_STRSTR(STR, MATCH) ((STR != NULL && MATCH != NULL) ? strstr(STR, MATCH) : NULL)
#define DM_STRCHR(STR, CHR) ((STR != NULL) ? strchr(STR, CHR) : NULL)
#define DM_STRRCHR(STR, CHR) ((STR != NULL) ? strrchr(STR, CHR) : NULL)
#define DM_STRTOL(SRC) ((SRC != NULL) ? strtol(SRC, NULL, 10) : 0)
#define DM_STRTOUL(SRC) ((SRC != NULL) ? strtoul(SRC, NULL, 10) : 0)
#define DM_STRCMP(S1, S2) ((S1 != NULL && S2 != NULL) ? strcmp(S1, S2) : -1)
#define DM_STRNCMP(S1, S2, LEN) ((S1 != NULL && S2 != NULL && LEN > 0) ? strncmp(S1, S2, LEN) : -1)
#define DM_STRCASECMP(S1, S2) ((S1 != NULL && S2 != NULL) ? strcasecmp(S1, S2) : -1)

/* below macros are only useful when the second argument is a string literal.
 * these macros are introduced to autofix the cppcheck warnings for null check
 * against string literal
 */
#define DM_LSTRSTR(STR, MATCH) ((STR != NULL) ? strstr(STR, MATCH) : NULL)
#define DM_LSTRCMP(S1, S2) ((S1 != NULL) ? strcmp(S1, S2) : -1)
#define DM_LSTRNCMP(S1, S2, LEN) ((S1 != NULL && LEN > 0) ? strncmp(S1, S2, LEN) : -1)

#define UBUS_ARGS (struct ubus_arg[])
#define RANGE_ARGS (struct range_args[])

#define DMPARAM_ARGS \
	struct dmctx *dmctx, \
	struct dmnode *node, \
	DMLEAF *leaf, \
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

typedef struct dm_leaf_s {
	/* PARAM, permission, type, getvalue, setvalue, bbfdm_type(6)*/
	char *parameter;
	struct dm_permession_s *permission;
	int type;
	int (*getvalue)(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
	int (*setvalue)(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
	int bbfdm_type;
	uint32_t dm_falgs;

} DMLEAF;

typedef struct dm_obj_s {
	/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, nextdynamicobj, dynamicleaf, nextobj, leaf, linker, bbfdm_type, uniqueKeys (13)*/
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
	const char **unique_keys; // To be removed later!!!!!!!!!!!!
} DMOBJ;

struct dm_parameter {
	struct list_head list;
	char *name;
	char *data;
	char *type;
	char *additional_data;
};

typedef struct dm_map_obj {
	char *path;
	struct dm_obj_s *root_obj;
	struct dm_leaf_s *root_leaf;
} DM_MAP_OBJ;

struct dm_reference {
	char *path;
	char *value;
};

struct dmctx {
	bool stop;
	bool match;
	int (*method_param)(DMPARAM_ARGS);
	int (*method_obj)(DMOBJECT_ARGS);
	int (*checkobj)(DMOBJECT_ARGS);
	int (*checkleaf)(DMOBJECT_ARGS);
	struct list_head list_parameter;
	struct list_head *memhead;
	DMOBJ *dm_entryobj;
	bool nextlevel;
	bool iswildcard;
	int faultcode;
	char fault_msg[256];
	int setaction;
	char *in_param;
	char *in_value;
	char *addobj_instance;
	char *linker;
	char *linker_param;
	unsigned int alias_register;
	unsigned int nbrof_instance;
	unsigned int instance_mode;
	unsigned int dm_type;
	unsigned char inparam_isparam;
	unsigned char findparam;
	char *inst_buf[16];
	bool isgetschema;
	bool iscommand;
	bool isevent;
	bool isinfo;
	bool disable_mservice_browse;
	int trans_id;
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
	bool is_ubus_service;
} DMNODE;

enum operate_ret_status {
	CMD_SUCCESS __attribute__ ((deprecated)),
	CMD_INVALID_ARGUMENTS __attribute__ ((deprecated)),
	CMD_FAIL __attribute__ ((deprecated)),
	CMD_NOT_FOUND __attribute__ ((deprecated)),
	__STATUS_MAX __attribute__ ((deprecated)),
};

typedef struct {
	const char **in;
	const char **out;
} operation_args;

typedef struct {
	const char *name;
	const char **param;
} event_args;

enum dm_flags_enum {
	DM_FLAG_REFERENCE = 1,
	DM_FLAG_UNIQUE = 1<<1,
	DM_FLAG_LINKER = 1<<2,
	DM_FLAG_SECURE = 1<<3
};

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
	BBF_GET_VALUE,
	BBF_SCHEMA,
	BBF_INSTANCES,
	BBF_GET_NAME,
	BBF_SET_VALUE,
	BBF_ADD_OBJECT,
	BBF_DEL_OBJECT,
	BBF_OPERATE,
	BBF_EVENT,
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

	// Param Error codes
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

enum instance_mode {
	INSTANCE_MODE_NUMBER,
	INSTANCE_MODE_ALIAS
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

enum bbfdm_type_enum {
	BBFDM_BOTH,
	BBFDM_CWMP,
	BBFDM_USP,
	BBFDM_NONE
};

enum {
	INDX_JSON_MOUNT,
	INDX_LIBRARY_MOUNT,
	INDX_SERVICE_MOUNT,
	__INDX_DYNAMIC_MAX
};

enum dm_uci_cmp {
	CMP_SECTION,
	CMP_OPTION_EQUAL,
	CMP_OPTION_REGEX,
	CMP_OPTION_CONTAINING,
	CMP_OPTION_CONT_WORD,
	CMP_LIST_CONTAINING,
	CMP_FILTER_FUNC
};

enum dm_uci_walk {
	GET_FIRST_SECTION,
	GET_NEXT_SECTION
};

enum ubus_arg_type {
	String,
	Integer,
	Boolean,
	Table
};

struct ubus_arg {
	const char *key;
	const char *val;
	enum ubus_arg_type type;
};

struct range_args {
	const char *min;
	const char *max;
};

struct dmmap_dup {
	struct list_head list;
	struct uci_section *config_section;
	struct uci_section *dmmap_section;
};

struct dm_data {
	struct list_head list;
	struct uci_section *config_section;
	struct uci_section *dmmap_section;
	struct json_object *json_object;
	void *additional_data;
};

struct dm_fault {
	int code;
	char *description;
};

#endif //__DMAPI_H__
