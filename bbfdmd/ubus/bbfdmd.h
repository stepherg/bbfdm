#ifndef BBFDMD_H
#define BBFDMD_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#include "dmbbf.h"

#define MAX_MULTI_OBJS 5

struct bbfdm_async_req {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_process process;
	void *result;
};

typedef struct bbfdm_config {
	int proto;
	int instance_mode;
	int transaction_timeout;
	int subprocess_level;
	uint8_t log_level;
	uint32_t refresh_time;
	char in_type[32];
	char in_name[128];
	char in_plugin_dir[128];
	char out_type[32];
	char out_name[128];
	char out_parent_dm[32];
	char out_object[32];
	char out_multi_objects[MAX_MULTI_OBJS][32];
	char out_root_obj[32];
	char cli_in_type[32];
	char cli_in_name[128];
	char cli_in_plugin_dir[128];
	char cli_out_type[32];
} bbfdm_config_t;

struct bbfdm_context {
	bbfdm_config_t config;
	struct ubus_context ubus_ctx;
	struct blob_buf dm_schema;
	struct uloop_timeout instance_timer;
	struct list_head event_handlers;
	struct list_head instances;
	struct list_head old_instances;
};

struct ev_handler_node {
	char *dm_path;
	char *ev_name;
	struct ubus_event_handler *ev_handler;
	struct list_head list;
};

typedef struct bbfdm_data {
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	struct list_head *plist;
	struct dmctx bbf_ctx;
	struct blob_buf *bbp;
	struct blob_buf bb;
	uint8_t depth;
	bool is_raw;
	int trans_id;
} bbfdm_data_t;

#endif /* BBFDMD_H */
