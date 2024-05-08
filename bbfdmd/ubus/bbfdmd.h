#ifndef BBFDMD_H
#define BBFDMD_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#include "dmbbf.h"

#define MAX_OBJS 5

struct bbfdm_async_req {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_process process;
	void *result;
};

typedef struct bbfdm_config {
	int proto; // Protocol identifier, Possible values: { '0'<both>, '1'<cwmp>, '2'<usp> }
	int instance_mode; // Instance mode, Possible values: { '0'<Instance Number>, '1'<Instance Alias> }
	int transaction_timeout; // Timeout for transactions
	int subprocess_level; // Subprocess level
	uint8_t log_level; // Log level, Possible values: { '1', '2', '3', '4' }
	uint32_t refresh_time; // Refresh time
	char service_name[16]; // Service name for micro-service identification
	char in_type[32]; // Input type, Possible values: { 'JSON', 'DotSo' }
	char in_name[128]; // plugin path
	char in_plugin_dir[128];  // extra plugin directory path
	char out_name[128]; // Ubus name to use
	char out_parent_dm[32]; // Parent device for micro-service
	char out_objects[MAX_OBJS][32]; // Micro-service objects to expose
	char out_root_obj[32]; // Ubus name to use as root data model
	char cli_in_type[32]; // CLI input type, Possible values: { 'UBUS', 'JSON', 'DotSo' }
	char cli_in_name[128]; // CLI input name
	char cli_in_plugin_dir[128]; // CLI input plugin directory
	char cli_out_type[32]; // CLI output type, Possible values: { 'CLI' }
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

void register_instance_refresh_timer(struct ubus_context *ctx, int start_sec);
void cancel_instance_refresh_timer(struct ubus_context *ctx);

#endif /* BBFDMD_H */
