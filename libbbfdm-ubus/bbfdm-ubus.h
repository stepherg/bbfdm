#ifndef BBFDM_UBUS_H
#define BBFDM_UBUS_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#include <libbbfdm-api/dmbbf.h>

#define BBFDM_DEFAULT_MICROSERVICE_INPUT_PATH "/etc/bbfdm/micro_services"
#define MAX_OBJS 7

#ifndef DAEMON_JSON_INPUT
#define BBFDM_JSON_INPUT "/tmp/bbfdm/input.json"
#else
#define BBFDM_JSON_INPUT DAEMON_JSON_INPUT
#endif

struct bbfdm_async_req {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_process process;
	bool is_operate;
	void *result;
};

typedef struct bbfdm_config {
	int proto; // Protocol identifier, Possible values: { '0'<both>, '1'<cwmp>, '2'<usp> }
	int subprocess_level; // Subprocess level
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
	struct uloop_timeout instance_timer;
	struct list_head event_handlers;
	struct list_head instances;
	struct list_head old_instances;
	int schema_len;
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
	struct blob_buf bb;
	uint8_t depth;
	bool is_raw;
} bbfdm_data_t;

void register_instance_refresh_timer(struct ubus_context *ctx, int start_sec);
void cancel_instance_refresh_timer(struct ubus_context *ctx);

int bbfdm_ubus_regiter_init(struct bbfdm_context *bbfdm_ctx);
int bbfdm_ubus_regiter_free(struct bbfdm_context *bbfdm_ctx);

void bbfdm_ubus_set_service_name(struct bbfdm_context *bbfdm_ctx, const char *srv_name);
void bbfdm_ubus_set_log_level(int log_level);
void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj);

#endif /* BBFDM_UBUS_H */
