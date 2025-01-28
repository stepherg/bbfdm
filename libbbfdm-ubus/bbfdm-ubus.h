#ifndef BBFDM_UBUS_H
#define BBFDM_UBUS_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#include "libbbfdm-api/legacy/dmbbf.h"

#define BBFDM_DEFAULT_UBUS_OBJ "bbfdm"

struct bbfdm_async_req {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_process process;
	void *result;
};

typedef struct bbfdm_config {
	char service_name[32]; // Service name for micro-service identification
	char in_name[128]; // Service plugin path
	char in_plugin_dir[128];  // Service extra/internal plugin directory path
	char out_name[128]; // Ubus name to use
} bbfdm_config_t;

struct bbfdm_context {
	bbfdm_config_t config;
	struct ubus_context ubus_ctx;
	struct list_head event_handlers;
	struct list_head linker_list;
	struct list_head obj_list;
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
} bbfdm_data_t;

int bbfdm_ubus_regiter_init(struct bbfdm_context *bbfdm_ctx);
int bbfdm_ubus_regiter_free(struct bbfdm_context *bbfdm_ctx);

void bbfdm_ubus_set_service_name(struct bbfdm_context *bbfdm_ctx, const char *srv_name);
void bbfdm_ubus_set_log_level(int log_level);
void bbfdm_ubus_load_data_model(DM_MAP_OBJ *DynamicObj);

#endif /* BBFDM_UBUS_H */
