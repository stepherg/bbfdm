#ifndef BBFDMD_H
#define BBFDMD_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#include "libbbf_api/dmbbf.h"

struct uspd_async_req {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_process process;
	void *result;
};

struct usp_context {
	struct ubus_context ubus_ctx;
	size_t dm_schema_len;
	struct uloop_timeout schema_timer;
	struct uloop_timeout instance_timer;
	struct list_head event_handlers;
	struct list_head instances;
	struct list_head old_instances;
};

struct ev_handler_node {
	struct ubus_event_handler *ev_handler;
	struct list_head list;
};

typedef struct usp_data {
	struct ubus_context *ctx;
	struct ubus_request_data *req;
	struct list_head *plist;
	struct dmctx bbf_ctx;
	struct blob_buf bb;
	uint8_t depth;
	bool is_raw;
	int trans_id;
} usp_data_t;

#endif /* BBFDMD_H */
