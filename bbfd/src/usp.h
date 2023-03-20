#ifndef USP_H
#define USP_H

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#define USP_ATTR_UNUSED __attribute__((unused))
#define USP_EXT_LEN (4) // length of usp.
#define MAX_GRANURALITY_DEPTH (3)
#define USP_SUBPROCESS_DEPTH (2)
#define SCHEMA_UPDATE_TIMEOUT (30 * 1000)

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
	struct ubus_object *notify_object;
	struct list_head obj_list;
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
	bool is_raw;
	int proto;
	char *qpath;
	uint8_t depth;
	char *next_level;
	int dm_cmd;
	struct list_head *plist;
	struct list_head *pv_list;
	char *set_key;
	char *op_action;
	char *op_input;
	int instance;
	int trans_id;
} usp_data_t;

enum {
	DM_LIST_NOTIFY_INSTANCE,
	__DM_LIST_NOTIFY_MAX,
};

enum {
	DM_SUPPORTED_PATH,
	DM_SUPPORTED_NXT_LEVEL,
	DM_SUPPORTED_SCHEMA_TYPE,
	__DM_SUPPORTED_MAX
};

enum {
	DM_NOTIFY_NAME,
	DM_NOTIFY_PRAMS,
	__DM_NOTIFY_MAX,
};

struct obNode {
	struct ubus_object *obj;
	struct list_head list;
};

int get_multi(struct ubus_context *ctx, struct ubus_object *obj,
	      struct ubus_request_data *req, struct blob_attr *msg,
	      int bbf_cmd);

int usp_getm_values(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req,
		    USP_ATTR_UNUSED const char *method,
		    struct blob_attr *msg);

int usp_getm_names(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req,
		   USP_ATTR_UNUSED const char *method,
		   struct blob_attr *msg);

int usp_add_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg);

int usp_raw_add_del_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg);

int usp_get_handler(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method USP_ATTR_UNUSED,
		    struct blob_attr *msg);

int usp_set(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg);

int usp_raw_set(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg);

int usp_operate(struct ubus_context *ctx, struct ubus_object *obj USP_ATTR_UNUSED,
		struct ubus_request_data *req, const char *method USP_ATTR_UNUSED,
		struct blob_attr *msg);

int usp_list_schema(struct ubus_context *actx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg USP_ATTR_UNUSED);

int usp_list_operate(struct ubus_context *actx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg USP_ATTR_UNUSED);

int handle_set_multi_value(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method USP_ATTR_UNUSED,
			   struct blob_attr *msg);

int usp_transaction_handler(struct ubus_context *ctx, struct ubus_object *obj,
			    struct ubus_request_data *req, const char *method,
			    struct blob_attr *msg);

bool usp_pre_init(struct usp_context *u);
bool usp_post_init(struct usp_context *u);
bool usp_cleanup(struct usp_context *u);

#endif /* COMMON_H */
