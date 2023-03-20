#ifndef GET_HELPER_H
#define GET_HELPER_H

#include "usp.h"
#include "common.h"
#include <libbbf_api/dmbbf.h>

#include <libubus.h>

enum operation {
	OPER_EQUAL_EQUAL,
	OPER_NOT_EQUAL,
	OPER_LESS_THAN_EQUAL,
	OPER_GREATER_THAN_EQUAL,
	OPER_LESS_THAN,
	OPER_GREATER_THAN,
};

struct pvNode {
	char *param;
	char *val;
	char *type;
	struct list_head list;
};

struct pathNode {
	struct list_head list;
	char path[MAX_DM_PATH];
};

int resolve_path(struct dmctx *bbf_ctx, char *qPath, size_t pos,
		 struct list_head *resolved_plist);

void add_path_node(char *para, struct list_head *plist);
void fill_err_code(struct blob_buf *bb, int fault);
void fill_resolve_err(struct blob_buf *bb, char *spath, int fault);
void add_pv_node(char *para, char *val, char *type,
		 struct list_head *pv_list);

bool path_present_in_pvlist(struct list_head *pvlist, char *entry);
void free_pv_list(struct list_head *head);
void free_pv_node(struct pvNode *pv);
void free_path_list(struct list_head *head);

bool get_granural_object_paths(struct list_head *path_list,
			       uint8_t maxdepth);

int bbf_dm_get_supported_dm(struct blob_buf *bb, char *path, bool first_level, int schema_type);
int bbf_dm_get_values(struct dmctx *bbf_ctx, char *path);
int bbf_dm_get_schema(struct blob_buf *bb);
int bbf_dm_get_names(struct dmctx *bbf_ctx, char *path, char *next);

int bbf_dm_list_operate(struct dmctx *bbf_ctx);
int usp_dm_set(struct dmctx *dm_ctx, char *path, char *value);

int get_resolved_paths(struct dmctx *bbf_ctx, char *qpath,
		       struct list_head *resolved_paths);

int usp_dm_operate(struct blob_buf *bb, char *path, char *input_params, bool raw, int instance);
int usp_del_object(struct dmctx *bbf_ctx, struct blob_buf *bb, char *path, const char *pkey);

int usp_add_object(struct dmctx *bbf_ctx, struct blob_buf *bb, char *path, const char *pkey);

int bbf_get_blob(usp_data_t *data, struct blob_buf *bb);
int bbf_get_raw(usp_data_t *data, struct blob_buf *bb);
bool get_next_param(char *qPath, size_t *pos, char *param);
int bbf_dm_get_instances(struct dmctx *bbf_ctx, char *path, char *next);
void bbf_init(struct dmctx *dm_ctx, int instance);
void bbf_configure_ubus(struct ubus_context *ctx);
void bbf_cleanup(struct dmctx *dm_ctx);
void bb_add_string(struct blob_buf *bb, const char *name, const char *value);
bool bbf_dm_event_registered(char *ename);
void set_datamodel_version(char * version);

bool present_in_path_list(struct list_head *plist, char *entry);

// Transaction related
bool is_transaction_running(void);
bool is_transaction_valid(int trans_id);
int transaction_start(const char *app, uint32_t max_timeout);
int fill_transaction_status(struct blob_buf *bb, int trans_id);
int transaction_commit(int trans_id, struct blob_buf *bp_service_list, bool is_service_restart);
int transaction_abort(int trans_id);
int configure_transaction_timeout(int timeout);
void handle_pending_signal(int);
void print_last_dm_object(void);
int usp_dm_exec_apply(struct dmctx *bbf_ctx, int cmd);

#endif /* GET_HELPER_H */
