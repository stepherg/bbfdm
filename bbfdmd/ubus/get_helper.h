#ifndef GET_HELPER_H
#define GET_HELPER_H

#include "bbfdmd.h"
#include "common.h"

#include <libubus.h>

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

void handle_pending_signal(int sig);

int bbfdm_cmd_exec(struct dmctx *bbf_ctx, int cmd);

void bbf_init(struct dmctx *dm_ctx);
void bbf_cleanup(struct dmctx *dm_ctx);
void bbf_sub_init(struct dmctx *dm_ctx);
void bbf_sub_cleanup(struct dmctx *dm_ctx);

bool present_in_path_list(struct list_head *plist, char *entry);

void add_pv_list(char *para, char *val, char *type, struct list_head *pv_list);
void free_pv_list(struct list_head *pv_list);

void add_path_list(char *param, struct list_head *plist);
void free_path_list(struct list_head *plist);

void fill_err_code_table(bbfdm_data_t *data, int fault);
void fill_err_code_array(bbfdm_data_t *data, int fault);

void bb_add_string(struct blob_buf *bb, const char *name, const char *value);

void bb_add_flags_arr(struct blob_buf *bb, char *data);

int transaction_start(bbfdm_data_t *data, char *app, uint32_t max_timeout);
int transaction_commit(bbfdm_data_t *data, int trans_id, bool is_service_restart);
int transaction_abort(bbfdm_data_t *data, int trans_id);
int transaction_status(struct blob_buf *bb);
bool is_transaction_running(void);
bool is_transaction_valid(int trans_id);
int configure_transaction_timeout(int timeout);
struct pvNode *sort_pv_path(struct list_head *pv_list, size_t pv_count);

#endif /* GET_HELPER_H */
