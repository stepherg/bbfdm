#ifndef SET_H
#define SET_H
#include "usp.h"
#include "common.h"

enum {
	DM_SETS_PATHS,
	DM_SETS_PROTO,
	DM_SETS_INSTANCE,
	DM_SETS_TRANS_ID,
	__DM_SETS_MAX
};

enum {
	DM_SETS_A_NOTIF_PATH,
	DM_SETS_A_NOTIF_VALUE,
	DM_SETS_A_NOTIF_CHANGE,
	__DM_SETS_A_NOTIF_MAX
};

enum {
	DM_SET_PATH,
	DM_SET_VALUE,
	DM_SET_VALUE_TABLE,
	DM_SET_PROTO,
	DM_SET_INSTANCE,
	__DM_SET_MAX,
};

enum {
	DM_RAW_SET_PATH,
	DM_RAW_SET_VALUE,
	DM_RAW_SET_VALUE_TABLE,
	DM_RAW_SET_PROTO,
	DM_RAW_SET_INSTANCE,
	DM_RAW_SET_TRANS_ID,
	__DM_RAW_SET_MAX,
};

enum {
	DM_SET_V_PATH,
	DM_SET_V_VALUE,
	__DM_SET_V_MAX
};

enum {
	DM_SET_MULTI_TUPLE,
	DM_SET_MULTI_PROTO,
	DM_SET_MULTI_INSTANCE,
	DM_SET_MULTI_TRANS_ID,
	__DM_SET_MULTI_MAX
};

int fill_pvlist_from_table(char *bpath, struct blob_attr *blob_value, struct list_head *pv_list, int instance);
int fill_pvlist_from_tuple(struct blob_attr *blob, struct list_head *pv_list);
int fill_pvlist_from_path(char *path, struct blob_attr *val_blob, struct list_head *pv_list, int instance);
int usp_set_value(usp_data_t *data);

#endif /* SET_H */

