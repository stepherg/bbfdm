#ifndef SET_H
#define SET_H

enum {
	DM_SET_PATH,
	DM_SET_VALUE,
	DM_SET_TYPE,
	DM_SET_OBJ_PATH,
	DM_SET_OPTIONAL,
	__DM_SET_MAX,
};

int fill_pvlist_set(char *param_name, char *param_value, char *data_type, struct blob_attr *blob_table, struct list_head *pv_list);
int bbfdm_set_value(bbfdm_data_t *data);

#endif /* SET_H */

