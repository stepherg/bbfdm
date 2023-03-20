#ifndef ADD_DEL_H
#define ADD_DEL_H

#include "usp.h"

enum {
	DM_ADD_PATH,
	DM_ADD_PROTO,
	DM_ADD_INSTANCE,
	__DM_ADD_MAX
};

enum {
	DM_RAW_ADD_PATH,
	DM_RAW_ADD_PROTO,
	DM_RAW_ADD_INSTANCE,
	DM_RAW_ADD_TRANS_ID,
	__DM_RAW_ADD_MAX
};

int create_add_response(usp_data_t *data, struct blob_buf *bb);
int create_del_response(usp_data_t *data, struct blob_buf *bb);
#endif /* ADD_DEL_H */
