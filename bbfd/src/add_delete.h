#ifndef ADD_DEL_H
#define ADD_DEL_H

#include "bbfd.h"

#include "libbbf_api/src/dmbbf.h"

enum {
	DM_ADD_PATH,
	DM_ADD_OBJ_PATH,
	DM_ADD_OPTIONAL,
	__DM_ADD_MAX
};

enum {
	DM_DELETE_PATH,
	DM_DELETE_PATHS,
	DM_DELETE_OPTIONAL,
	__DM_DELETE_MAX
};

int create_add_response(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);
int create_del_response(struct dmctx *bbf_ctx, usp_data_t *data, struct blob_buf *bb);

#endif /* ADD_DEL_H */
