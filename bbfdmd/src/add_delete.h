#ifndef ADD_DEL_H
#define ADD_DEL_H

#include "bbfdmd.h"

enum {
	DM_ADD_PATH,
	DM_ADD_OBJ_PATH,
	DM_ADD_OPTIONAL,
	__DM_ADD_MAX
};

enum {
	DM_DEL_PATH,
	DM_DEL_PATHS,
	DM_DEL_OPTIONAL,
	__DM_DEL_MAX
};

int create_add_response(bbfdm_data_t *data);
int create_del_response(bbfdm_data_t *data);

#endif /* ADD_DEL_H */
