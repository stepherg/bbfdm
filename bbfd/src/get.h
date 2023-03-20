#ifndef GET_H
#define GET_H
#include "usp.h"
#include "common.h"

enum {
	DM_GET_PATH,
	DM_GET_PROTO,
	DM_GET_MAXDEPTH,
	DM_GET_NXT_LVL,
	DM_GET_INSTANCE,
	__DM_GET_MAX
};

enum {
	DM_GET_SAFE_PATHS,
	DM_GET_SAFE_PROTO,
	DM_GET_SAFE_NXT_LVL,
	DM_GET_SAFE_INSTANCE,
	__DM_GET_SAFE_MAX
};

void init_dmmap(void);
void usp_validate_path(usp_data_t *data);
void usp_get_value(usp_data_t *data);
void usp_get_instance(usp_data_t *data);
void usp_get_name(usp_data_t *data);
void get_mpath(usp_data_t *data);
void usp_get_value_async(usp_data_t *data, void *output);

#endif /* GET_H */
