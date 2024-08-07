#ifndef GET_H
#define GET_H

#include "bbfdmd.h"
#include "common.h"

enum {
	DM_GET_PATH,
	DM_GET_PATHS,
	DM_GET_MAXDEPTH,
	DM_GET_OPTIONAL,
	__DM_GET_MAX
};

enum {
	DM_INSTANCES_PATH,
	DM_INSTANCES_PATHS,
	DM_INSTANCES_FIRST_LEVEL,
	DM_INSTANCES_OPTIONAL,
	__DM_INSTANCES_MAX
};

enum {
	DM_SCHEMA_PATH,
	DM_SCHEMA_PATHS,
	DM_SCHEMA_FIRST_LEVEL,
	DM_SCHEMA_OPTIONAL,
	__DM_SCHEMA_MAX
};

void bbfdm_get_value(bbfdm_data_t *data, void *output);

void bbfdm_get_names(bbfdm_data_t *data);

void bbfdm_get_instances(bbfdm_data_t *data);

int bbfdm_get_supported_dm(bbfdm_data_t *data);

#endif /* GET_H */
