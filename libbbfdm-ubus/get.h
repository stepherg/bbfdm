#ifndef GET_H
#define GET_H

enum {
	DM_GET_PATH,
	DM_GET_OPTIONAL,
	__DM_GET_MAX
};

enum {
	DM_INSTANCES_PATH,
	DM_INSTANCES_OPTIONAL,
	__DM_INSTANCES_MAX
};

enum {
	DM_SCHEMA_PATH,
	DM_SCHEMA_FIRST_LEVEL,
	DM_SCHEMA_OPTIONAL,
	__DM_SCHEMA_MAX
};

void bbfdm_get(bbfdm_data_t *data, int method);

#endif /* GET_H */
