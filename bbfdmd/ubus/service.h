/*
 * Copyright (C) 2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#ifndef BBFDMD_SERVICE_H
#define BBFDMD_SERVICE_H

typedef struct {
	enum bbfdmd_type_enum protocol;
	char parent_path[MAX_PATH_LENGTH - 256];
	char object_name[256];
} service_object_t;

typedef struct service_entry {
    struct list_head list;
    struct blob_buf *dm_schema;
    char *name;
    enum bbfdmd_type_enum protocol;
    bool is_unified;
    size_t object_count;
    service_object_t *objects;
    int timeout; // Ubus timeout used to get data from lower layer
    int consecutive_timeouts; // Tracks successive timeouts
    bool is_blacklisted; // Marks if the service is blacklisted
} service_entry_t;

int register_services(struct ubus_context *ctx);
void unregister_services(void);
void list_registered_services(struct blob_buf *bb);
void fill_service_schema(struct ubus_context *ubus_ctx, int ubus_timeout, const char *service_name, struct blob_buf **service_schema);

bool service_path_match(const char *requested_path, unsigned int requested_proto, service_entry_t *service);

#endif /* BBFDMD_SERVICE_H */
