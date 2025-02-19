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
    char *name;
    enum bbfdmd_type_enum protocol;
    bool is_unified;
    size_t object_count;
    service_object_t *objects;
} service_entry_t;

int register_services(struct ubus_context *ctx);
void unregister_services(void);
void list_registered_services(struct blob_buf *bb);

bool is_path_match(const char *requested_path, unsigned int requested_proto, service_entry_t *service);

#endif /* BBFDMD_SERVICE_H */
