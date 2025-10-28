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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <dirent.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

#include "common.h"
#include "service.h"

LIST_HEAD(registered_services);

static void add_service_to_list(const char *name, struct blob_buf *dm_schema, int service_proto, int service_timeout,
		service_object_t *objects, size_t count, bool is_unified)
{
	service_entry_t *service = NULL;

	if (!name || !objects || count == 0) {
		BBFDM_ERR("Invalid service registration parameters");
		return;
	}

	service = (service_entry_t *)calloc(1, sizeof(service_entry_t));
	if (!service) {
		BBFDM_ERR("Failed to allocate memory");
		return;
	}

	list_add_tail(&service->list, &registered_services);

	service->name = strdup(name);
	service->dm_schema = dm_schema;
	service->protocol = service_proto;
	service->timeout = service_timeout;
	service->objects = objects;
	service->object_count = count;
	service->is_unified = is_unified;
}

static void receive_schema_result(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *attr = NULL;
	int remaining = 0;

	if (msg == NULL || req == NULL)
		return;

	struct blob_buf *srv_schema = (struct blob_buf *)req->priv;
	if (!srv_schema)
		return;

	struct blob_attr *results = get_results_array(msg);
	if (!results)
		return;

	blobmsg_for_each_attr(attr, results, remaining) {
		blobmsg_add_blob(srv_schema, attr);
	}
}

void fill_service_schema(struct ubus_context *ubus_ctx, int ubus_timeout, const char *service_name, struct blob_buf **service_schema)
{
	uint32_t ubus_id;

	if (!ubus_ctx || !service_name || !service_schema)
		return;

	if (*service_schema != NULL) {
		blob_buf_free(*service_schema);
		BBFDM_FREE(*service_schema);
	}

	if (!ubus_lookup_id(ubus_ctx, service_name, &ubus_id)) {
		struct blob_buf bb = {0};

		*service_schema = (struct blob_buf *)calloc(1, sizeof(struct blob_buf));
		if (*service_schema == NULL) {
			BBFDM_ERR("Failed to allocate memory");
			return;
		}

		blob_buf_init(*service_schema, 0);

		memset(&bb, 0, sizeof(struct blob_buf));
		blob_buf_init(&bb, 0);

		blobmsg_add_string(&bb, "path", BBFDM_ROOT_OBJECT);

		void *table = blobmsg_open_table(&bb, "optional");
		blobmsg_add_string(&bb, "proto", "usp");
		blobmsg_close_table(&bb, table);

		int err = ubus_invoke(ubus_ctx, ubus_id, "schema", bb.head, receive_schema_result, (void *)*service_schema, ubus_timeout);

		if (err != 0) {
			BBFDM_ERR("UBUS invoke failed [object: %s, method: schema] with error (%d)", service_name, err);
		}

		blob_buf_free(&bb);
	} else {
		BBFDM_WARNING("Failed to lookup UBUS object: %s", service_name);
	}
}

static int load_service_from_file(struct ubus_context *ubus_ctx, const char *filename, const char *file_path)
{
	size_t num_objs = 0;

	if (!filename || !file_path) {
		BBFDM_ERR("Invalid filename or file path");
		return -1;
	}

	json_object *json_root = json_object_from_file(file_path);
	if (!json_root) {
		BBFDM_ERR("Failed to read JSON file: %s", file_path);
		return -1;
	}

	json_object *daemon_config = NULL;
	json_object_object_get_ex(json_root, "daemon", &daemon_config);
	if (!daemon_config) {
		BBFDM_ERR("Failed to find daemon object");
		json_object_put(json_root);
		return -1;
	}

	json_object *enable_jobj = NULL;
	json_object_object_get_ex(daemon_config, "enable", &enable_jobj);
	bool enable = enable_jobj ? json_object_get_boolean(enable_jobj) : false;
	if (!enable) {
		BBFDM_INFO("Service is disabled, Skipping service");
		json_object_put(json_root);
		return -1;
	}

	struct blob_buf *service_schema = NULL;
	char service_name[MAX_PATH_LENGTH] = {0};

	snprintf(service_name, sizeof(service_name), "%s.%.*s", BBFDM_UBUS_OBJECT, (int)(strlen(filename) - 5), filename);
	fill_service_schema(ubus_ctx, 2000, service_name, &service_schema);

	json_object *unified_daemon_jobj = NULL;
	json_object_object_get_ex(daemon_config, "unified_daemon", &unified_daemon_jobj);
	bool is_unified = unified_daemon_jobj ? json_object_get_boolean(unified_daemon_jobj) : false;

	json_object *proto_jobj = NULL;
	json_object_object_get_ex(daemon_config, "proto", &proto_jobj);
	int service_proto = get_proto_type(proto_jobj ? json_object_get_string(proto_jobj) : "");

	json_object *timeout_jobj = NULL;
	json_object_object_get_ex(daemon_config, "timeout", &timeout_jobj);
	int service_timeout = timeout_jobj ? json_object_get_int(timeout_jobj) : SERVICE_CALL_TIMEOUT;

	json_object *services_array = NULL;
	if (!json_object_object_get_ex(daemon_config, "services", &services_array) || json_object_get_type(services_array) != json_type_array) {
		json_object_put(json_root);
		return -1;
	}

	size_t service_count = json_object_array_length(services_array);
	if (service_count == 0) {
		BBFDM_WARNING("Skipping service '%s' due to no objects defined", service_name);
		json_object_put(json_root);
		return -1;
	}

	service_object_t *objects = (service_object_t *)calloc(service_count, sizeof(service_object_t));
	if (!objects) {
		BBFDM_ERR("Failed to allocate memory");
		json_object_put(json_root);
		return -1;
	}

	for (size_t i = 0; i < service_count; i++) {
		json_object *service_obj = json_object_array_get_idx(services_array, i);
		json_object *parent_dm = NULL, *object = NULL, *proto = NULL;

		json_object_object_get_ex(service_obj, "parent_dm", &parent_dm);
		json_object_object_get_ex(service_obj, "object", &object);
		json_object_object_get_ex(service_obj, "proto", &proto);

		snprintf(objects[num_objs].parent_path, sizeof(objects[num_objs].parent_path), "%s", parent_dm ? json_object_get_string(parent_dm) : "");
		snprintf(objects[num_objs].object_name, sizeof(objects[num_objs].object_name), "%s", object ? json_object_get_string(object) : "");

		if (strlen(objects[num_objs].parent_path) == 0 || strlen(objects[num_objs].object_name) == 0) {
			BBFDM_WARNING("Skip empty registration parent_dm[%s] or object[%s]", objects[num_objs].parent_path, objects[num_objs].object_name);
			continue;
		}

		objects[num_objs].protocol = get_proto_type(proto ? json_object_get_string(proto) : "");
		num_objs++;
	}

	BBFDM_INFO("Registering [%s :: %lu :: %d]", service_name, num_objs, is_unified);
	add_service_to_list(service_name, service_schema, service_proto, service_timeout, objects, num_objs, is_unified);
	json_object_put(json_root);
	return 0;
}

static int filter(const struct dirent *entry)
{
	return entry->d_name[0] != '.';
}

static int compare(const struct dirent **a, const struct dirent **b)
{
	size_t len_a = strlen((*a)->d_name);
	size_t len_b = strlen((*b)->d_name);

	if (len_a < len_b) // Sort by length (shorter first)
		return -1;

	if (len_a > len_b)
		return 1;

	return strcasecmp((*a)->d_name, (*b)->d_name); // If lengths are equal, sort alphabetically
}

int register_services(struct ubus_context *ubus_ctx)
{
	struct dirent **namelist;

	int num_files = scandir(BBFDM_MICROSERVICE_INPUT_PATH, &namelist, filter, compare);

	for (int i = 0; i < num_files; i++) {
		char file_path[512] = {0};

		snprintf(file_path, sizeof(file_path), "%s/%s", BBFDM_MICROSERVICE_INPUT_PATH, namelist[i]->d_name);

		if (!bbfdm_file_exists(file_path) || !bbfdm_is_regular_file(file_path)) {
			BBFDM_FREE(namelist[i]);
			continue;
		}

		if (load_service_from_file(ubus_ctx, namelist[i]->d_name, file_path)) {
			BBFDM_ERR("Failed to load service: %s", namelist[i]->d_name);
		}

		BBFDM_FREE(namelist[i]);
	}

	BBFDM_FREE(namelist);
	return 0;
}

void unregister_services(void)
{
    service_entry_t *service = NULL, *tmp = NULL;

    list_for_each_entry_safe(service, tmp, &registered_services, list) {
        list_del(&service->list);

        if (service->dm_schema) {
            blob_buf_free(service->dm_schema);
            BBFDM_FREE(service->dm_schema);
        }

        BBFDM_FREE(service->name);
        BBFDM_FREE(service->objects);
        BBFDM_FREE(service);
    }
}

void list_registered_services(struct blob_buf *bb)
{
	service_entry_t *service = NULL;

	if (!bb)
		return;

	void *array = blobmsg_open_array(bb, "registered_services");

	list_for_each_entry(service, &registered_services, list) {
		void *table = blobmsg_open_table(bb, NULL);

		blobmsg_add_string(bb, "name", service->name ? service->name : "");
		blobmsg_add_string(bb, "proto",
			service->protocol == BBFDMD_USP ? "usp" :
			service->protocol == BBFDMD_CWMP ? "cwmp" : "both");

		blobmsg_add_u8(bb, "unified_daemon", service->is_unified);
		blobmsg_add_u8(bb, "blacklisted", service->is_blacklisted);
		blobmsg_add_u32(bb, "timeout", service->timeout);

		void *objects_array = blobmsg_open_array(bb, "objects");
		for (size_t i = 0; i < service->object_count; i++) {
			void *obj_table = blobmsg_open_table(bb, NULL);
			blobmsg_add_string(bb, "parent_dm", service->objects[i].parent_path);
			blobmsg_add_string(bb, "object", service->objects[i].object_name);

			if (service->protocol == BBFDMD_USP) {
				blobmsg_add_string(bb, "proto", "usp");
			} else if (service->protocol == BBFDMD_CWMP) {
				blobmsg_add_string(bb, "proto", "cwmp");
			} else {
				blobmsg_add_string(bb, "proto",
					service->objects[i].protocol == BBFDMD_USP ? "usp" :
					service->objects[i].protocol == BBFDMD_CWMP ? "cwmp" : "both");
			}

			blobmsg_close_table(bb, obj_table);
		}
		blobmsg_close_array(bb, objects_array);

		blobmsg_close_table(bb, table);
	}

	blobmsg_close_array(bb, array);
}

bool service_path_match(const char *requested_path, unsigned int requested_proto, service_entry_t *service)
{
	if (!proto_match(requested_proto, service->protocol))
		return false;

	if (strlen(requested_path) == 0 || strcmp(requested_path, BBFDM_ROOT_OBJECT) == 0)
		return true;

	if (strncmp(BBFDM_ROOT_OBJECT, requested_path, strlen(BBFDM_ROOT_OBJECT)) != 0)
		return false;

	for (size_t idx = 0; idx < service->object_count; idx++) {
		char current_obj[MAX_PATH_LENGTH] = {0};

		if (!proto_match(requested_proto, service->objects[idx].protocol))
			continue;

		snprintf(current_obj, sizeof(current_obj), "%s%s", service->objects[idx].parent_path, service->objects[idx].object_name);

		if (strncmp(current_obj, requested_path, strlen(current_obj)) == 0)
			return true;

		if (strncmp(requested_path, current_obj, strlen(requested_path)) == 0)
			return true;
	}

	return false;
}
