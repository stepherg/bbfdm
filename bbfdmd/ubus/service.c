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

static void add_service_to_list(const char *name, int service_proto, service_object_t *objects, size_t count, bool is_unified)
{
	service_entry_t *service = NULL;

	if (!name || !objects || count == 0) {
		BBFDM_ERR("Invalid service registration parameters");
		return;
	}

	service = calloc(1, sizeof(service_entry_t));
	list_add_tail(&service->list, &registered_services);

	service->name = strdup(name);
	service->protocol = service_proto;
	service->objects = objects;
	service->object_count = count;
	service->is_unified = is_unified;
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

	char service_name[MAX_PATH_LENGTH] = {0};
	snprintf(service_name, sizeof(service_name), "%s.%.*s", BBFDM_UBUS_OBJECT, (int)(strlen(filename) - 5), filename);

	uint32_t ubus_id;
	if (ubus_lookup_id(ubus_ctx, service_name, &ubus_id)) {
		BBFDM_ERR("Failed to lookup UBUS object: %s", service_name);
	}

	json_object *unified_daemon_jobj = NULL;
	json_object_object_get_ex(daemon_config, "unified_daemon", &unified_daemon_jobj);
	bool is_unified = unified_daemon_jobj ? json_object_get_boolean(unified_daemon_jobj) : false;

	json_object *proto_jobj = NULL;
	json_object_object_get_ex(daemon_config, "proto", &proto_jobj);
	int service_proto = get_proto_type(proto_jobj ? json_object_get_string(proto_jobj) : "");

	json_object *services_array = NULL;
	if (!json_object_object_get_ex(daemon_config, "services", &services_array) || json_object_get_type(services_array) != json_type_array) {
		json_object_put(json_root);
		return -1;
	}

	size_t service_count = json_object_array_length(services_array);
	if (service_count == 0) {
		BBFDM_ERR("Skipping service '%s' due to no objects defined", service_name);
		json_object_put(json_root);
		return -1;
	}

	service_object_t *objects = calloc(service_count, sizeof(service_object_t));

	for (size_t i = 0; i < service_count; i++) {
		json_object *service_obj = json_object_array_get_idx(services_array, i);
		json_object *parent_dm = NULL, *object = NULL, *proto = NULL;

		json_object_object_get_ex(service_obj, "parent_dm", &parent_dm);
		json_object_object_get_ex(service_obj, "object", &object);
		json_object_object_get_ex(service_obj, "proto", &proto);

		snprintf(objects[num_objs].parent_path, sizeof(objects[num_objs].parent_path), "%s", parent_dm ? json_object_get_string(parent_dm) : "");
		snprintf(objects[num_objs].object_name, sizeof(objects[num_objs].object_name), "%s", object ? json_object_get_string(object) : "");

		if (strlen(objects[num_objs].parent_path) == 0 || strlen(objects[num_objs].object_name) == 0) {
			BBFDM_ERR("Skip empty registration parent_dm[%s] or object[%s]", objects[num_objs].parent_path, objects[num_objs].object_name);
			continue;
		}

		objects[num_objs].protocol = get_proto_type(proto ? json_object_get_string(proto) : "");
		num_objs++;
	}

	BBFDM_INFO("Registering [%s :: %lu :: %d]", service_name, num_objs, is_unified);
	add_service_to_list(service_name, service_proto, objects, num_objs, is_unified);
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
		blobmsg_add_string(bb, "proto", service->protocol == BBFDMD_USP ? "usp" : service->protocol == BBFDMD_CWMP ? "cwmp" : "both");
		blobmsg_add_u8(bb, "unified_daemon", service->is_unified);
		void *objects_array = blobmsg_open_array(bb, "objects");
		for (size_t i = 0; i < service->object_count; i++) {
			void *obj_table = blobmsg_open_table(bb, NULL);
			blobmsg_add_string(bb, "parent_dm", service->objects[i].parent_path);
			blobmsg_add_string(bb, "object", service->objects[i].object_name);
			blobmsg_add_string(bb, "proto", service->objects[i].protocol == BBFDMD_USP ? "usp" : service->objects[i].protocol == BBFDMD_CWMP ? "cwmp" : "both");
			blobmsg_close_table(bb, obj_table);
		}
		blobmsg_close_array(bb, objects_array);
		blobmsg_close_table(bb, table);
	}

	blobmsg_close_array(bb, array);
}

bool is_path_match(const char *requested_path, unsigned int requested_proto, service_entry_t *service)
{
	if (!proto_matches(requested_proto, service->protocol))
		return false;

	if (strlen(requested_path) == 0 || strcmp(requested_path, BBFDM_ROOT_OBJECT) == 0)
		return true;

	if (strncmp(BBFDM_ROOT_OBJECT, requested_path, strlen(BBFDM_ROOT_OBJECT)) != 0)
		return false;

	for (size_t idx = 0; idx < service->object_count; idx++) {
		char current_obj[MAX_PATH_LENGTH] = {0};

		if (!proto_matches(requested_proto, service->objects[idx].protocol))
			continue;

		snprintf(current_obj, sizeof(current_obj), "%s%s", service->objects[idx].parent_path, service->objects[idx].object_name);

		if (strncmp(current_obj, requested_path, strlen(current_obj)) == 0)
			return true;

		if (strncmp(requested_path, current_obj, strlen(requested_path)) == 0)
			return true;
	}

	return false;
}

static char *get_ubus_object_name(const char *path)
{
	service_entry_t *service = NULL;

	list_for_each_entry(service, &registered_services, list) {

		if (!is_path_match(path, BBFDMD_BOTH, service))
			continue;

		return service->name;
	}

	return NULL;
}

static void reference_data_callback(struct ubus_request *req, int type __attribute__((unused)), struct blob_attr *msg)
{
	struct blob_attr *fields[1];
	const struct blobmsg_policy policy[1] = {
		{ "data", BLOBMSG_TYPE_STRING },
	};

	if (!req || !msg)
		return;

	char *reference_data = (char *)req->priv;

	if (!reference_data)
		return;

	blobmsg_parse(policy, 1, fields, blobmsg_data(msg), blobmsg_len(msg));

	if (fields[0]) {
		snprintf(reference_data, MAX_PATH_LENGTH - 1, "%s", blobmsg_get_string(fields[0]));
		BBFDM_DEBUG("reference_data '%s'", reference_data);
	}
}

char *get_reference_data(const char *path, const char *method_name)
{
	struct blob_buf req_buf = {0};
	char reference_value[MAX_PATH_LENGTH] = {0};

	if (!path)
		return NULL;

	char *ubus_obj = get_ubus_object_name(path);
	if (!ubus_obj)
		return NULL;

	reference_value[0] = 0;

	memset(&req_buf, 0, sizeof(struct blob_buf));
	blob_buf_init(&req_buf, 0);

	blobmsg_add_string(&req_buf, "path", path);

	BBFDM_DEBUG("### ubus call %s %s '%s' ###", ubus_obj, method_name, blobmsg_format_json_indent(req_buf.head, true, -1));

	BBFDM_UBUS_INVOKE_SYNC(ubus_obj, method_name, req_buf.head, 2000, reference_data_callback, &reference_value);

	blob_buf_free(&req_buf);

	return (reference_value[0] != 0) ? strdup(reference_value) : NULL;
}
