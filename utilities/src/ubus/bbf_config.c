/*
 * bbf_config.c: bbf.config daemon
 *
 * Copyright (C) 2024 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <stdio.h>
#include <unistd.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "utils.h"

#define TIME_TO_WAIT_FOR_RELOAD 5
#define MAX_PACKAGE_NUM 256
#define MAX_SERVICE_NUM 16
#define MAX_INSTANCE_NUM 8
#define NAME_LENGTH 64

#define BBF_CONFIG_DAEMON_NAME "bbf_configd"
#define CONFIG_CONFDIR "/etc/config/"
#define DMMAP_CONFDIR "/etc/bbfdm/dmmap/"

struct proto_args {
	const char *name;
	const char *config_savedir;
	const char *dmmap_savedir;
	unsigned char index;
};

// Structure to represent an instance of a service
struct instance {
	char name[NAME_LENGTH];
	uint32_t pid;
	bool is_running;
};

// Structure to represent a service
struct service {
	char name[NAME_LENGTH];
	bool has_instances;
	struct instance instances[MAX_INSTANCE_NUM];
};

// Structure to represent a configuration package
struct config_package {
	char name[NAME_LENGTH];
	struct service services[MAX_SERVICE_NUM];
};

struct bbf_config_async_req {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_timeout timeout;
	struct blob_attr *services;
	struct config_package package[MAX_PACKAGE_NUM];
};

#ifdef BBF_CONFIG_DEBUG
static void log_instance(struct instance *inst)
{
	ULOG_ERR("    |- Instance name: '%s', PID: %d, Status: %s",
			 inst->name,
			 inst->pid,
			 inst->is_running ? "running" : "stopped");
}

static void log_service(struct service *svc)
{
	ULOG_ERR("  - Service name: '%s'", svc->name);
	if (svc->has_instances) {
		bool has_any_instance = false;
		for (int i_idx = 0; i_idx < MAX_INSTANCE_NUM; i_idx++) {
			if (svc->instances[i_idx].name[0] == '\0')
				break;

			log_instance(&svc->instances[i_idx]);
			has_any_instance = true;
		}
		if (!has_any_instance) {
			ULOG_ERR("    |- No active instances");
		}
	} else {
		ULOG_ERR("    |- No instances available");
	}
}

static void show_package_tree(struct config_package *packages)
{
	for (int p_idx = 0; p_idx < MAX_PACKAGE_NUM; p_idx++) {

		if (packages[p_idx].name[0] == '\0')
			break;

		ULOG_ERR("Package name: '%s'", packages[p_idx].name);
		bool has_any_service = false;
		for (int s_idx = 0; s_idx < MAX_SERVICE_NUM; s_idx++) {
			if (packages[p_idx].services[s_idx].name[0] == '\0')
				break;

			log_service(&packages[p_idx].services[s_idx]);
			has_any_service = true;
		}

		if (!has_any_service) {
			ULOG_ERR("  |- No services defined");
		}
	}
}
#endif

static struct proto_args supported_protocols[] = {
		{
				"both", "/tmp/bbfdm/.bbfdm/config/", "/tmp/bbfdm/.bbfdm/dmmap/", 0
		},
		{
				"cwmp", "/tmp/bbfdm/.cwmp/config/", "/tmp/bbfdm/.cwmp/dmmap/", 1
		},
		{
				"usp", "/tmp/bbfdm/.usp/config/", "/tmp/bbfdm/.usp/dmmap/", 2
		},
};

static bool g_internal_commit = false;

enum {
	SERVICES_NAME,
	SERVICES_PROTO,
	SERVICES_MONITOR,
	SERVICES_RELOAD,
	__MAX
};

static const struct blobmsg_policy bbf_config_policy[] = {
	[SERVICES_NAME] = { .name = "services", .type = BLOBMSG_TYPE_ARRAY },
	[SERVICES_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
	[SERVICES_MONITOR] = { .name = "monitor", .type = BLOBMSG_TYPE_BOOL },
	[SERVICES_RELOAD] = { .name = "reload", .type = BLOBMSG_TYPE_BOOL },
};

static unsigned char get_idx_by_proto(const char *proto)
{
	for (int i = 0; i < ARRAY_SIZE(supported_protocols); i++) {
		if (strcmp(supported_protocols[i].name, proto) == 0)
			return supported_protocols[i].index;
	}

	return 0;
}

static int find_config_idx(struct config_package *package, const char *config_name)
{
	if (!config_name)
		return -1;

	for (int i = 0; i < MAX_PACKAGE_NUM; i++) {

		if (strlen(package[i].name) == 0)
			return -1;

		if (strcmp(package[i].name, config_name) == 0)
			return i;
	}

	return -1;
}

static int find_service_idx(struct service *services)
{
	if (!services)
		return -1;

	for (int i = 0; i < MAX_SERVICE_NUM; i++) {

		if (strlen(services[i].name) == 0)
			return i;
	}

	return -1;
}

static int find_instance_idx(struct instance *instances, const char *instance_name)
{
	if (!instances)
		return -1;

	for (int i = 0; i < MAX_INSTANCE_NUM; i++) {

		if (instance_name && strcmp(instances[i].name, instance_name) == 0)
			return i;

		if (strlen(instances[i].name) == 0)
			return i;
	}

	return -1;
}

static int handle_instances_service(const char *service_name, struct blob_attr *instances, struct config_package *package, unsigned int pkg_idx)
{
	int srv_idx = find_service_idx(package[pkg_idx].services);

	if (srv_idx < 0) { // Returns if the number of services more than MAX_SERVICE_NUM
		ULOG_ERR("Failed to handle instance service: service count exceeds MAX_SERVICE_NUM");
		return -1;
	}

	strncpyt(package[pkg_idx].services[srv_idx].name, service_name, NAME_LENGTH);
	package[pkg_idx].services[srv_idx].has_instances = (instances) ? true : false;

	if (!instances)
		return -1;

	struct blob_attr *cur;
	int rem;

	int inst_idx = find_instance_idx(package[pkg_idx].services[srv_idx].instances, NULL);

	if (inst_idx < 0) // Returns if the number of instances more than MAX_INSTANCE_NUM
		return -1;

	blobmsg_for_each_attr(cur, instances, rem) {

		struct blob_attr *tb[2] = {0};
		const struct blobmsg_policy p[2] = {
				{ "running", BLOBMSG_TYPE_BOOL },
				{ "pid", BLOBMSG_TYPE_INT32 }
		};

		blobmsg_parse(p, 2, tb, blobmsg_data(cur), blobmsg_len(cur));

		strncpyt(package[pkg_idx].services[srv_idx].instances[inst_idx].name, blobmsg_name(cur), NAME_LENGTH);
		package[pkg_idx].services[srv_idx].instances[inst_idx].is_running = (tb[0]) ? blobmsg_get_bool(tb[0]) : false;
		package[pkg_idx].services[srv_idx].instances[inst_idx].pid = (tb[1]) ? blobmsg_get_u32(tb[1]) : 0;
		inst_idx++;
	}


	return 0;
}

static int handle_triggers_service(const char *service_name, struct blob_attr *triggers, struct blob_attr *instances, struct config_package *package, unsigned int *index)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, triggers, rem) {
		struct blob_attr *_cur, *type = NULL, *script = NULL, *config = NULL, *name = NULL;
		size_t _rem;
		int i = 0;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY)
			continue;

		blobmsg_for_each_attr(_cur, cur, _rem) {
			switch (i++) {
			case 0:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_STRING)
					type = _cur;
				break;

			case 1:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_ARRAY)
					script = _cur;
				break;
			}
		}

		if (!type || !script || strcmp(blobmsg_get_string(type), "config.change") != 0)
			continue;

		type = NULL;
		i = 0;

		blobmsg_for_each_attr(_cur, script, _rem) {
			switch (i++) {
			case 0:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_STRING)
					type = _cur;
				break;

			case 1:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_ARRAY)
					config = _cur;
				break;
			}
		}

		if (!type || !config || strcmp(blobmsg_get_string(type), "if") != 0)
			continue;

		type = NULL;
		script = NULL;
		i = 0;

		blobmsg_for_each_attr(_cur, config, _rem) {
			switch (i++) {
			case 0:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_STRING)
					type = _cur;
				break;

			case 1:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_STRING)
					script = _cur;
				break;

			case 2:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_STRING)
					name = _cur;
				break;
			}
		}

		if (!type || !script || !name ||
				strcmp(blobmsg_get_string(type), "eq") != 0 ||
				strcmp(blobmsg_get_string(script), "package") != 0)
			continue;

		char *config_name = blobmsg_get_string(name);

		int config_idx = find_config_idx(package, config_name);

		unsigned int pkg_idx = (config_idx < 0) ? (*index)++ : config_idx;

		strncpyt(package[pkg_idx].name, blobmsg_get_string(name), NAME_LENGTH);

		handle_instances_service(service_name, instances, package, pkg_idx);
	}

	return 0;
}

static void _get_service_list_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur;
	struct blob_attr *tb[2] = {0};
	const struct blobmsg_policy p[2] = {
			{ "triggers", BLOBMSG_TYPE_ARRAY },
			{ "instances", BLOBMSG_TYPE_TABLE }
	};
	size_t rem;
	unsigned int idx = 0;

	if (!msg || !req) {
		ULOG_ERR("Cannot proceed: 'msg' or 'req' is NULL.");
		return;
	}

	struct config_package *package = (struct config_package *)req->priv;

	blobmsg_for_each_attr(cur, msg, rem) {

		blobmsg_parse(p, 2, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[0])
			continue;

		handle_triggers_service(blobmsg_name(cur), tb[0], tb[1], package, &idx);
	}
}

static void _get_specific_service_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur;
	struct blob_attr *tb[1] = {0};
	const struct blobmsg_policy p[1] = {
			{ "instances", BLOBMSG_TYPE_TABLE }
	};
	size_t rem;

	if (!msg || !req) {
		ULOG_ERR("Cannot proceed: 'msg' or 'req' is NULL.");
		return;
	}

	struct config_package *package = (struct config_package *)req->priv;

	blobmsg_for_each_attr(cur, msg, rem) {

		blobmsg_parse(p, 1, tb, blobmsg_data(cur), blobmsg_len(cur));

		handle_instances_service(blobmsg_name(cur), tb[0], package, 0);
	}
}

static void fill_service_info(struct ubus_context *ctx, struct config_package *package, const char *name, bool verbose, ubus_data_handler_t callback)
{
	struct blob_buf ubus_bb = {0};

	memset(&ubus_bb, 0 , sizeof(struct blob_buf));
	blob_buf_init(&ubus_bb, 0);

	if (name) blobmsg_add_string(&ubus_bb, "name", name);

	blobmsg_add_u8(&ubus_bb, "verbose", verbose);

	bbf_config_call(ctx, "service", "list", &ubus_bb, callback, (void *)package);

	blob_buf_free(&ubus_bb);
}

static bool validate_required_services(struct ubus_context *ctx, struct config_package *package, struct blob_attr *services)
{
	struct blob_attr *service = NULL;
	size_t rem = 0;

	if (!services || !package)
		return true;

	// Iterate through each service attribute
	blobmsg_for_each_attr(service, services, rem) {
		char *config_name = blobmsg_get_string(service);

		// Find the index of the configuration package
		int idx = find_config_idx(package, config_name);
		if (idx < 0)
			continue;

		for (int j = 0; j < MAX_SERVICE_NUM && strlen(package[idx].services[j].name); j++) {

			if (strcmp(package[idx].services[j].name, BBF_CONFIG_DAEMON_NAME) == 0) {
				// Skip 'bbf_configd' service itself, as it does not need processing here
				continue; // Move to the next service
			}

			// Get configuration information for each service name
			struct config_package new_package[1] = {0};

			memset(new_package, 0, sizeof(struct config_package));

			fill_service_info(ctx, new_package, package[idx].services[j].name, false, _get_specific_service_cb);

			if (package[idx].services[j].has_instances != new_package[0].services[0].has_instances) {
				// If the number of instances has changed, the service is correctly updated
				continue; // Move to the next service
			}

			if (package[idx].services[j].has_instances == 0) {
				// No instances to check, unsure if service is correctly updated
				goto wait;
			}

			for (int t = 0; t < MAX_SERVICE_NUM && strlen(package[idx].services[j].instances[t].name); t++) {

				// Find the index of the instance in the new package
				int inst_idx = find_instance_idx(new_package[0].services[0].instances,
						package[idx].services[j].instances[t].name);

				if (inst_idx < 0) {
					// Instance doesn't exist after reload, indicating a disabled instance
					continue; // Move to the next service
				}

				if (package[idx].services[j].instances[t].is_running != new_package[0].services[0].instances[inst_idx].is_running) {
					// Instance status changed after reload, service correctly updated
					continue; // Move to the next service
				}

				if (package[idx].services[j].instances[t].pid != new_package[0].services[0].instances[inst_idx].pid) {
					// Instance PID changed after reload, service correctly updated
					continue; // Move to the next service
				}

				// Wait for a sufficient time to ensure services are reloaded
				goto wait;
			}
		}
	}

	return true;

wait:
	return false;
}

static void send_bbf_config_change_event()
{
	struct ubus_context *ctx;
	struct blob_buf bb = {0};

	ctx = ubus_connect(NULL);
	if (ctx == NULL) {
		ULOG_ERR("Can't create UBUS context for 'bbf.config.change' event");
		return;
	}

	ULOG_INFO("Sending bbf.config.change event");

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);
	ubus_send_event(ctx, "bbf.config.change", bb.head);
	blob_buf_free(&bb);
	ubus_free(ctx);
}

static void send_reply(struct ubus_context *ctx, struct ubus_request_data *req, const char *message, const char *description)
{
	struct blob_buf bb = {0};

	memset(&bb, 0, sizeof(struct blob_buf));

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, message, description);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);
}

static void complete_deferred_request(struct bbf_config_async_req *async_req)
{
	if (!async_req)
		return;

	// Send the response
	send_reply(async_req->ctx, &async_req->req, "status", "ok");

	// Complete the deferred request and send the response
	ubus_complete_deferred_request(async_req->ctx, &async_req->req, 0);

	// Free the allocated memory
	FREE(async_req->services);
	FREE(async_req);

	// Send 'bbf.config.change' event to run refresh instances
	send_bbf_config_change_event();

	// Set internal commit to false
	g_internal_commit = false;

	ULOG_INFO("Commit handler exit");
}

static void end_request_callback(struct uloop_timeout *t)
{
	struct bbf_config_async_req *async_req = container_of(t, struct bbf_config_async_req, timeout);

	// Complete the deferred request and send the reply
	complete_deferred_request(async_req);
}

static void complete_request_callback(struct uloop_timeout *t)
{
	struct bbf_config_async_req *async_req = container_of(t, struct bbf_config_async_req, timeout);

	// Check if the required services are really reloaded
	bool reload_done = validate_required_services(async_req->ctx, async_req->package, async_req->services);

	if (reload_done) {
		// Complete the deferred request and send the reply
		complete_deferred_request(async_req);
	} else {
		async_req->timeout.cb = end_request_callback;
		uloop_timeout_set(&async_req->timeout, TIME_TO_WAIT_FOR_RELOAD * 1000);
	}
}

static int bbf_config_commit_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__MAX];
	bool monitor = true, reload = true;
	unsigned char idx = 0;

	ULOG_INFO("Commit handler called");

	if (blobmsg_parse(bbf_config_policy, __MAX, tb, blob_data(msg), blob_len(msg))) {
		send_reply(ctx, req, "error", "Failed to parse blob");
		return -1;
	}

	struct bbf_config_async_req *async_req = calloc(1, sizeof(struct bbf_config_async_req));
	if (!async_req) {
		send_reply(ctx, req, "error", "Failed to allocate bbf config async request");
		return -1;
	}

	// Set internal commit to true
	g_internal_commit = true;

	async_req->ctx = ctx;

	memset(async_req->package, 0, sizeof(struct config_package) * MAX_PACKAGE_NUM);

	if (tb[SERVICES_PROTO]) {
		char *proto = blobmsg_get_string(tb[SERVICES_PROTO]);
		idx = get_idx_by_proto(proto);
		ULOG_DEBUG("Protocol index determined as %d for protocol '%s'", idx, proto);
	}

	if (tb[SERVICES_MONITOR]) {
		monitor = blobmsg_get_bool(tb[SERVICES_MONITOR]);
		ULOG_DEBUG("Monitor flag set to %s.", monitor ? "true" : "false");
	}

	if (tb[SERVICES_RELOAD]) {
		reload = blobmsg_get_bool(tb[SERVICES_RELOAD]);
		ULOG_DEBUG("Reload flag set to %s.", reload ? "true" : "false");
	}

	if (monitor) {
		ULOG_DEBUG("Retrieving all config information before committing changes");
		fill_service_info(ctx, async_req->package, NULL, true, _get_service_list_cb);
#ifdef BBF_CONFIG_DEBUG
		show_package_tree(async_req->package);
#endif
	}

	if (reload) {
		ULOG_INFO("Applying changes to dmmap UCI config");
		uci_apply_changes(DMMAP_CONFDIR, supported_protocols[idx].dmmap_savedir, true);
	}

	struct blob_attr *services = tb[SERVICES_NAME];

	size_t arr_len = (services) ? blobmsg_len(services) : 0;

	if (arr_len) {
		size_t blob_data_len = blob_raw_len(services);
		if (blob_data_len) {
			async_req->services = (struct blob_attr *)calloc(1, blob_data_len);
			if (!async_req->services) {
				ULOG_ERR("Failed to allocate memory for services blob data.");
				FREE(async_req);
				send_reply(ctx, req, "error", "Memory allocation error");
				g_internal_commit = false;
				return -1;
			}

			memcpy(async_req->services, services, blob_data_len);
		}

		ULOG_INFO("Committing changes for specified services and reloading");
		reload_specified_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, async_req->services, true, reload);
	} else {
		ULOG_INFO("Committing changes for all services and reloading");
		reload_all_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, true, reload);
	}

	if (monitor) {
		ULOG_INFO("Deferring request and setting up async completion");
		ubus_defer_request(ctx, req, &async_req->req);
		async_req->timeout.cb = complete_request_callback;
		uloop_timeout_set(&async_req->timeout, 2000);
	} else {
		ULOG_INFO("Sending immediate success response");
		send_reply(ctx, req, "status", "ok");

		// Free the allocated memory
		FREE(async_req->services);
		FREE(async_req);

		// Send 'bbf.config.change' event to run refresh instances
		send_bbf_config_change_event();

		// Set internal commit to false
		g_internal_commit = false;

		ULOG_INFO("Commit handler exit");
	}

	return 0;
}

static int bbf_config_revert_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__MAX];
	unsigned char idx = 0;

	ULOG_INFO("Revert handler called");

	if (blobmsg_parse(bbf_config_policy, __MAX, tb, blob_data(msg), blob_len(msg))) {
		send_reply(ctx, req, "error", "Failed to parse blob");
		return -1;
	}

	if (tb[SERVICES_PROTO]) {
		char *proto = blobmsg_get_string(tb[SERVICES_PROTO]);
		idx = get_idx_by_proto(proto);
		ULOG_DEBUG("Protocol index determined as %d for protocol '%s'", idx, proto);
	}

	struct blob_attr *services = tb[SERVICES_NAME];

	size_t arr_len = (services) ? blobmsg_len(services) : 0;

	if (arr_len) {
		ULOG_INFO("Reverting specified services");
		reload_specified_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, services, false, false);
	} else {
		ULOG_INFO("Reverting all services");
		reload_all_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, false, false);
	}

	ULOG_INFO("Applying changes to revert all UCI dmmap configurations");
	uci_apply_changes(DMMAP_CONFDIR, supported_protocols[idx].dmmap_savedir, false);

	ULOG_INFO("Sending success response");
	send_reply(ctx, req, "status", "ok");

	// Send 'bbf.config.change' event to run refresh instances
	send_bbf_config_change_event();

	ULOG_INFO("revert handler exit");

	return 0;
}

static int bbf_config_changes_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__MAX];
	struct blob_buf bb = {0};
	unsigned char idx = 0;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	if (blobmsg_parse(bbf_config_policy, __MAX, tb, blob_data(msg), blob_len(msg))) {
		blobmsg_add_string(&bb, "error", "Failed to parse blob");
		goto end;
	}

	if (tb[SERVICES_PROTO]) {
		char *proto = blobmsg_get_string(tb[SERVICES_PROTO]);
		idx = get_idx_by_proto(proto);
	}

	void *array = blobmsg_open_array(&bb, "configs");

	uci_config_changes(CONFIG_CONFDIR, supported_protocols[idx].config_savedir, &bb);

	blobmsg_close_array(&bb, array);

end:
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return 0;
}

static void receive_notify_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	// Skip sending 'bbf.config.change' event if triggered by an internal commit
	if (g_internal_commit) {
		ULOG_DEBUG("Event triggered by internal commit; skipping 'bbf.config.change' event transmission");
		return;
	}

	// Trigger 'bbf.config.change' event to refresh instances as required
	send_bbf_config_change_event();
}

static const struct ubus_method bbf_config_methods[] = {
	UBUS_METHOD("commit", bbf_config_commit_handler, bbf_config_policy),
	UBUS_METHOD("revert", bbf_config_revert_handler, bbf_config_policy),
	UBUS_METHOD("changes", bbf_config_changes_handler, bbf_config_policy),
};

static struct ubus_object_type bbf_config_object_type = UBUS_OBJECT_TYPE("bbf.config", bbf_config_methods);

static struct ubus_object bbf_config_object = {
	.name = "bbf.config",
	.type = &bbf_config_object_type,
	.methods = bbf_config_methods,
	.n_methods = ARRAY_SIZE(bbf_config_methods),
};

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -d  Use multiple time to get more verbose debug logs (Debug: -dddd)\n");
	fprintf(stderr, "    -h  Displays this help\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct ubus_event_handler ev = {
		.cb = receive_notify_event,
	};
	struct ubus_context *uctx;
	int ch, log_level = 0;

	while ((ch = getopt(argc, argv, "hd")) != -1) {
		switch (ch) {
		case 'd':
			log_level += 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	ulog_open(ULOG_SYSLOG, LOG_DAEMON, "bbf.config");
	ulog_threshold(LOG_ERR + log_level);

	uctx = ubus_connect(NULL);
	if (uctx == NULL) {
		ULOG_ERR("Failed to create UBUS context");
		return -1;
	}

	uloop_init();
	ubus_add_uloop(uctx);

	if (ubus_add_object(uctx, &bbf_config_object)) {
		ULOG_ERR("Failed to add 'bbf.config' ubus object");
		goto exit;
	}

	if (ubus_register_event_handler(uctx, &ev, "bbf.config.notify")) {
		ULOG_ERR("Failed to register 'bbf.config.notify' event handler");
		goto exit;
	}

	uloop_run();

exit:
	uloop_done();
	ubus_free(uctx);
	ulog_close();

	return 0;
}
