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
#include <syslog.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "utils.h"

#define TIME_TO_WAIT_FOR_RELOAD 5
#define MAX_PACKAGE_NUM 256
#define MAX_SERVICE_NUM 8
#define MAX_INSTANCE_NUM 32
#define NAME_LENGTH 64

#define CONFIG_CONFDIR "/etc/config/"
#define DMMAP_CONFDIR "/etc/bbfdm/dmmap/"

uint8_t g_log_level = 1;

#define PRINT_ERR(fmt, args...) \
	print_err(fmt, ##args)

#define PRINT_INFO(fmt, args...) \
	print_info(fmt, ##args)


struct proto_args {
	const char *name;
	const char *config_savedir;
	const char *dmmap_savedir;
	unsigned char index;
};

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

void print_info(const char *format, ...)
{
	va_list arglist;

	if (g_log_level > 1) {
		va_start(arglist, format);
		vsyslog(LOG_INFO, format, arglist);
		va_end(arglist);
	}
}

void print_err(const char *format, ...)
{
	va_list arglist;

	va_start(arglist, format);
	vsyslog(LOG_ERR, format, arglist);
	va_end(arglist);
}

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

	if (srv_idx < 0) // Returns if the number of services more than MAX_SERVICE_NUM
		return -1;

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
		package[pkg_idx].services[srv_idx].instances[inst_idx].pid = (tb[1]) ? blobmsg_get_u32(tb[1]) : false;
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

	if (!msg || !req)
		return;

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

	if (!msg || !req)
		return;

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

static void validate_required_services(struct ubus_context *ctx, struct config_package *package, struct blob_attr *services)
{
	struct blob_attr *service = NULL;
	size_t rem = 0;

	// Iterate through each service attribute
	blobmsg_for_each_attr(service, services, rem) {
		char *config_name = blobmsg_get_string(service);

		// Find the index of the configuration package
		int idx = find_config_idx(package, config_name);
		if (idx < 0)
			continue;

		for (int j = 0; j < MAX_SERVICE_NUM && strlen(package[idx].services[j].name); j++) {

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

	return;

wait:
	// Wait to reload all required services
	sleep(TIME_TO_WAIT_FOR_RELOAD);
}

static void send_bbf_config_change_event()
{
	struct ubus_context *ctx;
	struct blob_buf bb = {0};

	ctx = ubus_connect(NULL);
	if (ctx == NULL) {
		PRINT_ERR("Can't create UBUS context for event");
		return;
	}

	PRINT_INFO("Sending bbf.config.change event");

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);
	ubus_send_event(ctx, "bbf.config.change", bb.head);
	blob_buf_free(&bb);
	ubus_free(ctx);
}

static int bbf_config_commit_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__MAX];
	struct blob_buf bb = {0};
	struct config_package package[MAX_PACKAGE_NUM];
	unsigned char idx = 0;
	bool monitor = true, reload = true;

	PRINT_INFO("Commit handler called");
	memset(package, 0, sizeof(struct config_package) * MAX_PACKAGE_NUM);

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

	if (tb[SERVICES_MONITOR])
		monitor = blobmsg_get_bool(tb[SERVICES_MONITOR]);

	if (tb[SERVICES_RELOAD])
		reload = blobmsg_get_bool(tb[SERVICES_RELOAD]);

	if (monitor) {
		// Get all configs information before calling ubus call uci commit
		fill_service_info(ctx, package, NULL, true, _get_service_list_cb);
	}

	if (reload) {
		// Commit all uci dmmap changes
		uci_apply_changes(DMMAP_CONFDIR, supported_protocols[idx].dmmap_savedir, true);
	}

	struct blob_attr *services = tb[SERVICES_NAME];

	size_t arr_len = (services) ? blobmsg_len(services) : 0;

	if (arr_len) {
		// Commit uci config changes for the required configs and reload services
		reload_specified_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, services, true, reload);
	} else {
		// Commit uci config changes for all configs and reload services
		reload_all_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, true, reload);
	}

	if (monitor) {
		// Wait at least 2 seconds to reload the services
		sleep(2);

		// Check if the required services are really reloaded
		validate_required_services(ctx, package, services);
	}

	blobmsg_add_string(&bb, "status", "ok");

end:
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	// Send 'bbf.config.change' event to run refresh instances
	send_bbf_config_change_event();
	PRINT_INFO("Commit handler exit");

	return 0;
}

static int bbf_config_revert_handler(struct ubus_context *ctx, struct ubus_object *obj __attribute__((unused)),
		    struct ubus_request_data *req, const char *method __attribute__((unused)),
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__MAX];
	struct blob_buf bb = {0};
	unsigned char idx = 0;

	memset(&bb, 0, sizeof(struct blob_buf));
	blob_buf_init(&bb, 0);

	PRINT_INFO("Revert handler called");
	if (blobmsg_parse(bbf_config_policy, __MAX, tb, blob_data(msg), blob_len(msg))) {
		blobmsg_add_string(&bb, "error", "Failed to parse blob");
		goto end;
	}

	if (tb[SERVICES_PROTO]) {
		char *proto = blobmsg_get_string(tb[SERVICES_PROTO]);
		idx = get_idx_by_proto(proto);
	}

	struct blob_attr *services = tb[SERVICES_NAME];

	size_t arr_len = (services) ? blobmsg_len(services) : 0;

	if (arr_len) {
		// Revert uci config changes for the required configs and reload services
		reload_specified_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, services, false, false);
	} else {
		// Revert uci config changes for all configs and reload services
		reload_all_services(ctx, CONFIG_CONFDIR, supported_protocols[idx].config_savedir, false, false);
	}

	// Revert all uci dmmap changes
	uci_apply_changes(DMMAP_CONFDIR, supported_protocols[idx].dmmap_savedir, false);

	blobmsg_add_string(&bb, "status", "ok");

end:
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	// Send 'bbf.config.change' event to run refresh instances
	send_bbf_config_change_event();
	PRINT_INFO("revert handler exit");

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
	fprintf(stderr, "    -d    Use multiple time to get more verbose debug logs\n");
	fprintf(stderr, "    -h    Displays this help\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct ubus_context *uctx;
	int ch;

	openlog("bbf.config", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	uctx = ubus_connect(NULL);
	if (uctx == NULL) {
		PRINT_ERR("Failed to get UBUS context");
		return -1;
	}

	while ((ch = getopt(argc, argv, "hd")) != -1) {
		switch (ch) {
		case 'd':
			g_log_level += 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	uloop_init();
	ubus_add_uloop(uctx);

	if (ubus_add_object(uctx, &bbf_config_object))
		goto exit;

	uloop_run();

exit:
	uloop_done();
	ubus_free(uctx);
	closelog();

	return 0;
}
