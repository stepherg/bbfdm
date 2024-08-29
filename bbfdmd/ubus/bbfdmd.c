/*
 * bbfdmd.c: BBFDMD deamon
 *
 * Copyright (C) 2023-2024 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <sys/prctl.h>

#include "common.h"
#include "bbfdm-ubus.h"
#include "cli.h"

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -s <socket path>    ubus socket\n");
	fprintf(stderr, "    -m <json path>      json input configuration for micro services\n");
	fprintf(stderr, "    -c <command input>  Run cli command\n");
	fprintf(stderr, "    -h                 Displays this help\n");
	fprintf(stderr, "\n");
}

static int parse_input_cli_options(bbfdm_config_t *config, json_object *json_obj)
{
	char *opt_val = NULL;

	if (!config || !json_obj) {
		fprintf(stderr, "Invalid input options \n");
		return -1;
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "config", "proto");
	if (DM_STRLEN(opt_val)) {
		config->proto = get_proto_type(opt_val);
	} else {
		config->proto = BBFDM_BOTH;
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "input", "type");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_in_type, sizeof(config->cli_in_type), "%s", opt_val);
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "input", "name");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_in_name, sizeof(config->cli_in_name), "%s", opt_val);
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "input", "plugin_dir");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_in_plugin_dir, sizeof(config->cli_in_plugin_dir), "%s", opt_val);
	}

	opt_val = dmjson_get_value(json_obj, 3, "cli", "output", "type");
	if (DM_STRLEN(opt_val)) {
		snprintf(config->cli_out_type, sizeof(config->cli_out_type), "%s", opt_val);
	}
	return 0;
}

static int load_cli_config(bbfdm_config_t *config)
{
	json_object *json_obj = NULL;

	json_obj = json_object_from_file(BBFDM_JSON_INPUT);
	if (!json_obj) {
		fprintf(stderr, "Failed to read input %s file \n", BBFDM_JSON_INPUT);
		return -1;
	}

	parse_input_cli_options(config, json_obj);

	json_object_put(json_obj);
	return 0;
}

int main(int argc, char **argv)
{
	struct bbfdm_context bbfdm_ctx = {0};
	char *cli_argv[4] = {0};
	int err = 0, ch, cli_argc = 0, i;

	memset(&bbfdm_ctx, 0, sizeof(struct bbfdm_context));

	while ((ch = getopt(argc, argv, "hs:m:c:")) != -1) {
		switch (ch) {
		case 'm':
			bbfdm_ubus_set_service_name(&bbfdm_ctx, optarg);
			break;
		case 'c':
			cli_argc = argc-optind+1;
			for (i = 0; i < cli_argc; i++) {
				cli_argv[i] = argv[optind - 1 + i];
			}
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			break;
		}
	}

	if (cli_argc) {
		if (dm_is_micro_service() == true) {
			fprintf(stderr, "Failed to run cli with micro-service\n");
			return -1;
		}

		err = load_cli_config(&bbfdm_ctx.config);
		if (err) {
			fprintf(stderr, "Failed to load cli config from json file (%s)\n", BBFDM_JSON_INPUT);
			return err;
		}

		return bbfdm_cli_exec_command(&bbfdm_ctx.config, cli_argc, cli_argv);
	}

	openlog("bbfdm", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	err = bbfdm_ubus_regiter_init(&bbfdm_ctx);
	if (err != 0)
		goto exit;

	if (dm_is_micro_service() == true) {
		char proc_name[32] = {0};

		// Create process name using service name and prefix "dm_"
		snprintf(proc_name, sizeof(proc_name), "dm_%s", bbfdm_ctx.config.service_name);

		// Set process name for the current process
		prctl(PR_SET_NAME, proc_name, NULL, NULL, NULL);
	}

	BBF_INFO("Waiting on uloop....");
	uloop_run();

exit:
	bbfdm_ubus_regiter_free(&bbfdm_ctx);
	closelog();

	return err;
}
