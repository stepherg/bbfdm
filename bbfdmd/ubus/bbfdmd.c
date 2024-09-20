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

#include "../../libbbfdm/device.h"

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -c <command input>  Run cli command\n");
	fprintf(stderr, "    -l <loglevel>       log verbosity value as per standard syslog\n");
	fprintf(stderr, "    -h                  Displays this help\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct bbfdm_context bbfdm_ctx = {0};
	char *cli_argv[4] = {0};
	int log_level = 3; // Default is LOG_ERR
	int err = 0, ch, cli_argc = 0, i;

	memset(&bbfdm_ctx, 0, sizeof(struct bbfdm_context));

	while ((ch = getopt(argc, argv, "hc:l:")) != -1) {
		switch (ch) {
		case 'c':
			cli_argc = argc-optind+1;
			for (i = 0; i < cli_argc; i++) {
				cli_argv[i] = argv[optind - 1 + i];
			}
			break;
		case 'l':
			if (optarg) {
				log_level = (int)strtod(optarg, NULL);
				if (log_level < 0 || log_level > 7)
					log_level = 3;
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
		return bbfdm_cli_exec_command(cli_argc, cli_argv);
	}

	bbfdm_ubus_set_log_level(log_level);
	bbfdm_ubus_load_data_model(tDynamicObj);

	openlog(BBFDM_DEFAULT_UBUS_OBJ, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	err = bbfdm_ubus_regiter_init(&bbfdm_ctx);
	if (err != 0)
		goto exit;

	BBF_INFO("Waiting on uloop....");
	uloop_run();

exit:
	if (err != -5) // Error code is not -5, indicating that ubus_ctx is connected, proceed with shutdown
		bbfdm_ubus_regiter_free(&bbfdm_ctx);

	closelog();

	return err;
}
