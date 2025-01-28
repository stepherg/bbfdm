/*
 * dm_service.c: dm-service deamon
 *
 * Copyright (C) 2024-2025 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 * See LICENSE file for license related information.
 */

#include <sys/prctl.h>

#include "common.h"
#include "bbfdm-ubus.h"

static void usage(char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "    -m <ms name>        micro-service name\n");
	fprintf(stderr, "    -l <loglevel>       log verbosity value as per standard syslog\n");
	fprintf(stderr, "    -h                  Displays this help\n");
	fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct bbfdm_context bbfdm_ctx = {0};
	char proc_name[64] = {0};
	int log_level = LOG_ERR;
	int err = 0, ch;

	memset(&bbfdm_ctx, 0, sizeof(struct bbfdm_context));

	while ((ch = getopt(argc, argv, "hl:m:")) != -1) {
		switch (ch) {
		case 'm':
			bbfdm_ubus_set_service_name(&bbfdm_ctx, optarg);
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

	if (strlen(bbfdm_ctx.config.service_name) == 0) {
		fprintf(stderr, "Failed to start micro-service without providing the name using '-m' option\n");
		exit(-1);
	}

	bbfdm_ubus_set_log_level(log_level);

	openlog(bbfdm_ctx.config.service_name, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

	err = bbfdm_ubus_regiter_init(&bbfdm_ctx);
	if (err != 0)
		goto exit;

	// Create process name using service name and prefix "dm_"
	snprintf(proc_name, sizeof(proc_name), "dm_%s", bbfdm_ctx.config.service_name);

	// Set process name for the current process
	prctl(PR_SET_NAME, proc_name, NULL, NULL, NULL);

	BBF_INFO("Waiting on uloop....");
	uloop_run();

exit:
	if (err != -5) // Error code is not -5, indicating that ubus_ctx is connected, proceed with shutdown
		bbfdm_ubus_regiter_free(&bbfdm_ctx);

	closelog();

	return err;
}
