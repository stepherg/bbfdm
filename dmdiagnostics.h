/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DMDIAGNOSTICS_H__
#define __DMDIAGNOSTICS_H__

#include "libbbf_api/dmcommon.h"
#include <libubox/uloop.h>

#define HTTP_URI "http"
#define FTP_URI "ftp"
#define FILE_URI "file://"
#define FILE_LOCALHOST_URI "file://localhost"
#define default_date_format "AAAA-MM-JJTHH:MM:SS.000000Z"
#define default_date_size sizeof(default_date_format) + 1
#define FTP_SIZE_RESPONSE "213"
#define FTP_PASV_RESPONSE "227 Entering Passive"
#define FTP_TRANSFERT_COMPLETE "226 Transfer"
#define FTP_RETR_REQUEST "RETR"
#define FTP_STOR_REQUEST "STOR"
#define CURL_TIMEOUT 600
#define DMMAP_DIAGNOSTIGS "dmmap_diagnostics"
#define CONFIG_BACKUP "/tmp/bbf_config_backup"
#define MAX_TIME_WINDOW 5
#define DOWNLOAD_DUMP_FILE "/tmp/download_dump"
#define UPLOAD_DUMP_FILE "/tmp/upload_dump"

struct diagnostic_stats
{
	char romtime[default_date_size];
	char bomtime[default_date_size];
	char eomtime[default_date_size];
	char tcpopenrequesttime[default_date_size];
	char tcpopenresponsetime[default_date_size];
	int test_bytes_received;
	int tmp;
	int first_data;
	uint16_t ip_len;
	uint32_t ack_seq;
	uint32_t random_seq;
	uint32_t get_ack;
	uint32_t ftp_syn;
};

extern struct diagnostic_stats diag_stats;

enum diagnostic_protocol {
	DIAGNOSTIC_HTTP = 1,
	DIAGNOSTIC_FTP
};

enum diagnostic_type {
	DOWNLOAD_DIAGNOSTIC = 1,
	UPLOAD_DIAGNOSTIC
};

char *get_diagnostics_option(char *sec_name, char *option);
char *get_diagnostics_option_fallback_def(char *sec_name, char *option, char *default_value);
void set_diagnostics_option(char *sec_name, char *option, char *value);
void reset_diagnostic_state(char *sec_name);
char *get_diagnostics_interface_option(struct dmctx *ctx, char *value);
void set_diagnostics_interface_option(struct dmctx *ctx, char *sec_name, char *value);
int bbf_upload_log(const char *url, const char *username, const char *password,
		char *config_name, const char *command, const char *obj_path);
int bbf_config_backup(const char *url, const char *username, const char *password,
		char *config_name, const char *command, const char *obj_path);
int bbf_config_restore(const char *url, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *command, const char *obj_path);
int bbf_fw_image_download(const char *url, const char *auto_activate, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *bank_id, const char *command, const char *obj_path, const char *commandKey);

int extract_stats(char *dump_file, int proto, int diagnostic_type);

#endif
