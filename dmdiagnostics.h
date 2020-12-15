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

#include <libbbf_api/dmcommon.h>

#define DOWNLOAD_UPLOAD_PROTOCOL_HTTP "http://"
#define DOWNLOAD_UPLOAD_PROTOCOL_FTP "ftp://"
#define default_date_format "AAAA-MM-JJTHH:MM:SS.000000Z"
#define default_date_size sizeof(default_date_format) + 1
#define FTP_SIZE_RESPONSE "213"
#define FTP_PASV_RESPONSE "227 Entering Passive"
#define FTP_TRANSFERT_COMPLETE "226 Transfer"
#define FTP_RETR_REQUEST "RETR"
#define FTP_STOR_REQUEST "STOR"
#define DMMAP_DIAGNOSTIGS "dmmap_diagnostics"

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
void init_diagnostics_operation(char *sec_name, char *operation_path);
void set_diagnostics_interface_option(struct dmctx *ctx, char *sec_name, char *value);
int start_upload_download_diagnostic(int diagnostic_type, char *proto);

#endif
