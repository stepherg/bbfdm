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

#include <curl/curl.h>
#include <libtrace.h>
#include "dmentry.h"
#include "dmdiagnostics.h"

static int read_next;
static struct diagnostic_stats diag_stats = {0};

char *get_diagnostics_option(char *sec_name, char *option)
{
	char *value;
	dmuci_get_option_value_string_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, &value);
	return value;
}

char *get_diagnostics_option_fallback_def(char *sec_name, char *option, char *default_value)
{
	char *value = get_diagnostics_option(sec_name, option);
	return (*value != '\0') ? value : default_value;
}

void set_diagnostics_option(char *sec_name, char *option, char *value)
{
	check_create_dmmap_package(DMMAP_DIAGNOSTIGS);
	struct uci_section *section = dmuci_walk_section_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
	if (!section)
		dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, "", sec_name);

	dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, value);
}

void init_diagnostics_operation(char *sec_name, char *operation_path)
{
	check_create_dmmap_package(DMMAP_DIAGNOSTIGS);
	struct uci_section *section = dmuci_walk_section_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
	if (section)
		dmuci_delete_by_section_bbfdm(section, NULL, NULL);

	DMCMD("/bin/sh", 2, operation_path, "stop");
}

void set_diagnostics_interface_option(struct dmctx *ctx, char *sec_name, char *value)
{
	char *linker = NULL;

	if (value[0] == 0)
		return;

	if (strncmp(value, "Device.IP.Interface.", 20) != 0)
		return;

	adm_entry_get_linker_value(ctx, value, &linker);

	if (linker && *linker) {
		set_diagnostics_option(sec_name, "interface", linker);
		dmfree(linker);
	}
}

static int download_file(const char *file_path, const char *url, const char *username, const char *password)
{
	int res_code = 0;

	CURL *curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_USERNAME, username);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);

		FILE *fp = fopen(file_path, "wb");
		if (fp) {
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
			curl_easy_perform(curl);
			fclose(fp);
		}

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_code);
		curl_easy_cleanup(curl);
	}

	return res_code;
}

static int upload_file(const char *file_path, const char *url, const char *username, const char *password)
{
	int res_code = 0;

	CURL *curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_USERNAME, username);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

		FILE *fp = fopen(file_path, "rb");
		if (fp) {
			curl_easy_setopt(curl, CURLOPT_READDATA, fp);
			curl_easy_perform(curl);
			fclose(fp);
		}

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res_code);
		curl_easy_cleanup(curl);
	}

	return res_code;
}

int bbf_config_backup(const char *url, const char *username, const char *password, char *config_name)
{
	int res = 0;

	// Export config file to backup file
	if (dmuci_export_package(config_name, CONFIG_BACKUP)) {
		res = -1;
		goto end;
	}

	// Upload config file
	int res_code = upload_file(CONFIG_BACKUP, url, username, password);
	if ((strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) == 0 && res_code != 200) ||
		(strncmp(url, FTP_PROTO, strlen(FTP_PROTO)) == 0 && res_code != 226) ||
		(strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) && strncmp(url, FTP_PROTO, strlen(FTP_PROTO))))
		res = -1;

end:
	// Remove temporary file
	if (remove(CONFIG_BACKUP))
		res = -1;

	return res;
}

int bbf_config_restore(const char *url, const char *username, const char *password, const char *size)
{
	int res = 0;

	// Check file size
	if (size && *size) {
		unsigned long file_size = strtoul(size, NULL, 10);
		unsigned long fs_available_size = file_system_size("/tmp", FS_SIZE_AVAILABLE);

		if (fs_available_size < file_size) {
			res = -1;
			goto end;
		}
	}

	// Download config file
	int res_code = download_file(CONFIG_RESTORE, url, username, password);
	if ((strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) == 0 && res_code != 200) ||
		(strncmp(url, FTP_PROTO, strlen(FTP_PROTO)) == 0 && res_code != 226) ||
		(strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) && strncmp(url, FTP_PROTO, strlen(FTP_PROTO)))) {
		res = -1;
		goto end;
	}

	// Apply config file
	if (dmuci_import(NULL, CONFIG_RESTORE))
		res = -1;

end:
	// Remove temporary file
	if (remove(CONFIG_RESTORE))
		res = -1;

	return res;
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet)
{
	if (trace)
		trace_destroy(trace);

	if (packet)
		trace_destroy_packet(packet);
}

static void set_stats_value(char *diag_type)
{
	char buf[16] = {0};

	set_diagnostics_option(diag_type, "ROMtime", ((diag_stats.romtime)[0] != 0) ? diag_stats.romtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option(diag_type, "BOMtime", ((diag_stats.bomtime)[0] != 0) ? diag_stats.bomtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option(diag_type, "EOMtime", ((diag_stats.eomtime)[0] != 0) ? diag_stats.eomtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option(diag_type, "TCPOpenRequestTime", ((diag_stats.tcpopenrequesttime)[0] != 0) ? diag_stats.tcpopenrequesttime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option(diag_type, "TCPOpenResponseTime",((diag_stats.tcpopenresponsetime)[0] != 0) ? diag_stats.tcpopenresponsetime : "0001-01-01T00:00:00.000000Z");
	snprintf(buf, sizeof(buf), "%d", diag_stats.test_bytes_received);
	set_diagnostics_option(diag_type, "TestBytesReceived", buf);
}

static int get_tcp_flag_from_packet(libtrace_packet_t *packet, libtrace_tcp_t **tcp, char *tcp_flag, char **nexthdr)
{
	uint8_t proto;
	uint32_t remaining;

	*tcp = trace_get_transport(packet, &proto, &remaining);
	if (*tcp == NULL)
		return -1;

	*nexthdr = trace_get_payload_from_tcp(*tcp, &remaining);

	if ((*tcp)->ecn_ns) strcat(tcp_flag, "ECN_NS ");
	if ((*tcp)->cwr) strcat(tcp_flag, "CWR ");
	if ((*tcp)->ece) strcat(tcp_flag, "ECE ");
	if ((*tcp)->fin) strcat(tcp_flag, "FIN ");
	if ((*tcp)->syn) strcat(tcp_flag, "SYN ");
	if ((*tcp)->rst) strcat(tcp_flag, "RST ");
	if ((*tcp)->psh) strcat(tcp_flag, "PSH ");
	if ((*tcp)->ack) strcat(tcp_flag, "ACK ");
	if ((*tcp)->urg) strcat(tcp_flag, "URG ");

	return 0;
}

static void http_download_per_packet(libtrace_packet_t *packet)
{
	libtrace_tcp_t *tcp = NULL;
	char *nexthdr, tcp_flag[16] = {0}, s_now[20] = {0};
	struct tm http_download_lt;

	if (get_tcp_flag_from_packet(packet, &tcp, tcp_flag, &nexthdr))
		return;

	struct timeval http_download_ts = trace_get_timeval(packet);
	localtime_r(&(http_download_ts.tv_sec), &http_download_lt);
	strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &http_download_lt);

	if (strcmp(tcp_flag, "SYN ") == 0 && diag_stats.random_seq == 0) {
		snprintf(diag_stats.tcpopenrequesttime, sizeof(diag_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) http_download_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "SYN ACK ") == 0 && diag_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == diag_stats.random_seq) {
		snprintf(diag_stats.tcpopenresponsetime, sizeof(diag_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) http_download_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strncmp(nexthdr, "GET", 3) == 0) {
		snprintf(diag_stats.romtime, sizeof(diag_stats.romtime), "%s.%06ldZ", s_now, (long) http_download_ts.tv_usec);
		diag_stats.get_ack = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->seq) == diag_stats.get_ack && diag_stats.ack_seq == 0) {
		diag_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == diag_stats.ack_seq && diag_stats.first_data == 0) {
		snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) http_download_ts.tv_usec);
		char *val = strstr(nexthdr,"Content-Length");
		char *pch, *pchr;
		val += strlen("Content-Length: ");
		pch = strtok_r(val, " \r\n\t", &pchr);
		diag_stats.test_bytes_received = atoi(pch);
		diag_stats.first_data = 1;
		return;
	}

	if ((strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == diag_stats.ack_seq) {
		if (diag_stats.first_data == 0) {
			snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) http_download_ts.tv_usec);
			char *val = strstr(nexthdr,"Content-Length");
			char *pch, *pchr;
			val += strlen("Content-Length: ");
			pch = strtok_r(val, " \r\n\t", &pchr);
			diag_stats.test_bytes_received = atoi(pch);
			diag_stats.first_data = 1;
		}
		snprintf(diag_stats.eomtime, sizeof(diag_stats.eomtime), "%s.%06ldZ", s_now, (long) http_download_ts.tv_usec);
		read_next = 0;
		return;
	}
}

static void ftp_download_per_packet(libtrace_packet_t *packet)
{
	libtrace_tcp_t *tcp = NULL;
	char *nexthdr, tcp_flag[16] = {0}, s_now[20] = {0};
	struct tm ftp_download_lt;

	if (get_tcp_flag_from_packet(packet, &tcp, tcp_flag, &nexthdr))
		return;

	struct timeval ftp_download_ts = trace_get_timeval(packet);
	localtime_r(&(ftp_download_ts.tv_sec), &ftp_download_lt);
	strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &ftp_download_lt);

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_SIZE_RESPONSE) && strncmp(nexthdr, FTP_SIZE_RESPONSE, strlen(FTP_SIZE_RESPONSE)) == 0) {
		char *val = strstr(nexthdr,"213");
		char *pch, *pchr;
		val += strlen("213 ");
		pch =strtok_r(val, " \r\n\t", &pchr);
		diag_stats.test_bytes_received = atoi(pch);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_PASV_RESPONSE) && strncmp(nexthdr, FTP_PASV_RESPONSE, strlen(FTP_PASV_RESPONSE)) == 0) {
		diag_stats.ftp_syn = 1;
		return;
	}

	if (diag_stats.random_seq == 0 && strcmp(tcp_flag, "SYN ") == 0 && diag_stats.ftp_syn == 1) {
		snprintf(diag_stats.tcpopenrequesttime, sizeof(diag_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) ftp_download_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->seq);		
		return;
	}

	if (strcmp(tcp_flag, "SYN ACK ") == 0 && diag_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == diag_stats.random_seq) {
		snprintf(diag_stats.tcpopenresponsetime, sizeof(diag_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ftp_download_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_RETR_REQUEST) && strncmp(nexthdr, FTP_RETR_REQUEST, strlen(FTP_RETR_REQUEST)) == 0) {
		snprintf(diag_stats.romtime, sizeof(diag_stats.romtime), "%s.%06ldZ", s_now, (long) ftp_download_ts.tv_usec);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->seq) == diag_stats.random_seq && diag_stats.ack_seq == 0) {
		diag_stats.ack_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == diag_stats.ack_seq && diag_stats.first_data == 0) {
		snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) ftp_download_ts.tv_usec);
		diag_stats.first_data = 1;
		return;
	}

	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == diag_stats.ack_seq) {
		if (diag_stats.first_data == 0) {
			snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) ftp_download_ts.tv_usec);
			diag_stats.first_data = 1;
		}
		snprintf(diag_stats.eomtime, sizeof(diag_stats.eomtime), "%s.%06ldZ", s_now, (long) ftp_download_ts.tv_usec);
		read_next = 0;
		return;
	}
}

static void http_upload_per_packet(libtrace_packet_t *packet)
{
	libtrace_tcp_t *tcp = NULL;
	char *nexthdr, tcp_flag[16] = {0}, s_now[20] = {0};
	struct tm http_upload_lt;

	if (get_tcp_flag_from_packet(packet, &tcp, tcp_flag, &nexthdr))
		return;

	struct timeval http_upload_ts = trace_get_timeval(packet);
	localtime_r(&(http_upload_ts.tv_sec), &http_upload_lt);
	strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &http_upload_lt);

	if (strcmp(tcp_flag, "SYN ") == 0 && diag_stats.random_seq == 0) {
		snprintf(diag_stats.tcpopenrequesttime, sizeof(diag_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) http_upload_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "SYN ACK ") == 0 && diag_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == diag_stats.random_seq) {
		snprintf(diag_stats.tcpopenresponsetime, sizeof(diag_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) http_upload_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strncmp(nexthdr, "PUT", 3) == 0) {
		snprintf(diag_stats.romtime, sizeof(diag_stats.romtime), "%s.%06ldZ", s_now, (long) http_upload_ts.tv_usec);
		if (strstr(nexthdr, "Expect: 100-continue")) {
			diag_stats.tmp = 1;
			diag_stats.ack_seq = ntohl(tcp->ack_seq);
		} else
			diag_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && diag_stats.tmp == 1 && strstr(nexthdr, "100 Continue")) {
		diag_stats.tmp = 2;
		diag_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && diag_stats.tmp == 2 && ntohl(tcp->seq) == diag_stats.ack_seq) {
		diag_stats.tmp = 0;
		diag_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == diag_stats.ack_seq && diag_stats.tmp == 0 && diag_stats.first_data == 0) {
		snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) http_upload_ts.tv_usec);
		diag_stats.first_data = 1;
		return;
	}

	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == diag_stats.ack_seq && diag_stats.tmp == 0) {
		if (diag_stats.first_data == 0) {
			snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) http_upload_ts.tv_usec);
			diag_stats.first_data = 1;
		}
		return;
	}

	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->seq) == diag_stats.ack_seq && diag_stats.tmp == 0) {
		snprintf(diag_stats.eomtime, sizeof(diag_stats.eomtime), "%s.%06ldZ", s_now, (long) http_upload_ts.tv_usec);
		read_next = 0;
		return;
	}
}

static void ftp_upload_per_packet(libtrace_packet_t *packet)
{
	libtrace_tcp_t *tcp = NULL;
	char *nexthdr, tcp_flag[16] = {0}, s_now[20] = {0};
	struct tm ftp_upload_lt;

	if (get_tcp_flag_from_packet(packet, &tcp, tcp_flag, &nexthdr))
		return;

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_PASV_RESPONSE) && strncmp(nexthdr, FTP_PASV_RESPONSE, strlen(FTP_PASV_RESPONSE)) == 0) {
		diag_stats.ftp_syn = 1;
		return;
	}

	struct timeval ftp_upload_ts = trace_get_timeval(packet);
	localtime_r(&(ftp_upload_ts.tv_sec), &ftp_upload_lt);
	strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &ftp_upload_lt);

	if (strcmp(tcp_flag, "SYN ") == 0 && diag_stats.ftp_syn == 1) {
		diag_stats.random_seq = ntohl(tcp->seq);
		snprintf(diag_stats.tcpopenrequesttime, sizeof(diag_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) ftp_upload_ts.tv_usec);
		return;	
	}

	if (strcmp(tcp_flag, "SYN ACK ") == 0 && diag_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == diag_stats.random_seq) {
		snprintf(diag_stats.tcpopenresponsetime, sizeof(diag_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ftp_upload_ts.tv_usec);
		diag_stats.random_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_STOR_REQUEST) && strncmp(nexthdr, FTP_STOR_REQUEST, strlen(FTP_STOR_REQUEST)) == 0) {
		snprintf(diag_stats.romtime, sizeof(diag_stats.romtime), "%s.%06ldZ", s_now, (long) ftp_upload_ts.tv_usec);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->seq) == diag_stats.random_seq && diag_stats.ack_seq == 0) {
		diag_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == diag_stats.ack_seq && diag_stats.first_data == 0) {
		snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) ftp_upload_ts.tv_usec);
		diag_stats.first_data = 1;
		return;
	}

	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) && ntohl(tcp->ack_seq) == diag_stats.ack_seq) {
		if (diag_stats.first_data == 0) {
			snprintf(diag_stats.bomtime, sizeof(diag_stats.bomtime), "%s.%06ldZ", s_now, (long) ftp_upload_ts.tv_usec);
			diag_stats.first_data = 1;
		}
		return;
	}

	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  strlen(nexthdr) > strlen(FTP_TRANSFERT_COMPLETE) && strncmp(nexthdr, FTP_TRANSFERT_COMPLETE, strlen(FTP_TRANSFERT_COMPLETE)) == 0) {
		snprintf(diag_stats.eomtime, sizeof(diag_stats.eomtime), "%s.%06ldZ", s_now, (long) ftp_upload_ts.tv_usec);
		read_next = 0;
		return;
	}
}

static int extract_stats(char *dump_file, int proto, int diagnostic_type)
{
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = trace_create_packet();

	read_next = 1;
	if (packet == NULL) {
		libtrace_cleanup(trace, packet);
		return -1;
	}

	trace = trace_create(dump_file);
	if (!trace)
		return -1;

	if (trace_is_err(trace)) {
		libtrace_cleanup(trace, packet);
		return -1;
	}

	if (trace_start(trace) == -1) {
		libtrace_cleanup(trace, packet);
		return 1;
	}

	if (proto == DIAGNOSTIC_HTTP && diagnostic_type == DOWNLOAD_DIAGNOSTIC) {
		while (trace_read_packet(trace,packet) > 0 && read_next == 1) {
			http_download_per_packet(packet);
			continue;
		}
		set_stats_value("download");

	} else if (proto == DIAGNOSTIC_FTP && diagnostic_type == DOWNLOAD_DIAGNOSTIC) {
		while (trace_read_packet(trace,packet) > 0 && read_next == 1) {
			ftp_download_per_packet(packet);
			continue;
		}
		set_stats_value("download");

	} else if (proto == DIAGNOSTIC_HTTP && diagnostic_type == UPLOAD_DIAGNOSTIC) {
		while (trace_read_packet(trace,packet) > 0 && read_next == 1) {
			http_upload_per_packet(packet);
			continue;
		}
		set_stats_value("upload");

	} else {
		while (trace_read_packet(trace,packet) > 0 && read_next == 1) {
			ftp_upload_per_packet(packet);
			continue;
		}
		set_stats_value("upload");
	}

	libtrace_cleanup(trace, packet);
	return 0;
}

static char *get_default_gateway_device(void)
{
	char *device = "";

    FILE *f = fopen(PROC_ROUTE, "r");
	if (f != NULL) {
		char line[100] = {0}, *p = NULL, *c = NULL, *saveptr = NULL;

		while(fgets(line, sizeof(line), f)) {
			p = strtok_r(line, " \t", &saveptr);
			c = strtok_r(NULL, " \t", &saveptr);
			if (p && c && strcmp(c, "00000000") == 0) {
				device = dmstrdup(p);
				break;
			}
		}
		fclose(f);
	}

    return device;
}

int start_upload_download_diagnostic(int diagnostic_type)
{
	char *url, *interface, *device, *size, *status;

	if (diagnostic_type == DOWNLOAD_DIAGNOSTIC) {
		url = get_diagnostics_option("download", "url");
		interface = get_diagnostics_option("download", "interface");
	} else {
		url = get_diagnostics_option("upload", "url");
		size = get_diagnostics_option("upload", "TestFileLength");
		interface = get_diagnostics_option("upload", "interface");
	}

	if ((url[0] == '\0') ||
		(strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) != 0 &&
		strncmp(url, FTP_PROTO, strlen(FTP_PROTO)) != 0 &&
		strstr(url,"@") != NULL))
		return -1;

	device = (interface && *interface) ? get_device(interface) : get_default_gateway_device();
	if (device[0] == '\0')
		return -1;

	if (diagnostic_type == DOWNLOAD_DIAGNOSTIC) {
		// Commit and Free uci_ctx_bbfdm
		commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

		dmcmd("/bin/sh", 4, DOWNLOAD_DIAGNOSTIC_PATH, "run", url, device);

		// Allocate uci_ctx_bbfdm
		dmuci_init_bbfdm();

		url = get_diagnostics_option("download", "url");
		status = get_diagnostics_option("download", "DiagnosticState");
		if (status && strcmp(status, "Complete") == 0) {
			memset(&diag_stats, 0, sizeof(diag_stats));
			if (strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) == 0)
				extract_stats(DOWNLOAD_DUMP_FILE, DIAGNOSTIC_HTTP, DOWNLOAD_DIAGNOSTIC);
			if (strncmp(url, FTP_PROTO, strlen(FTP_PROTO)) == 0)
				extract_stats(DOWNLOAD_DUMP_FILE, DIAGNOSTIC_FTP, DOWNLOAD_DIAGNOSTIC);
		} else if (status && strncmp(status, "Error_", strlen("Error_")) == 0)
			return -1;
	} else {
		// Commit and Free uci_ctx_bbfdm
		commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

		dmcmd("/bin/sh", 5, UPLOAD_DIAGNOSTIC_PATH, "run", url, device, size);

		// Allocate uci_ctx_bbfdm
		dmuci_init_bbfdm();

		url = get_diagnostics_option("upload", "url");
		status = get_diagnostics_option("upload", "DiagnosticState");
		if (status && strcmp(status, "Complete") == 0) {
			memset(&diag_stats, 0, sizeof(diag_stats));
			if (strncmp(url, HTTP_PROTO, strlen(HTTP_PROTO)) == 0)
				extract_stats(UPLOAD_DUMP_FILE, DIAGNOSTIC_HTTP, UPLOAD_DIAGNOSTIC);
			if (strncmp(url, FTP_PROTO, strlen(FTP_PROTO)) == 0)
				extract_stats(UPLOAD_DUMP_FILE, DIAGNOSTIC_FTP, UPLOAD_DIAGNOSTIC);
		} else if (status && strncmp(status, "Error_", strlen("Error_")) == 0)
			return -1;
	}
	return 0;
}
