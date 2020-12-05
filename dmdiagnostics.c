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

#include <libtrace.h>
#include "dmentry.h"
#include "dmdiagnostics.h"

int read_next;
struct download_diag download_stats = {0};
struct upload_diagnostic_stats upload_stats = {0};

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
	struct uci_section *section = NULL;

	check_create_dmmap_package(DMMAP_DIAGNOSTIGS);
	section = dmuci_walk_section_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
	if (!section)
		dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, "", sec_name);

	dmuci_set_value_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, option, value);
}

void init_diagnostics_operation(char *sec_name, char *operation_path)
{
	struct uci_section *section = NULL;

	check_create_dmmap_package(DMMAP_DIAGNOSTIGS);
	section = dmuci_walk_section_bbfdm(DMMAP_DIAGNOSTIGS, sec_name, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
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

static void init_download_stats(void)
{
	memset(&download_stats, 0, sizeof(download_stats));
}

static void init_upload_stats(void)
{
	memset(&upload_stats, 0, sizeof(upload_stats));
}

static void ftp_download_per_packet(libtrace_packet_t *packet)
{
	struct tm lt;
	struct timeval ts;
	libtrace_tcp_t *tcp;
	char tcp_flag[16] = "";
	char *nexthdr;
	char s_now[20];
	uint8_t proto;
	uint32_t remaining;

	tcp = trace_get_transport(packet, &proto, &remaining);
	if (tcp == NULL)
		return;
	else
		nexthdr = trace_get_payload_from_tcp(tcp, &remaining);

	if (tcp->ecn_ns) strcat(tcp_flag, "ECN_NS ");
	if (tcp->cwr) strcat(tcp_flag, "CWR ");
	if (tcp->ece) strcat(tcp_flag, "ECE ");
	if (tcp->fin) strcat(tcp_flag, "FIN ");
	if (tcp->syn) strcat(tcp_flag, "SYN ");
	if (tcp->rst) strcat(tcp_flag, "RST ");
	if (tcp->psh) strcat(tcp_flag, "PSH ");
	if (tcp->ack) strcat(tcp_flag, "ACK ");
	if (tcp->urg) strcat(tcp_flag, "URG ");

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_SIZE_RESPONSE) && strncmp(nexthdr, FTP_SIZE_RESPONSE, strlen(FTP_SIZE_RESPONSE)) == 0)
	{
		char *val = strstr(nexthdr,"213");
		char *pch, *pchr;
		val += strlen("213 ");
		pch=strtok_r(val, " \r\n\t", &pchr);
		download_stats.test_bytes_received = atoi(pch);
	}
	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_PASV_RESPONSE) && strncmp(nexthdr, FTP_PASV_RESPONSE, strlen(FTP_PASV_RESPONSE)) == 0)
	{
		download_stats.ftp_syn = 1;
		return;
	}
    if (download_stats.random_seq == 0 && strcmp(tcp_flag, "SYN ") == 0 && download_stats.ftp_syn == 1)
	{
    	ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		download_stats.random_seq = ntohl(tcp->seq);
		snprintf(download_stats.tcpopenrequesttime, sizeof(download_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
	if (strcmp(tcp_flag, "SYN ACK ") == 0 && download_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == download_stats.random_seq)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(download_stats.tcpopenresponsetime, sizeof(download_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		download_stats.random_seq = ntohl(tcp->ack_seq);
		snprintf(download_stats.tcpopenresponsetime, sizeof(download_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_RETR_REQUEST) && strncmp(nexthdr, FTP_RETR_REQUEST, strlen(FTP_RETR_REQUEST)) == 0)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(download_stats.romtime, sizeof(download_stats.romtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->seq) == download_stats.random_seq && download_stats.ack_seq == 0)
	{
		download_stats.ack_seq = ntohl(tcp->seq);
		return;
	}
	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == download_stats.ack_seq )
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (download_stats.first_data == 0)
		{
			snprintf(download_stats.bomtime, sizeof(download_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		}
		download_stats.first_data = 1;
	}
	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == download_stats.ack_seq)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (download_stats.first_data == 0)
		{
			snprintf(download_stats.bomtime, sizeof(download_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			download_stats.first_data = 1;
		}
		snprintf(download_stats.eomtime, sizeof(download_stats.eomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
}

static void http_download_per_packet(libtrace_packet_t *packet)
{
	struct tm lt;
	struct timeval ts;
	libtrace_tcp_t *tcp;
	char *nexthdr, tcp_flag[16] = "", s_now[20];
	uint8_t proto;
	uint32_t remaining;

	tcp = trace_get_transport(packet, &proto, &remaining);
	if (tcp == NULL)
		return;
	else
		nexthdr = trace_get_payload_from_tcp(tcp, &remaining);

	if (tcp->ecn_ns) strcat(tcp_flag, "ECN_NS ");
	if (tcp->cwr) strcat(tcp_flag, "CWR ");
	if (tcp->ece) strcat(tcp_flag, "ECE ");
	if (tcp->fin) strcat(tcp_flag, "FIN ");
	if (tcp->syn) strcat(tcp_flag, "SYN ");
	if (tcp->rst) strcat(tcp_flag, "RST ");
	if (tcp->psh) strcat(tcp_flag, "PSH ");
	if (tcp->ack) strcat(tcp_flag, "ACK ");
	if (tcp->urg) strcat(tcp_flag, "URG ");

	if (strcmp(tcp_flag, "SYN ") == 0 && download_stats.random_seq == 0) {
    	ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(download_stats.tcpopenrequesttime, sizeof(download_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		download_stats.random_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "SYN ACK ") == 0 && download_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == download_stats.random_seq) {
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(download_stats.tcpopenresponsetime, sizeof(download_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		download_stats.random_seq = ntohl(tcp->seq);
		return;
	}

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strncmp(nexthdr, "GET", 3) == 0) {
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(download_stats.romtime, sizeof(download_stats.romtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		download_stats.get_ack = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->seq) == download_stats.get_ack && download_stats.ack_seq == 0) {
		download_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}

	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == download_stats.ack_seq ) {
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (download_stats.first_data == 0) {
			snprintf(download_stats.bomtime, sizeof(download_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			char *val = strstr(nexthdr,"Content-Length");
			char *pch, *pchr;
			val += strlen("Content-Length: ");
			pch=strtok_r(val, " \r\n\t", &pchr);
			download_stats.test_bytes_received = atoi(pch);
			download_stats.first_data = 1;
		}
		return;
	}

	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == download_stats.ack_seq) {
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (download_stats.first_data == 0) {
			snprintf(download_stats.bomtime, sizeof(download_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			char *val = strstr(nexthdr,"Content-Length");
			char *pch, *pchr;
			val += strlen("Content-Length: ");
			pch=strtok_r(val, " \r\n\t", &pchr);
			download_stats.test_bytes_received = atoi(pch);
			download_stats.first_data = 1;
		}
		snprintf(download_stats.eomtime, sizeof(download_stats.eomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		return;
	}
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet)
{
	if (trace)
		trace_destroy(trace);

	if (packet)
		trace_destroy_packet(packet);
}

static void set_download_stats(char *protocol)
{
	char buf[16] = {0};

	set_diagnostics_option("download", "ROMtime", ((download_stats.romtime)[0] != 0) ? download_stats.romtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("download", "BOMtime", ((download_stats.bomtime)[0] != 0) ? download_stats.bomtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("download", "EOMtime", ((download_stats.eomtime)[0] != 0) ? download_stats.eomtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("download", "TCPOpenRequestTime", ((download_stats.tcpopenrequesttime)[0] != 0) ? download_stats.tcpopenrequesttime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("download", "TCPOpenResponseTime",((download_stats.tcpopenresponsetime)[0] != 0) ? download_stats.tcpopenresponsetime : "0001-01-01T00:00:00.000000Z");
	snprintf(buf, sizeof(buf), "%d", download_stats.test_bytes_received);
	set_diagnostics_option("download", "TestBytesReceived", buf);
}

static void set_upload_stats(char *protocol)
{
	set_diagnostics_option("upload", "ROMtime", ((upload_stats.romtime)[0] != 0) ? upload_stats.romtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("upload", "BOMtime", ((upload_stats.bomtime)[0] != 0) ? upload_stats.bomtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("upload", "EOMtime", ((upload_stats.eomtime)[0] != 0) ? upload_stats.eomtime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("upload", "TCPOpenRequestTime", ((upload_stats.tcpopenrequesttime)[0] != 0) ? upload_stats.tcpopenrequesttime : "0001-01-01T00:00:00.000000Z");
	set_diagnostics_option("upload", "TCPOpenResponseTime", ((upload_stats.tcpopenresponsetime)[0] != 0) ? upload_stats.tcpopenresponsetime : "0001-01-01T00:00:00.000000Z");
}

static void http_upload_per_packet(libtrace_packet_t *packet)
{
	struct tm lt;
	struct timeval ts;
	libtrace_tcp_t *tcp;
	char tcp_flag[16] = "";
	char *nexthdr;
	char s_now[20];
	uint8_t proto;
	uint32_t remaining;

	tcp = trace_get_transport(packet, &proto, &remaining);
	if (tcp == NULL)
		return;
	else
		nexthdr = trace_get_payload_from_tcp(tcp, &remaining);

	if (tcp->ecn_ns) strcat(tcp_flag, "ECN_NS ");
	if (tcp->cwr) strcat(tcp_flag, "CWR ");
	if (tcp->ece) strcat(tcp_flag, "ECE ");
	if (tcp->fin) strcat(tcp_flag, "FIN ");
	if (tcp->syn) strcat(tcp_flag, "SYN ");
	if (tcp->rst) strcat(tcp_flag, "RST ");
	if (tcp->psh) strcat(tcp_flag, "PSH ");
	if (tcp->ack) strcat(tcp_flag, "ACK ");
	if (tcp->urg) strcat(tcp_flag, "URG ");

	if (strcmp(tcp_flag, "SYN ") == 0 && download_stats.random_seq == 0)
	{
    	ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.tcpopenrequesttime, sizeof(upload_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		upload_stats.random_seq = ntohl(tcp->seq);
	}
	if (strcmp(tcp_flag, "SYN ACK ") == 0 && upload_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == upload_stats.random_seq)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.tcpopenresponsetime, sizeof(upload_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		upload_stats.random_seq = ntohl(tcp->seq);
	}
	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strncmp(nexthdr, "PUT", 3) == 0)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.romtime, sizeof(upload_stats.romtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		if (strstr(nexthdr, "Expect: 100-continue"))
		{
			upload_stats.tmp=1;
			upload_stats.ack_seq = ntohl(tcp->ack_seq);
		}
		else
			upload_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}
	if (strcmp(tcp_flag, "PSH ACK ") == 0 && upload_stats.tmp == 1 && strstr(nexthdr, "100 Continue"))
	{
		upload_stats.tmp = 2;
		upload_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}
	if (strcmp(tcp_flag, "ACK ") == 0 && upload_stats.tmp == 2 && ntohl(tcp->seq) == upload_stats.ack_seq)
	{
		upload_stats.tmp = 0;
		upload_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}
	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == upload_stats.ack_seq && upload_stats.tmp == 0)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (upload_stats.first_data == 0)
		{
			snprintf(upload_stats.bomtime, sizeof(upload_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			upload_stats.first_data = 1;
		}
	}
	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == upload_stats.ack_seq && upload_stats.tmp == 0)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (upload_stats.first_data == 0)
		{
			snprintf(upload_stats.bomtime, sizeof(upload_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			upload_stats.first_data = 1;
		}
	}
	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->seq) == upload_stats.ack_seq && upload_stats.tmp == 0)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.eomtime, sizeof(upload_stats.eomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
}

static void ftp_upload_per_packet(libtrace_packet_t *packet)
{
	struct tm lt;
	struct timeval ts;
	libtrace_tcp_t *tcp;
	uint8_t proto;
	uint32_t remaining;
	char tcp_flag[16] = "";
	char *nexthdr;
	char s_now[20];

	tcp = trace_get_transport(packet, &proto, &remaining);
	if (tcp == NULL)
		return;
	else
		nexthdr = trace_get_payload_from_tcp(tcp, &remaining);

	if (tcp->ecn_ns) strcat(tcp_flag, "ECN_NS ");
	if (tcp->cwr) strcat(tcp_flag, "CWR ");
	if (tcp->ece) strcat(tcp_flag, "ECE ");
	if (tcp->fin) strcat(tcp_flag, "FIN ");
	if (tcp->syn) strcat(tcp_flag, "SYN ");
	if (tcp->rst) strcat(tcp_flag, "RST ");
	if (tcp->psh) strcat(tcp_flag, "PSH ");
	if (tcp->ack) strcat(tcp_flag, "ACK ");
	if (tcp->urg) strcat(tcp_flag, "URG ");

	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_PASV_RESPONSE) && strncmp(nexthdr, FTP_PASV_RESPONSE, strlen(FTP_PASV_RESPONSE)) == 0)
	{
		upload_stats.ftp_syn = 1;
		return;
	}
    if (strcmp(tcp_flag, "SYN ") == 0 && upload_stats.ftp_syn == 1)
	{
    	ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		upload_stats.random_seq = ntohl(tcp->seq);
		snprintf(upload_stats.tcpopenrequesttime, sizeof(upload_stats.tcpopenrequesttime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
	if (strcmp(tcp_flag, "SYN ACK ") == 0 && upload_stats.random_seq != 0 && (ntohl(tcp->ack_seq) - 1 ) == upload_stats.random_seq)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.tcpopenresponsetime, sizeof(upload_stats.tcpopenresponsetime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		upload_stats.random_seq = ntohl(tcp->ack_seq);
	}
	if (strcmp(tcp_flag, "PSH ACK ") == 0 && strlen(nexthdr) > strlen(FTP_STOR_REQUEST) && strncmp(nexthdr, FTP_STOR_REQUEST, strlen(FTP_STOR_REQUEST)) == 0)
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.romtime, sizeof(upload_stats.romtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
	}
	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->seq) == upload_stats.random_seq && upload_stats.ack_seq == 0)
	{
		upload_stats.ack_seq = ntohl(tcp->ack_seq);
		return;
	}
	if (strcmp(tcp_flag, "ACK ") == 0 && ntohl(tcp->ack_seq) == upload_stats.ack_seq )
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (upload_stats.first_data == 0)
		{
			snprintf(upload_stats.bomtime, sizeof(upload_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			upload_stats.first_data = 1;
		}
	}
	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  ntohl(tcp->ack_seq) == upload_stats.ack_seq) //&& strlen(nexthdr) > 16 && strncmp(nexthdr, "HTTP/1.1 200 OK", 16) == 0
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		if (upload_stats.first_data == 0)
		{
			snprintf(upload_stats.bomtime, sizeof(upload_stats.bomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
			upload_stats.first_data = 1;
		}
	}
	if ( (strcmp(tcp_flag, "PSH ACK ") == 0 || strcmp(tcp_flag, "FIN PSH ACK ") == 0) &&  strlen(nexthdr) > strlen(FTP_TRANSFERT_COMPLETE) && strncmp(nexthdr, FTP_TRANSFERT_COMPLETE, strlen(FTP_TRANSFERT_COMPLETE)) == 0) //&& strlen(nexthdr) > 16 && strncmp(nexthdr, "HTTP/1.1 200 OK", 16) == 0
	{
		ts = trace_get_timeval(packet);
		(void) localtime_r(&(ts.tv_sec), &lt);
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%S", &lt);
		snprintf(upload_stats.eomtime, sizeof(upload_stats.eomtime), "%s.%06ldZ", s_now, (long) ts.tv_usec);
		read_next = 0;
	}
}

static int extract_stats(char *dump_file, int proto, int diagnostic_type, char *protocol)
{
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;
	read_next = 1;
	packet = trace_create_packet();
	if (packet == NULL) {
		perror("Creating libtrace packet");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	trace = trace_create(dump_file);
	if (!trace) {
		return -1;
	}

	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace file");
		libtrace_cleanup(trace, packet);
		return 1;
	}

	if (trace_start(trace) == -1) {
		trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace, packet);
		return 1;
	}
	if (proto == DOWNLOAD_DIAGNOSTIC_HTTP && diagnostic_type == DOWNLOAD_DIAGNOSTIC)
	{
		while (trace_read_packet(trace,packet)>0 && read_next == 1) {
			http_download_per_packet(packet);
			continue;
		}
		set_download_stats(protocol);
	}
	else if (proto == DOWNLOAD_DIAGNOSTIC_FTP && diagnostic_type == DOWNLOAD_DIAGNOSTIC)
	{
		while (trace_read_packet(trace,packet)>0 && read_next == 1) {
			ftp_download_per_packet(packet);
			continue;
		}
		set_download_stats(protocol);
	}
	else if (proto == DOWNLOAD_DIAGNOSTIC_HTTP && diagnostic_type == UPLOAD_DIAGNOSTIC)
	{
		while (trace_read_packet(trace,packet)>0 && read_next == 1) {
			http_upload_per_packet(packet);
			continue;
		}
		set_upload_stats(protocol);
	}
	else
	{
		while (trace_read_packet(trace,packet)>0 && read_next == 1) {
			ftp_upload_per_packet(packet);
			continue;
		}
		set_upload_stats(protocol);
	}
	libtrace_cleanup(trace, packet);
	return 0;
}

static char *get_default_gateway_device(void)
{
	char *device = "";

    FILE *f = fopen(ROUTING_FILE, "r");
	if (f != NULL) {
		char line[100], *p, *c, *saveptr;
		while(fgets(line , 100 , f)) {
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

int start_upload_download_diagnostic(int diagnostic_type, char *proto)
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
		(strncmp(url, DOWNLOAD_UPLOAD_PROTOCOL_HTTP, strlen(DOWNLOAD_UPLOAD_PROTOCOL_HTTP)) != 0 &&
		strncmp(url, DOWNLOAD_UPLOAD_PROTOCOL_FTP, strlen(DOWNLOAD_UPLOAD_PROTOCOL_FTP)) != 0 &&
		strstr(url,"@") != NULL))
		return -1;

	device = (interface && *interface) ? get_device(interface) : get_default_gateway_device();
	if (device[0] == '\0')
		return -1;

	if (diagnostic_type == DOWNLOAD_DIAGNOSTIC) {
		// Commit and Free uci_ctx_bbfdm
		commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

		dmcmd("/bin/sh", 5, DOWNLOAD_DIAGNOSTIC_PATH, "run", proto, url, device);

		// Allocate uci_ctx_bbfdm
		dmuci_init_bbfdm();

		url = get_diagnostics_option("download", "url");
		status = get_diagnostics_option("download", "DiagnosticState");
		if (status && strcmp(status, "Complete") == 0) {
			init_download_stats();
			if (strncmp(url, DOWNLOAD_UPLOAD_PROTOCOL_HTTP, strlen(DOWNLOAD_UPLOAD_PROTOCOL_HTTP)) == 0)
				extract_stats(DOWNLOAD_DUMP_FILE, DOWNLOAD_DIAGNOSTIC_HTTP, DOWNLOAD_DIAGNOSTIC, proto);
			if (strncmp(url, DOWNLOAD_UPLOAD_PROTOCOL_FTP, strlen(DOWNLOAD_UPLOAD_PROTOCOL_FTP)) == 0)
				extract_stats(DOWNLOAD_DUMP_FILE, DOWNLOAD_DIAGNOSTIC_FTP, DOWNLOAD_DIAGNOSTIC, proto);
		} else if (status && strncmp(status, "Error_", strlen("Error_")) == 0)
			return -1;
	} else {
		// Commit and Free uci_ctx_bbfdm
		commit_and_free_uci_ctx_bbfdm(DMMAP_DIAGNOSTIGS);

		dmcmd("/bin/sh", 6, UPLOAD_DIAGNOSTIC_PATH, "run", proto, url, device, size);

		// Allocate uci_ctx_bbfdm
		dmuci_init_bbfdm();

		url = get_diagnostics_option("upload", "url");
		status = get_diagnostics_option("upload", "DiagnosticState");
		if (status && strcmp(status, "Complete") == 0) {
			init_upload_stats();
			if (strncmp(url, DOWNLOAD_UPLOAD_PROTOCOL_HTTP, strlen(DOWNLOAD_UPLOAD_PROTOCOL_HTTP)) == 0)
				extract_stats(UPLOAD_DUMP_FILE, DOWNLOAD_DIAGNOSTIC_HTTP, UPLOAD_DIAGNOSTIC, proto);
			if (strncmp(url, DOWNLOAD_UPLOAD_PROTOCOL_FTP, strlen(DOWNLOAD_UPLOAD_PROTOCOL_FTP)) == 0)
				extract_stats(UPLOAD_DUMP_FILE, DOWNLOAD_DIAGNOSTIC_FTP, UPLOAD_DIAGNOSTIC, proto);
		} else if (status && strncmp(status, "Error_", strlen("Error_")) == 0)
			return -1;
	}
	return 0;
}
