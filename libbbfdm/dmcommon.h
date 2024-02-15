/*
 * Copyright (C) 2023 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#ifndef __DMCOMMON_H__
#define __DMCOMMON_H__

#include "libbbfdm-api/dmcommon.h"
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
int bbf_upload_log(const char *url, const char *username, const char *password,
		char *config_name, const char *command, const char *obj_path);
int bbf_config_backup(const char *url, const char *username, const char *password,
		char *config_name, const char *command, const char *obj_path);
int bbf_config_restore(const char *url, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *command, const char *obj_path);
int bbf_fw_image_download(const char *url, const char *auto_activate, const char *username, const char *password,
		const char *file_size, const char *checksum_algorithm, const char *checksum,
		const char *bank_id, const char *command, const char *obj_path, const char *commandKey, char *keep);

bool ip___is_ip_interface_instance_exists(const char *sec_name, const char *device);
void ip___update_child_interfaces(char *device, char *option_name, char *option_value);

void ppp___update_sections(struct uci_section *s_from, struct uci_section *s_to);
void ppp___reset_options(struct uci_section *ppp_s);
void ppp___Update_PPP_Interface_Top_Layers(char *path, char *linker);

void ethernet___Update_MAC_VLAN_Top_Layers(char *path, char *linker);
void ethernet___Update_VLAN_Termination_Top_Layers(char *path, char *linker);
void ethernet___Update_Link_Layer(char *path, char *linker);
void ethernet___Update_Link_Top_Layers(char *path, char *linker);

void bridging___get_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char **value);
void bridging___set_priority_list(struct uci_section *device_sec, char *uci_opt_name, void *data, char *value);

void firewall__create_zone_section(char *s_name);

struct uci_section *ethernet___get_ethernet_interface_section(const char *device_name);
char *ethernet___get_ethernet_interface_name(char *device_name);

#endif //__DMCOMMON_H__
