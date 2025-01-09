/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DM_COMMON_H
#define __DM_COMMON_H

#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <regex.h>
#include <unistd.h>
#include <glob.h>
#include <limits.h>
#include <float.h>
#include <time.h>
#include <inttypes.h>
#include <assert.h>
#include <getopt.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <uci.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <json-c/json.h>

#include "dmbbf.h"
#include "dmuci.h"
#include "dmubus.h"
#include "dmjson.h"
#include "dmentry.h"

extern char *DiagnosticsState[];
extern char *IPv4Address[];
extern char *IPv6Address[];
extern char *IPAddress[];
extern char *MACAddress[];
extern char *IPPrefix[];
extern char *IPv4Prefix[];
extern char *IPv6Prefix[];

#define UPTIME "/proc/uptime"
#define DEFAULT_CONFIG_DIR "/etc/config/"
#define PROC_ROUTE "/proc/net/route"
#define PROC_ROUTE6 "/proc/net/ipv6_route"
#define PROC_INTF6 "/proc/net/if_inet6"
#define BOARD_JSON_FILE "/etc/board.json"
#define DMMAP_DIAGNOSTIGS "dmmap_diagnostics"
#define HTTP_URI "http"
#define FTP_URI "ftp"
#define FILE_URI "file://"
#define FILE_LOCALHOST_URI "file://localhost"
#define BBFDM_SCRIPTS_PATH "/usr/share/bbfdm/scripts"

#define DM_ASSERT(X, Y) \
do { \
	if(!(X)) { \
		Y; \
		return -1; \
	} \
} while(0)

enum fs_size_type_enum {
	FS_SIZE_TOTAL,
	FS_SIZE_AVAILABLE,
	FS_SIZE_USED,
};

enum option_type_enum {
	OPTION_IP = 1<<0,
	OPTION_INT = 1<<1,
	OPTION_STRING = 1<<2,
	OPTION_HEX = 1<<3,
	OPTION_LIST = 1<<4
};

#define sysfs_foreach_file(path,dir,ent) \
	if ((dir = opendir(path)) == NULL) return 0; \
	while ((ent = readdir(dir)) != NULL) \

struct browse_args {
	char *option;
	char *value;
};

struct dhcp_options_type {
	char *config_name;
	uint8_t tag;
	uint8_t type;
	uint8_t len;
};

pid_t get_pid(const char *pname);
int compare_strings(const void *a, const void *b);
char *get_uptime(void);
int check_file(const char *path);
char *cidr2netmask(int bits);
int netmask2cidr(const char *netmask);
bool is_strword_in_optionvalue(const char *option_value, const char *str);
void remove_new_line(char *buf);
int dmcmd(const char *cmd, int n, ...);
int dmcmd_no_wait(const char *cmd, int n, ...);
int run_cmd(const char *cmd, char *output, size_t out_len);
int hex_to_ip(const char *address, char *ret, size_t size);
void add_dmmap_config_dup_list(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section);
void free_dmmap_config_dup_list(struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap(const char *package, const char *section_type, const char *dmmap_package, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_eq(const char *package, const char *section_type, const char *dmmap_package,
		const char *option_name, const char *option_value, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_cont(const char *package, const char *section_type, const char *dmmap_package,
		const char *option_name, const char *option_value, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_option(const char *package, const char *section_type, const char *dmmap_package,
		const char *option_name, struct list_head *dup_list);
void get_dmmap_section_of_config_section(const char *dmmap_package, const char *section_type, const char *section_name, struct uci_section **dmmap_section);
void get_dmmap_section_of_config_section_eq(const char *dmmap_package, const char *section_type, const char *opt, const char *value, struct uci_section **dmmap_section);
void get_dmmap_section_of_config_section_cont(const char *dmmap_package, const char *section_type, const char *opt, const char *value, struct uci_section **dmmap_section);
void get_config_section_of_dmmap_section(const char *package, const char *section_type, const char *section_name, struct uci_section **config_section);
int adm_entry_get_reference_param(struct dmctx *ctx, char *param, char *linker, char **value);
int adm_entry_get_reference_value(struct dmctx *ctx, const char *param, char **value);
int dm_validate_allowed_objects(struct dmctx *ctx, struct dm_reference *reference, char *objects[]);
unsigned int count_occurrences(const char *str, char c);
bool isdigit_str(const char *str);
bool ishex_str(const char *str);
bool special_char(char c);
bool special_char_exits(const char *str);
void replace_special_char(char *str, char c);
char *dm_strword(char *src, char *str);
char **strsplit(const char *str, const char *delim, size_t *num_tokens);
void convert_str_to_uppercase(char *str);
char *get_macaddr(const char *interface_name);
char *get_device(const char *interface_name);
char *get_l3_device(const char *interface_name);
bool value_exists_in_uci_list(struct uci_list *list, const char *value);
bool value_exits_in_str_list(const char *str_list, const char *delimitor, const char *str);
char *add_str_to_str_list(const char *str_list, const char *delimitor, const char *str);
char *remove_str_from_str_list(const char *str_list, const char *delimitor, const char *str);
struct uci_section *get_origin_section_from_config(const char *package, const char *section_type, const char *orig_section_name);
struct uci_section *get_origin_section_from_dmmap(const char *package, const char *section_type, const char *orig_section_name);
struct uci_section *get_dup_section_in_dmmap(const char *dmmap_package, const char *section_type, const char *orig_section_name);
struct uci_section *get_dup_section_in_config_opt(const char *package, const char *section_type, const char *opt_name, const char *opt_value);
struct uci_section *get_dup_section_in_dmmap_opt(const char *dmmap_package, const char *section_type, const char *opt_name, const char *opt_value);
struct uci_section *get_dup_section_in_dmmap_eq(const char *dmmap_package, const char *section_type,
		const char *sect_name, const char *opt_name, const char *opt_value);
struct uci_section *get_section_in_dmmap_with_options_eq(const char *dmmap_package, const char *section_type,
		const char *opt1_name, const char *opt1_value, const char *opt2_name, const char *opt2_value);
int get_shift_utc_time(int shift_time, char *utc_time, int size);
int get_shift_time_time(int shift_time, char *local_time, int size);
struct uci_section *is_dmmap_section_exist(const char *package, const char *section);
struct uci_section *is_dmmap_section_exist_eq(const char *package, const char *section, const char *opt, const char *value);
int dm_read_sysfs_file(const char *file, char *dst, unsigned len);
int get_net_iface_sysfs(const char *uci_iface, const char *name, char **value);
int get_net_device_sysfs(const char *device, const char *name, char **value);
int get_net_device_status(const char *device, char **value);
int dm_time_utc_format(time_t ts, char **dst);
int dm_time_format(time_t ts, char **dst);
void convert_string_to_hex(const char *str, char *hex, size_t size);
void convert_hex_to_string(const char *hex, char *str, size_t size);
bool match(const char *string, const char *pattern, size_t nmatch, regmatch_t pmatch[]);
void bbfdm_set_fault_message(struct dmctx *ctx, const char *format, ...);
int bbfdm_validate_boolean(struct dmctx *ctx, const char *value);
int bbfdm_validate_unsignedInt(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size);
int bbfdm_validate_int(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size);
int bbfdm_validate_unsignedLong(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size);
int bbfdm_validate_long(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size);
int bbfdm_validate_string(struct dmctx *ctx, const char *value, int min_length, int max_length, char *enumeration[], char *pattern[]);
int bbfdm_validate_dateTime(struct dmctx *ctx, const char *value);
int bbfdm_validate_hexBinary(struct dmctx *ctx, const char *value, struct range_args r_args[], int r_args_size);
int bbfdm_validate_unsignedInt_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int bbfdm_validate_int_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int bbfdm_validate_unsignedLong_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int bbfdm_validate_long_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int bbfdm_validate_string_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[]);
int bbfdm_validate_hexBinary_list(struct dmctx *ctx, const char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int bbf_get_alias(struct dmctx *ctx, struct uci_section *s, const char *option_name, const char *instance, char **value);
int bbf_set_alias(struct dmctx *ctx, struct uci_section *s, const char *option_name, const char *instance, const char *value);
int bbfdm_get_references(struct dmctx *ctx, int match_action, const char *base_path, const char *key_name, char *key_value, char *out, size_t out_len);
int _bbfdm_get_references(struct dmctx *ctx, const char *base_path, const char *key_name, char *key_value, char **value);
int bbfdm_get_reference_linker(struct dmctx *ctx, char *reference_path, struct dm_reference *reference_args);
int bbfdm_operate_reference_linker(struct dmctx *ctx, const char *reference_path, char **reference_value);
char *dm_base64_decode(const char *src);
void string_to_mac(const char *str, size_t str_len, char *out, size_t out_len);
bool folder_exists(const char *path);
bool file_exists(const char *path);
bool is_regular_file(const char *path);
int create_empty_file(const char *file_name);
unsigned long file_system_size(const char *path, const enum fs_size_type_enum type);
void remove_char(char *str, const char c);
char *replace_char(char *str, char find, char replace);
char *replace_str(const char *input_str, const char *old_substr, const char *new_substr, char *result_str, size_t buffer_len);
int dm_file_to_buf(const char *filename, char *buf, size_t buf_size);
int dm_file_copy(const char *src, const char *dst);
int parse_proc_intf6_line(const char *line, const char *device, char *ipstr, size_t str_len);
void strip_lead_trail_whitespace(char *str);
int dm_buf_to_file(const char *buf, const char *filename);
char *diagnostics_get_option(const char *sec_name, const char *option);
char *diagnostics_get_option_fallback_def(const char *sec_name, const char *option, const char *default_value);
void diagnostics_set_option(const char *sec_name, const char *option, const char *value);
void diagnostics_reset_state(const char *sec_name);
char *diagnostics_get_interface_name(struct dmctx *ctx, const char *value);
long download_file(char *file_path, const char *url, const char *username, const char *password);
long upload_file(const char *file_path, const char *url, const char *username, const char *password);
int get_proto_type(const char *proto);
bool is_str_eq(const char *s1, const char *s2);

#endif
