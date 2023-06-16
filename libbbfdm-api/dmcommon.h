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

extern char *Encapsulation[];
extern char *LinkType[];
extern char *BridgeStandard[];
extern char *BridgeType[];
extern char *VendorClassIDMode[];
extern char *DiagnosticsState[];
extern char *SupportedProtocols[];
extern char *InstanceMode[];
extern char *NATProtocol[];
extern char *Config[];
extern char *Target[];
extern char *ServerConnectAlgorithm[];
extern char *KeepAlivePolicy[];
extern char *DeliveryHeaderProtocol[];
extern char *KeyIdentifierGenerationPolicy[];
extern char *PreambleType[];
extern char *MFPConfig[];
extern char *DuplexMode[];
extern char *RequestedState[];
extern char *BulkDataProtocols[];
extern char *EncodingTypes[];
extern char *CSVReportFormat[];
extern char *RowTimestamp[];
extern char *JSONReportFormat[];
extern char *StaticType[];
extern char *ProtocolVersion[];
extern char *ServerSelectionProtocol[];
extern char *DHCPType[];
extern char *DropAlgorithm[];
extern char *SchedulerAlgorithm[];
extern char *ProfileEnable[];
extern char *PIN[];
extern char *DestinationAddress[];
extern char *RegulatoryDomain[];
extern char *ConformingAction[];
extern char *IPv4Address[];
extern char *IPv6Address[];
extern char *IPAddress[];
extern char *MACAddress[];
extern char *IPPrefix[];
extern char *IPv4Prefix[];
extern char *IPv6Prefix[];
extern char *SupportedOperatingChannelBandwidth[];
extern char *SupportedStandards[];
extern char *SupportedFrequencyBands[];
extern char *Provider_Bridge_Type[];
extern char *AdvPreferredRouterFlag[];
extern char *PowerState[];
extern char *FW_Mode[];
extern char *AKMsAllowed[];
extern char *CellularDataPreference[];
extern char *IPLayerCapacityRole[];
extern char *UDPPayloadContent[];
extern char *IPLayerCapacityTestType[];
extern char *RateAdjAlgorithm[];

#define CRONTABS_ROOT "/etc/crontabs/root"
#define ACTIVATE_HANDLER_FILE "/usr/share/bbfdm/bbf_activate_handler.sh"
#define UPTIME "/proc/uptime"
#define DEFAULT_CONFIG_DIR "/etc/config/"
#define PROC_ROUTE "/proc/net/route"
#define PROC_ROUTE6 "/proc/net/ipv6_route"
#define PROC_INTF6 "/proc/net/if_inet6"
#define MAX_DHCP_LEASES 256
#define DHCP_LEASES_FILE "/tmp/dhcp.leases"
#define DHCP_CLIENT_OPTIONS_FILE "/var/dhcp.client.options"
#define SYSTEM_CERT_PATH "/etc/ssl/certs"
#define DMMAP "dmmap"
#define LIST_KEY (const char *[])
#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100)

#define DM_ASSERT(X, Y) \
do { \
	if(!(X)) { \
		Y; \
		return -1; \
	} \
} while(0)

#define dmstrappendstr(dest, src) \
do { \
	int len = DM_STRLEN(src); \
	memcpy(dest, src, len); \
	dest += len; \
} while(0)

#define dmstrappendchr(dest, c) \
do { \
	*dest = c; \
	dest += 1; \
} while(0)

#define dmstrappendend(dest) \
do { \
	*dest = '\0'; \
} while(0)

enum fs_size_type_enum {
	FS_SIZE_TOTAL,
	FS_SIZE_AVAILABLE,
	FS_SIZE_USED,
};

enum option_type_enum {
	OPTION_IP,
	OPTION_INT,
	OPTION_HEX
};

#define sysfs_foreach_file(path,dir,ent) \
        if ((dir = opendir(path)) == NULL) return 0; \
        while ((ent = readdir (dir)) != NULL) \

struct dmmap_sect {
	struct list_head list;
	char *section_name;
	char *instance;
};

struct sysfs_dmsection {
	struct list_head list;
	char *sysfs_folder_path;
	char *sysfs_folder_name;
	struct uci_section *dmmap_section;
};

struct browse_args {
	char *option;
	char *value;
};

struct option_tag_type {
	int tag;
	int type;
	int len;
};

pid_t get_pid(const char *pname);
int check_file(char *path);
char *cidr2netmask(int bits);
bool is_strword_in_optionvalue(char *optionvalue, char *str);
void remove_new_line(char *buf);
int dmcmd(char *cmd, int n, ...);
int dmcmd_no_wait(char *cmd, int n, ...);
void hex_to_ip(char *address, char *ret, size_t size);
void add_dmmap_config_dup_list(struct list_head *dup_list, struct uci_section *config_section, struct uci_section *dmmap_section);
void free_dmmap_config_dup_list(struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_eq(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list);
void synchronize_specific_config_sections_with_dmmap_cont(char *package, char *section_type, char *dmmap_package,char* option_name, char* option_value, struct list_head *dup_list);
void add_sysfs_section_list(struct list_head *dup_list, struct uci_section *dmmap_section, char *file_name, char *file_path);
void synchronize_specific_config_sections_with_dmmap_network(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list);
int synchronize_system_folders_with_dmmap_opt(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, char* inst_opt, struct list_head *dup_list);
void get_dmmap_section_of_config_section(char* dmmap_package, char* section_type, char *section_name, struct uci_section **dmmap_section);
void get_dmmap_section_of_config_section_eq(char* dmmap_package, char* section_type, char *opt, char* value, struct uci_section **dmmap_section);
void get_dmmap_section_of_config_section_cont(char* dmmap_package, char* section_type, char *opt, char* value, struct uci_section **dmmap_section);
void get_config_section_of_dmmap_section(char* package, char* section_type, char *section_name, struct uci_section **config_section);
int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value);
int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value);
int dm_entry_validate_allowed_objects(struct dmctx *ctx, char *value, char *objects[]);
char *check_create_dmmap_package(const char *dmmap_package);
unsigned char isdigit_str(char *str);
bool special_char(char c);
bool special_char_exits(const char *str);
void replace_special_char(char *str, char c);
char *dm_strword(char *src, char *str);
char **strsplit(const char* str, const char* delim, size_t* numtokens);
char **strsplit_by_str(const char str[], char *delim);
void convert_str_to_uppercase(char *str);
char *get_macaddr(char *interface_name);
char *get_device(char *interface_name);
char *get_l3_device(char *interface_name);
bool value_exists_in_uci_list(struct uci_list *list, const char *value);
bool value_exits_in_str_list(char *str_list, const char *delimitor, const char *value);
void add_elt_to_str_list(char **str_list, char *elt);
void remove_elt_from_str_list(char **str_list, char *ifname);
struct uci_section *get_origin_section_from_config(char *package, char *section_type, char *orig_section_name);
struct uci_section *get_origin_section_from_dmmap(char *package, char *section_type, char *orig_section_name);
struct uci_section *get_dup_section_in_dmmap(char *dmmap_package, char *section_type, char *orig_section_name);
struct uci_section *get_dup_section_in_config_opt(char *package, char *section_type, char *opt_name, char *opt_value);
struct uci_section *get_dup_section_in_dmmap_opt(char *dmmap_package, char *section_type, char *opt_name, char *opt_value);
struct uci_section *get_dup_section_in_dmmap_eq(char *dmmap_package, char* section_type, char*sect_name, char *opt_name, char* opt_value);
struct uci_section *get_section_in_dmmap_with_options_eq(char *dmmap_package, char *section_type, char *opt1_name, char *opt1_value, char *opt2_name, char *opt2_value);
bool elt_exists_in_array(char **str_array, char *str, int length);
int get_shift_utc_time(int shift_time, char *utc_time, int size);
int get_shift_time_time(int shift_time, char *local_time, int size);
struct uci_section *is_dmmap_section_exist(char* package, char* section);
struct uci_section *is_dmmap_section_exist_eq(char* package, char* section, char* opt, char* value);
int dm_read_sysfs_file(const char *file, char *dst, unsigned len);
int get_net_iface_sysfs(const char *uci_iface, const char *name, char **value);
int get_net_device_sysfs(const char *device, const char *name, char **value);
int get_net_device_status(const char *device, char **value);
int dm_time_utc_format(time_t ts, char **dst);
int dm_time_format(time_t ts, char **dst);
void convert_string_to_hex(const char *str, char *hex, size_t size);
void convert_hex_to_string(const char *hex, char *str, size_t size);
void convert_str_option_to_hex(unsigned int tag, const char *str, char *hex, size_t size);
void convert_hex_option_to_string(unsigned int tag, const char *hex, char *str, size_t size);
bool match(const char *string, const char *pattern);
int dm_validate_string(char *value, int min_length, int max_length, char *enumeration[], char *pattern[]);
int dm_validate_boolean(char *value);
int dm_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_int(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_long(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_dateTime(char *value);
int dm_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size);
int dm_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[]);
int dm_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int dm_validate_int_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int dm_validate_unsignedLong_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int dm_validate_long_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
int dm_validate_hexBinary_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);
char *base64_decode(const char *src);
void string_to_mac(const char *str, size_t str_len, char *out, size_t out_len);
bool folder_exists(const char *path);
bool file_exists(const char *path);
bool is_regular_file(const char *path);
unsigned long file_system_size(const char *path, const enum fs_size_type_enum type);
char *replace_char(char *str, char find, char replace);
char *replace_str(const char *str, const char *substr, const char *replacement);
int dm_file_to_buf(const char *filename, void *buf, size_t buf_size);
int check_browse_section(struct uci_section *s, void *data);
int parse_proc_intf6_line(const char *line, const char *device, char *ipstr, size_t str_len);
char *ioctl_get_ipv4(char *interface_name);
char *ifaddrs_get_global_ipv6(char *interface_name);
bool validate_blob_message(struct blob_attr *src, struct blob_attr *dst);
void strip_lead_trail_whitespace(char *str);
int dm_buf_to_file(char *buf, const char *filename);
#endif
