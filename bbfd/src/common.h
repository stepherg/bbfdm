#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <regex.h>
#include <sys/param.h>
#include <string.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/utils.h>
#include <libubox/list.h>

#define ROOT_NODE "Device."
#define USP "usp"
#define USPRAW "usp.raw"
#define USPEXT "usp.Device."
#define USP_ADD_EVENT "usp.AddObj"
#define USP_DEL_EVENT "usp.DelObj"

#define MAX_DM_KEY_LEN 256
#define MAX_DM_PATH 1024
#define MAX_DM_VALUE 4096
#define DM_VALUE_SEP ","
#define DELIM '.'

#define GLOB_CHAR "[[+*]+"
#define GLOB_EXPR "[=><]+"
#define GLOB_USP_PATH "[+#=><]+"

#define USP_ERR_OK                        0

bool match(const char *string, const char *pattern);
bool is_str_eq(const char *s1, const char *s2);
bool is_node_instance(char *path);
int count_delim(const char *path);
bool get_uci_option_string(char *package, char *section,
			   char *option, char **value);

void set_debug_level(unsigned char level);
void print_error(const char *format, ...);
void print_warning(const char *format, ...);
void print_info(const char *format, ...);
void print_debug(const char *format, ...);
bool get_boolean_string(char *value);
bool validate_msglen(struct blob_buf *bb);


#define DEBUG(fmt, args...) \
	print_debug("[%s:%d]"fmt, __func__, __LINE__, ##args)

#define INFO(fmt, args...) \
	print_info(fmt, ##args)

#define ERR(fmt, args...) \
	print_error("[%s:%d] " fmt, __func__, __LINE__, ##args)

#define WARNING(fmt, args...) \
	print_warning("[%s:%d] " fmt, __func__, __LINE__, ##args)

// glibc doesn't guarantee a 0 termianted string on strncpy
// strncpy with always 0 terminated string
static inline void strncpyt(char *dst, const char *src, size_t n)
{
        if (n > 1) {
                strncpy(dst, src, n - 1);
                dst[n - 1] = 0;
        }
}

#endif /* COMMON_H */
