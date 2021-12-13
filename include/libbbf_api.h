/*
 * Copyright (C) 2021 IOPSYS Software Solutions AB
 *
 * Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/**
 * \file libbbf_api.h
 *
 * This Library provides APIs for UCI, UBUS, JSON and memory management.
 */

#ifndef __LIBBBF_API_H__
#define __LIBBBF_API_H__

#include <uci.h>
#include <libubox/list.h>
#include <json-c/json.h>

#include "libbbf_api/dmapi.h"

/*******************
 *
 * BBF UCI API
 *
 ******************/

#define bbf_uci_foreach_sections(package, stype, section) \
	for (section = bbf_uci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = bbf_uci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION))

#define bbf_uci_foreach_sections_safe(package, stype, _tmp, section) \
	for (section = bbf_uci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? bbf_uci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? bbf_uci_walk_section(package, stype, NULL, NULL, CMP_SECTION, NULL, section, GET_NEXT_SECTION) : NULL)

#define bbf_uci_foreach_option_eq(package, stype, option, val, section) \
	for (section = bbf_uci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, NULL, GET_FIRST_SECTION); \
		section != NULL; \
		section = bbf_uci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION))

#define bbf_uci_foreach_option_eq_safe(package, stype, option, val, _tmp, section) \
	for (section = bbf_uci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, NULL, GET_FIRST_SECTION), \
		_tmp = (section) ? bbf_uci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? bbf_uci_walk_section(package, stype, option, val, CMP_OPTION_EQUAL, NULL, section, GET_NEXT_SECTION) : NULL)

#define section_name(s) s ? (s)->e.name : ""
#define section_type(s) s ? (s)->type : ""
#define section_config(s) s ? (s)->package->e.name : ""


/*********************************************************************//**
**
** bbf_uci_add_section
**
** This API is to add a new unnamed section under the default uci config path('/etc/config/')
**
** \param   package - package name to add the section
** \param   type - section type name
** \param   s - pointer to store a reference to the new section in
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_add_section(char *package, char *type, struct uci_section **s);

/*********************************************************************//**
**
** bbf_uci_delete_section
**
** This API is to delete a section or option under the default uci config path('/etc/config/')
**
** \param   package - package name to delete the section
** \param   type - section type name
** \param   option - option name
** \param   value - not used (must be removed later)
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_delete_section(char *package, char *type, char *option, char *value);

/*********************************************************************//**
**
** bbf_uci_add_section_bbfdm
**
** This API is to add a new unnamed section under the path '/etc/bbfdm/dmmap/'
**
** \param   package - package name to add the section
** \param   type - section type name
** \param   s - pointer to store a reference to the new section in
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_add_section_bbfdm(char *package, char *type, struct uci_section **s);

/*********************************************************************//**
**
** bbf_uci_delete_section_bbfdm
**
** This API is to delete a section or option under the path '/etc/bbfdm/dmmap/'
**
** \param   package - package name to delete the section
** \param   type - section type name
** \param   option - option name
** \param   value - not used (must be removed later)
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_delete_section_bbfdm(char *package, char *type, char *option, char *value);

/*********************************************************************//**
**
** bbf_uci_rename_section
**
** This API is to rename the section name
**
** \param   s - pointer to the uci section to rename
** \param   value - new uci section name
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_rename_section(struct uci_section *s, char *value);

/*********************************************************************//**
**
** bbf_uci_get_value
**
** This API is to get an uci option value
**
** \param   package - package name
** \param   section - section name
** \param   option - option name
** \param   value - pointer to the option value
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_get_value(char *package, char *section, char *option, char **value);

/*********************************************************************//**
**
** bbf_uci_set_value
**
** This API is to set an uci option value
**
** NOTE: the option will be created if it does not exist
**
** \param   package - package name
** \param   section - section name
** \param   option - option name
** \param   value - value to set to the option
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_set_value(char *package, char *section, char *option, char *value);

/*********************************************************************//**
**
** bbf_uci_get_value_by_section
**
** This API is to get an uci option value from the section pointer of uci context
**
** \param   s - section pointer of uci context
** \param   option - option name
** \param   value - pointer to the option value
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_get_value_by_section(struct uci_section *s, char *option, char **value);

/*********************************************************************//**
**
** bbf_uci_get_value_by_section_fallback_def
**
** This API is to get an uci option value from the section pointer of uci context and
**    return the default value if uci option value is empty
**
** \param   s - section pointer of uci context
** \param   option - option name
** \param   default_value - default value to return if the uci option value is empty
**
** \return  uci option value if the value is not empty, empty otherwise
**
**************************************************************************/
char *bbf_uci_get_value_by_section_fallback_def(struct uci_section *s, char *option, char *default_value);

/*********************************************************************//**
**
** bbf_uci_set_value_by_section
**
** This API is to set an uci option value from the section pointer of uci context
**
** \param   s - section pointer of uci context
** \param   option - option name
** \param   value - value to set to the option
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_set_value_by_section(struct uci_section *s, char *option, char *value);

/*********************************************************************//**
**
** bbf_uci_delete_section_by_section
**
** This API is to delete a section or option from the section pointer of uci context
**
** \param   s - section pointer of uci context
** \param   option - option name
** \param   value - not used (must be removed later)
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_uci_delete_section_by_section(struct uci_section *s, char *option, char *value);


struct uci_section *bbf_uci_walk_section(char *package, char *type, void *arg1, void *arg2, int cmp, int (*filter)(struct uci_section *s, void *value), struct uci_section *prev_section, int walk);


/*******************
 *
 * BBF UBUS API
 *
 ******************/

/*********************************************************************//**
**
** bbf_ubus_call
**
** This API is to get the json output of ubus call
**
** \param   obj - ubus object name
** \param   method - ubus method name
** \param   u_args - ubus arguments
** \param   u_args_size - number of ubus arguments
** \param   req_res - pointer to the json object message. it could be NULL if the json object is not found
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_ubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res);

/*********************************************************************//**
**
** bbf_ubus_call_set
**
** This API is to execute the ubus call without getting the json output
**
** \param   obj - ubus object name
** \param   method - ubus method name
** \param   u_args - ubus arguments
** \param   u_args_size - number of ubus arguments
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_ubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size);


/*******************
 *
 * BBF MEMORY MANAGEMENT API
 *
 ******************/

/*********************************************************************//**
**
** bbf_malloc
**
** This API is to allocate the requested memory using malloc().
**
** \param   size - number of bytes to allocate
**
** \return  pointer to the allocated memory if the operation is successful, NULL otherwise
**
**************************************************************************/
void *bbf_malloc(size_t size);

/*********************************************************************//**
**
** bbf_calloc
**
** This API is to allocate the requested memory using calloc().
**
** \param   nitems - number of elements to allocate
** \param   size - size of elements
**
** \return  pointer to the allocated memory if the operation is successful, NULL otherwise
**
**************************************************************************/
void *bbf_calloc(int nitems, size_t size);

/*********************************************************************//**
**
** bbf_realloc
**
** This API is to reallocate the memory using realloc().
**
** \param   ptr - pointer to current buffer than needs reallocating
** \param   size - number of bytes to reallocate
**
** \return  pointer to the reallocated memory if the operation is successful, NULL otherwise
**
**************************************************************************/
void *bbf_realloc(void *ptr, size_t size);

/*********************************************************************//**
**
** bbf_strdup
**
** This API is to copy a specific number of bytes from a string using malloc() and memcpy().
**
** NOTE: This function treats a NULL input string, as a NULL output
**
** \param   ptr - pointer to buffer containing string to copy
**
** \return  pointer to the new string if the operation is successful, NULL otherwise
**
**************************************************************************/
char *bbf_strdup(const char *ptr);


/*******************
 *
 * BBF API
 *
 ******************/

/*********************************************************************//**
**
** bbf_synchronise_config_sections_with_dmmap
**
** This API is to synchronise uci sections under the '/etc/config/' path with dmmap uci sections under the '/etc/bbfdm/dmmap/' path
**
** NOTE: bbf_free_config_sections_list should be called to free
**       the allocated resources used in this API.
**
** \param   package - package name
** \param   section_type - section type name
** \param   dmmap_package - dmmap package name
** \param   dup_list - pointer to the list of all sections
**
**************************************************************************/
void bbf_synchronise_config_sections_with_dmmap(char *package, char *section_type, char *dmmap_package, struct list_head *dup_list);

/*********************************************************************//**
**
** bbf_free_config_sections_list
**
** This API is to free the allocated resources used in bbf_synchronise_config_sections_with_dmmap function
**
** \param   dup_list - pointer to the list of all sections
**
**************************************************************************/
void bbf_free_config_sections_list(struct list_head *dup_list);

/*********************************************************************//**
**
** bbf_handle_instance
**
** This API is to allow to retrieve/attribute the instances number/alias from uci config sections depending of the request and the instance mode
**
** \param   dmctx - pointer to the bbf context
** \param   parent_node - pointer to the parent node of the object
** \param   s - pointer to the dmmap section
** \param   inst_opt - instance option name
** \param   alias_opt - alias option name
**
** \return  pointer to the instance value if the operation is successful, empty otherwise
**
**************************************************************************/
char *bbf_handle_instance(struct dmctx *dmctx, struct dmnode *parent_node, struct uci_section *s, char *inst_opt, char *alias_opt);

/*********************************************************************//**
**
** bbf_link_instance_object
**
** This API is to link the instance to the data model tree
**
** \param   ctx - pointer to the bbf context
** \param   parent_node - pointer to the parent node of the object
** \param   data - pointer to the data passed to the sub object and parameters
** \param   instance - the current instance linked to the object
**
** \return  0 if the operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_link_instance_object(struct dmctx *ctx, struct dmnode *parent_node, void *data, char *instance);

/*********************************************************************//**
**
** bbf_get_number_of_entries
**
** This API is to get the number of entries for multi-intance object
**
** \param   ctx - bbf context
** \param   data - the data passed from the parent object
** \param   instance - instance number
** \param   browseinstobj - pointer the browse function linked to the object that wants to obtain the instance number
**
** \return  number of entries if the operation is successful, 0 otherwise
**
**************************************************************************/
int bbf_get_number_of_entries(struct dmctx *ctx, void *data, char *instance, int (*browseinstobj)(struct dmctx *ctx, struct dmnode *node, void *data, char *instance));

/*********************************************************************//**
**
** bbf_convert_string_to_bool
**
** This API is to convert string to bool value
**
** \param   str - pointer to string to convert
** \param   b - pointer to bool value
**
** \return  bool value if the operation is successful, false otherwise
**
**************************************************************************/
int bbf_convert_string_to_bool(char *str, bool *b);

/*********************************************************************//**
**
** bbf_find_dmmap_section
**
** This API is to find the dmmap section based on the section name of uci config
**
** \param   dmmap_package - dmmap package name
** \param   section_type - section type
** \param   section_name - section name to find
** \param   dmmap_section - pointer to the dmmap section, it should be 'NULL' if the section is not found
**
**************************************************************************/
void bbf_find_dmmap_section(char *dmmap_package, char *section_type, char *section_name, struct uci_section **dmmap_section);

/*********************************************************************//**
**
** bbf_find_dmmap_section_by_option
**
** This API is to find the dmmap section based on option_name and option_value
**
** \param   dmmap_package - dmmap package name
** \param   section_type - section type
** \param   option_name - option name
** \param   option_value - option value
** \param   dmmap_section - pointer to the dmmap section, it should be 'NULL' if the section is not found
**
**************************************************************************/
void bbf_find_dmmap_section_by_option(char *dmmap_package, char *section_type, char *option_name, char *option_value, struct uci_section **dmmap_section);

/*********************************************************************//**
**
** bbf_validate_string
**
** This API is to validate a string value
**
** \param   value - pointer to the value to validate
** \param   min_length - minimum length allowed, -1 meaning there is no limit
** \param   max_length - maximum length allowed, -1 meaning there is no limit
** \param   enumeration - pointer to an array of strings to validate the string value based on it, NULL meaning there is no enumeration
** \param   pattern - pointer to an array of patterns to validate the string value based on it, NULL meaning there is no pattern
**
** \return  0 if the string value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_string(char *value, int min_length, int max_length, char *enumeration[], char *pattern[]);

/*********************************************************************//**
**
** bbf_validate_boolean
**
** This API is to validate a bool value
**
** \param   value - pointer to the value to validate
**
** \return  0 if the bool value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_boolean(char *value);

/*********************************************************************//**
**
** bbf_validate_unsignedInt
**
** This API is to validate an unsigned int value
**
** \param   value - pointer to the value to validate
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the unsigned int value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_int
**
** This API is to validate a int value
**
** \param   value - pointer to the value to validate
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the int value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_int(char *value, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_unsignedLong
**
** This API is to validate a unsigned long value
**
** \param   value - pointer to the value to validate
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the unsigned long value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_long
**
** This API is to validate a long value
**
** \param   value - pointer to the value to validate
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the long value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_long(char *value, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_dateTime
**
** This API is to validate a date time value
**
** \param   value - pointer to the value to validate
**
** \return  0 if the date time value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_dateTime(char *value);

/*********************************************************************//**
**
** bbf_validate_hexBinary
**
** This API is to validate a hexbinary value
**
** \param   value - pointer to the value to validate
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the hexbinary value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_string_list
**
** This API is to validate a list of string value
**
** \param   value - pointer to the value to validate
** \param   min_item - minimum item allowed in the list, -1 meaning there is no limit
** \param   max_item - maximum item allowed in the list, -1 meaning there is no limit
** \param   max_size - maximum length allowed in the list, -1 meaning there is no limit
** \param   min - minimum length allowed for each string value, -1 meaning there is no limit
** \param   max - maximum length allowed for each string value, -1 meaning there is no limit
** \param   enumeration - pointer to an array of strings to validate the string value based on it, NULL meaning there is no enumeration
** \param   pattern - pointer to an array of patterns to validate the string value based on it, NULL meaning there is no pattern
**
** \return  0 if the list of string value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[]);

/*********************************************************************//**
**
** bbf_validate_unsignedInt_list
**
** This API is to validate a list of unsigned int value
**
** \param   value - pointer to the value to validate
** \param   min_item - minimum item allowed in the list, -1 meaning there is no limit
** \param   max_item - maximum item allowed in the list, -1 meaning there is no limit
** \param   max_size - maximum length allowed in the list, -1 meaning there is no limit
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the list of unsigned int value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_int_list
**
** This API is to validate a list of int value
**
** \param   value - pointer to the value to validate
** \param   min_item - minimum item allowed in the list, -1 meaning there is no limit
** \param   max_item - maximum item allowed in the list, -1 meaning there is no limit
** \param   max_size - maximum length allowed in the list, -1 meaning there is no limit
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the list of int value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_int_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_unsignedLong_list
**
** This API is to validate a list of unsigned long value
**
** \param   value - pointer to the value to validate
** \param   min_item - minimum item allowed in the list, -1 meaning there is no limit
** \param   max_item - maximum item allowed in the list, -1 meaning there is no limit
** \param   max_size - maximum length allowed in the list, -1 meaning there is no limit
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the list of unsigned long value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_unsignedLong_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_long_list
**
** This API is to validate a list of long value
**
** \param   value - pointer to the value to validate
** \param   min_item - minimum item allowed in the list, -1 meaning there is no limit
** \param   max_item - maximum item allowed in the list, -1 meaning there is no limit
** \param   max_size - maximum length allowed in the list, -1 meaning there is no limit
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the list of long value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_long_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);

/*********************************************************************//**
**
** bbf_validate_hexBinary_list
**
** This API is to validate a list of hexBinary value
**
** \param   value - pointer to the value to validate
** \param   min_item - minimum item allowed in the list, -1 meaning there is no limit
** \param   max_item - maximum item allowed in the list, -1 meaning there is no limit
** \param   max_size - maximum length allowed in the list, -1 meaning there is no limit
** \param   r_args - array of allowed range, 'RANGE_ARGS{{NULL,NULL}}' meaning there is no range
** \param   r_args_size - number of allowed range
**
** \return  0 if the list of hexBinary value is valid, -1 otherwise
**
**************************************************************************/
int bbf_validate_hexBinary_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size);

#endif //__LIBBBF_API_H__
