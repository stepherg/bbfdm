# Migration of deprecated/removed APIs and user defined datatypes

To support new feature sometimes old APIs provided by libbbfdm-api library needs to be updated, this guide provides a better context to the migration.

Following table has deprecated and new APIs, datatypes:

| Type | Deprecated API | New API | Comment |
| ---- | -------------- | ------- | ------- |
| function | `int bbf_get_reference_param(char *path, char *key_name, char *key_value, char **value)` | `int bbfdm_get_references(struct dmctx *ctx, int match_action, const char *base_path, char *key_name, char *key_value, char *out, size_t out_len)` | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| function | `int bbf_get_reference_args(char *value, struct dm_reference *reference_args)` | `int bbfdm_get_reference_linker(struct dmctx *ctx, char *reference_path, struct dm_reference *reference_args)` | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| stucture | `struct dmmap_dup` | `structure dm_data` | Replaced to support the extension for Obj/Param/Operate using JSON plugin |


Following table has removed and new APIs, datatypes:

| Type | Removed API | New API | Comment |
| ---- | -------------- | ------- | ------- |
| function | `dm_validate_string(char *value, int min_length, int max_length, char *enumeration[], char *pattern[])` | `int bbfdm_validate_string(struct dmctx *ctx, char *value, int min_length, int max_length, char *enumeration[], char *pattern[])`| Replace to support fault_msg in case of errors |
| function | `bbf_validate_string(char *value, int min_length, int max_length, char *enumeration[], char *pattern[])` | `int bbfdm_validate_string(struct dmctx *ctx, char *value, int min_length, int max_length, char *enumeration[], char *pattern[])`| Replace to support fault_msg in case of errors |
| function | `bbf_validate_boolean(char *value)` | `int bbfdm_validate_boolean(struct dmctx *ctx, char *value)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedInt(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_int(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_int(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedLong(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_long(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_long(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_dateTime(char *value)` | `int bbfdm_validate_dateTime(struct dmctx *ctx, char *value)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_hexBinary(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])` | `int bbfdm_validate_string_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedInt_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_int_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_int_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_unsignedLong_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedLong_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `bbf_validate_long_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_long_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)`| Replace to support fault_msg in case of errors |
| function | `bbf_validate_hexBinary_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_hexBinary_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_boolean(char *value)` | `int bbfdm_validate_boolean(struct dmctx *ctx, char *value)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_unsignedInt(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedInt(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_int(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_int(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_unsignedLong(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedLong(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_long(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_long(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_dateTime(char *value)` | `int bbfdm_validate_dateTime(struct dmctx *ctx, char *value)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_hexBinary(char *value, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_hexBinary(struct dmctx *ctx, char *value, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_string_list(char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])` | `int bbfdm_validate_string_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, int min, int max, char *enumeration[], char *pattern[])` | Replace to support fault_msg in case of errors |
| function | `dm_validate_unsignedInt_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedInt_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_int_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_int_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_unsignedLong_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_unsignedLong_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `dm_validate_long_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_long_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)`| Replace to support fault_msg in case of errors |
| function | `dm_validate_hexBinary_list(char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | `int bbfdm_validate_hexBinary_list(struct dmctx *ctx, char *value, int min_item, int max_item, int max_size, struct range_args r_args[], int r_args_size)` | Replace to support fault_msg in case of errors |
| function | `int dm_entry_validate_allowed_objects(struct dmctx *ctx, char *value, char *objects[])` | `int dm_validate_allowed_objects(struct dmctx *ctx, struct dm_reference *reference, char *objects[])` | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| function | `int dm_entry_validate_external_linker_allowed_objects(struct dmctx *ctx, char *value, char *objects[])` | `int dm_validate_allowed_objects(struct dmctx *ctx, struct dm_reference *reference, char *objects[])` | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| function | `int adm_entry_get_linker_param(struct dmctx *ctx, char *param, char *linker, char **value)` | | Removed, no more required |
| function | `int adm_entry_get_linker_value(struct dmctx *ctx, char *param, char **value)` | | Removed, no more required |
| enum | `CMD_SUCCESS` | | Removed, no more required |
| enum | `CMD_INVALID_ARGUMENTS` | | Removed, no more required |
| enum | `CMD_FAIL` | | Removed, no more required |
| enum | `CMD_NOT_FOUND` | | Removed, no more required |
| enum | `__STATUS_MAX` | | Removed, no more required |

