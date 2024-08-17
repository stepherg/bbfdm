# API guide and usages

`libbbfdm-api` provides API to define datamodel objects as well as it also provides APIs to traverse the datamodel definitions.

Most used datamodel APIs described in [libbbfdm_api.h](../../libbbfdm-api/include/libbbfdm_api.h)

Following is the list of APIs used by bbfdmd for tree traversal:

### bbf_entry_method

used to read the data model based on the input given

```
int bbf_entry_method(struct dmctx *ctx, int cmd)

inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture. The list of parameter will be updated in ctx.list_parameter. each node in the list is of type
		struct dm_parameter which contains char *name, char *data, char *type and char *additional_data;
		the content of fields  are updated based on the cmd and are as follows-
		cmd			| Name       	| Type       	| Data			| Addtional Data	|
		|-------------		|-------------	|-------------	|------------		|---------------------	|
		|BBF_GET_VALUE		|Parameter	|$ref(type)	|Value			|	NA		|
		|BBF_GET_NAME		|Parameter	|$ref(type)	|writable(0/1)		|	NA		|
		|BBF_SET_VALUE		|path 		|	NA	| 	NA		|	NA	   	|
		|BBF_ADD_OBJECT	|path		|	NA	| 	NA		|	NA	   	|
		|BBF_DEL_OBJECT	|path		|	NA	| 	NA		|	NA	   	|
		|BBF_OPERATE	|path		|	NA	| 	NA		|	NA	   	|
		|BBF_SCHEMA	|paramter	||$ref(type)	|writable(0/1)		|unique keys  		|
		|BBF_INSTANCES	|parameter	| NA		|NA			|NA		   	|
		|BBF_EVENT	|path		|	NA	| 	NA		|	NA	   	|
		
	int cmd
		command to API to tell how the data model is to be read, possible values are
		BBF_GET_VALUE		-	Read the values of the parameters from data model
		BBF_GET_NAME 		-	Read the names of the parameters from data model
		BBF_SET_VALUE		-	Set value of specified parameters in the data model
		BBF_ADD_OBJECT		-	Add object in a multi instance parameter in the data model
		BBF_DEL_OBJECT		-	Delete object from a multi instance parameter in the data model	
		BBF_OPERATE			- 	execute the specified command
		BBF_SCHEMA			- 	Read all the parameter type parameter from data model.
		BBF_INSTANCES		-	Read all the instance of multi instance parameter from data model.
		BBF_EVENT			-	execute the specified event

return
	int fault
		contains the fault code if API is not able to read the data model. returns 0 on success.	
```

### bbf_ctx_init

This method is used to initialize the dmctx structure object to read the data model.

```
void bbf_ctx_init(struct dmctx *ctx, DMOBJ *tEntryObj);
inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture to be initialized.

return
	None
```

### bbf_ctx_init_sub

This method is an extension of bbf_ctx_init method. only difference it only intializes dmctx structure object and does not intializes other resources used in reading data model

```
void bbf_ctx_init_sub(struct dmctx *ctx, DMOBJ *tEntryObj)
inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture to be initialized.

return
	None
```


### bbf_ctx_clean

This method is used to free the dmctx structure object  and other resources post reading the data model.

```
void bbf_ctx_clean(struct dmctx *ctx)

input
	struct dmctx *ctx
		pointer to struct dmctx strunture to be freed.
	
return
	None	
```

### bbf_ctx_clean_sub

This method is an extension of bbf_ctx_clean method. only difference is it frees the dmctx structure and does not free other resources used in reading data model

```
void bbf_ctx_clean_sub(struct dmctx *ctx)

input
	struct dmctx *ctx
		pointer to struct dmctx strunture to be freed.
	
return
	None
```

### bbf_entry_restart_services

This method is used to restart the state of data model whenever its state is changed

```
void bbf_entry_restart_services(struct blob_buf *bb, bool restart_services)

input
	struct blob_buf *bb
		pointer to the struct blob_buf object. contains all the packages updated.

	bool restart_services
		if true packages will be updated through ubus call bbf.config internally.
		if false packages will be updated through ubus call bbf.config externally.
	
return
	None
```
### bbf_entry_revert_changes

This method is used to revert the changes whenever its state is changed

```
void bbf_entry_revert_changes(struct blob_buf *bb, bool revert_changes)

input
	struct blob_buf *bb
		pointer to the struct blob_buf object. contains all the packages updated.

	bool revert_changes
		if true changes will be reverted through ubus call bbf.config internally.
		if false changes will be reverted through ubus call bbf.config externally.
	
return
	None
```

# Deprecated/removed APIs and user defined datatypes

To support new feature sometimes old APIs provided by libbbfdm-api library needs to be updated, this guide provides a better context to the migration.

Following table has APIs/datatypes which are now deprecated:

| Type     | Deprecated API            | New API                      | Comment |
| -------- | ------------------------- | ---------------------------- | ------- |
| function | `bbf_get_reference_param` | `bbfdm_get_references`       | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| function | `bbf_get_reference_args`  | `bbfdm_get_reference_linker` | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| stucture | `dmmap_dup`               | `dm_data`                    | Replaced to support the extension for Obj/Param/Operate using JSON plugin |


Following table has list of APIs/datatypes which no longer exists in libbbfdm-api, along with new revised APIs replacement:

|   Type   |      Removed API                   | New API  	                    	| Comment                                |
| -------- | ---------------------------------- | ------------------------------------ 	| -------------------------------------- |
| function | `dm_validate_string`       	| `bbfdm_validate_string`      		| To support fault_msg in case of errors |
| function | `bbf_validate_string`      	| `bbfdm_validate_string`      		| To support fault_msg in case of errors |
| function | `bbf_validate_boolean`     	| `bbfdm_validate_boolean`     		| To support fault_msg in case of errors |
| function | `bbf_validate_unsignedInt` 	| `bbfdm_validate_unsignedInt` 		| To support fault_msg in case of errors |
| function | `bbf_validate_int`         	| `bbfdm_validate_int`         		| To support fault_msg in case of errors |
| function | `bbf_validate_unsignedLong`	| `bbfdm_validate_unsignedLong`		| To support fault_msg in case of errors |
| function | `bbf_validate_long`        	| `bbfdm_validate_long`        		| To support fault_msg in case of errors |
| function | `bbf_validate_dateTime`    	| `bbfdm_validate_dateTime`    		| To support fault_msg in case of errors |
| function | `bbf_validate_hexBinary`   	| `bbfdm_validate_hexBinary`   		| To support fault_msg in case of errors |
| function | `bbf_validate_string_list` 	| `bbfdm_validate_string_list` 		| To support fault_msg in case of errors |
| function | `bbf_validate_unsignedInt_list` 	| `bbfdm_validate_unsignedInt_list` 	| To support fault_msg in case of errors |
| function | `bbf_validate_int_list`    	| `bbfdm_validate_int_list`    		| To support fault_msg in case of errors |
| function | `bbf_validate_unsignedLong_list` 	| `bbfdm_validate_unsignedLong_list` 	| To support fault_msg in case of errors |
| function | `bbf_validate_long_list`   	| `bbfdm_validate_long_list`   		| To support fault_msg in case of errors |
| function | `bbf_validate_hexBinary_list` 	| `bbfdm_validate_hexBinary_list` 	| To support fault_msg in case of errors |
| function | `dm_validate_boolean` 		| `bbfdm_validate_boolean` 		| To support fault_msg in case of errors |
| function | `dm_validate_unsignedInt` 		| `bbfdm_validate_unsignedInt` 		| To support fault_msg in case of errors |
| function | `dm_validate_int` 			| `bbfdm_validate_int` 			| To support fault_msg in case of errors |
| function | `dm_validate_unsignedLong` 	| `bbfdm_validate_unsignedLong` 	| To support fault_msg in case of errors |
| function | `dm_validate_long` 		| `bbfdm_validate_long` 		| To support fault_msg in case of errors |
| function | `dm_validate_dateTime` 		| `bbfdm_validate_dateTime` 		| To support fault_msg in case of errors |
| function | `dm_validate_hexBinary` 		| `bbfdm_validate_hexBinary` 		| To support fault_msg in case of errors |
| function | `dm_validate_string_list` 		| `bbfdm_validate_string_list` 		| To support fault_msg in case of errors |
| function | `dm_validate_unsignedInt_list` 	| `bbfdm_validate_unsignedInt_list` 	| To support fault_msg in case of errors |
| function | `dm_validate_int_list` 		| `bbfdm_validate_int_list` 		| To support fault_msg in case of errors |
| function | `dm_validate_unsignedLong_list` 	| `bbfdm_validate_unsignedLong_list` 	| To support fault_msg in case of errors |
| function | `dm_validate_long_list` 		| `bbfdm_validate_long_list`		| To support fault_msg in case of errors |
| function | `dm_validate_hexBinary_list` 	| `bbfdm_validate_hexBinary_list` 	| To support fault_msg in case of errors |
| function | `dm_entry_validate_allowed_objects`| `dm_validate_allowed_objects` 	| Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| function | `dm_entry_validate_external_linker_allowed_objects` | `dm_validate_allowed_objects` | Replaced with a generic API that is accessible for both internal (bbfdm core) and external (microservices) data models |
| function | `add_list_parameter` | | Removed, no more required |
| function | `free_all_list_parameter` | | Removed, no more required |
| function | `adm_entry_get_linker_param` 	| | Removed, no more required |
| function | `adm_entry_get_linker_value` 	| | Removed, no more required |
| enum 	   | `CMD_SUCCESS` 			| | Removed, no more required |
| enum 	   | `CMD_INVALID_ARGUMENTS` 		| | Removed, no more required |
| enum     | `CMD_FAIL` 			| | Removed, no more required |
| enum     | `CMD_NOT_FOUND` 			| | Removed, no more required |
| enum     | `__STATUS_MAX` 			| | Removed, no more required |

