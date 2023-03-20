# Third party data model integration

It is also possible to itegrate thrid party data model to the uspd to expose it to the ubus. To do so certain APIs in data model library needs to be implemented to make the data model compatible with uspd. APIs are described below.


## List of libbbf methods used in uspd to integrate third party data model

### Refernces
Deatils of bbf data model librabry can be found at [link](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/docs)

following are the  libbbf methods used in uspd to access the data model defined in libbbf

```	dm_get_supported_dm
	dm_entry_param_method
	dm_entry_apply
	dm_ctx_init
	dm_ctx_init_sub
	dm_ctx_clean
	dm_ctx_clean_sub
	set_bbfdatamodel_type
	dm_entry_restart_services
	dm_entry_revert_changes
	dm_debug_browse_path
	get_dm_type
	dm_entry_manage_services
	dm_config_ubus


```

## Methods
Description of the methods are given below

### dm_get_supported_dm

used to get the complete data model schema in one browse

```
int dm_get_supported_dm(struct dmctx *ctx, char *path, bool first_level, schema_type_t schema_type)

inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture. The list of parameters will be updated in ctx.list_parameter. each node in the list is of type
		struct dm_parameter which contains char *name (name of the parameter), char *data, char *type and char *additional_data;
		the content of fields are as follows-
		
		| Type       	| Data		| Addtional Data		|
		|-------------	|------------	|---------------------		|
		|DMT_COMMAND	|in parameters	|command type(sync/async)	|
		|		|out parameter	|				|
		|DMT_EVENT	|in parameters	|NA		   		|
		|$ref(type)	|writable(0/1)	|unique keys	   		|
		|		|		|				|

	char * path
		Complete object element path for which the data model schema is to be read. default path is "Device." 
	
	bool first_level
		if true, read only  paramters at next level to path
		
	schem_type_t schema_type
		enumeration to type of the schema to be get. Possible values are
		ALL_SCHEMA 	- Complete schema
		PARAM_ONLY 	- Parameters only
		EVENT_ONLY	- Events only
		COMMAND_ONLY	- Commands only

return
	int fault
		contains the fault code if API is not able to read the data model.	
```
### dm_entry_param_method

used to read the data model based on the input given

``` 
int dm_entry_param_method(struct dmctx *ctx, int cmd, char *inparam, char *arg1, char *arg2)

inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture. The list of parameter will be updated in ctx.list_parameter. each node in the list is of type
		struct dm_parameter which contains char *name, char *data, char *type and char *additional_data;
		the content of fields  are updated based on the cmd and are as follows-
		cmd			| Name       	| Type       	| Data			| Addtional Data	|
		|-------------		|-------------	|-------------	|------------		|---------------------	|
		|CMD_GET_VALUE		|Parameter	|$ref(type)	|Value			|	NA		|
		|CMD_GET_NAME		|Parameter	|$ref(type)	|writable(0/1)		|	NA		|
		|CMD_SET_VALUE		|path 		|	NA	| 	NA		|	NA	   	|
		|CMD_ADD_OBJECT	|path		|	NA	| 	NA		|	NA	   	|
		|CMD_DEL_OBJECT	|path		|	NA	| 	NA		|	NA	   	|
		|CMD_USP_OPERATE	|path		|	NA	| 	NA		|	NA	   	|
		|CMD_USP_LIST_OPERATE	|parameter	|DMT_COMMAND	|in/out parameters	|cmd type (sync/async)	|
		|CMD_USP_LIST_EVENT	|paramter	|DMT_EVENT	|in parameters		|NA	   		|
		|CMD_GET_SCHEMA	|paramter	||$ref(type)	|writable(0/1)		|unique keys  		|
		|CMD_GET_INSTANCES	|parameter	| NA		|NA			|NA		   	|
		
	int cmd
		command to API to tell how the data model is to be read, possible values are
		CMD_GET_VALUE		-	Read the values of the parameters from data model
		CMD_GET_NAME 		-	Read the names of the parameters from data model
		CMD_SET_VALUE		-	Set value of specified parameters in the data model
		CMD_ADD_OBJECT		-	Add object in a multi instance parameter in the data model
		CMD_DEL_OBJECT		-	Delete object from a multi instance parameter in the data model	
		CMD_USP_OPERATE	- 	execute the specified command
		CMD_USP_LIST_OPERATE	- 	Read all the command type parameter from data model.	
		CMD_USP_LIST_EVENT	- 	Read all the event type parameter from data model.
		CMD_GET_SCHEMA		- 	Read all the parameter type parameter from data model.
		CMD_GET_INSTANCES	-	Read all the instance of multi instance parameter from data model.
	
	char * inparam
		Complete object element path for which the data model schema is to be read. default path is "Device." 
		
	char *arg1 and char *arg2
		arguments specific to commands.

return
	int fault
		contains the fault code if API is not able to read the data model. returns 0 on success.	
```
### dm_entry_apply

This method is called to apply the changes done to data model. used with set_value

```
int dm_entry_apply(struct dmctx *ctx, int cmd)

inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture. The list of parameter will be updated in ctx.list_parameter
	
	int cmd
		command to API to tell how the data model is to be read, possible values are

		CMD_SET_VALUE		-	Set value of specified parameters in the data model
		
	char *arg1

return
	int fault
		contains the fault code if API is not able to read the data model.	
```
### dm_ctx_init

This method is used to initialize the dmctx structure object to read the data model.

``` 
int dm_ctx_init(struct dmctx *ctx, unsigned int instance_mode)
inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture to be initialized.
	
	unsigned int instance_mode
		instance mode of the dmctx to be set. 
return
	int fault
		returns 0 on success.
```

### dm_ctx_init_sub

This method is an extension of dm_ctx_init method. only difference it only intializes dmctx structure object and does not intializes other resources used in reading data model

``` 
int dm_ctx_init_sub(struct dmctx *ctx, unsigned int instance_mode)
inputs
	struct dmctx *ctx
		pointer to struct dmctx strunture to be initialized.
	
	unsigned int instance_mode
		instance mode of the dmctx to be set. 
return
	int fault
		returns 0 on success.
```


### dm_ctx_clean

This method is used to free the dmctx structure object  and other resources post reading the data model.

```
int dm_ctx_clean(struct dmctx *ctx)

input
	struct dmctx *ctx
		pointer to struct dmctx strunture to be freed.
	
return
	int fault
		returns 0 on success.
		
```

### dm_ctx_clean_sub

This method is an extension of dm_ctx_clean method. only difference is it frees the dmctx structure and does not free other resources used in reading data model

```
int dm_ctx_clean_sub(struct dmctx *ctx)

input
	struct dmctx *ctx
		pointer to struct dmctx strunture to be freed.
	
return
	int fault
		returns 0 on success.

```
### set_bbfdatamodel_type

This method is used to set the type of protocol for which the data model is to be read
```
int set_bbfdatamodel_type(int bbf_type)

input
	int cmd
		the protocol through which the data model is to be read, possible values are
		BBFDM_USP  - Protocol USP
		BBFDM_CWMP - Protocol CWMP
		BBFDM_BOTH - Both USP and CWMP

return
	int 
		returns 0 on success.
```
### dm_entry_restart_services

This method is used to restart the state of data model whenever its state is changed

```
int dm_entry_restart_services(void)

input
	None
	
return
	int 
		returns 0 on success.
```
### dm_entry_revert_changes

This method is used to restart the state of data model whenever its state is changed

```
int dm_entry_revert_changes(void)

input
	None
	
return
	int 
		returns 0 on success.
```


### dm_debug_browse_path

This method returns the last accessed path in the data model

``` 
int dm_debug_browse_path(char *buff, size_t len)
input 
	char *buff
		pointer to the buffer in which the path will be returned
	size_t len
		length of the buffer
return
	int 
		returns 0 on success.
```


### get_dm_type

This method is used to get the type assigned to the data model parameter.

```
int get_dm_type(char *dm_str)

input 
	char *dm_str
		data model parameter type, eg. xsd:string, xsd:unit etc.

return
	int 
		type of data model assigned to the object eg. DMT_STRING, DMT_UNINT etc.

```

### dm_entry_manage_services
 This method is used to commit the changes made to the data model using either ubus call or uci commit.
 
``` 
int dm_entry_manage_services(struct blob_buf *bb, bool restart)

input
	struct blob_buf *bb
		pointer to the struct blob_buf object. contains all the packages updated.
	bool restart 
		if true packages will be updated through ubus call.
		if false packages will be updated through uci.
	
return 
	int - returns 0 on success.
```

### dm_entry_restart_services 

this method is used to  commit all the changes made to the data model.

``` 
int dm_entry_restart_services(void)

return 
	int -  returns 0 on success.
```
### dm_config_ubus 
This method is used to configure ubus.

``` 
void dm_config_ubus(struct ubus_context *ctx)

input
	struct ubus_context *ctx
		pointer to struct ubus_context object to be intialized.	
