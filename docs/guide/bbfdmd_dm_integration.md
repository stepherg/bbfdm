# Third party data model integration

It is also possible to itegrate thrid party data model to the bbfdmd to expose it to the ubus. To do so certain APIs in libbbfdm-api needs to be implemented to make the data model compatible with bbfdmd. APIs are described below.


## List of libbbfdm-api methods used in bbfdmd to integrate third party data model

### Refernces
Deatils of libbbfdm-api can be found at [link](../../docs)

following are the libbbfdm-api methods used in bbfdmd to access the data model defined in libbbfdm

```	
bbf_entry_method
bbf_ctx_init
bbf_ctx_init_sub
bbf_ctx_clean
bbf_ctx_clean_sub
bbf_entry_restart_services
bbf_entry_revert_changes
```

## Methods
Description of the methods are given below

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
		if true packages will be updated through ubus call.
		if false packages will be updated through uci.
	
return 
	None
```
### bbf_entry_revert_changes

This method is used to revert the changes whenever its state is changed

```
void bbf_entry_revert_changes(struct blob_buf *bb)

input
	struct blob_buf *bb
		pointer to the struct blob_buf object. contains all the packages updated.
	
return
	None
```

### Datamodel Tree
`libbbfdm-api` provides API to easily extend and define datamodel tree.

#### Alias handling
In general datamodel parameters with multi-instance objects has a parameter named as '.Alias' to uniquely identify the instance. libbbf-api provides two generic APIs to handle the get/set of Alias parameters.

These APIs only applicable for standard/dmmap uci mappings.
```bash
/*********************************************************************//**
**
** bbf_get_alias
**
** This API is used to get the Alias parameter value based on s and option_name
**
** \param   ctx - bbf context
** \param   s - uci section from where will get Alias value
** \param   option_name - option name
** \param   instance - instance value
** \param   value - pointer to where the value will be stored
**
** \return  0 if operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_get_alias(struct dmctx *ctx, struct uci_section *s, char *option_name, char *instance, char **value);

/*********************************************************************//**
**
** bbf_set_alias
**
** This API is used to set the Alias parameter value
**
** \param   ctx - bbf context
** \param   s - uci section to where will save Alias value
** \param   option_name - option name
** \param   instance - instance value
** \param   value - the value to be set
**
** \return  0 if operation is successful, -1 otherwise
**
**************************************************************************/
int bbf_set_alias(struct dmctx *ctx, struct uci_section *s, char *option_name, char *instance, char *value);
```

Example:
```bash
static int get_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return bbf_get_alias(ctx, ((struct dm_data *)data)->dmmap_section, "endpointalias", instance, value);
}

static int set_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	return bbf_set_alias(ctx, ((struct dm_data *)data)->dmmap_section, "endpointalias", instance, value);
}
```
