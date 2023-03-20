# Function Specification

The scope of uspd is to expose the datamodel provided by libbbfdm APIs over ubus, along with provididng the features deinfed by requirements R-ARC.7 to R-ARC.12 of USP protocol.

```
root@iopsys:~# ubus -v list usp
'usp' @232da280
	"list_operate":{}
	"get_supported_dm":{"path":"String","next-level":"Boolean","schema_type":"Integer"}
	"get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer"}
	"operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
	"add_object":{"path":"String","proto":"String","instance_mode":"Integer"}
	"del_object":{"path":"String","proto":"String","instance_mode":"Integer"}

root@iopsys:~#
root@iopsys:~# ubus -v list usp.raw
'usp.raw' @4c9c3c6e
	"dump_schema":{}
	"list_operate":{}
	"list_events":{}
	"get_supported_dm":{"path":"String","next-level":"Boolean","schema_type":"Integer"}
	"get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"getm_values":{"paths":"Array","proto":"String","next-level":"Boolean","instance_mode":"Integer"}
	"getm_names":{"paths":"Array","proto":"String","next-level":"Boolean","instance_mode":"Integer"}
	"object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"transaction_start":{"app":"String"}
	"set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
	"add_object":{"path":"String","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"del_object":{"path":"String","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"setm_values":{"pv_tuple":"Array","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"transaction_commit":{"transaction_id":"Integer","restart_services":"Boolean"}
	"transaction_abort":{"transaction_id":"Integer"}
	"transaction_status":{"transaction_id":"Integer"}
	"notify_event":{"name":"String","input":"Table"}

```

# Contents
* [usp](#usp)
* [usp.raw](#uspraw)

## APIs

uspd publishes two different types UBUS objects, `usp`, `usp.raw`. USP object is meant for end users/CLI users
usp.raw is meant for API integration
usp.raw has more ganureality in the function to match the third party apllication requiremtns whereas usp obect take cares of cutomization internally to provide simple interface for the end users.


### usp

An object that publishes device information.

````bash
        "list_operate":{}
	"get_supported_dm":{"path":"String","next-level":"Boolean","schema_type":"Integer"}
	"get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer"}
	"operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
	"add_object":{"path":"String","proto":"String","instance_mode":"Integer"}
	"del_object":{"path":"String","proto":"String","instance_mode":"Integer"}
````

| Method      						|Function ID	|
| :--- 	  					| :---        	|
| [list_operate](#list_operate)			| 1		|
| [get_supported_dm](#get_supported_dm)		| 2		|
| [get](#get)						| 3		|
| [object_names](#object_names)			| 4		|
| [instances](#instances)				| 5		|
| [validate](#validate)				| 6		|
| [set](#set)						| 7		|
| [operate](#operate)		 		        | 8		|
| [add_object](#add_object)			        | 9   		|
| [del_object](#del_object)		    	        | 10		|

#### Methods

Below methods are supported in usp methods. Method description of the `usp` object in succeding paragraphs . 


##### list_operate

Exposes various sync and async operations supported by datamodel. e.g., IPPing(), NeighbourDiagnostics() etc.

* [list_operate documentation](../api/ubus/usp.md#list_operate)

##### get_supported_dm

This method exposes the all type of objects supported in the data model in one browse. it will expose name, type, cmd_type and writable properties of the object depending on the type of the parameters present in the data model. 

* [get_supported_dm documentation](../api/ubus/usp.md#get_supported_dm)


##### get

This method exposes information regarding various schema parameters registered in the data model.

* [get documentation](../api/ubus/usp.md#get)

##### object_names

This method exposes names of the object registered in the data model.

* [object_names documentation](../api/ubus/usp.md#object_names)

##### instances

This method exposes information of all instances of various objects registered in the data model for specified schema path.

* [disconnect documentation](../api/ubus/usp.md#instances)

##### validate

This method validates whether the path provided is valid  as per registerd schema paths.

* [validate documentation](../api/ubus/usp.md#validate)

##### set

This method is used to set information of various registered schema parameters.

* [set documentation](../api/ubus/usp.md#set)

##### operate

This method is used to execute various sync/async operations e.g., IPPing(), NeighbourDiagnostics() etc.

* [operate documentation](../api/ubus/usp.md#operate)

##### add_object

This method is used to add an object to specified multi instance object in registered schema.

* [add_object neighbor documentation](../api/ubus/usp.md#add_object)

##### del_object

This method is used to delete an object from specified multi instance object in registered schema.

* [del_object documentation](../api/ubus/usp.md#del_object)



### usp.raw

Object for device functionality. One object per device will be published to
ubus.

````bash
       "dump_schema":{}
	"list_operate":{}
	"list_events":{}
	"get_supported_dm":{"path":"String","next-level":"Boolean","schema_type":"Integer"}
	"get":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"getm_values":{"paths":"Array","proto":"String","next-level":"Boolean","instance_mode":"Integer"}
	"getm_names":{"paths":"Array","proto":"String","next-level":"Boolean","instance_mode":"Integer"}
	"object_names":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"instances":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"validate":{"path":"String","proto":"String","maxdepth":"Integer","next-level":"Boolean","instance_mode":"Integer"}
	"transaction_start":{"app":"String"}
	"set":{"path":"String","value":"String","values":"Table","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"operate":{"path":"String","action":"String","input":"Table","proto":"String","instance_mode":"Integer"}
	"add_object":{"path":"String","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"del_object":{"path":"String","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"setm_values":{"pv_tuple":"Array","proto":"String","instance_mode":"Integer","transaction_id":"Integer"}
	"transaction_commit":{"transaction_id":"Integer","restart_services":"Boolean"}
	"transaction_abort":{"transaction_id":"Integer"}
	"transaction_status":{"transaction_id":"Integer"}
	"notify_event":{"name":"String","input":"Table"}

````

| Method      						|Function ID	|
| :--- 	  					| :---        	|
| [dump_schema](#dump_schema_raw)			| 1		|
| [list_operate](#list_operate_raw)			| 2		|
| [list_events](#list_events_raw)			| 3		|
| [get_supported_dm](#get_supported_dm_raw)		| 4		|
| [get](#get_raw)					| 5		|
| [getm_values](#getm_values_raw)			| 6		|
| [getm_names](#getm_names_raw)			| 7		|
| [object_names](#object_names_raw)			| 8		|
| [instances](#instances_raw)				| 9		|
| [validate](#validate_raw)				| 10		|
| [transaction_start](#transaction_start_raw)		| 11		|
| [set](#set_raw)		 			| 12		|
| [operate](#operate_raw)				| 13		|
| [add_object](#add_object_raw)			| 14  		|
| [del_object](#del_object_raw)			| 15		|
| [setm_values](#setm_values_raw)			| 16		|
| [transaction_commit](#transaction_commit_raw)	| 17		|
| [transaction_abort](#transaction_abort_raw)		| 18		|
| [transaction_status](#transaction_status_raw)	| 19		|
| [notify_event](#notify_event_raw)			| 20		|


#### Methods

Below methods are supported in usp methods. Method description of the `usp` object in succeding paragraphs . 


##### dump_schema_raw

This method exposes schema registered in the data model .

* [dump_schema documentation](../api/ubus/usp.raw.md#dump_schema)

##### list_operate_raw

Exposes various sync and async operations supported by datamodel. e.g., IPPing(), NeighbourDiagnostics() etc.

* [list_operate documentation](../api/ubus/usp.raw.md#list_operate)

##### list_events_raw

Exposes various events registered in the datamodel.

* [list_events documentation](../api/ubus/usp.raw.md#list_events)

##### get_supported_dm_raw

This method exposes the all type of objects supported in the data model in one browse. it will expose name, type, cmd_type and writable properties of the object depending on the type of the parameters present in the data model. 

* [get_supported_dm documentation](../api/ubus/usp.md#get_supported_dm)


##### get_raw

This method exposes information of various schema parameters registered in the data model.

* [get documentation](../api/ubus/usp.raw.md#get)

##### getm_values_raw

This method is an extension to get method, this method can be use to get parameter values for multiple query paths at once.

* [getm_values documentation](../api/ubus/usp.raw.md#getm_values)

##### getm_names_raw

This method is an extension to get method, this method can be use to get parameter names for multiple query paths at once.

* [getm_names documentation](../api/ubus/usp.raw.md#getm_names)


##### object_names_raw

This method exposes names of the objects in the spectified query path registered in the data model.

* [object_names documentation](../api/ubus/usp.raw.md#object_names)

##### instances_raw

Get all the instances for specified schema path.

* [disconnect documentation](../api/ubus/usp.raw.md#instances)

##### validate_raw

This method validates whether the path provided is valid  as per registerd schema paths.

* [validate documentation](../api/ubus/usp.raw.md#validate)


##### transaction_start

This method starts a transaction with the name provided.

* [transaction_start documentation](../api/ubus/usp.raw.md#transaction_start)


##### set_raw

This method is used to set information of various registered schema parameters.

* [set documentation](../api/ubus/usp.raw.md#set)

##### operate_raw

This method is used to execute various sync/async operations e.g., IPPing(), NeighbourDiagnostics() etc.

* [operate documentation](../api/ubus/usp.raw.md#operate)

##### add_object_raw

This method is used to add an object to specified multi instance object in registered schema.

* [add_object neighbor documentation](../api/ubus/usp.raw.md#add_object)

##### del_object_raw

This method is used to delete an object from specified multi instance object in registered schema.

* [del_object documentation](../api/ubus/usp.raw.md#del_object)

##### setm_values_raw

This method is an extension to set method, this method can be use to set parameter values for multiple query paths at once.

* [setm_values documentation](../api/ubus/usp.raw.md#setm_values)


##### transaction_commit

This method commits the changes made by an ongoing transaction.

* [transaction_commit documentation](../api/ubus/usp.raw.md#transaction_commit)


##### transaction_abort

This method aborts an ongoing transaction.

* [transaction_abort documentation](../api/ubus/usp.raw.md#transaction_abort)

##### transaction_status

This method provides with the status of an ongoing transaction.

* [transaction_status documentation](../api/ubus/usp.raw.md#transaction_status)

##### notify_event

This method is used to get notified whenever the specified event occurs

* [notify_event documentation](../api/ubus/usp.raw.md#notify_event)
