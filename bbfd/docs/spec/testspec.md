# Test Specification

Most of the functionalities in uspd can be tested via its ubus API. Each
API can be broken down into an individual test case to show full coverage is
achieved.

# Sections
* [Preqreuisites](#prerequisites)
* [Test Suites](#test-suites)
* [Functional API Tests](#functional-api-tests)
* [Unit Tests](#unit-tests)
* [Functional Tests](#functional-tests)


## Prerequisites

The prerequisite for the uspd test suites is that libbbfdm and ubusd has to be
built for the TEST platform, a version prepared to publish dummy data for get
API, and record set API to a test logfile at `/tmp/test.log`.

| Dependency |                   Link                   | License  |
| :---	     | :---                                     | :---     |
| ---------- | ---------------------------------------- | -------- |
| ubusd      | https://git.openwrt.org/project/ubus.git | LGPL 2.1 |
| libbbfdm   | https://dev.iopsys.eu/iopsys/bbf.git     | LGPL 2.1 |


## Test Suites

The uspd build pipe has three test suites, a functional-api suite, unit test suite
and functional test suite.

### Functional API Tests

The functional API tests consists of two individual test suites, one per object
Ubus under test. The functional API tests use the Ubus-API-validation
command-line interface tool to invoke a method, programmatically through
libubus, and validates it against the objects json-schema.

#### usp

| Execution ID	| Method      	 	| Description 			   		| Function ID Coverage			 	|
| :---		| :--- 	 	| :---				   		| :---						|
| 1		| list_operate   	| No argument  		        	| [1](./functionspec.md#list_operate)		|
| 2		| get_supported_dm     \ with path argument	 		 	| [2](./functionspec.md#get_supported_dm)	|
| 3		| get  	 	| With path argument                   	| [3](./functionspec.md#get)      		|
| 4		| object_names 	| With path argument	                	| [4](./functionspec.md#object_names)		|
| 5		| instances   	 	| With path argument  	           		| [5](./functionspec.md#instances)		|
| 6		| validate	 	| With path argument	                	| [6](./functionspec.md#validate)      	|
| 7		| set	         	| With path and value arguments          	| [7](./functionspec.md#set)	        	|
| 8		| operate     	 	| With path, action and input arguments  	| [8](./functionspec.md#operate)		|
| 9		| add_object  	 	| With path argument	                   	| [9](./functionspec.md#add_object)		|
| 10		| del_object    	| With path argument		           	| [10](./functionspec.md#del_object)		|


#### usp.raw

| Execution ID	| Method      	 	| Description 			   		| Function ID Coverage				|
| :---		| :--- 	 	| :---				   		| :---						|
| 1		| dump_schema    	| No argument	  		   		| [15](./functionspec.md#dump_schema_raw)	|
| 2		| list_operate   	| No argument  		           	| [16](./functionspec.md#list_operate_raw)	|
| 3 		| list_events		| No argument  		           	| [16](./functionspec.md#list_events)		|
| 4		| get_supported_dm     | with path argument	 		 	| [2](./functionspec.md#get_supported_dm)	|
| 5		| get  	  	| With path argument                    	| [17](./functionspec.md#get_raw)      	|
| 6		| getm_values    	| With paths array argument		   	| [25](./functionspec.md#getm_values_raw)	|
| 7		| getm_name      	| With paths array argument 	           	| [26](./functionspec.md#getm_names_raw)	|
| 8		| object_names   	| With path argument	                   	| [18](./functionspec.md#object_names_raw) 	|
| 9		| instances   	  	| With path argument  	           		| [19](./functionspec.md#instances_raw)	|
| 10		| validate	  	| With path argument	                   	| [20](./functionspec.md#validate_raw)     	|
| 11		| transaction_start  	| With app argument                    	| [17](./functionspec.md#transaction_start)	|
| 12		| set	         	| With path and value arguments          	| [21](./functionspec.md#set_raw)	        |
| 13		| operate     	 	| With path, action and input arguments  	| [22](./functionspec.md#operate_raw)		|
| 14		| add_object  	 	| With path argument	                   	| [23](./functionspec.md#add_object_raw)	|
| 15		| del_object     	| With path argument		           	| [24](./functionspec.md#del_object_raw)	|
| 16		| setm_values  	| With pv_tuple and transaction_id argument 	| [17](./functionspec.md#setm_val)      	|
| 17		| transaction_commit  	| With transaction_id argument                 | [17](./functionspec.md#transaction_commit)	|
| 18		| transaction_abort  	| With transaction_id argument                 | [17](./functionspec.md#transaction_abort)   |
| 19		| transaction_status  	| With transaction_id argument              	| [17](./functionspec.md#transaction_status)  |
| 20		| notify_event  	| With ***** argument                    	| [17](./functionspec.md#notify_event)	|


### Unit Tests

The uspd unit tests are written in cmocka, invoking the ubus callbacks
directly from the source code, which is compiled into a shared library.
This means mocking the arguments of a cli or libubus invoke in a
`struct blob_attr *`. The results of the call will be logged to the logfile at
`/tmp/test.log`.

| Execution ID	| Method     		| Test Case Name						   | Function ID Coverage		  |
| :---		| :--- 		| :---								   | :---				  |
| 1		| dump_schema		| [test_api_usp_raw_dump_schema](#test_api_usp_raw_dump_schema)  | [1](./functionspec.md#dump_schema_raw)
| 2		| list_operate         | [test_api_usp_list_operate](#test_api_usp_list_operate)  	   | [2](./functionspec.md#list_operate) |
| 3		| get  	        | [test_api_usp_get](#test_api_usp_get)                         | [3](./functionspec.md#get)      	   |
| 4		| object_names         | [test_api_usp_object_name](#test_api_usp_object_name)         | [4](./functionspec.md#object_names)  |
| 5		| instances   	        | [test_api_usp_instances](#test_api_usp_instances)  	   | [5](./functionspec.md#instances)	   |
| 6		| validate	        | [test_api_usp_resolve](#test_api_usp_resolve)                 | [6](./functionspec.md#validate)      |
| 7		| set	                | [test_api_usp_set](#test_api_usp_set)                         | [7](./functionspec.md#set)	   |
| 8		| add_object  	        | [test_api_usp_add_object](#test_api_usp_add_object)	   | [9](./functionspec.md#add_object)    |
| 9		| del_object   	| [test_api_usp_del](#test_api_usp_del_object)		   | [10](./functionspec.md#del_object)   |
| 10		| getm_values  	| [test_api_usp_get_safe_values](#test_api_usp_get_safe_values) | [11](./functionspec.md#getm_values)   |
| 11		| getm_name    	| [test_api_usp_get_safe_names](#test_api_usp_get_safe_names)   | [12](./functionspec.md#getm_names)    |

#### test_api_usp_dump_schema

##### Description

Tests the uspd ubus API callback `dump_schema`, publishing the method
[dump_schema](./functionspec.md#dump_schema).

##### Test Steps

Issuing a dump_schema to a client from the uspd test platform.

Read the logfile and verify that the `schema` argument was
accurately logged.

##### Test Expected Results

The expected result is for the log file to have recorded a call to the
dump_schema function.

````bash
{
        "parameters": [
                {
                        "parameter": "Device.ATM.Link.{i}.",
                        "writable": "1",
                        "type": "xsd:object"
                },
                {
                        "parameter": "Device.ATM.Link.{i}.Alias",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.ATM.Link.{i}.DestinationAddress",
                        "writable": "1",
                        "type": "xsd:string"
                },
                {
                        "parameter": "Device.ATM.Link.{i}.Enable",
                        "writable": "1",
                        "type": "xsd:boolean"
                },
                {
...
}
```

#### test_api_usp_list_operate

##### Description

Tests the uspd ubus API `list_operate`, publishing the method
[list_operate](./functionspec.md#list_operate).

##### Test Steps

Issuing a list_operate to a client from the uspd test platform.

Read the logfile and verify that the `list_operate` argument was
accurately logged.

##### Test Expected Results

````bash
{
        "parameters": [
                {
                        "parameter": "Device.DHCPv4.Client.{i}.Renew()",
                        "type": "sync"
                },
                {
                        "parameter": "Device.DNS.Diagnostics.NSLookupDiagnostics()",
                        "type": "async"
                },
                {
                {
                        "parameter": "Device.IP.Diagnostics.IPPing()",
                        "type": "async"
                },
                {
                        "parameter": "Device.IP.Diagnostics.TraceRoute()",
                        "type": "async"
                },
                {
                        "parameter": "Device.IP.Diagnostics.UDPEchoDiagnostics()",
                        "type": "async"
                },
                {
                        "parameter": "Device.IP.Interface.{i}.Reset()",
                        "type": "sync"
                },
                {
                        "parameter": "Device.Reboot()",
                        "type": "sync"
                },
                {

```

#### test_api_usp_get

##### Description

Tests the uspd ubus API get, publishing the method
[get](./functionspec.md#get).

##### Test Steps

Prepare the arguments as:

````bash
{"path":"Device.IP.Diagnostics.", "proto":"usp"}
```

Requesting the libbfdm with the path `Device.IP.Diagnostics.`.

Read the logfile and verify that the interface and arguments were accurately
logged.

##### Test Expected Results

The expected result is for the log file to have recorded a call to the
`libbbfdm`, through ubus and with the argument `path` as `Device.IP.Diagnostics.`
`proto` as `usp`. 

````bash
{
        "Diagnostics": {
                "IPv4DownloadDiagnosticsSupported": true,
                "IPv4PingSupported": true,
                "IPv4ServerSelectionDiagnosticsSupported": true,
                "IPv4TraceRouteSupported": true,
                "IPv6UploadDiagnosticsSupported": true,
                "UDPEchoConfig": {
                        "BytesReceived": 0,
                        "BytesResponded": 0,
                        "TimeFirstPacketReceived": "0",
                        "TimeLastPacketReceived": "0",
                        "UDPPort": 0
                }
        }
}
```

#### test_api_usp_instances

##### Description

Tests the uspd ubus API instances, publishing the method
[instances](./functionspec.md#instances).

##### Test Steps

Prepare the arguments as:

````bash
{"path":"Device.IP.Interface.", "proto":"usp"}
```

Requesting the libbfdm with the path `Device.IP.Interface.`.

Read the logfile and verify that the interface and arguments were accurately
logged.

##### Test Expected Results

The expected result is for the log file to have recorded a call to the
`libbbfdm`, through ubus and with the argument `path` as `Device.IP.Interface.`
`proto` as `usp`. 

````bash
{
        "parameters": [
                {
                        "parameter": "Device.IP.Interface.1."
                },
                {
                        "parameter": "Device.IP.Interface.1.IPv4Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.2."
                },
                {
                        "parameter": "Device.IP.Interface.3."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv4Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv6Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv6Prefix.1."
                }
        ]
}
```

#### test_api_usp_instances

##### Description

Tests the uspd ubus API instances, publishing the method
[instances](./functionspec.md#instances).

##### Test Steps

Prepare the arguments as:

````bash
{"path":"Device.IP.Interface.", "proto":"usp"}
````

Requesting the libbfdm with the path `Device.IP.Interface.`.

Read the logfile and verify that the interface and arguments were accurately
logged.

##### Test Expected Results

The expected result is for the log file to have recorded a call to the
`libbbfdm`, through ubus and with the argument `path` as `Device.IP.Interface.`
`proto` as `usp`. 

```bash
{
        "parameters": [
                {
                        "parameter": "Device.IP.Interface.1."
                },
                {
                        "parameter": "Device.IP.Interface.1.IPv4Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.2."
                },
                {
                        "parameter": "Device.IP.Interface.3."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv4Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv6Address.1."
                },
                {
                        "parameter": "Device.IP.Interface.3.IPv6Prefix.1."
                }
        ]
}
```


### Functional Tests


#### test_func_ref_follow

##### Description

Tests the reference follow for search path. Reference follow is basically
quering a search path, which is referenced by the path queried for.

##### Test Steps

Prepare the arguments as:

````bash
{"path":"Device.WiFi.SSID.1.LowerLayers+.Alias", "proto":"usp"}
```

##### Test Expected Results

The expected result is for the log file to have recorded a call to the
`libbbfdm`, through ubus and with the argument `path` as `Device.WiFi.SSID.1.LowerLayers+.Alias` and `proto` as `usp`. 

````bash
{
        "Device": {
                "WiFi": {
                        "Radio": [
                                {
                                        "Alias": "cpe-1"
                                }
                        ]
                }
        }
}
```

#### test_func_list_of_ref

##### Description

Tests the list of reference following for search path. Reference follow is basically
quering a search path, which is referenced by the path queried for.

##### Test Steps

Prepare the arguments as:

````bash
{"path":"Device.WiFi.SSID.1.LowerLayers#1+.Name"}
```

##### Test Expected Results

The expected result is for the log file to have recorded a call to the
`libbbfdm`, through ubus and with the argument `path` as `Device.WiFi.SSID.1.LowerLayers#1+.Name` and `proto` as `usp`. 

````bash
{
        "Device": {
                "WiFi": {
                        "Radio": [
                                {
                                        "Name": "wl0"
                                }
                        ]
                }
        }
}
```

#### test_func_search_expr

##### Description

Testing search path, this is a path Name that contains search criteria for addressing a 
set of Multi-Instance Objects and/or their parameters. A Search path may contain a 
Search Expression or Wildcard.

##### Test Steps

Prepare the arguments as:

````bash
{"path":"Device.WiFi.SSID.[Status==\"Up\"].Alias"}
```

##### Test Expected Results

In the above bash parameter path we can identify the square brackets as search path. So basically through this search path we are querying 'Alias' for any WiFi.SSID instance having 
`Up` Status. 

The expected result is for the log file to have recorded a call to the
`libbbfdm`, through ubus and with the argument `path` as `Device.WiFi.SSID.1.LowerLayers#1+.Name` and `proto` as `usp`. 

````bash
{
        "SSID": [
                {
                        "Alias": "cpe-1"
                },
                {
                        "Alias": "cpe-2"
                }
        ]
}
```

