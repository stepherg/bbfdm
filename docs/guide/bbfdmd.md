# BBFDM Daemon (bbfdmd)

`bbfdmd` daemon responsible for creating a datamodel layer between system resources and exposing TR181 data-model objects over ubus for higher layer application protocols like [TR-069/cwmp](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).

> Note 1: The command outputs shown in this document are examples only, actual output may differ based on device and configuration.

## Concepts and Workflow

`bbfdmd` daemon gets started by `/etc/init.d/bbfdmd` service, bbfdmd init script reads the input from `bbfdm` uci file and then it generates the input for `bbfdmd` daemon in json format in `/tmp/bbfdm/input.json`

```json input.json
{
  "daemon": {
    "config": {
      "loglevel": "1",
      "refresh_time": "120",
      "transaction_timeout": "30",
      "subprocess_level": "2"
    },
    "input": {
      "type": "DotSo",
      "name": "/usr/share/bbfdm/libbbfdm.so",
      "plugin_dir": "/usr/share/bbfdm/plugins"
    },
    "output": {
      "type": "UBUS",
      "name": "bbfdm"
    }
  },
  "cli": {
    "config": {
      "proto": "both"
    },
    "input": {
      "type": "UBUS",
      "name": "bbfdm"
    },
    "output": {
      "type": "CLI"
    }
  }
}
```

When `bbfdmd` starts it parses the `input.json` file to check the different configurations, like
- Name of the TR181 datamodel definition file (daemon.input.name)
- Location of datamodel definition loaded as plugins (daemon.input.plugin_dir
- Name of the ubus object it has to register (daemon.output.name)

`bbfdmd` daemon use `libbbfdm-api` library to traverse the datamodel tree added by 'libbbfdm' or other plugins added in predefined plugin path(daemon.input.plugin_dir).

When a ubus method is called it first fills `bbfdm_data_t` structure with the necessary information, then proceeds the `Get/Set/Operate/Add/Del` operation based on that information.

To load the datamodel definitions from a DotSO file, it looks for a 'tDynamicObj' symbol and use it to create the base entry object, for datamodel operations it rely on libbbfdm-api's `bbf_entry_method` which process the datamodel operation on input path and produces result in list/blob, which further gets responded over ubus.

In short, it covers/supports all methods introduced in `TR-069` and `TR-369` by using the `bbf_entry_method` API from `libbbfdm-api`  with the different methods and the existing data-model available with `libbbfdm`.

`bbfdmd` daemon can also be used to expose a module specific datamodel or sub-tree, by using datamodel micro-services. Datamodel micro-service is nothing but another `bbfdmd` instance running with smaller data sub-set, micro-service can be identified in the runtime by running a `ps` command

```bash
# ps|grep bbf
 3804 root      6968 S    {dm_bridgemngr} /usr/sbin/bbfdmd -m bridgemngr
 3805 root      7064 S    {dm_bulkdata} /usr/sbin/bbfdmd -m bulkdata
 3806 root      6900 S    {dm_ddnsmngr} /usr/sbin/bbfdmd -m ddnsmngr
 3807 root      6996 S    {dm_dhcpmngr} /usr/sbin/bbfdmd -m dhcpmngr
```

A `bbfdmd` instance with -m input means its running a module(sub-tree) datamodel. These micro-services exposed their own ubus objects

```bash
# ubus list bbfdm.*
bbfdm.Bridging
bbfdm.BulkData
bbfdm.DHCPv4_DHCPv6
bbfdm.DNS
```

When a datamodel started as micro-service, it looks/waits for `bbfdm` ubus object(added by main bbfdmd process), once its available micro-service resister with the main `bbfdmd` process by calling it 'service' method

```bash
# ubus -v list bbfdm
'bbfdm' @e970413c
        "service":{"cmd":"String","name":"String","parent_dm":"String","objects":"Array"}
```

More details about micro-services covered in a dedicated section.

> Note: In general, bbfdmd does not reload the services after updating the configs, higher layer applications (i.e. icwmp, obuspa) usages `bbf.config` to apply the configs and reloads the services, please check `bbf.config` documentation for more details.

## Input and output Schema(s)

`bbfdmd` basic configuration can be updated with uci, a guide and uci schema available in following links
- [bbfdm uci guide](../api/uci/bbfdm.md)
- [bbfdm uci schema](../api/uci/bbfdm.json)

`bbfdmd` ubus guide and schema
- [bbfdm ubus guide](../api/ubus/bbfdm.md)
- [bbfdm ubus schema](../api/ubus/bbfdm.json)

`bbfmdd` can also be used to expose sub tree using different ubus object by using datamodel micro-service, ubus guide and schema for datamodel micro-services

- [datamodel micro-service](../api/ubus/bbfdm_micro_service.md)
- [datamodel micro-service schema](../api/ubus/bbfdm_micro_service.json)

Apart from these, datamodel micro-services can also be configured by updating their input files directly at the runtime, micro-service input files present in `/etc/bbfdm/micro_services/` in CPE.

Datamodel micro-service has a similar input file as of main bbfdmd

```json
{
  "daemon": {
    "enable": "1",
    "service_name": "sshmngr",
    "config": {
      "loglevel": "1"
    }
  }
}
```

### Ubus methods

Following are the ubus methods exposed by `bbfdmd` main process:

```bash
# ubus -v list bbfdm
'bbfdm' @9e9928ef
        "get":{"path":"String","paths":"Array","maxdepth":"Integer","optional":"Table"}
        "schema":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "instances":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "set":{"path":"String","value":"String","obj_path":"Table","optional":"Table"}
        "operate":{"command":"String","command_key":"String","input":"Table","optional":"Table"}
        "add":{"path":"String","obj_path":"Table","optional":"Table"}
        "del":{"path":"String","paths":"Array","optional":"Table"}
        "transaction":{"cmd":"String","timeout":"Integer","restart_services":"Boolean","optional":"Table"}
        "service":{"cmd":"String","name":"String","parent_dm":"String","objects":"Array"}
        "notify_event":{"name":"String","input":"Table"}
```

Each datamodel micro-service expose their own ubus object, which is slightly different from main `bbfdm` ubus object, following is an example of ubus methods exposed by datamodel micro-services.

```bash
# ubus -v list bbfdm.SSH
'bbfdm.SSH' @bb8a66da
        "get":{"path":"String","paths":"Array","maxdepth":"Integer","optional":"Table"}
        "schema":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "instances":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
        "set":{"path":"String","value":"String","obj_path":"Table","optional":"Table"}
        "operate":{"command":"String","command_key":"String","input":"Table","optional":"Table"}
        "add":{"path":"String","obj_path":"Table","optional":"Table"}
        "del":{"path":"String","paths":"Array","optional":"Table"}
        "transaction":{"cmd":"String","timeout":"Integer","restart_services":"Boolean","optional":"Table"}
```

> Note1: `optional` table are present in all methods and it supports below options:

```console
"optional":{"proto":"String", "instance_mode":"Integer", "transaction_id":"Integer", "format":"String"}
```

 - `proto` in each method specify the data-model prototype('cwmp', 'usp') to use, if not provided default data-model will be used.

 - `instance_mode` could be 0 or 1, for instance number, instance alias respectively.

 - `transaction_id` to define the transaction id number.

 - `format` could be 'raw' or 'pretty', to specify the format to use as output, if not provided 'pretty' format will be used.

> Note2: `first_level` true means only get next level objects and false means get all objects recursively

> Note3: `maxdepth` is measured on max number of .(Dot) present in object name

> Note4: Check ubus schema document for more details

### Fault handling

To indicate a fault and source of fault `bbfdmd` provides `fault` along with `fault_msg` in the response in case of faults, which then handled by higher layer applications (i.e icwmp, obuspa).

This provides a clear inside on the root cause of the fault, and based on `fault_msg` it's easily to understand what the issue is and how to fix it and find out the limitations(if there are any on the device).

#### Example(s)

1. The requested value is correct as per TR181 standard, but there is a limitation in the device.

```console
root@iopsys:~# ubus call bbfdm set '{"path":"Device.Firewall.Config", "value":"High"}'
{
    "results": [
        {
            "path": "Device.Firewall.Config",
            "fault": 9007,
            "fault_msg": "The current Firewall implementation supports only 'Advanced' config."
        }
    ]
}
```

2. The requested value is outside the allowed range.

```console
root@iopsys:~# ubus call bbfdm set '{"path":"Device.Firewall.Chain.1.Rule.9.DestPort", "value":"123456"}'
{
    "results": [
        {
            "path": "Device.Firewall.Chain.1.Rule.9.DestPort",
            "fault": 9007,
            "fault_msg": "'123456' value is not within range (min: '-1' max: '65535')"
        }
    ]
}
```

3. Some arguments should be defined to perform the requested operation.

```console
root@iopsys:~# ubus call bbfdm operate '{"command":"Device.IP.Diagnostics.IPPing()", "command_key":"ipping_test", "input":{}}'
{
    "results": [
        {
            "path": "Device.IP.Diagnostics.IPPing()",
            "data": "ipping_test",
            "fault": 7004,
            "fault_msg": "IPPing: 'Host' input should be defined"
        }
    ]
}
```

4. The path parameter value must start with 'Device.'. The command below doesn't have Device before path "Users.User."

```console
root@iopsys:~# ubus call bbfdm get '{"path":"Users.User.", "optional": {"format":"raw", "proto":"usp"}}'
{
    "results": [
        {
            "path": "Users.User.",
            "fault": 7026,
            "fault_msg": "Path is not present in the data model schema"
        }
    ]
}
```

These fault messages defined in datamodel handlers, user can add such fault message using `bbfdm_set_fault_message` libbbfdm-api's API, if no specific fault message defined for particular obj/param, datamodel returns standard error messages that are defined in CWMP and USP protocols as the fault message value.

##### Errors Codes

| Error Code | Meaning                                                      |
|------------|--------------------------------------------------------------|
| 7003       | Message failed due to an internal error.                     |
| 7004       | Message failed due to invalid values in the request elements and/or failure to update one or more parameters during Add or Set requests. |
| 7005       | Message failed due to memory or processing limitations.      |
| 7008       | Requested path was invalid or a reference was invalid.       |
| 7010       | Requested Path Name associated with this ParamError did not match any instantiated parameters. |
| 7011       | Unable to convert string value to correct data type.         |
| 7012       | Out of range or invalid enumeration.                         |
| 7022       | Command failed to operate.                                   |
| 7026       | Path is not present in the data model schema.                |


### Parallel calls over Ubus

Some datamodel operations takes less time to execute compared to other, like
- Get on sub-set of datamodel or an individual datamodel parameter takes very less, where as
- Get on complete Device. and Async operate commands takes much longer

executing/serializing operations simplifies the code from developer perspective, but its not suitable for deployments. To make it suitable `bbfdmd` support parallel calls.

- All datamodel `operate` commands are running in parallel
- `get` calls depends on uci option 'bbfdm.bbfdmd.subprocess_level' (default: 2)


example(s):

```console
root@iopsys:~# time ubus call bbfdm get '{"path":"Device."}' >/dev/null &
root@iopsys:~# time ubus call bbfdm get '{"path":"Device.Users."}' >/dev/null
real    0m 0.07s
user    0m 0.00s
sys     0m 0.00s
root@iopsys:~#
real     0m 1.86s
user    0m 0.05s
sys     0m 0.00s

[1]+  Done                       time ubus call bbfdm get "{\"path\":\"Device.\"}" >/dev/null
root@iopsys:~#
```

## Datamodel micro-services

Datamodel micro-service is nothing but running a partial datamodel sub-set with another instance of `bbfdmd` binary.

Benefit:
- Instead of having a huge datamodel tree, it split the tree based on modules, which reduce the cost of operation on the tree
- Resolves one point failure, if any datamodel micro-service not working correctly it only affects that specific module, not the rest of the tree
- Moving datamodel code to module repo, brings the service layer and datamodel layer closer, which lowers the possibilities of wrong mapping
- Possible to use lightweight `bbfdmd` inside containers with json plugin for Container service management
- Possible to impose CPU/Memory restrictions or even run it in a procd jail to limit the host resource access

Cons:
- It requires to execute a `bbfdmd` instance each module, so takes bit more resouces
- Resolving of complex datamodel paths, like datamodel references of external modules (ex: `bridgemngr` refers to wifi layer from `wifidmd`) cost more on IPC

When not to use micro-service:
- Its suggested not to use datamodel micro-service specially in the devices which are having very less resources(in terms of memory/cpu), or
- On devices which have high IPC cost over ubus

### How to Use micro-service

Manually configuring and starting a micro-services requires multiple steps, but its made simple by using `bbfdm.mk` compile time helper utility.
To launch a datamodel definition as a datamodel micro-service, user need to install the datamodel definition/plugin using

`BBFDM_INSTALL_MS_DM` API from `bbfdm.mk`


```bash
bulkdata/Makefile:      $(BBFDM_INSTALL_MS_DM) $(PKG_BUILD_DIR)/bbf_plugin/bulkdata.json $(1) $(PKG_NAME)
ddnsmngr/Makefile:      $(BBFDM_INSTALL_MS_DM) $(PKG_BUILD_DIR)/src/libddnsmngr.so $(1) $(PKG_NAME)
```

Please check [bbfdm.mk](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/bbfdm.mk) documentation for more details.

In Devices, datamodel micro-services started and managed by `/etc/init.d/bbfdm.services` init script, which reads the global micro-service related configuration from `bbfdm` uci file, and reads module specific configuration for each module's input file present in `/etc/bbfdm/micro_services/` directory.


> In plugins approach, the 3rd party datamodel gets attached to main bbfdm process, which further increases nodes in main datamodel tree, which overtime become a huge tree, results in slower turn around service time for the APIs. Also, any unhandled fault in plugin result in segfault in main bbfdmd process, which takes down the whole tree along with plugin, resulting in complete failure from cwmp and USP, with micro-services plugins runs as an individual processes, so impact of fault limited to its own micro-service only.

Micro-service approach, disintegrate the plugins further and run them as individual daemons with the help of "bbfdmd" "-m" command line options.
## Datamodel debugging tools

To debug the datamodel objects/parameters, `bbfdmd` provides a command line interface, which can

- Work directly on plugins, or
- Gets the data from an ubus object

and then show it on the CLI. This command line tool is part of `bbfdmd` binary itself and can be accessed with command line argument option '-c' along with binary.

```bash
# bbfdmd -h
Usage: bbfdmd [options]

options:
    -s <socket path>    ubus socket
    -m <json path>      json input configuration for micro services
    -c <command input>  Run cli command
    -h                 Displays this help

#
```
If no command line option provided along with `bbfdmd` command then it starts in daemon mode.
In command (or CLI) mode, it supports interactively querying the data model and setting values in the configuration via the data model.

```bash
# bbfdmd -c help
Valid commands:
   help
   get [path-expr]
   set [path-expr] [value]
   add [object]
   del [path-expr]
   instances [path-expr]
   schema [path-expr]
#
```

To debug datamodel mapping/description code, user/developer can use below API to add debug logs

```bash
BBF_ERR(MESSAGE, ...)
BBF_WARNING(MESSAGE, ...)
BBF_INFO(MESSAGE, ...)
BBF_DEBUG(MESSAGE, ...)
```

Above API logs gets logged using syslog, based on log_level defined in `bbfdm`.
To configure the log_level use `bbfdm.bbfdmd.loglevel` uci option.

To configure the log_level in micro-service, update the `loglevel` module json file,

```json
# cat /etc/bbfdm/micro_services/sshmngr.json
{
    "cli": {
        "config": {
            "proto": "usp" // usp, cwmp
        },
        "input": {
            "type": "UBUS", // JSON, UBUS, DotSO, UNIX
            "name": "bbfdm"
        },
        "output": {
            "type": "CLI" // CLI, JSON
        }
    }
  }
}
```

and then restart the bbfdm.services

## How to extend datamodel

Although `bbfdm/iowrt` provides datamodels for major services, but still for deployment user might need to add some vendor extensions or needs to add the missing datamodel support. To do the same `bbfdm` or more precisely `libbfdm-api` provides the infrastructure to easily define a new datamodel tree.

As per TR106 description, a datamodel is, "A hierarchical set of Objects, Parameters, Commands and/or Events that define the managed Objects accessible via a particular Agent."

Please check [TR106](https://www.broadband-forum.org/pdfs/tr-106-1-13-0.pdf) for more details about datamodel terminology.

`bbfdm` provide the tools and utilities to further extend/overwrite/disable the datamodel using C-code or simply by using JSON datamodel definition.

### JSON datamodel

Pro:
 - Easy to add (compilation not required)
 - Least maintenance (Change in libbbfdm-api has minimal impact)

Con:
 - Can only support easy one to one mappings with uci and ubus
 - Invalid plugin syntax might cause faults

### C Based datamodel

Pro:
 - Support complex mapping and data sharing between nodes
 - Lots of references available
 - Tools available to auto-generate the template code
 - All core operations supported

Con:
 - Moderate maintenance (Change in libbbfdm-api requires adaptation/alignment)


Both ways of extending datamodel covered at length with examples in following links
* [How to extend datamodel with C Code](How_to_extend_datamodel_with_C_Code.md)
* [How to extend datamodel with JSON](How_to_extend_datamodel_with_JSON.md)

After creating the datamodel definition, it can be installed the help of `bbfdm.mk` APIs to run them from main `bbfdmd` instance or from micro-service instance.

> Note: If a datamodel object added by a micro-service, all datamodel extensions below that path needed to be hanlded in the same micro-service. Like a wifi extension needed to be installed in wifidmd micro-service as a plugin.

### How to choose C or JSON for datamodel extensions

C/JSON both datamodel definition support defining all datamodel operations, but JSON should be used with simple datamodel deployments.

If its requires to perform more than one step to retrieve data from lowerlayer, it is suggested to use C-Based datamodel definitions, as it gives more control over the data and its mapping, or simply put if JSON plugin does not meets the requirement of datamodel mapping use C-Based definition.
