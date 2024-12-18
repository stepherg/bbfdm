# BBFDM Daemon (bbfdmd)

`bbfdmd` daemon responsible for creating a datamodel layer between system resources and exposing TR181 data-model objects over ubus for higher layer application protocols like [TR-069/cwmp](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).

> Note 1: The command outputs shown in this document are examples only, actual output may differ based on device and configuration.

## Concepts and Workflow

`bbfdmd` daemon gets started by `/etc/init.d/bbfdmd` service, bbfdmd init script reads the input from `bbfdm` uci file and then it starts using the APIs provided by `libbbfdm-ubus` and `libbbfdm-api`.

`bbfdmd` daemon use `libbbfdm-api` library to traverse the core datamodel tree added by static library `libbbfdm` or other plugins defined in `/usr/share/bbfdm/plugins`.

`bbfdmd` daemon use `libbbfdm-ubus` library to expose datamodel over ubus.

When a ubus method is called it first fills `bbfdm_data_t` structure with the necessary information, then register the micro-services information defined for each JSON service file after that proceeds the `Get/Set/Operate/Add/Del` operation based on that information.

To load the datamodel definitions from a DotSO file, it looks for a 'tDynamicObj' symbol and use it to create the base entry object, for datamodel operations it rely on libbbfdm-api's `bbf_entry_method` which process the datamodel operation on input path and produces result in list/blob, which further gets responded over ubus.

In short, it covers/supports all methods introduced in `TR-069` and `TR-369` by using the `bbf_entry_method` API from `libbbfdm-api`  with the different methods and the existing data-model available with `libbbfdm`.

> Note1: In general, bbfdmd does not reload the services after updating the configs, higher layer applications (i.e. icwmp, obuspa) usages `bbf.config` to apply the configs and reloads the services, please check `bbf.config` documentation for more details.

> Note2: All RPC method's output is stored directly in a blob buffer, which can be used at the end by Ubus reply API to expose the data and reducing CPU usage of `bbfdmd` daemon.

## Input and output Schema(s)

`bbfdmd` basic configuration can be updated with uci, a guide and uci schema available in following links
- [bbfdm uci guide](../api/uci/bbfdm.md)
- [bbfdm uci schema](../api/uci/bbfdm.json)

`bbfdmd` ubus guide and schema
- [bbfdm ubus guide](../api/ubus/bbfdm.md)
- [bbfdm ubus schema](../api/ubus/bbfdm.json)

### Ubus methods

Following are the ubus methods exposed by `bbfdmd` main process:

```bash
# ubus -v list bbfdm
'bbfdm' @b93b62aa
    "get":{"path":"String","paths":"Array","maxdepth":"Integer","optional":"Table"}
    "schema":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
    "instances":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
    "set":{"path":"String","value":"String","datatype":"String","obj_path":"Table","optional":"Table"}
    "operate":{"command":"String","command_key":"String","input":"Table","optional":"Table"}
    "add":{"path":"String","obj_path":"Table","optional":"Table"}
    "del":{"path":"String","paths":"Array","optional":"Table"}
    "notify_event":{"name":"String","input":"Array"}
    "service":{}
```

> Note1: `optional` table are present in all methods and it supports below options:

```console
"optional":{"proto":"String", "format":"String"}
```

 - `proto` in each method specify the data-model prototype('cwmp', 'usp') to use, if not provided default data-model will be used.

 - `format` could be 'raw' or 'pretty', to specify the format to use as output, if not provided 'pretty' format will be used.

> Note2: `first_level` true means only get next level objects and false means get all objects recursively

> Note3: `maxdepth` is measured on max number of .(Dot) present in object name

> Note4: Check ubus schema document for more details


## Datamodel debugging tools

To debug the datamodel objects/parameters, `bbfdmd` provides a command line interface, which can gets the data from an ubus object and then show it on the CLI. This command line tool is part of `bbfdmd` binary itself and can be accessed with command line argument option '-c' along with binary.

```bash
# bbfdmd -h
Usage: bbfdmd [options]

options:
    -c <command input>  Run cli command
    -l <loglevel>       log verbosity value as per standard syslog
    -h                  Displays this help

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
