# Data Model Micro-Service (dm-service)

`dm-service` daemon is designed to expose a specific module or sub-tree of a data model as a datamodel micro-service.

> Note: The command outputs shown in this document are examples and may vary depending on your device and configuration.

## Concepts and Workflow

`dm-service` daemon is started by `/etc/init.d/bbfdm.services` service. This init script reads input from `bbfdm` UCI file, particularly from the `micro_services` section. It then parses each micro-service configuration file located in `/etc/bbfdm/services/`. Each micro-service’s configuration, written in JSON, is used to start the service using the APIs provided by `libbbfdm-ubus` and `libbbfdm-api` libraries.

`dm-service` daemon uses the `libbbfdm-api/legacy` library to traverse the datamodel tree defined by DotSo or JSON plugins located in `/usr/share/bbfdm/micro_services/$micro-service-name{.so,.json}` and its plugins defined in `/usr/share/bbfdm/micro_services/$micro-service-name/`.

`dm-service` daemon uses the `libbbfdm-ubus` library to expose the datamodel over UBUS.

A datamodel micro-service is a data model instance running with a smaller data subset and can be identified at runtime by running a `ps` command:

```bash
# ps|grep dm-service
11371 root      4904 S    {dm_bridgemngr} /usr/sbin/dm-service -m bridgemngr -l 3
11372 root      5052 S    {dm_core} /usr/sbin/dm-service -m core -l 3
11373 root      4856 S    {dm_ddnsmngr} /usr/sbin/dm-service -m ddnsmngr -l 3
11374 root      4848 S    {dm_dhcp-on-boar} /usr/sbin/dm-service -m dhcp-on-boarding -l 3
11375 root      4924 S    {dm_dhcpmngr} /usr/sbin/dm-service -m dhcpmngr -l 3
11376 root      4896 S    {dm_dnsmngr} /usr/sbin/dm-service -m dnsmngr -l 3
11377 root      4896 S    {dm_firewallmngr} /usr/sbin/dm-service -m firewallmngr -l 3
11378 root      4844 S    {dm_gateway-info} /usr/sbin/dm-service -m gateway-info -l 3
11379 root      4848 S    {dm_gnx-ux-manag} /usr/sbin/dm-service -m gnx-ux-manager -l 3
11380 root      4868 S    {dm_hostmngr} /usr/sbin/dm-service -m hostmngr -l 3
11381 root      4900 S    {dm_icwmp} /usr/sbin/dm-service -m icwmp -l 3
```

Each `dm-service` instance must be started with -m input to define its service name and run its module(sub-tree) datamodel. These micro-services exposed their own ubus objects.

```bash
# ubus list bbfdm.*
bbfdm.bridgemngr
bbfdm.bulkdata
bbfdm.core
bbfdm.ddnsmngr
bbfdm.dhcp-on-boarding
bbfdm.dhcpmngr
bbfdm.dnsmngr
bbfdm.ethmngr
bbfdm.firewallmngr
bbfdm.gateway-info
```

## Setting Up a Datamodel as a Micro-Service

Before starting a datamodel as a micro-service, ensure that the datamodel definition file is correctly placed and configured. The file should be located at:
`/etc/bbfdm/services/${micro_service_name}.json`.

This file must include the following required fields:

- `enable`: Enables or disables the microservice.
- `service_name`: The name of the service.
- `unified_daemon`: A boolean indicating whether the service uses a unified daemon.
- `proto`: Indicates the protocol (e.g., cwmp, both) where the micro-service will be visible.
- `services`: An array containing multiple JSON objects, each providing information about the object that will be exposed from this micro-service and supports three possible options:
  - `parent_dm`: Specifies the parent data model where the object will be linked.
  - `object`: Defines the object or parameter name exposed from the micro-service.
  - `proto`: Indicates the protocol (e.g., cwmp, both) where the object will be visible.
- `loglevel`: The log level used for the microservice

Once all required fields are defined, the datamodel can be registered and started when the `bbfdmd` is initialized.

```bash
# cat /etc/bbfdm/services/core.json 
{
  "daemon": {
    "enable": "1",
    "service_name": "core",
    "unified_daemon": false,
    "services": [
      {
        "parent_dm": "Device.",
        "object": "LANConfigSecurity"
      },
      {
        "parent_dm": "Device.",
        "object": "Schedules"
      },
      {
        "parent_dm": "Device.",
        "object": "Security",
        "proto": "cwmp"
      },
      {
        "parent_dm": "Device.",
        "object": "PacketCaptureDiagnostics"
      },
      {
        "parent_dm": "Device.",
        "object": "SelfTestDiagnostics"
      },
      {
        "parent_dm": "Device.",
        "object": "Syslog"
      },
      {
        "parent_dm": "Device.",
        "object": "X_IOWRT_EU_OpenVPN",
        "proto": "usp"
      },    
      {
        "parent_dm": "Device.",
        "object": "RootDataModelVersion"
      },
      {
        "parent_dm": "Device.",
        "object": "Reboot()"
      },
      {
        "parent_dm": "Device.",
        "object": "FactoryReset()"
      }
    ],
    "config": {
      "loglevel": "3"
    }
  }
}
```

## Verifying Micro-Service Registration

After defining the datamodel, wait for the `bbfdmd` to start. Then, verify that the micro-service has been successfully registered to the core data model. You can do this by listing the registered services using the following command:

```bash
# ubus call bbfdm services
{
  "registered_services": [
    {
      "name": "bbfdm.icwmp",
      "proto": "both",
      "unified_daemon": false,
      "objects": [
        {
          "parent_dm": "Device.",
          "object": "ManagementServer",
          "proto": "both"
        },
        {
          "parent_dm": "Device.",
          "object": "CWMPManagementServer",
          "proto": "usp"
        },
        {
          "parent_dm": "Device.",
          "object": "XMPP",
          "proto": "both"
        }
      ]
    },
    {
      "name": "bbfdm.ssdpd",
      "proto": "both",
      "unified_daemon": false,
      "objects": [
        {
          "parent_dm": "Device.",
          "object": "UPnP",
          "proto": "both"
        }
      ]
    },
    {
      "name": "bbfdm.tr104",
      "proto": "both",
      "unified_daemon": false,
      "objects": [
        {
          "parent_dm": "Device.Services.",
          "object": "VoiceService",
          "proto": "both"
        }
      ]
    },
    {
      "name": "bbfdm.obuspa",
      "proto": "cwmp",
      "unified_daemon": false,
      "objects": [
        {
          "parent_dm": "Device.",
          "object": "USPAgent",
          "proto": "both"
        },
        {
          "parent_dm": "Device.",
          "object": "MQTT",
          "proto": "both"
        },
        {
          "parent_dm": "Device.",
          "object": "STOMP",
          "proto": "both"
        }
      ]
    },
    {
      "name": "bbfdm.swmodd",
      "proto": "both",
      "unified_daemon": false,
      "objects": [
        {
          "parent_dm": "Device.",
          "object": "SoftwareModules",
          "proto": "both"
        }
      ]
    },
    {
      "name": "bbfdm.dnsmngr",
      "proto": "both",
      "unified_daemon": false,
      "objects": [
        {
          "parent_dm": "Device.",
          "object": "DNS",
          "proto": "both"
        }
      ]
    }
```

In this example:

- Each entry in `registered_services` represents a micro-service.
- Verify that your service is included in this list, and that its properties (`name`, `parent_dm`, `object`, `proto`, `unified_daemon`) are correctly configured.

## Input and output Schema(s)

`dm-service` is used to expose sub-tree using different ubus object, UBUS guide and schema for datamodel micro-services

- [datamodel micro-service](../api/ubus/bbfdm_micro_service.md)
- [datamodel micro-service schema](../api/ubus/bbfdm_micro_service.json)

Apart from these, datamodel micro-services can also be configured by updating their input files directly at runtime, micro-service input files present in `/etc/bbfdm/services/` in CPE.

A typical micro-service input file looks like below:

```json
{
  "daemon": {
    "enable": "1",
    "service_name": "bulkdata",
    "unified_daemon": true,
    "services": [
      {
        "parent_dm": "Device.",
        "object": "BulkData",
        "proto": "cwmp"
      }
    ],
    "config": {
      "loglevel": "3"
    }
  }
}
```

### Ubus methods

Following are the UBUS methods exposed by `dm-service` process:

```bash
# ubus -v list bbfdm.netmngr
'bbfdm.netmngr' @e93fc046
  "get":{"path":"String","optional":"Table"}
  "schema":{"path":"String","first_level":"Boolean","optional":"Table"}
  "instances":{"path":"String","optional":"Table"}
  "set":{"path":"String","value":"String","datatype":"String","obj_path":"Table","optional":"Table"}
  "operate":{"path":"String","command_key":"String","input":"Table","optional":"Table"}
  "add":{"path":"String","obj_path":"Table","optional":"Table"}
  "del":{"path":"String","paths":"Array","optional":"Table"}
  "reference_path":{"path":"String","optional":"Table"}
  "reference_value":{"path":"String","optional":"Table"}
```

> Note1: `optional` table are present in all methods and it supports below options:

```json
"optional":{"proto":"String", "format":"String"}
```

 - `proto` in each method specify the data-model prototype('cwmp', 'usp') to use, if not provided default data-model will be used.

 - `format` could be 'raw' or 'pretty', to specify the format to use as output, if not provided 'pretty' format will be used.

> Note2: `first_level` true means only get next level objects and false means get all objects recursively

> Note4: Check ubus schema document for more details


## Pros and Cons of Data Model Micro-Service

Data model micro-service is running a partial datamodel sub-set.

Benefit:
- Instead of having a huge datamodel tree, it split the tree based on modules, which reduce the cost of operation on the tree
- Resolves one point failure, if any datamodel micro-service not working correctly it only affects that specific module, not the rest of the tree
- Moving datamodel code to module repo, brings the service layer and datamodel layer closer, which lowers the possibilities of wrong mapping
- Possible to use lightweight `dm-service` inside containers with json plugin for Container service management
- Possible to impose CPU/Memory restrictions or even run it in a procd jail to limit the host resource access

Cons:
- It requires to execute a `dm-service` instance each module, so takes bit more resouces
- Resolving of complex datamodel paths, like datamodel references of external modules (ex: `bridgemngr` refers to wifi layer from `wifidmd`) cost more on IPC

When not to use micro-service:
- Its suggested not to use datamodel micro-service specially in the devices which are having very less resources(in terms of memory/cpu), or
- On devices which have high IPC cost over ubus

### How to Use micro-service

Manually configuring and starting a micro-services requires multiple steps, but its made simple by using `bbfdm.mk` compile time helper utility.

First of all, To register a datamodel definition as a datamodel micro-service, user needs to register the datamodel definition/plugin using

`BBFDM_REGISTER_SERVICES` API from `bbfdm.mk`

```bash
bulkdata/Makefile:      $(BBFDM_REGISTER_SERVICES) ./bbfdm_service.json $(1) $(PKG_NAME)
ddnsmngr/Makefile:      $(BBFDM_REGISTER_SERVICES) ./bbfdm_service.json $(1) $(PKG_NAME)
```

Then to launch a datamodel definition as a datamodel micro-service, user needs to install the datamodel definition/plugin using

`BBFDM_INSTALL_MS_DM` API from `bbfdm.mk`


```bash
bulkdata/Makefile:      $(BBFDM_INSTALL_MS_DM) $(PKG_BUILD_DIR)/bbf_plugin/bulkdata.json $(1) $(PKG_NAME)
ddnsmngr/Makefile:      $(BBFDM_INSTALL_MS_DM) $(PKG_BUILD_DIR)/src/libddnsmngr.so $(1) $(PKG_NAME)
```

Please check [bbfdm.mk](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/bbfdm.mk) documentation for more details.

In Devices, datamodel micro-services started and managed by `/etc/init.d/bbfdm.services` init script, which reads the global micro-service related configuration from `bbfdm` uci file, and reads module specific configuration for each module's input file present in `/etc/bbfdm/services/` directory.

> In plugins approach, the 3rd party datamodel gets attached to main bbfdm process, which further increases nodes in main datamodel tree, which overtime become a huge tree, results in slower turn around service time for the APIs. Also, any unhandled fault in plugin result in segfault in main bbfdmd process, which takes down the whole tree along with plugin, resulting in complete failure from cwmp and USP, with micro-services plugins runs as an individual processes, so impact of fault limited to its own micro-service only.

Micro-service approach, disintegrate the plugins further and run them as individual daemons with the help of "bbfdmd" "-m" command line options.

## Datamodel debugging tools

To configure the log_level in a micro-service, update the `loglevel` value in the module JSON file:

```json
# cat /etc/bbfdm/services/netmngr.json 
{
  "daemon": {
    "enable": "1",
    "service_name": "netmngr",
    "unified_daemon": false,
    "services": [
      {
        "parent_dm": "Device.",
        "object": "IP"
      },
      {
        "parent_dm": "Device.",
        "object": "GRE"
      },
      {
        "parent_dm": "Device.",
        "object": "PPP"
      },
      {
        "parent_dm": "Device.",
        "object": "Routing"
      },
      {
        "parent_dm": "Device.",
        "object": "RouterAdvertisement"
      }
    ],
    "config": {
      "loglevel": "7"
    }
  }
}
```

Then restart `bbfdm.services` for that specific micro-service:

```bash
/etc/init.d/bbfdm.services restart netmngr
```

To restart all micro-services:

```bash
/etc/init.d/bbfdm.services restart
```
