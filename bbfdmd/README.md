# BBFDM Daemon (bbfdmd)

`bbfdmd` is daemon which exposes data-model objects over ubus as required by [TR-069/cwmp](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).

> Note 1: The command outputs shown in this readme are examples only, actual output may differ based on device and configuration.

> Note 2: Long command outputs are compressed for better readability

## UCI Config

The configuration file is an `uci` file `/etc/config/bbfdm`. Sample configuration file is provided below.

```bash
config bbfdmd 'bbfdmd'
        option loglevel  '2'
        option sock '/tmp/usp.sock'
        option transaction_timeout 10
        option subprocess_level '1'
        option refresh_time '10'
```

In the above uci, loglevel can have below value:

|loglevel |  Meaning                                 |
|---------| -----------------------------------------|
|  0      | Disabled logging                         |
|  1      | Only errors will be logged               |
|  2      | Only errors and warnings will be logged  |
|  3      | Log everything except debug              |
|  4      | Everything will be logged                |

For more info on the `bbfdmd` UCI configuration visit [uci documentation](../docs/api/uci/bbfdm.md) OR [raw uci schema](../schemas/uci/bbfdm.json)

## Concepts and Workflow

`bbfdmd` internally uses both `libbbfdm-api` and `libbbfdm` to get the data-model objects. On startup it parses the uci file to check the different configurations and then based on that it registers the `bbfdm` ubus namespace.

When a ubus method is called it first fills `usp_data_t` structure with the necessary information, then proceeds the `Get/Set/Operate/Add/Del` operation based on that information.

`bbfdmd` uses `bbf_entry_method` API from `libbbfdm-api` and  `tEntryRoot`, `tVendorExtension`, `tVendorExtensionOverwrite` and `tVendorExtensionExclude` global shared arrays from `libbbfdm` to get the device tree schema and its values.

In short, it covers/supports all methods introduced in `TR-069` and `TR-369` by using the `bbf_entry_method` API from `libbbfdm-api`  with the differents methods and the existing data-model available with `libbbfdm`.

## BBFDMD Command Line Arguments

`bbfdmd` supports two modes, a daemon mode (seen above) and a command (or CLI) mode, which supports interactively querying the data model and setting values in the configuration via the data model.

Actually, the CLI mode is an utility to simplify the interaction with data model that gives to customer the visibility to expose any kind of data model (which can be a `DotSo` plugin, `JSON` plugin, `UBUS` command or `UNIX` socket) with a specific format (`CLI` or `JSON`).

The CLI mode is specified with the `-c` option and can be run using `cwmp` or `usp` protocol.

All of the above configurations should be done by json file which can be located anywhere, just don't forget to pass the path with `-I` option.

```console
root@iopsys:~# bbfdmd -I /tmp/test.json -c help
Valid commands:
   help
   get [path-expr]
   set [path-expr] [value]
   add [object]
   del [path-expr]
   instances [path-expr]
   schema [path-expr]

```

Below is an example of json file:

```json
{
    "client": {
        "config": {
            "proto": "usp", // usp, cwmp
            "instance_mode": 0 // 0:number, 1:alias
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
```
> NOTE1: `bbfdmd` CLI mode is an experimentation feature and it can be updated later.

> NOTE2: If `-I` option is not passed when starting `bbfdmd`, so configuration options will be loaded from the default [INPUT.JSON](../../json/input.json) located in '/etc/bbfdm/input.json'.

* To see a list of arguments supported by `bbfdmd` use:

```console
root@iopsys:~# bbfdmd -h
Usage: bbfdmd [options]

options:
    -s <socket path>    ubus socket
    -I <json path>      json input configuration
    -c <command input>  Run cli command
    -h                 Displays this help

```

* To see a list of commands supported by `bbfdmd` in CLI mode use:

```console
root@iopsys:~# bbfdmd -c help
Valid commands:
   help
   get [path-expr]
   set [path-expr] [value]
   add [object]
   del [path-expr]
   instances [path-expr]
   schema [path-expr]

```

* To see the currently implemented data model use:

```console
$ bbfdmd -c schema Device.
```

* To query the value of a parameter use:

```console
root@iopsys:~# bbfdmd -c get Device.Time.           
Device.Time.Enable => 0
Device.Time.Status => Disabled
Device.Time.NTPServer1 => ntp1.sth.netnod.se
Device.Time.NTPServer2 => ntp1.gbg.netnod.se
Device.Time.NTPServer3 => 
Device.Time.NTPServer4 => 
Device.Time.NTPServer5 => 
Device.Time.CurrentLocalTime => 2023-04-22T13:45:01+00:00
Device.Time.LocalTimeZone => CET-1CEST,M3.5.0,M10.5.0/3
root@iopsys:~# bbfdmd -c get Device.WiFi.SSID.1.SSID
Device.WiFi.SSID.1.SSID => test-5g
```

> Note: The "parameter" may contain wildcard intance and partial paths.


* To set the value of a data model parameter use:

```console
$ bbfdmd -c set "parameter" "value"
```

> Note: The CLI mode also supports adding and deleting instances of data model objects and supported instances.


## Important topics
* [UBUS methods](../docs/guide/bbfdm_ubus_methods.md)
* [UBUS Errors](../docs/guide/bbfdm_ubus_errors.md)
* [Parallel UBUS call](../docs/guide/bbfdm_ubus_parallel_call.md)
* [Third party datamodel integration](../docs/guide/bbfdm_dm_integration.md)


## Dependencies

### Build-Time Dependencies

To successfully build bbfdmd, following libraries are needed:

| Dependency |                    Link                     |    License     |
| ---------- | ------------------------------------------- | -------------- |
| libuci     | https://git.openwrt.org/project/uci.git     | LGPL 2.1       |
| libubox    | https://git.openwrt.org/project/libubox.git | BSD            |
| libubus    | https://git.openwrt.org/project/ubus.git    | LGPL 2.1       |
| libjson-c  | https://s3.amazonaws.com/json-c_releases    | MIT            |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3       |
| libbbfdm  | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3       |


### Run-Time Dependencies

In order to run the `bbfdmd`, following dependencies are needed to be running/available before `bbfdmd`.

| Dependency |                   Link                   | License  |
| ---------- | ---------------------------------------- | -------- |
| ubusd      | https://git.openwrt.org/project/ubus.git | LGPL 2.1 |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3       |
| libbbfdm  | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3       |


System daemon `ubusd` is used to expose the BBFDM functionality over `ubus`.
