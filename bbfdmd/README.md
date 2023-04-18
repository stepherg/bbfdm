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
