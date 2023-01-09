# BroadBand Forum Data Models (BBFDM)

`bbfdm` is a data model library implementation which includes a list of objects, parameters and operates used for CPE management through remote control protocols such as [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).
This package comprises of the below libraries:

| Library |                    Description                    |
| ------- | ------------------------------------------------- |
| libbbfdm | This provides the mechanism to add new parameters or extend the existing DM tree using json plugin or shared library plugin. |
| libbbf_api | This provides the APIs for UCI, Ubus, JSON, CLI and memory management. |
| libbbf_ubus | This library helps to expose the datamodel directly over ubus. Application can expose any datamodel(need not be part of "Device."/TR-181) using this library. |

Note: Applications that use libbbf_ubus to expose datamodel, not required to use libbbfdm.

## Design of bbfdm

`bbfdm` library is structred as follow :


```bash
├── dm...(.c and .h)
├── dmtree
│   ├── json
│   ├── tr104
│   ├── tr143
│   ├── tr181
│   └── vendor
│       ├── iopsys
│       ├── openwrt
│       └── vendor.h
├── libbbf_api
├── libbbf_ubus
├── scripts
└── tools
```

- `dmtree` folder which includes all supported Data Models. It contains 5 folders:

	- `tr181` folder : TR-181 Data Model files

	- `tr104` folder : Voice Services Data Model files

	- `tr143` folder : Diagnostics Data Model files

	- `vendor` folder : Vendor Data Model files

	- `json` folder : TR-181 and TR-104 JSON files

- `libbbf_api` folder which contains the source code of all API functions (UCI, Ubus, JSON, CLI and memory management). These API are used for GET/SET/ADD/Delete/Operate calls which can be called in internal or external packages.
All APIs exposed by libbbf_api are presented in this header file [libbbf_api.h](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/include/libbbf_api.h).

- `libbbf_ubus` folder which contains the source code of all API functions helps in exposing datamodel constructed with the help of libbbf APIs directly over ubus.
All APIs exposed by libbbf_ubus are presented in this header file [libbbf_ubus.h](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/include/libbbf_ubus.h).

- `scripts` folder which contains the Diagnostics scripts

- `tools` folder which contains some tools to generate Data Model in C, JSON, XML and Excel format

- `dm...(.c and .h)` files which contains the `bbfdm` engine (operate, diagnostics) functions


## Important Topics
* [Design for firmware activation](./docs/guide/activate_firmware.md)
* [TR181 Firewall datamodel mappings](./docs/guide/firewall.md)
* [Datamodel extension using JSON plugin](./docs/guide/json_plugin_v1.md)
* [Add support of a new Object/Parameter](./docs/guide/obj_param_extension.md)
* [How to add new vendor](./docs/guide/vendor.md)
* [Dynamic Object/Parameter/Operate/Event](./docs/guide/dynamic_dm.md)
* [BBFDM Tools](./docs/guide/tools.md)
* [Expose datamodel over UBUS using libbbf APIs](./docs/guide/dm_expose_over_ubus.md)


## Dependencies of of libbbfdm and libbbf_ubus

To successfully build libbbfdm or libbbf_ubus, the following libraries are needed:

| Dependency  | Link                                        | License        |
| ----------- | ------------------------------------------- | -------------- |
| libuci      | https://git.openwrt.org/project/uci.git     | LGPL 2.1       |
| libubox     | https://git.openwrt.org/project/libubox.git | BSD            |
| libubus     | https://git.openwrt.org/project/ubus.git    | LGPL 2.1       |
| libjson-c   | https://s3.amazonaws.com/json-c_releases    | MIT            |
| libcurl     | https://dl.uxnr.de/mirror/curl              | MIT            |
| libwolfssl  | https://github.com/wolfSSL/wolfssl          | GPL-2.0        |
