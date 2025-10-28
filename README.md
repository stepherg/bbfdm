# BroadBand Forum Data Models (BBFDM)

`bbfdm` is a suite to provide a TR181 data model backend for higher-layer management protocols like [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/). It is designed in a hardware-agnostic way and provides the available data model parameters over Ubus on the northbound interface and creates the data model mapping based on UCI and Ubus on the southbound interface.

`bbfdm` has five main components:

| Component    |                    Description                    |
| ------------ | ------------------------------------------------- |
| bbfdmd       | A daemon to expose data model objects over Ubus |
| dm-service   | A daemon to expose data model objects as a microservice over Ubus |
| libbbfdm-api | API library to create and parse data model trees |
| libbbfdm-ubus | API library to expose data model over Ubus |
| libbbfdm     | A shared library containing the core data model of TR181, running as a microservice |

## Directory Structure

`bbfdm` package is structured as follows:

```bash
├── bbfdmd            --  This directory contains daemon code to expose the data model tree on the northbound
│   └── ubus              - Daemon to expose data model over Ubus
├── dm-service        --  This directory contains daemon code to expose the data model tree as a microservice
├── docs              --  More detailed explanation of the data model and user guide
├── gitlab-ci         --  Used for CI/CD pipeline tests
├── libbbfdm          --  Minimal TR181 core data model implementation
├── libbbfdm-api      --  API library to create data model definitions and parse the data model definition to form a data model tree
│   └── legacy            - Legacy version of `libbbfdm-api` containing APIs for creating and parsing data model definitions to build a data model tree  
│   └── version-2         - New version of `libbbfdm-api` with a more flexible and generic implementation, making it easier to use in dm-service and unified daemon
├── libbbfdm-ubus     --  API library to expose data model over Ubus
├── tools             --  Tools to convert XML data model definitions to JSON, generate C code, and more
└── utilities         --  Small helper utilities to complete/optimize the data model deployment
```

## Important Topics

* [BBFDMD Design](./docs/guide/bbfdmd.md)
* [Microservice Design](./docs/guide/dm-service.md)
* [LIBBBFDM-API/Legacy Documentation](./docs/guide/libbbfdm-api-legacy.md)
* [LIBBBFDM-API/Vesrion-2 Documentation](./docs/guide/libbbfdm-api-version-2.md)
* [LIBBBFDM-UBUS Documentation](./docs/guide/libbbfdm-ubus.md)
* [Utilities Documentation](./utilities/README.md)
* [Tools](./tools/README.md)
* [How to extend data model with C Code](./docs/guide/How_to_extend_datamodel_with_C_Code.md)
* [How to extend data model with JSON](./docs/guide/How_to_extend_datamodel_with_JSON.md)

## Good To Know

- The current data model implementation follows the latest version of the data model, version `2.18`.

- Instance alias handling has been moved to the icwmp repository since `bbfdm` repository only supports the common functionality provided by CWMP and USP protocols.

- The current data model implementation does not support the delete method for all instances (e.g., Device.Users.User.) since CWMP and USP protocols do not provide support for this operation.

- The data model implementation uses different directories to store temporary UCI configurations based on the protocol being used. The details are as follows:

| Protocol | Save Config Directory    | Config Directory | Save Dmmap Directory   | Dmmap Directory  |
| -------- | ------------------------ | ---------------- | ---------------------- | ---------------- |
| cwmp     | /tmp/bbfdm/.cwmp/config  | /etc/config      | /tmp/bbfdm/.cwmp/dmmap | /etc/bbfdm/dmmap |
| usp      | /tmp/bbfdm/.usp/config   | /etc/config      | /tmp/bbfdm/.usp/dmmap  | /etc/bbfdm/dmmap |
| both     | /tmp/bbfdm/.bbfdm/config | /etc/config      | /tmp/bbfdm/.cwmp/dmmap | /etc/bbfdm/dmmap |

### Compilation Helper Utilities

* [Readme](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/README.md)
* [Compilation Helper Utility](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/bbfdm.mk)
* [JSON Plugin Validator](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/tools/validate_plugins.py)

## Additional Data Model Objects

This repository has a bare minimum TR181 data model integrated. Each service has its own data model additions, which they expose using plugins and microservices.  
A list of IOWRT-provided service data model sets is available in [tools_input.json](./tools/tools_input.json).

## Dependencies

### Build-Time Dependencies

To successfully build `bbfdmd`, the following libraries are required:

| Dependency   |                    Link                     | License  |
| ------------ | ------------------------------------------- | -------- |
| libuci       | https://git.openwrt.org/project/uci.git     | LGPL 2.1 |
| libubox      | https://git.openwrt.org/project/libubox.git | BSD      |
| libubus      | https://git.openwrt.org/project/ubus.git    | LGPL 2.1 |
| libjson-c    | https://s3.amazonaws.com/json-c_releases    | MIT      |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3    |
| libbbfdm-ubus | https://dev.iopsys.eu/bbf/bbfdm.git        | BSD-3    |

### Run-Time Dependencies

To run `bbfdmd`, the following dependencies are required:

| Dependency   |                   Link                   | License  |
| ------------ | ---------------------------------------- | -------- |
| ubusd        | https://git.openwrt.org/project/ubus.git | LGPL 2.1 |
| libubox      | https://git.openwrt.org/project/libubox.git | BSD   |
| libjson-c    | https://s3.amazonaws.com/json-c_releases    | MIT   |
| libbbfdm-api/version-2 | https://dev.iopsys.eu/bbf/bbfdm.git | BSD-3 |

To run `dm-service`, the following dependencies are required:

| Dependency   |                   Link                   | License  |
| ------------ | ---------------------------------------- | -------- |
| ubusd        | https://git.openwrt.org/project/ubus.git | LGPL 2.1 |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git      | BSD-3    |
| libbbfdm-ubus | https://dev.iopsys.eu/bbf/bbfdm.git     | BSD-3    |
