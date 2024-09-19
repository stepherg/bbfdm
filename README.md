# BroadBand Forum Data Models (BBFDM)

`bbfdm` is a suite to provide TR181 datamodel backend for Higher layer management protocols like [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/). It is designed in a hardware agnostic way and provides the available datamodel parameters over ubus on the northbound interface and creates the datamodel mapping based on uci and ubus on southbound interface.

`bbfdm` has five main components:

| Component    |                    Description                    |
| ------------ | ------------------------------------------------- |
| bbfdmd       | A daemon to expose data model objects over ubus |
| dm-service   | A daemon to expose data model objects as micro-service over ubus |
| libbbfdm-api | API library to create and parse datamodel tree |
| libbbfdm-ubus | API library to expose datamodel over ubus |
| libbbfdm     | A static library that contains the core data model of TR181 |


## Directory Structure

`bbfdm` package is structured as follow:

```bash
├── bbfdmd            --  This directory contains daemon code to expose the datamodel tree on northbound
│   └── ubus              - Daemon to expose datamodel over ubus
├── dm-service        --  This directory contains daemon code to expose the datamodel tree as micro-service
├── docs              --  More detailed explanation of datamodel and user guide
├── gitlab-ci         --  Used for CI/CD pipeline test
├── libbbfdm          --  Minimal TR181 core datamodel implementation
├── libbbfdm-api      --  API library to create datamodel definition and parse the datamodel definition to form a datamodel tree
├── libbbfdm-ubus     --  API library to expose datamodel over ubus
├── tools             --  Tools to convert xml datamodel definition to json, generate c code and many more
└── utilities         --  Small helper utilities to complete/optimize the datamodel deployment
```

## Important Topics

* [BBFDMD Design](./docs/guide/bbfdmd.md)
* [API Documentation](./docs/guide/libbbfdm-api.md)
* [Tools](./tools/README.md)
* [Utilities](./utilities/README.md)
* [How to extend datamodel with C Code](./docs/guide/How_to_extend_datamodel_with_C_Code.md)
* [How to extend datamodel with JSON](./docs/guide/How_to_extend_datamodel_with_JSON.md)

### Datamodel related topics

* [Design for firmware activation](./docs/guide/libbbfdm_DeviceInfo_FirmwareImage.md)

### Compilation helper utilities

* [Readme](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/README.md)
* [Compilation Helper utility](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/bbfdm.mk)
* [JSON Plugin Validator](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/bbfdm/tools/validate_plugins.py)

## Additional datamodel objects

This repository has bare minimal TR181 datamodel integrated, each service has their own datamodel additions, which they expose using plugins and micro-services.
List of IOWRT provided service datamodel set available in [tools_input.json](./tools/tools_input.json)

## Dependencies

### Build-Time Dependencies

To successfully build bbfdmd, following libraries are needed:

| Dependency   |                    Link                     | License  |
| ------------ | ------------------------------------------- | -------- |
| libuci       | https://git.openwrt.org/project/uci.git     | LGPL 2.1 |
| libubox      | https://git.openwrt.org/project/libubox.git | BSD      |
| libubus      | https://git.openwrt.org/project/ubus.git    | LGPL 2.1 |
| libjson-c    | https://s3.amazonaws.com/json-c_releases    | MIT      |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3    |
| libbbfdm-ubus | https://dev.iopsys.eu/bbf/bbfdm.git        | BSD-3    |
| libbbfdm     | https://dev.iopsys.eu/bbf/bbfdm.git         | BSD-3    |


### Run-Time Dependencies

In order to run the `bbfdmd`, following dependencies are needed to be running/available before `bbfdmd`.

| Dependency   |                   Link                   | License  |
| ------------ | ---------------------------------------- | -------- |
| ubusd        | https://git.openwrt.org/project/ubus.git | LGPL 2.1 |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git      | BSD-3    |
| libbbfdm-ubus | https://dev.iopsys.eu/bbf/bbfdm.git     | BSD-3    |
| libbbfdm     | https://dev.iopsys.eu/bbf/bbfdm.git      | BSD-3    |

In order to run the `dm-service`, following dependencies are needed to be running/available before `dm-service`.

| Dependency   |                   Link                   | License  |
| ------------ | ---------------------------------------- | -------- |
| ubusd        | https://git.openwrt.org/project/ubus.git | LGPL 2.1 |
| libbbfdm-api | https://dev.iopsys.eu/bbf/bbfdm.git      | BSD-3    |
| libbbfdm-ubus | https://dev.iopsys.eu/bbf/bbfdm.git     | BSD-3    |
