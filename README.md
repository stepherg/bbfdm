# BroadBand Forum Data Models (BBFDM)

`bbfdm` is a datamodel backend for Higher layer management protocols like [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/). It is designed in a hardware agnostic way and provides the available datamodel parameters over ubus on the northbound interface and creates the datamodel mapping based on uci and ubus on southbound interface.

`bbfdm` has three main components:

| Component  |                    Description                    |
| ---------- | ------------------------------------------------- |
| bbfdmd | A daemon to expose data model objects over ubus in pretty and raw format |
| libbbfdm-api | A shared library which provides API to build and parse datamodel tree, it also provides API to create datamodel extensions using shared DotSo plugin, or with JSON Plugin. |
| libbbfdm  | A datamodel tree/library build with libbbfdm-api, it includes core TR181 and related datamodel |


## Directory Structure

`bbfdm` package is structured as follow:

```bash
├── bbfdmd
├── docs
├── libbbfdm-api
├── libbbfdm
│   ├── dmtree
│   │   ├── json
│   │   ├── tr143
│   │   ├── tr181
│   │   ├── tr471
│   │   ├── vendor
│   ├── scripts
└── tools
```

- `bbfdmd` folder which contains the source code of bbfdm deamon.
More explanation on how this daemon works and all supported methods are presented in this file [BBFDMD](./docs/guide/bbfdmd.md)

- `libbbfdm` folder which contains the different data models supported by iopsys

	- `dmtree` folder which includes all supported Data Models and vendor extension objects. It contains 6 folders:

		- `tr181` folder : TR-181 Data Model files

		- `tr143` folder : Diagnostics Data Model files

		- `tr471` folder : IPLayerCapacityMetrics Diagnostics Data Model files

		- `vendor` folder : Vendor Data Model files

		- `json` folder : TR-181 and TR-104 JSON files

	- `scripts` folder which contains all the scripts used to run the different types of diagnostics.

- `libbbfdm-api` folder which contains the source code of all API functions (UCI, Ubus, JSON, CLI and memory management). These API are used for GET/SET/ADD/Delete/Operate calls which can be called in internal or external packages.
All APIs exposed by libbbfdm-api are presented in this header file [libbbfdm_api.h](./libbbfdm-api/include/libbbfdm_api.h).

- `tools` folder which contains some tools to generate Data Model in C, JSON, XML and Excel format.
All supported tools are presented in this file[BBFDM Tools](./tools/README.md)

- `docs` folder which contains all documentation files.


## Design
* [BBFDMD Design](./docs/guide/bbfdmd.md)
* [Datamodel extension using JSON plugin](./docs/guide/libbbfdm-api_json_plugin_v1.md)
* [Datamodel Plugins and Microservice](./docs/guide/libbbfdm-api_datamodel_as_microservice.md)
* [BBFDM Tools](./tools/README.md)

## Important Topics
* [Add support of a new Object/Parameter](./docs/guide/libbbfdm-api_obj_param_extension.md)
* [How to add new vendor](./docs/guide/libbbfdm-api_vendor.md)
* [Dynamic Object/Parameter/Operate/Event](./docs/guide/libbbfdm-api_dynamic_dm.md)
* [Design for firmware activation](./docs/guide/libbbfdm_DeviceInfo_FirmwareImage.md)
* [TR181 Firewall datamodel mappings](./docs/guide/libbbfdm_Firewall.md)
* [Wireless Configuration handling](./docs/guide/libbbfdm_WiFi.md)
* [Explain the different Network Deployment Scenarios](./docs/guide/network_depoyment_scenarios.md)
* [How to Configure MACVLAN](./docs/guide/libbbfdm_Ethernet_X_IOPSYS_EU_MACVLAN.md)
* [Explain Policy Based Routing Management](./docs/guide/libbbfdm_Routing.md)
* [TR181 DNS datamodel](./docs/guide/libbbfdm_DNS.md)

## External dependencies for datamodel objects

| Datamodel                                | Package        | Link                                         |
| ---------------------------------------- | -------------- | -------------------------------------------- |
| Device.BulkData.                         | bulkdata       | https://dev.iopsys.eu/bbf/bulkdata.git       |
| Device.ManagementServer.                 | icwmp          | https://dev.iopsys.eu/bbf/icwmp.git          |
| Device.CWMPManagementServer.             | icwmp          | https://dev.iopsys.eu/bbf/icwmp.git          |
| Device.IP.Diagnostics.UDPEchoConfig.     | udpecho-server | https://dev.iopsys.eu/bbf/udpecho.git        |
| Device.IP.Diagnostics.UDPEchoDiagnostics.| udpecho-client | https://dev.iopsys.eu/bbf/udpecho.git        |
| Device.IP.Interface.{i}.TWAMPReflector.  | twamp          | https://dev.iopsys.eu/bbf/twamp-light.git    |
| Device.XMPP.                             | xmppc          | https://dev.iopsys.eu/bbf/xmppc.git          |
| Device.USPAgent.                         | obuspa         | https://dev.iopsys.eu/bbf/obuspa.git         |
| STUN parameters                          | stunc          | https://dev.iopsys.eu/bbf/stunc.git          |
| Device.XPON.                             | ponmngr        | https://dev.iopsys.eu/hal/ponmngr.git        |
| Device.UPNP.                             | ssdpd          | https://github.com/miniupnp/miniupnp.git     |
| Device.Users.				               | usermngr       | https://dev.iopsys.eu/bbf/usermngr.git       |
| Device.PeriodicStatistics.		       | periodicstats  | https://dev.iopsys.eu/bbf/periodicstats.git  |
| Device.SoftwareModules.		           | swmodd         | https://dev.iopsys.eu/lcm/swmodd.git         |
| Device.Time.		                       | timemngr       | https://dev.iopsys.eu/bbf/timemngr.git       |
| Device.DynamicDNS.	                       | ddnsmngr       | https://dev.iopsys.eu/bbf/ddnsmngr.git       |
| Device.Hosts.		                       | hostmngr       | https://dev.iopsys.eu/iopsys/hostmngr.git    |
| Device.Services.VoiceService.            | tr104          | https://dev.iopsys.eu/voice/tr104.git        |
