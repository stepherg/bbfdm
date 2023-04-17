# BroadBand Forum Data Models (BBFDM)

`bbfdm` is an implementation developed by iopsys that conforms to Broadband Forum Data Models and which includes a list objects, parameters, events and operates used for CPE management through remote control protocols such as [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).


This implementation comprises of the three main components:

| Component  |                    Description                    |
| ---------- | ------------------------------------------------- |
| libbbf_api | It is a library that provides many APIs used to interact with UCI configurations, Ubus objects, JSON schema, CLI commands and memory management. It also provides a mechanism to add new objects, parameters, events and operates or extend the existing DM tree using json plugin or shared library plugin. |
| libbbf_dm  | It's a libarry that provides the different data models supported by iopsys |
| bbfdmd | It's a deamon which used to expose data model objects over ubus |


## Design of bbfdm

`bbfdm` package is structred as follow:


```bash
├── bbfdmd
├── docs
├── libbbf_api
├── libbbf_dm
│   ├── dmtree
│   │   ├── json
│   │   ├── tr104
│   │   ├── tr143
│   │   ├── tr181
│   │   ├── tr471
│   │   ├── vendor
│   ├── scripts
└── tools
```

- `bbfdmd` folder which contains the source code of bbfdm deamon.
More explanation on how this daemon works and all supported methods are presented in this file[BBFDMD](./bbfdmd/src/README.md)

- `libbbf_dm` folder which contains the different data models supported by iopsys

	- `dmtree` folder which includes all supported Data Models and vendor extension objects. It contains 6 folders:

		- `tr181` folder : TR-181 Data Model files

		- `tr104` folder : Voice Services Data Model files

		- `tr143` folder : Diagnostics Data Model files

		- `tr471` folder : IPLayerCapacityMetrics Diagnostics Data Model files

		- `vendor` folder : Vendor Data Model files

		- `json` folder : TR-181 and TR-104 JSON files

	- `scripts` folder which contains all the scripts used to run the different types of diagnostics.

- `libbbf_api` folder which contains the source code of all API functions (UCI, Ubus, JSON, CLI and memory management). These API are used for GET/SET/ADD/Delete/Operate calls which can be called in internal or external packages.
All APIs exposed by libbbf_api are presented in this header file [libbbf_api.h](https://dev.iopsys.eu/bbf/bbfdm/-/tree/devel/libbbf_api/include/libbbf_api.h).

- `tools` folder which contains some tools to generate Data Model in C, JSON, XML and Excel format.
All supported tools are presented in this file[BBFDM Tools](./docs/guide/tools.md)

- `docs` folder which contains all documentation files.


## Important Topics
* [Design for firmware activation](./docs/guide/activate_firmware.md)
* [TR181 Firewall datamodel mappings](./docs/guide/firewall.md)
* [Datamodel extension using JSON plugin](./docs/guide/json_plugin_v1.md)
* [Add support of a new Object/Parameter](./docs/guide/obj_param_extension.md)
* [How to add new vendor](./docs/guide/vendor.md)
* [Dynamic Object/Parameter/Operate/Event](./docs/guide/dynamic_dm.md)
* [BBFDM Tools](./docs/guide/tools.md)
* [Wireless Configuration handling](./docs/guide/wireless_easymesh.md)
* [Explain the different Network Deployment Scenarios](./docs/guide/network_depoyment_scenarios.md)
* [How to Configure MACVLAN](./docs/guide/macvlan_interface.md)
* [Explain Policy Based Routing Management](./docs/guide/policy_based_routing.md)


## External dependencies for datamodel objects

| Datamodel                                | Package        | Link                                         |
| ---------------------------------------- | -------------- | -------------------------------------------- |
| Device.BulkData.                         | bulkdata       | https://dev.iopsys.eu/bbf/bulkdata.git    |
| Device.ManagementServer.                 | icwmp          | https://dev.iopsys.eu/bbf/icwmp.git       |
| Device.CWMPManagementServer.             | icwmp          | https://dev.iopsys.eu/bbf/icwmp.git       |
| Device.IP.Diagnostics.UDPEchoConfig.     | udpecho-server | https://dev.iopsys.eu/bbf/udpecho.git     |
| Device.IP.Diagnostics.UDPEchoDiagnostics.| udpecho-client | https://dev.iopsys.eu/bbf/udpecho.git     |
| Device.IP.Interface.{i}.TWAMPReflector.  | twamp          | https://dev.iopsys.eu/bbf/twamp-light.git |
| Device.UPNP.                             | ssdpd          | https://github.com/miniupnp/miniupnp.git     |
| Device.XMPP.                             | xmppc          | https://dev.iopsys.eu/bbf/xmppc.git       |
| Device.XPON.                             | ponmngr        | https://dev.iopsys.eu/bbf/ponmngr.git     |
| Device.USPAgent.                         | obuspa         | https://dev.iopsys.eu/bbf/obuspa.git        |
| STUN parameters                          | stunc          | https://dev.iopsys.eu/bbf/stunc.git       |
