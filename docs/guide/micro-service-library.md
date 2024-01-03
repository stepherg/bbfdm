The document is just a proposal to explain why it is necessary to have a micro-service library and what its benefits are.

# Current State of micro-service:

The current implementation consists of two main components for each service:

 - One provides the service layer (hostmngr, periodicstats, etc..)
 - Other provides the Data Model layer/wrapper/mappings (bbfdm micro-service)

These components are connected using uci and ubus mappings, but this design introduces some known limitations/problems:

 - another layer of abstraction always required, like uci for service configuration and ubus for runtime stats
 - sync between the Data Model layer and service layer

# Proposed Solution:

To address the identified limitations and problems, the proposal is to introduce a new micro-service library which will be integrated with the service daemon itself.
Therefore with this approach, we will be sure that all operations are handled internally, and only a standard Data Model layer will be exposed over ubus.

# Benefit:

- Reduces resource and memory usage by minimizing the number of processes.

- Removes redundancy of information, making it visible only through the Data Model.

- Everything will managed internally and exposed directly through the Data Model.

- Higher-level applications (e.g., GUI, USP, CWMP) can easily interact with the Data Model for various operations.

- Easy to each team to manage their Data Model based on their internal APIs.

# Integration Steps:

1. Update bbfdmd to use the new micro-service library.
2. Align all other applications with the new library to streamline Data Model integration.

# Example Using the New Micro-Service Library:

Let's consider SoftwareModules as an example. Currently, we manage software modules internally using a uci file as a configuration and then expose the necessary APIs to higher applications through ubus.
Afterward, we utilize these APIs to expose the SoftwareModules Data Model and handle SoftwareModules from other applications, such as cwmp, which uses these APIs to manage the CDState rpc.

```bash
$ ubus -v list swmodules
'swmodules' @c5b7fce5
	"ee_list":{}
	"reload":{}
	"du_list":{"eeid":"Integer","ee_name":"String"}
	"eu_list":{"eeid":"Integer","ee_name":"String"}
	"du_install":{"eeid":"Integer","ee_name":"String","uuid":"String","url":"String","username":"String","password":"String"}
	"du_update":{"eeid":"Integer","ee_name":"String","uuid":"String","url":"String","username":"String","password":"String"}
	"du_uninstall":{"eeid":"Integer","ee_name":"String","du_name":"String"}
	"set_config":{"eeid":"Integer","ee_name":"String","uuid":"String","eu_name":"String","parameter":"String","value":"String"}
root@nvg678-a0687ef725c0:~# 
```

The disadvantage of this approach is that any updates to these APIs require modifications in all top layers.
The proposed solution is to internally integrate the new micro-service library with the SoftwareModules core to expose the Data Model layer over ubus. Subsequently, higher applications can utilize these APIs to manage the device without requiring additional changes if backend updates are needed.

Below are the new APIs that will be exposed from SoftwareModules and utilized by all higher applications.

```bash
'bbfdm.swmodules' @5d33aba5
	"get":{"path":"String","paths":"Array","maxdepth":"Integer","optional":"Table"}
	"schema":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
	"instances":{"path":"String","paths":"Array","first_level":"Boolean","optional":"Table"}
	"set":{"path":"String","value":"String","obj_path":"Table","optional":"Table"}
	"operate":{"command":"String","command_key":"String","input":"Table","optional":"Table"}
	"add":{"path":"String","obj_path":"Table","optional":"Table"}
	"del":{"path":"String","paths":"Array","optional":"Table"}
	"transaction":{"cmd":"String","timeout":"Integer","restart_services":"Boolean","optional":"Table"}
```

> These new APIs will streamline the integration process and minimize the need for changes in higher application layers when backend updates occur.
