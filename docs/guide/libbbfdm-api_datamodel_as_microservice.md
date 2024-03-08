# Datamodel additions (DotSO Plugin/ JSON Plugin/ Micro-Service)

It is often required by customers to have/implement some datamodel parameters which is not available in bbfdm, `bbfdm` provides four ways to extend the existing datamodel parameters.

- Using [JSON Plugin](./json_plugin_v1.md)
- Using [DotSO Plugin](./bbfdm_dm_integration.md)
- With bbfdm micro-service
- [Individual datamodel daemon](https://dev.iopsys.eu/voice/tr104)

Out of all the supported method, each have its own pro and cons:

## JSON Plugins
Pro:
 - Easy to add (compilation not required)
 - Least maintenance (Change in libbbfdm-api has minimal impact)

Con:
 - Can only support easy one to one mappings with uci and ubus
 - In-tree datamodel references not supported
 - Invalid plugin syntax might cause segfault on main bbfdmd service, result in complete cwmp/usp service down
 - Make the main tree bigger, which result into slow service time

## DotSO Plugin
Pro:
 - Similar to adding in the core
 - Support complex mapping and data sharing between nodes
 - All core operations supported

Con:
 - Moderate maintenance (Change in libbbfdm-api requires adaptation/alignment)
 - Any segfault on plugin might teardown main bbfdmd service, result in complete cwmp/usp service down
 - Make the main tree bigger, which result into slow service time

## BBFDM micro-service
Pro:
 - Creates a sub datamodel tree and registers to main datamodel tree
 - Can be used with existing DotSO and JSON Plugins
 - Faults in plugins only limited to micro-service, main tree won't gets affected

Con:
 - Currently references to out side tree nodes not supported
 - Maintenance cost depends on JSON or DotSO plugin selection

## Individual daemon to run micro-service
It has same pro and cons as of running the plugin with micro-service, with a added benefit of low maintenance as all the dependency embedded in single binary.

## Workflow of Individual daemon and micro-service
daemon started by the init script, it adds its own ubus objects based on input and wait for parent/master ubus object, once master ubus object available, it registers self with the main tree.

`icwmp` and `obuspa` gets the datamodel from main tree which is provided by `bbfdm` daemon, so no change required in either cwmp and obuspa.

## Summary
In plugins approach, the 3rd party datamodel gets attached to main bbfdm process, which further increases nodes in main datamodel tree, which overtime become a huge tree, results in slower turn around service time for the APIs.

Also with plugins, since its part of main process, any unhandled fault result in segfault in main bbfdmd process, which takes down the whole tree along with it, resulting in complete failure from cwmp and USP, with micro-services plugins runs as an individual processes, so impact of fault limited to its own process only.

Micro-service approach, disintegrate the plugins further and run them as individual daemons with the help of "bbfdmd" "-m" command line options.

## How to switch to micro-service model
It's a three step process, if DotSO or JSON plugin already present, if not refer to the plugins document.

1. Install the DotSO/JSON plugin to non-bbf plugin location
2. Create an input.json file, like below

```json
{
	"daemon": {
		"input": {
			"type": "JSON",  // JSON or DotSO
			"name": "/etc/bulkdata/bulkdata.json" // Path of the plugin
		},
		"output": {
			"type": "UBUS",
			"parent_dm": "Device.",    // Parent tree to attach the plugin
			"object": "BulkData",      // Name of the object
			"root_obj": "bbfdm"        // Name of the root tree ubus object which is bbfdm
		}
	}
}
```

3. Update init script to start the datamodel micro-service, which made simpler with `bbfdm` [init hooks](https://dev.iopsys.eu/feed/iopsys/-/commit/8bdfd3ea51a81941ee9c53a46a66cf6c0f6eb88f)

```bash
. /etc/bbfdm/bbfdm_services.sh
bbfdm_add_service "bbfdm.bulkdata" "/etc/bulkdata/input.json"
```

## When to switch to micro-service model
There are few parameters which can help in answer this query,
1. If a plugin add significantly huge amount of nodes to main tree
2. If the service known to miss-behave and cause faults
3. If a plugin add a service with no/less dependency on other datamodel parameters

## DotSO Plugins examples
 - [STUN](https://dev.iopsys.eu/bbf/stunc.git)
 - [UDPEcho](https://dev.iopsys.eu/bbf/udpecho.git)
 - [SoftwareModule](https://dev.iopsys.eu/bbf/swmodd.git)
 - [XMPP](https://dev.iopsys.eu/bbf/xmpp.git)
 - [TWAMP](https://dev.iopsys.eu/bbf/twamp-light.git)
 - [Usermngr](https://dev.iopsys.eu/bbf/usermngr.git)
 - [ManagementServer](https://dev.iopsys.eu/bbf/icwmp.git)

## JSON Plugin example
 - [URLFilter](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/urlfilter/files/etc/bbfdm/json/urlfilter.json)
 - [XPON](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/ponmngr/files/etc/bbfdm/json/xpon.json)

## Micro service example
 - [Bulkdata](https://dev.iopsys.eu/feed/iopsys/-/commit/8bdfd3ea51a81941ee9c53a46a66cf6c0f6eb88f)
 - [PeriodicStats](https://dev.iopsys.eu/feed/iopsys/-/commit/66163d394586b953b8f891f91afb1677df29403a)

## Individual daemons
 - [TR104](https://dev.iopsys.eu/feed/iopsys/-/commit/7160fadf5607fcc785fd13e41eac402da6164280)
