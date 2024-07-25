# Proposals for next bbfdm enhancements

I would like to bring a new perspective for the datamodel, that might help in achieving the lightning speed and will be least error prone.
I think, we can categorise datamodel in two parts,

1. Configuration, and
2. Information

and the magical glue to bind complex dependency/relationships between them are the datamodel references.

The current bbfdm stack works well to provide simple/moderate mappings, but it has its own limitations/issues, lets first review them,

-: Limitations/Issues :-

1. For configuration part of the datamodel it mostly maps to uci(Present in default path '/etc/config/'), which works well if we already have a OpenWRT service to provide that functionality, but if the datamodel layer is an abstraction between the datamodel and service layer and its kind of required to introduce another uci just for the sake of maintaining the datamodel in the same path which kind of duplicacy(ex: ddns and ddnsmngr uci)

2. For information part of it mostly maps to ubus, which currently only works with 'ubus_invoke' blocking call, so its not asynchronous. Which becomes bottleneck in real world fault scenarios. To give an example, assuming dataelement/wifi service daemon taking longer to provide the output over ubus, so either datamodel layer will timeout or it will take long to respond, which will result in longer wait time for ACS/Controller to fetch information.

3. Current way of defining datamodel in DotSO plugin is quite restrictive in the sence that adding new feature/enhancement requires complete re-write of all the DotSO plugins, also for new additions, users have to write all the handlers(get/set/add/del) from scratch.

4. JSON plugins are quite easy but can only hanlde simple one-to-one mapping

5. DMMAP works good as workaround, but its very messy and slow, each datamodel browse requires two way syncing from dmmap to standard-uci and vice-versa for each multi-instance object.

6. Current way of handling the datmaodel tree is also putting some restrictions, like it requires to load/map the tree in the memory for each operation, its not always in memory, so its bit slower and can't be use to simulate events, dues to which we have to use polling mechanism for operations like ValueChange from higherlayers, also for any kind of monitoring or threshold mapping we can't do that from current bbfdm because of its stateless nature.

7. Simple one-to-one mapping of datamodel parameters and lowerlayer, which works most of time, but fails for complex scenarios or can only support with  limitations, just to give an example 'Device.Bridging.ProviderBridge.{i}.Type' can't be implemented, as this changes the bridge type ('S-VLAN' => 'PE')

8. Also datamodel references were hard to manage, would like to highlight this point with few use cases
  - Someone try to setup a new Guest network from USP controller (Add with Set on multiple objects), but this would fail as bbfdm can't allow to have references of non-existing parameters
  - Since all datamodel references translates to lower layer directly, so some other action can easily change the datamodel references, like if someone created an Ethernet.Link with existing name, then all references to this new Link, automatically resolves to old one
  - Due to the hard coupling of datamodel and lowerlayer, it might possible that datamodel refrence might gets changed after upgrades

9. Over all response time is higher for CUD(Create/Update/Delete) operations, also its very error prone, one has to follow the exact same sequence of steps to do certain thing

10. It takes very long time to get the tree if it has too many instances (Currently we have a cap on max 255 instance per object)

I think, these are few point that I can think of right now, but there might be more points where we might have to improve.
In this document, I try to propose solution for most of these issues/limitations.

## Proposal for auto-generated datamodel layer (autodm)

This proposal might not be applicable to all the datamodel, but could be a good fit for the most complex sub-systems(like network).

Its a mixed approach to re-define datamodel using JSON and DOTSo plugin combined, so user has to use the JSON for base datamodel definition, `autodm` will automatically create a uci file in non-default uci location ('/etc/bbfdm/config/') with file of base object and it will automatically create sections and uci options based on json.

example: Lets consider user wants to add `Device.PCP.` datamodel,

- User has to define a base datamodel json definition,

```json
{
        "_autodm_version": 1.0,
        "_overload_apply": true,
		"Device.PCP.": {
			"type": "object",
			"protocols": [
				"cwmp",
				"usp"
			],
			"access": false,
			"array": false,
			"Enable": {
				"type": "boolean",
				"read": true,
				"write": true,
				"protocols": [
					"cwmp",
					"usp"
				],
				"datatype": "boolean"
			},
			"SupportedVersions": {
				"type": "string",
				"read": true,
				"write": false,
				"protocols": [
					"cwmp",
					"usp"
				],
				"list": {
					"datatype": "unsignedInt",
					"range": [
						{
							"min": 0,
							"max": 65535
						}
					]
				},
				"_overload": true
			},
			"Device.PCP.Client.{i}.": {
				"type": "object",
				"protocols": [
					"cwmp",
					"usp"
				],
				"uniqueKeys": [
					"Alias",
					"WANInterface"
				],
				"access": true,
				"array": true,
				"Enable": {
					"type": "boolean",
					"read": true,
					"write": true,
					"protocols": [
						"cwmp",
						"usp"
					],
					"datatype": "boolean"
				},
				"Alias": {
					"type": "string",
					"read": true,
					"write": true,
					"protocols": [
						"cwmp",
						"usp"
					],
					"datatype": "Alias",
					"range": [
						{
							"max": 64
						}
					]
				}
			}
		}
    }
```

- and `autodm` will create a uci mapping for this as

```bash
$ cat /etc/bbfdm/config/pcp
config pcp pcp
    option Enable '0'

config pcp_client pcp_client_1
    option Enable '0'
    option Alias 'cpe-1'
```

- For complex mapping User can overload the auto-mapping with C-Function using '_overload' key as true, so when this '_overload' is true, instead of using predefined auto-handlers, `autodm` shall call the overload handler function for that parameter handling.

Now, this approach does not take care for the lowerlayer implemention, so the apply hanler has to be written externally, like ddnsmngr can write 'ddns' uci from this information and apply it, so it decouples the datamodel layer and service layer.

If for some use cases, we might not want to use an external handler, then we can use '_overload_apply' override to do the apply using another C-function, which will be called from 'bbf.config' to apply the changes, so again de-coupling the datamodel layer from service layer.


Notes:
- USP operate and event operations will work based on generic events based mechanism
- dmmap would not be required, as all the additional information can be kept along with datamodel parameters


## Proposal for In memory tree

Currently each operation start with 'bbfdm_ctx_init' followed by actuall operation and finished with 'bbfdm_ctx_cleanup', which creates the tree, operates on the tree and deletes the tree at the end.

This is a slow approach and this always have to use blocking calls to get the values and to do the multi-instance browsing.

My proposal is to use the 'bbfdm_ctx_init' only when bbfdmd starts and do the datamodel operations directly, so this will keep the tree and all the datamodel operation will be performed on the same tree, so the tree in memory act as a cached data source, with this it would be possible to use 'ubus_invoke_async' which will update the data when its available from lowerlayer, so this way it will work even with slow responding service backend quite significantly and it will responde quickly on low resource system as well.

With this it would also be possible to have a event like simulation for ValueChange/monitor kind of operation.


## Proposal for core-datamodel plugin

Currently we have below datamodel defined directly in bbfdm

- device.c
- deviceinfo.c
- gatewayinfo.c
- gre.c
- interfacestack.c
- ip.c
- lanconfigsecurity.c
- ppp.c
- routeradvertisement.c
- routing.c
- security.c

We already had a discussions to move some of the components out, but for the time being, proposal is to create a micro-service 'bbfdm.core' to host all these as plugins and only have `bbfdm` with `device.c` to further reduce the possibility of crash due to datamodel.

This step will also increase the readiness of these datamodels for easy migrations to their micro-services latter.
