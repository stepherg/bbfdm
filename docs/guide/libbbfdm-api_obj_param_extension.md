# How to add support for a new Object/Parameter

As mentioned in README, all Data Models are stored in the **'dmtree'** folder. In order to implement a new object/parameter, you need to expand its get/set/add/delete functions and then save them in the right folder.

`bbfdm` library offers a tool to generate templates of the source code from json files placed under **'dmtree/json'**. So, any developer can fill these json files ([tr181](../../libbbfdm/dmtree/json/tr181.json) or [tr104](../../libbbfdm/dmtree/json/tr104.json)) with mapping field according to UCI, UBUS or CLI commands then generate the source code in C.

```bash
$ ./convert_dm_json_to_c.py
Usage: convert_dm_json_to_c.py <data model name> [Object path]
data model name:   The data model(s) to be used, for ex: tr181 or tr181,tr104
Examples:
  - convert_dm_json_to_c.py tr181
    ==> Generate the C code of tr181 data model in datamodel/ folder
  - convert_dm_json_to_c.py tr104
    ==> Generate the C code of tr104 data model in datamodel/ folder
  - convert_dm_json_to_c.py tr181,tr104
    ==> Generate the C code of tr181 and tr104 data model in datamodel/ folder
  - convert_dm_json_to_c.py tr181 Device.DeviceInfo.
    ==> Generate the C code of Device.DeviceInfo object in datamodel/ folder
  - convert_dm_json_to_c.py tr104 Device.Services.VoiceService.{i}.Capabilities.
    ==> Generate the C code of Device.Services.VoiceService.{i}.Capabilities. object in datamodel/ folder
```

Below some examples of **UCI**, **UBUS** or **CLI** mappings:

#### UCI command

- **@Name:** the section name of parent object

- **@i:** is the number of instance object

```bash
	"mapping": [
		{
			"type": "uci",
			"uci": {
				"file": "wireless",
				"section": {
					"type": "wifi-device",
					"name": "@Name",
					"index": "@i-1"
				},
				"option": {
					"name": "disabled"
				}
			}
		}
	]
```

#### UBUS command

- **@Name:** the section name of parent object

```bash
	"mapping": [
		{
			"type": "ubus",
			"ubus": {
				"object": "network.device",
				"method": "status",
				"args": {
					"name": "@Name"
				},
				"key": "statistics.rx_bytes"
			}
		}
	]
```

#### CLI command:

- **@Name:** the section name of parent object

- **-i:** is the number of arguments command

```bash
	"mapping": [
		{
			"type" : "cli",
			"cli" : {
				"command" : "wlctl",
				"args" : [
					"-i",
					"@Name",
					"bands"
				]
			}
		}
	]
```

After building the templates of C source code, a **datamodel** folder will be generated under **'tools'** folder that contains all files related to each object under root "**Device.**"

> Note: You can generate the source code without filling out the mapping field in the JSON file

### Object definition

Each object in the **DMOBJ** table contains the following arguments:

|     Argument        |                            Description                                                               |
| ------------------- | ---------------------------------------------------------------------------------------------- |
| `OBJ`               | A string of the object name. Example “Bridging”, “IP”, “DeviceInfo”, “WiFi” |
| `permission`        | The permission of the object. Could be **&DMREAD** or **&DMWRITE**. If it's `&DMWRITE` then we can add/delete instances of this object |
| `addobj`            | The function to add new instance under this object. This function will be triggered when the ACS/Controller call AddObject of this object |
| `delobj`            | The function to delete instance under this object. This function will be triggered when the ACS/Controller call DeleteObject of an instance of this object |
| `checkdep`          | A string of the object dependency, it can be a file("file:/etc/config/network") or an ubus object,method("ubus:network.interface->status"). If it's `NULL` then the object has always appeared in the tree |
| `browseinstobj`     | This function allow to browse all instances under this object |
| `nextdynamicobj`    | Pointer to the next of **DMOBJ** which contains a list of the child objects using json files, shared libraries and vendor extension |
| `dynamicleaf`       | Pointer to the next of **DMLEAF** which contains a list of the child parameters using json files, shared libraries and vendor extension |
| `nextobj`           | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `leaf`              | Pointer to a **DMLEAF** array which contains a list of the child parameters |
| `linker`            | This argument is deprecated and should be `NULL` |
| `bbfdm_type`        | The bbfdm type of the object. Could be **BBFDM_CWMP**, **BBFDM_USP**, **BBFDM_BOTH** or **BBFDM_NONE**.If it's **BBFDM_BOTH** then we can see this object in all protocols (CWMP, USP,...) |
| `uniqueKeys`        | This argument is deprecated and should be `NULL` |

### Leaf definition

Each leaf in the **DMLEAF** table can be a **Parameter**, **Command** or **Event**.


#### 1.Parameter definition

|     Argument        |                             Description                                                               |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the parameter name. Example “Enable”, “Status”, “Name” |
| `permission`        | The permission of the parameter. Could be **&DMREAD** or **&DMWRITE**.If it's `&DMWRITE` then we can set a value for this parameter |
| `type`              | Type of the parameter: **DM_STRING**, **DM_BOOL**, **DM_UNINT**,... |
| `getvalue`          | The function which return the value of this parameter |
| `setvalue`          | The function which set the value of this parameter |
| `bbfdm_type`        | The bbfdm type of the parameter. Could be **BBFDM_CWMP**, **BBFDM_USP**, **BBFDM_BOTH** or **BBFDM_NONE**.If it's **BBFDM_BOTH** then we can see this parameter in all protocols (CWMP, USP,...) |
| `dm_falgs`          | An enumeration value used to specify the displayed parameter value. Could be **DM_FLAG_REFERENCE**, **DM_FLAG_UNIQUE**, **DM_FLAG_LINKER** or **DM_FLAG_SECURE**. |

#### 2.Command definition

|     Argument        |                             Description                                                               |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the command name. Example “IPPing()”, “DownloadDiagnostics()”, “Renew()” |
| `permission`        | The permission of the command. Could be **&DMASYNC** or **&DMSYNC**. |
| `type`              | Type of the command, It should be **DMT_COMMAND** |
| `getvalue`          | The function which return the input, output arguments of the command |
| `setvalue`          | The function which call the operation of the command |
| `bbfdm_type`        | The bbfdm type of the command. It should be **BBFDM_USP** as long as operate commands are only defined in USP protocol. |


#### 3.Event definition

|     Argument        |                             Description                                                               |
| ------------------- | -------------------------------------------------------------------------------------------------- |
| `PARAM`             | A string of the event name. Example “Boot!”, “Push!”, “Periodic!” |
| `permission`        | The permission of the event. It should be **DMREAD** |
| `type`              | Type of the event, It should be **DMT_EVENT** |
| `getvalue`          | The function which return the parameter arguments of the event |
| `setvalue`          | The function which call the operation of the event |
| `bbfdm_type`        | The bbfdm type of the event. It should be **BBFDM_USP** as long as events are only defined in USP protocol. |


### Browse definition

The browse function allow to go over all instances of the current object and link them to the data model tree.

In this function, there are two functions that need to be defined:

- function to retrieve the instances: it can be:

	* `handle_instance` function: allow to retrieve/attribute the instances number/alias from uci config sections depending of the request and the instance mode.

	* `handle_instance_without_section` function: allow to attribute the instances number/alias with constant values.

- function to link the instances: To link each instance to the data model tree, it's necessary to call `DM_LINK_INST_OBJ()` API for every instance. Additionally, it's recommended to utilize the generic structure `(struct dm_data *)` as the passed `data` at each instance level. This structure will be utilized later in functions related to sub-objects and parameters (Get/Set/Add/Delete/Operate/Event).

> Note1: the browse function is only developed for multi-instances objects.

> Note2: you can use [bbf_test plugin](../../test/bbf_test/bbf_test.c) as a reference in order to develop any new object/leaf/browse.

> Note3: Extending the object list below using `JSON` Plugin is prohibited because the `data` passed in `DM_LINK_INST_OBJ()` API differs from the generic structure `(struct dm_data *)`. To accomplish this task, you have two options: either update the required object to utilize the generic structure in the passed data, or alternatively, use the `DotSo` plugin.

- Device.ATM.Link.{i}.
- Device.ATM.Link.{i}.Stats.
- Device.Bridging.Bridge.{i}.
- Device.Bridging.Bridge.{i}.Port.{i}.
- Device.Bridging.Bridge.{i}.Port.{i}.Stats.
- Device.Bridging.Bridge.{i}.STP.
- Device.Bridging.Bridge.{i}.VLAN.{i}.
- Device.Bridging.Bridge.{i}.VLANPort.{i}.
- Device.Bridging.ProviderBridge.{i}.
- Device.DHCPv4.Server.Pool.{i}.
- Device.DHCPv4.Server.Pool.{i}.Client.{i}.
- Device.DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}.
- Device.DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}.
- Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.
- Device.DHCPv6.Server.Pool.{i}.Client.{i}.
- Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Address.{i}.
- Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Prefix.{i}.
- Device.DNS.Client.Server.{i}.
- Device.DNS.Relay.Forwarding.{i}.
- Device.DNS.SD.Service.{i}.
- Device.DNS.SD.Service.{i}.TextRecord.{i}.
- Device.DSL.Channel.{i}.
- Device.DSL.Channel.{i}.Stats.
- Device.DSL.Channel.{i}.Stats.CurrentDay.
- Device.DSL.Channel.{i}.Stats.LastShowtime.
- Device.DSL.Channel.{i}.Stats.QuarterHour.
- Device.DSL.Channel.{i}.Stats.Showtime.
- Device.DSL.Channel.{i}.Stats.Total.
- Device.DSL.Line.{i}.
- Device.DSL.Line.{i}.Stats.
- Device.DSL.Line.{i}.Stats.CurrentDay.
- Device.DSL.Line.{i}.Stats.LastShowtime.
- Device.DSL.Line.{i}.Stats.QuarterHour.
- Device.DSL.Line.{i}.Stats.Showtime.
- Device.DSL.Line.{i}.Stats.Total.
- Device.DeviceInfo.FirmwareImage.{i}.
- Device.DeviceInfo.MemoryStatus.
- Device.DeviceInfo.ProcessStatus.
- Device.DeviceInfo.ProcessStatus.Process.{i}.
- Device.DeviceInfo.Processor.{i}.
- Device.DeviceInfo.VendorConfigFile.{i}.
- Device.DynamicDNS.Client.{i}.
- Device.DynamicDNS.Client.{i}.Hostname.{i}.
- Device.DynamicDNS.Server.{i}.
- Device.Ethernet.Interface.{i}.
- Device.Ethernet.Interface.{i}.Stats.
- Device.Ethernet.Link.{i}.
- Device.Ethernet.Link.{i}.Stats.
- Device.Ethernet.RMONStats.{i}.
- Device.Ethernet.VLANTermination.{i}.
- Device.Ethernet.VLANTermination.{i}.Stats.
- Device.Ethernet.X_IOPSYS_EU_MACVLAN.{i}.
- Device.Ethernet.X_IOPSYS_EU_MACVLAN.{i}.Stats.
- Device.FAST.Line.{i}.
- Device.FAST.Line.{i}.Stats.
- Device.FAST.Line.{i}.Stats.CurrentDay.
- Device.FAST.Line.{i}.Stats.LastShowtime.
- Device.FAST.Line.{i}.Stats.QuarterHour.
- Device.FAST.Line.{i}.Stats.Showtime.
- Device.FAST.Line.{i}.Stats.Total.
- Device.Firewall.Chain.{i}.
- Device.Firewall.Chain.{i}.Rule.{i}.
- Device.Firewall.Level.{i}.
- Device.Hosts.AccessControl.{i}.
- Device.Hosts.AccessControl.{i}.Schedule.{i}.
- Device.Hosts.Host.{i}.
- Device.Hosts.Host.{i}.IPv4Address.{i}.
- Device.Hosts.Host.{i}.IPv6Address.{i}.
- Device.Hosts.Host.{i}.WANStats.
- Device.IEEE1905.AL.ForwardingTable.ForwardingRule.{i}.
- Device.IEEE1905.AL.Interface.{i}.
- Device.IEEE1905.AL.Interface.{i}.Link.{i}.
- Device.IEEE1905.AL.Interface.{i}.Link.{i}.Metric.
- Device.IEEE1905.AL.Interface.{i}.VendorProperties.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.BridgingTuple.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IEEE1905Neighbor.{i}.Metric.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv4Address.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.IPv6Address.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.Interface.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.NonIEEE1905Neighbor.{i}.
- Device.IEEE1905.AL.NetworkTopology.IEEE1905Device.{i}.VendorProperties.{i}.
- Device.IP.Interface.{i}.
- Device.IP.Interface.{i}.IPv4Address.{i}.
- Device.IP.Interface.{i}.IPv6Address.{i}.
- Device.IP.Interface.{i}.IPv6Prefix.{i}.
- Device.IP.Interface.{i}.Stats.
- Device.IP.Interface.{i}.TWAMPReflector.{i}.
- Device.InterfaceStack.{i}.
- Device.NAT.PortTrigger.{i}.
- Device.NAT.PortTrigger.{i}.Rule.{i}.
- Device.PPP.Interface.{i}.
- Device.PPP.Interface.{i}.IPCP.
- Device.PPP.Interface.{i}.IPv6CP.
- Device.PPP.Interface.{i}.PPPoE.
- Device.PPP.Interface.{i}.Stats.
- Device.PTM.Link.{i}.
- Device.PTM.Link.{i}.Stats.
- Device.PeriodicStatistics.SampleSet.{i}.
- Device.PeriodicStatistics.SampleSet.{i}.Parameter.{i}.
- Device.QoS.QueueStats.{i}.
- Device.Routing.RouteInformation.InterfaceSetting.{i}.
- Device.Routing.Router.{i}.
- Device.Routing.Router.{i}.IPv4Forwarding.{i}.
- Device.Routing.Router.{i}.IPv6Forwarding.{i}.
- Device.SSH.AuthorizedKey.{i}.
- Device.SSH.Server.{i}.Session.{i}.
- Device.Security.Certificate.{i}.
- Device.Services.VoiceService.{i}.
- Device.Services.VoiceService.{i}.CallControl.
- Device.Services.VoiceService.{i}.CallControl.CallingFeatures.
- Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.
- Device.Services.VoiceService.{i}.CallControl.CallingFeatures.Set.{i}.SCREJ.{i}.
- Device.Services.VoiceService.{i}.CallControl.Extension.{i}.
- Device.Services.VoiceService.{i}.CallControl.Group.{i}.
- Device.Services.VoiceService.{i}.CallControl.IncomingMap.{i}.
- Device.Services.VoiceService.{i}.CallControl.Line.{i}.
- Device.Services.VoiceService.{i}.CallControl.Line.{i}.Stats.
- Device.Services.VoiceService.{i}.CallControl.Line.{i}.Stats.DSP.
- Device.Services.VoiceService.{i}.CallControl.Line.{i}.Stats.IncomingCalls.
- Device.Services.VoiceService.{i}.CallControl.Line.{i}.Stats.OutgoingCalls.
- Device.Services.VoiceService.{i}.CallControl.Line.{i}.Stats.RTP.
- Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.
- Device.Services.VoiceService.{i}.CallControl.NumberingPlan.{i}.PrefixInfo.{i}.
- Device.Services.VoiceService.{i}.CallControl.OutgoingMap.{i}.
- Device.Services.VoiceService.{i}.CallLog.{i}.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.DSP.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.DSP.ReceiveCodec.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.DSP.TransmitCodec.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Destination.RTP.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.DSP.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.DSP.ReceiveCodec.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.DSP.TransmitCodec.
- Device.Services.VoiceService.{i}.CallLog.{i}.Session.{i}.Source.RTP.
- Device.Services.VoiceService.{i}.Capabilities.
- Device.Services.VoiceService.{i}.Capabilities.Codec.{i}.
- Device.Services.VoiceService.{i}.Capabilities.POTS.
- Device.Services.VoiceService.{i}.Capabilities.SIP.
- Device.Services.VoiceService.{i}.Capabilities.SIP.Client.
- Device.Services.VoiceService.{i}.CodecProfile.{i}.
- Device.Services.VoiceService.{i}.DECT.
- Device.Services.VoiceService.{i}.DECT.Base.{i}.
- Device.Services.VoiceService.{i}.DECT.Portable.{i}.
- Device.Services.VoiceService.{i}.POTS.
- Device.Services.VoiceService.{i}.POTS.FXS.{i}.
- Device.Services.VoiceService.{i}.POTS.FXS.{i}.VoiceProcessing.
- Device.Services.VoiceService.{i}.ReservedPorts.
- Device.Services.VoiceService.{i}.SIP.
- Device.Services.VoiceService.{i}.SIP.Client.{i}.
- Device.Services.VoiceService.{i}.SIP.Network.{i}.
- Device.Services.VoiceService.{i}.SIP.Network.{i}.FQDNServer.{i}.
- Device.Services.VoiceService.{i}.VoIPProfile.{i}.
- Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.
- Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.RTCP.
- Device.Services.VoiceService.{i}.VoIPProfile.{i}.RTP.SRTP.
- Device.SoftwareModules.DeploymentUnit.{i}.
- Device.SoftwareModules.ExecEnv.{i}.
- Device.SoftwareModules.ExecutionUnit.{i}.
- Device.Time.Client.{i}.
- Device.Time.Client.{i}.Stats.
- Device.Time.Server.{i}.
- Device.Time.Server.{i}.Stats.
- Device.UPnP.Description.DeviceDescription.{i}.
- Device.UPnP.Description.DeviceInstance.{i}.
- Device.UPnP.Description.ServiceInstance.{i}.
- Device.UPnP.Discovery.Device.{i}.
- Device.UPnP.Discovery.RootDevice.{i}.
- Device.UPnP.Discovery.Service.{i}.
- Device.USB.Interface.{i}.
- Device.USB.Interface.{i}.Stats.
- Device.USB.Port.{i}.
- Device.USB.USBHosts.Host.{i}.
- Device.USB.USBHosts.Host.{i}.Device.{i}.
- Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.
- Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.Interface.{i}.
- Device.UserInterface.HTTPAccess.{i}.
- Device.UserInterface.HTTPAccess.{i}.Session.{i}.
- Device.Users.Group.{i}.
- Device.Users.Role.{i}.
- Device.Users.SupportedShell.{i}.
- Device.Users.User.{i}.
- Device.XMPP.Connection.{i}.
- Device.XMPP.Connection.{i}.Server.{i}.
- Device.XMPP.Connection.{i}.Stats.
