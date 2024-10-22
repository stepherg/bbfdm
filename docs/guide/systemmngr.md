# System Manager
This is a high level proposal document for 'Device.DeviceInfo.' implementation, since most of the datamodel in 'DeviceInfo' related to device/cpe/system management hence the name systemmngr`

## Sub-components of systemmngr(DeviceInfo)

Broadly `DeviceInfo` provides basic system details like SerialNumber, ManufactureOUI, ModelName etc, but it also provides

- VendorConfigFile
  This primarily provides a way to Backup/Upload the configuration, which currently maps to system uci files.

- MemoryStatus.MemoryMonitor.
  Currently `MemoryMonitor` is not implemented but, this provides a way to defined the critical state in term of system Memory Usages and then have datamodel parameters and events to reports it to USP-Controller. We do need an uci to store the parameter values which defines the critical thresold and a periodic timer based application to fetch the memory status and raise an Alarm.

- ProcessStatus.CPU.
  Like `MemoryMonitor` this does the same thing, but with the CPU Usages and has similar requirements for uci and daemon.

- TemperatureStatus
  Currently not implemented, but this object meant to provided 'Temperature' of various components like (cpu/wifi-chip) etc, here again we need uci and daemon to do periodic mesurment and raise alarms in case of faults.

- NetworkProperties
  Currently not implemented, but can be easily added

- LogRotate
  Part of Logmngr

- VendorLogFile
  Part of Logmngr

- Location
  currently not implemented, but we can implement easily to updated the location using external source.

- DeviceImageFile
  Currently not implemented, but this datamodel suppose to provide png/jpeg images of CPE, could be used to show realistic images in topology

- FirmwareImage
  Currently its been handled using `fwbank` rpcd libexec script along with several othere verdor specific helper scripts
  ```bash
  . /lib/upgrade/iopsys.sh
  . /lib/upgrade/platform.sh
  . /lib/functions/iopsys-system-layout.sh
  . /lib/functions/iopsys-fwbank.sh
  ```

  `fwbank` provides three ubus methods

  ```bash
  # ubus -v list fwbank
  'fwbank' @cce6afa9
  "dump":{}
  "set_bootbank":{"bank":"Integer"}
  "upgrade":{"path":"String","auto_activate":"Boolean","bank":"Integer","keep_settings":"Boolean"}
  ```

- KernelFaults
  Not implemented, but provides a way to collect core dumps for kernel modules

- ProcessFaults
  Not implemented, but provides a way to collect core dumps

- Reboots
  Implementation in review, details avaialble [here](https://dev.iopsys.eu/bbf/bbfdm/-/blob/b997f15afa5873046c09d24e54e0ef314d84290d/docs/guide/libbbfdm_DeviceInfo_Reboots.md). This usages a init script and uci to record the reboots, reboot causes are based on `reset_reason` file.

Apart from these, the base system information fetched from db uci(/etc/board-db/config/device), currently used to add/update these information using several scripts in base-files package.


## Proposal for System mangement daemon

So, if we see currently we have sub-components of `DeviceInfo` scattered in different places, we have few of them from db, some from fwbank script and rest datamodel layer does internal implementation to probe and fill the datamodel object at the runtime.

This proposal aims to bring harmony in all these different sub-components and bring them under one roof/package, to begin with this package might be called as `systemmngr` or `devicemngr` and it will provide all dependent components along with init script.

Now this init script can further include vendor script/hooks and it will generate nessary metadata for the datamodel.

Proposal also include a unified daemon to expose the datamodel directly over ubus using bbfdm micro-service along with perioric handlers for Memory/CPU/Temperature monitoring, this daemon can also expose `fwbank` for the timebeing for backward compability reasons.


