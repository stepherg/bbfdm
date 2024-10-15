# Design for Reboot Data Model

In TR-181 version 2.18, a new object, Device.DeviceInfo.Reboots, was introduced to track and monitor reboot operations. This object provides details such as reboot reasons, counts, timestamps, and more, offering a comprehensive view of the device's state. It simplifies diagnostics and troubleshooting for applications and processes running on the device.

Currently, there is no standard configuration mapping to this object. However, we propose introducing a custom config called `deviceinfo` to manage this information effectively.

The idea is to maintain a 1-to-1 mapping between the parameters and UCI config. To achieve this, we need to create an `init.d` service script that generates a UCI section each time the boot() function is called. Essentially, when the boot() function is executed, it will check the `/tmp/reset_reason` file for specific markers, such as (reset reason) and (reset triggered), to identify the cause of the last boot. And based on these markers, it will calculate the required counter for data model parameters and commit the changes in `deviceinfo.globals` section. Furthermore, if necessary, it will create a UCI reboot section by checking `deviceinfo.globals.max_reboot_entries` and adjusting the config accordingly.

This approach ensures that the data model maps directly to UCI config as closely as possible, eliminating the need for any adjustments at the data model layer.

## Parameter Mapping Details

- Device.DeviceInfo.Reboots.BootCount: Maps to deviceinfo.globals.boot_count. This value is determined based on the marker (reset triggered: defaultreset) defined in `/tmp/reset_reason` file.
- Device.DeviceInfo.Reboots.CurrentVersionBootCount: Maps to deviceinfo.globals.curr_version_boot_count. This value is determined based on the marker (reset triggered: upgrade) defined in `/tmp/reset_reason` file.
- Device.DeviceInfo.Reboots.WatchdogBootCount: Maps to deviceinfo.globals.watchdog_boot_count. This value is determined based on the marker (reset reason: WATCHDOG) defined in `/tmp/reset_reason` file.
- Device.DeviceInfo.Reboots.ColdBootCount: 
- Device.DeviceInfo.Reboots.WarmBootCount: 
- Device.DeviceInfo.Reboots.MaxRebootEntries: Maps to deviceinfo.globals.max_reboot_entries. Possible values include {-1, 0, etc..}. Each case will be handled internally by bbfdm and default value is 3 and maximum reboot entry supported is 255.
- Device.DeviceInfo.Reboots.RebootNumberOfEntries: This is an internal bbfdm mechanism used to count the number of reboot entries.
- Device.DeviceInfo.Reboots.RemoveAllReboots(): An internal bbfdm API to remove all reboot sections.
- Device.DeviceInfo.Reboots.Reboot.{i}.: Each reboot entry is stored in a 'reboot' section.
- Device.DeviceInfo.Reboots.Reboot.{i}.Alias: Maps to deviceinfo.reboot[i].alias. This is managed internally by bbfdm.
- Device.DeviceInfo.Reboots.Reboot.{i}.TimeStamp: Maps to deviceinfo.reboot[i].time_stamp. This value is based on system uptime.
- Device.DeviceInfo.Reboots.Reboot.{i}.FirmwareUpdated: Maps to deviceinfo.reboot[i].firmware_updated.
- Device.DeviceInfo.Reboots.Reboot.{i}.Cause: Maps to deviceinfo.reboot[i].cause. Possible values include {LocalReboot, RemoteReboot, FactoryReset, LocalFactoryReset, RemoteFactoryReset}.
- Device.DeviceInfo.Reboots.Reboot.{i}.Reason: Maps to deviceinfo.reboot[i].reason. This value is determined based on the marker (reset reason) defined in `/tmp/reset_reason` file. 
- Device.DeviceInfo.Reboots.Reboot.{i}.Remove(): An internal bbfdm API to remove the current 'reboot' section.


## Example Configuration

Below is an example of the configuration file:

```bash
cat /etc/config/deviceinfo

config globals 'globals'
	option boot_count '2'
	option curr_version_boot_count '4'
	option watchdog_boot_count '3'
	option cold_boot_count '2'
	option warm_boot_count '2'
	option max_reboot_entries '3'

config reboot 'reboot_1'
	option alias 'cpe-1'
	option time_stamp '2024-09-22T20:34:45Z'
	option firmware_updated '0'
	option cause 'RemoteReboot'
	option reason 'REBOOT'
	
config reboot 'reboot_2'
	option alias 'cpe-2'
	option time_stamp '2024-09-22T21:55:09Z'
	option firmware_updated '0'
	option cause 'LocalReboot'
	option reason 'POR_RESET'

config reboot 'reboot_3'
	option alias 'cpe-3'
	option time_stamp '2024-09-23T04:11:24Z'
	option firmware_updated '1'
	option cause 'LocalReboot'
	option reason 'upgrade'

config reboot 'reboot_4'
	option alias 'cpe-4'
	option time_stamp '2024-09-23T04:15:53Z'
	option firmware_updated '0'
	option cause 'RemoteFactoryReset'
	option reason 'REBOOT'

```

