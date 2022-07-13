# Design For Firmware Activation

According to the TR181 data model, the Activate() command is an operation to activate the firmware image immediately or schedule it in another time.

In fact, the Linux system already provides us a cron to schedule some jobs. And since Openwrt is one of the Linux systems, so we can use a cron job as solution to handle the firmware activation.

The Activate() command has as arguments the TimeWindow object which is used to activate the required firmware in a specified time. For that, foreach TimeWindow instance a cron job will be created.

> Note: As per TR181 data model, max 5 instances of TimeWindow is supported.

Below is an example of an 'Activate()' command call with three TimeWindow instances. As a result, three jobs are created according to the defined TimeWindow.{i}.Start:

```bash
root@iopsys-44d43771aff0:~# ubus call usp operate '{"path":"Device.DeviceInfo.FirmwareImage.2.", "action":"Activate()", "input":{"TimeWindow.1
.Start":"1800", "TimeWindow.1.End":"3600", "TimeWindow.1.Mode":"WhenIdle", "TimeWindow.2.Start":"5400", "TimeWindow.2.End":"9000", "TimeWindow
.2.Mode":"WhenIdle", "TimeWindow.3.Start":"86400", "TimeWindow.3.End":"172800", "TimeWindow.3.Mode":"Immediately"}}'
{
	"Results": [
		{
			"path": "Device.DeviceInfo.FirmwareImage.2.Activate()",
			"result": [
				{
					
				}
			]
		}
	]
}
root@iopsys-44d43771aff0:~# crontab -l
52 22 21 2 * sh /usr/share/bbfdm/bbf_activate_handler.sh 'WhenIdle' '2' '1800' '0' '' ''
52 23 21 2 * sh /usr/share/bbfdm/bbf_activate_handler.sh 'WhenIdle' '2' '3600' '0' '' ''
22 22 22 2 * sh /usr/share/bbfdm/bbf_activate_handler.sh 'Immediately' '2' '86400' '1' '' ''
root@iopsys-44d43771aff0:~# 

```

For those cron jobs it is required to give the handler script to be executed which is in our case [bbf_activate_handler.sh](/scripts/bbf_activate_handler.sh). And, it is located under '/usr/share/bbfdm/' in the device.


## Cron job specification

For each cron job related to the activated firmware, it is needed to define it as below:

```bash
* * * * * command to execute * * * * * *
- - - - - -                  - - - - - -
| | | | | |                  | | | | | |
| | | | | |                  | | | | | --- Message that informs the user of a new activation request
| | | | | |                  | | | | ----- Maximum number of retries
| | | | | |                  | | | ------- Force firmware activation when it's not idle (0 - 1)
| | | | | |                  | | --------- End of the time window
| | | | | |                  | ----------- Firmware Bank id to be activated
| | | | | |                  ------------- Mode (AnyTime, Immediately, WhenIdle, ConfirmationNeeded)
| | | | | -------------------------------- Activate firmware script 'bbf_activate_handler.sh'
| | | | ---------------------------------- Day of week (0 - 6) (Sunday =0)
| | | ------------------------------------ Month (1 - 12)
| | -------------------------------------- Day (1 - 31)
| ---------------------------------------- Hour (0 - 23)
------------------------------------------ Minute (0 - 59)
```


## Activate Handler script

As described, we create a cron job for each TimeWindow in order to activate the required firmware within a specified time by running the [bbf_activate_handler.sh](/scripts/bbf_activate_handler.sh) handler script.

In fact, the aim of this script is to manage firmware images based on the **mode** and the other passed arguments.


### 1. Mode 'AnyTime' and 'Immediately':

For these modes and based on the firmware bank id, the required firmware image will be immediately activated at start time. The TimeWindow.{i}.End is ignored.

### 2. How to handle 'WhenIdle' mode:

Definition of WhenIdle may vary for each deployment and customer, to make it customizable [bbf_check_idle.sh](/scripts/bbf_check_idle.sh) script is used. It is assumed that customer shall overwrite this file using customer-config to match with there requirement.

In this mode, [bbf_activate_handler.sh](/scripts/bbf_activate_handler.sh) script calls this script [bbf_check_idle.sh](/scripts/bbf_check_idle.sh) to determine the idle state of the device. [bbf_activate_handler.sh](/scripts/bbf_activate_handler.sh) assumes the device as idle if the exit status of the above script is 0, or if the [bbf_check_idle.sh](/scripts/bbf_check_idle.sh) is not present in the predefined path "/usr/share/bbfdm/".


If the exit code from the idle script is zero then firmware image can be activated. Otherwise, it has to wait for next time slot which is defined by 'RETRY_TIME' variable.

> Note1: The time slot is set through 'RETRY_TIME' variable which is defined under '/usr/share/bbfdm/bbf_activate_handler.sh' script.

> Note2: The exit status of the script [bbf_check_idle.sh](/scripts/bbf_check_idle.sh) is important because based on it, the '[bbf_activate_handler.sh](/scripts/bbf_activate_handler.sh) script will decide whether the image can be activated or not.

> Note3: Algorithm/Logic to determine the Idle state of device is out of scope of this document and it is expected that users overwrite this script with the logic to determine the same in actual deployment.

> Note4: If 1 or more TimeWindow.{i}.Mode is set to 'WhenIdle' and all of them fails to get the idle state. The latest TimeWindow instance will force the device to activate the firmware image.

> Note5: If the idle script [bbf_check_idle.sh](/scripts/bbf_check_idle.sh) not present in the pre-defined path "/usr/share/bbfdm/", then the device is assumed to be in ideal state and the firmware shall be activated instantly.

> Note6: It is very likely that TimeWindow with 'WhenIdle' mode might not find any suitable Idle state, in that case firmware shall not be activated. If users/operators want to make sure that firmware gets activated at the end, then they can add a TimeWindow with 'AnyTime/Immediate' mode at the end, to activate the firmware.


## Good to know

* TimeWindow instance arguments are optional.

* TimeWindow instances attributes must not overlap.

* If TimeWindow.{i}.Start is set, TimeWindow.{i}.End and TimeWindow.{i}.Mode become mondatory.

* The firmware activation is done by [bbf_activate_handler.sh](/scripts/bbf_activate_handler.sh) script as per the defined Mode in TimeWindow, but if the TimeWindow is not defined, it will activate the requested FirmwareImage instance immediately.

* If the customer wants to be sure that the required firmware is getting activated at the end then they can define the TimeWindow.{i}.Mode as 'AnyTime' or 'Immediately' in the last TimeWindow instance.

* This document is only target for Firmware management using USP.

* TimeWindow.{i}.Mode = 'ConfirmationNeeded' is not supported.
