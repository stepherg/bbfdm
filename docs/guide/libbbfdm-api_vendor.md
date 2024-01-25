# BBFDM Vendor

The `bbfdm` library offers functionality for vendors to define their vendor extensions. This allows them to **extend** the core Data Model by introducing new objects/parameters/operates/events, **overwrite** and **exclude** existing ones.

## How to Add a New Vendor

### 1. Create a Vendor Folder

To add a new vendor, simply create a new folder under **'dmtree/vendor/'** which contains all files related to the vendor. Ensure that the folder name matches the vendor name specified in **BBF_VENDOR_LIST** macro.

### 2. Populate the `tDynamicObj` Table

For extending, overwriting, and excluding objects/parameters/operates/events from the core tree, it's mandatory to have a `tDynamicObj` table. This table should be defined using **DM_MAP_OBJ** structure, which has three arguments:

|     Argument     |                                     Description                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `parentobj`      | A string representing the parent object name from which to extend/exclude/overwrite the required items. Example: "Device.IP.Diagnostics.", "Device.WiFi.Radio." |
| `nextobject`     | Pointer to a **DMOBJ** array containing a list of child objects to extend/exclude/overwrite |
| `parameter`      | Pointer to a **DMLEAF** array containing a list of child parameters to extend/exclude/overwrite |


- The `parentobj` must be a string path of an **object** available in the core tree. If it doesn't exist, it will be skipped during parsing of the `tDynamicObj` table.

- To extend the Data Model tree, fill the `nextobject` and `parameter` arguments with the required objects/parameters/operates/events not supported by the core tree.

- To overwrite existing objects/parameters/operates/events in the core tree, fill the `nextobject` and `parameter` arguments with the same items defined in the core tree, along with new **add/del/get/set/browse** APIs needed by the vendor.

- To exclude existing objects/parameters/operates/events in the core tree, fill the `nextobject` and `parameter` arguments with the same items defined in the core tree, and setting **bbfdm_type** to **BBFDM_NONE**.

### 3. Enable vendor

To enable the new vendor:

- Add the vendor to the list in **BBF_VENDOR_LIST** macro.

- Define the vendor prefix using **BBF_VENDOR_PREFIX** macro.

Example Configuration Options:

```bash
BBF_VENDOR_LIST="iopsys,xxxx"
BBF_VENDOR_PREFIX="X_IOPSYS_EU_"
```

## Example how to Extend, Overwrite and Exclude the Data Model tree

In the [test/vendor_test/](../../test/vendor_test) directory, you'll find an example implementation for **test** vendor. This implementation demonstrates how to extend, overwrite, and exclude objects/parameters/operates/events from the core tree.

### 1. Extend Data Model

- using DotSo Plugin:
	- Add support for [Device.Firewall.Chain.{i}.Rule.{i}.X_TEST_COM_TimeSpan.](../../test/vendor_test/firewall.c#L172) object
	- Add support for [Device.Firewall.Chain.{i}.Rule.{i}.X_TEST_COM_ICMPType](../../test/vendor_test/firewall.c#L178) parameter

- using JSON Plugin:
	- Add support for [Device.PD2.{i}.](../../test/vendor_test/test_extend.json) object

### 2. Overwrite Data Model

- using DotSo Plugin:
	- Overwrite [Device.X_IOPSYS_EU_Dropbear.{i}.](../../test/vendor_test/device.c#L18) object in the core tree
	- Overwrite [Device.DeviceInfo.Manufacturer](../../test/vendor_test/deviceinfo.c#L29) parameter in the core tree

- using JSON Plugin:
	- Overwrite [Device.DeviceInfo.Processor.](../../test/vendor_test/test_overwrite.json) object in the core tree

### 3. Exclude Data Model

- using DotSo Plugin:
	- Exclude [Device.USB.](../../test/vendor_test/device.c#L17) object from the core tree
	- Exclude [Device.Ethernet.RMONStats.{i}.Packets1024to1518Bytes](../../test/vendor_test/extension.c#L37) parameter from the core tree

- using JSON Plugin:
	- Exclude [Device.X_IOPSYS_EU_IGMP.](../../test/vendor_test/test_exclude.json) object from the core tree


> Note1: The `libbbfdm` vendor list can support multiple vendors, separated by commas.

> Note2: If multi vendors are supported and there is an objects/parameters/operates/events implemented differently by different vendors, the implementation of the **last vendor name** in **BBF_VENDOR_LIST** will be considered.

> Note3: In the JSON plugin, there is no way to extend, overwrite and exclude parameters/operates/events that have an existing object in the core tree.
