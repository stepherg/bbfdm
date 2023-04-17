# BBFDM Vendor

`bbfdm` library can be used to **Extend** the Data Model with new objects/parameters, to **Overwrite** existing objects/parameters with new ones and **Exclude** some objects/parameters from Data Model tree.

## How to add new vendor

### 1. Create a vendor folder

Create a new folder under **'dmtree/vendor/'** which contains all files related to the vendor

### 2. Fill Extend, Overwrite and Exclude tables with objects/parameters

Create the first vendor C file which contains new **Extend**, **Overwrite** and **Exclude** tables of objects/parameters.

#### Extend and Overwrite table

The Extend and Overwrite tables contain entries of **DM_MAP_OBJ** structure.

The **DM_MAP_OBJ** structure contains three arguments:

|     Argument     |                                     Description                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `parentobj`      | A string of the parent object name. Example “Device.IP.Diagnostics.”, “Device.DeviceInfo”, “Device.WiFi.Radio.” |
| `nextobject`     | Pointer to a **DMOBJ** array which contains a list of the child objects |
| `parameter`      | Pointer to a **DMLEAF** array which contains a list of the child parameters |

#### Exclude table

Each entry in the exclude table is a string which could be a path of object or parameter that need to be excluded from the tree

The following [link](https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/libbbfdm/dmtree/vendor/test/tr181/vendor.c) contains example of Extend, Overwrite and Exclude table.

### 3. Adding vendor and standard objects/Parameters

Implement the new vendor/standard objects and parameters as defined above in the first section.

Example: [Custom Vendor Object Dropbear](https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/libbbfdm/dmtree/vendor/test/tr181/x_test_com_dropbear.c)

### 4. link vendor tables to the main tree

To register the new vendor tables, you need to link them in the main three tables:

- **tVendorExtension**

- **tVendorExtensionOverwrite**

- **tVendorExtensionExclude**

These tables are defined in the file **'dmtree/vendor/vendor.c'**.

Example: [Link vendor tables to the main tree](https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/libbbfdm/dmtree/vendor/vendor.c)

### 5. Enable vendor

To enable the new vendor

- Define **BBF_VENDOR_EXTENSION** macro

- Add the new vendor in the list **BBF_VENDOR_LIST** macro

- Define the vendor prefix using **BBF_VENDOR_PREFIX** macro

Example of Config Options:

```bash
BBF_VENDOR_EXTENSION=y
BBF_VENDOR_LIST="iopsys,test"
BBF_VENDOR_PREFIX="X_TEST_COM_"
```

> Note1: The `libbbfdm` vendor list can support multi-vendor with comma seperated.

> Note2: If multi vendors are supported and there is a object/parameter that is implmented by multi customers in different way, the implemented object/parameter of the first vendor name in the **BBF_VENDOR_LIST** will be considered.

> Note3: Overwrite and Exclude are only considered in `dmtree/vendor/<vendor>/`

- The directory **'dmtree/vendor/test/'** contains an example of **test** vendor implementation
