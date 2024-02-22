# JSON Plugin Version 2

The purpose of this document is to describe the new features supported by JSON Plugin V2.

JSON Plugin Version 2 introduces enhancements to the previous versions by providing increased flexibility in extending, overwriting, and excluding objects/parameters/commands/events from the core data model.

## How It Works

To illustrate how the new features work, let's consider the following example JSON Plugin:

```json
{
    "json_plugin_version": 2,
    "Device.WiFi.AccessPoint.{i}.Security.": {
        "type": "object",
        "protocols": [
            "cwmp",
            "usp"
        ],
        "access": false,
        "array": false,
        "{BBF_VENDOR_PREFIX}KeyPassphrase": {
            "type": "string",
            "read": true,
            "write": true,
            "protocols": [
                "cwmp",
                "usp"
            ],
            "datatype": "string",
            "mapping": [
                {
                    "data": "@Parent",
                    "type": "uci_sec",
                    "key": "key"
                }
            ]
        },
        "WEPKey": {
            "type": "string",
            "read": true,
            "write": true,
            "protocols": [
                "cwmp",
                "usp"
            ],
            "datatype": "string",
            "mapping": [
                {
                    "data": "@Parent",
                    "type": "uci_sec",
                    "key": "wek_key"
                }
            ]
        },
        "SAEPassphrase": {
            "type": "string",
            "read": true,
            "write": false,
            "protocols": [
                "none"
            ]
        }
    }
}
```

The JSON Plugin V2 operates by parsing the JSON file. Then it checks the parent top object, which in this example is `Device.WiFi.AccessPoint.{i}.Security`. 

 - If this object exists in the core data model, the plugin proceeds to examine the next each subsequent level to determine the necessary action for each JSON object.

    - If the object does not exist in the core data model, it is extended.
    - If the object exists, it is either overwritten or excluded, depending on the defined protocols. If the protocols array is defined as 'none', the object is excluded.

 - If the parent top object does not exist in the core data model, the plugin follows the old behavior defined in JSON Plugin V0 and V1, which is extending the core data model.

Examples

 - Device.WiFi.AccessPoint.{i}.Security.X_IOPSYS_EU_KeyPassphrase: This parameter will be extended to the core data model since it does not exist.
 - Device.WiFi.AccessPoint.{i}.Security.WEPKey: This parameter will be overwritten in the core data model since it already exists.
 - Device.WiFi.AccessPoint.{i}.Security.SAEPassphrase: This parameter will be excluded from the core data model since it exists, but the new protocol defined is `none`.

## Important Notes

> Note1: To utilize the functionalities described, ensure that JSON version 2 is specified in the plugin by `json_plugin_version` option.

> Note2: When extending a multiple-instance object, align the passed data from the browse function to children (LEAF) by keeping it `(struct uci_section *)data` pointer in case of the `type` is `uci_sec` or `(json_object *)data` pointer in case of the `type` is `json`.

> Note3: The mapping format used by JSON Plugin V2 follows the format of version 1. Ensure that all mappings are aligned with JSON Plugin V1 specifications.

> Note4: Additional examples for each feature can be found in the following links:[Extend](../../test/vendor_test/test_extend.json), [Overwrite](../../test/vendor_test/test_overwrite.json), and [Exclude](../../test/vendor_test/test_exclude.json).

## Features Supported with JSON Plugin V2

 - Allow extending the core tree with simple mappings based on the data passed from the parent object.
 - Allow overwriting an existing object, parameter, command, or event from the core tree.
 - Allow excluding an existing object, parameter, command, or event from the core tree.
