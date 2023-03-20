# usp Schema

```
https://dev.iopsys.eu/iopsys/uspd/-/blob/devel/docs/api/ubus/usp.md
```

| Custom Properties | Additional Properties |
| ----------------- | --------------------- |
| Forbidden         | Forbidden             |

# usp

| List of Methods                       |
| ------------------------------------- |
| [add_object](#add_object)             | Method | usp (this schema) |
| [del_object](#del_object)             | Method | usp (this schema) |
| [get](#get)                           | Method | usp (this schema) |
| [get_supported_dm](#get_supported_dm) | Method | usp (this schema) |
| [instances](#instances)               | Method | usp (this schema) |
| [list_operate](#list_operate)         | Method | usp (this schema) |
| [object_names](#object_names)         | Method | usp (this schema) |
| [operate](#operate)                   | Method | usp (this schema) |
| [set](#set)                           | Method | usp (this schema) |
| [validate](#validate)                 | Method | usp (this schema) |

## add_object

### Add a new object instance

Add a new object in multi instance object

`add_object`

- type: `Method`

### add_object Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` | object | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance_mode` | integer | Optional     |          |
| `key`           | string  | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance_mode

`instance_mode`

- is optional
- type: `integer`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

#### key

`key`

- is optional
- type: `string`

##### key Type

`string`

#### path

Complete object element path as per TR181

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.1.
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#add_object-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp add_object {"path":"in dolore nul","proto":"usp","instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "add_object",
    { "path": "in dolore nul", "proto": "usp", "instance_mode": 1 }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property     | Type  | Required     |
| ------------ | ----- | ------------ |
| `parameters` | array | **Required** |

#### parameters

`parameters`

- is **required**
- type: `object[]`

##### parameters Type

Array type: `object[]`

All items must be of the type: `object` with following properties:

| Property    | Type    | Required     |
| ----------- | ------- | ------------ |
| `fault`     | integer | Optional     |
| `instance`  | string  | Optional     |
| `parameter` | string  | **Required** |
| `status`    | boolean | **Required** |

#### fault

`fault`

- is optional
- type: reference

##### fault Type

`integer`

- minimum value: `7000`
- maximum value: `9050`

#### instance

`instance`

- is optional
- type: `string`

##### instance Type

`string`

#### parameter

Complete object element path as per TR181

`parameter`

- is **required**
- type: reference

##### parameter Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### parameter Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.1.
```

```json
Device.WiFi.
```

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{
  "parameters": [
    { "parameter": "consequat", "status": false, "instance": "occaecat sit con", "fault": 8804 },
    { "parameter": "mollit proident nisi est commodo", "status": false, "instance": "sunt ut nisi", "fault": 7496 },
    { "parameter": "et irure ut incididunt", "status": true, "instance": "minim", "fault": 7873 },
    { "parameter": "occaecat sint eu", "status": false, "instance": "est aliqua voluptate cillum", "fault": 7743 },
    { "parameter": "Ut repr", "status": true, "instance": "velit voluptate in", "fault": 7418 }
  ]
}
```

## del_object

### Delete object instance

Delete a object instance from multi instance object

`del_object`

- type: `Method`

### del_object Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` | object | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance_mode` | integer | Optional     |          |
| `key`           | string  | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance_mode

`instance_mode`

- is optional
- type: `integer`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

#### key

`key`

- is optional
- type: `string`

##### key Type

`string`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#del_object-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp del_object {"path":"ea amet qui et culp","proto":"usp",instance_mode":0}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "del_object",
    { "path": "ea amet qui et culp", "proto": "usp", "instance_mode": 0 }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property     | Type  | Required     |
| ------------ | ----- | ------------ |
| `parameters` | array | **Required** |

#### parameters

`parameters`

- is **required**
- type: `object[]`

##### parameters Type

Array type: `object[]`

All items must be of the type: `object` with following properties:

| Property    | Type    | Required     |
| ----------- | ------- | ------------ |
| `fault`     | integer | Optional     |
| `parameter` | string  | **Required** |
| `status`    | boolean | **Required** |

#### fault

`fault`

- is optional
- type: reference

##### fault Type

`integer`

- minimum value: `7000`
- maximum value: `9050`

#### parameter

Complete object element path as per TR181

`parameter`

- is **required**
- type: reference

##### parameter Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### parameter Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.1.
```

```json
Device.WiFi.
```

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{
  "parameters": [
    { "parameter": "culpaconsectetur proident voluptate", "status": true, "fault": 7084 },
    { "parameter": "auteofficia", "status": false, "fault": 8637 },
    { "parameter": "eu occaecat cillum laborum", "status": true, "fault": 7337 },
    { "parameter": "irure adipisicing", "status": true, "fault": 8214 }
  ]
}
```

## get

### Get handler

Query the datamodel object

`get`

- type: `Method`

### get Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance-mode` | integer | Optional     |          |
| `maxdepth`      | integer | Optional     |          |
| `next-level`    | boolean | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance-mode

`instance-mode`

- is optional
- type: `integer`

##### instance-mode Type

`integer`

#### maxdepth

Integer to decide the depth of data model to be parsed

`maxdepth`

- is optional
- type: `integer`

##### maxdepth Type

`integer`

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#get-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp get {"path":"adipisicing aliqua","proto":"both","maxdepth":-13721201,"next-level":true,"instance-mode":-25889726}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "get",
    {
      "path": "adipisicing aliqua",
      "proto": "both",
      "maxdepth": -13721201,
      "next-level": true,
      "instance-mode": -25889726
    }
  ]
}
```

#### output

`output`

- is **required**
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code in fault_t"
      }
    },
    {
      "type": "object",
      "properties": {},
      "examples": [
        "root@iopsys:/tmp# ubus call usp get '{\"path\":\"Device.Users.User.2.\"}'\n{\n\t\"User\": [\n\t\t{\n\t\t\t\"Alias\": \"\",\n\t\t\t\"Enable\": true,\n\t\t\t\"Language\": \"\",\n\t\t\t\"Password\": \"\",\n\t\t\t\"RemoteAccessCapable\": false,\n\t\t\t\"Username\": \"user_2\"\n\t\t}\n\t]\n}",
        "root@iopsys:/tmp# ubus call usp get '{\"path\":\"Device.Users.\"}'\n{\n\t\"Users\": {\n\t\t\"User\": [\n\t\t\t{\n\t\t\t\t\"Alias\": \"\",\n\t\t\t\t\"Enable\": true,\n\t\t\t\t\"Language\": \"\",\n\t\t\t\t\"Password\": \"\",\n\t\t\t\t\"RemoteAccessCapable\": true,\n\t\t\t\t\"Username\": \"user\"\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"Alias\": \"\",\n\t\t\t\t\"Enable\": true,\n\t\t\t\t\"Language\": \"\",\n\t\t\t\t\"Password\": \"\",\n\t\t\t\t\"RemoteAccessCapable\": false,\n\t\t\t\t\"Username\": \"user_2\"\n\t\t\t}\n\t\t],\n\t\t\"UserNumberOfEntries\": 2\n\t}\n}"
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": {
      "type": "string",
      "enum": ["0", "1"]
    },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": {
      "type": "string",
      "enum": ["async", "sync"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": {
      "description": "Multi object instances",
      "type": "string",
      "minLength": 6,
      "maxLength": 256
    },
    "proto_t": {
      "type": "string",
      "default": "both",
      "enum": ["usp", "cwmp", "both"]
    },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":8504},{}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [{ "fault": 8504 }, {}],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": { "type": "string", "enum": ["0", "1"] },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": { "type": "string", "enum": ["async", "sync"] },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": { "description": "Multi object instances", "type": "string", "minLength": 6, "maxLength": 256 },
    "proto_t": { "type": "string", "default": "both", "enum": ["usp", "cwmp", "both"] },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## get_supported_dm

### Get list of supported datamodel parameters

Schema will have all the nodes/objects supported by libbbf

`get_supported_dm`

- type: `Method`

### get_supported_dm Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | Optional     |
| `output` |        | **Required** |

#### input

`input`

- is optional
- type: `object`

##### input Type

`object` with following properties:

| Property      | Type    | Required |
| ------------- | ------- | -------- |
| `next-level`  | boolean | Optional |
| `path`        | string  | Optional |
| `schema_type` | integer | Optional |

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### path

DM object path with search queries

`path`

- is optional
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### schema_type

0-All, 1-Parameter only 2- Event only 3- operate only

`schema_type`

- is optional
- type: `integer`

##### schema_type Type

`integer`

- minimum value: `0`
- maximum value: `3`

### Ubus CLI Example

```
ubus call usp get_supported_dm {"path":"cupidatat mollit do off","next-level":false,"schema_type":0}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "get_supported_dm",
    { "path": "cupidatat mollit do off", "next-level": false, "schema_type": 0 }
  ]
}
```

#### output

`output`

- is **required**
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
      }
    },
    {
      "type": "object",
      "properties": {
        "parameters": {
          "type": "array",
          "items": [
            {
              "type": "object",
              "required": ["parameter", "type", "writable"],
              "properties": {
                "parameter": {
                  "$ref": "#/definitions/schema_path_t"
                },
                "writable": {
                  "$ref": "#/definitions/boolean_t"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
                },
                "cmd_type": {
                  "$ref": "#/definitions/operate_type_t"
                },
                "in": {
                  "type": "array",
                  "uniqueItems": true,
                  "items": [
                    {
                      "type": "string"
                    }
                  ]
                },
                "out": {
                  "type": "array",
                  "uniqueItems": true,
                  "items": [
                    {
                      "type": "string"
                    }
                  ]
                }
              }
            }
          ]
        }
      }
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": {
      "type": "string",
      "enum": ["0", "1"]
    },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": {
      "type": "string",
      "enum": ["async", "sync"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": {
      "description": "Multi object instances",
      "type": "string",
      "minLength": 6,
      "maxLength": 256
    },
    "proto_t": {
      "type": "string",
      "default": "both",
      "enum": ["usp", "cwmp", "both"]
    },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":8131},{\"parameters\":[{\"parameter\":\"Lorem eu dolor\",\"type\":\"xsd:object\",\"writable\":\"0\",\"cmd_type\":\"async\",\"in\":[\"reprehenderit consectetur mollit dolor\"],\"out\":[\"sed proident et magna pariatur\"]}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 8131 },
    {
      "parameters": [
        {
          "parameter": "Lorem eu dolor",
          "type": "xsd:object",
          "writable": "0",
          "cmd_type": "async",
          "in": ["reprehenderit consectetur mollit dolor"],
          "out": ["sed proident et magna pariatur"]
        }
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": { "type": "string", "enum": ["0", "1"] },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": { "type": "string", "enum": ["async", "sync"] },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": { "description": "Multi object instances", "type": "string", "minLength": 6, "maxLength": 256 },
    "proto_t": { "type": "string", "default": "both", "enum": ["usp", "cwmp", "both"] },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## instances

### Instance query handler

Get the instances of multi object

`instances`

- type: `Method`

### instances Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance-mode` | integer | Optional     |          |
| `maxdepth`      | integer | Optional     |          |
| `next-level`    | boolean | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance-mode

`instance-mode`

- is optional
- type: `integer`

##### instance-mode Type

`integer`

#### maxdepth

Integer to decide the depth of data model to be parsed

`maxdepth`

- is optional
- type: `integer`

##### maxdepth Type

`integer`

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#instances-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp instances {"path":"veniam ex fugiat","proto":"cwmp","maxdepth":72958357,"next-level":true,"instance-mode":-75752298}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "instances",
    {
      "path": "veniam ex fugiat",
      "proto": "cwmp",
      "maxdepth": 72958357,
      "next-level": true,
      "instance-mode": -75752298
    }
  ]
}
```

#### output

`output`

- is **required**
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code in fault_t"
      }
    },
    {
      "type": "object",
      "required": ["parameters"],
      "properties": {
        "parameters": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "parameter": {
                "$ref": "#/definitions/instance_t"
              }
            }
          }
        }
      }
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": {
      "type": "string",
      "enum": ["0", "1"]
    },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": {
      "type": "string",
      "enum": ["async", "sync"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": {
      "description": "Multi object instances",
      "type": "string",
      "minLength": 6,
      "maxLength": 256
    },
    "proto_t": {
      "type": "string",
      "default": "both",
      "enum": ["usp", "cwmp", "both"]
    },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":7958},{\"parameters\":[{\"parameter\":\"magna dolor ess\"},{\"parameter\":\"exidut in cillum\"},{\"parameter\":\"adipisicing Ut\"},{\"parameter\":\"in dolore in irure\"}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 7958 },
    {
      "parameters": [
        { "parameter": "magna dolor ess" },
        { "parameter": "exidut in cillum" },
        { "parameter": "adipisicing Ut" },
        { "parameter": "in dolore in irure" }
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": { "type": "string", "enum": ["0", "1"] },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": { "type": "string", "enum": ["async", "sync"] },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": { "description": "Multi object instances", "type": "string", "minLength": 6, "maxLength": 256 },
    "proto_t": { "type": "string", "default": "both", "enum": ["usp", "cwmp", "both"] },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## list_operate

### List down supported usp operate commands

Commands will be shown in schema format

`list_operate`

- type: `Method`

### list_operate Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | Optional     |
| `output` | object | **Required** |

#### input

`input`

- is optional
- type: `object`

##### input Type

`object` with following properties:

| Property | Type | Required |
| -------- | ---- | -------- |
| None     | None | None     |

### Ubus CLI Example

```
ubus call usp list_operate {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "usp", "list_operate", {}] }
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property     | Type  | Required     |
| ------------ | ----- | ------------ |
| `parameters` | array | **Required** |

#### parameters

`parameters`

- is **required**
- type: `object[]`

##### parameters Type

Array type: `object[]`

All items must be of the type: `object` with following properties:

| Property    | Type   | Required     |
| ----------- | ------ | ------------ |
| `in`        | array  | Optional     |
| `out`       | array  | Optional     |
| `parameter` | string | **Required** |
| `type`      | string | **Required** |

#### in

`in`

- is optional
- type: `string[]`

##### in Type

Array type: `string[]`

All items must be of the type: `string`

#### out

`out`

- is optional
- type: `string[]`

##### out Type

Array type: `string[]`

All items must be of the type: `string`

#### parameter

Datamodel object schema path

`parameter`

- is **required**
- type: reference

##### parameter Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### parameter Examples

```json
Device.DHCPv4.Client.{i}.Renew()
```

```json
Device.FactoryReset()
```

#### type

`type`

- is **required**
- type: reference

##### type Type

`string`

The value of this property **must** be equal to one of the [known values below](#list_operate-known-values).

##### type Known Values

| Value |
| ----- |
| async |
| sync  |

### Output Example

```json
{
  "parameters": [
    {
      "parameter": "incididunt occaecat",
      "type": "async",
      "in": ["sed magna", "in", "exercitation ut culpa"],
      "out": ["fugiat eu in officia"]
    }
  ]
}
```

## object_names

### Get objects names

Get names of all the objects below input object path

`object_names`

- type: `Method`

### object_names Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance-mode` | integer | Optional     |          |
| `maxdepth`      | integer | Optional     |          |
| `next-level`    | boolean | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance-mode

`instance-mode`

- is optional
- type: `integer`

##### instance-mode Type

`integer`

#### maxdepth

Integer to decide the depth of data model to be parsed

`maxdepth`

- is optional
- type: `integer`

##### maxdepth Type

`integer`

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#object_names-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp object_names {"path":"ullamco","proto":"cwmp","maxdepth":6964414,"next-level":true,"instance-mode":-14339037}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "object_names",
    { "path": "ullamco", "proto": "cwmp", "maxdepth": 6964414, "next-level": true, "instance-mode": -14339037 }
  ]
}
```

#### output

`output`

- is **required**
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code in fault_t"
      }
    },
    {
      "type": "object",
      "required": ["parameters"],
      "properties": {
        "parameters": {
          "type": "array",
          "items": {
            "type": {
              "$ref": "#/definitions/type_t"
            },
            "required": ["parameter", "type", "writable"],
            "writable": {
              "$ref": "#/definitions/boolean_t"
            },
            "properties": {
              "parameter": {
                "$ref": "#/definitions/path_t"
              }
            }
          }
        }
      }
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": {
      "type": "string",
      "enum": ["0", "1"]
    },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": {
      "type": "string",
      "enum": ["async", "sync"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": {
      "description": "Multi object instances",
      "type": "string",
      "minLength": 6,
      "maxLength": 256
    },
    "proto_t": {
      "type": "string",
      "default": "both",
      "enum": ["usp", "cwmp", "both"]
    },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":8049},{\"parameters\":[{\"type\":\"xsd:int\",\"required\":[\"parameter\",\"type\",\"writable\"],\"writable\":\"0\",\"properties\":{\"parameter\":\"dolore sint\"}},{\"type\":\"xsd:string\",\"required\":[\"parameter\",\"type\",\"writable\"],\"writable\":\"0\",\"properties\":{\"parameter\":\"ipsum Duis do sunt\"}},{\"type\":\"xsd:hexBinary\",\"required\":[\"parameter\",\"type\",\"writable\"],\"writable\":\"1\",\"properties\":{\"parameter\":\"dolore\"}},{\"type\":\"xsd:unsignedLong\",\"required\":[\"parameter\",\"type\",\"writable\"],\"writable\":\"1\",\"properties\":{\"parameter\":\"esse proident aliqua\"}},{\"type\":\"xsd:boolean\",\"required\":[\"parameter\",\"type\",\"writable\"],\"writable\":\"1\",\"properties\":{\"parameter\":\"labore fugiat\"}}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 8049 },
    {
      "parameters": [
        {
          "type": "xsd:int",
          "required": ["parameter", "type", "writable"],
          "writable": "0",
          "properties": { "parameter": "dolore sint" }
        },
        {
          "type": "xsd:string",
          "required": ["parameter", "type", "writable"],
          "writable": "0",
          "properties": { "parameter": "ipsum Duis do sunt" }
        },
        {
          "type": "xsd:hexBinary",
          "required": ["parameter", "type", "writable"],
          "writable": "1",
          "properties": { "parameter": "dolore" }
        },
        {
          "type": "xsd:unsignedLong",
          "required": ["parameter", "type", "writable"],
          "writable": "1",
          "properties": { "parameter": "esse proident aliqua" }
        },
        {
          "type": "xsd:boolean",
          "required": ["parameter", "type", "writable"],
          "writable": "1",
          "properties": { "parameter": "labore fugiat" }
        }
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": { "type": "string", "enum": ["0", "1"] },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": { "type": "string", "enum": ["async", "sync"] },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": { "description": "Multi object instances", "type": "string", "minLength": 6, "maxLength": 256 },
    "proto_t": { "type": "string", "default": "both", "enum": ["usp", "cwmp", "both"] },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## operate

### Operate handler

Operate on object element provided in path

`operate`

- type: `Method`

### operate Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `action`        | string  | **Required** |          |
| `input`         | object  | Optional     |          |
| `instance-mode` | integer | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### action

Opreate command as defined in TR-369, TR-181-2.13

`action`

- is **required**
- type: `string`

##### action Type

`string`

All instances must conform to this regular expression

```regex
[a-zA-Z]+\(\)
```

- test example:
  [{&amp;quot;path&amp;quot;:&amp;quot;Device.WiFi.&amp;quot;, &amp;quot;action&amp;quot;:&amp;quot;Reset\(\)&amp;quot;}](<https://regexr.com/?expression=%5Ba-zA-Z%5D%2B%5C(%5C)&text=%7B%22path%22%3A%22Device.WiFi.%22%2C%20%22action%22%3A%22Reset%5C(%5C)%22%7D>)

##### action Example

```json
{ "path": "Device.WiFi.", "action": "Reset()" }
```

#### input

Input arguments for the operate command as defined in TR-181-2.13

`input`

- is optional
- type: `object`

##### input Type

`object` with following properties:

| Property | Type | Required |
| -------- | ---- | -------- |
| None     | None | None     |

##### input Example

```json
{ "path": "Device.IP.Diagnostics", "action": "IPPing()", "input": { "Host": "iopsys.eu" } }
```

#### instance-mode

`instance-mode`

- is optional
- type: `integer`

##### instance-mode Type

`integer`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#operate-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp operate {"path":"nullaea aliquip","action":"MFy()","proto":"usp","instance-mode":21204540,"input":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "operate",
    { "path": "nullaea aliquip", "action": "MFy()", "proto": "usp", "instance-mode": 21204540, "input": {} }
  ]
}
```

#### output

`output`

- is **required**
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code in fault_t"
      }
    },
    {
      "description": "Output will have status for sync commands and for async commands parameters as defined in TR-181-2.13",
      "type": "object",
      "required": ["Results"],
      "properties": {
        "Results": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "path": {
                "$ref": "#/definitions/path_t"
              },
              "result": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "Result": {
                      "type": "string",
                      "Description": "Success or Failure"
                    }
                  }
                }
              }
            }
          }
        }
      },
      "examples": [
        "{\n\t\"status\": true}",
        "{\n\t\"AverageResponseTime\": \"0\",\n\t\"AverageResponseTimeDetailed\": \"130\",\n\t\"FailureCount\": \"0\",\n\t\"MaximumResponseTime\": \"0\",\n\t\"MaximumResponseTimeDetailed\": \"140\",\n\t\"MinimumResponseTime\": \"0\",\n\t\"MinimumResponseTimeDetailed\": \"120\",\n\t\"SuccessCount\": \"3\"}"
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": {
      "type": "string",
      "enum": ["0", "1"]
    },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": {
      "type": "string",
      "enum": ["async", "sync"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": {
      "description": "Multi object instances",
      "type": "string",
      "minLength": 6,
      "maxLength": 256
    },
    "proto_t": {
      "type": "string",
      "default": "both",
      "enum": ["usp", "cwmp", "both"]
    },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":7934},{\"Results\":[{\"path\":\"nisi quis fugi\",\"result\":[{\"Result\":\"adipisicing consequat sunt laborum\"}]},{\"path\":\"in Excepteur exerci\",\"result\":[{\"Result\":\"aliqua ullamco laborum irure\"},{\"Result\":\"sed\"},{\"Result\":\"ullamco do occae\"}]}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 7934 },
    {
      "Results": [
        { "path": "nisi quis fugi", "result": [{ "Result": "adipisicing consequat sunt laborum" }] },
        {
          "path": "in Excepteur exerci",
          "result": [
            { "Result": "aliqua ullamco laborum irure" },
            { "Result": "sed" },
            { "Result": "ullamco do occae" }
          ]
        }
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": { "type": "string", "enum": ["0", "1"] },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": { "type": "string", "enum": ["async", "sync"] },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": { "description": "Multi object instances", "type": "string", "minLength": 6, "maxLength": 256 },
    "proto_t": { "type": "string", "default": "both", "enum": ["usp", "cwmp", "both"] },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## set

### Set handler

Set values of datamodel object element

`set`

- type: `Method`

### set Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance_mode` | integer | Optional     |          |
| `key`           | string  | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |
| `value`         | string  | **Required** |          |
| `values`        | object  | Optional     |          |

#### instance_mode

`instance_mode`

- is optional
- type: `integer`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

#### key

`key`

- is optional
- type: `string`

##### key Type

`string`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#set-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

#### value

value of the object element provided in path, path should contains valid writable object element

`value`

- is **required**
- type: `string`

##### value Type

`string`

##### value Examples

```json
{ "path": "Device.WiFi.SSID.1.SSID", "value": "test_ssid" }
```

```json
{ "path": "Device.WiFi.SSID.2.Enable", "value": "true" }
```

```json
{ "path": "Device.WiFi.SSID.1.Enable", "value": "0" }
```

#### values

To set multiple values at once, path should be relative to object elements

`values`

- is optional
- type: `object`

##### values Type

`object` with following properties:

| Property | Type | Required |
| -------- | ---- | -------- |
| None     | None | None     |

##### values Examples

```json
{ "path": "Device.WiFi.SSID.1", "values": { ".SSID": "test_ssid", ".Name": "test_name" } }
```

```json
{ "path": "Device.WiFi.SSID.2", "values": { ".SSID": "test_ssid" } }
```

### Ubus CLI Example

```
ubus call usp set {"path":"magna voluptate labore","value":"cupidatat","proto":"usp","values":{},"instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "set",
    {
      "path": "magna voluptate labore",
      "value": "cupidatat",
      "proto": "usp",
      "values": {},
      "key": "quis",
      "instance_mode": 1
    }
  ]
}
```

#### output

`output`

- is **required**
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "type": "object",
      "properties": {
        "status": {
          "const": "1"
        }
      }
    },
    {
      "type": "object",
      "required": ["parameters"],
      "properties": {
        "parameters": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "path": {
                "$ref": "#/definitions/path_t"
              },
              "status": {
                "const": "0"
              },
              "fault": {
                "$ref": "#/definitions/fault_t"
              }
            }
          }
        }
      }
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": {
      "type": "string",
      "enum": ["0", "1"]
    },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": {
      "type": "string",
      "enum": ["async", "sync"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": {
      "description": "Multi object instances",
      "type": "string",
      "minLength": 6,
      "maxLength": 256
    },
    "proto_t": {
      "type": "string",
      "default": "both",
      "enum": ["usp", "cwmp", "both"]
    },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"status\":\"1\"},{\"parameters\":[{\"path\":\"nulla ad\",\"status\":\"0\",\"fault\":8453},{\"path\":\"ut non\",\"status\":\"0\",\"fault\":8067},{\"path\":\"exercitation ad\",\"status\":\"0\",\"fault\":7689},{\"path\":\"nostrud\",\"status\":\"0\",\"fault\":8772}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "status": "1" },
    {
      "parameters": [
        { "path": "nulla ad", "status": "0", "fault": 8453 },
        { "path": "ut non", "status": "0", "fault": 8067 },
        { "path": "exercitation ad", "status": "0", "fault": 7689 },
        { "path": "nostrud", "status": "0", "fault": 8772 }
      ]
    }
  ],
  "definitions": {
    "path_t": {
      "description": "Complete object element path as per TR181",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.1.", "Device.WiFi."]
    },
    "schema_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.Bridging.Bridge.{i}.", "Device.DeviceInfo.Manufacturer", "Device.WiFi.SSID.{i}.SSID"]
    },
    "boolean_t": { "type": "string", "enum": ["0", "1"] },
    "operate_path_t": {
      "description": "Datamodel object schema path",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": ["Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "operate_type_t": { "type": "string", "enum": ["async", "sync"] },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.[SSID==\"test_ssid\"].BSSID",
        "Device.WiFi.SSID.*.BSSID",
        "Device.WiFi.SSID.[SSID!=\"test_ssid\"&&Enable==1].BSSID",
        "Device.WiFi."
      ]
    },
    "instance_t": { "description": "Multi object instances", "type": "string", "minLength": 6, "maxLength": 256 },
    "proto_t": { "type": "string", "default": "both", "enum": ["usp", "cwmp", "both"] },
    "type_t": {
      "type": "string",
      "enum": [
        "xsd:string",
        "xsd:unsignedInt",
        "xsd:int",
        "xsd:unsignedLong",
        "xsd:long",
        "xsd:boolean",
        "xsd:dateTime",
        "xsd:hexBinary",
        "xsd:object"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## validate

### Validate a datamodel object

API to check if a datamodel object is available

`validate`

- type: `Method`

### validate Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` | object | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property        | Type    | Required     | Default  |
| --------------- | ------- | ------------ | -------- |
| `instance-mode` | integer | Optional     |          |
| `maxdepth`      | integer | Optional     |          |
| `next-level`    | boolean | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance-mode

`instance-mode`

- is optional
- type: `integer`

##### instance-mode Type

`integer`

#### maxdepth

Integer to decide the depth of data model to be parsed

`maxdepth`

- is optional
- type: `integer`

##### maxdepth Type

`integer`

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### path

DM object path with search queries

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.
```

```json
Device.DeviceInfo.Manufacturer
```

```json
Device.WiFi.SSID.[SSID=="test_ssid"].BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.SSID.[SSID!="test_ssid"&&Enable==1].BSSID
```

```json
Device.WiFi.
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#validate-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp validate {"path":"et Excepteur ad","proto":"cwmp","maxdepth":2151689,"next-level":true,"instance-mode":-6258066}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp",
    "validate",
    { "path": "et Excepteur ad", "proto": "cwmp", "maxdepth": 2151689, "next-level": true, "instance-mode": -6258066 }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property    | Type    | Required |
| ----------- | ------- | -------- |
| `fault`     | integer | Optional |
| `parameter` | string  | Optional |

#### fault

`fault`

- is optional
- type: reference

##### fault Type

`integer`

- minimum value: `7000`
- maximum value: `9050`

#### parameter

`parameter`

- is optional
- type: `string`

##### parameter Type

`string`

### Output Example

```json
{ "parameter": "nisi te", "fault": 8845 }
```
