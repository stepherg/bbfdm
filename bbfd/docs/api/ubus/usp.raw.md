# usp.raw Schema

```
https://dev.iopsys.eu/iopsys/uspd/-/blob/devel/docs/api/ubus/usp.raw.md
```

| Custom Properties | Additional Properties |
| ----------------- | --------------------- |
| Forbidden         | Forbidden             |

# usp.raw

| List of Methods                           |
| ----------------------------------------- |
| [add_object](#add_object)                 | Method | usp.raw (this schema) |
| [del_object](#del_object)                 | Method | usp.raw (this schema) |
| [dump_schema](#dump_schema)               | Method | usp.raw (this schema) |
| [get](#get)                               | Method | usp.raw (this schema) |
| [get_supported_dm](#get_supported_dm)     | Method | usp.raw (this schema) |
| [getm_names](#getm_names)                 | Method | usp.raw (this schema) |
| [getm_values](#getm_values)               | Method | usp.raw (this schema) |
| [instances](#instances)                   | Method | usp.raw (this schema) |
| [list_events](#list_events)               | Method | usp.raw (this schema) |
| [list_operate](#list_operate)             | Method | usp.raw (this schema) |
| [notify_event](#notify_event)             | Method | usp.raw (this schema) |
| [object_names](#object_names)             | Method | usp.raw (this schema) |
| [operate](#operate)                       | Method | usp.raw (this schema) |
| [set](#set)                               | Method | usp.raw (this schema) |
| [setm_values](#setm_values)               | Method | usp.raw (this schema) |
| [transaction_abort](#transaction_abort)   | Method | usp.raw (this schema) |
| [transaction_commit](#transaction_commit) | Method | usp.raw (this schema) |
| [transaction_start](#transaction_start)   | Method | usp.raw (this schema) |
| [transaction_status](#transaction_status) | Method | usp.raw (this schema) |
| [validate](#validate)                     | Method | usp.raw (this schema) |

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

| Property         | Type    | Required     | Default  |
| ---------------- | ------- | ------------ | -------- |
| `instance_mode`  | integer | Optional     |          |
| `key`            | string  | Optional     |          |
| `path`           | string  | **Required** |          |
| `proto`          | string  | Optional     | `"both"` |
| `transaction_id` | integer | **Required** |          |

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

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

### Ubus CLI Example

```
ubus call usp.raw add_object {"path":"eu sit","transaction_id":13511822,"proto":"both","instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "add_object",
    {
      "path": "eu sit",
      "transaction_id": 13511822,
      "proto": "both",
      "key": "ut non in qui cupidatat",
      "instance_mode": 1
    }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["parameter", "status"],
      "properties": {
        "parameter": {
          "$ref": "#/definitions/path_t"
        },
        "status": {
          "type": "boolean"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be determined by fault code"
        },
        "instance": {
          "type": "string"
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "parameters": [
    {
      "parameter": "exnon sint minim cupidatat anim",
      "status": false,
      "fault": 8106,
      "instance": "exercitation qui culpa ven"
    }
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

| Property         | Type    | Required     | Default  |
| ---------------- | ------- | ------------ | -------- |
| `instance_mode`  | integer | Optional     |          |
| `key`            | string  | Optional     |          |
| `path`           | string  | **Required** |          |
| `proto`          | string  | Optional     | `"both"` |
| `transaction_id` | integer | **Required** |          |

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

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

### Ubus CLI Example

```
ubus call usp.raw del_object {"path":"ut adipisicing ut nisi","transaction_id":8573124,"proto":"cwmp","instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "del_object",
    {
      "path": "ut adipisicing ut nisi",
      "transaction_id": 8573124,
      "proto": "cwmp",
      "key": "tempor consectetur veniam laborum",
      "instance_mode": 1
    }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["parameter", "status"],
      "properties": {
        "parameter": {
          "$ref": "#/definitions/path_t"
        },
        "status": {
          "type": "boolean"
        },
        "fault": {
          "$ref": "#/definitions/fault_t"
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "parameters": [{ "parameter": "essein incididunt Duis dolore mollit", "status": true, "fault": 7621 }] }
```

## dump_schema

### Get available datamodel schema from Device

Schema will have all the nodes/objects supported by data model

`dump_schema`

- type: `Method`

### dump_schema Type

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
ubus call usp.raw dump_schema {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "usp.raw", "dump_schema", {}] }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "uniqueItems": true,
  "items": [
    {
      "type": "object",
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
        "unique_keys": {
          "type": "array",
          "uniqueItems": true,
          "maxItems": 8,
          "items": [
            {
              "type": "string"
            }
          ]
        }
      },
      "required": ["parameter", "writable", "type"]
    },
    {
      "type": "object",
      "properties": {
        "parameter": {
          "$ref": "#/definitions/schema_path_t"
        },
        "writable": {
          "$ref": "#/definitions/boolean_t"
        },
        "type": {
          "$ref": "#/definitions/type_t"
        }
      },
      "required": ["parameter", "writable", "type"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "parameters": [
    {
      "parameter": "aliquip adipisicing sed quis",
      "writable": "1",
      "type": "xsd:unsignedLong",
      "unique_keys": ["nisi"]
    },
    { "parameter": "reprehenderit occaecat i", "writable": "0", "type": "xsd:object" }
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
ubus call usp.raw get {"path":"etcillum in Duis","proto":"cwmp","maxdepth":-12869241,"next-level":false,"instance-mode":-60814589}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "get",
    {
      "path": "etcillum in Duis",
      "proto": "cwmp",
      "maxdepth": -12869241,
      "next-level": false,
      "instance-mode": -60814589
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
              "required": ["parameter", "value", "type"],
              "properties": {
                "parameter": {
                  "$ref": "#/definitions/path_t"
                },
                "value": {
                  "type": "string"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":8248},{\"parameters\":[{\"parameter\":\"in magna et\",\"value\":\"Excepteur\",\"type\":\"xsd:int\"}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 8248 },
    { "parameters": [{ "parameter": "in magna et", "value": "Excepteur", "type": "xsd:int" }] }
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
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
ubus call usp.raw get_supported_dm {"path":"minim occae","next-level":false,"schema_type":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "usp.raw", "get_supported_dm", { "path": "minim occae", "next-level": false, "schema_type": 1 }]
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
              },
              "required": ["parameter", "type"]
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":7018},{\"parameters\":[{\"parameter\":\"sunt Ut nulla labore id\",\"type\":\"xsd:unsignedInt\",\"writable\":\"1\",\"cmd_type\":\"async\",\"in\":[\"minim est\"],\"out\":[\"sed in laborum fugiat\"]}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 7018 },
    {
      "parameters": [
        {
          "parameter": "sunt Ut nulla labore id",
          "type": "xsd:unsignedInt",
          "writable": "1",
          "cmd_type": "async",
          "in": ["minim est"],
          "out": ["sed in laborum fugiat"]
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## getm_names

### Get multiple object names

Query multiple object names at once

`getm_names`

- type: `Method`

### getm_names Type

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
| `next-level`    | boolean | Optional     |          |
| `paths`         | array   | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance_mode

`instance_mode`

- is optional
- type: `integer`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### paths

`paths`

- is **required**
- type: `array`

##### paths Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "$ref": "#/definitions/path_t"
    }
  ],
  "simpletype": "`array`"
}
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#getm_names-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp.raw getm_names {"paths":["sit id"],"proto":"usp","next-level":true,"instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "getm_names",
    { "paths": ["sit id"], "proto": "usp", "next-level": true, "instance_mode": 1 }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["parameter"],
      "properties": {
        "parameter": {
          "$ref": "#/definitions/path_t"
        },
        "value": {
          "type": "string"
        },
        "type": {
          "$ref": "#/definitions/type_t"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be determined by fault code"
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "parameters": [
    { "parameter": "incididunt sed et", "value": "consequat incididunt dolore", "type": "xsd:boolean", "fault": 9006 }
  ]
}
```

## getm_values

### Get multiple values

Query multiple paths at once

`getm_values`

- type: `Method`

### getm_values Type

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
| `next-level`    | boolean | Optional     |          |
| `paths`         | array   | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### instance_mode

`instance_mode`

- is optional
- type: `integer`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### paths

`paths`

- is **required**
- type: `array`

##### paths Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "$ref": "#/definitions/path_t"
    }
  ],
  "simpletype": "`array`"
}
```

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#getm_values-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp.raw getm_values {"paths":["nulla esse magna"],"proto":"both","next-level":true,"instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "getm_values",
    { "paths": ["nulla esse magna"], "proto": "both", "next-level": true, "instance_mode": 1 }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["parameter"],
      "properties": {
        "parameter": {
          "$ref": "#/definitions/path_t"
        },
        "value": {
          "type": "string"
        },
        "type": {
          "$ref": "#/definitions/type_t"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be determined by fault code"
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "parameters": [{ "parameter": "aliqua ullamco", "value": "qui eiusmo", "type": "xsd:string", "fault": 8116 }] }
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
| `output` |        | Optional     |

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
ubus call usp.raw instances {"path":"eiusmod","proto":"usp","next-level":true,"maxdepth":-11964632,"instance-mode":9983797}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "instances",
    { "path": "eiusmod", "proto": "usp", "next-level": true, "maxdepth": -11964632, "instance-mode": 9983797 }
  ]
}
```

#### output

`output`

- is optional
- type: complex

##### output Type

Unknown type ``.

```json
{
  "oneof": [
    {
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be determined by fault code"
      }
    },
    {
      "type": "object",
      "required": ["parameters"],
      "properties": {
        "parameters": {
          "type": "array",
          "required": ["parameter"],
          "items": [
            {
              "type": "object",
              "properties": {
                "parameter": {
                  "$ref": "#/definitions/instance_t"
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":7620},{\"parameters\":[{\"parameter\":\"doloret minim adi\"}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [{ "fault": 7620 }, { "parameters": [{ "parameter": "doloret minim adi" }] }],
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## list_events

### List down supported usp events

events will be shown in schema format

`list_events`

- type: `Method`

### list_events Type

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
ubus call usp.raw list_events {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "usp.raw", "list_events", {}] }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["parameter", "type"],
      "properties": {
        "parameter": {
          "$ref": "#/definitions/operate_path_t"
        },
        "type": {
          "type": "string",
          "pattern": "xsd:event"
        },
        "in": {
          "type": "array",
          "items": [
            {
              "type": "string"
            }
          ]
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "parameters": [{ "parameter": "in est nostrud ea", "type": "xsd:event", "in": ["labore"] }] }
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
ubus call usp.raw list_operate {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "usp.raw", "list_operate", {}] }
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
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["parameter", "type"],
      "properties": {
        "parameter": {
          "$ref": "#/definitions/operate_path_t"
        },
        "type": {
          "$ref": "#/definitions/operate_type_t"
        },
        "in": {
          "type": "array",
          "items": [
            {
              "type": "string"
            }
          ]
        },
        "out": {
          "type": "array",
          "items": [
            {
              "type": "string"
            }
          ]
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "parameters": [
    { "parameter": "in com", "type": "async", "in": ["fugiat"], "out": ["pariatur ut cillum proident veniam"] }
  ]
}
```

## notify_event

### notify occurance of an event on ubus

`notify_event`

- type: `Method`

### notify_event Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | **Required** |
| `output` |        | Optional     |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | string | Optional     |
| `name`   | string | **Required** |

#### input

`input`

- is optional
- type: `string`

##### input Type

`string`

#### name

`name`

- is **required**
- type: `string`

##### name Type

`string`

### Ubus CLI Example

```
ubus call usp.raw notify_event {"name":"deserunt ipsum dolor officia","input":"Lorem consequat commodo in occaecat"}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "notify_event",
    { "name": "deserunt ipsum dolor officia", "input": "Lorem consequat commodo in occaecat" }
  ]
}
```

#### output

`output`

- is optional
- type: complex

##### output Type

Unknown type ``.

```json
{
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
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
ubus call usp.raw object_names {"path":"mollit aliqua dolor Duis elit","proto":"cwmp","next-level":true,"maxdepth":-77404850,"instance-mode":-15946651}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "object_names",
    {
      "path": "mollit aliqua dolor Duis elit",
      "proto": "cwmp",
      "next-level": true,
      "maxdepth": -77404850,
      "instance-mode": -15946651
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
        "Description": "Any discrepancy in input will result in fault. The type of fault can be determined by fault code"
      }
    },
    {
      "type": "object",
      "required": ["parameters"],
      "properties": {
        "parameters": {
          "type": "array",
          "items": [
            {
              "type": "object",
              "required": ["parameter", "writable", "type"],
              "properties": {
                "parameter": {
                  "$ref": "#/definitions/path_t"
                },
                "writable": {
                  "type": "integer",
                  "description": "1 if object is writable, 0 otherwise"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":7963},{\"parameters\":[{\"parameter\":\"sint do dolor ex\",\"writable\":-25525336,\"type\":\"xsd:event\"}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 7963 },
    { "parameters": [{ "parameter": "sint do dolor ex", "writable": -25525336, "type": "xsd:event" }] }
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
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
| `output` | object | **Required** |

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
| `instance_mode` | integer | Optional     |          |
| `path`          | string  | **Required** |          |
| `proto`         | string  | Optional     | `"both"` |

#### action

Opreate command as defined in TR-369, TR-181-2.13

`action`

- is **required**
- type: `string`

##### action Type

`string`

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

#### instance_mode

`instance_mode`

- is optional
- type: `integer`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

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
ubus call usp.raw operate {"path":"magna dolor qui","action":"qui in dolore eiusmod","proto":"cwmp","input":{},"instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "operate",
    { "path": "magna dolor qui", "action": "qui in dolore eiusmod", "proto": "cwmp", "input": {}, "instance_mode": 1 }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property  | Type  | Required     |
| --------- | ----- | ------------ |
| `Results` | array | **Required** |

#### Results

`Results`

- is **required**
- type: `array`

##### Results Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["path"],
      "properties": {
        "path": {
          "$ref": "#/definitions/path_t"
        },
        "parameters": {
          "description": "Output will have status for sync commands and for async commands parameters as defined in TR-181-2.13",
          "type": "array",
          "items": [
            {
              "type": "object",
              "properties": {
                "parameter": {
                  "type": "string"
                },
                "value": {
                  "type": "string"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
                },
                "fault": {
                  "$ref": "#/definitions/fault_t"
                }
              }
            }
          ],
          "examples": [
            "{\n\t\"status\": true}",
            "{\n\t\"AverageResponseTime\": \"0\",\n\t\"AverageResponseTimeDetailed\": \"130\",\n\t\"FailureCount\": \"0\",\n\t\"MaximumResponseTime\": \"0\",\n\t\"MaximumResponseTimeDetailed\": \"140\",\n\t\"MinimumResponseTime\": \"0\",\n\t\"MinimumResponseTimeDetailed\": \"120\",\n\t\"SuccessCount\": \"3\"}"
          ]
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "Results": [
    {
      "path": "minim irure enim exercitation e",
      "parameters": [
        { "parameter": "laboris anim commodo", "value": "consequat in veniam", "type": "xsd:boolean", "fault": 8214 }
      ]
    }
  ]
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

| Property         | Type    | Required     | Default  |
| ---------------- | ------- | ------------ | -------- |
| `instance_mode`  | integer | Optional     |          |
| `key`            | string  | Optional     |          |
| `path`           | string  | **Required** |          |
| `proto`          | string  | Optional     | `"both"` |
| `transaction_id` | integer | **Required** |          |
| `value`          | string  | **Required** |          |
| `values`         | object  | Optional     |          |

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

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

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
ubus call usp.raw set {"path":"anim ullamco","value":"officia nostrud dolor ad tempor","transaction_id":47775846,"proto":"usp","values":{},"instance_mode":1}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "set",
    {
      "path": "anim ullamco",
      "value": "officia nostrud dolor ad tempor",
      "transaction_id": 47775846,
      "proto": "usp",
      "values": {},
      "key": "dolore aliquip quis nostrud",
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
          "items": [
            {
              "type": "object",
              "required": ["parameter"],
              "properties": {
                "parameter": {
                  "$ref": "#/definitions/path_t"
                },
                "status": {
                  "type": "boolean"
                },
                "fault": {
                  "$ref": "#/definitions/fault_t"
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"status\":\"1\"},{\"parameters\":[{\"parameter\":\"deserunt tempor\",\"status\":false,\"fault\":7042}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [{ "status": "1" }, { "parameters": [{ "parameter": "deserunt tempor", "status": false, "fault": 7042 }] }],
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```

## setm_values

### Set values of multiple objects at once

`setm_values`

- type: `Method`

### setm_values Type

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

| Property         | Type    | Required     | Default  |
| ---------------- | ------- | ------------ | -------- |
| `instance_mode`  | integer | Optional     |          |
| `key`            | string  | Optional     |          |
| `proto`          | string  | Optional     | `"both"` |
| `pv_tuple`       | array   | **Required** |          |
| `transaction_id` | integer | **Required** |          |

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

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#setm_values-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

#### pv_tuple

`pv_tuple`

- is **required**
- type: `array`

##### pv_tuple Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "required": ["path", "value"],
      "properties": {
        "path": {
          "$ref": "#/definitions/path_t"
        },
        "value": {
          "type": "string"
        },
        "key": {
          "type": "string"
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `0`

### Ubus CLI Example

```
ubus call usp.raw setm_values {"pv_tuple":[{"path":"exmagna incididunt qui labore","value":"cillum occaecat aliquip anim id"}],"transaction_id":54841604,"proto":"both","instance_mode":0}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "setm_values",
    {
      "pv_tuple": [
        {
          "path": "exmagna incididunt qui labore",
          "value": "cillum occaecat aliquip anim id",
          "key": "adipisicing reprehenderit"
        }
      ],
      "transaction_id": 54841604,
      "proto": "both",
      "key": "ad",
      "instance_mode": 0
    }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property     | Type    | Required |
| ------------ | ------- | -------- |
| `parameters` | array   | Optional |
| `status`     | boolean | Optional |

#### parameters

`parameters`

- is optional
- type: `array`

##### parameters Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "object",
      "properties": {
        "path": {
          "$ref": "#/definitions/path_t"
        },
        "status": {
          "type": "boolean"
        },
        "fault": {
          "$ref": "#/definitions/fault_t"
        }
      }
    }
  ],
  "simpletype": "`array`"
}
```

#### status

`status`

- is optional
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{ "status": false, "parameters": [{ "path": "Excepteur eu quis voluptate", "status": false, "fault": 8080 }] }
```

## transaction_abort

### Aborts an on-going transaction

`transaction_abort`

- type: `Method`

### transaction_abort Type

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

| Property         | Type    | Required     |
| ---------------- | ------- | ------------ |
| `transaction_id` | integer | **Required** |

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

### Ubus CLI Example

```
ubus call usp.raw transaction_abort {"transaction_id":57946802}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "usp.raw", "transaction_abort", { "transaction_id": 57946802 }]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property | Type    | Required     |
| -------- | ------- | ------------ |
| `error`  | string  | Optional     |
| `status` | boolean | **Required** |

#### error

`error`

- is optional
- type: `string`

##### error Type

`string`

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{ "status": true, "error": "labore ad id" }
```

## transaction_commit

### Commits an on-going transaction

`transaction_commit`

- type: `Method`

### transaction_commit Type

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

| Property           | Type    | Required     |
| ------------------ | ------- | ------------ |
| `restart_services` | boolean | Optional     |
| `transaction_id`   | integer | **Required** |

#### restart_services

`restart_services`

- is optional
- type: `boolean`

##### restart_services Type

`boolean`

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

### Ubus CLI Example

```
ubus call usp.raw transaction_commit {"transaction_id":86335477,"restart_services":false}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "usp.raw", "transaction_commit", { "transaction_id": 86335477, "restart_services": false }]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property           | Type    | Required     |
| ------------------ | ------- | ------------ |
| `error`            | string  | Optional     |
| `status`           | boolean | **Required** |
| `updated_services` | array   | Optional     |

#### error

`error`

- is optional
- type: `string`

##### error Type

`string`

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

#### updated_services

`updated_services`

- is optional
- type: `array`

##### updated_services Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "items": [
    {
      "type": "string"
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "status": true, "error": "mollit id deserunt", "updated_services": ["id pariatur enim ut sunt"] }
```

## transaction_start

### Start a transaction before set/add/del operations

`transaction_start`

- type: `Method`

### transaction_start Type

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

| Property      | Type    | Required     |
| ------------- | ------- | ------------ |
| `app`         | string  | **Required** |
| `max_timeout` | integer | Optional     |

#### app

`app`

- is **required**
- type: `string`

##### app Type

`string`

#### max_timeout

`max_timeout`

- is optional
- type: `integer`

##### max_timeout Type

`integer`

- minimum value: `0`

### Ubus CLI Example

```
ubus call usp.raw transaction_start {"app":"a","max_timeout":76766611}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "usp.raw", "transaction_start", { "app": "a", "max_timeout": 76766611 }]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property         | Type    | Required     |
| ---------------- | ------- | ------------ |
| `error`          | string  | Optional     |
| `status`         | boolean | **Required** |
| `transaction_id` | integer | Optional     |

#### error

`error`

- is optional
- type: `string`

##### error Type

`string`

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

#### transaction_id

`transaction_id`

- is optional
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

### Output Example

```json
{ "status": false, "transaction_id": 12109922, "error": "deserunt aliquip consectetur q" }
```

## transaction_status

### Shows status of a transaction

`transaction_status`

- type: `Method`

### transaction_status Type

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

| Property         | Type    | Required     |
| ---------------- | ------- | ------------ |
| `transaction_id` | integer | **Required** |

#### transaction_id

`transaction_id`

- is **required**
- type: `integer`

##### transaction_id Type

`integer`

- minimum value: `1`

### Ubus CLI Example

```
ubus call usp.raw transaction_status {"transaction_id":55898564}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "usp.raw", "transaction_status", { "transaction_id": 55898564 }]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property         | Type    | Required     |
| ---------------- | ------- | ------------ |
| `app`            | string  | Optional     |
| `remaining_time` | integer | Optional     |
| `status`         | string  | **Required** |

#### app

`app`

- is optional
- type: `string`

##### app Type

`string`

#### remaining_time

`remaining_time`

- is optional
- type: `integer`

##### remaining_time Type

`integer`

#### status

on-going or not-exists

`status`

- is **required**
- type: `string`

##### status Type

`string`

### Output Example

```json
{ "status": "sed ut", "remaining_time": 13818285, "app": "anim" }
```

## validate

### Validate a datamodel path

Validate a path

`validate`

- type: `Method`

### validate Type

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

The value of this property **must** be equal to one of the [known values below](#validate-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call usp.raw validate {"path":"id adipisicing","proto":"both","next-level":true,"maxdepth":232638,"instance-mode":47166958}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "usp.raw",
    "validate",
    { "path": "id adipisicing", "proto": "both", "next-level": true, "maxdepth": 232638, "instance-mode": 47166958 }
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
        "Description": "Any discrepancy in input will result in fault. The type of fault can be determined by fault code"
      }
    },
    {
      "type": "object",
      "required": ["parameters"],
      "properties": {
        "parameters": {
          "$ref": "#/definitions/path_t"
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": {
      "type": "integer",
      "minimum": 7000,
      "maximum": 9050
    }
  },
  "out": "{\"oneof\":[{\"fault\":7959},{\"parameters\":\"id aute\"}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.[SSID==\\\"test_ssid\\\"].BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.SSID.[SSID!=\\\"test_ssid\\\"&&Enable==1].BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [{ "fault": 7959 }, { "parameters": "id aute" }],
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
        "xsd:object",
        "xsd:command",
        "xsd:event"
      ]
    },
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 }
  }
}
```
