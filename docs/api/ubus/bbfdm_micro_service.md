# bbf Schema

```
https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/docs/api/ubus/bbfdm.md
```

| Custom Properties | Additional Properties |
| ----------------- | --------------------- |
| Forbidden         | Forbidden             |

# bbf

| List of Methods             |
| --------------------------- |
| [add](#add)                 | Method | bbf (this schema) |
| [del](#del)                 | Method | bbf (this schema) |
| [get](#get)                 | Method | bbf (this schema) |
| [instances](#instances)     | Method | bbf (this schema) |
| [operate](#operate)         | Method | bbf (this schema) |
| [schema](#schema)           | Method | bbf (this schema) |
| [set](#set)                 | Method | bbf (this schema) |
| [transaction](#transaction) | Method | bbf (this schema) |

## add

### Add a new object instance

Add a new object in multi instance object

`add`

- type: `Method`

### add Type

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

| Property   | Type   | Required     |
| ---------- | ------ | ------------ |
| `obj_path` | object | Optional     |
| `optional` | object | **Required** |
| `path`     | string | **Required** |

#### obj_path

`obj_path`

- is optional
- type: `object`

##### obj_path Type

`object` with following properties:

| Property | Type | Required |
| -------- | ---- | -------- |
| None     | None | None     |

#### optional

`optional`

- is **required**
- type: `object`

##### optional Type

`object` with following properties:

| Property         | Type    | Required |
| ---------------- | ------- | -------- |
| `transaction_id` | integer | Optional |

#### transaction_id

Required for CUD operation, it shall be same number as got from transaction->start

`transaction_id`

- is optional
- type: reference

##### transaction_id Type

`integer`

- minimum value: `1`

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

### Ubus CLI Example

```
ubus call bbf add {"path":"estanim Ut","optional":{"transaction_id":31269307},"obj_path":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "add",
    { "path": "estanim Ut", "optional": { "transaction_id": 31269307 }, "obj_path": {} }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
        "data": {
          "type": "string"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        }
      },
      "required": ["path"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "results": [
    { "path": "nulla voluptate eiusmod sit", "data": "ni", "fault": 7499, "fault_msg": "laboris pariatur tempor" }
  ]
}
```

## del

### Delete object instance

Delete a object instance from multi instance object

`del`

- type: `Method`

### del Type

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

| Property   | Type   | Required     |
| ---------- | ------ | ------------ |
| `optional` | object | Optional     |
| `path`     | string | **Required** |
| `paths`    | array  | Optional     |

#### optional

`optional`

- is optional
- type: `object`

##### optional Type

`object` with following properties:

| Property         | Type    | Required |
| ---------------- | ------- | -------- |
| `transaction_id` | integer | Optional |

#### transaction_id

Required for CUD operation, it shall be same number as got from transaction->start

`transaction_id`

- is optional
- type: reference

##### transaction_id Type

`integer`

- minimum value: `1`

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

#### paths

`paths`

- is optional
- type: `array`

##### paths Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "uniqueItems": true,
  "items": [
    {
      "$ref": "#/definitions/query_path_t"
    }
  ],
  "simpletype": "`array`"
}
```

### Ubus CLI Example

```
ubus call bbf del {"path":"amet e","paths":["magna ani"],"optional":{"transaction_id":75019380}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "del",
    { "path": "amet e", "paths": ["magna ani"], "optional": { "transaction_id": 75019380 } }
  ]
}
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
        "data": {
          "type": "string"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        }
      },
      "required": ["parameter", "type"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "results": [
    { "path": "qui ex officia", "data": "nostrud est do ex", "fault": 7045, "fault_msg": "sed sunt Lorem occaecat" }
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
| `output` | object | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property   | Type    | Required     |
| ---------- | ------- | ------------ |
| `maxdepth` | integer | Optional     |
| `optional` | object  | Optional     |
| `path`     | string  | **Required** |
| `paths`    | array   | Optional     |

#### maxdepth

Integer to decide the depth of data model to be parsed

`maxdepth`

- is optional
- type: `integer`

##### maxdepth Type

`integer`

#### optional

`optional`

- is optional
- type: `object`

##### optional Type

`object` with following properties:

| Property        | Type    | Required | Default    |
| --------------- | ------- | -------- | ---------- |
| `format`        | string  | Optional | `"pretty"` |
| `instance_mode` | integer | Optional | `0`        |
| `proto`         | string  | Optional | `"both"`   |

#### format

`format`

- is optional
- type: reference
- default: `"pretty"`

##### format Type

`string`

The value of this property **must** be equal to one of the [known values below](#get-known-values).

##### format Known Values

| Value  |
| ------ |
| raw    |
| pretty |

#### instance_mode

`instance_mode`

- is optional
- type: reference
- default: `0`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

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
Device.WiFi.SSID.1.BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.
```

#### paths

`paths`

- is optional
- type: `array`

##### paths Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "uniqueItems": true,
  "items": [
    {
      "$ref": "#/definitions/query_path_t"
    }
  ],
  "simpletype": "`array`"
}
```

### Ubus CLI Example

```
ubus call bbf get {"path":"occaecat culpa","paths":["non voluptate"],"maxdepth":42643410,"optional":{"format":"pretty","proto":"both","instance_mode":0}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "get",
    {
      "path": "occaecat culpa",
      "paths": ["non voluptate"],
      "maxdepth": 42643410,
      "optional": { "format": "pretty", "proto": "both", "instance_mode": 0 }
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

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
        "data": {
          "type": "string"
        },
        "type": {
          "$ref": "#/definitions/type_t"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        }
      },
      "required": ["path"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "results": [{ "path": "veniam ", "data": "et", "type": "xsd:int", "fault": 7572, "fault_msg": "enim" }] }
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
| `output` | object | Optional     |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property      | Type    | Required     |
| ------------- | ------- | ------------ |
| `first_level` | boolean | Optional     |
| `optional`    | object  | Optional     |
| `path`        | string  | **Required** |

#### first_level

gets only first level objects if true

`first_level`

- is optional
- type: `boolean`

##### first_level Type

`boolean`

#### optional

`optional`

- is optional
- type: `object`

##### optional Type

`object` with following properties:

| Property        | Type    | Required | Default  |
| --------------- | ------- | -------- | -------- |
| `instance_mode` | integer | Optional | `0`      |
| `proto`         | string  | Optional | `"both"` |

#### instance_mode

`instance_mode`

- is optional
- type: reference
- default: `0`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

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
Device.WiFi.SSID.1.BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.
```

### Ubus CLI Example

```
ubus call bbf instances {"path":"fugiat anim Lorem reprehende","first_level":false,"optional":{"proto":"cwmp","instance_mode":0}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "instances",
    {
      "path": "fugiat anim Lorem reprehende",
      "first_level": false,
      "optional": { "proto": "cwmp", "instance_mode": 0 }
    }
  ]
}
```

#### output

`output`

- is optional
- type: `object`

##### output Type

`object` with following properties:

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        }
      },
      "required": ["path"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "results": [{ "path": "in ipsum proident Duis nulla", "fault": 8425, "fault_msg": "elit culpa" }] }
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

| Property      | Type   | Required     |
| ------------- | ------ | ------------ |
| `command`     | string | **Required** |
| `command_key` | string | Optional     |
| `input`       | object | Optional     |
| `optional`    | object | Optional     |

#### command

Datamodel object schema path

`command`

- is **required**
- type: reference

##### command Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### command Examples

```json
Device.IP.Diagnostics.IPPing()
```

```json
Device.DHCPv4.Client.{i}.Renew()
```

```json
Device.FactoryReset()
```

#### command_key

`command_key`

- is optional
- type: `string`

##### command_key Type

`string`

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
{ "path": "Device.IP.Diagnostics.IPPing()", "input": { "Host": "iopsys.eu" } }
```

#### optional

`optional`

- is optional
- type: `object`

##### optional Type

`object` with following properties:

| Property        | Type    | Required | Default    |
| --------------- | ------- | -------- | ---------- |
| `format`        | string  | Optional | `"pretty"` |
| `instance_mode` | integer | Optional | `0`        |
| `proto`         | string  | Optional | `"both"`   |

#### format

`format`

- is optional
- type: reference
- default: `"pretty"`

##### format Type

`string`

The value of this property **must** be equal to one of the [known values below](#operate-known-values).

##### format Known Values

| Value  |
| ------ |
| raw    |
| pretty |

#### instance_mode

`instance_mode`

- is optional
- type: reference
- default: `0`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

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
ubus call bbf operate {"command":"exipsum cillum labore cupidatat minim","command_key":"ullamco nostrud sunt","input":{},"optional":{"format":"raw","proto":"both","instance_mode":1}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "operate",
    {
      "command": "exipsum cillum labore cupidatat minim",
      "command_key": "ullamco nostrud sunt",
      "input": {},
      "optional": { "format": "raw", "proto": "both", "instance_mode": 1 }
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

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
        "data": {
          "$ref": "#/definitions/boolean_t"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "output": {
          "type": "array",
          "items": [
            {
              "type": "object",
              "properties": {
                "path": {
                  "$ref": "#/definitions/path_t"
                },
                "data": {
                  "$ref": "#/definitions/boolean_t"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
                }
              }
            }
          ]
        }
      },
      "required": ["path", "data"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "results": [
    {
      "path": "deserunt cillum amet",
      "data": "0",
      "fault": 7140,
      "fault_msg": "laborum",
      "output": [{ "path": "proident", "data": "1", "type": "xsd:boolean" }]
    }
  ]
}
```

## schema

### Get list of supported datamodel parameters

Schema will have all the nodes/objects supported by libbbf

`schema`

- type: `Method`

### schema Type

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

| Property      | Type    | Required |
| ------------- | ------- | -------- |
| `commands`    | boolean | Optional |
| `events`      | boolean | Optional |
| `first_level` | boolean | Optional |
| `optional`    | object  | Optional |
| `params`      | boolean | Optional |
| `path`        | string  | Optional |
| `paths`       | array   | Optional |

#### commands

includes commands in the list if true

`commands`

- is optional
- type: `boolean`

##### commands Type

`boolean`

#### events

includes events in the list if true

`events`

- is optional
- type: `boolean`

##### events Type

`boolean`

#### first_level

gets only first level objects if true

`first_level`

- is optional
- type: `boolean`

##### first_level Type

`boolean`

#### optional

`optional`

- is optional
- type: `object`

##### optional Type

`object` with following properties:

| Property | Type   | Required | Default  |
| -------- | ------ | -------- | -------- |
| `proto`  | string | Optional | `"both"` |

#### proto

`proto`

- is optional
- type: reference
- default: `"both"`

##### proto Type

`string`

The value of this property **must** be equal to one of the [known values below](#schema-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

#### params

includes objs/params in the list if true

`params`

- is optional
- type: `boolean`

##### params Type

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
Device.WiFi.SSID.1.BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.
```

#### paths

`paths`

- is optional
- type: `array`

##### paths Type

Array type: `array`

All items must be of the type: Unknown type ``.

```json
{
  "type": "array",
  "uniqueItems": true,
  "items": [
    {
      "$ref": "#/definitions/query_path_t"
    }
  ],
  "simpletype": "`array`"
}
```

### Ubus CLI Example

```
ubus call bbf schema {"path":"magna cillum consequat","paths":["nisi nulla ullamco"],"first_level":false,"commands":false,"events":true,"params":false,"optional":{"proto":"both"}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "schema",
    {
      "path": "magna cillum consequat",
      "paths": ["nisi nulla ullamco"],
      "first_level": false,
      "commands": false,
      "events": true,
      "params": false,
      "optional": { "proto": "both" }
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

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
          "$ref": "#/definitions/schema_path_t"
        },
        "data": {
          "$ref": "#/definitions/boolean_t"
        },
        "type": {
          "$ref": "#/definitions/type_t"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "input": {
          "type": "array",
          "items": [
            {
              "type": "object",
              "properties": {
                "path": {
                  "$ref": "#/definitions/schema_path_t"
                },
                "data": {
                  "$ref": "#/definitions/boolean_t"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
                }
              }
            }
          ]
        },
        "output": {
          "type": "array",
          "items": [
            {
              "type": "object",
              "properties": {
                "path": {
                  "$ref": "#/definitions/schema_path_t"
                },
                "data": {
                  "$ref": "#/definitions/boolean_t"
                },
                "type": {
                  "$ref": "#/definitions/type_t"
                }
              }
            }
          ]
        }
      },
      "required": ["path"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{
  "results": [
    {
      "path": "Duis in dolore",
      "data": "0",
      "type": "xsd:dateTime",
      "fault": 7341,
      "fault_msg": "",
      "input": [{ "path": "veniam officia consectetur aute", "data": "0", "type": "xsd:dateTime" }],
      "output": [{ "path": "velit laboris Lorem proident officia", "data": "1", "type": "xsd:unsignedLong" }]
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
| `output` | object | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property   | Type   | Required     |
| ---------- | ------ | ------------ |
| `obj_path` | object | Optional     |
| `optional` | object | **Required** |
| `path`     | string | **Required** |
| `value`    | string | **Required** |

#### obj_path

To set multiple values at once, path should be relative to object elements

`obj_path`

- is optional
- type: `object`

##### obj_path Type

`object` with following properties:

| Property | Type | Required |
| -------- | ---- | -------- |
| None     | None | None     |

##### obj_path Examples

```json
{ "path": "Device.WiFi.SSID.1.", "obj_path": { "SSID": "test_ssid", "Name": "test_name" } }
```

```json
{ "path": "Device.WiFi.SSID.2.", "obj_path": { "SSID": "test_ssid" } }
```

#### optional

`optional`

- is **required**
- type: `object`

##### optional Type

`object` with following properties:

| Property         | Type    | Required | Default  |
| ---------------- | ------- | -------- | -------- |
| `instance_mode`  | integer | Optional | `0`      |
| `proto`          | string  | Optional | `"both"` |
| `transaction_id` | integer | Optional |          |

#### instance_mode

`instance_mode`

- is optional
- type: reference
- default: `0`

##### instance_mode Type

`integer`

- minimum value: `0`
- maximum value: `1`

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

Required for CUD operation, it shall be same number as got from transaction->start

`transaction_id`

- is optional
- type: reference

##### transaction_id Type

`integer`

- minimum value: `1`

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
Device.WiFi.SSID.1.BSSID
```

```json
Device.WiFi.SSID.*.BSSID
```

```json
Device.WiFi.
```

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

### Ubus CLI Example

```
ubus call bbf set {"path":"qui ullamco non","value":"ut aliquip anim ex","optional":{"proto":"cwmp","instance_mode":0,"transaction_id":62652682},"obj_path":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "set",
    {
      "path": "qui ullamco non",
      "value": "ut aliquip anim ex",
      "optional": { "proto": "cwmp", "instance_mode": 0, "transaction_id": 62652682 },
      "obj_path": {}
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

| Property  | Type  | Required |
| --------- | ----- | -------- |
| `results` | array | Optional |

#### results

`results`

- is optional
- type: `array`

##### results Type

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
        "data": {
          "$ref": "#/definitions/boolean_t"
        },
        "fault": {
          "$ref": "#/definitions/fault_t",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        },
        "fault_msg": {
          "type": "string",
          "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
        }
      },
      "required": ["path"]
    }
  ],
  "simpletype": "`array`"
}
```

### Output Example

```json
{ "results": [{ "path": "labore et amet", "data": "0", "fault": 7959, "fault_msg": "dolor sunt" }] }
```

## transaction

### Start/commit/abort/status a transaction before set/add/del operations

`transaction`

- type: `Method`

### transaction Type

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
| `cmd`              | string  | **Required** |
| `optional`         | object  | Optional     |
| `restart_services` | boolean | Optional     |
| `timeout`          | integer | Optional     |

#### cmd

`cmd`

- is **required**
- type: reference

##### cmd Type

`string`

The value of this property **must** be equal to one of the [known values below](#transaction-known-values).

##### cmd Known Values

| Value  |
| ------ |
| start  |
| commit |
| abort  |
| status |

#### optional

`optional`

- is optional
- type: `object`

##### optional Type

`object` with following properties:

| Property         | Type    | Required |
| ---------------- | ------- | -------- |
| `transaction_id` | integer | Optional |

#### transaction_id

Required for CUD operation, it shall be same number as got from transaction->start

`transaction_id`

- is optional
- type: reference

##### transaction_id Type

`integer`

- minimum value: `1`

#### restart_services

If yes, bbfdmd restart the service after CUD operation, else return list of updated uci to handler restart externally.

`restart_services`

- is optional
- type: `boolean`

##### restart_services Type

`boolean`

#### timeout

Timeout (in milliseconds) for the transaction, on timeout changes will be reverted

`timeout`

- is optional
- type: `integer`

##### timeout Type

`integer`

- minimum value: `0`

### Ubus CLI Example

```
ubus call bbf transaction {"cmd":"start","timeout":81531371,"restart_services":false,"optional":{"transaction_id":25600713}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "bbf",
    "transaction",
    { "cmd": "start", "timeout": 81531371, "restart_services": false, "optional": { "transaction_id": 25600713 } }
  ]
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
{ "status": false, "transaction_id": 44817555, "error": "labore id laborum mollit" }
```
