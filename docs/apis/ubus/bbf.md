# bbf Schema

```
https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/docs/api/bbfdm.md
```

| Custom Properties | Additional Properties |
| ----------------- | --------------------- |
| Forbidden         | Forbidden             |

# bbf

| List of Methods               |
| ----------------------------- |
| [add](#add)                   | Method | bbf (this schema) |
| [del](#del)                   | Method | bbf (this schema) |
| [get](#get)                   | Method | bbf (this schema) |
| [instances](#instances)       | Method | bbf (this schema) |
| [notify_event](#notify_event) | Method | bbf (this schema) |
| [operate](#operate)           | Method | bbf (this schema) |
| [schema](#schema)             | Method | bbf (this schema) |
| [set](#set)                   | Method | bbf (this schema) |
| [transaction](#transaction)   | Method | bbf (this schema) |

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
ubus call bbf add {"path":"aute dolore","optional":{"transaction_id":6658315},"obj_path":{}}
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
    { "path": "aute dolore", "optional": { "transaction_id": 6658315 }, "obj_path": {} }
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
{ "results": [{ "path": "cupidatat enim non ullamco tempor", "data": "aliqua eu", "fault": 8966, "fault_msg": "ci" }] }
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
ubus call bbf del {"path":"ea enim","paths":["commodo proi"],"optional":{"transaction_id":35247793}}
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
    { "path": "ea enim", "paths": ["commodo proi"], "optional": { "transaction_id": 35247793 } }
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
    { "path": "laborum aliqua", "data": "tempor culpa in", "fault": 7997, "fault_msg": "amet reprehenderit consec" }
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
ubus call bbf get {"path":"aute dolor ut laborum deserunt","paths":["Loremnisi sunt enim"],"maxdepth":-13915475,"optional":{"format":"raw","proto":"usp","instance_mode":0}}
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
      "path": "aute dolor ut laborum deserunt",
      "paths": ["Loremnisi sunt enim"],
      "maxdepth": -13915475,
      "optional": { "format": "raw", "proto": "usp", "instance_mode": 0 }
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
{
  "results": [
    {
      "path": "adipisicing labore",
      "data": "anim Excepteur laboris",
      "type": "xsd:hexBinary",
      "fault": 8645,
      "fault_msg": "tempor"
    }
  ]
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
ubus call bbf instances {"path":"labore","first_level":false,"optional":{"proto":"usp","instance_mode":1}}
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
    { "path": "labore", "first_level": false, "optional": { "proto": "usp", "instance_mode": 1 } }
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
{ "results": [{ "path": "aliqua reprehenderit Except", "fault": 8825, "fault_msg": "minim eu incididunt" }] }
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
| `input`  | object | Optional     |
| `name`   | string | **Required** |

#### input

`input`

- is optional
- type: `object`

##### input Type

`object` with following properties:

| Property | Type | Required |
| -------- | ---- | -------- |
| None     | None | None     |

#### name

`name`

- is **required**
- type: `string`

##### name Type

`string`

### Ubus CLI Example

```
ubus call bbf notify_event {"name":"veniam dolor t","input":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "notify_event", { "name": "veniam dolor t", "input": {} }]
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
      "examples": ["Device.IP.Diagnostics.IPPing()", "Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.1.BSSID",
        "Device.WiFi.SSID.*.BSSID",
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
    },
    "trans_type_t": {
      "type": "string",
      "enum": ["start", "commit", "abort", "status"]
    },
    "format_t": {
      "type": "string",
      "default": "pretty",
      "enum": ["raw", "pretty"]
    },
    "instance_mode_t": {
      "type": "integer",
      "default": 0,
      "minimum": 0,
      "maximum": 1
    },
    "trans_id_t": {
      "type": "integer",
      "minimum": 1
    }
  },
  "out": "{\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.IP.Diagnostics.IPPing()\",\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050},\"trans_type_t\":{\"type\":\"string\",\"enum\":[\"start\",\"commit\",\"abort\",\"status\"]},\"format_t\":{\"type\":\"string\",\"default\":\"pretty\",\"enum\":[\"raw\",\"pretty\"]},\"instance_mode_t\":{\"type\":\"integer\",\"default\":0,\"minimum\":0,\"maximum\":1},\"trans_id_t\":{\"type\":\"integer\",\"minimum\":1}}}",
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
      "examples": ["Device.IP.Diagnostics.IPPing()", "Device.DHCPv4.Client.{i}.Renew()", "Device.FactoryReset()"]
    },
    "query_path_t": {
      "description": "DM object path with search queries",
      "type": "string",
      "minLength": 6,
      "maxLength": 1024,
      "examples": [
        "Device.",
        "Device.DeviceInfo.Manufacturer",
        "Device.WiFi.SSID.1.BSSID",
        "Device.WiFi.SSID.*.BSSID",
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
    "fault_t": { "type": "integer", "minimum": 7000, "maximum": 9050 },
    "trans_type_t": { "type": "string", "enum": ["start", "commit", "abort", "status"] },
    "format_t": { "type": "string", "default": "pretty", "enum": ["raw", "pretty"] },
    "instance_mode_t": { "type": "integer", "default": 0, "minimum": 0, "maximum": 1 },
    "trans_id_t": { "type": "integer", "minimum": 1 }
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
ubus call bbf operate {"command":"officia nostrud sunt","command_key":"sunt qui","input":{},"optional":{"format":"raw","proto":"both","instance_mode":1}}
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
      "command": "officia nostrud sunt",
      "command_key": "sunt qui",
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
      "path": "fugiat occaecat",
      "data": "1",
      "fault": 8855,
      "fault_msg": "magna deserunt labore enim",
      "output": [{ "path": "dolore ullamco", "data": "1", "type": "xsd:unsignedLong" }]
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
ubus call bbf schema {"path":"proident elit","paths":["in null"],"first_level":false,"commands":true,"events":false,"params":true,"optional":{"proto":"both"}}
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
      "path": "proident elit",
      "paths": ["in null"],
      "first_level": false,
      "commands": true,
      "events": false,
      "params": true,
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
      "path": "utipsum magna",
      "data": "0",
      "type": "xsd:boolean",
      "fault": 8703,
      "fault_msg": "eu dolor est",
      "input": [{ "path": "Excepteur Ut incididunt", "data": "1", "type": "xsd:unsignedLong" }],
      "output": [{ "path": "ullamco adipisicing in", "data": "1", "type": "xsd:command" }]
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
{ "path": "Device.WiFi.SSID.1", "values": { ".SSID": "test_ssid", ".Name": "test_name" } }
```

```json
{ "path": "Device.WiFi.SSID.2", "values": { ".SSID": "test_ssid" } }
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
ubus call bbf set {"path":"amet id ex adipisicing","value":"elit","optional":{"proto":"both","instance_mode":0,"transaction_id":13670657},"obj_path":{}}
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
      "path": "amet id ex adipisicing",
      "value": "elit",
      "optional": { "proto": "both", "instance_mode": 0, "transaction_id": 13670657 },
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
{
  "results": [
    { "path": "cillum dolore enim ea tempor", "data": "1", "fault": 7177, "fault_msg": "cupidatat do fugiat sed" }
  ]
}
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

`transaction_id`

- is optional
- type: reference

##### transaction_id Type

`integer`

- minimum value: `1`

#### restart_services

`restart_services`

- is optional
- type: `boolean`

##### restart_services Type

`boolean`

#### timeout

`timeout`

- is optional
- type: `integer`

##### timeout Type

`integer`

- minimum value: `0`

### Ubus CLI Example

```
ubus call bbf transaction {"cmd":"commit","timeout":67151755,"restart_services":true,"optional":{"transaction_id":45369701}}
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
    { "cmd": "commit", "timeout": 67151755, "restart_services": true, "optional": { "transaction_id": 45369701 } }
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
{ "status": true, "transaction_id": 61009982, "error": "amet qui Duis eiusmod" }
```
