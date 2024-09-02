# bbf Schema

```
https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/docs/api/ubus/bbfdm.md
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
| [service](#service)           | Method | bbf (this schema) |
| [set](#set)                   | Method | bbf (this schema) |

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
ubus call bbf add {"path":"anim consequat","obj_path":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "add", { "path": "anim consequat", "obj_path": {} }]
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
{ "results": [{ "path": "dolor in sunt eiusmod", "data": "sunt pariatur", "fault": 8972, "fault_msg": "ea culpa" }] }
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

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `path`   | string | **Required** |
| `paths`  | array  | Optional     |

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
ubus call bbf del {"path":"eu venia","paths":["adipisicing ad dolor do"]}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "del", { "path": "eu venia", "paths": ["adipisicing ad dolor do"] }]
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
    {
      "path": "incididunt laborum Duis",
      "data": "nostrud aliquip velit",
      "fault": 7729,
      "fault_msg": "culpa nisi adipisicing dolore eiusmod"
    }
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

| Property | Type   | Required | Default    |
| -------- | ------ | -------- | ---------- |
| `format` | string | Optional | `"pretty"` |
| `proto`  | string | Optional | `"both"`   |

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
ubus call bbf get {"path":"veniam sunt","paths":["nisi ad et veniam"],"maxdepth":-3902100,"optional":{"format":"raw","proto":"both"}}
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
      "path": "veniam sunt",
      "paths": ["nisi ad et veniam"],
      "maxdepth": -3902100,
      "optional": { "format": "raw", "proto": "both" }
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
    { "path": "anim consectetur", "data": "dolore d", "type": "xsd:command", "fault": 8024, "fault_msg": "quis minim" }
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
ubus call bbf instances {"path":"veniam mollit occaecat cillum","first_level":true,"optional":{"proto":"cwmp"}}
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
    { "path": "veniam mollit occaecat cillum", "first_level": true, "optional": { "proto": "cwmp" } }
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
{ "results": [{ "path": "labore occaecat a", "fault": 9010, "fault_msg": "Lorem" }] }
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
| `input`  | array  | Optional     |
| `name`   | string | **Required** |

#### input

`input`

- is optional
- type: `array`

##### input Type

Array type: `array`

#### name

`name`

- is **required**
- type: `string`

##### name Type

`string`

### Ubus CLI Example

```
ubus call bbf notify_event {"name":"eu laboris anim","input":[]}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "notify_event", { "name": "eu laboris anim", "input": [] }]
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
    "datatype_t": {
      "type": "string",
      "enum": ["int", "unsignedInt", "long", "unsignedLong", "string", "boolean", "dateTime", "base64", "hexBinary"]
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
    "srv_type_t": {
      "type": "string",
      "enum": ["register", "list"]
    },
    "format_t": {
      "type": "string",
      "default": "pretty",
      "enum": ["raw", "pretty"]
    }
  },
  "out": "{\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"datatype_t\":{\"type\":\"string\",\"enum\":[\"int\",\"unsignedInt\",\"long\",\"unsignedLong\",\"string\",\"boolean\",\"dateTime\",\"base64\",\"hexBinary\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.IP.Diagnostics.IPPing()\",\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"query_path_t\":{\"description\":\"DM object path with search queries\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.BSSID\",\"Device.WiFi.SSID.*.BSSID\",\"Device.WiFi.\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050},\"trans_type_t\":{\"type\":\"string\",\"enum\":[\"start\",\"commit\",\"abort\",\"status\"]},\"srv_type_t\":{\"type\":\"string\",\"enum\":[\"register\",\"list\"]},\"format_t\":{\"type\":\"string\",\"default\":\"pretty\",\"enum\":[\"raw\",\"pretty\"]}}}",
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
    "datatype_t": {
      "type": "string",
      "enum": ["int", "unsignedInt", "long", "unsignedLong", "string", "boolean", "dateTime", "base64", "hexBinary"]
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
    "srv_type_t": { "type": "string", "enum": ["register", "list"] },
    "format_t": { "type": "string", "default": "pretty", "enum": ["raw", "pretty"] }
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

| Property | Type   | Required | Default    |
| -------- | ------ | -------- | ---------- |
| `format` | string | Optional | `"pretty"` |
| `proto`  | string | Optional | `"both"`   |

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
ubus call bbf operate {"command":"velit magna laboris aliquip culpa","command_key":"voluptate ad cupidatat","input":{},"optional":{"format":"pretty","proto":"usp"}}
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
      "command": "velit magna laboris aliquip culpa",
      "command_key": "voluptate ad cupidatat",
      "input": {},
      "optional": { "format": "pretty", "proto": "usp" }
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
      "path": "commodo dolor laboris",
      "data": "1",
      "fault": 7192,
      "fault_msg": "non Lorem",
      "output": [{ "path": "fugiat in qui", "data": "0", "type": "xsd:string" }]
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
ubus call bbf schema {"path":"qui dolor nisi","paths":["veniam in dolor deserunt"],"first_level":true,"commands":true,"events":false,"params":false,"optional":{"proto":"cwmp"}}
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
      "path": "qui dolor nisi",
      "paths": ["veniam in dolor deserunt"],
      "first_level": true,
      "commands": true,
      "events": false,
      "params": false,
      "optional": { "proto": "cwmp" }
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
      "path": "pariatur ",
      "data": "1",
      "type": "xsd:boolean",
      "fault": 7493,
      "fault_msg": "mollit ",
      "input": [{ "path": "aliquip", "data": "1", "type": "xsd:int" }],
      "output": [{ "path": "elit est dolor do", "data": "1", "type": "xsd:int" }]
    }
  ]
}
```

## service

### Register a micro-service in the main service

`service`

- type: `Method`

### service Type

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

| Property    | Type   | Required     |
| ----------- | ------ | ------------ |
| `cmd`       | string | **Required** |
| `name`      | string | Optional     |
| `object`    | string | Optional     |
| `parent_dm` | string | Optional     |

#### cmd

`cmd`

- is **required**
- type: reference

##### cmd Type

`string`

The value of this property **must** be equal to one of the [known values below](#service-known-values).

##### cmd Known Values

| Value    |
| -------- |
| register |
| list     |

#### name

Name of the micro-service ubus object

`name`

- is optional
- type: `string`

##### name Type

`string`

#### object

Name of the micro-service object

`object`

- is optional
- type: `string`

##### object Type

`string`

#### parent_dm

Object path where the micro-service object will be added

`parent_dm`

- is optional
- type: `string`

##### parent_dm Type

`string`

### Ubus CLI Example

```
ubus call bbf service {"cmd":"list","name":"ex fugiat","parent_dm":"esse ipsum dolore Ut et","object":"sed amet Duis"}
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
    "service",
    { "cmd": "list", "name": "ex fugiat", "parent_dm": "esse ipsum dolore Ut et", "object": "sed amet Duis" }
  ]
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
{ "status": true, "error": "eu aliq" }
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
| `datatype` | string | Optional     |
| `obj_path` | object | Optional     |
| `path`     | string | **Required** |
| `value`    | string | **Required** |

#### datatype

datatype of the object element provided in path

`datatype`

- is optional
- type: reference

##### datatype Type

`string`

The value of this property **must** be equal to one of the [known values below](#set-known-values).

##### datatype Known Values

| Value        |
| ------------ |
| int          |
| unsignedInt  |
| long         |
| unsignedLong |
| string       |
| boolean      |
| dateTime     |
| base64       |
| hexBinary    |

##### datatype Examples

```json
{ "path": "Device.WiFi.SSID.1.SSID", "value": "test_ssid", "datatype": "string" }
```

```json
{ "path": "Device.WiFi.SSID.2.Enable", "value": "true", "datatype": "boolean" }
```

```json
{ "path": "Device.DHCPv4.Relay.Forwarding.1.ClientID", "value": "0103060C", "datatype": "hexBinary" }
```

```json
{ "path": "Device.DHCPv4.Server.Pool.1.LeaseTime", "value": "120", "datatype": "int" }
```

```json
{ "path": "Device.DHCPv4.Relay.Forwarding.1.Order", "value": "1", "datatype": "unsignedInt" }
```

```json
{ "path": "Device.QoS.Queue.1.ShapingRate", "value": "1002", "datatype": "long" }
```

```json
{ "path": "Device.IP.Diagnostics.UploadDiagnostics.TestFileLength", "value": "1002", "datatype": "unsignedLong" }
```

```json
{ "path": "Device.USPAgent.ControllerTrust.Challenge.1.Value", "value": "01Z3A6YC", "datatype": "base64" }
```

```json
{ "path": "Device.ManagementServer.ScheduleReboot", "value": "2024-08-23T23:59:59Z", "datatype": "dateTime" }
```

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
ubus call bbf set {"path":"occaecat veniam consequa","value":"et Excepteur occaecat fugiat","datatype":"dateTime","obj_path":{}}
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
      "path": "occaecat veniam consequa",
      "value": "et Excepteur occaecat fugiat",
      "datatype": "dateTime",
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
{ "results": [{ "path": "cillum Ut laborum proident", "data": "0", "fault": 7277, "fault_msg": "dolore ut aliquip" }] }
```
