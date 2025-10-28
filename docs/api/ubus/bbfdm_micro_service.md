# bbf Schema

```
https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/docs/api/ubus/bbfdm.md
```

| Custom Properties | Additional Properties |
| ----------------- | --------------------- |
| Forbidden         | Forbidden             |

# bbf

| List of Methods         |
| ----------------------- |
| [add](#add)             | Method | bbf (this schema) |
| [del](#del)             | Method | bbf (this schema) |
| [get](#get)             | Method | bbf (this schema) |
| [instances](#instances) | Method | bbf (this schema) |
| [operate](#operate)     | Method | bbf (this schema) |
| [schema](#schema)       | Method | bbf (this schema) |
| [set](#set)             | Method | bbf (this schema) |

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
ubus call bbf add {"path":"eucommodo voluptate cillum","obj_path":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "add", { "path": "eucommodo voluptate cillum", "obj_path": {} }]
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
    {
      "path": "eiusmod consequ",
      "data": "adipisicing incidid",
      "fault": 8484,
      "fault_msg": "in labore nostrud voluptate est"
    }
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
ubus call bbf del {"path":"eiusmod c","paths":["utamet incididunt fugiat in labore"]}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "del", { "path": "eiusmod c", "paths": ["utamet incididunt fugiat in labore"] }]
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
      "path": "eiusmod ipsum",
      "data": "Lorem sunt laboris occaecat dolor",
      "fault": 7023,
      "fault_msg": "aute proident"
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

| Property   | Type   | Required     |
| ---------- | ------ | ------------ |
| `optional` | object | Optional     |
| `path`     | string | **Required** |

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

### Ubus CLI Example

```
ubus call bbf get {"path":"Lorem c","optional":{"format":"raw","proto":"both"}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "get", { "path": "Lorem c", "optional": { "format": "raw", "proto": "both" } }]
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
      "path": "eiusmod consectetu",
      "data": "laborum non",
      "type": "xsd:hexBinary",
      "fault": 7671,
      "fault_msg": "enim ea fugiat velit nulla"
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

| Property   | Type   | Required     |
| ---------- | ------ | ------------ |
| `optional` | object | Optional     |
| `path`     | string | **Required** |

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
ubus call bbf instances {"path":"sint culpa laborum","optional":{"proto":"usp"}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "bbf", "instances", { "path": "sint culpa laborum", "optional": { "proto": "usp" } }]
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
{ "results": [{ "path": "labore Lorem in", "fault": 8069, "fault_msg": "adipisicing non anim cupidatat amet" }] }
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
| `command_key` | string | Optional     |
| `input`       | object | Optional     |
| `optional`    | object | Optional     |
| `path`        | string | **Required** |

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

#### path

Datamodel object schema path

`path`

- is **required**
- type: reference

##### path Type

`string`

- minimum length: 6 characters
- maximum length: 1024 characters

##### path Examples

```json
Device.IP.Diagnostics.IPPing()
```

```json
Device.DHCPv4.Client.{i}.Renew()
```

```json
Device.FactoryReset()
```

### Ubus CLI Example

```
ubus call bbf operate {"path":"aliqua elit deserunt","command_key":"nostrud aute sed","input":{},"optional":{"format":"raw","proto":"cwmp"}}
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
      "path": "aliqua elit deserunt",
      "command_key": "nostrud aute sed",
      "input": {},
      "optional": { "format": "raw", "proto": "cwmp" }
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
      "path": "do cillum",
      "data": "1",
      "fault": 8145,
      "fault_msg": "velit irure dolore qui proident",
      "output": [{ "path": "labore", "data": "1", "type": "xsd:int" }]
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
| `first_level` | boolean | Optional |
| `optional`    | object  | Optional |
| `path`        | string  | Optional |

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

### Ubus CLI Example

```
ubus call bbf schema {"path":"eiusmod in nostrud Excepteur","first_level":false,"optional":{"proto":"usp"}}
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
    { "path": "eiusmod in nostrud Excepteur", "first_level": false, "optional": { "proto": "usp" } }
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
      "path": "id deserunt exer",
      "data": "1",
      "type": "xsd:string",
      "fault": 9040,
      "fault_msg": "velit",
      "input": [{ "path": "innostrud quis sit", "data": "0", "type": "xsd:string" }],
      "output": [{ "path": "sint quis aliqua", "data": "0", "type": "xsd:unsignedLong" }]
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
ubus call bbf set {"path":"aliquip consequat fugiat","value":"esse","datatype":"hexBinary","obj_path":{}}
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
    { "path": "aliquip consequat fugiat", "value": "esse", "datatype": "hexBinary", "obj_path": {} }
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
{ "results": [{ "path": "auteconsequat in", "data": "0", "fault": 8847, "fault_msg": "irure esse Lorem" }] }
```
