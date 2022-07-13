# dmtest Schema

```
https://dev.iopsys.eu/iopsys/uspd/-/blob/devel/docs/api/dmtest.json
```

| Custom Properties | Additional Properties |
| ----------------- | --------------------- |
| Forbidden         | Forbidden             |

# dmtest

| List of Methods                           |
| ----------------------------------------- |
| [add_object](#add_object)                 | Method | dmtest (this schema) |
| [del_object](#del_object)                 | Method | dmtest (this schema) |
| [get](#get)                               | Method | dmtest (this schema) |
| [get_supported_dm](#get_supported_dm)     | Method | dmtest (this schema) |
| [operate](#operate)                       | Method | dmtest (this schema) |
| [set](#set)                               | Method | dmtest (this schema) |
| [transaction_abort](#transaction_abort)   | Method | dmtest (this schema) |
| [transaction_commit](#transaction_commit) | Method | dmtest (this schema) |
| [transaction_start](#transaction_start)   | Method | dmtest (this schema) |

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
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property | Type   | Required     | Default  |
| -------- | ------ | ------------ | -------- |
| `path`   | string | **Required** |          |
| `proto`  | string | Optional     | `"both"` |

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
ubus call dmtest add_object {"path":"Lorem aliqua laboris","proto":"cwmp"}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "dmtest", "add_object", { "path": "Lorem aliqua laboris", "proto": "cwmp" }]
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
      "required": ["parameters"],
      "properties": {
        "parameters": {
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
  "out": "{\"oneof\":[{\"fault\":7961},{\"parameters\":[{\"parameter\":\"aliquip ut laborum tempor\",\"status\":true,\"fault\":7103,\"instance\":\"a\"}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 7961 },
    { "parameters": [{ "parameter": "aliquip ut laborum tempor", "status": true, "fault": 7103, "instance": "a" }] }
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
| `output` |        | **Required** |

#### input

`input`

- is **required**
- type: `object`

##### input Type

`object` with following properties:

| Property | Type   | Required     | Default  |
| -------- | ------ | ------------ | -------- |
| `path`   | string | **Required** |          |
| `proto`  | string | Optional     | `"both"` |

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

The value of this property **must** be equal to one of the [known values below](#del_object-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call dmtest del_object {"path":"ut officia pariatur","proto":"cwmp"}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "dmtest", "del_object", { "path": "ut officia pariatur", "proto": "cwmp" }]
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
      "required": ["parameters"],
      "properties": {
        "parameters": {
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
  "out": "{\"oneof\":[{\"fault\":7423},{\"parameters\":[{\"parameter\":\"laborum consequat elit in\",\"status\":true,\"fault\":8381}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 7423 },
    { "parameters": [{ "parameter": "laborum consequat elit in", "status": true, "fault": 8381 }] }
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

| Property | Type   | Required     | Default  |
| -------- | ------ | ------------ | -------- |
| `path`   | string | **Required** |          |
| `proto`  | string | Optional     | `"both"` |

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

The value of this property **must** be equal to one of the [known values below](#get-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

### Ubus CLI Example

```
ubus call dmtest get {"path":"elit in dolore enim culpa","proto":"both"}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "dmtest", "get", { "path": "elit in dolore enim culpa", "proto": "both" }]
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
  "out": "{\"oneof\":[{\"fault\":8800},{\"parameters\":[{\"parameter\":\"cupidatat\",\"value\":\"dolor in pariatur\",\"type\":\"xsd:event\"}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 8800 },
    { "parameters": [{ "parameter": "cupidatat", "value": "dolor in pariatur", "type": "xsd:event" }] }
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

| Property      | Type    | Required | Default  |
| ------------- | ------- | -------- | -------- |
| `next-level`  | boolean | Optional |          |
| `path`        | string  | Optional |          |
| `proto`       | string  | Optional | `"both"` |
| `schema_type` | integer | Optional |          |

#### next-level

gets only next level objects if true

`next-level`

- is optional
- type: `boolean`

##### next-level Type

`boolean`

#### path

Complete object element path as per TR181

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

The value of this property **must** be equal to one of the [known values below](#get_supported_dm-known-values).

##### proto Known Values

| Value |
| ----- |
| usp   |
| cwmp  |
| both  |

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
ubus call dmtest get_supported_dm {"path":"ut nostrud do e","proto":"usp","next-level":false,"schema_type":2}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": [
    "<SID>",
    "dmtest",
    "get_supported_dm",
    { "path": "ut nostrud do e", "proto": "usp", "next-level": false, "schema_type": 2 }
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
  "out": "{\"oneof\":[{\"fault\":8801},{\"parameters\":[{\"parameter\":\"qui irure au\",\"type\":\"xsd:dateTime\",\"writable\":\"1\",\"cmd_type\":\"async\",\"in\":[\"ipsum occaecat labore Ut\"],\"out\":[\"Excepteur dolore cupidatat aliquip\"]}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "fault": 8801 },
    {
      "parameters": [
        {
          "parameter": "qui irure au",
          "type": "xsd:dateTime",
          "writable": "1",
          "cmd_type": "async",
          "in": ["ipsum occaecat labore Ut"],
          "out": ["Excepteur dolore cupidatat aliquip"]
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

| Property | Type   | Required     |
| -------- | ------ | ------------ |
| `input`  | object | Optional     |
| `path`   | string | **Required** |

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
Device.DHCPv4.Client.{i}.Renew()
```

```json
Device.FactoryReset()
```

### Ubus CLI Example

```
ubus call dmtest operate {"path":"nonesse nostrud anim","input":{}}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "dmtest", "operate", { "path": "nonesse nostrud anim", "input": {} }]
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
      "path": "velit sit veniam magna et",
      "parameters": [
        { "parameter": "ullamco Duis do eiusmod eu", "value": "aute velit sit", "type": "xsd:event", "fault": 7524 }
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

| Property | Type   | Required     | Default  |
| -------- | ------ | ------------ | -------- |
| `path`   | string | **Required** |          |
| `proto`  | string | Optional     | `"both"` |
| `value`  | string | **Required** |          |

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

### Ubus CLI Example

```
ubus call dmtest set {"path":"ea consecte","value":"et ipsum velit","proto":"both"}
```

### JSONRPC Example

```json
{
  "jsonrpc": "2.0",
  "id": 0,
  "method": "call",
  "params": ["<SID>", "dmtest", "set", { "path": "ea consecte", "value": "et ipsum velit", "proto": "both" }]
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
      "fault": {
        "$ref": "#/definitions/fault_t",
        "Description": "Any discrepancy in input will result in fault. The type of fault can be identified by fault code"
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
  "out": "{\"oneof\":[{\"status\":\"1\"},{\"fault\":7434},{\"parameters\":[{\"parameter\":\"consequat in et cillum voluptate\",\"status\":true,\"fault\":7297}]}],\"definitions\":{\"path_t\":{\"description\":\"Complete object element path as per TR181\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.1.\",\"Device.WiFi.\"]},\"schema_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.Bridging.Bridge.{i}.\",\"Device.DeviceInfo.Manufacturer\",\"Device.WiFi.SSID.{i}.SSID\"]},\"boolean_t\":{\"type\":\"string\",\"enum\":[\"0\",\"1\"]},\"operate_path_t\":{\"description\":\"Datamodel object schema path\",\"type\":\"string\",\"minLength\":6,\"maxLength\":1024,\"examples\":[\"Device.DHCPv4.Client.{i}.Renew()\",\"Device.FactoryReset()\"]},\"operate_type_t\":{\"type\":\"string\",\"enum\":[\"async\",\"sync\"]},\"instance_t\":{\"description\":\"Multi object instances\",\"type\":\"string\",\"minLength\":6,\"maxLength\":256},\"proto_t\":{\"type\":\"string\",\"default\":\"both\",\"enum\":[\"usp\",\"cwmp\",\"both\"]},\"type_t\":{\"type\":\"string\",\"enum\":[\"xsd:string\",\"xsd:unsignedInt\",\"xsd:int\",\"xsd:unsignedLong\",\"xsd:long\",\"xsd:boolean\",\"xsd:dateTime\",\"xsd:hexBinary\",\"xsd:object\",\"xsd:command\",\"xsd:event\"]},\"fault_t\":{\"type\":\"integer\",\"minimum\":7000,\"maximum\":9050}}}",
  "simpletype": "complex"
}
```

### Output Example

```json
{
  "oneof": [
    { "status": "1" },
    { "fault": 7434 },
    { "parameters": [{ "parameter": "consequat in et cillum voluptate", "status": true, "fault": 7297 }] }
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

## transaction_abort

### Aborts an on-going transaction

`transaction_abort`

- type: `Method`

### transaction_abort Type

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
ubus call dmtest transaction_abort {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "dmtest", "transaction_abort", {}] }
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property | Type    | Required     |
| -------- | ------- | ------------ |
| `status` | boolean | **Required** |

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{ "status": true }
```

## transaction_commit

### Commits an on-going transaction

`transaction_commit`

- type: `Method`

### transaction_commit Type

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
ubus call dmtest transaction_commit {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "dmtest", "transaction_commit", {}] }
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property | Type    | Required     |
| -------- | ------- | ------------ |
| `status` | boolean | **Required** |

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{ "status": false }
```

## transaction_start

### Start a transaction before set/add/del operations

`transaction_start`

- type: `Method`

### transaction_start Type

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
ubus call dmtest transaction_start {}
```

### JSONRPC Example

```json
{ "jsonrpc": "2.0", "id": 0, "method": "call", "params": ["<SID>", "dmtest", "transaction_start", {}] }
```

#### output

`output`

- is **required**
- type: `object`

##### output Type

`object` with following properties:

| Property | Type    | Required     |
| -------- | ------- | ------------ |
| `status` | boolean | **Required** |

#### status

`status`

- is **required**
- type: `boolean`

##### status Type

`boolean`

### Output Example

```json
{ "status": false }
```
