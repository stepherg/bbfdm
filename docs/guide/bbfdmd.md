# BBFDM Daemon (`bbfdmd`)

`bbfdmd` daemon creates a data model layer between system resources and exposes TR-181 data model objects over `ubus` for higher-layer application protocols such as [TR-069/CWMP](https://cwmp-data-models.broadband-forum.org/) or [TR-369/USP](https://usp.technology/).

> **Note:** The command outputs shown in this document are examples. The actual output may vary depending on the device and configuration.

---

## Concepts and Workflow

`bbfdmd` daemon collects data models from various microservices and exposes them over `ubus`. It does not handle the data model internally or validate its existence.

### Initialization

1. The `bbfdmd` daemon is started by the `/etc/init.d/bbfdmd` service.
2. During startup, it registers all available microservices listed under `/etc/bbfdm/service/` by parsing each JSON file to extract information such as:
   - `service_name`
   - Data model paths exposed by the service
   - Protocol visibility (CWMP or USP)
3. After processing the JSON files, it registers the supported `bbfdm` ubus methods.

### Handling Ubus Calls

When a `bbfdm` ubus object is called, the daemon determines the handling type based on the ubus method:

- **Asynchronous methods** (`get`, `schema`, `instances`, `operate`)  
   These methods are executed asynchronously to collect data model output from multiple microservices simultaneously.

- **Synchronous methods** (`set`, `add`, `delete`)  
   These methods are executed synchronously because they only target a specific microservice.

### Microservice Identification

To identify which microservice to call, `bbfdm`:
- Extracts the requested path from the `"path"` input.
- Retrieves the protocol from `"optional.proto"` input.
- Matches the extracted path and protocol against the list of registered services.

---

## Example Configuration

```json
{
  "daemon": {
    "enable": "1",
    "service_name": "dhcpmngr",
    "unified_daemon": false,
    "services": [
      {
        "parent_dm": "Device.",
        "object": "DHCPv4"
      },
      {
        "parent_dm": "Device.",
        "object": "DHCPv6"
      }
    ],
    "config": {
      "loglevel": "3"
    }
  }
}
```

### Explanation

- **service_name** → `dhcpmngr` → `ubus` service name is `bbfdm.dhcpmngr`  
- **Data model paths** → `Device.DHCPv4.` and `Device.DHCPv6.`  
- **Protocol** → Both CWMP and USP since no restriction is defined in the JSON file.  

Any call to `bbfdm` with the path `Device.DHCPv4.XXXX` or `Device.DHCPv6.XXXX` will be directed to the `dhcpmngr` microservice.

> **Note:** `bbfdmd` does not automatically reload services after updating the configuration. Higher-layer applications (e.g., `icwmp`, `obuspa`) use `bbf.config` to apply updates and reload services.

---

## Input and Output Schema

### Configuration
- `bbfdmd` configuration can be updated using `uci`:
   - [bbfdm uci guide](../api/uci/bbfdm.md)  
   - [bbfdm uci schema](../api/uci/bbfdm.json)  

### Ubus Schema
- `bbfdmd` exposes a detailed schema for ubus methods:
   - [bbfdm ubus guide](../api/ubus/bbfdm.md)  
   - [bbfdm ubus schema](../api/ubus/bbfdm.json)  

---

## Ubus Methods

### Available Methods

```bash
# ubus -v list bbfdm
'bbfdm' @7971a201
    "get":{"path":"String","value":"String","optional":"Table"}
    "schema":{"path":"String","value":"String","optional":"Table"}
    "instances":{"path":"String","value":"String","optional":"Table"}
    "operate":{"path":"String","value":"String","optional":"Table"}
    "set":{"path":"String","value":"String","optional":"Table"}
    "add":{"path":"String","value":"String","optional":"Table"}
    "del":{"path":"String","value":"String","optional":"Table"}
    "services":{}
```

### `optional` Table Options

```json
"optional": {"proto": "String", "format": "String"}
```

- **proto** → Specifies the data model protocol (`cwmp`, `usp`). Defaults to the standard model if not provided.  
- **format** → Specifies the output format (`raw`, `pretty`). Defaults to `pretty` if not provided.  

> **Note:** See the ubus schema document for more details.

---

## Debugging Tools

### Command Line Interface (CLI)

`bbfdmd` provides a CLI to debug the data model using the `-c` option:

```bash
# bbfdmd -h
Usage: bbfdmd [options]

Options:
  -c <command input>  Run CLI command
  -l <loglevel>       Log verbosity value (0-7) as per syslog
  -h                  Displays this help
```

If no options are provided, `bbfdmd` starts in daemon mode.

### CLI Commands

```bash
# bbfdmd -c help
Valid commands:
   help
   get [path-expr]
   set [path-expr] [value]
   add [object]
   del [path-expr]
   instances [path-expr]
   schema [path-expr]
```

### Debugging Logs

To enable debugging logs, use the following macros:

```c
BBFDM_ERR(MESSAGE, ...)
BBFDM_WARNING(MESSAGE, ...)
BBFDM_INFO(MESSAGE, ...)
BBFDM_DEBUG(MESSAGE, ...)
```

Logs are written to `syslog` based on the `log_level` defined in the `bbfdm` configuration.  
To configure the log level, use the `bbfdm.bbfdmd.loglevel` option.

---

## Notes

1. `bbfdmd` does not handle RPC method output.  
2. The actual arguments expected by `bbfdmd` may differ from the ones shown in the ubus schema because `bbfdmd` only routes the calls to the correct microservice.  

---

