# Utilities to support datamodel deployments

This directory has sets of small utilities to ease the datamodel deployments and integration with higher layer application protocols.

List of utilities:

1. bbf.diag
2. bbf.secure
3. bbf.config

## bbf.diag utility

`bbf.diag` is a `rpcd` libexec based utility, which is responsible for providing ubus backend to few datamodel diagnostics commands like:

- ipping
- nslookup
- serverselection
- udpecho

### How to add a new bbf.diag utility

To add a new bbf.diag utility user has to add an script with below syntax

```bash
#!/bin/sh

. /usr/share/libubox/jshn.sh
. /usr/share/bbfdm/scripts/bbf_api

__list() {
        json_add_object "test"
        json_add_string "host" "str"
        json_close_object
}

__error() {
        json_init
        json_add_string "Status" "$1"
}

__launch() {
        json_init
        json_add_string "Status" "$1"
}

if [ "$1" = "list" ]; then
        __list
elif [ -n "$1" ]; then
        __launch "$1"
else
        __error "Error_Internal" "1"
fi
```

User needs to install this newly added script using `BBFDM_INSTALL_SCRIPT` bbfdm.mk API.

References:
- [Diagnostics Scripts](https://dev.iopsys.eu/bbf/tr143d/-/tree/devel/scripts/bbf_diag)
- [Installation](https://dev.iopsys.eu/feed/iopsys/-/blob/devel/tr143/Makefile)


## bbf.secure utility

USP[TR369 Specifications](https://usp.technology/specification/index.html#sec:special-roles) requirement of 'SecuredRole' requires bbfdm layer to retrieve and provide the Secured(Password/key) parameter values in plain text.

But storing Secured parameters in plain text in uci/filesystem is bit of a security risk, to mitigate the risk `bbf.secure` provides way to store the Secured parameter values in hashed format.

A how to use guide for bbf.secure available [here](https://dev.iopsys.eu/feed/iopsys/-/tree/devel/bbfdm?ref_type=heads#bbf_obfuscation_key)

## bbf.config utility

OpenWRT way of reloading services with `ubus call uci commit '{"name":"<uci_name>"}` does not perfectly fits with datamodel requirements. It send a trigger via rpcd to procd by using this ubus call which returns instantly, internally procd reloads for all the services which has a reload dependency configured on that specific uci.
Sometimes, there is a good amount of delay in trigger and actual service reload.

Bbf.config solves that by adding an in-build reload monitoring functionality which get the list of impacted services and then monitor for PID change for the services with a timeout of 10 sec, with this we make sure Higher layer application(icwmp/obsupa) waits for the application before processing more command.

Currently have two variants of bbf.config, which can be enabled with below compile time configs

1. CONFIG_BBF_CONFIGMNGR_SCRIPT_BACKEND => Simple rpcd script based backend
2. CONFIG_BBF_CONFIGMNGR_C_BACKEND => C based application backend with PID monitoring (default)

### bbf.config Supported methods

`bbf.config` provides several methods for managing and monitoring configuration changes in services. These methods can be accessed using the ubus command.

```bash
$ ubus -v list bbf.config
'bbf.config' @da2cc0d9
        "commit":{"services":"Array","proto":"String","reload":"Boolean"}
        "revert":{"services":"Array","proto":"String","reload":"Boolean"}
        "changes":{"services":"Array","proto":"String","reload":"Boolean"}
```
#### bbf.config commit method: 

This method commits configuration changes to the specified services based on the given `proto` option (protocol). It reloads services according to `reload` option but handles critical services differently.

The Critical services are defined in `/etc/bbfdm/critical_services.json` file.
- If a service is critical, the process waits until the service's timeout expires or the service's PID changes and then it does reload the service.
- Non-critical services are reloaded immediately.

Critical Services File

The following file defines critical services for each protocol:

```bash
cat /etc/bbfdm/critical_services.json 
{
        "usp": [
                        "firewall",
                        "network",
                        "dhcp",
                        "wireless",
                        "time"
        ],
        "cwmp": [
                        "firewall",
                        "network",
                        "dhcp",
                        "stunc",
                        "xmpp",
                        "wireless",
                        "time"
        ]
}
```

#### bbf.config revert method: 
this method commits the changes in the required services based on proto option.

#### bbf.config changes method: 

this method provides the list of certical services based on protocol (proto option) and provide the available config changes based on protocol.  
```bash
ubus call bbf.config changes '{"proto":"usp"}'
{
        "configs": [
                "users",
                "wireless"
        ],
        "critical_services": [
                "firewall",
                "network",
                "dhcp",
                "wireless",
                "time"
        ]
}
```
