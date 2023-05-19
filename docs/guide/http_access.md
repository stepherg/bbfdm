# Device.UserInterface.HTTPAccess
The backend of HTTPAccess datamodel has been implemented using nginx and nginx-util.
The parameters under `Device.UserInterface.` are mapped with the `userinterface` UCI parameters and `Device.UserInerface.HTTPAccess.` with `nginx` UCI parameters.

> Note: To enable `Device.UserInterface.` and `Device.UserInerface.HTTPAccess.` Datamodel object there must exist `/etc/config/userinerface` and `etc/config/nginx` respectively in the CPE, hence need to have `userinterface, nginx and nginx-util` packages in the build.

## Mapping between UCI and datamodel params
| Datamodel param                                         | UCI package   | UCI Section   | UCI param  |
|---------------------------------------------------------|---------------|---------------|------------|
| Device.UserInerface.Enable                              | userinterface | userinterface | enable     |
| Device.UserInterface.HTTPAccess.{i}.Port                | nginx         | server        | listen     |
| Device.UserInterface.HTTPAccess.{i}.AllowedPathPrefixes | nginx         | server        | root       |
| Device.UserInterface.HTTPAccess.{i}.AllowedHosts        | nginx         | server        | include    |

> Note: There are a few datamodel parameters which either has no direct mapping with nginx UCI standard parameter or not supported in nginx. Some of such parameters are handled using non standard UCI params and dmmap file.

## Non standard and dmmap file supported params
| Datamodel param                                         | UCI package   | UCI Section   | UCI param      |
|---------------------------------------------------------|---------------|---------------|----------------|
| Device.UserInterface.HTTPAccess.{i}.Enable              | nginx         | server        | uci_enable     |
| Device.UserInterface.HTTPAccess.{i}.AccessType          | nginx         | server        | uci_access     |
| Device.UserInterface.HTTPAccess.{i}.Interface           | nginx         | server        | uci_interface  |
| Device.UserInterface.HTTPAccess.{i}.ActivationDate      | dmmap_nginx   | server        | activationdate |
| Device.UserInterface.HTTPAccess.{i}.Alias               | dmmap_nginx   | server        | server_alias   |

## How to enable remote access of any server
To enable remote access of any server instance it is needed to set the `Device.UserInterface.HTTPAccess.{i}.AccessType` to `RemoteAccess`.
Along with the `AccessType` it is also required to set the `Device.UserInterface.HTTPAccess.{i}.Interface` with the specific `Device.IP.Interface.` instance on which the server will listen for remote connection.

## Port configuration
For port configuration it should be considered that each enabled server instance must have assigned a unique port number.

