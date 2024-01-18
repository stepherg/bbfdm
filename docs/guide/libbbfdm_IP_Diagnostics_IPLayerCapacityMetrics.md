# How to test IPLayerCapicity
To test the IPLayerCapacity for uplink and downlink `obudpst` tool can be used. This is a client/server software utility to demonstrate one approach of doing IP capacity measurements.

## Usage for server mode
Before starting a IPLayerCapacity diagnostic it is needed to have a server to which the CPE will communicate.
So need to start the server on a host which is reachable from the CPE for a successful diagnostic result. Below is the command to start `obudpst` server.

```
root@asd:/#udpst -4 -v -D [ip]
```
| option | info                                                     |
|--------|----------------------------------------------------------|
| [ip]   | IP address of the interface on which server will listen  |
| -4     | Use IPv4 address family                                  |
| -v     | Verbose mode enable                                      |
| -D     | Enable debug logs                                        |


## How to start IPLayerCapacity diagnostic on CPE
For a minimal testing below are the parameters need to be configured on CPE.
- Device.IP.Diagnostics.IPLayerCapacityMetrics.Interface => Interface instance on which client will bind
- Device.IP.Diagnostics.IPLayerCapacityMetrics.Role => `Sender` for uplink `Receiver` for downlink test
- Device.IP.Diagnostics.IPLayerCapacityMetrics.Host => Server address

After setting the above parameters, need to set `Device.IP.Diagnostics.IPLayerCapacityMetrics.DiagnosticsState` to `Requested` for starting the test. 
Above test will produce incremental result if the test success. To check the status of the test just do get of `Device.IP.Diagnostics.IPLayerCapacityMetrics.DiagnosticsState`.
If test will succeed then to check the result do get of `Device.IP.Diagnostics.IPLayerCapacityMetrics.IncrementalResult.`.

### How to collect ModalResult
For running bimodal test, along with the above parameters an additional parameter `Device.IP.Diagnostics.IPLayerCapacityMetrics.NumberFirstModeTestSubIntervals` need to set with the value for e.g 2 (must be lower than `NumberTestSubInterval` parameter value, which is by default 10 and must be greater than 0). This parameter should be configured before starting the test.

To collect the bimodal test result, do get of `Device.IP.Diagnostics.IPLayerCapacityMetrics.ModalResult.`.

> Note: IPLayerCapacity test starts after the end of currently running CWMP session if the DiagnosticsState is set to `Requested`
