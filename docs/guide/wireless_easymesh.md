# Wireless configuration using TR-181

The purpose of this document is to explain the datamodel handling/mapping for the wireless configuration using data model parameters.

Currently in a CPE, wireless configuration can be managed using TR-181 or if the CPE is Easymesh capable then its managed by multi-ap-controller present in the network. As per TR-181 Easymesh network represented by 'Device.WiFi.DataElements.' datamodel object, whereas standalone wireless parameters available in 'Device.WiFi.{SSID,AccessPoint,Radio,EndPoint}' datamodel objects.

Easymesh multi-ap-controller configuration stored in `mapcontroller` uci, but it also configures the same wireless uci which is used by standalone wireless datamodel object. The Easymesh wireless access-point configuration can easily be identified as they have a additional uci option called 'multi_ap', this uci option defines the fronthaul/backhaul behaviour for the access-point.

TR-181 wifi definition bit open for the Easymesh enabled cpe, to simplify the same in our implementation, Wifi standalone objects maps 1-to-1 with wireless uci, so they will show non-multi-ap access-points, fronthaul-access-points and backhaul-access-points. Any update using standalone wireless objects specifically in SSID, Password, EncryptionType and Enable parameters automatically synced by datamodel in `mapcontroller` uci as well in case of Easymesh device for 'multi_ap' access-points.

> Note: If 'multi_ap' option is defined in wireless uci and its corresponding section not present in `mapcontroller` uci, then an error will be returned when the user tries to modify any configuration for those wireless access-point.
