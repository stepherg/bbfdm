# Wireless configuration using TR-181

The purpose of this document is to explain the TR181 datamodel parameters handling/mapping for the wireless configuration.

Before TR181 - v2.13, wifi configuration was modeled for a single device and managed with following objects

- WiFi.Radio.
  - maps to actual wireless radios present in the system, which is driven from 'config wifi-device' uci sections of wireless uci
- WiFi.SSID.
  - Provides SSID related configuration, which is driven from 'config wifi-iface' uci sections of wireless uci, with 'option mode' set as 'ap'
- WiFi.AccessPoint.
  - Provides Access related configuration for a SSID, this maps 1-to-1 with SSID mapped 'config wifi-iface' section of wireless uci
- WiFi.EndPoint.
  - Used to manage/define STA(s) in the system, maps to 'config wifi-iface' uci section of wireless uci, with 'option mode' set as 'sta'


With TR181 - 2.14, it also provides a way to configure/manage easy-mesh controller, with the help of 'Device.WiFi.DataElements.' object.
So, now it is possible to manage/optimize wifi network configuration on a easymesh network devices including self node.

More information about easymesh available in this [link](https://www.wi-fi.org/discover-wi-fi/specifications)

## Uci examples

Example wireless uci
```bash
config wifi-device 'wl0'
        option type 'mac80211'
        option channel 'auto'
        option band '5g'
        option country 'DE'
        option htmode 'HE80'
        option apsta '0
        option phy 'phy0'

config wifi-iface 'default_wl0'
        option device 'wl0'
        option network 'lan'
        option mode 'ap'
        option ifname 'wl0'
        option ssid 'test'
        option uuid 'd3d3e3e6-e5de-4453-9483-44D43771B500'
        option key 'VGVQOB2WX3E5OU'
        option wps '1'
        option wps_pushbutton '1'
        option ieee80211k '1'
        option ieee80211v '1'
        option bss_transition '1'
        option multicast_to_unicast '1'
        option multi_ap '2'
        option encryption 'sae-mixed'
        option ieee80211w '1'
        option mbo '1'
        option wps_device_type '6-0050f204-1'
        option isolate '0'
        option disabled '0'
        option multi_ap_backhaul_ssid 'MAP-44D43771B500-BH-5GHz'
        option multi_ap_backhaul_key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'

config wifi-device 'wl1'
        option type 'mac80211'
        option channel 'auto'
        option band '2g'
        option country 'DE'
        option htmode 'HE20'
        option apsta '0'
        option phy 'phy1'

config wifi-iface 'default_wl1'
        option device 'wl1'
        option network 'lan'
        option mode 'ap'
        option ifname 'wl1'
        option ssid 'iopsysWrt-44D43771B500'
        option uuid 'd3d3e3e6-e5de-4453-9483-44D43771B500'
        option key 'VGVQOB2WX3E5OU'
        option wps '1'
        option wps_pushbutton '1'
        option ieee80211k '1'
        option ieee80211v '1'
        option bss_transition '1'
        option multicast_to_unicast '1'
        option multi_ap '2'
        option encryption 'sae-mixed'
        option ieee80211w '1'
        option mbo '1'
        option wps_device_type '6-0050f204-1'
        option isolate '0'
        option disabled '0'
        option multi_ap_backhaul_ssid 'MAP-44D43771B500-BH-2.4GHz'
        option multi_ap_backhaul_key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'

config wifi-iface 'wl0_1_ap'
        option ifname 'wl0.1'
        option ieee80211k '1'
        option bss_transition '1'
        option uuid 'd3d3e3e6-e5de-4453-9483-44D43771B500'
        option hidden '1'
        option network 'lan'
        option ssid 'MAP-44D43771B500-BH-5GHz'
        option key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'
        option encryption 'sae'
        option mode 'ap'
        option device 'wl0'
        option multi_ap '1'
        option ieee80211w '2'
        option mbo '1'
        option multicast_to_unicast '0'
        option isolate '0'
        option disabled '0'

config wifi-iface 'wl1_1_ap'
        option ifname 'wl1.1'
        option ieee80211k '1'
        option bss_transition '1'
        option uuid 'd3d3e3e6-e5de-4453-9483-44D43771B500'
        option hidden '1'
        option network 'lan'
        option ssid 'MAP-44D43771B500-BH-2.4GHz'
        option key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'
        option encryption 'sae'
        option mode 'ap'
        option device 'wl1'
        option multi_ap '1'
        option ieee80211w '2'
        option mbo '1'
        option multicast_to_unicast '0'
        option isolate '0'
        option disabled '0'
```

Example map-controller uci

```bash
config controller 'controller'
        option enabled '1'
        option profile '4'
        option registrar '2 5 6'
        option debug '0'
        option bcn_metrics_max_num '10'
        option initial_channel_scan '0'
        option enable_ts '0'
        option primary_vid '1'
        option primary_pcp '0'
        option allow_bgdfs '0'
        option channel_plan '0'
        option de_collect_interval '60'

config sta_steering
        option steer_module 'rcpi'
        option enabled '1'
        option enable_sta_steer '0'
        option enable_bsta_steer '0'
        option use_bcn_metrics '0'
        option use_usta_metrics '0'
        option bandsteer '0'
        option diffsnr '8'
        option rcpi_threshold_2g '70'
        option rcpi_threshold_5g '86'
        option rcpi_threshold_6g '86'
        option report_rcpi_threshold_2g '80'
        option report_rcpi_threshold_5g '96'
        option report_rcpi_threshold_6g '96'

config ap
        option band '2'
        option ssid 'iopsysWrt-44D43771B500'
        option encryption 'sae-mixed'
        option key 'VGVQOB2WX3E5OU'
        option vid '1'
        option type 'fronthaul'

config ap
        option band '5'
        option ssid 'iopsysWrt-44D43771B500'
        option encryption 'sae-mixed'
        option key 'VGVQOB2WX3E5OU'
        option vid '1'
        option type 'fronthaul'

config ap
        option band '6'
        option ssid 'iopsysWrt-44D43771B500'
        option encryption 'sae'
        option key 'VGVQOB2WX3E5OU'
        option vid '1'
        option type 'fronthaul'

config ap
        option band '2'
        option ssid 'MAP-44D43771B500-BH-2.4GHz'
        option encryption 'sae'
        option key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'
        option type 'backhaul'
        option vid '1'

config ap
        option band '5'
        option ssid 'MAP-44D43771B500-BH-5GHz'
        option encryption 'sae'
        option key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'
        option type 'backhaul'
        option vid '1'

config ap
        option band '6'
        option ssid 'MAP-44D43771B500-BH-6GHz'
        option encryption 'sae'
        option key '4e89e7a73ce54d765d48c61bd2cf82e18a807e7b1f231456663836b2641c8bf'
        option type 'backhaul'
        option vid '1'

config node 'node_46d43771b500'
        option agent_id '46:d4:37:71:b5:00'

config radio 'radio_44d43771b50f'
        option agent_id '46:d4:37:71:b5:00'
        option macaddr '44:d4:37:71:b5:0f'
        option band '5'

config radio 'radio_44d43771b50e'
        option agent_id '46:d4:37:71:b5:00'
        option macaddr '44:d4:37:71:b5:0e'
        option band '2'

config node 'node_46d43771b410'
        option agent_id '46:d4:37:71:b4:10'

config radio 'radio_44d43771b41f'
        option agent_id '46:d4:37:71:b4:10'
        option macaddr '44:d4:37:71:b4:1f'
        option band '5'

config radio 'radio_44d43771b41e'
        option agent_id '46:d4:37:71:b4:10'
        option macaddr '44:d4:37:71:b4:1e'
        option band '2'
```

# Ambiguity in self node management
Now, with the inclusion of 'DataElement', we have two control points to manage the SSID and AccessPoint related configurations, either with
 - WiFi.DataElements., or
 - WiFi.SSID./WiFi.AccessPoint.


TR181 definition for WiFi management does not address this ambiguity and its bit open for the Easymesh enabled cpe.

To simplify the same in our implementation, 
 - WiFi.SSID./WiFi.AccessPoint. objects maps 1-to-1 with wireless uci, which means it shows non-multi-ap access-points, fronthaul-access-points and backhaul-access-points
 - Any updates done using WiFi.SSID./WiFi.AccessPoint. objects specifically in SSID, Password, EncryptionType and Enable parameters also propagated to `mapcontroller` uci as well in case of Easymesh device for 'multi_ap' access-points.

> Note: If 'multi_ap' option is defined in wireless uci and its corresponding section not present in `mapcontroller` uci, then an error will be returned when the user tries to modify any configuration for those wireless access-point.

# Easymesh management from TR181
'Device.WiFi.DataElements.' table used for managing Easymesh nodes, regardless of if the node is self node or a remote network node, the management ownership owned by easy-mesh controller.

Easymesh controller provides an ubus object to show the current/active configuration, and an uci to configure the input parameters.

Any configuration update in easymesh uci might take some time to apply the same in network, and to update it in the ubus object output.
So, datamodel parameters which maps to 'WiFi.DataElements.' table might also show the old values until the configuration not propagated to the network node by easymesh controller.

> Note: To verify the new configuration, either user can wait for a significant time before getting the datamodel and verify the configuration, or they can subscribe for ValueChange notification with a max timeout to handler the same.
