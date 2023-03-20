# UCI Config

<tbody>
    <tr>
        <td colspan="2">
            <div style="font-weight: bold">uspd</div>
            <table style="width:100%">
                <tbody>
                    <tr>
                        <td>
                            <div style="font-weight: bold; font-size: 14px">section</div>
                        </td>
                        <td>
                            <div style="font-weight: bold; font-size: 14px">description</div>
                        </td>
                        <td>
                            <div style="font-weight: bold; font-size: 14px">multi</div>
                        </td>
                        <td>
                            <div style="font-weight: bold; font-size: 14px">options</div>
                        </td>
                    </tr>
                    <tr>
                        <td class="td_row_even">
                            <div class="td_row_even">uspd</div>
                        </td>
                        <td class="td_row_even">
                            <div class="td_row_even">USP daemon Settings</div>
                        </td>
                        <td class="td_row_even">
                            <div class="td_row_even">false</div>
                        </td>
                        <td class="td_row_even">
                            <table style="width:100%">
                                <tbody>
                                    <tr>
                                        <td>
                                            <div style="font-weight: bold; font-size: 14px">name</div>
                                        </td>
                                        <td>
                                            <div style="font-weight: bold; font-size: 14px">type</div>
                                        </td>
                                        <td>
                                            <div style="font-weight: bold; font-size: 14px">required</div>
                                        </td>
                                        <td>
                                            <div style="font-weight: bold; font-size: 14px">default</div>
                                        </td>
                                        <td>
                                            <div style="font-weight: bold; font-size: 14px">description</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">granularitylevel</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">integer</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">0</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">Creates ubus objects along with object names, depth of object name depends
                                                on granularitylevel</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">debug</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">boolean</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">no</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd"></div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">Enabled debug logging</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">sock</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">string</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even"></div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">Path for ubus socket to register uspd services</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">transaction_timeout</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">integer</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">no</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">10</div>
                                        </td>
                                        <td class="td_row_odd">
                                            <div class="td_row_odd">Transaction timeout value in seconds</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">loglevel</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">integer</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">1</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">Internal loglevel for debugging {0: No Logs; 1: Errors only; 2: Errors
                                                and warnings; 3: Error, warning and info; 4: Everything}</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">subprocess_level</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">integer</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">2</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">This parameter configures when subprocess can be used for get operation. Level here denotes the Datamodel object depth up-to which subprocess will be used to collect the get data. For example, if this is configured to 1, then only get for 'Device.' shall be called within the subprocess. If configured as level 2, then all the get with up-to depth 2 like 'Device.WiFi.', 'Device.IP.' shall be called in subprocess.</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">bbf_caching_time</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">integer</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">0</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">Max caching time in seconds for ubus output used in datamodel parameters. If not configured, output shall be cleared end the end of call.</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">dm_version</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">string</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even"></div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">Configures the datamodel version to use for datamodel parameters, if not configured show all defined datamodel</div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td class="td_row_even">
                                            <div class="td_row_even">refresh_time</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">integer</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">no</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">5</div>
                                        </td>
                                        <td class="td_row_even">
                                            <div class="td_row_even">The time period in seconds after which uspd will refresh the datamodel instances in a periodic manner. If configured to '0' then instance updater will be disabled. If not configured at all then after every 5 seconds datamodel instances will be refreshed.</div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </td>
                    </tr>
                </tbody>
            </table>
        </td>
    </tr>
</tbody>
