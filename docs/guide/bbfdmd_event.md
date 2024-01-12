# Monitoring Events in the Data Model

`bbfdmd` now supports monitoring events directly from the Data Model, eliminating the need for internal registration and handling within `bbfdmd`.

# How to add an new event

- Insert the event into the required `DMLEAF` table

- Ensure that `leaf_type` is defined as `DMT_EVENT` and `bbfdm_type` as `BBFDM_USP`

- Implement the get/set event API

# How it works

Upon starting `bbfdmd`, it calls `bbf_entry_method` API with `BBF_SCHEMA` method to retrieve all events supported by Data Model. Subsequently, it attempts to register an event handler for each event by using the event name argument defined in each event leaf and then listens for that event name.

When the event name is triggered, `bbfdmd` calls `bbf_entry_method` API with `BBF_EVENT` method to perform the event operation. And finally, it sends `bbfdm.event` ubus event with the required input information obtained from the returned event operation.

# Event Example 

Below is an example of `Device.WiFi.DataElements.AssociationEvent.Associated!` event implementation:

static event_args wifidataelementsassociationevent_associated_args = {
	.name = "wifi.dataelements.Associated",
    .param = (const char *[]) {
        "type",
        "version",
        "protocols",
        "BSSID",
        "MACAddress",
        "StatusCode",
        "HTCapabilities",
        "VHTCapabilities",
        "HECapabilities",
        "TimeStamp",
        NULL
    }
};

static int get_event_args_WiFiDataElementsAssociationEvent_Associated(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
    *value = (char *)&wifidataelementsassociationevent_associated_args;
    return 0;
}

static int event_WiFiDataElementsAssociationEvent_Associated(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *event_time = dmjson_get_value((json_object *)value, 1, "eventTime");
	char *bssid = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent.AssocData", "DisassocData", "BSSID");
	char *mac_addr = dmjson_get_value((json_object *)value, 3, "wfa-dataelements:AssociationEvent.AssocData", "DisassocData", "MACAddress");
	
	add_list_parameter(ctx, dmstrdup("TimeStamp"), dmstrdup(event_time), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("BSSID"), dmstrdup(bssid), DMT_TYPE[DMT_STRING], NULL);
	add_list_parameter(ctx, dmstrdup("MACAddress"), dmstrdup(mac_addr), DMT_TYPE[DMT_STRING], NULL);

    return 0;
}

DMLEAF tWiFiDataElementsAssociationEventParams[] = {
/* PARAM, permission, type, getvalue, setvalue, bbfdm_type*/
{"Associated!", &DMREAD, DMT_EVENT, get_event_args_WiFiDataElementsAssociationEvent_Associated, event_WiFiDataElementsAssociationEvent_Associated, BBFDM_USP},
{0}
};