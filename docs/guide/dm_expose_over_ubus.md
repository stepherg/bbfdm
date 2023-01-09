# How to expose datamodel over ubus directly with the help of libbbf APIs

`Libbbf_ubus` is the library that helps in exposing the datamodel over ubus directly using libbbf_api.
Application using `libbbf_ubus`, shall not use the `libbbfdm` library because all needed operations from `libbbfdm` library has been internally handled in `libbbf_ubus`.

To identify the mechanism of exposing datamodel directly over ubus please refer to the sample code [dmtest.c](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/test/dynamicdm_ubus_test/bbf_ubus.c)

For more info you can see the schemas at:

- Raw schema [link](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/schemas/dmtest.json)
- Markdown schema [link](https://dev.iopsys.eu/iopsys/bbf/-/tree/devel/schemas/dmtest.md)

