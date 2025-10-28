# How to extend datamodel

Although `bbfdm/iowrt` provides datamodels for major services, but still for deployment user might need to add some vendor extensions or needs to add the missing datamodel support. To do the same `bbfdm.XXXX` or more precisely `libbfdm-api/legacy` provides the infrastructure to easily define a new datamodel tree.

As per TR106 description, a datamodel is, "A hierarchical set of Objects, Parameters, Commands and/or Events that define the managed Objects accessible via a particular Agent."

Please check [TR106](https://www.broadband-forum.org/pdfs/tr-106-1-13-0.pdf) for more details about datamodel terminology.

`bbfdm` provide the tools and utilities to further extend/overwrite/disable the datamodel using C-code or simply by using JSON datamodel definition.

## JSON datamodel

Pro:
 - Easy to add (compilation not required)
 - Least maintenance (Change in libbbfdm-api has minimal impact)

Con:
 - Can only support easy one to one mappings with uci and ubus
 - Invalid plugin syntax might cause faults

## C Based datamodel

Pro:
 - Support complex mapping and data sharing between nodes
 - Lots of references available
 - Tools available to auto-generate the template code
 - All core operations supported

Con:
 - Moderate maintenance (Change in libbbfdm-api requires adaptation/alignment)


Both ways of extending datamodel covered at length with examples in following links
* [How to extend datamodel with C Code](How_to_extend_datamodel_with_C_Code.md)
* [How to extend datamodel with JSON](How_to_extend_datamodel_with_JSON.md)

After creating the datamodel definition, it can be installed the help of `bbfdm.mk` APIs to run them from any specific micro-service instance or with a new micro-service.

> Note: If the new data model added for specific micro service, all datamodel extension need to be hanlded in the same micro-service. Like a wifi extension needed to be installed in wifidmd micro-service as a plugin.

# How to choose C or JSON for datamodel extensions

C/JSON both datamodel definition support defining all datamodel operations, but JSON should be used with simple datamodel deployments.

If its requires to perform more than one step to retrieve data from lowerlayer, it is suggested to use C-Based datamodel definitions, as it gives more control over the data and its mapping, or simply put if JSON plugin does not meets the requirement of datamodel mapping use C-Based definition.
