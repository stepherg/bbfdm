# Datamodel diagnostics and support tools

bbfdm offers several tools/utilities to facilitate(s)

- Generation of json based datamodel definition from broadband forum xml based definition
- Generation of "C" code templates based on json definition
- Generate xml definition of supported datamodel for Nokia HDM ACS
- Generate xml definition of supported datamodel for other ACS
- Generate list of supported data models in XML format for both USP and CWMP variants
- Provide tools to validate JSON based datamodel plugins

## Dependencies

Tools are mostly written in python and shell script, some requires docker images

- python3-pip
- libxml2-utils
- docker.io
- jsonschema
- xlwt
- ubus

System utilities: python3-pip, libxml2-utils docker.io

```bash
$ sudo apt install -y python3-pip
$ sudo apt install -y libxml2-utils
```

Python utilities: jsonschema, xlwt, ubus

```bash
$ pip3 install jsonschema xlwt ubus
```

To install docker follow [external link](https://docs.docker.com/engine/install)


## Tools

Below are the list of tools

| Tools                     | Description                                                  |
| ------------------------- | ------------------------------------------------------------ |
| convert_dm_xml_to_json.py | Tool to convert Broadband forum's xml based datamodel definition to JSON based datamodel Definition |
| convert_dm_json_to_c.py   | Tool to generate json based datamodel definition with ubus/uci mappings to C code |
| validate_json_plugin.py   | Validate json based datamodel plugin files |
| generate_dm.sh            | Generate list of supported/un-supported parameters based of json input|


### convert_dm_xml_to_json.py
[Broadband Forum](https://www.broadband-forum.org/) provides TR181 and other datamodel definitions in two formats xml(machine friendly) and html(User friendly),

- [CWMP Specific datamodels](https://cwmp-data-models.broadband-forum.org/#sec:current-data-models)
- [USP specific datamodels](https://usp-data-models.broadband-forum.org/#sec:current-data-models)

In bbfdm, we needed a unified file which can be used for machine translations as well as at the same time readable to humans, so we provide a this tools to convert Data Model from Broadband Forum XML format to JSON format.

This tools can be used as shown below

```bash
$ ./tools/convert_dm_xml_to_json.py
Usage: python convert_dm_xml_to_json -d <directory>
Options:
  -d, --directory <directory>: Directory containing XML files to convert to JSON
Example:
  ./tools/convert_dm_xml_to_json.py -d test/tools/
    ==> Generate the JSON file containing of all XML files defined under test/tools/ directory in datamodel.json

Example of xml data model file: https://www.broadband-forum.org/cwmp/tr-181-2-*-cwmp-full.xml
```

### convert_dm_json_to_c.py

To add the datamodel via bbfdm, it is required to follow [datamodel guide](https://dev.iopsys.eu/bbf/bbfdm/-/blob/devel/docs/guide/datamodel_as_microservice.md), which allows to add the datamodel with json plugins, or with DotSO plugins.

This tool can generate template "C" code from JSON datamodel definitions.

```bash
$ ./tools/convert_dm_json_to_c.py
Usage: ./tools/convert_dm_json_to_c.py [Object path]
Examples:
  - ./tools/convert_dm_json_to_c.py
    ==> Generate the C code of full data model in datamodel/ folder
  - ./tools/convert_dm_json_to_c.py Device.DeviceInfo.
    ==> Generate the C code of Device.DeviceInfo object in datamodel/ folder
```


### validate_json_plugin.py

This tool helps in validating the json schema, which is very helpful in the development of a JSON based plugins.

```bash
$ ./tools/validate_json_plugin.py test/files/etc/bbfdm/json/UserInterface.json
$ ./tools/validate_json_plugin.py test/files/etc/bbfdm/json/X_IOPSYS_EU_TEST.json
$ ./tools/validate_json_plugin.py dmtree/json/datamodel.json
```

More examples available in [this path](https://dev.iopsys.eu/bbf/bbfdm/-/tree/devel/test/files/etc/bbfdm/plugins).

### generate_dm.sh

This tool generates the list of supported datamodel objects/parameters in xml and xls format, based on the input.

Historically bbfdm tools used to do text parsing to provide list of supported datamodel parameters, which has many limitations:
- Strict binding of datamodel definitions
- Need to maintain specific sequence in definition

This improved tool usages an docker image to get the list of supported datamodel to provide the accurate output.

#### How this works

Based on plugins listed in tools_input.json file, it simulates a runtime environment with docker image and get the datamodel from `bbfdm` ubus object(exposed by bbfdmd) which gets the data from all supported plugins and microservices.


```bash
Usage: ./tools/generate_dm.sh [OPTIONS]...

    -I <docker image>
    -i json input file path relative to top directory
    -h help


examples:
~/git/bbfdm$ ./tools/generate_dm.sh -i tools/tools_input.json
```

The parameters/keys used in tools_input.json file are mostly self-explanatory but few parameters are required a bit more details.

| Key | Description |
|-----|-------------|
| manufacturer | The manufacturer's name, e.g., "IOPSYS" |
| protocol | The device protocol, e.g., "DEVICE_PROTOCOL_DSLFTR069v1 |
| manufacturer_oui | The Manufacturer's Organizationally Unique Identifier (OUI) in hexadecimal format, e.g., "002207" |
| product_class" | The product class, e.g., "DG400PRIME" |
| model_name | The model name, e.g., "DG400PRIME-A" |
| software_version | The software version, e.g., "1.2.3.4" |
| vendor_list | This option should have the same name of the vendor directory names, e.g., ["iopsys"] |
| dm_json_files | This should contain the list of json file path, where each file contains the definition of DM objects/parameters |
| vendor_prefix | The prefix used by vendor for vendor extension in DM objects/parameters, e.g., "X_IOPSYS_EU_" |
| plugins | A list of plugins with associated repositories and data model files |
| | repo: The path of the plugin repository. Could be 'URL' or 'folder_path' |
| | proto: The protocol of the plugin repository. Could be 'git' or 'local' |
| | version: (optional): The version of the git plugin |
| | dm_files: A list of data model files associated with the plugin |
| | extra_dependencies: (optional): Extra dependencies for the plugin, if any |
| output.acs | Currently the tool support two variants of xml definitions of DM objects/parameters |
| | hdm: This variant of xml is compatible with Nokia HDM ACS |
| | default: This contains the generic definition which has the capability to define more descriptive DM objects/parameters |
| output.file_format | Output file formats, e.g., ["xls", "xml"] |
| output.output_dir | The output directory for generated files, e.g., "./out" |
| output.output_file_prefix | The prefix for output file names, e.g., "datamodel" |


> Note:
> To add more description about the vendor extended DM objects/parameters, it is required to add the definition of the required/related DM objects/parameters in a json file (The json structure should follow same format as given in [datamodel.json](../libbbfdm/dmtree/json/datamodel.json)), The same json file need to be defined in dm_json_files list.


The input json file should be defined as follow:

```bash
{
	"manufacturer": "iopsys",
	"protocol": "DEVICE_PROTOCOL_DSLFTR069v1",
	"manufacturer_oui": "002207",
	"product_class": "DG400PRIME",
	"model_name": "DG400PRIME-A",
	"software_version": "1.2.3.4",
	"vendor_list": [
		"iopsys",
		"test"
	],
	"dm_json_files": [
		"../libbbfdm/dmtree/json/datamodel.json"
	]
	"vendor_prefix": "X_IOPSYS_EU_",
	"plugins": [
		{
			"repo": "https://dev.iopsys.eu/bbf/mydatamodel.git",
			"proto": "git",
			"version": "tag/hash/branch",
			"dm_files": [
				"src/datamodel.c",
				"src/additional_datamodel.c"
			]
		},
		{
			"repo": "https://dev.iopsys.eu/bbf/mybbfplugin.git",
			"proto": "git",
			"version": "tag/hash/branch",
			"dm_files": [
				"dm.c"
			]
		},
		{
			"repo": "https://dev.iopsys.eu/bbf/mydatamodeljson.git",
			"proto": "git",
			"version": "tag/hash/branch",
			"dm_files": [
				"src/plugin/testdm.json"
			]
		},
		{
			"repo": "/home/iopsys/sdk/mypackage/",
			"proto": "local",
			"dm_files": [
				"src/datamodel.c",
				"additional_datamodel.c"
			]
		},
		{
			"repo": "/src/feeds/mypackage/",
			"proto": "local",
			"dm_files": [
				"datamodel.c",
				"src/datamodel.json"
			]
		}
	],
	"output": {
		"acs": [
			"hdm",
			"default"
		],
		"file_format": [
			"xml",
			"xls"
		],
		"output_dir": "./out",
		"output_file_prefix": "datamodel"
	}
}
```

---
**NOTE**

> All the tools need to be executed from the top directory.
---

