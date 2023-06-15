# BBFDM Tools

BBFDM tools are written in python3 and has below dependencies.

System utilities: python3-pip, libxml2-utils
```bash
$ sudo apt install -y python3-pip
$ sudo apt install -y libxml2-utils
```
Python utilities: jsonschema, xlwt
```bash
$ pip3 install jsonschema xlwt
```

| Tools                   | Description                                                  |
| ----------------------- |:------------------------------------------------------------:|
|convert_dm_json_to_c.py  | Convert json mapping to C code for dynamic plugins library.  |
|convert_dm_xml_to_json.py| Convert standart xml to Json format.                         |
|generate_dm.py           | Generate list of supported/un-supported parameters based of json input|
|generate_dm_xml.py       | Generate list of supported/un-supported parameters in xml format |
|generate_dm_excel.py     | Generate list of supported/un-supported parameters in xls format |
|validate_json_plugin.py  | Validate json plugin files for dynamic library or standard data model |

> Note: Currently all the tools needs to be executed in tools directory.

## XML->JSON convertor
It is a [python script](../../tools/convert_dm_xml_to_json.py) to convert Data Model from Broadband Forum XML format to JSON format.

```bash
$ ./convert_dm_xml_to_json.py
Usage: ./convert_dm_xml_to_json.py <tr-xxx cwmp xml data model> <tr-xxx usp xml data model> [Object path]
Examples:
  - ./convert_dm_xml_to_json.py tr-181-2-*-cwmp-full.xml tr-181-2-*-usp-full.xml Device.
    ==> Generate the json file of the sub tree Device. in tr181.json
  - ./convert_dm_xml_to_json.py tr-104-2-0-2-cwmp-full.xml tr-104-2-0-2-usp-full.xml Device.Services.VoiceService.
    ==> Generate the json file of the sub tree Device.Services.VoiceService. in tr104.json
  - ./convert_dm_xml_to_json.py tr-106-1-2-0-full.xml Device.
    ==> Generate the json file of the sub tree Device. in tr106.json

Example of xml data model file: https://www.broadband-forum.org/cwmp/tr-181-2-*-cwmp-full.xml
```

## XML generator

[Python script](../../tools/generate_dm_xml.py) to generator list of supported and un-supported Data Model tree in XML for acs supported format: **Broadband Forum schema** and **HDM**.

```bash
$ ./generate_dm_xml.py -h
usage: generate_dm_xml.py [-h] [-r git^https://dev.iopsys.eu/bbf/stunc.git^devel] [-v iopsys] [-p X_IOPSYS_EU_] [-d DEVICE_PROTOCOL_DSLFTR069v1] [-m iopsys] [-u 002207] [-c DG400PRIME] [-n DG400PRIME-A]
                          [-s 1.2.3.4] [-f BBF] [-o datamodel.xml]

Script to generate list of supported and non-supported parameter in xml format

optional arguments:
  -h, --help            show this help message and exit
  -r git^https://dev.iopsys.eu/bbf/stunc.git^devel, --remote-dm git^https://dev.iopsys.eu/bbf/stunc.git^devel
                        Includes OBJ/PARAM defined under remote repositories defined as bbf plugin
  -v iopsys, --vendor-list iopsys
                        Generate data model tree with vendor extension OBJ/PARAM.
  -p X_IOPSYS_EU_, --vendor-prefix X_IOPSYS_EU_
                        Generate data model tree using provided vendor prefix for vendor defined objects.
  -d DEVICE_PROTOCOL_DSLFTR069v1, --device-protocol DEVICE_PROTOCOL_DSLFTR069v1
                        Generate data model tree using this device protocol.
  -m iopsys, --manufacturer iopsys
                        Generate data model tree using this manufacturer.
  -u 002207, --manufacturer-oui 002207
                        Generate data model tree using this manufacturer oui.
  -c DG400PRIME, --product-class DG400PRIME
                        Generate data model tree using this product class.
  -n DG400PRIME-A, --model-name DG400PRIME-A
                        Generate data model tree using this model name.
  -s 1.2.3.4, --software-version 1.2.3.4
                        Generate data model tree using this software version.
  -f BBF, --format BBF  Generate data model tree with HDM format.
  -o datamodel.xml, --output datamodel.xml
                        Generate the output file with given name

Part of BBF-tools, refer Readme for more examples
```

More examples:
```bash
$ ./generate_dm_xml.py -v iopsys -v test
$ ./generate_dm_xml.py -v iopsys -p X_IOPSYS_EU_ -r git^https://dev.iopsys.eu/bbf/stunc.git^devel
$ ./generate_dm_xml.py -f HDM -v iopsys -p X_IOPSYS_EU_ -o iopsys.xml
```

> Note: For the remote data model, *git* is the only proto allowed to use in the *generate_dm_xml.py* script. Therefore, if you want to use vendor extensions from a local repository, you must use the *generate_dm.py* script.

## Excel generator
[Python script](../../tools/generate_dm_excel.py) to generate list of supported and un-supported parameters in excel sheet.

```bash
$ ./generate_dm_excel.py -h
usage: generate_dm_excel.py [-h] -d tr181 [-r git^https://dev.iopsys.eu/bbf/stunc.git^devel] [-v iopsys] [-p X_IOPSYS_EU_] [-o supported_datamodel.xls]

Script to generate list of supported and non-supported parameter in xls format

optional arguments:
  -h, --help            show this help message and exit
  -d tr181, --datamodel tr181
  -r git^https://dev.iopsys.eu/bbf/stunc.git^devel, --remote-dm git^https://dev.iopsys.eu/bbf/stunc.git^devel
                        Includes OBJ/PARAM defined under remote repositories defined as bbf plugin
  -v iopsys, --vendor-list iopsys
                        Generate data model tree with vendor extension OBJ/PARAM
  -p X_IOPSYS_EU_, --vendor-prefix X_IOPSYS_EU_
                        Generate data model tree using provided vendor prefix for vendor defined objects
  -o supported_datamodel.xls, --output supported_datamodel.xls
                        Generate the output file with given name

Part of BBF-tools, refer Readme for more examples
```

More examples:
```bash
$ ./generate_dm_excel.py -d tr181 -v iopsys -o datamodel.xls
$ ./generate_dm_excel.py -d tr181 -d tr104 -v iopsys -o datamodel.xls
$ ./generate_dm_excel.py -d tr181 -v iopsys -p X_IOPSYS_EU_ -r git^https://dev.iopsys.eu/bbf/xmppc.git^devel -o datamodel_iopsys.xls
```

## Validate JSON plugin
It is a [python script](../../tools/validate_json_plugin.py) to validate JSON plugin files for dynamic library or standard data model [TR181](./libbbfdm/dmtree/json/tr181.json), [TR104](./libbbfdm/dmtree/json/tr104.json), etc..

```bash
$ ./tools/validate_json_plugin.py test/files/etc/bbfdm/json/UserInterface.json
$ ./tools/validate_json_plugin.py test/files/etc/bbfdm/json/X_IOPSYS_EU_TEST.json
$ ./tools/validate_json_plugin.py dmtree/json/tr181.json
```

## Data Model generator

This is a pipeline friendly master script to generate the list of supported and un-supported datamodels in xml and xls formats based on provided input in a json file.
Example json file available [here](../../tools/tools_input.json).

```bash
$ Usage: generate_dm.py <input json file>
Examples:
  - generate_dm.py tools_input.json
    ==> Generate all required files defined in tools_input.json file
```

The parameters/keys used in tools_input.json file are mostly self-explanatory but few parameters are required a bit more details.

| Key | Description |
|-----|-------------|
| vendor_list | This option should have the same name of the vendor directory names |
| dm_json_files | This should contain the list of json file path, where each file contains the definition of DM objects/parameters |
| vendor_prefix | The prefix used by vendor for vendor extension in DM objects/parameters |
| output.acs | Currently the tool support two variants of xml definitions of DM objects/parameters |
| | hdm: This variant of xml is compatible with Nokia HDM ACS |
| | default: This contains the generic definition which has the capability to define more descriptive DM objects/parameters |
| output.file_format | xls: An excel file listing the supported and unsupported DM objects/parameters |

> Note: To add more description about the vendor extended DM objects/parameters, it is required to add the definition of the required/related DM objects/parameters in a json file (The json structure should follow same format as given in [tr181.json](../../libbbfdm/dmtree/json/tr181.json)), The same json file need to be defined in dm_json_files list.

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
		"../libbbfdm/dmtree/json/tr181.json",
		"../libbbfdm/dmtree/json/tr104.json"
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
				"src/plugin/datamodel.json"
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

> Note1: For the local repository, you must use an absolute path as repo option.

> Note2: If proto is not defined in the json config file, then git is used by default as proto option.

- For more examples of tools input json file, you can see this link: [tools_input.json](../../tools/tools_input.json)

