#!/bin/bash

echo "Verification of BBF Tools"
pwd
source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip
exec_cmd apt install -y libxml2-utils
exec_cmd pip3 install jsonschema
exec_cmd pip3 install xlwt
exec_cmd pip3 install pylint

echo "Validating PEP8 syntax on tools"
exec_cmd_verbose pylint -d R,C,W0603 tools/*.py

echo "********* Validate JSON Plugin *********"

echo "Validate BBF TR-181 JSON Plugin"
./tools/validate_json_plugin.py libbbf_dm/src/dmtree/json/tr181.json
check_ret $?

echo "Validate BBF TR-104 JSON Plugin"
./tools/validate_json_plugin.py libbbf_dm/src/dmtree/json/tr104.json
check_ret $?

echo "Validate X_IOPSYS_EU_Dropbear JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/json/X_IOPSYS_EU_Dropbear.json
check_ret $?

echo "Validate X_IOPSYS_EU_TEST JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/json/X_IOPSYS_EU_TEST.json
check_ret $?

echo "Validate X_IOPSYS_EU_WiFi JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/json/X_IOPSYS_EU_WiFi.json
check_ret $?

echo "Validate X_IOPSYS_EU_URLFilter JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/json/urlfilter.json
check_ret $?

echo "Validate CWMPManagementServer JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/json/cwmp_management_server.json
check_ret $?

echo "Validate TR-181 JSON Plugin after generating from XML"
json_path=$(./tools/convert_dm_xml_to_json.py test/tools/tr-181-2-15-0-cwmp-full.xml test/tools/tr-181-2-15-0-usp-full.xml Device.)
./tools/validate_json_plugin.py $json_path
check_ret $?

echo "Validate TR-104 JSON Plugin after generating from XML"
json_path=$(./tools/convert_dm_xml_to_json.py test/tools/tr-104-2-0-2-cwmp-full.xml test/tools/tr-104-2-0-2-usp-full.xml Device.Services.VoiceService.)
./tools/validate_json_plugin.py $json_path
check_ret $?

echo "Validate TR-135 JSON Plugin after generating from XML"
json_path=$(./tools/convert_dm_xml_to_json.py test/tools/tr-135-1-4-1-cwmp-full.xml test/tools/tr-135-1-4-1-usp-full.xml Device.Services.STBService.)
./tools/validate_json_plugin.py $json_path
check_ret $?


echo "********* Validate XML File *********"

cd tools
./generate_dm.py tools_input.json
check_ret $?

echo "Check if the required tools are generated"
[ ! -f "out/datamodel.xls" ] && echo "Excel file doesn't exist" && exit 1
[ ! -f "out/datamodel_hdm.xml" ] && echo "XML file with HDM format doesn't exist" && exit 1
[ ! -f "out/datamodel_default.xml" ] && echo "XML file with BBF format doesn't exist" && exit 1

cd ..

echo "Validate datamodel_default generated XML file"
xmllint --schema test/tools/cwmp-datamodel-1-8.xsd tools/out/datamodel_default.xml --noout
check_ret $?

echo "********* Validate C File *********"

## TODO

date +%s > timestamp.log

echo "Tools Test :: PASS"
