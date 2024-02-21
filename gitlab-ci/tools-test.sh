#!/bin/bash

echo "Verification of BBF Tools"
pwd
source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip
exec_cmd pip3 install jsonschema xlwt pylint

echo "Validating PEP8 syntax on tools"
exec_cmd_verbose pylint -d R,C,W0603 tools/*.py

echo "********* Validate JSON Plugin *********"

echo "Validate BBF TR-181 JSON Plugin"
./tools/validate_json_plugin.py libbbfdm/dmtree/json/tr181.json
check_ret $?

echo "Validate BBF TR-104 JSON Plugin"
./tools/validate_json_plugin.py libbbfdm/dmtree/json/tr104.json
check_ret $?

echo "Validate X_IOPSYS_EU_Dropbear JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/plugins/X_IOPSYS_EU_Dropbear.json
check_ret $?

echo "Validate X_IOPSYS_EU_TEST JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/plugins/X_IOPSYS_EU_TEST.json
check_ret $?

echo "Validate X_IOPSYS_EU_WiFi JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/plugins/X_IOPSYS_EU_WiFi.json
check_ret $?

echo "Validate UCI_TEST_V1 JSON Plugin"
./tools/validate_json_plugin.py test/files/etc/bbfdm/plugins/X_IOPSYS_EU_JSON_TEST_V1.json
check_ret $?

echo "Validate test extend Plugin"
./tools/validate_json_plugin.py test/vendor_test/test_extend.json 
check_ret $?

echo "Validate test exclude Plugin"
./tools/validate_json_plugin.py test/vendor_test/test_exclude.json 
check_ret $?

echo "Validate test overwrite Plugin"
./tools/validate_json_plugin.py test/vendor_test/test_overwrite.json 
check_ret $?

echo "Validate TR-181 JSON Plugin after generating from XML"
json_path=$(./tools/convert_dm_xml_to_json.py test/tools/tr-181-2-*-cwmp-full.xml test/tools/tr-181-2-*-usp-full.xml Device.)
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

date +%s > timestamp.log
echo "Tools Test :: PASS"
