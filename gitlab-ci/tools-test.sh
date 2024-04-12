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

echo "Validate BBF Data Model JSON Plugin"
./tools/validate_json_plugin.py libbbfdm/dmtree/json/datamodel.json
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

echo "Validate Data Model JSON Plugin after generating from TR-181, TR-104 and TR-135 XML Files"
json_path=$(./tools/convert_dm_xml_to_json.py -d test/tools/)
./tools/validate_json_plugin.py $json_path
check_ret $?

date +%s > timestamp.log
echo "Tools Test :: PASS"
