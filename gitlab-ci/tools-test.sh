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
./tools/validate_json_plugin.py tools/datamodel.json
check_ret $?

echo "Validating plugins"
for plugin in $(ls -1 test/files/usr/share/bbfdm/plugins/*); do
	echo "Validating ${plugin} JSON Plugin"
	./tools/validate_json_plugin.py ${plugin}
	check_ret $?
done

echo "Validate test Plugin"
for plugin in $(ls -1 test/vendor_test/*); do
	echo "Validating ${plugin} JSON Plugin"
	./tools/validate_json_plugin.py test/vendor_test/test_extend.json 
	check_ret $?
done

echo "Validate Data Model JSON Plugin after generating from TR-181, TR-104 and TR-135 XML Files"
json_path=$(./tools/convert_dm_xml_to_json.py -d test/tools/)
./tools/validate_json_plugin.py $json_path
check_ret $?

date +%s > timestamp.log
echo "Tools Test :: PASS"
