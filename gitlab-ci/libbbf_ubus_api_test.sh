#!/bin/bash

echo "$0 preparation script"
pwd

source ./gitlab-ci/shared.sh

# clean and make
# compile and install libbbf
install_libbbf

#compile and install libbbf_test dynamic extension library
install_libbbf_test

supervisorctl update
supervisorctl restart all
supervisorctl status all
exec_cmd ubus wait_for dmtest
supervisorctl status all

# debug logging
echo "Checking ubus status [$(date '+%d/%m/%Y %H:%M:%S')]"
ubus list
ubus -v list dmtest

echo "Checking system resources"
free -h
df -h
sleep 5

# run functional on dmtest object validation
if [ -f "/usr/share/rpcd/schemas/dmtest.json" ]; then
	rm /usr/share/rpcd/schemas/dmtest.json
fi

cp -r ./schemas/dmtest.json /usr/share/rpcd/schemas
ubus-api-validator -t 5 -f ./test/api/json/dmtest.validation.json >> ./api-result.log
check_ret $?

supervisorctl status all
supervisorctl stop all
supervisorctl status

#report part
date +%s > timestamp.log
exec_cmd tap-junit --input ./api-result.log --output report

echo "Checking memory leaks..."
grep -q "Leak" memory-report.xml
error_on_zero $?

echo "Functional libbbf_ubus API test :: PASS"
