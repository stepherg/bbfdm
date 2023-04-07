#!/bin/bash

echo "$0 preparation script"
pwd

source ./gitlab-ci/shared.sh

trap cleanup EXIT
trap cleanup SIGINT

# clean and make
make clean
CFLAGS="-g -Os -fprofile-arcs -ftest-coverage -DUSPD_MAX_MSG_LEN=1048576"  LDFLAGS="--coverage" make func-test -C ./
check_ret $?

supervisorctl update
supervisorctl restart all
supervisorctl status all
exec_cmd ubus wait_for usp.raw usp
supervisorctl status all

# debug logging
echo "Checking ubus status [$(date '+%d/%m/%Y %H:%M:%S')]"
ubus list
ubus -v list usp.raw
ubus -v list usp

echo "Checking system resources"
free -h
df -h
sleep 5
# run functional on usp object validation
if [ -f "/usr/share/rpcd/schemas/usp*.json" ]; then
	rm /usr/share/rpcd/schemas/usp*.json
fi

cp -r ./schemas/ubus/usp.json /usr/share/rpcd/schemas
ubus-api-validator -t 5 -f ./test/api/json/usp.validation.json > ./api-result.log
generate_report usp_api api-result.log

# run functional on usp object validation
if [ -f "/usr/share/rpcd/schemas/usp*.json" ]; then
	rm /usr/share/rpcd/schemas/usp*.json
fi

cp -r ./schemas/ubus/usp.raw.json /usr/share/rpcd/schemas
ubus-api-validator -t 5 -f ./test/api/json/usp.raw.validation.json >> ./api-result.log
generate_report usp_raw_api api-result.log

supervisorctl status all
supervisorctl stop all
supervisorctl status

#report part
date +%s > timestamp.log
gcovr -r . --xml -o ./api-test-coverage.xml
gcovr -r .

echo "Checking memory leaks..."
grep -q "Leak" memory-report.xml
error_on_zero $?

echo "Functional ubus API test :: PASS"
