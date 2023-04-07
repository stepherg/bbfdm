#!/bin/bash

echo "$0 preparation script"
pwd

source ./gitlab-ci/shared.sh

trap cleanup EXIT
trap cleanup SIGINT

make clean
CFLAGS="-g -Os -fprofile-arcs -ftest-coverage -DUSPD_MAX_MSG_LEN=1048576"  LDFLAGS="--coverage" make func-test -C ./
check_ret $?
ls

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

echo "## Preparing shared library for uspd msglen test ##"
exec_cmd make -C ./test

echo "## Running python based verification of functionalities ##"
echo > ./funl-result.log
num=0
for test in `ls -1 ./test/python/*.py`
do
	num=$(( num + 1 ))
	sleep 1
	$test
	if [ $? -eq 0 ]; then
		echo "ok ${num} - $test" >> ./funl-result.log

	else
		echo "not ok ${num} - $test" >>  ./funl-result.log
	fi
done

echo "1..${num}" >> ./funl-result.log
generate_report python_test ./funl-result.log

# run functional on usp object validation
if [ -f "/usr/share/rpcd/schemas/usp*.json" ]; then
	rm /usr/share/rpcd/schemas/usp*.json
fi

fault=0
# run functional on usp object validation
cp -r ./test/funl/schema/usp_test_positive.json /usr/share/rpcd/schemas/usp.json
ubus-api-validator -t 5 -f ./test/funl/validation/usp.validation.positive.json > ./funl-result.log
fault=$?
generate_report usp_positive ./funl-result.log

cp -r ./test/funl/schema/usp_test_negative.json /usr/share/rpcd/schemas/usp.json
ubus-api-validator -t 5 -f ./test/funl/validation/usp.validation.negative.json > ./funl-result.log
fault=$(( $fault + $? ))
generate_report usp_negative ./funl-result.log

# run functional on usp.raw object validation
rm /usr/share/rpcd/schemas/usp*.json
cp -r ./test/funl/schema/usp.raw_test_positive.json  /usr/share/rpcd/schemas/usp.raw.json
ubus-api-validator -t 5 -f ./test/funl/validation/usp.raw.validation.positive.json > ./funl-result.log
fault=$(( $fault + $? ))
generate_report usp_raw_positive ./funl-result.log

#test usp.raw for negative test cases
cp -r ./test/funl/schema/usp.raw_test_negative.json /usr/share/rpcd/schemas/usp.raw.json
ubus-api-validator -t 5 -f ./test/funl/validation/usp.raw.validation.negative.json > ./funl-result.log
fault=$(( $fault + $? ))
generate_report usp_raw_negative ./funl-result.log

# TODO: add for granularity ubus objects
#uci set uspd.usp.granularitylevel='1'
#uci commit

#ubus-api-validator -f ./test/funl/json/gran/gran.validation.json >> ./funl-result.log
#fault=$?

#uci set uspd.usp.granularitylevel='0'
#uci commit

supervisorctl stop all
supervisorctl status

#report part
gcovr -r . --xml -o ./funl-test-coverage.xml
gcovr -r .
date +%s > timestamp.log

echo "Checking memory leaks..."
grep -q "Leak" memory-report.xml
error_on_zero $?

if [ "${fault}" -ne 0 ]; then
	echo "Failed running ubus-api-validator fault[$fault]"
	exit $fault
fi

echo "Functional Test :: PASS"
