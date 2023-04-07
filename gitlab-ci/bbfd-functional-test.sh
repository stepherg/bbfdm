#!/bin/bash

echo "$0 preparation script"
pwd

source ./gitlab-ci/shared.sh

trap cleanup EXIT
trap cleanup SIGINT

supervisorctl update
supervisorctl restart all
supervisorctl status all
exec_cmd ubus wait_for bbf
supervisorctl status all

# debug logging
echo "Checking ubus status [$(date '+%d/%m/%Y %H:%M:%S')]"
ubus list
ubus -v list bbf

echo "Checking system resources"
free -h
df -h

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

# run functional on bbf object validation
rm /usr/share/rpcd/schemas/bbf.json
fault=0

# run functional on bbf object validation
#cp -r ./test/funl/schema/bbf_test_positive.json  /usr/share/rpcd/schemas/bbf.json
#ubus-api-validator -t 5 -f ./test/funl/validation/bbf.validation.positive.json > ./funl-result.log
#fault=$(( $fault + $? ))
#generate_report bbf_positive ./funl-result.log

#test bbf for negative test cases
#cp -r ./test/funl/schema/bbf_test_negative.json /usr/share/rpcd/schemas/bbf.json
#ubus-api-validator -t 5 -f ./test/funl/validation/bbf.validation.negative.json > ./funl-result.log
#fault=$(( $fault + $? ))
#generate_report bbf_negative ./funl-result.log

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
