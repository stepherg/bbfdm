#!/bin/bash

echo "$0 preparation script"
pwd

source ./gitlab-ci/shared.sh

echo "Starting services..."
cp ./gitlab-ci/bbfdm_services.conf /etc/supervisor/conf.d/

supervisorctl reread
supervisorctl update
sleep 10

supervisorctl status all
exec_cmd ubus wait_for bbfdm

# debug logging
echo "Checking ubus status [$(date '+%d/%m/%Y %H:%M:%S')]"
ubus list
ubus -v list bbfdm

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
cp -r ./docs/api/ubus/bbfdm.json /usr/share/rpcd/schemas/bbf.json
ubus-api-validator -t 10 -f ./test/funl/validation/bbf.validation.json > ./funl-result.log
fault=$?
generate_report bbf_positive ./funl-result.log

supervisorctl stop all
supervisorctl status

#report part
gcovr -r . --xml -o ./funl-test-coverage.xml
gcovr -r .

check_valgrind_xml "/tmp/memory-report.xml" "bbfdmd"

if [ "${fault}" -ne 0 ]; then
	echo "Failed running ubus-api-validator fault[$fault]"
	exit $fault
fi

echo "Functional Test :: PASS"
