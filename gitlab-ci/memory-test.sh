#!/bin/bash

echo "Functional API Tests"
pwd
source ./gitlab-ci/shared.sh

date +%s > timestamp.log
# compile and install libbbf
install_libbbf

install_libbbf_test
install_libbulkdata
#install_libperiodicstats

supervisorctl status all
supervisorctl update
sleep 5
supervisorctl status all

ret=0

function run_valgrind()
{
    echo "Running $@ in valgrind"
    valgrind --xml=yes --xml-file=/builds/iopsys/bbf/memory-report-usp-get.xml --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /builds/iopsys/bbf/test/bbf_test/bbf_dm $@
    ret=$(( ret + $? ))
}

echo "Running memory check on datamodel"
run_valgrind -u get Device.

# Test memory leak for get_supported_dm
run_valgrind  -u get_info Device. 0
run_valgrind  -u get_info Device. 1
run_valgrind  -u get_info Device. 2
run_valgrind  -u get_info Device. 3
run_valgrind  -u get_info Device. 4

run_valgrind -u list_operate

run_valgrind -u get_schema

run_valgrind -u instances Device.

run_valgrind -c get Device.

run_valgrind -c list_operate

run_valgrind -c get_schema

run_valgrind  -c instances Device.

if [ "$ret" -ne 0 ]; then
	echo "Memory check failed"
	check_ret $ret
fi

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./memory-test-coverage.xml

echo "Memory Test :: PASS"
