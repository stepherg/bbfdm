#!/bin/bash

echo "Functional API Tests"
pwd
. ./gitlab-ci/shared.sh

echo "Starting supervisor in current directory"
supervisorctl shutdown
sleep 1
supervisord -c supervisord.conf

# install required packages
exec_cmd apt update
exec_cmd apt install -y zip

date +%s > timestamp.log

# compile and install libbbf
install_libbbf

install_libbbf_test
install_libbulkdata
install_libperiodicstats

supervisorctl status all
supervisorctl update
sleep 5
supervisorctl status all

ret=0

function run_valgrind()
{
    echo "Running bbf_dm $1 in valgrind"
    valgrind --xml=yes --xml-file=$2 --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes ./test/bbf_test/bbf_dm $1 > $3
    ret=$(( ret + $? ))
}

echo "Running memory check on datamodel"

run_valgrind "-u get_info Device. 0" "memory-report-usp-get_info-all-schema.xml" "output-report-usp-get_info-all-schema.log"

run_valgrind "-u get_info Device. 1" "memory-report-usp-get_info-param-only.xml" "output-report-usp-get_info-param-only.log"

run_valgrind "-u get_info Device. 2" "memory-report-usp-get_info-event-only.xml" "output-report-usp-get_info-event-only.log"

run_valgrind "-u get_info Device. 3" "memory-report-usp-get_info-operate-only.xml" "output-report-usp-get_info-operate-only.log"

run_valgrind "-u get Device." "memory-report-usp-get.xml" "output-report-usp-get.log"

run_valgrind "-u list_operate" "memory-report-usp-operate.xml" "output-report-usp-operate.log"

run_valgrind "-u get_schema" "memory-report-usp-schema.xml" "output-report-usp-schema.log"

run_valgrind "-u instances Device." "memory-report-usp-instances.xml" "output-report-usp-instances.log"

run_valgrind "-c get Device." "memory-report-cwmp-get.xml" "output-report-cwmp-get.log"

run_valgrind "-c list_operate" "memory-report-cwmp-operate.xml" "output-report-cwmp-operate.log"

run_valgrind "-c get_schema" "memory-report-cwmp-schema.xml" "output-report-cwmp-schema.log"

run_valgrind "-c instances Device." "memory-report-cwmp-instances.xml" "output-report-cwmp-instances.log"

if [ "$ret" -ne 0 ]; then
	echo "Memory check failed"
	check_ret $ret
fi

supervisorctl stop all
supervisorctl status

exec_cmd zip -r bbf_out.zip memory-report-* output-report-*

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./memory-test-coverage.xml

echo "Memory Test :: PASS"
