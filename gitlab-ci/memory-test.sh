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
install_libperiodicstats

supervisorctl update
supervisorctl status all
supervisorctl restart all
sleep 5
supervisorctl status all

function run_valgrind()
{
    echo "Running # bbf_dm $@ #"
    exec_cmd valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes ./test/bbf_test/bbf_dm $@
}

function run_valgrind_verbose()
{
    echo "Running # bbf_dm $@ #"
    exec_cmd_verbose valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes ./test/bbf_test/bbf_dm $@
}

function run_valgrind_redirect()
{
    echo "Running # bbf_dm $@ #" > output-report-device-get.txt
    exec_cmd_verbose valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes ./test/bbf_test/bbf_dm $@ | tee -a output-report-device-get.txt
}

echo "Running memory check on datamodel"

run_valgrind_verbose -u get Device.RootDataModelVersion
run_valgrind_verbose -c get Device.RootDataModelVersion

run_valgrind_verbose -u list_operate
run_valgrind -u get_schema
run_valgrind -u instances Device.
run_valgrind -c get Device.
run_valgrind -c list_operate
run_valgrind -c get_schema
run_valgrind_verbose -c instances Device.

run_valgrind -u get_info Device. 0
run_valgrind -u get_info Device. 1
run_valgrind -u get_info Device. 2
run_valgrind -u get_info Device. 3

run_valgrind -u get Device.
run_valgrind -c get Device.

run_valgrind_redirect -u get Device.

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./memory-test-coverage.xml

echo "Generating release"
generate_release

echo "Memory Test :: PASS"
