#!/bin/bash

echo "Functional API Tests"
pwd
. ./gitlab-ci/shared.sh

echo "Starting supervisor in current directory"
supervisorctl shutdown
sleep 1
supervisord -c supervisord.conf

date +%s > timestamp.log

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
    echo "Running # bbf_dm $@ #" >> output-report-device-get.txt
    exec_cmd_verbose valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes ./test/bbf_test/bbf_dm $@ | tee -a output-report-device-get.txt
}

echo "Running memory check on datamodel"

run_valgrind_verbose -u get Device.RootDataModelVersion
run_valgrind_verbose -c get Device.RootDataModelVersion

run_valgrind -u get Device.
run_valgrind -c get Device.

run_valgrind -u get_instances Device.
run_valgrind -c get_instances Device.

run_valgrind -u get_supported_dm Device.
run_valgrind -c get_supported_dm Device.

run_valgrind_verbose -u get Device.IP.Interface.*.IPv4Address.
run_valgrind_verbose -c get Device.IP.Interface.*.IPv6Address.*.IPAddress

run_valgrind_redirect -u get Device.
run_valgrind_redirect -c get Device.

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./memory-test-coverage.xml

echo "Memory Test :: PASS"
