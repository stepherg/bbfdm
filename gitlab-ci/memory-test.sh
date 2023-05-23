#!/bin/bash

echo "Functional API Tests"
pwd
. ./gitlab-ci/shared.sh

date +%s > timestamp.log

echo "Starting supervisor"
supervisorctl shutdown
sleep 1
supervisord -c /etc/supervisor/supervisord.conf
sleep 3

supervisorctl status all

function run_valgrind()
{
    echo "Running # bbfdmd $@ #"
    exec_cmd valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /usr/sbin/bbfdmd $@
}

function run_valgrind_verbose()
{
    echo "Running # bbfdmd $@ #"
    exec_cmd_verbose valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /usr/sbin/bbfdmd $@
}

function run_valgrind_redirect()
{
    echo "Running # bbfdmd $@ #" >> output-report-device-get.txt
    exec_cmd_verbose valgrind -q --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /usr/sbin/bbfdmd $@ | tee -a output-report-device-get.txt
}

echo "Running memory check on datamodel"

run_valgrind -c get Device.

run_valgrind -c instances Device.

run_valgrind -c schema Device.

run_valgrind_redirect -c get Device.

run_valgrind_redirect -c schema Device.

run_valgrind_verbose -c get Device.BulkData.

run_valgrind_verbose -c get Device.RootDataModelVersion

run_valgrind_verbose -c get Device.IP.Interface.*.IPv6Address.*.IPAddress

run_valgrind -c set Device.WiFi.SSID.1.Enable 1
run_valgrind -c add Device.WiFi.SSID.
run_valgrind -c del Device.WiFi.SSID.3.

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./memory-test-coverage.xml

echo "Memory Test :: PASS"
