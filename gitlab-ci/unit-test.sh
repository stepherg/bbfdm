#!/bin/bash

echo "Unit Tests"
pwd
. ./gitlab-ci/shared.sh

echo "Starting supervisor"
supervisorctl stop all
sleep 1
supervisorctl start ubusd rpcd bbf.config netmngr sysmngr
sleep 3

supervisorctl status all

echo "Running the unit test cases"
make clean -C test/cmocka/
make unit-test -C test/cmocka/
check_ret $?

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./unit-test-coverage.xml
date +%s > timestamp.log

echo "Unit test PASS"
