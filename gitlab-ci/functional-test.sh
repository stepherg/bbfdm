#!/bin/bash

echo "Functional Tests"
pwd
source ./gitlab-ci/shared.sh

supervisorctl status all

echo "Running the functional test cases"
make clean -C test/cmocka/
make functional-test -C test/cmocka/
check_ret $?

sleep 10
supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./functional-test-coverage.xml

echo "Functional Test :: PASS"
