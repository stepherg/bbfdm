#!/bin/bash

echo "Functional API Tests"
pwd
source ./gitlab-ci/shared.sh

supervisorctl status all

echo "Running the functional API test cases"
make clean -C test/cmocka/
make functional-api-test -C test/cmocka/
check_ret $?

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./functional-api-test-coverage.xml

echo "Functional API Test :: PASS"
