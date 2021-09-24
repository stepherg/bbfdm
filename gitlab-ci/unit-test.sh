#!/bin/bash

echo "Unit Tests"
pwd
source ./gitlab-ci/shared.sh

# compile and install libbbf
install_libbbf

#compile and install libbbf_test dynamic extension library
install_libbbf_test

supervisorctl status all
supervisorctl update
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
