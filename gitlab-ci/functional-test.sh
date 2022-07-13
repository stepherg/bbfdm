#!/bin/bash

echo "Functional Tests"
pwd
source ./gitlab-ci/shared.sh

echo "Starting supervisor in current directory"
supervisorctl shutdown
sleep 1
supervisord -c supervisord.conf

# compile and install libbbf
install_libbbf

#compile and install libbbf_test dynamic extension library
install_libbbf_test

supervisorctl status all
supervisorctl update
sleep 3
supervisorctl status all

echo "Running the functional test cases"
make clean -C test/cmocka/
make functional-test -C test/cmocka/
check_ret $?

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./functional-test-coverage.xml
date +%s > timestamp.log

echo "Functional Test :: PASS"
