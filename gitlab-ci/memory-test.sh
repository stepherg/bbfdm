#!/bin/bash

echo "Functional API Tests"
pwd
source ./gitlab-ci/shared.sh

date +%s > timestamp.log
# compile and install libbbf
install_libbbf

install_libbbf_test

supervisorctl status all
supervisorctl update
sleep 5
supervisorctl status all

echo "Running memory check on datamodel"
ret=0
valgrind --xml=yes --xml-file=/builds/iopsys/bbf/memory-report-get.xml --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /builds/iopsys/bbf/test/bbf_test/bbf_dm -u get Device.
ret=$?

valgrind --xml=yes --xml-file=/builds/iopsys/bbf/memory-report-operate.xml --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /builds/iopsys/bbf/test/bbf_test/bbf_dm -u list_operate
ret=$(( ret + $? ))

valgrind --xml=yes --xml-file=/builds/iopsys/bbf/memory-report-schema.xml --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /builds/iopsys/bbf/test/bbf_test/bbf_dm -u get_schema
ret=$(( ret + $? ))

valgrind --xml=yes --xml-file=/builds/iopsys/bbf/memory-report-instances.xml --leak-check=full --show-reachable=yes --show-leak-kinds=all --errors-for-leak-kinds=all --error-exitcode=1 --track-origins=yes /builds/iopsys/bbf/test/bbf_test/bbf_dm -u instances Device.
ret=$(( ret + $? ))

if [ "$ret" -ne 0 ]; then
	echo "Memory check failed"
	return $ret
fi

supervisorctl stop all
supervisorctl status

#report part
#GitLab-CI output
gcovr -r . 2> /dev/null #throw away stderr
# Artefact
gcovr -r . 2> /dev/null --xml -o ./memory-test-coverage.xml

echo "Memory Test :: PASS"
