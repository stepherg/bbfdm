#!/bin/bash

echo "Unit Tests"
pwd
source ./gitlab-ci/shared.sh

# link '/bin/sh' to bash instead of dash
ln -sf bash /bin/sh

# compile and install libbbf
echo "Compiling libbbf"
if [ -f Makefile ]; then
	exec_cmd make maintainer-clean
	find -name '*.gcno' -exec rm {} -fv \;
	find -name '*.gcov' -exec rm {} -fv \;
	find -name '*.deps' -exec rm {} -rfv \;
	rm -f *.log *.xml
fi

exec_cmd autoreconf -i
exec_cmd ./configure --enable-tr181 --enable-tr104 --enable-tr143 --enable-bbf-test --enable-vendor-extension BBF_VENDOR_LIST="iopsys"
exec_cmd make CPPFLAGS=-DBBF_VENDOR_LIST=\\\"iopsys\\\" CPPFLAGS+=-DBBF_VENDOR_PREFIX=\\\"X_IOPSYS_EU_\\\"

echo "installing libbbf"
exec_cmd make install
ldconfig

echo "configuring libbbf"
mkdir -p /etc/bbfdm/
mkdir -p /etc/bbfdm/dmmap
mkdir -p /etc/bbfdm/json
mkdir -p /usr/share/bbfdm
mkdir -p /usr/lib/bbfdm
cp -f scripts/* /usr/share/bbfdm

# compile and install libbbf_test
echo "Compiling libbbf_test"
make clean -C test/bbf_test/
make -C test/bbf_test/

echo "installing libbbf_test"
cp -f test/bbf_test/libbbf_test.so /usr/lib/bbfdm


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
