#!/bin/bash

function check_ret()
{
	ret=$1
	if [ "$ret" -ne 0 ]; then
		echo "Validation of last command failed, ret(${ret})"
		exit $ret
	fi

}

function exec_cmd()
{
	echo "executing $@"
	$@ >/dev/null 2>&1

	if [ $? -ne 0 ]; then
		echo "Failed to execute $@"
		exit 1
	fi
}

function install_libbbf()
{
	COV_CFLAGS='-fprofile-arcs -ftest-coverage'
	COV_LDFLAGS='--coverage'
	VENDOR_LIST='iopsys,test'

	echo "Compiling libbbf"
	if [ -f Makefile ]; then
		exec_cmd make maintainer-clean
		find -name '*.gcno' -exec rm {} -fv \;
		find -name '*.gcov' -exec rm {} -fv \;
		find -name '*.deps' -exec rm {} -rfv \;
		rm -f *.log *.xml
	fi

	autoreconf -i  >/dev/null 2>&1
	./configure CFLAGS="$COV_CFLAGS" LDFLAGS="$COV_LDFLAGS" BBF_VENDOR_LIST="$VENDOR_LIST" --enable-tr181 --enable-tr104 --enable-tr143 --enable-libopenssl --enable-vendor-extension >/dev/null 2>&1
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
}
