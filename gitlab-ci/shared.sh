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

function exec_cmd_verbose()
{
	echo "executing $@"
	$@

	if [ $? -ne 0 ]; then
		echo "Failed to execute $@"
		exit 1
	fi
}

function install_libbbf()
{
	COV_CFLAGS='-fprofile-arcs -ftest-coverage'
	COV_LDFLAGS='--coverage'
	VENDOR_LIST='iopsys'
	VENDOR_PREFIX='X_IOPSYS_EU_'

	echo "Compiling libbbf"
	if [ -f Makefile ]; then
		exec_cmd make maintainer-clean
		find -name '*.gcno' -exec rm {} -fv \;
		find -name '*.gcov' -exec rm {} -fv \;
		find -name '*.deps' -exec rm {} -rfv \;
		rm -f *.log *.xml
	fi

	exec_cmd autoreconf -i
	exec_cmd ./configure --enable-tr181 --enable-tr104 --enable-tr143 --enable-libopenssl --enable-json-plugin --enable-shared-library --enable-vendor-extension BBF_VENDOR_LIST="$VENDOR_LIST" BBF_VENDOR_PREFIX="$VENDOR_PREFIX"
	make CFLAGS="-D_GNU_SOURCE -Wall -Werror" CFLAGS+="$COV_CFLAGS" LDFLAGS="$COV_LDFLAGS" >/dev/null 2>&1

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
}

function install_libbbf_test()
{
	# compile and install libbbf_test
	echo "Compiling libbbf_test"
	make clean -C test/bbf_test/
	make -C test/bbf_test/

	echo "installing libbbf_test"
	cp -f test/bbf_test/libbbf_test.so /usr/lib/bbfdm
}

function install_libbulkdata()
{
	# clone and compile libbulkdata
	rm -rf /opt/dev/bulkdata
	exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/bulkdata.git /opt/dev/bulkdata
	echo "Compiling libbulkdata"
	make clean -C /opt/dev/bulkdata/
	make CFLAGS="-D_GNU_SOURCE" -C /opt/dev/bulkdata/

	echo "installing libbulkdata"
	cp -f /opt/dev/bulkdata/libbulkdata.so /usr/lib/bbfdm
}

function install_libperiodicstats()
{
	# clone and compile libperiodicstats
	rm -rf /opt/dev/periodicstats
	exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/periodicstats.git /opt/dev/periodicstats
	echo "Compiling libperiodicstats"
	make clean -C /opt/dev/periodicstats/
	make -C /opt/dev/periodicstats/

	echo "installing libperiodicstats"
	cp -f /opt/dev/periodicstats/libperiodicstats.so /usr/lib/bbfdm
}
