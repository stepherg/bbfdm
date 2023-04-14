#!/bin/bash

if [ -z "${CI_PROJECT_PATH}" ]; then
	CI_PROJECT_PATH=${PWD}
fi

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

function install_libusermngr()
{
	# clone and compile libusermngr
	rm -rf /opt/dev/usermngr
	exec_cmd git clone -b devel https://dev.iopsys.eu/bbf/usermngr.git /opt/dev/usermngr

	echo "Compiling libusermngr"
	exec_cmd_verbose make clean -C /opt/dev/usermngr/src/
	exec_cmd_verbose make -C /opt/dev/usermngr/src/

	echo "installing libusermngr"
	cp -f /opt/dev/usermngr/src/libusermngr.so /usr/lib/bbfdm
}

function install_libbbf()
{
	COV_CFLAGS='-fprofile-arcs -ftest-coverage'
	COV_LDFLAGS='--coverage'
	VENDOR_LIST='iopsys'
	VENDOR_PREFIX='X_IOPSYS_EU_'

	echo "Compiling libbbf"
	if [ -d build ]; then
		rm -rf build
	fi

	mkdir -p build
	cd build
	cmake ../ -DCMAKE_C_FLAGS="$COV_CFLAGS " -DCMAKE_EXE_LINKER_FLAGS="$COV_LDFLAGS" -DBBFDMD_ENABLED=ON -DBBF_TR181=ON -DBBF_TR104=ON -DBBF_TR143=ON -DWITH_OPENSSL=ON -DBBF_JSON_PLUGIN=ON -DBBF_DOTSO_PLUGIN=ON -DBBF_VENDOR_EXTENSION=ON -DBBF_VENDOR_LIST="$VENDOR_LIST" -DBBF_VENDOR_PREFIX="$VENDOR_PREFIX" -DBBF_MAX_OBJECT_INSTANCES=255 -DBBFD_MAX_MSG_LEN=1048576 -DCMAKE_INSTALL_PREFIX=/
	exec_cmd_verbose make

	echo "installing libbbf"
	exec_cmd_verbose make install
	ln -sf /usr/share/bbfdm/bbf.diag /usr/libexec/rpcd/bbf.diag
	cd ..
}

function install_libbbf_test()
{
	# compile and install libbbf_test
	echo "Compiling libbbf_test"
	exec_cmd_verbose make clean -C test/bbf_test/
	exec_cmd_verbose make -C test/bbf_test/

	echo "installing libbbf_test"
	cp -f test/bbf_test/libbbf_test.so /usr/lib/bbfdm
}

function install_libperiodicstats()
{
	# clone and compile libperiodicstats
	rm -rf /opt/dev/periodicstats
	exec_cmd git clone -b devel https://dev.iopsys.eu/bbf/periodicstats.git /opt/dev/periodicstats

	echo "Compiling libperiodicstats"
	exec_cmd_verbose make clean -C /opt/dev/periodicstats/
	exec_cmd_verbose make -C /opt/dev/periodicstats/

	echo "installing libperiodicstats"
	cp -f /opt/dev/periodicstats/bbf_plugin/libperiodicstats.so /usr/lib/bbfdm
}

function install_libcwmpdm()
{
	# clone and compile libcwmpdm
	rm -rf /opt/dev/icwmp
	exec_cmd git clone -b ticket_8966 --depth 1 https://dev.iopsys.eu/bbf/icwmp.git /opt/dev/icwmp

	echo "Compiling libcwmpdm"
	cd /opt/dev/icwmp
	cmake -DWITH_OPENSSL=ON -DCMAKE_INSTALL_PREFIX=/
	exec_cmd_verbose make

	echo "installing libcwmpdm"
	cp -f /opt/dev/icwmp/libcwmpdm.so /usr/lib/bbfdm

	cd /builds/bbf/bbfdm
}

function error_on_zero()
{
	ret=$1
	if [ "$ret" -eq 0 ]; then
		echo "Validation of last command failed, ret(${ret})"
		exit $ret
	fi

}

function generate_report()
{
	exec_cmd tap-junit --name "${1}" --input "${2}" --output report
	sync
}

