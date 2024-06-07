#!/bin/bash

if [ -z "${CI_PROJECT_PATH}" ]; then
	CI_PROJECT_PATH=${PWD}
fi

function check_ret()
{
	ret=$1
	if [ "$ret" -ne 0 ]; then
		echo "Validation of last command failed, ret(${ret})"
		cp /tmp/memory-*.xml .
		exit $ret
	fi

}

function exec_cmd()
{
	echo "executing $@"
	$@ >/dev/null 2>&1

	if [ $? -ne 0 ]; then
		echo "Failed to execute $@"
		cp /tmp/memory-*.xml .
		exit 1
	fi
}

function exec_cmd_verbose()
{
	echo "executing $@"
	$@

	if [ $? -ne 0 ]; then
		echo "Failed to execute $@"
		cp /tmp/memory-*.xml .
		exit 1
	fi
}

function install_plugin()
{
	exec_cmd cp -f "${1}" /etc/bbfdm/plugins/
}

function install_libbbf()
{
	# Enable coverage flags only for test
	if [ -z "${1}" ]; then
		COV_CFLAGS='-fprofile-arcs -ftest-coverage'
		COV_LDFLAGS='--coverage'
	fi

	VENDOR_LIST='iopsys'
	VENDOR_PREFIX='X_IOPSYS_EU_'

	echo "Compiling libbbf"
	if [ -d build ]; then
		rm -rf build
	fi

	mkdir -p build
	cd build
	cmake ../ -DCMAKE_C_FLAGS="$COV_CFLAGS " -DCMAKE_EXE_LINKER_FLAGS="$COV_LDFLAGS -lm" -DBBF_TR181_ALL=ON -DWITH_OPENSSL=ON -DBBF_VENDOR_EXTENSION=ON -DBBF_VENDOR_LIST="$VENDOR_LIST" -DBBF_VENDOR_PREFIX="$VENDOR_PREFIX" -DBBF_MAX_OBJECT_INSTANCES=255 -DBBFDMD_MAX_MSG_LEN=1048576 -DCMAKE_INSTALL_PREFIX=/
	exec_cmd_verbose make

	echo "installing libbbf"
	exec_cmd_verbose make install
	ln -sf /usr/share/bbfdm/bbf.diag /usr/libexec/rpcd/bbf.diag
	cd ..
}

function install_libbbf_test()
{
	# Enable coverage flags only for test
	[ -n "${1}" ] && return 0;

	# compile and install libbbf_test
	echo "Compiling libbbf_test"
	exec_cmd_verbose make clean -C test/bbf_test/
	exec_cmd_verbose make -C test/bbf_test/

	echo "installing libbbf_test"
	install_plugin ./test/bbf_test/libbbf_test.so
}

function error_on_zero()
{
	ret=$1
	if [ "$ret" -eq 0 ]; then
		echo "Validation of last command failed, ret(${ret})"
		cp /tmp/memory-*.xml .
		exit $ret
	fi

}

function check_valgrind_xml() {
	echo "${1}: Checking memory leaks..."
	echo "checking UninitCondition"
	grep -q "<kind>UninitCondition</kind>" ${2}
	error_on_zero $?

	echo "checking Leak_PossiblyLost"
	grep -q "<kind>Leak_PossiblyLost</kind>" ${2}
	error_on_zero $?

	echo "checking Leak_DefinitelyLost"
	grep -q "<kind>Leak_DefinitelyLost</kind>" ${2}
	error_on_zero $?
}

function generate_report()
{
	exec_cmd tap-junit --name "${1}" --input "${2}" --output report
}

