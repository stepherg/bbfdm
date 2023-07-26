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
	[ -d "/opt/dev/usermngr" ] && rm -rf /opt/dev/usermngr
	
	if [ -n "${USERMNGR_BRANCH}" ]; then
		exec_cmd git clone -b ${USERMNGR_BRANCH} https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/usermngr.git /opt/dev/usermngr
	else
		exec_cmd git clone -b devel https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/usermngr.git /opt/dev/usermngr
	fi

	echo "Compiling libusermngr"
	exec_cmd_verbose make clean -C /opt/dev/usermngr/src/
	exec_cmd_verbose make -C /opt/dev/usermngr/src/

	echo "installing libusermngr"
	cp -f /opt/dev/usermngr/src/libusermngr.so /usr/lib/bbfdm
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
	cmake ../ -DCMAKE_C_FLAGS="$COV_CFLAGS " -DCMAKE_EXE_LINKER_FLAGS="$COV_LDFLAGS" -DWITH_OPENSSL=ON -DBBF_JSON_PLUGIN=ON -DBBF_DOTSO_PLUGIN=ON -DBBF_VENDOR_EXTENSION=ON -DBBF_WIFI_DATAELEMENTS=OFF -DBBF_VENDOR_LIST="$VENDOR_LIST" -DBBF_VENDOR_PREFIX="$VENDOR_PREFIX" -DBBF_MAX_OBJECT_INSTANCES=255 -DBBFDMD_MAX_MSG_LEN=1048576 -DCMAKE_INSTALL_PREFIX=/
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
	cp -f test/bbf_test/libbbf_test.so /usr/lib/bbfdm
}

function install_libwifi_dataelements()
{
	# Enable coverage flags only for test
	[ -n "${1}" ] && return 0;

	# compile and install libwifi_dataelements
	echo "Compiling libwifi_dataelements"
	exec_cmd_verbose make clean -C test/wifi_dataelements/
	exec_cmd_verbose make -C test/wifi_dataelements/

	echo "installing libwifi_dataelements"
	cp -f test/wifi_dataelements/wifi_dataelements.json /tmp/wifi_dataelements.json
	cp -f test/wifi_dataelements/libwifi_dataelements.so /tmp/libwifi_dataelements.so
}

function install_libperiodicstats()
{
	# clone and compile libperiodicstats
	[ -d "/opt/dev/periodicstats" ] && rm -rf /opt/dev/periodicstats

	if [ -n "${PERIODICSTATS_BRANCH}" ]; then
		exec_cmd git clone -b ${PERIODICSTATS_BRANCH} https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/periodicstats.git /opt/dev/periodicstats
	else
		exec_cmd git clone -b devel https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/periodicstats.git /opt/dev/periodicstats
	fi

	echo "Compiling libperiodicstats"
	exec_cmd_verbose make clean -C /opt/dev/periodicstats/
	exec_cmd_verbose make -C /opt/dev/periodicstats/

	echo "installing libperiodicstats"
	mkdir -p /etc/periodicstats
	cp -f /opt/dev/periodicstats/bbf_plugin/libperiodicstats.so /etc/periodicstats/
	cp -f /opt/dev/iopsys/periodicstats/files/etc/periodicstats/input.json /etc/periodicstats
}

function install_libcwmpdm()
{
	# clone and compile libcwmpdm
	[ -d "/opt/dev/icwmp" ] && rm -rf /opt/dev/icwmp

	if [ -n "${ICWMP_BRANCH}" ]; then
		exec_cmd git clone -b ${ICWMP_BRANCH} --depth 1 https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/icwmp.git /opt/dev/icwmp
	else
		exec_cmd git clone -b devel --depth 1 https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/icwmp.git /opt/dev/icwmp
	fi

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
	sync
}

