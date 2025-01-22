#!/bin/bash

BBFDM_PLUGIN_DIR="/usr/share/bbfdm/plugins"
BBFDM_MS_DIR="/usr/share/bbfdm/micro_services"
BBFDM_LOG_FILE="/tmp/bbfdm.log"

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
	exec_cmd cp -f "${1}" ${BBFDM_PLUGIN_DIR}/
}

function install_libbbf()
{
	# Enable coverage flags only for test
	if [ -z "${1}" ]; then
		COV_CFLAGS='-fprofile-arcs -ftest-coverage'
		COV_LDFLAGS='--coverage'
	fi

	VENDOR_PREFIX='X_IOPSYS_EU_'

	echo "Compiling libbbf"
	if [ -d build ]; then
		rm -rf build
	fi

	mkdir -p build
	cd build
	cmake ../ -DCMAKE_C_FLAGS="$COV_CFLAGS " -DCMAKE_EXE_LINKER_FLAGS="$COV_LDFLAGS -lm" -DBBF_VENDOR_PREFIX="$VENDOR_PREFIX" -DBBF_MAX_OBJECT_INSTANCES=255 -DBBFDMD_MAX_MSG_LEN=1048576 -DCMAKE_INSTALL_PREFIX=/
	exec_cmd_verbose make

	echo "installing libbbf"
	exec_cmd_verbose make install
	echo "371d530c95a17d1ca223a29b7a6cdc97e1135c1e0959b51106cca91a0b148b5e42742d372a359760742803f2a44bd88fca67ccdcfaeed26d02ce3b6049cb1e04" > /etc/bbfdm/.secure_hash
	cd ..
	exec_cmd cp utilities/bbf_configd /usr/sbin/
}

function install_libbbf_test()
{
	# compile and install libbbf_test
	echo "Compiling libbbf_test"
	exec_cmd_verbose make clean -C test/bbf_test/
	exec_cmd_verbose make -C test/bbf_test/

	echo "installing libbbf_test"
	install_plugin ./test/bbf_test/libbbf_test.so
}

function install_wifidmd_as_micro_service()
{
	[ -d "/opt/dev/wifidmd" ] && return 0

	exec_cmd git clone https://dev.iopsys.eu/bbf/wifidmd.git /opt/dev/wifidmd

	exec_cmd make -C /opt/dev/wifidmd/src/ clean && make -C /opt/dev/wifidmd/src/ CFLAGS="-D'BBF_VENDOR_PREFIX=\"X_IOPSYS_EU_\"'"
	exec_cmd cp -f /opt/dev/wifidmd/src/libwifi.so /usr/share/bbfdm/micro_services/wifidmd.so
	exec_cmd cp -f /opt/dev/wifidmd/src/libdataelements.so /usr/share/bbfdm/micro_services/wifidmd.dataelements.so
}

function install_libeasy()
{
	[ -d "/opt/dev/libeasy" ] && return 0

	exec_cmd git clone https://dev.iopsys.eu/iopsys/libeasy.git /opt/dev/libeasy
	(

		cd /opt/dev/libeasy
		exec_cmd make
		mkdir -p /usr/include/easy
		cp -a libeasy*.so* /usr/lib
		cp -a *.h /usr/include/easy/
	)
}

function install_libethernet()
{
	[ -d "/opt/dev/libethernet" ] && return 0

	exec_cmd git clone https://dev.iopsys.eu/iopsys/libethernet.git /opt/dev/libethernet
	(
		 cd /opt/dev/libethernet
		 make PLATFORM=TEST
		 cp ethernet.h /usr/include
		 cp -a libethernet*.so* /usr/lib
		 sudo ldconfig
	)
}

function install_ethmngr_as_micro_service()
{
	[ -d "/opt/dev/ethmngr" ] && return 0

	install_libeasy
	install_libethernet

	exec_cmd git clone https://dev.iopsys.eu/hal/ethmngr.git /opt/dev/ethmngr
	exec_cmd make -C /opt/dev/ethmngr
	exec_cmd cp /opt/dev/ethmngr/ethmngr /usr/sbin/ethmngr
}

function install_netmngr_as_micro_service()
{
	[ -d "/opt/dev/netmngr" ] && return 0

	exec_cmd git clone https://dev.iopsys.eu/network/netmngr.git /opt/dev/netmngr

	exec_cmd make -C /opt/dev/netmngr/src/ clean
	exec_cmd make -C /opt/dev/netmngr/src/ NETMNGR_GRE_OBJ=y NETMNGR_IP_OBJ=y NETMNGR_ROUTING_OBJ=y NETMNGR_PPP_OBJ=y NETMNGR_ROUTER_ADVERTISEMENT_OBJ=y NETMNGR_IPV6RD_OBJ=y
	exec_cmd cp -f /opt/dev/netmngr/src/libnetmngr.so /usr/share/bbfdm/micro_services/netmngr.so
	exec_cmd cp -f /opt/dev/netmngr/src/libinterface_stack.so /usr/share/bbfdm/plugins
	exec_cmd mkdir -p /usr/share/bbfdm/micro_services/netmngr

	exec_cmd git clone https://dev.iopsys.eu/bbf/tr143d.git /opt/dev/tr143d
	exec_cmd make -C /opt/dev/tr143d/src/ clean && make -C /opt/dev/tr143d/src/
	exec_cmd cp -f /opt/dev/tr143d/src/libtr143d.so /usr/share/bbfdm/micro_services/netmngr

	exec_cmd git clone https://dev.iopsys.eu/bbf/tr471d.git /opt/dev/tr471d
	exec_cmd make -C /opt/dev/tr471d/src/ clean && make -C /opt/dev/tr471d/src/
	exec_cmd cp -f /opt/dev/tr471d/src/libtr471d.so /usr/share/bbfdm/micro_services/netmngr

	exec_cmd git clone https://dev.iopsys.eu/bbf/twamp-light.git /opt/dev/twamp
	exec_cmd make -C /opt/dev/twamp clean && make -C /opt/dev/twamp
	exec_cmd cp -f /opt/dev/twamp/libtwamp.so /usr/share/bbfdm/micro_services/netmngr

	exec_cmd git clone https://dev.iopsys.eu/bbf/udpecho.git /opt/dev/udpecho
	exec_cmd make -C /opt/dev/udpecho/src/ clean && make -C /opt/dev/udpecho/src/
	exec_cmd cp -f /opt/dev/udpecho/src/libudpechoserver.so /usr/share/bbfdm/micro_services/netmngr
}

function install_sysmngr_as_micro_service()
{
	[ -d "/opt/dev/sysmngr" ] && return 0

	exec_cmd git clone https://dev.iopsys.eu/system/sysmngr.git /opt/dev/sysmngr

	exec_cmd make -C /opt/dev/sysmngr/src/ clean && \
	exec_cmd make -C /opt/dev/sysmngr/src/ \
		CFLAGS+="-DBBF_VENDOR_PREFIX=\\\"X_IOPSYS_EU_\\\"" \
		SYSMNGR_VENDOR_CONFIG_FILE='y' \
		SYSMNGR_MEMORY_STATUS='y' \
		SYSMNGR_PROCESS_STATUS='y' \
		SYSMNGR_SUPPORTED_DATA_MODEL='y' \
		SYSMNGR_FIRMWARE_IMAGE='y' \
		SYSMNGR_REBOOTS='y' \
		SYSMNGR_NETWORK_PROPERTIES='y' \
		SYSMNGR_VENDOR_EXTENSIONS='y' \
		SYSMNGR_FWBANK_UBUS_SUPPORT='y'

	exec_cmd cp /opt/dev/sysmngr/src/sysmngr /usr/sbin/
	exec_cmd mkdir /etc/sysmngr
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
	echo "Memory check [$@] ..."
	valgrind-ci ${1} --summary
	exec_cmd valgrind-ci ${1} --abort-on-errors
}

function generate_report()
{
	exec_cmd tap-junit --name "${1}" --input "${2}" --output report
}

function install_cmph()
{
	[ -d "/opt/dev/cmph" ] && return 0

	exec_cmd git clone https://git.code.sf.net/p/cmph/git /opt/dev/cmph
	(
		cd /opt/dev/cmph
		exec_cmd autoreconf -i
		exec_cmd ./configure
		exec_cmd make
		exec_cmd sudo make install
	)
}

