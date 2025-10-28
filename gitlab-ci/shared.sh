#!/bin/bash

BBFDM_TOOLS_INPUT_FILE="$(pwd)/tools/tools_input.json"
BBFDM_PLUGIN_DEST="/opt/dev"
BBFDM_MS_DIR="/usr/share/bbfdm/micro_services"
BBFDM_MS_CONF="/etc/bbfdm/services"
BBFDM_DMMAP_DIR="etc/bbfdm/dmmap/"

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

function install_ms()
{
	exec_cmd cp -f "${1}" ${BBFDM_MS_DIR}/${2}.so
}

function install_ms_plugin()
{
	exec_cmd mkdir -p ${BBFDM_MS_DIR}/${2}
	exec_cmd cp -f "${1}" ${BBFDM_MS_DIR}/${2}/
}

function install_ms_config()
{
	exec_cmd cp -f "${1}" ${BBFDM_MS_CONF}/${2}.json
}

function install_libbbf()
{
	# Enable coverage flags only for bbfdm test
	if [ "$1" == "bbfdm" ]; then
		COV_CFLAGS='-fprofile-arcs -ftest-coverage'
		COV_LDFLAGS='--coverage'
	fi

	VENDOR_PREFIX='X_IOWRT_EU_'

	echo "Compiling libbbf"
	if [ -d build ]; then
		rm -rf build
	fi

	mkdir -p build
	cd build

	# Construct the CMake command as an array for safety
	cmake_args=(
		../
		-DCMAKE_C_FLAGS="$COV_CFLAGS"
		-DCMAKE_EXE_LINKER_FLAGS="$COV_LDFLAGS -lm"
		-DBBF_VENDOR_PREFIX="$VENDOR_PREFIX"
		-DBBF_MAX_OBJECT_INSTANCES=255
		-DBBFDMD_MAX_MSG_LEN=1048576
		-DCMAKE_INSTALL_PREFIX=/
	)

	# Add this flag only if $1 is "tools"
	if [ "$1" == "tools" ]; then
		cmake_args+=(-DBBF_SCHEMA_FULL_TREE=ON)
	fi

	# Run cmake with arguments
	cmake "${cmake_args[@]}"

	# Compile and install
	exec_cmd_verbose make

	echo "installing libbbf"
	exec_cmd_verbose make install
	echo "371d530c95a17d1ca223a29b7a6cdc97e1135c1e0959b51106cca91a0b148b5e42742d372a359760742803f2a44bd88fca67ccdcfaeed26d02ce3b6049cb1e04" > /etc/bbfdm/.secure_hash
	cd ..
	exec_cmd cp utilities/bbf_configd /usr/sbin/
	exec_cmd cp -f utilities/files/usr/share/bbfdm/scripts/bbf_api /usr/share/bbfdm/scripts/
	install_ms build/libbbfdm/libcore.so core
}

function install_libbbf_test()
{
	# compile and install libbbf_test
	echo "Compiling libbbf_test"
	exec_cmd_verbose make clean -C test/bbf_test/
	exec_cmd_verbose make -C test/bbf_test/

	echo "installing libbbf_test"
	install_ms_plugin ./test/bbf_test/libbbf_test.so core
}

function install_wifidmd_as_micro_service()
{
	[ -d "${BBFDM_PLUGIN_DEST}/wifidmd" ] && return 0

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/bbf/wifidmd.git ${BBFDM_PLUGIN_DEST}/wifidmd

	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/wifidmd/src/ clean && make -C ${BBFDM_PLUGIN_DEST}/wifidmd/src/ WIFIDMD_ENABLE_WIFI_DATAELEMENTS='y'
	exec_cmd cp -f ${BBFDM_PLUGIN_DEST}/wifidmd/src/wifidmd /usr/sbin/
}

function install_libeasy()
{
	[ -d "${BBFDM_PLUGIN_DEST}/libeasy" ] && return 0

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/iopsys/libeasy.git ${BBFDM_PLUGIN_DEST}/libeasy
	(

		cd ${BBFDM_PLUGIN_DEST}/libeasy
		exec_cmd make
		sudo mkdir -p /usr/include/easy
		sudo cp -a libeasy*.so* /usr/lib
		sudo cp -a *.h /usr/include/easy/
	)
}

function install_libqos()
{
	[ -d "${BBFDM_PLUGIN_DEST}/libqos" ] && return 0

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/hal/libqos.git ${BBFDM_PLUGIN_DEST}/libqos
	(

		cd ${BBFDM_PLUGIN_DEST}/libqos
		exec_cmd make
		sudo mkdir -p /usr/include/
		sudo cp -a libqos*.so* /usr/lib/
		sudo cp -a include/*.h /usr/include/
	)
}

function install_libethernet()
{
	[ -d "${BBFDM_PLUGIN_DEST}/libethernet" ] && return 0

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/iopsys/libethernet.git ${BBFDM_PLUGIN_DEST}/libethernet
	(
		 cd ${BBFDM_PLUGIN_DEST}/libethernet
		 make PLATFORM=TEST
		 sudo cp ethernet.h /usr/include
		 sudo cp -a libethernet*.so* /usr/lib
		 sudo ldconfig
	)
}

function install_ethmngr_as_micro_service()
{
	[ -d "${BBFDM_PLUGIN_DEST}/ethmngr" ] && return 0

	install_libeasy
	install_libethernet
	install_libqos

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/hal/ethmngr.git ${BBFDM_PLUGIN_DEST}/ethmngr
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/ethmngr
	exec_cmd sudo cp -f ${BBFDM_PLUGIN_DEST}/ethmngr/ethmngr /usr/sbin/ethmngr
}

function install_netmngr_as_micro_service()
{
	[ -d "${BBFDM_PLUGIN_DEST}/netmngr" ] && return 0

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/network/netmngr.git ${BBFDM_PLUGIN_DEST}/netmngr
	
	exec_cmd apt install iproute2 -y

	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/netmngr/src/ clean
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/netmngr/src/ NETMNGR_GRE_OBJ=y NETMNGR_IP_OBJ=y NETMNGR_ROUTING_OBJ=y NETMNGR_PPP_OBJ=y NETMNGR_ROUTER_ADVERTISEMENT_OBJ=y NETMNGR_IPV6RD_OBJ=y
	install_ms ${BBFDM_PLUGIN_DEST}/netmngr/src/libnetmngr.so netmngr

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/bbf/tr143d.git ${BBFDM_PLUGIN_DEST}/tr143d
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/tr143d/src/ clean && make -C ${BBFDM_PLUGIN_DEST}/tr143d/src/
	exec_cmd cp -f utilities/files/usr/share/bbfdm/scripts/bbf_api /usr/share/bbfdm/scripts/
	exec_cmd cp -rf ${BBFDM_PLUGIN_DEST}/tr143d/scripts/* /usr/share/bbfdm/scripts/
	install_ms_plugin ${BBFDM_PLUGIN_DEST}/tr143d/src/libtr143d.so netmngr

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/bbf/tr471d.git ${BBFDM_PLUGIN_DEST}/tr471d
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/tr471d/src/ clean && make -C ${BBFDM_PLUGIN_DEST}/tr471d/src/
	install_ms_plugin ${BBFDM_PLUGIN_DEST}/tr471d/src/libtr471d.so netmngr

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/bbf/twamp-light.git ${BBFDM_PLUGIN_DEST}/twamp
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/twamp clean && make -C ${BBFDM_PLUGIN_DEST}/twamp
	install_ms_plugin ${BBFDM_PLUGIN_DEST}/twamp/libtwamp.so netmngr

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/bbf/udpecho.git ${BBFDM_PLUGIN_DEST}/udpecho
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/udpecho/src/ clean && make -C ${BBFDM_PLUGIN_DEST}/udpecho/src/
	install_ms_plugin ${BBFDM_PLUGIN_DEST}/udpecho/src/libudpechoserver.so netmngr
}

function install_sysmngr_as_micro_service()
{
	[ -d "${BBFDM_PLUGIN_DEST}/sysmngr" ] && return 0

	exec_cmd git clone -b ${BRANCH:-devel} --depth=1 https://dev.iopsys.eu/system/sysmngr.git ${BBFDM_PLUGIN_DEST}/sysmngr

	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/sysmngr/src/ clean && \
	exec_cmd make -C ${BBFDM_PLUGIN_DEST}/sysmngr/src/ \
		CFLAGS+="-DBBF_VENDOR_PREFIX=\\\"X_IOWRT_EU_\\\"" \
		SYSMNGR_VENDOR_CONFIG_FILE='y' \
		SYSMNGR_MEMORY_STATUS='y' \
		SYSMNGR_PROCESS_STATUS='y' \
		SYSMNGR_SUPPORTED_DATA_MODEL='y' \
		SYSMNGR_FIRMWARE_IMAGE='y' \
		SYSMNGR_REBOOTS='y' \
		SYSMNGR_NETWORK_PROPERTIES='y' \
		SYSMNGR_VENDOR_EXTENSIONS='y' \
		SYSMNGR_FWBANK_UBUS_SUPPORT='y'

	exec_cmd cp -f ${BBFDM_PLUGIN_DEST}/sysmngr/src/sysmngr /usr/sbin/
	exec_cmd mkdir /etc/sysmngr
}

function error_on_zero()
{
	ret=$1
	if [ "$ret" -eq 0 ]; then
		echo "Validation of Last command failed, ret(${ret})"
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
	[ -d "${BBFDM_PLUGIN_DEST}/cmph" ] && return 0

	exec_cmd git clone https://git.code.sf.net/p/cmph/git ${BBFDM_PLUGIN_DEST}/cmph
	(
		cd ${BBFDM_PLUGIN_DEST}/cmph
		exec_cmd autoreconf -i
		exec_cmd ./configure
		exec_cmd make
		exec_cmd sudo make install
	)
}
