#!/bin/bash

echo "install dependencies of bbf"

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip iproute2 libmxml-dev uuid-dev zip
exec_cmd pip3 install pexpect ubus

# compile and install libbbf
install_libbbf ${1}
mkdir -p /etc/bbfdm/plugins

#compile and install libbbf_test dynamic extension library
install_libbbf_test ${1}

#compile and install libwifi_dataelements dynamic extension library
install_libwifi_dataelements ${1}

# Install datamodel plugins/micro-service only when pipeline trigger for bbfdm
if [ -z "${1}" ]; then
	git clone --depth 1 https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/feed/iopsys.git /opt/dev/iopsys
	git clone --depth 1 https://gitlab-ci-token:${CI_JOB_TOKEN}@dev.iopsys.eu/bbf/bulkdata.git /opt/dev/bulkdata

	install_plugin /opt/dev/iopsys/urlfilter/files/etc/bbfdm/json/urlfilter.json
	install_plugin /opt/dev/iopsys/obuspa/files/etc/bbfdm/json/USPAgent.json
	install_plugin /opt/dev/iopsys/icwmp/files/etc/bbfdm/json/CWMPManagementServer.json
	install_plugin /opt/dev/iopsys/ponmngr/files/etc/bbfdm/json/xpon.json
	
	# install bulkdata micro-service
	mkdir -p /etc/bulkdata
	cp -f /opt/dev/bulkdata/bbf_plugin/bulkdata.json /etc/bulkdata
	cp -f /opt/dev/iopsys/bulkdata/files/etc/bulkdata/input.json /etc/bulkdata

	# install usermngr plugin
	install_libusermngr

	# install periodicstats micro-service
	install_periodicstats

	# install cwmpdm plugin
	install_libcwmpdm
	
	# install hosts micro-service
	install_hosts_micro_service
	
	# install time micro-service
	install_time_micro_service

	ls -l /etc/bbfdm/plugins/
fi
