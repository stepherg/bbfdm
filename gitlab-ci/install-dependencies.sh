#!/bin/bash

echo "install dependencies of bbf"

source ./gitlab-ci/shared.sh

# install required packages
apt update
apt install -y python3-pip iproute2 libmxml-dev uuid-dev zip
pip3 install pexpect ubus

# compile and install libbbf
install_libbbf ${1}

#compile and install libbbf_test dynamic extension library
install_libbbf_test ${1}

#compile and install libwifi_dataelements dynamic extension library
install_libwifi_dataelements ${1}

# Install datamodel plugins only when pipeline trigger for bbfdm
if [ -z "${1}" ]; then
	git clone -b ${DEFAULT_BRANCH} --depth 1 https://dev.iopsys.eu/feed/iopsys.git /opt/dev/iopsys
	git clone -b ${DEFAULT_BRANCH} --depth 1 https://dev.iopsys.eu/bbf/bulkdata.git /opt/dev/bulkdata

	cp -f /opt/dev/iopsys/urlfilter/files/etc/bbfdm/json/urlfilter.json /etc/bbfdm/json
	cp -f /opt/dev/iopsys/obuspa/files/etc/bbfdm/json/USPAgent.json /etc/bbfdm/json
	cp -f /opt/dev/iopsys/obuspa/files/etc/bbfdm/json/TransferComplete.json /etc/bbfdm/json
	cp -f /opt/dev/iopsys/icwmp/files/etc/bbfdm/json/CWMPManagementServer.json /etc/bbfdm/json
	cp -f /opt/dev/iopsys/ponmngr/files/etc/bbfdm/json/xpon.json /etc/bbfdm/json
	cp -f /opt/dev/bulkdata/bbf_plugin/bulkdata.json /etc/bbfdm/json/

	# install usermngr plugin
	install_libusermngr

	# install periodicstats plugin
	install_libperiodicstats

	# install cwmpdm plugin
	install_libcwmpdm
fi

ls /usr/lib/bbfdm/
ls /etc/bbfdm/json/
