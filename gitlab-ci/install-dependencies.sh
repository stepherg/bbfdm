#!/bin/bash

echo "install dependencies of bbf"
pwd

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip iproute2
exec_cmd pip3 install pexpect ubus

mkdir -p /usr/lib/bbfdm
mkdir -p /etc/bbfdm/json

git clone -b devel --depth 1 https://dev.iopsys.eu/feed/iopsys.git /opt/dev/iopsys
git clone -b devel --depth 1 https://dev.iopsys.eu/iopsys/bulkdata.git /opt/dev/bulkdata

cp -f /opt/dev/iopsys/urlfilter/files/etc/bbfdm/json/urlfilter.json /etc/bbfdm/json
cp -f /opt/dev/iopsys/obuspa/files/etc/bbfdm/json/USPAgent.json /etc/bbfdm/json
cp -f /opt/dev/iopsys/obuspa/files/etc/bbfdm/json/TransferComplete.json /etc/bbfdm/json
cp -f /opt/dev/iopsys/icwmp/files/etc/bbfdm/json/CWMPManagementServer.json /etc/bbfdm/json
cp -f /opt/dev/iopsys/ponmngr/files/etc/bbfdm/json/xpon.json /etc/bbfdm/json
cp -f /opt/dev/bulkdata/bbf_plugin/bulkdata.json /etc/bbfdm/json

# install usermngr plugin
rm -rf /opt/dev/usermngr
exec_cmd git clone -b devel --depth 1 https://dev.iopsys.eu/iopsys/usermngr.git /opt/dev/usermngr

echo "Compiling libusermngr"
make clean -C /opt/dev/usermngr/src
make -C /opt/dev/usermngr/src

echo "Installing libusermngr"
cp -f /opt/dev/usermngr/src/libusermngr.so /usr/lib/bbfdm

# install periodicstats plugin
rm -rf /opt/dev/periodicstats
exec_cmd git clone -b devel --depth 1 https://dev.iopsys.eu/iopsys/periodicstats.git /opt/dev/periodicstats

echo "Compiling libperiodicstats"
make clean -C /opt/dev/periodicstats/
make -C /opt/dev/periodicstats/

echo "installing libperiodicstats"
cp -f /opt/dev/periodicstats/bbf_plugin/libperiodicstats.so /usr/lib/bbfdm

# install cwmpdm plugin
rm -rf /opt/dev/periodicstats
exec_cmd git clone -b devel --depth 1 https://dev.iopsys.eu/iopsys/icwmp.git /opt/dev/icwmp

echo "Compiling libcwmpdm"
cmake /opt/dev/icwmp/ -DWITH_OPENSSL=ON -DCMAKE_INSTALL_PREFIX=/
make -C /opt/dev/icwmp/

echo "installing libcwmpdm"
cp -f /opt/dev/icwmp/libcwmpdm.so /usr/lib/bbfdm

ls /usr/lib/bbfdm/
ls /etc/bbfdm/json/
