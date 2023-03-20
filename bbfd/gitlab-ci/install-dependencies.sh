#!/bin/bash

echo "install dependencies of uspd"
pwd

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip
exec_cmd pip3 install pexpect ubus
git config --global --add safe.directory ${PWD}
branch="$(git branch --show-current)"

# install libbbf
cd /opt/dev
rm -rf bbf

if [ -z "${BBF_TAR_URL}" ]; then
	if ! git clone -b ${branch} https://dev.iopsys.eu/iopsys/bbf.git; then
		exec_cmd git clone https://dev.iopsys.eu/iopsys/bbf.git
	fi

	cd bbf
	echo "BBF Upstream Hash ${UPSTREAM_BBF_SHA}, uspd branch ${branch}"
	if [ -n "${UPSTREAM_BBF_SHA}" ]; then
		exec_cmd git checkout ${UPSTREAM_BBF_SHA}
	fi

	git log -1
	source ./gitlab-ci/shared.sh
	install_libbbf
	./gitlab-ci/setup.sh
else
	echo "## Installing upstream libbbf release from [${BBF_TAR_URL}] ##"
	mkdir -p bbf
	cd bbf
	exec_cmd wget -q ${BBF_TAR_URL} -O bbf.sh
	chmod +x bbf.sh
	./bbf.sh --prefix=/ --exclude-subdir --skip-license
	ldconfig
	cd ..
fi

cd -
# install usermngr plugin
rm -rf /opt/dev/usermngr
exec_cmd git clone https://dev.iopsys.eu/iopsys/usermngr.git /opt/dev/usermngr

echo "Compiling libusermngr"
make clean -C /opt/dev/usermngr/src
make -C /opt/dev/usermngr/src

echo "Installing libusermngr"
cp -f /opt/dev/usermngr/src/libusermngr.so /usr/lib/bbfdm

