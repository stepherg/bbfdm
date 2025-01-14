#!/bin/bash

echo "install unified daemon dependencies"

source ./gitlab-ci/shared.sh

dst=$(pwd)

# libeasy for ethmngr
cd /opt/dev
rm -fr libeasy
mkdir -p /usr/include/easy
git clone -b devel https://dev.iopsys.eu/iopsys/libeasy.git
cd libeasy
make
cp -a libeasy*.so* /usr/lib
cp -a *.h /usr/include/easy/

# libethernet for ethmngr
cd /opt/dev
rm -fr libethernet
git clone -b devel https://dev.iopsys.eu/iopsys/libethernet.git
cd libethernet
make PLATFORM=TEST
cp ethernet.h /usr/include
cp -a libethernet*.so* /usr/lib
sudo ldconfig

cd ${dst}
pwd
