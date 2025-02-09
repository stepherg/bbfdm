#!/bin/bash

echo "# Preparation script ..."

# link '/bin/sh' to bash instead of dash
ln -sf bash /bin/sh

echo "Installing bbfdm rpcd utilities"
cp -r ./test/files/etc/* /etc/
cp -r ./test/files/usr/* /usr/
cp -r ./test/files/var/* /var/
cp -r ./test/files/tmp/* /tmp/
cp -r ./test/files/lib/* /lib/

mkdir -p /tmp/bbfdm/.bbfdm /tmp/bbfdm/.cwmp /tmp/bbfdm/.usp
mkdir -p /usr/libexec/rpcd/

cp utilities/files/usr/libexec/rpcd/bbf.diag /usr/libexec/rpcd/
cp utilities/files/usr/libexec/rpcd/bbf.secure /usr/libexec/rpcd/

cp ./gitlab-ci/core_service.conf /etc/supervisor/conf.d/
cp ./gitlab-ci/reload_service.conf /etc/supervisor/conf.d/

if [ -n "$1" ]; then
	cp ./gitlab-ci/micro_service.conf /etc/supervisor/conf.d/
fi

rm -f /etc/bbfdm/dmmap/*

echo "Starting base services..."
supervisorctl reread
supervisorctl update
sleep 10

ubus list
