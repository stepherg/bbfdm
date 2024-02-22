#!/bin/bash

echo "# Preparation script ..."

# link '/bin/sh' to bash instead of dash
ln -sf bash /bin/sh

cp -r ./test/files/etc/* /etc/
cp -r ./test/files/usr/* /usr/
cp -r ./test/files/var/* /var/
cp -r ./test/files/tmp/* /tmp/
cp -r ./test/files/lib/* /lib/

cp ./gitlab-ci/core_service.conf /etc/supervisor/conf.d/

rm -f /etc/bbfdm/dmmap/*

echo "Starting base services..."
supervisorctl reread
supervisorctl update
sleep 10
