#!/bin/bash

echo "preparation script"

pwd

cp -r ./test/files/etc/* /etc/
cp -r ./test/files/usr/* /usr/
cp -r ./test/files/var/* /var/
cp -r ./test/files/tmp/* /tmp/
cp -r ./test/files/lib/* /lib/

cp ./gitlab-ci/iopsys-supervisord.conf /etc/supervisor/conf.d/

ls /etc/config/
ls /etc/supervisor/conf.d/
