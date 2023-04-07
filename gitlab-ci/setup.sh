#!/bin/bash

echo "preparation script"
pwd

# link '/bin/sh' to bash instead of dash
ln -sf bash /bin/sh

cp -r ./test/files/etc/* /etc/
cp -r ./test/files/usr/* /usr/
cp -r ./test/files/var/* /var/
cp -r ./test/files/tmp/* /tmp/
cp -r ./test/files/lib/* /lib/

cp ./gitlab-ci/iopsys-supervisord.conf /etc/supervisor/conf.d/

ls /etc/config/

supervisorctl shutdown
supervisord -c /etc/supervisor/supervisord.conf
