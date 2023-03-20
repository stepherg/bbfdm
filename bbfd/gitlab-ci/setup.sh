#!/bin/bash

echo "preparation script"
pwd

cp -r ./test/files/* /
cp ./gitlab-ci/iopsys-supervisord.conf /etc/supervisor/conf.d/

ls /etc/config/
ls /usr/share/rpcd/schemas/
ls /etc/supervisor/conf.d/

supervisorctl shutdown
supervisord -c /etc/supervisor/supervisord.conf
