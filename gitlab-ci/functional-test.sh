#!/bin/bash

echo "$0 preparation script"
pwd

source ./gitlab-ci/shared.sh

echo "Starting services..."
cp ./gitlab-ci/bbfdm_services.conf /etc/supervisor/conf.d/

supervisorctl reread
supervisorctl update
sleep 10

supervisorctl status all
exec_cmd ubus wait_for bbfdm

# Test ubus bbfdm 'notify_event' method
./test/python-test-cases/python/validate_ubus_notify_event_method.py test/python-test-cases/json/ubus_notify_event_method.json

# Test 'bbfdm.event' event callback
./test/python-test-cases/python/validate_event_callback.py test/python-test-cases/json/event_callback.json

# Test 'bbfdm.AddObj' & 'bbfdm.DelObj' event
./test/python-test-cases/python/validate_add_del_event.py test/python-test-cases/json/add_del_event.json

# Test ubus bbfdm 'get' method
./test/python-test-cases/python/validate_ubus_get_method.py test/python-test-cases/json/ubus_get_method.json

# Test ubus bbfdm 'instances' method
./test/python-test-cases/python/validate_ubus_schema_method.py test/python-test-cases/json/ubus_schema_method.json

supervisorctl stop all
supervisorctl status

echo "Functional Test :: PASS"
