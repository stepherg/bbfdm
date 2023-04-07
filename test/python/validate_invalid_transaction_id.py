#!/usr/bin/python3

import ubus
import json
import pathlib

TEST_NAME = "Validate fault on invalid transaction id with usp.raw"

print("Running: " + TEST_NAME)

def fault_wrong_transaction(cmd, param, efault):
    out = ubus.call("usp.raw", cmd, param)
    assert out[0]["fault"] == efault, "FAIL: for " + cmd + str(param) + " output " + str(out)


sock = pathlib.Path('/var/run/ubus/ubus.sock')
if sock.exists ():
    assert ubus.connect('/var/run/ubus/ubus.sock')
else:
    assert ubus.connect()

fault_wrong_transaction("set", {"path":"Device.Users.User.1.Username", "value":"abc", "transaction_id":1234}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.Username", "value":"abc", "proto":"usp", "transaction_id":1234}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.Username", "value":"abc", "proto":"cwmp", "transaction_id":1234}, 9002)

fault_wrong_transaction("set", {"path":"Device.Users.User.1.", "values":{"Username":"abc"}, "transaction_id":1234}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.", "values":{"Username":"abc"}, "transaction_id":1234, "proto":"usp"}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.", "values":{"Username":"abc"}, "transaction_id":1234, "proto":"cwmp"}, 9002)

fault_wrong_transaction("add_object", {"path":"Device.Users.User.", "transaction_id":1234}, 7003)
fault_wrong_transaction("add_object", {"path":"Device.Users.User.", "transaction_id":1234, "proto":"usp"}, 7003)
fault_wrong_transaction("add_object", {"path":"Device.Users.User.", "transaction_id":1234, "proto":"cwmp"}, 9002)

fault_wrong_transaction("del_object", {"path":"Device.Users.User.1", "transaction_id":1234}, 7003)
fault_wrong_transaction("del_object", {"path":"Device.Users.User.1", "transaction_id":1234, "proto":"usp"}, 7003)
fault_wrong_transaction("del_object", {"path":"Device.Users.User.1", "transaction_id":1234, "proto":"cwmp"}, 9002)


fault_wrong_transaction("setm_values", {"pv_tuple":[{"path":"Device.Users.User.1.Username", "value":"abc"}], "transaction_id":1234}, 7003)
fault_wrong_transaction("setm_values", {"pv_tuple":[{"path":"Device.Users.User.1.Username", "value":"abc"}], "transaction_id":1234, "proto":"usp"}, 7003)
fault_wrong_transaction("setm_values", {"pv_tuple":[{"path":"Device.Users.User.1.Username", "value":"abc"}], "transaction_id":1234, "proto":"cwmp"}, 9002)

ubus.disconnect()

print("PASS: " + TEST_NAME)
