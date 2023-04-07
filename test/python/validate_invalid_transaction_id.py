#!/usr/bin/python3

import ubus
import json
import pathlib

TEST_NAME = "Validate fault on invalid transaction id with bbf"

print("Running: " + TEST_NAME)

def fault_wrong_transaction(cmd, param, efault):
    out = ubus.call("bbf", cmd, param)
    assert out[0]['results'][0]['fault'] == efault, "FAIL: for " + cmd + str(param) + " output " + str(out)


sock = pathlib.Path('/var/run/ubus/ubus.sock')
if sock.exists ():
    assert ubus.connect('/var/run/ubus/ubus.sock')
else:
    assert ubus.connect()

fault_wrong_transaction("set", {"path":"Device.Users.User.1.Username", "value":"abc", "optional":{"format":"raw", "transaction_id":1234}}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.Username", "value":"abc", "optional":{"format":"raw", "proto":"usp", "transaction_id":1234}}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.Username", "value":"abc", "optional":{"format":"raw", "proto":"cwmp", "transaction_id":1234}}, 9002)

fault_wrong_transaction("set", {"path":"Device.Users.User.1.", "obj_path":{"Username":"abc"}, "optional":{"format":"raw", "transaction_id":1234}}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.", "obj_path":{"Username":"abc"}, "optional":{"format":"raw", "transaction_id":1234, "proto":"usp"}}, 7003)
fault_wrong_transaction("set", {"path":"Device.Users.User.1.", "obj_path":{"Username":"abc"}, "optional":{"format":"raw", "transaction_id":1234, "proto":"cwmp"}}, 9002)

fault_wrong_transaction("add", {"path":"Device.Users.User.", "optional":{"format":"raw", "transaction_id":1234}}, 7003)
fault_wrong_transaction("add", {"path":"Device.Users.User.", "optional":{"format":"raw", "transaction_id":1234, "proto":"usp"}}, 7003)
fault_wrong_transaction("add", {"path":"Device.Users.User.", "optional":{"format":"raw", "transaction_id":1234, "proto":"cwmp"}}, 9002)

fault_wrong_transaction("del", {"path":"Device.Users.User.1", "optional":{"format":"raw", "transaction_id":1234}}, 7003)
fault_wrong_transaction("del", {"path":"Device.Users.User.1", "optional":{"format":"raw", "transaction_id":1234, "proto":"usp"}}, 7003)
fault_wrong_transaction("del", {"path":"Device.Users.User.1", "optional":{"format":"raw", "transaction_id":1234, "proto":"cwmp"}}, 9002)

ubus.disconnect()

print("PASS: " + TEST_NAME)
