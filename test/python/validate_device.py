#!/usr/bin/python3

import ubus
import pathlib
import subprocess
import json

TEST_NAME = "Get Device."

print("Running: " + TEST_NAME)

sock = pathlib.Path('/var/run/ubus/ubus.sock')
if sock.exists():
    assert ubus.connect('/var/run/ubus/ubus.sock')
else:
    assert ubus.connect()

out = ubus.call('bbf', 'get', {"path":"Device.", "optional":{"format":"raw"}})
assert isinstance(out[0]["results"][0], dict), "FAIL: get Device. on bbf with raw format"

# Check get operation for Device. path succeed
out = ubus.call('bbf', 'get', {"path":"Device."})
assert isinstance(out[0]['Device'], dict), "FAIL: get Device. on bbf with pretty format"

ubus.disconnect()
print("PASS: " + TEST_NAME)
