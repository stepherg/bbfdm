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

out = ubus.call('usp.raw', 'get', {"path":"Device."})
assert isinstance(out[0]["parameters"][0], dict), "FAIL: get Device. on usp.raw"

# Check get operation for Device. path succeed
out = ubus.call('usp', 'get', {"path":"Device."})
assert isinstance(out[0]['Device'], dict), "FAIL: get Device. on usp"

ubus.disconnect()
print("PASS: " + TEST_NAME)
