#!/usr/bin/python3

import ubus
import json
import pathlib
import shutil
import os

TEST_NAME = "Validate USPD Max MSG Len"
SHARED_LIB = "/builds/iopsys/uspd/test/libuspd_test.so"
DEST_DIR = "/usr/lib/bbfdm/"

print("Running: " + TEST_NAME)

sock = pathlib.Path('/var/run/ubus/ubus.sock')
if sock.exists():
    assert ubus.connect('/var/run/ubus/ubus.sock')
else:
    assert ubus.connect()

# Check get operation for Device. path succeed
out = ubus.call('usp.raw', 'get', {"path":"Device."}) 
assert isinstance(out[0]["parameters"][0], dict), "FAIL: get Device. on usp"

# Now copy the shared library
print("Copying shared library to /usr/lib/bbfdm")
try:
    shutil.copy(SHARED_LIB, DEST_DIR)
except:
    assert False, "FAIL: can't copy shared lib to /usr/lib/bbfdm"

# Again check get for Device. path should fail due to max msglen crossed
out = ubus.call('usp.raw', 'get', {"path":"Device.", "proto":"usp"})
fault = out[0]["fault"];
assert fault == 7003, "FAIL: " + TEST_NAME

# Now check usp.raw object should still present
out = ubus.objects()
objects = out.keys()
assert "usp.raw" in objects, "Object vanished"

# Again check get operation with less msglen should succeed
out = ubus.call('usp.raw', 'get', {"path":"Device.DeviceInfo."}) 
assert isinstance(out[0]["parameters"][0], dict), "FAIL: get Device. on usp"

# Now delete the shared library from /usr/lib/bbfdm
os.remove(DEST_DIR + "libuspd_test.so")

print("PASS: " + TEST_NAME)
