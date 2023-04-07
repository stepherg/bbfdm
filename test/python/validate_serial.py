#!/usr/bin/python3

import subprocess
import json

TEST_NAME = "Get serial number"

print("Running: " + TEST_NAME)

out = subprocess.Popen(['ubus', 'call', 'bbf', 'get', '{"path":"Device.DeviceInfo.SerialNumber", "optional":{"format":"raw"}}'], 
           stdout=subprocess.PIPE, 
           stderr=subprocess.STDOUT)

stdout,stderr = out.communicate()

jout = json.loads(stdout)

assert jout["results"][0]["data"] == "000000001", "FAIL: serial number mismatch"

print("PASS: " + TEST_NAME)
