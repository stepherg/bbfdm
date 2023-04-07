#!/usr/bin/python3

import subprocess
import json

TEST_NAME = "BUG_3272"

print("Running: " + TEST_NAME)

def usp_get(path, proto = ""):
    path_arg = "{\"path\":\"" + path + "\",\"proto\":\"" + proto + "\"}"
    cmd = ['ubus', 'call', 'bbf', 'get', path_arg]

    out = subprocess.Popen(cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT)

    stdout,stderr = out.communicate()
    return stdout

# check fault code of invalid path
output = json.loads(usp_get("Device.USB.USBHosts.Host.[Enable==0].Device."))

for param in enumerate(output["parameters"]):
	assert param[1]["parameter"].endswith("DeviceNumberOfEntries") == False, "FAIL" + TEST_NAME

print("PASS: " + TEST_NAME)
