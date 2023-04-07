#!/usr/bin/python3

import subprocess
import json

TEST_NAME = "BUG_3536"

print("Running: " + TEST_NAME)

def usp_get(path, proto = ""):
    path_arg = "{\"path\":\"" + path + "\",\"proto\":\"" + proto + "\"}"
    cmd = ['ubus', 'call', 'usp.raw', 'get', path_arg]

    out = subprocess.Popen(cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT)

    stdout,stderr = out.communicate()
    return stdout

# check fault code of invalid path
output = json.loads(usp_get("Device", "usp"))
assert output["fault"] == 7026, "Wrong fault code"

# check fault code of invalid path
output = json.loads(usp_get("Device", "cwmp"))
assert output["fault"] == 9005, "Wrong fault code for cwmp"

print("PASS: " + TEST_NAME)
