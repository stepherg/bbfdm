#!/usr/bin/python3

import subprocess
import json

TEST_NAME = "BUG_3536"

print("Running: " + TEST_NAME)

def bbf_get(path, proto = ""):
    path_arg = "{\"path\":\"" + path + "\", \"optional\":{\"format\":\"raw\", \"proto\":\"" + proto + "\"}}"
    cmd = ['ubus', 'call', 'bbf', 'get', path_arg]

    out = subprocess.Popen(cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT)

    stdout,stderr = out.communicate()
    return stdout

# check fault code of invalid path
output = json.loads(bbf_get("Device", "usp"))
assert output["results"][0]["fault"] == 7026, "Wrong fault code"

# check fault code of invalid path
output = json.loads(bbf_get("Device", "cwmp"))
assert output["results"][0]["fault"] == 9005, "Wrong fault code for cwmp"

# check fault code of invalid path
output = json.loads(bbf_get("Device"))
assert output["results"][0]["fault"] == 9005, "Wrong fault code for default proto"

print("PASS: " + TEST_NAME)
