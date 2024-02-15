#!/usr/bin/python3

import pexpect
import os

print("Running: Schema updater notification validation")

ret = 1
child = pexpect.spawn('ubus monitor')

# force change in schema, by removing dependency uci file
os.rename("/etc/config/dropbear", "/etc/config/dropbear_1")

try:
    ret = child.expect('notify', timeout=40)
except:
    print("FAIL: Schema updater notification")

if ret == 0:
    try:
        ret = child.expect('bbfdm.DelObj')
    except:
        print("FAIL: Schema updater notification")

# Revert back uci changes
os.rename("/etc/config/dropbear_1", "/etc/config/dropbear")

if ret == 0:
    try:
        ret = child.expect('notify', timeout=40)
    except:
        print("FAIL: Schema updater notification")
        
if ret == 0:
    try:
        ret = child.expect('bbfdm.AddObj')
    except:
        print("FAIL: Schema updater notification")

if ret == 0:        
    print("PASS: Schema updater notification")

exit(ret)
