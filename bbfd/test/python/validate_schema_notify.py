#!/usr/bin/python3

import pexpect
import os

print("Running: Schema updater notification validation")

ret = 1
child = pexpect.spawn('ubus monitor')

# force change in schema, by removing dependency uci file
os.rename("/etc/config/users", "/etc/config/users_1")

try:
    ret = child.expect('notify', timeout=35)
except:
    print("FAIL: Schema updater notification")

if ret == 0:
    try:
        ret = child.expect('schema_update_available')
    except:
        print("FAIL: Schema updater notification")

# Revert back uci changes
os.rename("/etc/config/users_1", "/etc/config/users")

if ret == 0:
    print("PASS: Schema updater notification")

exit(ret)
