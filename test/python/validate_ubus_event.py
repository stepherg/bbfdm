#!/usr/bin/python3

import ubus
import json
import pathlib

TEST_NAME = "Validate ubus event bbf"

print("Running: " + TEST_NAME)

def callback(event, data):
    print("PASS: " + TEST_NAME)
    ubus.disconnect()
    exit(0)
    
sock = pathlib.Path('/var/run/ubus/ubus.sock')
if sock.exists ():
    assert ubus.connect('/var/run/ubus/ubus.sock')
else:
    assert ubus.connect()

ubus.listen(("bbfdm.event", callback))

ubus.call("bbfdm", "notify_event", {"name":"Device.LocalAgent.TransferComplete!", "input":[{"path":"Command","data":"Backup()","type":"xsd:string"},{"path":"CommandKey","data":"","type":"xsd:string"}]})

ubus.loop()

ubus.disconnect()

print("FAIL: " + TEST_NAME)
