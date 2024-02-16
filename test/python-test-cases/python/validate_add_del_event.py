#!/usr/bin/python3

import os
import sys
import ubus
import json

# Global variable to track UBUS disconnection
UBUS_DISCONNECT = 0

class TestArguments:
    """
    Class to hold test arguments.
    """
    def __init__(self, description, config_path, objects_to_look):
        self.description = description
        self.config_path = config_path
        self.objects_to_look = objects_to_look

def callback(event, data):
    """
    Callback function to handle UBUS events.
    """
    global UBUS_DISCONNECT
    # Check if the objects to look for are in the instances list
    if set(args.objects_to_look).issubset(set(data['instances'])):
        # Mark UBUS as disconnected
        UBUS_DISCONNECT = 1
        # Disconnect from UBUS
        ubus.disconnect()

def run_global_test(args, event_name, path_1, path_2):
    """
    Run a global test.
    """
    global UBUS_DISCONNECT

    # Connect to UBUS
    ubus.connect()
    UBUS_DISCONNECT = 0

    # Listen for UBUS events
    ubus.listen((event_name, callback))

    # Force change in schema by moving dependency file
    os.rename(path_1, path_2)

    # Run UBUS loop with a timeout
    ubus.loop(timeout=35000)
    
    # If UBUS is still connected, disconnect and mark test as failed
    if UBUS_DISCONNECT == 0:
        ubus.disconnect()
        return -1

    return 0

def run_test(args):
    """
    Run a single test.
    """
    print("Running: " + args.description)

    # Test deletion of object
    res = run_global_test(args, "bbfdm.DelObj", args.config_path, "/tmp/bbfdm_test_1")
    if res != 0:
        print("FAIL: " + args.description)
        return

    # Test addition of object
    res = run_global_test(args, "bbfdm.AddObj", "/tmp/bbfdm_test_1", args.config_path)
    if res != 0:
        print("FAIL: " + args.description)
        return
        
    print("PASS: " + args.description)

if __name__ == "__main__":
    # Check for correct command line arguments
    if len(sys.argv) != 2:
        print("Usage: {} <test_arguments_json>".format(sys.argv[0]))
        sys.exit(1)

    test_arguments_file = sys.argv[1]

    try:
        # Load test arguments from JSON file
        with open(test_arguments_file, 'r') as f:
            test_arguments_data = json.load(f)
            args_list = [TestArguments(**event) for event in test_arguments_data["events"]]
    except FileNotFoundError:
        print("File not found:", test_arguments_file)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("Error parsing JSON:", e)
        sys.exit(1)

    # Run tests for each set of arguments
    for args in args_list:
        run_test(args)
