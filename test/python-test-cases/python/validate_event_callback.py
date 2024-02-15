#!/usr/bin/python3

import sys
import ubus
import json

# Global variable to track UBUS disconnection
UBUS_DISCONNECT = 0

class TestArguments:
    """
    Class to hold test arguments.
    """
    def __init__(self, description, event_name, inputs, output):
        self.description = description
        self.event_name = event_name
        self.inputs = inputs
        self.output = output

def callback(event, data):
    """
    Callback function to handle UBUS events.
    """
    global UBUS_DISCONNECT
    if data == args.output:
        print("PASS: " + args.description)
    else:
        print("FAIL: " + args.description)
    ubus.disconnect()
    UBUS_DISCONNECT = 1

def run_test(args):
    """
    Run a single test.
    """
    global UBUS_DISCONNECT

    print("Running: " + args.description)

    # Connect to UBUS
    ubus.connect()
    UBUS_DISCONNECT = 0

    # Listen for UBUS events
    ubus.listen(("bbfdm.event", callback))

    # Send UBUS event with inputs
    ubus.send(args.event_name, args.inputs)

    # Run UBUS loop with a timeout
    ubus.loop(timeout=5000)
    
    # If UBUS is still connected, disconnect and mark test as failed
    if UBUS_DISCONNECT == 0:
        ubus.disconnect()
        print("FAIL: " + args.description)

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
