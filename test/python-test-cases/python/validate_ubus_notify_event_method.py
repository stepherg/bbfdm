#!/usr/bin/python3

import sys
import ubus
import json

class TestArguments:
    """
    Class to hold test arguments.
    """
    def __init__(self, description, service, method, input, output):
        self.description = description
        self.service = service
        self.method = method
        self.input = input
        self.output = output

def callback(event, data):
    """
    Callback function to handle UBUS events.
    """
    if data == args.output:
        print("PASS: " + args.description)
    else:
        print("FAIL: " + args.description)
    ubus.disconnect()
    exit(0)

def run_test(args):
    """
    Run a single test.
    """

    print("Running: " + args.description)

    ubus.connect()

    ubus.listen(("bbfdm.event", callback))

    ubus.call(args.service, args.method, args.input)

    # Run UBUS loop with a timeout
    ubus.loop(timeout=5000)

    ubus.disconnect()
    print("FAIL: " + args.description)

if __name__ == "__main__":
    # Check for correct command line arguments
    if len(sys.argv) != 2:
        print("Usage: {} <test_arguments_json>".format(sys.argv[0]))
        sys.exit(1)

    test_arguments_file = sys.argv[1]

    try:
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
