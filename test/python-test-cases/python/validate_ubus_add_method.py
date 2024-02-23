#!/usr/bin/python3

import sys
import ubus
import json

class TestArguments:
    """
    Class to hold test arguments.
    """
    def __init__(self, description, service, input, expected_error, output):
        self.description = description
        self.service = service
        self.input = input
        self.expected_error = expected_error
        self.output = output

def run_test(args):
    """
    Run a single test.
    """

    print("Running: " + args.description)

    out = ubus.call(args.service, "add", args.input)
    
    if isinstance(out, list) and out:
        out = out[0]
    else:
        print("FAIL: " + args.description)
        return
        
    res_len = len(out["results"])
    fault = out["results"][0]["fault"] if res_len and "fault" in out["results"][0] else 0
        
    if fault != args.expected_error:
        print("FAIL: " + args.description)
        return
        
    if args.expected_error == 0 and res_len == 0:
        print("FAIL: " + args.description)
        return
    
    # Check if output matches expected output
    if args.output != {}:
        if out == args.output:
            print("PASS: " + args.description)
        else:
            print("FAIL: " + args.description)
    else:
        print("PASS: " + args.description)

if __name__ == "__main__":
    # Check for correct command line arguments
    if len(sys.argv) != 2:
        print("Usage: {} <test_arguments_json>".format(sys.argv[0]))
        sys.exit(1)

    test_arguments_file = sys.argv[1]

    try:
        with open(test_arguments_file, 'r') as f:
            test_arguments_data = json.load(f)
            service_name = test_arguments_data.get("object", "bbfdm")
            args_list = [TestArguments(**test_case, service=service_name) for test_case in test_arguments_data["add"]]
    except FileNotFoundError:
        print("File not found:", test_arguments_file)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("Error parsing JSON:", e)
        sys.exit(1)
    
    ubus.connect()

    # Run tests for each set of arguments
    for args in args_list:
        run_test(args)
        
    ubus.disconnect()
