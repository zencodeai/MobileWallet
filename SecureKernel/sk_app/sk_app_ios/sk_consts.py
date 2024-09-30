import argparse
import json
import datetime
import builtins

from typing import List, Any, Tuple

# Create file and write list as json array
def write_json_array(file_name: str, data: List[Any]):
    with open(file_name, 'w') as f:
        json.dump(data, f, indent=4) 


# Parse command line arguments: -i <input file> -o <output file>
if __name__ == "__main__":
    # Create parser
    parser = argparse.ArgumentParser(description='Generate plugin constants file.')
    # Add arguments
    parser.add_argument('-i', '--input', help='Input file name', required=True)
    parser.add_argument('-o', '--output', help='Output file name', required=True)
    # Parse arguments
    args = parser.parse_args()
    # Print arguments
    print("Input file: " + args.input)
    print("Output file: " + args.output)
    # Open input file, read json data
    with open(args.input, 'r') as f:
        data_json = json.load(f)
        # Error codes list
        error_codes = [entry for entry in data_json if entry and entry['type'] == 'SKError']
        print (error_codes)
        # Commands list
        commands = [entry for entry in data_json if entry and entry['type'] == 'SKRndUInt32' and entry['name'].startswith('SK_CMD_')]
        print (commands)
        # State list
        states = [entry for entry in data_json if entry and entry['type'] == 'SKRndUInt32' and entry['name'].startswith('SK_CTX_')]
        print (states)
    # Create error codes file
    write_json_array(args.output + '/SKError.json', error_codes)
    # Create commands file
    write_json_array(args.output + '/SKCommand.json', commands)
    # Create states file
    write_json_array(args.output + '/SKState.json', states)
    