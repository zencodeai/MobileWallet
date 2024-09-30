import argparse
import json
import datetime
import builtins

from typing import List, Any, Tuple

# File header
def get_sk_plugin_const_header() -> str:
    # Get current date
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
/// 
/// FFI plugin constants
/// This file is auto-generated by the sk_plugin_consts.py script
/// Do not edit this file manually
/// Generated on: {date}
///\n
"""

class Attribute:
    def __init__(self, name: str, type: str):
        self._name = name
        self._type = type

    # Name getter
    @property
    def name(self) -> str:
        return self._name
    
    # Type getter
    @property
    def type(self) -> str:
        return self._type


# Error code attributes
AttributeError = [
    Attribute('name', 'String'),
    Attribute('code', 'int'),
    Attribute('category', 'String'),
    Attribute('description', 'String')
]

# Command attributes
AttributeCommand = [
    Attribute('name', 'String'),
    Attribute('value', 'int'),
    Attribute('description', 'String')
]

# State attributes
AttributeState = [
    Attribute('name', 'String'),
    Attribute('value', 'int'),
    Attribute('description', 'String')
]

# Convert capitalized string with underscores to lower camel case
def to_lower_camel_case(s: str) -> str:
    val = ''.join([word.capitalize() for word in s.split('_')])
    return val[0].lower() + val[1:]

# Convert value from json to dart type
def to_dart_type(value: Any) -> Tuple[str, Any]:
    match type(value):
        case builtins.int:
            return 'int', value
        case builtins.float:
            return 'double', value
        case builtins.bool:
            return 'bool', value
        case builtins.str:
            return 'String', '"' + value + '"'
        case _:
            raise Exception(f"Unsupported type: {type(value)}")

# Generate enum entry
def get_enum_entry(attributes: List[Attribute], entry: dict) -> str:
    entry_name = to_lower_camel_case(entry['name'])
    entry_args = '\n    ' + ',\n    '.join([f"{attribute.name}: {to_dart_type(entry[attribute.name])[1]}" for attribute in attributes])
    return f"{entry_name}({entry_args})"

# Generate enum entries
def get_enum_entries(attributes: List[Attribute], entries: list) -> List[str]:
    return [get_enum_entry(attributes, entry) for entry in entries]

# Generate class members
def get_class_members(attributes: List[Attribute]) -> List[str] :
    return [f"final {attribute.type} {attribute.name}" for attribute in attributes]

# Generate generative constructor arguments
def get_generative_constructor_args(attributes: List[Attribute]) -> List[str]:
    return [f"required this.{attribute.name}" for attribute in attributes]


# Class template for constants
def get_sk_plugin_const_class_template(name: str, valueName: str, description: str, attributes: list, entries: list) -> str:
    # Enum entries
    enum_entries = '  ' + ',\n  '.join(get_enum_entries(attributes, entries)) + ';\n'
    # Generative constructor arguments
    generative_constructor_args = '    ' + ',\n    '.join(get_generative_constructor_args(attributes))
    # Class members
    class_members = '  ' + ';\n  '.join(get_class_members(attributes)) + ';\n'
    # Create class template
    return f"""
///
/// {description}
///
enum {name} _B_

  /// Enum entries
{enum_entries}

  /// Generative constructor
  const {name}(_B_\n{generative_constructor_args}
  _E_);

  /// Class members
{class_members}

  /// Map code to {name} enum
  static {name} fromCode(int code) _B_
    return {name}.values
        .firstWhere((e) => e.{valueName} == code);
  _E_
_E_
""".replace('_B_', '{').replace('_E_', '}')

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
    # Create output file
    with open(args.output, 'w') as f:
        f.write(get_sk_plugin_const_header())
        # Write error codes
        f.write(get_sk_plugin_const_class_template('SKError', 'code', 'Error codes', AttributeError, error_codes))
        # Write commands
        f.write(get_sk_plugin_const_class_template('SKCommand', 'value', 'Commands', AttributeCommand, commands))
        # Write states
        f.write(get_sk_plugin_const_class_template('SKState', 'value', 'States', AttributeState, states))



