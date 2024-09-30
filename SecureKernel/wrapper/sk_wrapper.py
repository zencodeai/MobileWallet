import ctypes
import os
import sys

from sk_utils import SKDefinitions, SKConfig
from sk_client import RestClient

# Get platform dependent library extension
if sys.platform == "win32":
    lib_ext = ".dll"
elif sys.platform == "darwin":
    lib_ext = ".dylib"
else:
    lib_ext = ".so"

# Get file path of the native library
file_path = os.path.dirname(os.path.realpath(__file__))
lib_path = os.path.join(file_path, f"../build/libsk{lib_ext}")

# Load the native library
sk_lib = ctypes.CDLL(lib_path)

# Define the function prototype
sk_call = sk_lib.sk_call
sk_call.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # in
    ctypes.c_size_t,                 # in_len
    ctypes.POINTER(ctypes.c_ubyte),  # out
    ctypes.POINTER(ctypes.c_size_t)  # out_len
]
sk_call.restype = None

def call_sk(input_data, max_output_size):
    # Convert input data to a ctypes array
    input_data = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    # Allocate the output buffer
    output_data = (ctypes.c_ubyte * max_output_size)()
    output_size = ctypes.c_size_t(max_output_size)

    # Call the native function
    sk_call(input_data, len(input_data), output_data, ctypes.byref(output_size))

    # Convert the output buffer to a Python array
    output_data = bytes(output_data[:output_size.value])

    return output_data


class SKCallArgs:
    # SK call arguments

    def __init__(self, cmd: SKDefinitions.SKDefinition, args: bytearray):
        self.cmd = cmd
        self.args = args

    def __bytes__(self):
        # Serialize the arguments to a bytestring
        return bytes(self.cmd.value.to_bytes(4, byteorder='little', signed=False) + (self.args if self.args else bytearray()))


class SKCallArgsCmd(SKCallArgs):
    # SK call arguments, cmd only

    def __init__(self, cmd: SKDefinitions.SKDefinition):
        super().__init__(cmd, None)


class SKCallArgsCmdOnlineTX(SKCallArgs):
    # SK Call arguments for online TX

    def __init__(self, cmd: SKDefinitions.SKDefinition, amount: int, cuid: bytearray):

        # Generate args bytearray
        args = amount.to_bytes(8, byteorder='little', signed=True) + cuid

        super().__init__(cmd, args)


class SKCallArgsMsg(SKCallArgs):
    # SK call arguments, cmd and msg

    def __init__(self, cmd: SKDefinitions.SKDefinition, msg: bytearray):
        super().__init__(cmd, msg)


class SKCallException(Exception):
    # SK call exception

    def __init__(self, err: SKDefinitions.SKDefinition):
        self.err = err

    def __str__(self):
        return f"SK call error: {self.err.name} (0x{self.err.code:08X}): {self.err.description}"


class SKCall:
    # SK client call class

    def __init__(self, defs : SKDefinitions, cmd: SKDefinitions.SKDefinition, max_output_size: int, args: SKCallArgs = None):
        self.defs = defs
        self.args = args if args else SKCallArgsCmd(cmd)
        self.max_output_size = max_output_size

    def __call__(self):

        input_data = bytes(self.args)
        output_data = call_sk(input_data, self.max_output_size)

        if len(output_data) == 8:
            err_code = int.from_bytes(output_data[4:], byteorder='little', signed=False)
            err = self.defs.get_error(err_code)
            raise SKCallException(err)

        return output_data


class SKCallStatus(SKCall):
    # SK get status call class

    def __init__(self, defs: SKDefinitions):
        super().__init__(defs, defs.SK_CMD_STATUS, 8)

    def __call__(self):
        output_data = super().__call__()
        if len(output_data) != 4:
            raise SKCallException(self.defs.SK_ERROR_FAILED)
        res_int = int.from_bytes(output_data, byteorder='little', signed=False)
        return self.defs.get_status(res_int)


class SKCallProcessMsg(SKCall):
    # SK process message call class

    def __init__(self, defs: SKDefinitions, msg: bytearray, max_output_size: int):
        super().__init__(defs, defs.SK_CMD_PROCESS_MSG, max_output_size, SKCallArgsMsg(defs.SK_CMD_PROCESS_MSG, msg))

    def __call__(self):
        return super().__call__()
