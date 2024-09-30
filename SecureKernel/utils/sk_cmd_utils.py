
# Class to serialize a variable list of arguments to a bytestring
class SKArgsToBytes:

    def int64_to_bytes(self, value):
        return value.to_bytes(8, byteorder='big', signed=True)
    

    def __init__(self, *args):
        self.args = args

    
