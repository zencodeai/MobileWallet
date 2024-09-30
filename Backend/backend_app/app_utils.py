import json
from typing import TextIO

# Secure kernel definitions 
class SKDefinitions:

    # SK definition
    class SKDefinition:
        
        def __init__(self, **entries):
            self.__dict__.update(entries)


    # SK definitions
    def __init__(self, **entries):
        self.__dict__.update(entries)
        self.error_dict = {v.code: v for k, v in entries.items() if v.type == 'SKError'}
        self.status_dict = {v.value: v for k, v in entries.items() if k.startswith('SK_CTX_')}

    def __getitem__(self, key):
        return self.defs[key]

    def __iter__(self):
        return iter(self.defs)

    def __len__(self):
        return len(self.defs)

    def get_error(self, code: int):
        # Get error definition from code
        return self.error_dict[code] if code in self.error_dict else self.SK_ERROR_FAILED
    
    def get_status(self, status: int):
        # Get status definition from code
        return self.status_dict[status] if status in self.status_dict else self.SK_CTX_INV

    @classmethod
    def load_definitions(cls, defs_fp: TextIO):
        # Load definitions from JSON file
        defs_json = json.load(defs_fp)
        defs_dict = {e['name']: SKDefinitions.SKDefinition(**e) for e in defs_json if e}
        return SKDefinitions(**defs_dict)


class AppContext:
    # Application context

    def __init__(self):
        # Load SK definitions
        with open('./data/sk_definitions.json', 'r') as defs_fp:
            sk_defs = SKDefinitions.load_definitions(defs_fp)
        self._sk_defs = sk_defs

    @property
    def sk_defs(self):
        return self._sk_defs
