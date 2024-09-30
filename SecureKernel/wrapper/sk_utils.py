import json
import secrets
import base64
from dataclasses import dataclass
from typing import TextIO


@dataclass
class SKConfig:
    # SK Client configuration
    description: str
    protocol: str
    prefix: str
    host: str
    port: int

    @classmethod
    def get_config(cls, config_fp: TextIO):
        # Create config object from JSON encoded file
        config_json = json.load(config_fp)
        return SKConfig(**config_json)


@dataclass
class SKMessage:
    # SK message class
    session_id: str
    data: str


def get_rnd_receipt():
    # Get random receipt
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')


# Definitions 
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
