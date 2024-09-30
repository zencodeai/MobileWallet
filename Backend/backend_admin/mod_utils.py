import argparse
from dataclasses import dataclass
from typing import NoReturn


@dataclass
class AdminCfg:
    # Admin client configuration
    description: str = 'Backend admin client'
    protocol: str = 'http://'
    prefix: str = '/api/v1/admin'
    host: str = 'localhost'
    port: int = 8000
    dataset: str = 'data/dataset.json'


class CmdArgumentParser(argparse.ArgumentParser):
    # Local argument parser

    def exit(self, status: int = ..., message: str | None = ...) -> NoReturn:
        # Interactive mode: prevent exit on help or parsing error
        if status:
            print('Argument parsing error {} : {}'.format(status, message if message else '???'))
        # Else silent
