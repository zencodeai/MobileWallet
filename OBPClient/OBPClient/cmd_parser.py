import argparse
from typing import NoReturn


class OBPArgumentParser(argparse.ArgumentParser):
    # Local argument parser

    def exit(self, status: int = ..., message: str | None = ...) -> NoReturn:
        # Interactive mode: prevent exit on help or parsing error
        if status:
            print('Argument parsing error {} : {}'.format(status, message if message else '???'))
        # Else silent
