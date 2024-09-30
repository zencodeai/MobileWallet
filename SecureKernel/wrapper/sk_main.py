import cmd
import argparse
from dataclasses import dataclass, field

from sk_wrapper import SKCallStatus
from sk_provision import SKCallProvision
from sk_balance import SKCallBalanceInit
from sk_online import SKCallOnline
from sk_transaction import SKCallTransaction
from sk_utils import SKConfig, SKDefinitions
from sk_client import RestClient

def parse_args():
    # Process command line arguments

    # Parser
    parser = argparse.ArgumentParser(
        prog='SK E2E test wrapper',
        description='Secure kernel end-2-end test wrapper')

    # Add config argument
    parser.add_argument(
        '-c',
        '--config',
        default='sk_wrapper.cfg',
        type=argparse.FileType('r'),
        help='Path to JSON parameters file')

    # Add definitions argument
    parser.add_argument(
        '-d',
        '--definitions',
        default='sk_definitions.json',
        type=argparse.FileType('r'),
        help='Path to JSON definition file')

    # Add verbose argument
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Verbose output')
    return parser.parse_args()


class SKCmdMain(cmd.Cmd):
    # SK client command prompt class
    prompt = 80 * '-' + '\n> '

    def __init__(self, cfg: SKConfig, defs: SKDefinitions):
        super().__init__()
        self.cfg = cfg
        self.defs = defs
        self.client = RestClient(cfg)
        self.intro = f"{self.cfg.description}\n"

    def do_status(self, arg):
        """Get SK client status"""
        print('- Status ')
        call = SKCallStatus(self.defs)
        status = call()
        print(f"Status: {status.name} (0x{status.value:08X}): {status.description})")

    def do_provision(self, arg):
        """Provision SK client"""
        print(f'- Provision {arg}')
        call = SKCallProvision(arg, self.client, self.defs)
        call()

    def do_balance_init(self, arg):
        """Initialize SK client balance"""
        print(f'- Balance init {arg}')
        call = SKCallBalanceInit(arg, self.client, self.defs)
        call()

    def do_online(self, arg):
        """Create SK client online session"""
        # Delete session_id if exists
        if hasattr(self, 'session_id'):
            delattr(self, 'session_id')
        print(f'- Online {arg}')
        call = SKCallOnline(arg, self.client, self.defs)
        self.session_id = call()

    def do_tx(self, arg):
        """Process SK client transaction"""
        print(f'- Tx {arg}')
        if not hasattr(self, 'session_id'):
            print('No online session')
            return False
        call = SKCallTransaction(self.session_id, arg, self.client, self.defs)
        call()
    
    def do_quit(self, arg):
        """Exit SK manager command shell"""
        print('- Exit ')
        return True
    
    def do_EOF(self, arg):
        """Exit SK manager command shell"""
        print('- Exit ')
        return True
    
    # Process cmd exceptions
    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except Exception as e:
            print(e)
            return False


def main():
    # Application entry point
    args = parse_args()
    cfg = SKConfig.get_config(args.config)
    defs = SKDefinitions.load_definitions(args.definitions)
    SKCmdMain(cfg, defs).cmdloop()

# entry point
if __name__ == '__main__':
    main()
