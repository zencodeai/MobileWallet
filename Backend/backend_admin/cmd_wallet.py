import argparse
from dataclasses import dataclass
from mod_utils import AdminCfg, CmdArgumentParser
from mod_client import RestClient

@dataclass
class WalletCreate:
    # Wallet create request
    name: str
    description: str
    balance: int
    owner_id: int


class CmdWallet:
    # Wallets management commands

    def _get_parser(this):
        # Build args parser
        parser = CmdArgumentParser(prog='CmdWallet', exit_on_error=False)
        subparser = parser.add_subparsers(dest='cmd', required=True, help='admin commands')
        # Help sub-parser
        subparser.add_parser('help', help='print help')
        # Create sub-parser
        parser_create = subparser.add_parser('create', help='create new wallet for holder')
        parser_create.add_argument(
			'-i',
			'--holder',
			type=int,
            required=True,
			help='Holder id'
		)
        parser_create.add_argument(
			'-n',
			'--name',
			type=str,
            nargs='+',
            required=True,
			help='Wallet name, must be unique'
		)
        parser_create.add_argument(
			'-d',
			'--description',
			type=str,
            nargs='+',
            default=['test', 'wallet'],
			help='Wallet description'
		)
        parser_create.add_argument(
			'-b',
			'--balance',
			type=int,
            default=1000,
			help='Initial balance'
		)
        # list sub-parser
        parser_list = subparser.add_parser('list', help='get wallet list for holder')
        parser_list.add_argument(
			'-i',
			'--holder',
            dest='holder',
			type=int,
            required=True,
			help='Holder id'
		)
        # Get sub-parser
        parser_get = subparser.add_parser('get', help='get wallet by id')
        parser_get.add_argument(
			'-i',
			'--id',
			type=int,
            required=True,
			help='Wallet id'
		)
        # Delete sub-parser
        parser_delete = subparser.add_parser('delete', help='delete wallet by id')
        parser_delete.add_argument(
			'-i',
			'--id',
			type=int,
            required=True,
			help='Wallet id'
		)
        return parser

    def __init__(self, admin_cfg: AdminCfg, rest_client: RestClient):
        # Class constructor
        self.admin_cfg = admin_cfg
        self.rest_client = rest_client
        self.parser = self._get_parser()

    def _do_create(self, arg):
        # Execute command
        wallet_create = WalletCreate(
            name=' '.join(arg.name),
            description=' '.join(arg.description),
            balance=arg.balance,
            owner_id=arg.holder
        )
        rsp = self.rest_client.api_put('wallet', wallet_create.__dict__)
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)

    def _do_list(self, arg):
        # Execute command
        rsp = self.rest_client.api_get(f'wallets/{arg.holder}')
        RestClient.assert_satus_code(rsp, [200])
        for e in rsp.json():
            print(e)

    def _do_get(self, arg):
        # Execute command
        rsp = self.rest_client.api_get(f'wallet/{arg.id}')
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)

    def _do_delete(self, arg):
        # Execute command
        rsp = self.rest_client.api_delete(f'wallet/{arg.id}')
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)

    def _execute(self, arg: str):
        # Execute command
        args = self.parser.parse_args(arg.split())
        match args.cmd:

            case 'help':
                self.parser.print_help()

            case 'create':
                self._do_create(args)

            case 'list':
                self._do_list(args)

            case 'get':
                self._do_get(args)

            case 'delete':
                self._do_delete(args)

            case _:
                raise Exception('Unknown command {}'.format(args.cmd))

    def execute(self, arg: str):
        # Execute command, process errors
        try:
            self._execute(arg)
        except Exception as e:
            print(e)
