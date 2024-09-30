import argparse
from dataclasses import dataclass
from mod_utils import AdminCfg, CmdArgumentParser
from mod_client import RestClient

@dataclass
class TransactionCreate:
    # Transaction create request
    name: str
    description: str
    amount: int
    wallet_id: int
    cuid: str


class CmdTransaction:
    # Transactions management commands

    def _get_parser(this):
        # Build args parser
        parser = CmdArgumentParser(prog='CmdTransaction', exit_on_error=False)
        subparser = parser.add_subparsers(dest='cmd', required=True, help='admin commands')
        # Help sub-parser
        subparser.add_parser('help', help='print help')
        # Create sub-parser
        parser_create = subparser.add_parser('create', help='create new transaction for wallet')
        parser_create.add_argument(
			'-i',
			'--wallet',
			type=int,
            required=True,
			help='Wallet id'
		)
        parser_create.add_argument(
			'-n',
			'--name',
			type=str,
            nargs='+',
            required=True,
			help='Transaction name, must be unique'
		)
        parser_create.add_argument(
			'-d',
			'--description',
			type=str,
            nargs='+',
            default=['test', 'transaction'],
			help='Transaction description'
		)
        parser_create.add_argument(
			'-a',
			'--amount',
			type=int,
            required=True,
			help='Transaction amount'
		)
        parser_create.add_argument(
            '-c',
            '--counterparty',
            type=str,
            required=True,
            help='Counterparty uid'
        )
        # list sub-parser
        parser_list = subparser.add_parser('list', help='get transaction list for wallet')
        parser_list.add_argument(
			'-i',
			'--wallet',
            dest='wallet',
			type=int,
            required=True,
			help='Wallet id'
		)
        # Get sub-parser
        parser_get = subparser.add_parser('get', help='get transaction by id')
        parser_get.add_argument(
			'-i',
			'--id',
			type=int,
            required=True,
			help='Transaction id'
		)
        # Delete sub-parser
        parser_delete = subparser.add_parser('delete', help='delete transaction by id')
        parser_delete.add_argument(
			'-i',
			'--id',
			type=int,
            required=True,
			help='Transaction id'
		)
        return parser

    def __init__(self, admin_cfg: AdminCfg, rest_client: RestClient):
        # Class constructor
        self.admin_cfg = admin_cfg
        self.rest_client = rest_client
        self.parser = self._get_parser()

    def _do_create(self, arg):
        # Execute command
        transaction_create = TransactionCreate(
            name=' '.join(arg.name),
            description=' '.join(arg.description),
            amount=arg.amount,
            wallet_id=arg.wallet,
            cuid=arg.counterparty
        )
        rsp = self.rest_client.api_put('transaction', transaction_create.__dict__)
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)

    def _do_list(self, arg):
        # Execute command
        rsp = self.rest_client.api_get(f'transactions/{arg.wallet}')
        RestClient.assert_satus_code(rsp, [200])
        for e in rsp.json():
            print(e)

    def _do_get(self, arg):
        # Execute command
        rsp = self.rest_client.api_get(f'transaction/{arg.id}')
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)

    def _do_delete(self, arg):
        # Execute command
        rsp = self.rest_client.api_delete(f'transaction/{arg.id}')
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
