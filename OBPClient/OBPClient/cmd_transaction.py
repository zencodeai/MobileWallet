import argparse
import json
from dacite import from_dict

from OBPClient.cmd_user import OBPCmdUser
from OBPClient.obp_transaction import OBPTransactionAPI
from OBPClient.obp_config import OBPConfig
from OBPClient.cmd_parser import OBPArgumentParser
from OBPClient.obp_admin import OBPSysAdmin
from OBPClient.obp_user import OBPUserAPI


class OBPCmdTransaction:
    # Account management commands interpreter

    @classmethod
    def _get_parser(cls, cfg: OBPConfig):
        # Build args parser
        parser = OBPArgumentParser(prog='account', exit_on_error=False)
        subparser = parser.add_subparsers(dest='cmd', required=True, help='Accounts management commands')
        # Find account sub-parser
        parser_find = subparser.add_parser('find', help='Find account')
        parser_find.add_argument(
            '-u',
            '--username',
            type=str,
            required=True,
            help='Username'
        )
        parser_find.add_argument(
            '-b',
            '--bank',
            type=str,
            default=cfg.get_default_bank_id(),
            help='User bank_id'
        )

        # Send amount to user
        parser_send = subparser.add_parser('send', help='Send amount to user')
        parser_send.add_argument(
            '-u',
            '--username',
            type=str,
            required=True,
            help='Username'
        )
        parser_send.add_argument(
            '-a',
            '--amount',
            type=int,
            required=True,
            help='Amount to send'
        )
        parser_send.add_argument(
            '-m',
            '--message',
            type=str,
            default="Send amount",
            help='Transaction message'
        )
        parser_send.add_argument(
            '-b',
            '--bank',
            type=str,
            default=cfg.get_default_bank_id(),
            help='User bank_id'
        )
        # Manage transaction requests
        parser_req = subparser.add_parser('req', help='Manage transaction requests')
        parser_req.add_argument(
            '-l',
            '--list',
            action='store_true',
            help='List transaction requests',
        )
        parser_req.add_argument(
            '-b',
            '--bank',
            type=str,
            default=cfg.get_default_bank_id(),
            help='User bank_id'
        )
        parser_req.add_argument(
            '-a',
            '--accept',
            type=int,
            help='User bank_id'
        )
        parser_req.add_argument(
            '-m',
            '--message',
            type=str,
            default='Transaction processed',
            help='User bank_id'
        )
        return parser

    def __init__(self, cmd_user: OBPCmdUser):
        self._parser = self._get_parser(cmd_user.get_config())
        self._cfg = cmd_user.get_config()
        self._admin = cmd_user.get_admin()

        def get_user() -> OBPSysAdmin:
            return cmd_user.get_user()

        self._account_api = OBPTransactionAPI(self._cfg, self._admin, get_user)

    def _do_cmd_find(self, args: argparse.Namespace):
        # Find account
        # account_id = self._account_api.get_account_id(args.username, args.bank)
        # print(account_id)
        ids = self._account_api.get_account_id_list(args.username, args.bank)
        for account_id in ids:
            print(f'Account id: {account_id}')

    def _do_cmd_send(self, args: argparse.Namespace):
        # Send amount to user
        request = self._account_api.send_amount(args.username, args.bank, args.amount, args.message)
        print(json.dumps(request, indent=4))

    def _do_cmd_req(self, args: argparse.Namespace):
        # Manage transaction requests
        if args.list:
            requests = self._account_api.get_transaction_request_list(args.bank)
            print(json.dumps(requests, indent=4))
        if args.accept is not None:
            request = self._account_api.accept_transaction_request(args.bank, args.accept, args.message)
            print(json.dumps(request, indent=4))

    def _do_cmd(self, arg: str):
        # Execute command
        args = self._parser.parse_args(arg.split())
        match args.cmd:

            case 'find':
                # find account
                self._do_cmd_find(args)

            case 'send':
                # find account
                self._do_cmd_send(args)

            case 'req':
                # Manage transaction requests
                self._do_cmd_req(args)

            case _:
                raise Exception('Unknown command {}'.format(args.cmd))

    def do_cmd(self, arg: str):
        # Execute command, process errors
        try:
            self._do_cmd(arg)
        except Exception as e:
            print(e)
