import argparse
from mod_utils import AdminCfg, CmdArgumentParser
from mod_client import RestClient

class CmdMerchant:
    # Merchants management commands

    def _get_parser(this):
        # Build args parser
        parser = CmdArgumentParser(prog='CmdMerchant', exit_on_error=False)
        subparser = parser.add_subparsers(dest='cmd', required=True, help='admin commands')
        # Help sub-parser
        subparser.add_parser('help', help='print help')
        # list sub-parser
        parser_list = subparser.add_parser('list', help='get merchants list')
        # Get sub-parser
        parser_get = subparser.add_parser('get', help='get merchant by id')
        parser_get.add_argument(
			'-i',
			'--id',
			type=int,
            required=True,
			help='Merchant id'
		)
        return parser

    def __init__(self, admin_cfg: AdminCfg, rest_client: RestClient):
        # Class constructor
        self.admin_cfg = admin_cfg
        self.rest_client = rest_client
        self.parser = self._get_parser()

    def _do_list(self, arg):
        # Execute command
        rsp = self.rest_client.api_get('merchants')
        RestClient.assert_satus_code(rsp, [200])
        for h in rsp.json():
            print(h)

    def _do_get(self, arg):
        # Execute command
        rsp = self.rest_client.api_get(f'merchant/{arg.id}')
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)

    def _execute(self, arg: str):
        # Execute command
        args = self.parser.parse_args(arg.split())
        match args.cmd:

            case 'help':
                self.parser.print_help()

            case 'list':
                self._do_list(args)

            case 'get':
                self._do_get(args)

            case _:
                raise Exception('Unknown command {}'.format(args.cmd))

    def execute(self, arg: str):
        # Execute command, process errors
        try:
            self._execute(arg)
        except Exception as e:
            print(e)
