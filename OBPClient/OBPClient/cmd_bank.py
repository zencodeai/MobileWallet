import json
import argparse
from dacite import from_dict

from OBPClient.obp_config import OBPConfig
from OBPClient.cmd_parser import OBPArgumentParser
from OBPClient.obp_admin import OBPSysAdmin
from OBPClient.obp_request import OBPRequest
from OBPClient.obj_bank import OBPBank, OBPBankList


class OBPCmdBank:
	# Admin commands interpreter

	@classmethod
	def _get_parser(cls, cfg: OBPConfig):
		# Build args parser
		parser = OBPArgumentParser(prog='bank', exit_on_error=False)
		subparser = parser.add_subparsers(dest='cmd', required=True, help='admin commands')
		# list sub-parser
		parser_list = subparser.add_parser('list', help='get banks list')
		parser_list.add_argument(
			'-d',
			'--delete',
			action="store_true",
			default=False,
			help='Delete listed users'
		)
		# role management sub-parser
		parser_create = subparser.add_parser('create', help='Create banks from json list')
		parser_create.add_argument(
			'-f',
			'--file',
			default=cfg.get_default_bank_data(),
			type=argparse.FileType('r'),
			help='Path to JSON parameters file'
		)
		return parser

	def __init__(self, cfg: OBPConfig, admin: OBPSysAdmin):
		self._parser = self._get_parser(cfg)
		self._cfg = cfg
		self._admin = admin

	def _get_banks_list(self) -> dict:
		# List banks
		request = self._admin.get_get_request('/banks')
		rsp = request()
		print(rsp.text)
		OBPRequest.assert_satus_code(rsp, [200])
		bank_list = from_dict(data_class=OBPBankList, data=rsp.json())
		return dict((b.id, b) for b in bank_list.banks)

	def _do_create_banks(self, args):
		banks = json.load(args.file)
		for b in banks['banks']:
			b['logo'] = f'{self._cfg.face_image_url}{b["id"]}.png'
			print(b)
			request = self._admin.get_post_request('/banks', b)
			rsp = request()
			OBPRequest.assert_satus_code(rsp, [201, 400])

	def _do_list(self, args):
		banks = self._get_banks_list()
		for b in banks.values():
			print(b)
			if args.delete:
				if not b.id == 'THE_DEFAULT_BANK_ID':
					print(f'Delete bank {b.id}...')
					request = self._admin.get_delete_request(f'/management/cascading/banks/{b.id}')
					rsp = request()
					OBPRequest.assert_satus_code(rsp, [200])

	def _do_cmd(self, arg: str):
		# Execute command
		args = self._parser.parse_args(arg.split())
		match args.cmd:

			case 'list':
				self._do_list(args)

			case 'create':
				self._do_create_banks(args)

			case _:
				raise Exception('Unknown command {}'.format(args.cmd))

	def do_cmd(self, arg: str):
		# Execute command, process errors
		try:
			self._do_cmd(arg)
		except Exception as e:
			print(e)
