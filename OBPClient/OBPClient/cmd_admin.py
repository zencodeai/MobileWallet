from OBPClient.obp_config import OBPConfig
from OBPClient.cmd_parser import OBPArgumentParser
from OBPClient.obp_admin import OBPSysAdmin


class OBPCmdAdmin:
	# Admin commands interpreter

	@classmethod
	def _get_parser(cls):
		# Build args parser
		parser = OBPArgumentParser(prog='admin', exit_on_error=False)
		subparser = parser.add_subparsers(dest='cmd', required=True, help='admin commands')
		# id sub-parser
		subparser.add_parser('id', help='get admin user id')
		# role management sub-parser
		parser_role = subparser.add_parser('roles', help='Admin user entitlements')
		parser_role.add_argument(
			'-l',
			'--list',
			action='store_true',
			help='List entitlements for a bank if -b specified else system only'
		)

		parser_role.add_argument(
			'-a',
			'--add',
			action='store_true',
			help='Add all entitlements for a bank if -b specified else all system roles'
		)

		parser_role.add_argument(
			'-b',
			'--bank',
			action='store',
			type=str,
			help='Specify bank id'
		)
		return parser

	def __init__(self, cfg: OBPConfig):
		self._parser = OBPCmdAdmin._get_parser()
		self._cfg = cfg
		self._admin = cfg.get_admin()
		self._admin.initialize()

	def _do_cmd_roles(self, args):
		# Execute roles command
		if args.list:
			bank_id = args.bank if args.bank else ''
			e_list = self._admin.get_entitlements(bank_id)
			for e in e_list:
				print(e)

		if args.add:
			if args.bank:
				self._admin.add_bank_entitlements(args.bank)
			else:
				self._admin.add_sys_entitlements()

	def _do_cmd(self, arg: str):
		# Execute command
		args = self._parser.parse_args(arg.split())
		match args.cmd:

			case 'id':
				# Get admin user id
				user_id = self._admin.get_user_id()
				print('Admin user id: {}'.format(user_id))

			case 'roles':
				# List roles
				self._do_cmd_roles(args)

			case _:
				raise Exception('Unknown command {}'.format(args.cmd))

	def do_cmd(self, arg: str):
		# Execute command, process errors
		try:
			self._do_cmd(arg)
		except Exception as e:
			print(e)

	def get_admin(self) -> OBPSysAdmin:
		# Return sysadmin object
		return self._admin
