from dacite import from_dict

from OBPClient.obp_config import OBPConfig
from OBPClient.cmd_parser import OBPArgumentParser
from OBPClient.obp_admin import OBPSysAdmin
from OBPClient.obj_role import OBPRole, OBPRoleList
from OBPClient.obp_request import OBPRequest


class OBPCmdRoles:
	# Admin commands interpreter

	@classmethod
	def _get_parser(cls):
		# Build args parser
		parser = OBPArgumentParser(prog='roles', exit_on_error=False)
		parser.add_argument(
			'-l',
			'--list',
			action='store_true',
			help='List roles'
		)

		parser.add_argument(
			'-i',
			'--info',
			action='store',
			type=str,
			help='Get specified role information'
		)
		return parser

	def _get_roles(self) -> dict:
		# Get roles list as dict
		request = self._admin.get_get_request('/roles')
		rsp = request()
		OBPRequest.assert_satus_code(rsp, [200])
		role_list = from_dict(data_class=OBPRoleList, data=rsp.json())
		return dict((r.role, r) for r in role_list.roles)

	def __init__(self, cfg: OBPConfig, admin: OBPSysAdmin):
		self._parser = self._get_parser()
		self._cfg = cfg
		self._admin = admin
		self._roles = self._get_roles()

	def _do_cmd(self, arg: str):
		# Execute command
		args = self._parser.parse_args(arg.split())
		if args.list:
			for r in self._roles.values():
				print(r)
		elif args.info:
			if args.info in self._roles:
				print(self._roles[args.info])
			else:
				print('Unknown role: {}'.format(args.info))

	def do_cmd(self, arg: str):
		# Execute command, process errors
		try:
			self._do_cmd(arg)
		except Exception as e:
			print(e)
