import cmd
from OBPClient.obp_config import OBPConfig
from OBPClient.cmd_admin import OBPCmdAdmin
from OBPClient.cmd_roles import OBPCmdRoles
from OBPClient.cmd_bank import OBPCmdBank
from OBPClient.cmd_user import OBPCmdUser
from OBPClient.cmd_transaction import OBPCmdTransaction


class OBPCmdMain(cmd.Cmd):
	# OBP client command prompt class
	intro = 'Mobile Wallet Project. OBP sandbox manager.\n'
	prompt = 80 * '-' + '\n> '

	def __init__(self, cfg: OBPConfig):
		super().__init__()
		self._cfg = cfg
		self._cmd_admin = OBPCmdAdmin(cfg)
		admin = self._cmd_admin.get_admin()
		self._cmd_roles = OBPCmdRoles(cfg, admin)
		self._cmd_bank = OBPCmdBank(cfg, admin)
		self._cmd_user = OBPCmdUser(cfg, admin)
		self._cmd_transaction = OBPCmdTransaction(self._cmd_user)

	def do_admin(self, arg):
		"""Global OBP sandbox administration """
		self._cmd_admin.do_cmd(arg)

	def do_role(self, arg):
		"""Roles information"""
		self._cmd_roles.do_cmd(arg)

	def do_bank(self, arg):
		"""Banks management"""
		self._cmd_bank.do_cmd(arg)

	def do_user(self, arg):
		"""Users management"""
		self._cmd_user.do_cmd(arg)

	def do_trx(self, arg):
		"""Transactions management"""
		self._cmd_transaction.do_cmd(arg)

	def do_quit(self, arg):
		"""Exit OBP manager command shell"""
		print('- Exit ')
		return True
