import cmd

from mod_utils import AdminCfg
from mod_client import RestClient
from cmd_status import CmdStatus
from cmd_populate import CmdPopulate
from cmd_holder import CmdHolder
from cmd_merchant import CmdMerchant
from cmd_intermediary import CmdIntermediary
from cmd_wallet import CmdWallet
from cmd_transaction import CmdTransaction


class AdminCmdMain(cmd.Cmd):
    # SK client command prompt class
    prompt = 80 * '-' + '\n> '

    def __init__(self, admin_cfg: AdminCfg):
        super().__init__()
        self.admin_cfg = admin_cfg
        self.intro = f"\n- {admin_cfg.description}"
        self.rest_client = RestClient(admin_cfg)

    def do_status(self, arg):
        """Get backend status"""
        print('- Status ')
        cmd_status = CmdStatus(self.admin_cfg, self.rest_client)
        cmd_status.execute()

    def do_populate(self, arg):
        """Populate backend with dataset"""
        print('- Populate ')
        cmd_populate = CmdPopulate(self.admin_cfg, self.rest_client)
        cmd_populate.execute()

    def do_holder(self, arg):
        """Manage holders"""
        print(f'- Holder {arg}')
        cmd_holder = CmdHolder(self.admin_cfg, self.rest_client)
        cmd_holder.execute(arg)

    def do_merchant(self, arg):
        """Manage merchants"""
        print(f'- Merchant {arg}')
        cmd_merchant = CmdMerchant(self.admin_cfg, self.rest_client)
        cmd_merchant.execute(arg)

    def do_intermediary(self, arg):
        """Manage intermediaries"""
        print(f'- Intermediary {arg}')
        cmd_intermediary = CmdIntermediary(self.admin_cfg, self.rest_client)
        cmd_intermediary.execute(arg)

    def do_wallet(self, arg):
        """Manage wallets"""
        print(f'- Wallet {arg}')
        cmd_wallet = CmdWallet(self.admin_cfg, self.rest_client)
        cmd_wallet.execute(arg)

    def do_transaction(self, arg):
        """Manage transactions"""
        print(f'- Transaction {arg}')
        cmd_transaction = CmdTransaction(self.admin_cfg, self.rest_client)
        cmd_transaction.execute(arg)

    def do_quit(self, arg):
        """Exit admin command shell"""
        print('- Exit ')
        return True
    
    def do_EOF(self, arg):
        """Exit admin command shell"""
        print('- Exit ')
        return True
    
    # Process cmd exceptions
    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except Exception as e:
            print(e)
            return False


# Entry point of the program
def main():
    # Create SK client command prompt
    admin_cfg = AdminCfg()
    admin_cmd = AdminCmdMain(admin_cfg)
    admin_cmd.cmdloop()


# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
