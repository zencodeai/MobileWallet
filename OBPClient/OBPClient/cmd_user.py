import argparse
import json

from OBPClient.obp_config import OBPConfig
from OBPClient.cmd_parser import OBPArgumentParser
from OBPClient.obp_admin import OBPSysAdmin
from OBPClient.obp_user import OBPUserAPI


class OBPCmdUser:
    # User management commands interpreter

    @classmethod
    def _get_parser(cls, cfg: OBPConfig):
        # Build args parser
        parser = OBPArgumentParser(prog='user', exit_on_error=False)
        subparser = parser.add_subparsers(dest='cmd', required=True, help='user management commands')
        # User creation sub-parser
        parser_create = subparser.add_parser('create', help='Create users')
        parser_create.add_argument(
            '-f',
            '--file',
            default=cfg.get_default_user_data(),
            type=argparse.FileType('r'),
            help='Path to JSON users information file'
        )
        parser_create.add_argument(
            '-t',
            '--template',
            default=cfg.get_default_user_template(),
            type=argparse.FileType('r'),
            help='Path to JSON users creation template file'
        )
        # User list sub-parser
        parser_list = subparser.add_parser('list', help='List all users')
        parser_list.add_argument(
            '-d',
            '--delete',
            action="store_true",
            default=False,
            help='Delete listed users'
        )
        parser_list.add_argument(
            '-b',
            '--bank',
            type=str,
            default=cfg.get_default_bank_id(),
            help='User bank_id'
        )
        # Add role
        parser_role = subparser.add_parser('role', help='Add role to user')
        parser_role.add_argument(
            '-r',
            '--role',
            required=True,
            type=str,
            help='Role name'
        )
        parser_role.add_argument(
            '-b',
            '--bank',
            type=str,
            default="",
            help='User bank_id'
        )
        # Delete user
        parser_del = subparser.add_parser('delete', help='Delete user')
        parser_del.add_argument(
            '-u',
            '--user',
            required=True,
            type=str,
            help='User user_id'
        )
        parser_del.add_argument(
            '-b',
            '--bank',
            type=str,
            default=cfg.get_default_bank_id(),
            help='User bank_id'
        )
        # User authentication sub-parser
        parser_auth = subparser.add_parser('auth', help='Authenticate user')
        parser_auth.add_argument(
            '-u',
            '--username',
            type=str,
            required=True,
            help='Username'
        )
        parser_auth.add_argument(
            '-p',
            '--password',
            type=str,
            default=cfg.get_default_password(),
            help='Password'
        )
        # User information sub-parser
        parser_info = subparser.add_parser('info', help='User information')
        parser_info.add_argument(
            '-c',
            '--customer',
            action="store_true",
            help='Get customer information'
        )
        parser_info.add_argument(
            '-i',
            '--info',
            action="store_true",
            help='Get user information'
        )
        parser_info.add_argument(
            '-a',
            '--account',
            action="store_true",
            help='Get account information'
        )
        parser_info.add_argument(
            '-b',
            '--bank',
            type=str,
            default=cfg.get_default_bank_id(),
            help='Bank id'
        )
        return parser

    def __init__(self, cfg: OBPConfig, admin: OBPSysAdmin):
        self._parser = self._get_parser(cfg)
        self._cfg = cfg
        self._admin = admin
        self.user_api = OBPUserAPI(cfg, admin)

    def _print_user_info(self, user_id: str):
        # Print user information
        print('-' * 80)
        print(f'User information: {user_id}')
        info = self.user_api.get_user_by_id(user_id)
        print(json.dumps(info, indent=4))

    def _do_cmd_create(self, args):
        # Execute create command
        users = json.load(args.file)
        template = json.load(args.template)
        self.user_api.create_users(users, template)

    def _do_cmd_list_users(self, args):
        # List users
        users = self.user_api.get_users_list()
        for user in users.users:
            if not user.username == 'system.admin':
                print(user)
                if args.delete:
                    # Delete user
                    self.user_api.delete_user_cascade(args.bank, user.user_id)

    def _do_cmd_add_role(self, args):
        # Add role
        self.user_api.add_role(args.role, args.bank)

    def _do_cmd_delete_user(self, args):
        # Delete user
        self.user_api.delete_user_cascade(args.bank, args.user)

    def _do_cmd_auth(self, args):
        # Authenticate user
        print(f'Authenticating user {args.username}...')
        self.user_api.auth_user('Alias.' + args.username, args.password)

    def _do_cmd_info(self, args):
        # User information
        user = self.user_api.get_user()
        user_id = user.get_user_id()
        print('Information for user: ' + user_id)
        if args.info:
            print('-' * 80)
            print(f'User: {user_id}')
            print(json.dumps(user.get_user_json(), indent=4))
        if args.customer or args.account:
            links = self.user_api.get_user_customer_links(args.bank, user_id)
            for link in links.user_customer_links:
                if args.customer:
                    print('-' * 80)
                    print(f'Customer: {link.customer_id}')
                    print(json.dumps(self.user_api.get_customer_by_id(args.bank, link.customer_id), indent=4))
                if args.account:
                    print('-' * 80)
                    print(f'Account: {link.customer_id}')
                    print(json.dumps(self.user_api.get_account_by_id(args.bank, link.customer_id), indent=4))

    def _do_cmd(self, arg: str):
        # Execute command
        args = self._parser.parse_args(arg.split())
        match args.cmd:

            case 'create':
                # Create users
                self._do_cmd_create(args)

            case 'list':
                # List users
                self._do_cmd_list_users(args)

            case 'role':
                # Add role to user
                self._do_cmd_add_role(args)

            case 'delete':
                # Delete users
                self._do_cmd_delete_user(args)

            case 'auth':
                # Authenticate user
                self._do_cmd_auth(args)

            case 'info':
                # User information
                self._do_cmd_info(args)

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

    def get_config(self) -> OBPConfig:
        # Return configuration object
        return self._cfg

    def get_user(self) -> OBPSysAdmin:
        # Return user object
        return self.user_api.get_user()
