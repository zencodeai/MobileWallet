import json
import argparse
import os

from OBPClient import OBPConfig, OBPCmdMain
from OBPClient import OBPRole, OBPRoleList, OBPUser, OBPBankList
from dacite import from_dict


def parse_args():
    # Process command line arguments

    # Parser
    parser = argparse.ArgumentParser(
        prog='OBP client',
        description='PoT OBP backend management')

    # Add config argument
    parser.add_argument(
        '-c',
        '--config',
        required=True,
        type=argparse.FileType('r'),
        help='Path to JSON parameters file')

    # Add verbose argument
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Verbose output')
    return parser.parse_args()


def main():
    # Application entry point
    args = parse_args()
    cfg = OBPConfig.get_config(args.config)
    OBPCmdMain(cfg).cmdloop()

#
#     print(os.getcwd())
#     args = parse_args()
#     print(args)
#     print(args.config)
#     cfg = OBPConfig.get_config(args.config)
#     client = cfg.get_client()
#     auth = cfg.get_authentication()
#     auth.authenticate(client)
#     print(auth.get_headers())
#     auth_headers = auth.get_headers()
#     rsp = client.api_get('/roles', auth_headers)
#     print(rsp)
#     print(rsp.json())
#     obj = from_dict(data_class=OBPRoleList, data=rsp.json())
#
#     for role in obj.roles:
#         print(role)
#
#     rsp = client.api_get('/users/current', auth_headers)
#     print(rsp)
#     print(rsp.json)
#     rsp_text = rsp.text.replace('"list":', '"list_":')
#     print(rsp_text)
#     rsp_json = json.loads(rsp_text)
#     obj = from_dict(data_class=OBPUser, data=rsp_json)
#     print(obj)
#
#     rsp = client.api_get('/banks', auth_headers)
#     print(rsp)
#     print(rsp.json())
#     obj = from_dict(data_class=OBPBankList, data=rsp.json())
#     print(obj)
#
#     admin = cfg.get_admin()
#     admin.initialize()
#     admin.add_sys_entitlements()
#

if __name__ == '__main__':
    main()
