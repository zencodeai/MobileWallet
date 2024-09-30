
from mod_utils import AdminCfg
from mod_client import RestClient

class CmdStatus:
    # Status command

    def __init__(self, admin_cfg: AdminCfg, rest_client: RestClient):
        # Class constructor
        self.admin_cfg = admin_cfg
        self.rest_client = rest_client

    def execute(self):
        # Execute command
        rsp = self.rest_client.api_get('status')
        RestClient.assert_satus_code(rsp, [200])
        print(rsp.text)
