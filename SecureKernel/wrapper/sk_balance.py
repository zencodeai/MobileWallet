import base64
from dataclasses import dataclass

from sk_utils import SKDefinitions, SKMessage, get_rnd_receipt
from sk_wrapper import SKCall, SKCallProcessMsg, SKCallArgsMsg
from sk_client import RestClient


@dataclass
class SKBalanceInitArgs:
    # SK balance init call arguments
    token: str
    data: str


class SKCallBalanceInit(SKCall):
    # SK balance initialization call class

    def __init__(self, token: str, client: RestClient, defs: SKDefinitions):
        super().__init__(defs, defs.SK_CMD_ONLINE, 1024)
        self.token = token
        self.client = client

    def __call__(self):
        output_data = super().__call__()
        data = SKBalanceInitArgs(self.token, base64.urlsafe_b64encode(output_data).decode('utf-8'))
        rsp = self.client.api_post('init', data.__dict__)
        RestClient.assert_satus_code(rsp, [200])
        rsp_data_json = rsp.json()
        rsp_data = SKMessage(rsp_data_json['session_id'], rsp_data_json['data'])
        self.session_id = rsp_data.session_id
        data_out = base64.urlsafe_b64decode(rsp_data.data)
        while len(data_out) > 0:
            data_bin = SKCallProcessMsg(self.defs, data_out, 1024)()
            if len(data_bin) == 0:
                break
            data_b64 = base64.urlsafe_b64encode(data_bin).decode('utf-8')
            data_args = SKMessage(session_id=self.session_id, data=data_b64)
            rsp = self.client.api_post('process', data_args.__dict__)
            RestClient.assert_satus_code(rsp, [200])
            rsp_data_json = rsp.json()
            rsp_data = SKMessage(rsp_data_json['session_id'], rsp_data_json['data'])
            data_out = base64.urlsafe_b64decode(rsp_data.data)
        data_args = SKMessage(session_id=self.session_id, data=get_rnd_receipt())
        rsp = self.client.api_post('process', data_args.__dict__)
        RestClient.assert_satus_code(rsp, [200])
