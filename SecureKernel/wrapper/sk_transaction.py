import base64
import enum
from dataclasses import dataclass

from sk_utils import SKDefinitions, SKMessage, get_rnd_receipt
from sk_wrapper import SKCall, SKCallProcessMsg, SKCallArgsMsg
from sk_client import RestClient


@dataclass
class SKTransactionArgs:
    # SK online transaction call arguments
    session_id: str
    data: str


class TransactionMode(enum.Enum):
    # Transaction mode
    invalid = 'invalid'
    validate = 'validate'
    accept = 'accept'
    reject = 'reject'
    push = 'push'
    pull = 'pull'


class SKCallTransaction(SKCall):
    # SK online mode call class

    def __init__(self, session_id: str, args: str, client: RestClient, defs: SKDefinitions):
        # Parse arguments
        arg_list = args.split()
        if len(arg_list) != 3:
            print('Invalid number of arguments: <mode> <amount> <cuid>')
            return
        # Parse arguments
        mode = arg_list[0]
        if mode not in TransactionMode._member_names_:
            print(f'Invalid transaction mode: {mode}')
            return
        # Parse amount
        try:
            amount = int(arg_list[1])
        except ValueError:
            print(f'Invalid amount: {arg_list[1]}')
            return
        if (amount < 0) or (amount > 0xffffffff):
            print(f'Invalid amount: {amount}')
            return
        # Parse cuid
        cuid = arg_list[2]
        cuid_bytes = base64.urlsafe_b64decode(cuid)
        if len(cuid_bytes) != 32:
            print(f'Invalid cuid: {cuid}')
            return
        # Update amount
        match TransactionMode(mode):
            case TransactionMode.validate:
                amount = -amount
            case TransactionMode.accept:
                pass
            case TransactionMode.reject:
                amount = 0
            case TransactionMode.push:
                pass
            case TransactionMode.pull:
                amount = -amount
            case _:
                raise Exception(f'Invalid transaction mode: {mode}')
        # Set call context
        amount_bytes = amount.to_bytes(8, byteorder='little', signed=True)
        call_args = SKCallArgsMsg(defs.SK_CMD_TX_ONLINE, amount_bytes + cuid_bytes)
        super().__init__(defs, defs.SK_CMD_TX_ONLINE, 1024, args=call_args)
        self.session_id = session_id
        self.client = client

    def __call__(self):
        output_data = super().__call__()
        data = SKTransactionArgs(self.session_id, base64.urlsafe_b64encode(output_data).decode('utf-8'))
        rsp = self.client.api_post('process', data.__dict__)
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
