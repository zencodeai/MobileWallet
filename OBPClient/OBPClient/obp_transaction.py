import json
from dataclasses import dataclass, field
from dacite import from_dict
import copy
from urllib.parse import quote

from OBPClient.obj_customer import OBPUserCustomerLinkList
from OBPClient.obj_transaction import get_transaction_request_account, TransactionRequestWithChargesList
from OBPClient.obp_client import OBPClientRoot, sanitize
from OBPClient.obj_user import OBPUser
from OBPClient.obp_config import OBPConfig
from OBPClient.obp_admin import OBPSysAdmin
from OBPClient.obp_request import OBPRequest


class OBPTransactionAPI(OBPClientRoot):
    # Transactions management API

    def __init__(self, cfg: OBPConfig, admin: OBPSysAdmin, get_user: callable):
        self._cfg = cfg
        self._admin = admin
        self._get_user = get_user
        self._request_list = None

    def _check_state(self):
        # Check if state is valid
        if self._request_list is None:
            raise Exception('Request list not initialized')

    def find_user(self, user_name: str) -> OBPUser:
        # Find user
        user = self._get_user()
        provider = quote(user.get_user().provider, safe='')
        rel_endpoint = f'/users/provider/{provider}/username/Alias.{user_name}'
        request = self._get_user().get_get_request(rel_endpoint)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        return from_dict(data_class=OBPUser, data=rsp.json())

    def get_user_customer_links(self, bank_id: str, user_id: str) -> OBPUserCustomerLinkList:
        request = self._get_user().get_get_request(f'/banks/{bank_id}/user_customer_links/users/{user_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        list_json = json.loads(sanitize(rsp.text))
        return from_dict(data_class=OBPUserCustomerLinkList, data=list_json)

    def get_account_id_list(self, user_name: str, bank_id: str) -> list[str]:
        # Get account id for specified user
        user = self.find_user(user_name)
        accounts_obj = self.get_user_customer_links(bank_id, user.user_id)
        return [account.customer_id for account in accounts_obj.user_customer_links]

    def get_account_id(self, user_name: str, bank_id: str) -> str:
        # Get account id for specified user
        account_ids = self.get_account_id_list(user_name, bank_id)
        if not len(account_ids):
            raise Exception(f'No account found for user {user_name} at bank {bank_id}')
        return account_ids[0]

    def send_amount(self, user_name: str, bank_id: str, amount: int, message: str):
        # Send amount to specified user
        account_id = self.get_account_id(user_name, bank_id)
        body = get_transaction_request_account(bank_id, account_id, amount, message)
        # /banks/BANK_ID/accounts/ACCOUNT_ID/VIEW_ID/transaction-request-types/ACCOUNT/transaction-requests
        request = self._get_user().get_post_request(f'/banks/{bank_id}/accounts/{account_id}/owner/transaction-request-types/ACCOUNT/transaction-requests', body)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [201])
        return rsp.json()

    def get_user_account_id(self, bank_id: str):
        # Get account id for current user
        user_id = self._get_user().get_user().user_id
        links = self.get_user_customer_links(bank_id, user_id)
        account_ids = [link.customer_id for link in links.user_customer_links]
        if not len(account_ids):
            raise Exception(f'No account found for user {user_id} at bank {bank_id}')
        return account_ids[0]

    def get_transaction_request_list(self, bank_id: str):
        # Get transaction request list
        self._request_list = None
        user_id = self._get_user().get_user().user_id
        account_id = self.get_user_account_id(bank_id)
        request = self._get_user().get_get_request(f'/banks/{bank_id}/accounts/{account_id}/owner/transaction-requests')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        rsp_json = json.loads(sanitize(rsp.text))
        self._request_list = from_dict(data_class=TransactionRequestWithChargesList, data=rsp_json)
        return rsp.json()

    def accept_transaction_request(self, bank_id: str, index: int, message: str):
        # Accept transaction request
        # self._check_state()
        #         if index >= len(self._request_list.transaction_requests_with_charges):
        #             raise Exception(f'Invalid index {index}')
        #         account_id = self.get_user_account_id(bank_id)
        #         request_obj = self._request_list.transaction_requests_with_charges[index]
        #         request_id = request_obj.id
        #         request_type = request_obj.type
        body = {
            # 'id': request_obj.challenge.id,
            'id': '927725fb-a61f-4eb4-a9a4-e33449908266',
            'answer': '123'
        }

        # /obp/v5.1.0/banks/BANK_ID/accounts/ACCOUNT_ID/VIEW_ID/transaction-request-types/TRANSACTION_REQUEST_TYPE/transaction-requests/TRANSACTION_REQUEST_ID/challenge
        # uri = '/banks/b.890.ca/accounts/79e50da7-bb2b-4a91-b08e-eadc6fcfa2d1/owner/transaction-request-types/ACCOUNT/transaction-requests/f8333db4-2e43-4337-963c-8c8edcead9da/challenge'
        # uri = f'/banks/{bank_id}/accounts/{account_id}/owner/transaction-request-types/{request_type}/transaction-requests/{request_id}/challenge'
        uri =  "http://127.0.0.1:8080/obp/v4.0.0/banks/b.890.ca/accounts/79e50da7-bb2b-4a91-b08e-eadc6fcfa2d1/owner/transaction-request-types/ACCOUNT/transaction-requests/62c62204-ee87-4abe-8e62-e1b88f9aa882/challenge"
        request = self._get_user().get_post_abs_request(uri, body)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        return rsp.json()
