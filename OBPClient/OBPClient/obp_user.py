import datetime
import json
import uuid
from dataclasses import dataclass, field
from dacite import from_dict
import copy

from OBPClient import OBPUser
from OBPClient.obj_account import OBPAccount, OBPAccountList
from OBPClient.obj_user import OBPUserList
from OBPClient.obj_customer import OBPCustomer, OBPUserCustomerLinkList
from OBPClient.obp_config import OBPConfig
from OBPClient.obp_admin import OBPSysAdmin
from OBPClient.obp_client import OBPClientRoot, sanitize
from OBPClient.obp_request import OBPRequest


# {
#   "users":
#   [
#     {  "username":"Alias.Massimo",  "password":"P@ssword1234",  "first_name":"James",  "last_name":"Smith", "bank_id":"b.890.ca"},
#     {  "username":"Alias.Carla",  "password":"P@ssword1234",  "first_name":"Mary",  "last_name":"Smith", "bank_id":"b.890.ca"}
#   ]
# }
@dataclass
class OBPUserData:
    # User data
    username: str
    password: str
    first_name: str
    last_name: str
    bank_id: str


@dataclass
class OBPUserDataList:
    # User data list
    users: list[OBPUserData] = field(default_factory=list)


# {
#   "user": {
#     "email": "<fisrt_name>.<last_name>@obp.ca",
#     "username": "<username>",
#     "password": "<password>",
#     "first_name": "<first_name>",
#     "last_name": "<last_name>"
#   },
#   "customer": {
#     "legal_name":"<first_name> <last_name>",
#     "mobile_phone_number":"(999) 999-9999",
#     "email":"<fisrt_name>.<last_name>@obp.ca",
#     "face_image": {
#       "url":"127.0.0.1:8081",
#       "date":"2023-03-01T00:00:00Z"
#     },
#     "date_of_birth":"1975-01-01T00:00:00Z",
#     "relationship_status":"single",
#     "dependants":0,
#     "dob_of_dependants":["2000-01-01T00:00:00Z"],
#     "credit_rating": {
#       "rating":"OBP",
#       "source":"OBP"
#     },
#     "credit_limit":{
#       "currency":"CAD",
#       "amount":"0"
#     },
#     "highest_education_attained":"Master",
#     "employment_status":"worker",
#     "kyc_status":true,
#     "last_ok_date":"2023-03-01T00:00:00Z",
#     "title":"Dr.",  "branch_id":"Online",
#     "name_suffix":"Sr"
#   },
#   "account": {
#     "user_id":"<user_id>",
#     "label":"OBP client account",
#     "product_code":"OBP-1",
#     "balance": {
#       "currency":"eCAD",
#       "amount":"100"
#     },
#     "branch_id":"Online",
#     "account_routing": {
#       "scheme":"AccountNumber",
#       "address":"4930396"
#     },
#     "account_attributes": [
#       {
#         "product_code":"OBP-1",
#         "account_attribute_id":"613c83ea-80f9-4560-8404-b9cd4ec42a7f",
#         "name":"OVERDRAFT_START_DATE",
#         "type":"DATE_WITH_DAY",
#         "value":"2012-04-23"
#       }
#     ]
#   },
#   "user_customer_link": {
#     "user_customer_link_id":"<uid>",
#     "customer_id":"<customer_id>",
#     "user_id":"user_id",
#     "date_inserted":"<current date>",
#     "is_active":true
#   }
# }
@dataclass
class OBPUserTemplate:
    user: dict
    customer: dict
    account: dict
    user_customer_link: dict
    customer_account_link: dict


class OBPUserAPI(OBPClientRoot):
    # User management API

    def __init__(self, cfg: OBPConfig, admin: OBPSysAdmin):
        self._cfg = cfg
        self._admin = admin
        self._user: OBPSysAdmin | None = None

    def _create_user(self, user_json: dict) -> OBPUser:
        # Create user
        request = self._admin.get_post_request('/users', user_json)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [201])
        return from_dict(data_class=OBPUser, data=rsp.json())

    def _check_state(self):
        if self._user is None:
            raise Exception('User is not created')

    def _create_customer(self, bank_id: str, customer_json: dict) -> OBPCustomer:
        # Create Customer
        request = self._admin.get_post_request(f'/banks/{bank_id}/customers', customer_json)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [201])
        return from_dict(data_class=OBPCustomer, data=rsp.json())

    def _create_user_customer_link(self, bank_id: str, link_json: dict):
        # Create Customer link
        request = self._admin.get_post_request(f'/banks/{bank_id}/user_customer_links', link_json)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [201])

    def _create_account(self, bank_id: str, account_id: str, account_json: dict):
        # Create Account
        request = self._admin.get_put_request(f'/banks/{bank_id}/accounts/{account_id}', account_json)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [201])
        return from_dict(data_class=OBPAccount, data=rsp.json())

    def _create_customer_account_link(self, bank_id: str, link_json: dict):
        # Create Customer Account link
        request = self._admin.get_post_request(f'/banks/{bank_id}/customer_account_links', link_json)
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [201])

    def create_user(self, user_data: OBPUserData, template: dict):
        print(f"Creating user {user_data.username}")
        template = OBPUserTemplate(**template)
        payloads = copy.deepcopy(template)
        email = f"{user_data.first_name}.{user_data.last_name}@obp.ca"
        payloads.user['email'] = email
        payloads.user['username'] = user_data.username
        payloads.user['password'] = user_data.password
        payloads.user['first_name'] = user_data.first_name
        payloads.user['last_name'] = user_data.last_name
        payloads.customer['legal_name'] = f"{user_data.first_name} {user_data.last_name}"
        payloads.customer['email'] = email
        payloads.customer['face_image']['url'] = f'{self._cfg.face_image_url}{user_data.username}.png'

        bank_id = user_data.bank_id

        # Create user
        print('Creating user: ', payloads.user)
        user = self._create_user(payloads.user)

        # Create customer
        print('Creating customer: ', payloads.customer)
        customer = self._create_customer(bank_id, payloads.customer)

        # Create customer link
        payloads.user_customer_link['user_id'] = user.user_id
        payloads.user_customer_link['customer_id'] = customer.customer_id
        print('Creating customer link: ', payloads.user_customer_link)
        self._create_user_customer_link(bank_id, payloads.user_customer_link)

        # Create account
        account_id = customer.customer_id
        payloads.account['user_id'] = user.user_id
        payloads.account['account_routings'][0]['address'] = user.user_id
        payloads.account['account_routings'][1]['address'] = user.username
        print('Creating account: ', payloads.account)
        account = self._create_account(bank_id, account_id, payloads.account)

    def create_users(self, users: dict, template: dict):
        user_data_list = from_dict(data_class=OBPUserDataList, data=users)
        for user_data in user_data_list.users:
            self.create_user(user_data, template)

    def get_users_list(self) -> OBPUserList:
        print('Getting users list')
        request = self._admin.get_get_request('/users')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        list_json = json.loads(sanitize(rsp.text))
        return from_dict(data_class=OBPUserList, data=list_json)

    def get_user_customer_links(self, bank_id : str, user_id: str) -> OBPUserCustomerLinkList:
        print('Getting user customer links')
        request = self._admin.get_get_request(f'/banks/{bank_id}/user_customer_links/users/{user_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        list_json = json.loads(sanitize(rsp.text))
        return from_dict(data_class=OBPUserCustomerLinkList, data=list_json)

    def delete_user(self, user_id: str):
        print(f'Deleting user: {user_id}')
        request = self._admin.get_delete_request(f'/users/{user_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])

    def delete_customer(self, bank_id: str, customer_id: str):
        print(f'Deleting customer: {customer_id}')
        request = self._admin.get_delete_request(f'/management/cascading/banks/{bank_id}/customers/{customer_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])

    def delete_user_customer_link(self, bank_id: str, user_customer_link_id: str):
        print(f'Deleting customer link: {user_customer_link_id}')
        request = self._admin.get_delete_request(f'/banks/{bank_id}/user_customer_links/{user_customer_link_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])

    def delete_account(self, bank_id: str, account_id: str):
        print(f'Deleting account: {account_id}')
        request = self._admin.get_delete_request(f'/management/cascading/banks/{bank_id}/accounts/{account_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])

    def get_accounts(self, bank_id: str) -> OBPAccountList:
        print('Getting user accounts ' + bank_id)
        request = self._admin.get_get_request(f'/banks/{bank_id}/accounts')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        print(json.dumps(rsp.json(), indent=4))
        return from_dict(data_class=OBPAccountList, data=rsp.json())

    def delete_user_cascade(self, bank_id: str, user_id: str):
        # Delete user
        # Get user customer links
        links = self.get_user_customer_links(bank_id, user_id)
        for link in links.user_customer_links:
            # Delete account
            self.delete_account(bank_id, link.customer_id)
            # Delete customer
            self.delete_customer(bank_id, link.customer_id)
        # Delete user
        self.delete_user(user_id)

    def get_user_by_id(self, user_id: str) -> dict:
        request = self._admin.get_get_request(f'/users/user_id/{user_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        return rsp.json()

    def get_user(self) -> OBPSysAdmin:
        self._check_state()
        return self._user

    def get_customer_by_id(self, bank_id: str, customer_id: str) -> dict:
        self._check_state()
        request = self._admin.get_get_request(f'/banks/{bank_id}/customers/{customer_id}')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        return rsp.json()

    def get_account_by_id(self, bank_id: str, account_id: str) -> dict:
        self._check_state()
        request = self._user.get_get_request(f'/my/banks/{bank_id}/accounts/{account_id}/account')
        rsp = request()
        OBPRequest.assert_satus_code(rsp, [200])
        return rsp.json()

    def auth_user(self, user_name: str, user_password: str):
        self._user = None
        print(f'Authenticating user: {user_name} / {user_password}')
        # logout current user
        user = self._cfg.get_user(user_name, user_password)
        user.initialize()
        self._user = user

    def add_role(self, role_name: str,  bank_id: str):
        # Add role to user
        self._check_state()
        user_id = self._user.get_user_id()
        print(f'Adding role {role_name} to user {user_id}')
        self._admin.add_role_to_user(user_id, role_name, bank_id)
