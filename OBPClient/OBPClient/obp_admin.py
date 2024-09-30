import json
from dacite import from_dict
import requests.status_codes

from OBPClient.obp_client import OBPClientRoot
from OBPClient.obp_request import OBPRequest
from OBPClient.obp_authentication import OBPAuthentication
from OBPClient.obj_user import OBPUser
from OBPClient.obj_role import OBPRoleList
from OBPClient.obj_entitlement import OBPEntitlement


class OBPSysAdmin(OBPClientRoot):
    # System administration class

    def __init__(self, auth: OBPAuthentication, req: OBPRequest):
        # Class constructor
        super().__init__()
        self._auth: OBPAuthentication = auth
        self._req: OBPRequest = req
        self._user: OBPUser | None = None
        self._roles: OBPRoleList | None = None

    def _assert_ready(self):
        # Check if we connected to the backend
        if not self._user:
            raise Exception('{} invalid state'.format(self.__class__.__name__))

    def _load_user_info(self):
        # Load user info

        # Get current user info from backend
        auth_headers = self._auth.get_headers()
        rsp = self._req.api_get('/users/current', auth_headers)
        OBPRequest.assert_satus_code(rsp, [200])

        # Sanitize (list reserved keyword)
        rsp_text = rsp.text.replace('"list":', '"list_":')
        rsp_json = json.loads(rsp_text)

        self._user_json = rsp_json

        # JSON to structure
        self._user = from_dict(data_class=OBPUser, data=rsp_json)

    def _get_roles(self) -> OBPRoleList:
        # Load roles

        if self._roles:
            # Cached
            return self._roles
        else:
            # Get role list from backend
            auth_headers = self._auth.get_headers()
            rsp = self._req.api_get('/roles', auth_headers)
            OBPRequest.assert_satus_code(rsp, [200])
            self._roles = from_dict(data_class=OBPRoleList, data=rsp.json())
            return self._roles

    def _add_role(self, role_name: str, bank_id: str = ""):
        # Add role to sysadmin
        payload = {
            "bank_id": bank_id,
            "role_name": role_name
        }

        endpoint = '/users/{}/entitlements'.format(self._user.user_id)
        auth_headers = self._auth.get_headers()
        rsp = self._req.api_post(endpoint, auth_headers, payload)
        OBPRequest.assert_satus_code(rsp, [200, 201, 400])

    def initialize(self):
        # Connect and authenticate sysadmin
        self._auth.authenticate(self._req)
        self._load_user_info()

    def get_user_id(self):
        # Get user id
        return self._user.user_id

    def get_user(self) -> OBPUser:
        # Get user object
        return self._user

    def get_user_json(self) -> dict:
        # Get user json
        return self._user_json

    def get_entitlements(self, bank_id='') -> list[OBPEntitlement]:
        # Return entitlement list for a bank id (default system)
        return [e for e in self._user.entitlements.list_ if e.bank_id == bank_id]

    def init_roles(self):
        # Admin configuration
        self._add_role('CanCreateEntitlementAtAnyBank')

    def add_sys_entitlements(self):
        # Add all system entitlements to admin
        self._assert_ready()

        # self._add_role('CanCreateEntitlementAtAnyBank')

        # Get roles
        roles = self._get_roles()

        # Index entitlement list
        index = dict((e.role_name, e) for e in self._user.entitlements.list_ if e.bank_id == '')

        # Roles to be added
        new_roles = [r.role for r in roles.roles if r.role not in index and not r.requires_bank_id]

        # Add roles
        for r in new_roles:
            self._add_role(r)

        # Reload user info
        self._load_user_info()

    def add_bank_entitlements(self, bank_id: str):
        # Add all system entitlements to admin
        self._assert_ready()

        # Get roles
        roles = self._get_roles()

        # Index entitlement list
        index = dict((e.role_name, e) for e in self._user.entitlements.list_ if e.bank_id == bank_id)

        # Roles to be added
        new_roles = [r.role for r in roles.roles if r.role not in index and r.requires_bank_id]

        # Add roles
        for r in new_roles:
            self._add_role(r, bank_id)

        # Reload user info
        self._load_user_info()

    def get_get_request(self, params: str):
        # Get GET request closure
        auth_headers = self._auth.get_headers()

        def api_get_request():
            return self._req.api_get(params, auth_headers)

        return api_get_request

    def get_post_request(self, params: str, payload: json):
        # Get POST request closure
        auth_headers = self._auth.get_headers()

        def api_post_request():
            return self._req.api_post(params, auth_headers, payload)

        return api_post_request

    def get_post_abs_request(self, params: str, payload: json):
        # Get POST request closure
        auth_headers = self._auth.get_headers()

        def api_post_abs_request():
            return self._req.api_post_abs(params, auth_headers, payload)

        return api_post_abs_request

    def get_put_request(self, params: str, payload: json):
        # Get PUT request closure
        auth_headers = self._auth.get_headers()

        def api_put_request():
            return self._req.api_put(params, auth_headers, payload)

        return api_put_request

    def get_delete_request(self, params: str):
        # Get GET request closure
        auth_headers = self._auth.get_headers()

        def api_delete_request():
            return self._req.api_delete(params, auth_headers)

        return api_delete_request

    def add_role_to_user(self, user_id: str, role_name: str, bank_id: str = ""):
        # Add role to user
        payload = {
            "bank_id": bank_id,
            "role_name": role_name
        }

        endpoint = f'/users/{user_id}/entitlements'
        auth_headers = self._auth.get_headers()
        rsp = self._req.api_post(endpoint, auth_headers, payload)
        OBPRequest.assert_satus_code(rsp, [201])
