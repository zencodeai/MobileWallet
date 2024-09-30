import json
from abc import ABC, abstractmethod
from enum import Enum, auto

import requests.status_codes

from OBPClient.obp_client import OBPClientRoot
from OBPClient.obp_request import OBPRequest


class OBPAuthenticationType(Enum):
    # Authentication types
    AUTH_NONE = auto()
    AUTH_DIRECT = auto()


class OBPAuthentication(OBPClientRoot, ABC):
    # Authentication root class

    def __init__(self):
        # Class constructor
        super().__init__()

    @abstractmethod
    def get_auth_type(self):
        # Default authentication type
        return OBPAuthenticationType.AUTH_NONE

    @abstractmethod
    def authenticate(self, _: OBPRequest):
        # Default authentication method
        pass

    @abstractmethod
    def get_headers(self) -> dict:
        # Default authentication method
        return {}


class OBPDirectLoginToken(object):

    def __init__(self, token):
        # Class constructor
        self._token = token

    def get_token(self):
        # Token getter
        return self._token

    def get_headers(self) -> dict:
        # Default authentication method
        return {'Authorization': 'DirectLogin token="{}"'.format(self._token)}


class OBPAuthenticationDirect(OBPAuthentication):
    # Direct login authentication

    # Direct login endpoint
    _endpoint = '/my/logins/direct'

    def __init__(self, user_name: str, user_password: str, oauth_consumer_key: str):
        # Class constructor
        super().__init__()
        self._user_name = user_name
        self._user_password = user_password
        self._oauth_consumer_key = oauth_consumer_key
        self._auth_token = None

    def get_auth_type(self):
        # Authentication type
        return OBPAuthenticationType.AUTH_DIRECT

    def get_headers(self) -> dict:
        # Default authentication method
        if self._auth_token is None:
            return {}
        else:
            return self._auth_token.get_headers()

    def authenticate(self, client: OBPRequest):
        # Direct login authentication method

        # Prepare headers
        authorization = 'DirectLogin username="{}", password="{}", consumer_key="{}"'.format(
            self._user_name, self._user_password, self._oauth_consumer_key
        )

        headers = {
            'Accept': 'application/json',
            'Authorization': authorization
        }

        # Send request
        print(headers)
        req = client.post(self._endpoint, headers)

        if req.status_code != 201:
            raise Exception('Unexpected status code {} : {}'.format(req.status_code, req.text))

        body = req.json()
        print(body)
        self._auth_token = OBPDirectLoginToken(**body)
