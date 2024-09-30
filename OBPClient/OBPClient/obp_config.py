import json
from typing import TextIO
from dacite import from_dict
from dataclasses import dataclass, field
from OBPClient.obp_authentication import OBPAuthenticationType, OBPAuthentication, OBPAuthenticationDirect
from OBPClient.obp_request import OBPRequest
from OBPClient.obp_admin import OBPSysAdmin


@dataclass
class OBPConfig:
    # OBP Client configuration
    description: str
    api_root: str
    api_version: str
    host_prefix: str
    host_name: str
    auth_name: str
    user_name: str
    user_password: str
    oauth_consumer_key: str
    oauth_consumer_secret: str
    face_image_url: str
    default_bank_data: str
    default_user_data: str
    default_user_template: str
    default_bank_id: str
    default_password: str
    auth_type: OBPAuthenticationType = field(init=False)

    def __post_init__(self):
        match self.auth_name:
            case 'direct':
                self.auth_type = OBPAuthenticationType.AUTH_DIRECT
            case _:
                self.auth_type = OBPAuthenticationType.AUTH_NONE

    @classmethod
    def get_config(cls, config_fp: TextIO):
        # Create config object from JSON encoded file
        config_json = json.load(config_fp)
        return from_dict(data_class=OBPConfig, data=config_json)

    def get_authentication(self) -> OBPAuthentication:
        # Get authentication object
        match self.auth_type:
            case OBPAuthenticationType.AUTH_DIRECT:
                return OBPAuthenticationDirect(self.user_name, self.user_password, self.oauth_consumer_key)
            case _:
                raise Exception('Invalid authentication type')

    def get_default_bank_data(self):
        # Get default bank data
        return self.default_bank_data

    def get_default_user_data(self):
        # Get default user data
        return self.default_user_data

    def get_default_user_template(self):
        # Get default user template
        return self.default_user_template

    def get_default_bank_id(self):
        # Get default bank id
        return self.default_bank_id

    def get_default_password(self):
        # Get default password
        return self.default_password

    def get_client(self):
        # Get API client object instance
        return OBPRequest(self.api_root, self.api_version, self.host_prefix, self.host_name)

    def get_admin(self) -> OBPSysAdmin:
        # Get OBPSysAdmin object instance
        return OBPSysAdmin(self.get_authentication(), self.get_client())

    def get_user(self, user_name: str, user_password: str) -> OBPSysAdmin:
        # Get account admin object instance
        auth = OBPAuthenticationDirect(user_name, user_password, self.oauth_consumer_key)
        return OBPSysAdmin(auth, self.get_client())
