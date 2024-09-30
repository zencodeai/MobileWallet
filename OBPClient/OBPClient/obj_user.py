from dataclasses import dataclass, field
from OBPClient.obj_entitlement import OBPEntitlement
from OBPClient.obj_view import OBPView


@dataclass
class OBPUserEntitlementList:
	# OBPUser entitlement list
	list_: list[OBPEntitlement] = field(default_factory=list)


# {
#   "bank_id": "b.890.ca",
#   "account_id": "c7a97004-4bc6-4d70-9b34-b5c1f70625a8",
#   "view_id": "owner"
# }
@dataclass
class OBPUserView:
	# OBPUser view list
	bank_id: str
	account_id: str
	view_id: str


@dataclass
class OBPUserViewList:
	# OBPUser entitlement list
	list_: list[OBPUserView] = field(default_factory=list)


# @dataclass
# class OBPUser1:
# 	# User object class
# 	user_id: str
# 	email: str
# 	provider_id: str
# 	provider: str
# 	username: str
# 	entitlements: OBPUserEntitlementList = None
# 	views: OBPUserViewList = None

# Class: User
# {
#     "user_id":"9ca9a7e4-6d02-40e3-a129-0b2bf89de9b1",
#     "email":"felixsmith@example.com",
#     "provider_id":"Chris",
#     "provider":"http://127.0.0.1:8080",
#     "username":"felixsmith",
#     "entitlements":{
#       "list":[{
#         "entitlement_id":"6fb17583-1e49-4435-bb74-a14fe0996723",
#         "role_name":"CanQueryOtherUser",
#         "bank_id":"gh.29.uk"
#       }]
#     },
#     "is_deleted":false,
#     "last_marketing_agreement_signed_date":"1100-01-01T00:00:00Z",
#     "is_locked":false
#   }
@dataclass
class OBPUser:
	# User object class
	user_id: str
	email: str
	provider_id: str
	provider: str
	username: str
	entitlements: OBPUserEntitlementList = None
	views: OBPUserViewList = None
	is_deleted: bool = False
	last_marketing_agreement_signed_date: str | None = None
	is_locked: bool = False


#
# {
#   "users":[{
#     "user_id":"9ca9a7e4-6d02-40e3-a129-0b2bf89de9b1",
#     "email":"felixsmith@example.com",
#     "provider_id":"Chris",
#     "provider":"http://127.0.0.1:8080",
#     "username":"felixsmith",
#     "entitlements":{
#       "list":[{
#         "entitlement_id":"6fb17583-1e49-4435-bb74-a14fe0996723",
#         "role_name":"CanQueryOtherUser",
#         "bank_id":"gh.29.uk"
#       }]
#     },
#     "is_deleted":false,
#     "last_marketing_agreement_signed_date":"1100-01-01T00:00:00Z",
#     "is_locked":false
#   }]
# }
@dataclass
class OBPUserList:
	# OBPUser list
	users: list[OBPUser] = field(default_factory=list)
