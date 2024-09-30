from dataclasses import dataclass, field

from OBPClient.obj_common import OBPAmount, OBPRouting, OBPOwner, OBPTag
from OBPClient.obj_view import OBPView


#
# {
#     "product_code":"1234BW",
#     "account_attribute_id":"613c83ea-80f9-4560-8404-b9cd4ec42a7f",
#     "name":"OVERDRAFT_START_DATE",
#     "type":"DATE_WITH_DAY",
#     "value":"2012-04-23",
#     "product_instance_code":"LKJL98769F"
# }
#
@dataclass
class OBPAccountAttribute:
	# Account Attribute object class
	product_code: str
	account_attribute_id: str
	name: str
	type: str
	value: str
	product_instance_code: str


# {
#     "account_id": "0db7e1c6-c8e4-11ed-9828-012c1b082414",
#     "user_id": "3c3d0661-8340-4eb0-8a78-368aed4a17e5",
#     "label": "OBP client account",
#     "product_code": "OBP-1",
#     "balance": {
#         "currency": "CAD",
#         "amount": "0.00"
#     },
#     "branch_id": "Online",
#     "account_routings": [],
#     "account_attributes": []
# }
@dataclass
class OBPAccount:
	account_id: str
	user_id: str
	label: str
	product_code: str
	balance: OBPAmount
	branch_id: str
	account_routings: list[OBPRouting] = field(default_factory=list)
	account_attributes: list[OBPAccountAttribute] = field(default_factory=list)


# {
#   "accounts":[{
#     "id":"8ca8a7e4-6d02-48e3-a029-0b2bf89de9f0",
#     "label":"NoneLabel",
#     "bank_id":"gh.29.uk",
#     "views_available":[{
#       "id":"1",
#       "short_name":"HHH",
#       "is_public":true
#     }]
#   }]
# }
@dataclass
class OBPAccountViewAvailable:
	id: str
	short_name: str
	is_public: bool


@dataclass
class OBPAccountShort:
	id: str
	label: str
	bank_id: str
	views_available: list[OBPAccountViewAvailable] = field(default_factory=list)


@dataclass
class OBPAccountList:
	accounts: list[OBPAccountShort] = field(default_factory=list)
