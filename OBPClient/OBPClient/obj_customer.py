from dataclasses import dataclass, field
from typing import Optional

from OBPClient.obj_common import OBPAmount


@dataclass
class OBPCustomerFaceImage:
    # Customer face image object class
    url: str
    date: str


@dataclass
class OBPCustomerCreditRating:
    # Customer credit rating object class
    rating: str
    source: str


# {
#   "bank_id":"gh.29.uk",
#   "customer_id":"7uy8a7e4-6d02-40e3-a129-0b2bf89de8uh"
# }
@dataclass
class OBPCustomerMinimal:
    # Customer minimal object class
    bank_id: str
    customer_id: str


# {
#   "user_customer_links":[{
#     "user_customer_link_id":"9ca9a7e4-6d02-40e3-a129-0b2bf89de9b1",
#     "customer_id":"7uy8a7e4-6d02-40e3-a129-0b2bf89de8uh",
#     "user_id":"9ca9a7e4-6d02-40e3-a129-0b2bf89de9b1",
#     "date_inserted":"1100-01-01T00:00:00Z",
#     "is_active":true
#   }]
# }
@dataclass
class OBPUserCustomerLink:
    # User customer link object class
    user_customer_link_id: str
    customer_id: str
    user_id: str
    date_inserted: str
    is_active: bool


@dataclass
class OBPUserCustomerLinkList:
    # User customer link list object class
    user_customer_links: list[OBPUserCustomerLink] = field(default_factory=list)


#
# {
#   "bank_id":"gh.29.uk",
#   "customer_id":"7uy8a7e4-6d02-40e3-a129-0b2bf89de8uh",
#   "customer_number":"5987953",
#   "legal_name":"Eveline Tripman",
#   "mobile_phone_number":"+44 07972 444 876",
#   "email":"felixsmith@example.com",
#   "face_image":{
#     "url":"www.openbankproject",
#     "date":"1100-01-01T00:00:00Z"
#   },
#   "date_of_birth":"1100-01-01T00:00:00Z",
#   "relationship_status":"single",
#   "dependants":1,
#   "dob_of_dependants":["1100-01-01T00:00:00Z"],
#   "credit_rating":{
#     "rating":"OBP",
#     "source":"OBP"
#   },
#   "credit_limit":{
#     "currency":"EUR",
#     "amount":"0"
#   },
#   "highest_education_attained":"Master",
#   "employment_status":"worker",
#   "kyc_status":true,
#   "last_ok_date":"2022-03-21T14:38:51Z",
#   "title":"Dr.",
#   "branch_id":"DERBY6",
#   "name_suffix":"Sr"
# }
#
@dataclass
class OBPCustomer(OBPCustomerMinimal):
    # Customer object class
    customer_number: str
    legal_name: str
    mobile_phone_number: str
    email: str
    face_image: Optional[OBPCustomerFaceImage] = None
    date_of_birth: str = ""
    relationship_status: str = ""
    dependants: int = 0
    dob_of_dependants: list[str] = field(default_factory=list)
    credit_rating: Optional[OBPCustomerCreditRating] = None
    credit_limit: Optional[OBPAmount] = None
    highest_education_attained: str = ""
    employment_status: str = ""
    kyc_status: bool = False
    last_ok_date: str = ""
    title: str = ""
    branch_id: str = ""
    name_suffix: str = ""


# {
#   "bank_id":"gh.29.uk",
#   "customer_id":"7uy8a7e4-6d02-40e3-a129-0b2bf89de8uh",
#   "customer_number":"5987953",
#   "legal_name":"Eveline Tripman",
#   "mobile_phone_number":"+44 07972 444 876",
#   "email":"felixsmith@example.com",
#   "face_image":{
#     "url":"www.openbankproject",
#     "date":"1100-01-01T00:00:00Z"
#   },
#   "date_of_birth":"1100-01-01T00:00:00Z",
#   "relationship_status":"single",
#   "dependants":1,
#   "dob_of_dependants":["1100-01-01T00:00:00Z"],
#   "credit_rating":{
#     "rating":"OBP",
#     "source":"OBP"
#   },
#   "credit_limit":{
#     "currency":"EUR",
#     "amount":"0"
#   },
#   "highest_education_attained":"Master",
#   "employment_status":"worker",
#   "kyc_status":true,
#   "last_ok_date":"2022-03-21T14:38:51Z",
#   "title":"Dr.",
#   "branch_id":"DERBY6",
#   "name_suffix":"Sr",
#   "customer_attributes":[{
#     "customer_attribute_id":"7uy8a7e4-6d02-40e3-a129-0b2bf89de8uh",
#     "name":"SPECIAL_TAX_NUMBER",
#     "type":"STRING",
#     "value":"123456789"
#   }],
#   "accounts":[{
#     "account_id":"8ca8a7e4-6d02-40e3-a129-0b2bf89de9f0",
#     "label":"My Account",
#     "product_code":"787LOW",
#     "balance":{
#       "currency":"EUR",
#       "amount":"0"
#     },
#     "branch_id":"DERBY6",
#     "account_routings":[{
#       "scheme":"AccountNumber",
#       "address":"4930396"
#     }],
#     "account_attributes":[{
#       "contract_code":"LKJL98769F",
#       "product_code":"1234BW",
#       "account_attribute_id":"613c83ea-80f9-4560-8404-b9cd4ec42a7f",
#       "name":"OVERDRAFT_START_DATE",
#       "type":"DATE_WITH_DAY",
#       "value":"2012-04-23"
#     }]
#   }]
# }
@dataclass
class OBPCustomerFull(OBPCustomer):
    # Customer full object class
    customer_attributes: list[dict] = field(default_factory=list)
    accounts: list[dict] = field(default_factory=list)
