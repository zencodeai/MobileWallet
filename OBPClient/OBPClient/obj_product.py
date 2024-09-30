from dataclasses import dataclass


# {
#   "bank_id":"gh.29.uk",
#   "product_code":"1234BW",
#   "parent_product_code":"787LOW",
#   "name":"Deposit Account 1",
#   "more_info_url":"www.example.com/abc",
#   "terms_and_conditions_url":"www.example.com/xyz",
#   "description":"This an optional field. Maximum length is 2000. It can be any characters here.",
#   "meta":{
#     "license":{
#       "id":"ODbL-1.0",
#       "name":"Open Database License"
#     }
#   }
# }
@dataclass
class OBPProduct:
	# Product object class
	bank_id: str
	product_code: str
	parent_product_code: str | None
	name: str
	more_info_url: str | None
	terms_and_conditions_url: str | None
	description: str | None
	meta: dict | None
