from dataclasses import dataclass, field


#   "balance":{
#     "currency":"eCAN",
#     "amount":"0"
#   },
@dataclass
class OBPAmount:
	# Amount object class
	currency: str
	amount: str


#   "account_routings":[{
#     "scheme":"AccountNumber",
#     "address":"4930396"
#   }],
@dataclass
class OBPRouting:
	# Routing object class
	scheme: str
	address: str


#
# {
#     "id":"5995d6a2-01b3-423c-a173-5481df49bdaf",
#     "provider":"http://127.0.0.1:8080",
#     "display_name":"OBP"
#  }
#
@dataclass
class OBPOwner:
	# Owner object class
	id: str
	provider: str
	display_name: str


#
# {
#     "id":"5995d6a2-01b3-423c-a173-5481df49bdaf",
#     "value":"OBP",
#     "date":"1100-01-01T00:00:00Z",
#     "user":{
#       "id":"5995d6a2-01b3-423c-a173-5481df49bdaf",
#       "provider":"http://127.0.0.1:8080",
#       "display_name":"OBP"
# }
#
@dataclass
class OBPTag:
	# Tag object class
	id: str
	value: str
	date: str
	user: OBPOwner
