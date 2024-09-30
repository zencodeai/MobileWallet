from dataclasses import dataclass, field
from typing import Optional


# User: 0f44bd13-48e3-4d6f-a258-d0dec63ead2a
# {
#     "user_id": "0f44bd13-48e3-4d6f-a258-d0dec63ead2a",
#     "email": "james.smith@obp.ca",
#     "provider_id": "Alias.Massimo",
#     "provider": "http://127.0.0.1:8080",
#     "username": "Alias.Massimo",
#     "entitlements": {
#         "list_": [
#             {
#                 "entitlement_id": "b4e4b8bc-3a42-4071-ab24-45b1346f34e6",
#                 "role_name": "CanCreateAnyTransactionRequest",
#                 "bank_id": "b.890.ca"
#             },
#             {
#                 "entitlement_id": "08f63806-15c8-4673-b925-3ea786ad63a7",
#                 "role_name": "CanGetUserCustomerLink",
#                 "bank_id": "b.890.ca"
#             },
#             {
#                 "entitlement_id": "74a22675-bc6c-4da2-aec4-db9bdc48a452",
#                 "role_name": "CanGetAnyUser",
#                 "bank_id": ""
#             }
#         ]
#     },
#     "views": {
#         "list_": [
#             {
#                 "bank_id": "b.890.ca",
#                 "account_id": "e15958e9-dd3f-43c2-8fc1-8b9feaaad9a7",
#                 "view_id": "owner"
#             }
#         ]
#     }
# }
#

# {
#     "id": "40be5c1a-8d30-4af9-a461-6bdf76cc10ef",
#     "type": "ACCOUNT",
#     "from": {
#         "bank_id": "b.890.ca",
#         "account_id": "98d17919-0930-49d6-a8a7-c2a4b6570709"
#     },
#     "details": {
#         "to_sandbox_tan": {
#             "bank_id": "b.890.ca",
#             "account_id": "98d17919-0930-49d6-a8a7-c2a4b6570709"
#         },
#         "value": {
#             "currency": "CAD",
#             "amount": "2000"
#         },
#         "description": "Send amount"
#     },
#     "transaction_ids": [
#         ""
#     ],
#     "status": "INITIATED",
#     "start_date": "2023-03-28T20:47:54Z",
#     "end_date": "2023-03-28T20:47:54Z",
#     "challenges": [
#         {
#             "id": "c391c05b-06d0-4a2e-8146-788c6772822f",
#             "user_id": "0f44bd13-48e3-4d6f-a258-d0dec63ead2a",
#             "allowed_attempts": 3,
#             "challenge_type": "OBP_TRANSACTION_REQUEST_CHALLENGE",
#             "link": "http://127.0.0.1:8080/obp/v4.0.0/banks/b.890.ca/accounts/98d17919-0930-49d6-a8a7-c2a4b6570709/owner/transaction-request-types/ACCOUNT/transaction-requests/40be5c1a-8d30-4af9-a461-6bdf76cc10ef/challenge"
#         }
#     ],
#     "charge": {
#         "summary": "Total charges for completed transaction",
#         "value": {
#             "currency": "CAD",
#             "amount": "2.0"
#         }
#     }
# }
#

def get_transaction_request_account(bank_id: str, account_id: str, amount: int, message: str) -> dict:
    # Get ACCOUNT transaction request
    return {
        "to": {
            "bank_id": bank_id,
            "account_id": account_id,
        },
        "value": {
            "currency": "CAD",
            "amount": str(amount)
        },
        "description": message
    }


# {
#     "id": "4d0819c8-1463-46eb-be22-24799bda6e29",
#     "type": "ACCOUNT",
#     "from": {
#         "bank_id": "b.890.ca",
#         "account_id": "79e50da7-bb2b-4a91-b08e-eadc6fcfa2d1"
#     },
#     "details": {
#         "to_sandbox_tan": {
#             "bank_id": "b.890.ca",
#             "account_id": "79e50da7-bb2b-4a91-b08e-eadc6fcfa2d1"
#         },
#         "value": {
#             "currency": "CAD",
#             "amount": "100"
#         },
#         "description": "Send amount"
#     },
#     "transaction_ids": [
#         ""
#     ],
#     "status": "INITIATED",
#     "start_date": "2023-03-29T00:00:00Z",
#     "end_date": "2023-03-29T00:00:00Z",
#     "challenge": {
#         "id": "challenges number:0",
#         "allowed_attempts": 3,
#         "challenge_type": "OBP_TRANSACTION_REQUEST_CHALLENGE"
#     },
#     "charge": {
#         "summary": "Total charges for completed transaction",
#         "value": {
#             "currency": "CAD",
#             "amount": "2.0"
#         }
#     }
# }

@dataclass
class TransactionFrom:
    bank_id: str
    account_id: str


@dataclass
class TransactionToSandBoxTan:
    bank_id: str
    account_id: str


@dataclass
class TransactionValue:
    currency: str
    amount: str


@dataclass
class TransactionDetails:
    value: TransactionValue
    description: str
    to_sandbox_tan: Optional[TransactionToSandBoxTan] = None


@dataclass
class TransactionChallenge:
    id: str
    allowed_attempts: int
    challenge_type: str


@dataclass
class TransactionCharge:
    summary: str
    value: TransactionValue


@dataclass
class TransactionRequest:
    id: str
    type: str
    from_: TransactionFrom
    details: TransactionDetails
    transaction_ids: list[str]
    status: str
    start_date: str
    end_date: str
    challenge: Optional[TransactionChallenge] = None
    charge: Optional[TransactionCharge] = None


@dataclass
class TransactionRequestWithChargesList:
    transaction_requests_with_charges: list[TransactionRequest]
