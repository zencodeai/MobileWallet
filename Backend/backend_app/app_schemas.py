from __future__ import annotations
from typing import List
from pydantic import BaseModel

from app_types import WalletStatus, TransactionType, TransactionStatus, SessionDataType


class IntermediaryBase(BaseModel):
    # Intermediate common fields
    name: str
    description: str
    icon: str


class IntermediaryCreate(IntermediaryBase):
    # Intermediate fields required for creation
    pass


class Intermediary(IntermediaryBase):
    # Intermediate schema
    id: int
    uid: str
    accounts: List[Account] = []

    class Config:
        orm_mode = True


class MerchantBase(BaseModel):
    # Merchants common fields
    name: str
    description: str
    icon: str


class MerchantCreate(MerchantBase):
    # Merchants fields required for creation
    pass


class Merchant(MerchantBase):
    # Merchants schema
    id: int
    uid: str

    class Config:
        orm_mode = True


class AccountBase(BaseModel):
    # Financial accounts common fields
    name: str
    description: str
    owner_id: int
    holder_id: int


class AccountCreate(AccountBase):
    # Financial accounts fields required for creation
    pass


class Account(AccountBase):
    # Financial accounts schema
    id: int
    uid: str

    class Config:
        orm_mode = True


class HolderBase(BaseModel):
    # Financial account holders common fields
    name: str
    description: str
    icon: str


class HolderCreate(HolderBase):
    # Financial account holders fields required for creation
    pass


class Holder(HolderBase):
    # Financial account holders schema
    id: int
    uid: str
    accounts: List[Account] = []
    wallets: List[Wallet] = []
    fav_holders: List[FavHolder] = []

    class Config:
        orm_mode = True


class WalletBase(BaseModel):
    # Wallets common fields
    name: str
    description: str
    balance: int
    owner_id: int


class WalletCreate(WalletBase):
    # Wallets fields required for creation
    pass


class WalletPublic(WalletBase):
    # Wallets public fields
    id: int
    uid: str
    status: WalletStatus
    token: str

    class Config:
        orm_mode = True


class Wallet(WalletPublic):
    # Wallets schema
    cl_cert: bytes
    cl_sig_key: bytes
    tx_sig_key: bytes
    tx_enc_key: bytes
    st_enc_key: bytes

    transactions: List[Transaction] = []

    class Config:
        orm_mode = True


class TransactionBase(BaseModel):
    # Transactions common fields
    amount: int
    description: str

class TransactionOnlineCreate(BaseModel):
    name: str
    description: str
    amount: int
    wallet_id: int
    cuid: str


class TransactionPublic(TransactionBase):
    # Transactions public fields
    id: int
    uid: str
    name: str
    type: TransactionType
    status: TransactionStatus
    cuid: str
    timestamp: int
    reason: str

    class Config:
        orm_mode = True


class Transaction(TransactionPublic):
    # Transactions schema
    wallet: Wallet
    payload: bytes

    class Config:
        orm_mode = True


class FavHolderBase(BaseModel):
    # Favourite holders common fields
    name: str
    description: str
    holder_id: int
    fav_holder_id: int


class FavHolderCreate(FavHolderBase):
    # Favourite holders fields required for creation
    pass


class FavHolder(FavHolderBase):
    # Favourite holders schema
    id: int
    uid: str

    class Config:
        orm_mode = True


class FavMerchantBase(BaseModel):
    # Favourite merchants common fields
    name: str
    description: str
    holder_id: int
    fav_merchant_id: int


class FavMerchantCreate(FavMerchantBase):
    # Favourite merchants fields required for creation
    pass


class FavMerchant(FavMerchantBase):
    # Favourite merchants schema
    id: int
    uid: str

    class Config:
        orm_mode = True 


class ProvisioningData(BaseModel):
    # Provisioning endpoint data
    token: str
    data: str


class BalanceInitData(BaseModel):
    # Balance initalization endpoint data
    token: str
    data: str


class OnlineTransactionData(BaseModel):
    # Online transaction endpoint data
    token: str
    data: str


class ProcessingData(BaseModel):
    # Message data
    session_id: str
    data: str


class RequestSessionData(BaseModel):
    # Request data
    session_id: str
    data_type: SessionDataType


class SessionData(BaseModel):
    pass


class SessionDataList(BaseModel):
    # Session data list
    data: List[SessionData]


class PendingTransaction(SessionData):
    # Pending transaction
    uid: str
    cuid: str
    amount: int
    timestamp: int
    icon: str
    name: str
    description: str
    type: TransactionType


# Update forward references
Holder.update_forward_refs()
Account.update_forward_refs()
Wallet.update_forward_refs()
Transaction.update_forward_refs()
