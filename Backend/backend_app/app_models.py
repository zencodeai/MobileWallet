from sqlalchemy import Column, ForeignKey, Integer, String, LargeBinary, Enum
from sqlalchemy.orm import relationship

from app_database import Base
from app_types import WalletStatus, TransactionStatus, TransactionType


class Intermediary(Base):
    # Financials intermediaries (banks, payment processors, etc.)
    __tablename__ = "intermediaries"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    icon = Column(String)

    accounts = relationship("Account", back_populates="owner")


class Merchant(Base):
    # Merchants
    __tablename__ = "merchants"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    icon = Column(String)


class Account(Base):
    # Financial accounts (bank accounts, credit cards, etc.)
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("intermediaries.id"))
    holder_id = Column(Integer, ForeignKey("holders.id"))

    owner = relationship("Intermediary", back_populates="accounts")
    holder = relationship("Holder", back_populates="accounts")


class Holder(Base):
    # Financial account holders (people, companies, etc.)
    __tablename__ = "holders"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    icon = Column(String)

    accounts = relationship("Account", back_populates="holder")
    wallets = relationship("Wallet", back_populates="owner")


class Wallet(Base):
    # Wallets
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("holders.id"))
    balance = Column(Integer)
    status = Column(Enum(WalletStatus), default=WalletStatus.new)
    token = Column(String, unique=True, index=True)
    cl_cert = Column(LargeBinary)
    cl_sig_key = Column(LargeBinary)
    tx_sig_key_pub = Column(LargeBinary)
    tx_sig_key_prv = Column(LargeBinary)
    tx_enc_key = Column(LargeBinary)
    st_enc_key = Column(LargeBinary)

    owner = relationship("Holder", back_populates="wallets")
    transactions = relationship("Transaction", back_populates="wallet")


class Transaction(Base):
    # Transactions
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String)
    description = Column(String)
    wallet_id = Column(Integer, ForeignKey("wallets.id"))
    type = Column(Enum(TransactionType))
    status = Column(Enum(TransactionStatus), default=TransactionStatus.new)
    amount = Column(Integer)
    cuid = Column(String)
    timestamp = Column(Integer)
    payload = Column(LargeBinary)
    reason = Column(String)

    wallet = relationship("Wallet", back_populates="transactions")


class FavHolder(Base):
    # Favorite holders
    __tablename__ = "fav_holders"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    holder_id = Column(Integer, ForeignKey("holders.id"))
    fav_holder_id = Column(Integer, ForeignKey("holders.id"))

    holder = relationship("Holder", foreign_keys=[holder_id])
    fav_holder = relationship("Holder", foreign_keys=[fav_holder_id])


class FavMerchant(Base):
    # Favorite merchants
    __tablename__ = "fav_merchants"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    holder_id = Column(Integer, ForeignKey("holders.id"))
    fav_merchant_id = Column(Integer, ForeignKey("merchants.id"))

    holder = relationship("Holder", foreign_keys=[holder_id])
    fav_merchant = relationship("Merchant", foreign_keys=[fav_merchant_id])
