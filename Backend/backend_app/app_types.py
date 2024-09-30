import enum
import secrets
import base64


class WalletStatus(enum.Enum):
    # Wallet statuses
    new = "new"
    provisioned = "provisioned"
    initialized = "initialized"
    active = "active"
    inactive = "inactive"
    closed = "closed"
    error = "error"

class TransactionStatus(enum.Enum):
    # Transaction statuses
    new = "new"
    pending = "pending"
    confirmed = "confirmed"
    rejected = "rejected"
    failed = "failed"


class TransactionType(enum.Enum):
    # Transaction types
    balance = "balance"
    offine = "offline"
    deposit = "deposit"
    withdrawal = "withdrawal"
    w2w_push = "w2w_push"
    w2w_pull = "w2w_pull"
    w2m_push = "w2m_push"
    w2m_pull = "w2m_pull"
    w2w_validation = "w2w_validation"
    w2m_validation = "w2m_validation"


class CounterpartyType(enum.Enum):
    # Transaction types
    wallet = "wallet"
    merchant = "merchant"
    intermediary = "intermediary"
    transaction = "transaction"
    none = "none"


class SessionDataType(enum.Enum):
    # Session data types
    none = "none"
    tx_pending_list = "tx_pending_list"
    fav_holders_list = "fav_holders_list"
    fav_merchants_list = "fav_merchants_list"
    fav_intermediaries_list = "fav_intermediaries_list"


class AppUID:
    # Application UID

    def __init__(self, val: str = None):
        # Initialize UID
        if val:
            self.val = val
        else:
            self.val = self.generate()
        pass
    
    def __str__(self):
        # Return UID as string
        return self.val
    
    def __bytes__(self):
        # Return base 64 encoded UID as bytes string
        base64.b64decode(self.val)

    # Generate UID
    @staticmethod
    def generate()->str:
        # Generate UID as 32 bytes random binary string, encoded as url safe base64
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
