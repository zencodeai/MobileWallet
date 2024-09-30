import base64
from typing import List, Tuple, Any


from fastapi import HTTPException
from sqlalchemy.orm import Session

import app_schemas as schemas
import app_models as models
import app_types as types
from app_crud_transaction import get_transaction_by_uid
from app_crud_wallet import get_wallet, get_wallet_by_uid
from app_crud_holder import get_holder
from app_crud_merchant import get_merchant_by_uid
from app_crud_intermediary import get_intermediary_by_uid


# Session data request class
class SessionDataRequest:
    # Session data request

    def __init__(self, db: Session, wallet: models.Wallet, data_type: types.SessionDataType):
        # Initialize session data request
        self._db = db
        self._wallet = wallet
        self._data_type = data_type

    def _get_counterparty(self, db_transaction: models.Transaction) -> Tuple[types.CounterpartyType, Any]:
        # Get counterparty
        # Get counterparty type
        match db_transaction.type:
            case [types.TransactionType.w2w_push, types.TransactionType.w2w_pull]:
                counterparty_type = types.CounterpartyType.wallet
            case types.TransactionType.w2m_push:
                counterparty_type = types.CounterpartyType.merchant
            case [types.TransactionType.deposit, types.TransactionType.withdrawal]:
                counterparty_type = types.CounterpartyType.intermediary
            case [types.TransactionType.w2m_pull, types.TransactionType.w2w_validation, types.TransactionType.w2m_validation]:
                counterparty_type = types.CounterpartyType.transaction
            case _:
                HTTPException(status_code=400, detail="Invalid transaction type")
        # Get counterparty
        match counterparty_type:
            case types.CounterpartyType.wallet:
                # Get wallet
                counterparty_wallet = get_wallet_by_uid(self._db, db_transaction.cuid)
                # Get wallet holder
                counterparty = get_holder(self._db, counterparty_wallet.owner_id)
            case types.CounterpartyType.merchant:
                # Get merchant
                counterparty = get_merchant_by_uid(self._db, db_transaction.cuid)
            case types.CounterpartyType.intermediary:
                # Get intermediary
                counterparty = get_intermediary_by_uid(self._db, db_transaction.cuid)
            case types.CounterpartyType.transaction:
                # Get transaction
                counterparty_tx = get_transaction_by_uid(self._db, db_transaction.cuid)
                if not counterparty_tx:
                    raise HTTPException(status_code=400, detail="Transaction not found")
                # Check transaction type
                if counterparty_tx.type in [types.TransactionType.w2m_pull, types.TransactionType.w2w_validation, types.TransactionType.w2m_validation]:
                    raise HTTPException(status_code=400, detail="Invalid counterparty transaction type")
                # Get counterparty
                counterparty_type, counterparty = self._get_counterparty(counterparty_tx)
            case _:
                HTTPException(status_code=400, detail="Invalid counterparty type")
            
        # Return counterparty
        return counterparty_type, counterparty

    def _load_icon(self, icon_pathname: str) -> str:
        # Load icon
        with open(icon_pathname, 'rb') as f:
            icon = base64.b64encode(f.read()).decode('utf-8')
        # Return icon
        return icon

    def _get_icon_business(self, icon_name: str):
        # Get business icon
        # Get icon pathname
        icon_pathname = f'./data/icons_business/{icon_name}.png'
        # Load icon
        return self._load_icon(icon_pathname)

    def _get_icon_people(self, icon_name: str):
        # Get people icon
        # Get icon pathname
        icon_pathname = f'./data/icons_people/{icon_name}.png'
        # Load icon
        return self._load_icon(icon_pathname)

    def _get_couterparty_icon(self, db_transaction: models.Transaction) -> str:
        # Get counterparty icon
        # Get counterparty type
        counterparty_type, counterparty = self._get_counterparty(db_transaction)
        # Get icon
        match counterparty_type:
            case types.CounterpartyType.wallet:
                db_record: models.Holder = counterparty
                icon = self._get_icon_people(db_record.icon)
            case types.CounterpartyType.merchant:
                db_record: models.Merchant = counterparty
                icon = self._get_icon_business(db_record.icon)
            case types.CounterpartyType.intermediary:
                db_record: models.Intermediary = counterparty
                icon = self._get_icon_business(db_record.icon)
            case _:
                raise HTTPException(status_code=400, detail="Invalid record type")
        # Return icon
        return icon

    def _get_pending_tx_list(self) -> List[schemas.PendingTransaction]:
        # Get pending transactions list
        # Get transactions
        db_transactions = self._db.query(models.Transaction).filter(
            models.Transaction.wallet_id == self._wallet.id,
            models.Transaction.status == types.TransactionStatus.pending,
        ).all()
        # Return transactions
        return [
            schemas.PendingTransaction(
                uid=db_transaction.uid,
                name=db_transaction.name,
                description=db_transaction.description,
                type=db_transaction.type,
                amount=db_transaction.amount,
                cuid=db_transaction.cuid,
                timestamp=db_transaction.timestamp,
                icon=self._get_couterparty_icon(db_transaction),
            )
            for db_transaction in db_transactions
        ]

    def request_session_data(self) -> List[schemas.SessionData]:
        # Process session data request
        # Get wallet
        db_wallet = get_wallet(self._db, self._wallet.id)
        if not db_wallet:
            raise HTTPException(status_code=400, detail="Wallet not found")
        
        # Get session data
        match self._data_type:
            case types.SessionDataType.tx_pending_list:
                # Get pending transactions list
                return self._get_pending_tx_list()

            case _:
                raise HTTPException(status_code=400, detail="Invalid session data type")

    