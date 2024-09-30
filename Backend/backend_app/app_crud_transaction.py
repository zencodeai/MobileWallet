import datetime
import typing

from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID

# Create transaction
def create_transaction_with_uid(
        db: Session,
        uid: str,
        wallet: models.Wallet, 
        name: str,
        description: str,
        type: schemas.TransactionType,
        status: schemas.TransactionStatus,
        amount: int,
        cuid: str,
        reason: str = '',
        payload: bytes = b'',
) -> models.Transaction:

    # Timestamp as integer
    timestamp = int(datetime.datetime.now().timestamp())

    # Create transaction
    db_transaction = models.Transaction(
        uid=uid,
        name=name,
        description=description,
        wallet_id=wallet.id,
        type=type,
        status=status,
        amount=amount,
        cuid=cuid,
        timestamp=timestamp,
        payload=payload,
        reason=reason,
    )

    # Add transaction to database
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)
    # Return transaction
    return db_transaction


# Create transaction
def create_transaction(
        db: Session, 
        wallet: models.Wallet, 
        name: str,
        description: str,
        type: schemas.TransactionType,
        status: schemas.TransactionStatus,
        amount: int,
        cuid: str,
        reason: str = '',
        payload: bytes = b'',
) -> models.Transaction:

    return create_transaction_with_uid(
        db,
        AppUID.generate(),
        wallet,
        name,
        description,
        type,
        status,
        amount,
        cuid,
        reason,
        payload,
    )

# Get transaction by UID
def get_transaction_by_uid(
        db: Session,
        uid: str,
) -> models.Transaction:
    # Get transaction
    db_transaction = db.query(models.Transaction).filter(models.Transaction.uid == uid).first()
    # Return transaction
    return db_transaction

# Update transaction status
def update_transaction_status(
        db: Session,
        transaction: models.Transaction,
        status: schemas.TransactionStatus,
        reason: str,
        payload: bytes = b'',
) -> models.Transaction:

    # Update transaction
    transaction.status = status
    transaction.reason = reason
    transaction.payload = payload

    # commit changes
    db.commit()
    db.refresh(transaction)
    # Return transaction
    return transaction

# Get transactions list for wallet
def get_transactions_list(
        db: Session,
        wallet: models.Wallet,
        skip: int = 0,
        limit: int = 100,
) -> typing.List[models.Transaction]:
    # Get transactions list
    return db.query(models.Transaction).filter(models.Transaction.wallet_id == wallet.id).offset(skip).limit(limit).all()

# Get transaction by id
def get_transaction_by_id(
        db: Session,
        id: int,
):
    # Get transaction
    db_transaction = db.query(models.Transaction).filter(models.Transaction.id == id).first()
    return db_transaction

# Delete transaction
def delete_transaction(
        db: Session,
        db_transaction: models.Transaction,
):

    # Delete transaction
    db.delete(db_transaction)
    # commit changes
    db.commit()
    # Return transaction
    return db_transaction
