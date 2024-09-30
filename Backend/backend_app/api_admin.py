from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app_database import get_db
from app_crud_intermediary import create_intermediary, get_intermediary_by_name, get_intermediary_by_id, get_intermediaries_list
from app_crud_merchant import create_merchant, get_merchant_by_name, get_merchent_by_id, get_merchants_list, get_merchant_by_uid
from app_crud_holder import create_holder, get_holder_by_name, get_holders_list, get_holder
from app_crud_account import create_account, get_account_by_name
from app_crud_fav_holder import create_fav_holder, get_fav_holder_by_name
from app_crud_fav_merchant import create_fav_merchant, get_fav_merchant_by_name
from app_crud_wallet import create_wallet, get_wallet, get_wallets_list, delete_wallet, get_wallet_by_uid
from app_crud_transaction import get_transactions_list, delete_transaction, get_transaction_by_id, create_transaction
import app_schemas as schemas

# API router for admin
router_api_admin = APIRouter()

# Get backend status
@router_api_admin.get("/status")
def status():
    return {"status": "OK"}

# Create intermediary
@router_api_admin.put("/intermediary")
def create_intermediary_api(intermediary: schemas.IntermediaryCreate, db: Session = Depends(get_db)):

    # Check if intermediary already exists
    db_intermediary = get_intermediary_by_name(db, intermediary.name)
    if db_intermediary:
        raise HTTPException(status_code=400, detail="Intermediary already exists")

    return create_intermediary(db, intermediary)

# Create merchant
@router_api_admin.put("/merchant")
def create_merchant_api(merchant: schemas.MerchantCreate, db: Session = Depends(get_db)):

    # Check if merchant already exists
    db_merchant = get_merchant_by_name(db, merchant.name)
    if db_merchant:
        raise HTTPException(status_code=400, detail="Merchant already exists")

    return create_merchant(db, merchant)

# Create holder
@router_api_admin.put("/holder")
def create_holder_api(holder: schemas.HolderCreate, db: Session = Depends(get_db)):

    # Check if holder already exists
    db_holder = get_holder_by_name(db, holder.name)
    if db_holder:
        raise HTTPException(status_code=400, detail="Holder already exists")

    return create_holder(db, holder)

# Create account
@router_api_admin.put("/account")
def create_account_api(account: schemas.AccountCreate, db: Session = Depends(get_db)):
        
        # Check if account already exists
        db_account = get_account_by_name(db, account.name)
        if db_account:
            raise HTTPException(status_code=400, detail="Account already exists")
    
        return create_account(db, account)

# Create fav_holder
@router_api_admin.put("/fav_holder")
def create_fav_holder_api(fav_holder: schemas.FavHolderCreate, db: Session = Depends(get_db)):
            
        # Check if fav_holder already exists
        db_fav_holder = get_fav_holder_by_name(db, fav_holder.name)
        if db_fav_holder:
            raise HTTPException(status_code=400, detail="Fav_holder already exists")
    
        return create_fav_holder(db, fav_holder)

# Create fav_merchant
@router_api_admin.put("/fav_merchant")
def create_fav_merchant_api(fav_merchant: schemas.FavMerchantCreate, db: Session = Depends(get_db)):
                
        # Check if fav_merchant already exists
        db_fav_merchant = get_fav_merchant_by_name(db, fav_merchant.name)
        if db_fav_merchant:
            raise HTTPException(status_code=400, detail="Fav_merchant already exists")
    
        return create_fav_merchant(db, fav_merchant)

# Get holders list
@router_api_admin.get("/holders")
def get_holders_list_api(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_holders_list(db, skip=skip, limit=limit)

# Get holder by id
@router_api_admin.get("/holder/{holder_id}")
def get_holder_api(holder_id: int, db: Session = Depends(get_db)):
    db_holder = get_holder(db, holder_id=holder_id)
    if db_holder is None:
        raise HTTPException(status_code=404, detail="Holder not found")
    return db_holder

# Get merchants list
@router_api_admin.get("/merchants")
def get_merchants_list_api(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_merchants_list(db, skip=skip, limit=limit)

# Get merchant by id
@router_api_admin.get("/merchant/{merchant_id}")
def get_merchant_api(merchant_id: int, db: Session = Depends(get_db)):
    db_merchant = get_merchent_by_id(db, id=merchant_id)
    if db_merchant is None:
        raise HTTPException(status_code=404, detail="Merchant not found")
    return db_merchant

# Get intermediaries list
@router_api_admin.get("/intermediaries")
def get_intermediaries_list_api(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return get_intermediaries_list(db, skip=skip, limit=limit)

# Get intermediary by id
@router_api_admin.get("/intermediary/{intermediary_id}")
def get_intermediary_api(intermediary_id: int, db: Session = Depends(get_db)):
    return get_intermediary_by_id(db, id=intermediary_id)

# Create wallet
@router_api_admin.put("/wallet")
def create_wallet_api(wallet: schemas.WalletCreate, db: Session = Depends(get_db)):
    return create_wallet(db, wallet)

# Get wallet by id
@router_api_admin.get("/wallet/{wallet_id}")
def get_wallet_api(wallet_id: int, db: Session = Depends(get_db)):
    db_wallet = get_wallet(db, wallet_id=wallet_id)
    if db_wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return db_wallet

# Get wallets list by owner id
@router_api_admin.get("/wallets/{owner_id}")
def get_wallets_list_api(owner_id: int, db: Session = Depends(get_db)):
    return get_wallets_list(db, owner_id=owner_id)

# Delete wallet by id
@router_api_admin.delete("/wallet/{wallet_id}")
def delete_wallet_api(wallet_id: int, db: Session = Depends(get_db)):
    db_wallet = delete_wallet(db, wallet_id=wallet_id)
    if db_wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return db_wallet

# Create transaction
@router_api_admin.put("/transaction")
def create_transaction_w2m_pull_api(tx_data: schemas.TransactionOnlineCreate, db: Session = Depends(get_db)):
    
    # Get wallet by id
    db_wallet = get_wallet(db, wallet_id=tx_data.wallet_id)
    if db_wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")

    # Get counterparty by id
    db_counterparty = get_merchant_by_uid(db, uid=tx_data.cuid)
    if db_counterparty is None:
        db_counterparty = get_wallet_by_uid(db, uid=tx_data.cuid)
        if db_counterparty is None:
            raise HTTPException(status_code=404, detail="Counterparty not found")
        else:
            type = schemas.TransactionType.w2w_pull if tx_data.amount < 0 else schemas.TransactionType.w2w_push
    else:
        type = schemas.TransactionType.w2m_pull

    # Create transaction
    db_transaction = create_transaction(
        db,
        db_wallet,
        tx_data.name,
        tx_data.description,
        type,
        schemas.TransactionStatus.pending,
        tx_data.amount,
        tx_data.cuid,
    )

    # Return transaction
    return schemas.TransactionPublic.from_orm(db_transaction)

# Get transaction list by wallet id
@router_api_admin.get("/transactions/{wallet_id}")
def get_transactions_list_api(wallet_id: int, db: Session = Depends(get_db)):
    # Get wallet by id
    db_wallet = get_wallet(db, wallet_id=wallet_id)
    if db_wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")
    # Get transactions list
    db_tx_list = get_transactions_list(db, db_wallet)
    return [schemas.TransactionPublic.from_orm(db_tx) for db_tx in db_tx_list]

# Get transaction by id
@router_api_admin.get("/transaction/{transaction_id}")
def get_transaction_api(transaction_id: int, db: Session = Depends(get_db)):
    db_transaction = get_transaction_by_id(db, id=transaction_id)
    if db_transaction is None:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return schemas.TransactionPublic.from_orm(db_transaction)

# Delete transaction by id
@router_api_admin.delete("/transaction/{transaction_id}")
def delete_transaction_api(transaction_id: int, db: Session = Depends(get_db)):
    # Get transaction by id
    db_transaction = get_transaction_by_id(db, id=transaction_id)
    if db_transaction is None:
        raise HTTPException(status_code=404, detail="Transaction not found")
    # Delete transaction
    delete_transaction(db, db_transaction)
    return schemas.TransactionPublic.from_orm(db_transaction)
