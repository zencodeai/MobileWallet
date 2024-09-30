import base64
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session


from app_database import get_db
import app_schemas as schemas
from app_crud_wallet import get_wallet_by_token, update_wallet_status
from ses_session import ISession
from ses_provision import SessionProvision
from ses_balance import SessionBalance
from ses_online import SessionOnline
from app_utils import AppContext

# Application context
app_context = AppContext()

# API router for client
router_api_client = APIRouter()

# Decode base64 encoded data
def decode_base64(data: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid data")

# Initiate provisioning
@router_api_client.post("/provision")
def provision(data: schemas.ProvisioningData, db: Session = Depends(get_db)):
    # Get wallet by token
    db_wallet = get_wallet_by_token(db, data.token)
    if not db_wallet:
        raise HTTPException(status_code=400, detail="Wallet not found")
    # Wallet status must be 'new'
    if db_wallet.status != schemas.WalletStatus.new:
        raise HTTPException(status_code=400, detail="Invalid wallet status")
    # update wallet status to 'error'
    update_wallet_status(db, db_wallet, schemas.WalletStatus.error)
    # Create provisioning session
    session = SessionProvision.create(app_context, db_wallet)
    # Process data
    return session.process(db, decode_base64(data.data))

# Balance initialization
@router_api_client.post("/init")
def init(data: schemas.BalanceInitData, db: Session = Depends(get_db)):
    # Get wallet by token
    db_wallet = get_wallet_by_token(db, data.token)
    if not db_wallet:
        raise HTTPException(status_code=400, detail="Wallet not found")
    # Wallet status must be 'provisioned'
    if db_wallet.status != schemas.WalletStatus.provisioned:
        raise HTTPException(status_code=400, detail="Invalid wallet status")
    # update wallet status to 'error'
    update_wallet_status(db, db_wallet, schemas.WalletStatus.error)
    # Create balance initialization session
    session = SessionBalance.create(app_context, db_wallet)
    # Process data
    return session.process(db, decode_base64(data.data))

# Online session
@router_api_client.post("/online")
def online(data: schemas.OnlineTransactionData, db: Session = Depends(get_db)):
    # Get wallet by token
    db_wallet = get_wallet_by_token(db, data.token)
    if not db_wallet:
        raise HTTPException(status_code=400, detail="Wallet not found")
    # Wallet status must be 'initialized'
    if db_wallet.status != schemas.WalletStatus.initialized:
        raise HTTPException(status_code=400, detail="Invalid wallet status")
    # Create balance initialization session
    session = SessionOnline.create(app_context, db_wallet)
    # Process data
    return session.process(db, decode_base64(data.data))

# Process data
@router_api_client.post("/process")
def process(data: schemas.ProcessingData, db: Session = Depends(get_db)):
    # Get session
    session = ISession.get_session(data.session_id)
    if not session:
        raise HTTPException(status_code=400, detail="Session not found")
    # Process data
    return session.process(db, decode_base64(data.data))

# Process session data request
@router_api_client.post("/session_data")
def session_data(data: schemas.RequestSessionData, db: Session = Depends(get_db)):
    # Get session
    session = ISession.get_session(data.session_id)
    if not session:
        raise HTTPException(status_code=400, detail="Session not found")
    # Process data
    return session.process_session_data(db, data.data_type)
