from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID

def create_merchant(db: Session, merchant: schemas.MerchantCreate):
    # Create merchant
    db_merchant = models.Merchant(**merchant.dict(), uid=AppUID.generate())
    db.add(db_merchant)
    db.commit()
    db.refresh(db_merchant)
    return db_merchant

def get_merchant_by_name(db: Session, name: str):
    # Get merchant by name
    return db.query(models.Merchant).filter(models.Merchant.name == name).first()

def get_merchant_by_uid(db: Session, uid: str):
    # Get merchant by uid
    return db.query(models.Merchant).filter(models.Merchant.uid == uid).first()

def get_merchants_list(db: Session, skip: int = 0, limit: int = 100):
    # Get merchants list
    return db.query(models.Merchant).offset(skip).limit(limit).all()

def get_merchent_by_id(db: Session, id: int):
    # Get merchant by id
    return db.query(models.Merchant).filter(models.Merchant.id == id).first()
