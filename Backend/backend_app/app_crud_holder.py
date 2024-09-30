from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID

def create_holder(db: Session, holder: schemas.HolderCreate):
    # Create holder
    db_holder = models.Holder(**holder.dict(), uid=AppUID.generate())
    db.add(db_holder)
    db.commit()
    db.refresh(db_holder)
    return db_holder

def get_holder_by_name(db: Session, name: str):
    # Get holder by name
    return db.query(models.Holder).filter(models.Holder.name == name).first()

def get_holders_list(db: Session, skip: int = 0, limit: int = 100):
    # Get holders list
    return db.query(models.Holder).offset(skip).limit(limit).all()

def get_holder(db: Session, holder_id: int):
    # Get holder by id
    return db.query(models.Holder).filter(models.Holder.id == holder_id).first()

def get_holder_by_uid(db: Session, uid: str):
    # Get holder by uid
    return db.query(models.Holder).filter(models.Holder.uid == uid).first()
