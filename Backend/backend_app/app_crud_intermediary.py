from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID

def create_intermediary(db: Session, intermediary: schemas.IntermediaryCreate):
    # Create intermediary
    db_intermediary = models.Intermediary(**intermediary.dict(), uid=AppUID.generate())
    db.add(db_intermediary)
    db.commit()
    db.refresh(db_intermediary)
    return db_intermediary

def get_intermediary_by_name(db: Session, intermediary_name: str):
    # Get intermediary by name
    return db.query(models.Intermediary).filter(models.Intermediary.name == intermediary_name).first()

def get_intermediary_by_uid(db: Session, uid: str):
    # Get intermediary by uid
    return db.query(models.Intermediary).filter(models.Intermediary.uid == uid).first()

def get_intermediaries_list(db: Session, skip: int = 0, limit: int = 100):
    # Get intermediaries list
    return db.query(models.Intermediary).offset(skip).limit(limit).all()

def get_intermediary_by_id(db: Session, id: int):
    # Get intermediary by id
    return db.query(models.Intermediary).filter(models.Intermediary.id == id).first()
