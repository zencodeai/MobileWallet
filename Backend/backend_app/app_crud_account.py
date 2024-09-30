from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID


def create_account(db: Session, account: schemas.AccountCreate):
    # Create account
    db_account = models.Account(**account.dict(), uid=AppUID.generate())
    db.add(db_account)
    db.commit()
    db.refresh(db_account)
    return db_account

def get_account_by_name(db: Session, account_name: str):
    # Get account by name
    return db.query(models.Account).filter(models.Account.name == account_name).first()
