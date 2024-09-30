from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID


def create_fav_merchant(db: Session, fav_merchant: schemas.FavMerchantCreate):
    # Create fav_merchant
    db_fav_merchant = models.FavMerchant(**fav_merchant.dict(), uid=AppUID.generate())
    db.add(db_fav_merchant)
    db.commit()
    db.refresh(db_fav_merchant)
    return db_fav_merchant

def get_fav_merchant_by_name(db: Session, name: str):
    # Get fav_merchant by name
    return db.query(models.FavMerchant).filter(models.FavMerchant.name == name).first()
