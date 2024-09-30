from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID


def create_fav_holder(db: Session, fav_holder: schemas.FavHolderCreate):
    # Create fav_holder
    db_fav_holder = models.FavHolder(**fav_holder.dict(), uid=AppUID.generate())
    db.add(db_fav_holder)
    db.commit()
    db.refresh(db_fav_holder)
    return db_fav_holder

def get_fav_holder_by_name(db: Session, name: str):
    # Get fav_holder by name
    return db.query(models.FavHolder).filter(models.FavHolder.name == name).first()
