from fastapi import FastAPI

from api_admin import router_api_admin
from api_client import router_api_client

import app_models as models
from app_database import engine

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Create FastAPI instance
app = FastAPI(
    title="MobileWalletPOT", 
    version="0.1.0", 
    description="Mobile Wallet POT backend API")
app.include_router(router_api_client, prefix="/api/v1")
app.include_router(router_api_admin, prefix="/api/v1/admin")
