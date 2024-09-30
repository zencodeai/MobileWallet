import secrets
import datetime
import base64
from typing import Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from sqlalchemy.orm import Session

import app_models as models
import app_schemas as schemas

from app_types import AppUID

# Generate attributes
def generate_attributes(cn: str) -> list:
    return [
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'CA'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'ON'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Ottawa'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Fintech Inc.'),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'fintech-inc.ca'),
    ]

# Generate client P-256 certificate signed by the root CA
def generate_client_cert(uid: str, rootprefix: str = './data/ca_fintech_inc_root') -> Tuple[bytes, bytes]:

    # Convert UID to hex string
    uid_bin = base64.urlsafe_b64decode(uid)
    uid_hex = uid_bin.hex().upper()

    # cn
    cn = f'CA-FINTECH-INC-{uid_hex}'
  
    # Read the root CA certificate from a file
    with open(f'{rootprefix}_cert.der', 'rb') as f:
        root_ca_cert = x509.load_der_x509_certificate(f.read(), default_backend())

    # Read the root CA private key from a file
    with open(f'{rootprefix}_key.der', 'rb') as f:
        root_ca_key = serialization.load_der_private_key(f.read(), password=None, backend=default_backend())

    # Generate a private key for the intermediate CA
    intermediate_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Generate a certificate signing request for the intermediate CA
    intermediate_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
        generate_attributes(cn)
    )).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True, ).sign(
        intermediate_key, hashes.SHA256(), default_backend())

    # Generate a certificate signed by the root CA for the intermediate CA
    intermediate_cert = x509.CertificateBuilder().subject_name(x509.Name(
        generate_attributes(cn)
    )).issuer_name(root_ca_cert.subject).not_valid_before(datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)).serial_number(
        x509.random_serial_number()).public_key(intermediate_csr.public_key()).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True, ).sign(root_ca_key, hashes.SHA256(),
                                                                                 default_backend())

    # Get DER encoded certificate
    cert_der = intermediate_cert.public_bytes(serialization.Encoding.DER)

    # Get DER encoded private key
    pkey_der = intermediate_key.private_bytes(
        serialization.Encoding.DER, 
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())

    # Return DER encoded certificate and private key
    return cert_der, pkey_der

# Generate an AES-128 key
def generate_aes128_key() -> bytes:
    return secrets.token_bytes(16)

# Generate P-256 key pair
def generate_p256_key_pair() -> Tuple[bytes, bytes]:
    # Generate a private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # Get DER encoded private key
    private_key_der = private_key.private_bytes(
        serialization.Encoding.DER, 
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    # Get DER encoded public key
    public_key_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, 
        serialization.PublicFormat.SubjectPublicKeyInfo)
    # Return DER encoded private key and public key
    return public_key_der, private_key_der

def create_wallet(db: Session, wallet: schemas.WalletCreate):
    # Create wallet
    uid = AppUID.generate()
    token = AppUID.generate()
    cl_cert, cl_sig_key = generate_client_cert(uid)
    tx_sig_key_pub, tx_sig_key_prv = generate_p256_key_pair()
    tx_enc_key = generate_aes128_key()
    st_enc_key = generate_aes128_key()

    db_wallet = models.Wallet(**wallet.dict(), 
                              uid=uid,
                              token=token,
                              cl_cert=cl_cert,
                              cl_sig_key=cl_sig_key,
                              tx_sig_key_pub=tx_sig_key_pub,
                              tx_sig_key_prv=tx_sig_key_prv,
                              tx_enc_key=tx_enc_key,
                              st_enc_key=st_enc_key)
    db.add(db_wallet)
    db.commit()
    db.refresh(db_wallet)
    return schemas.WalletPublic.from_orm(db_wallet)

def get_wallet(db: Session, wallet_id: int):
    # Get wallet by id
    db_wallet = db.query(models.Wallet).filter(models.Wallet.id == wallet_id).first()
    if db_wallet is None:
        return None
    return schemas.WalletPublic.from_orm(db_wallet)

def get_wallet_by_uid(db: Session, uid: str):
    # Get wallet by uid
    db_wallet = db.query(models.Wallet).filter(models.Wallet.uid == uid).first()
    if db_wallet is None:
        return None
    return db_wallet

def get_wallet_by_token(db: Session, token: str):
    # Get wallet by token
    db_wallet = db.query(models.Wallet).filter(models.Wallet.token == token).first()
    if db_wallet is None:
        return None
    return db_wallet

def get_wallets_list(db: Session, owner_id: int):
    # Get wallet list by owner id
    db_wallets = db.query(models.Wallet).filter(models.Wallet.owner_id == owner_id).all()
    wallets_list = [schemas.WalletPublic.from_orm(db_wallet) for db_wallet in db_wallets]
    return wallets_list

def delete_wallet(db: Session, wallet_id: int):
    # Delete wallet by id
    db_wallet = db.query(models.Wallet).filter(models.Wallet.id == wallet_id).first()
    if db_wallet is None:
        return None
    db.delete(db_wallet)
    db.commit()
    return schemas.WalletPublic.from_orm(db_wallet)

def update_wallet_status(db: Session, db_wallet: models.Wallet, status: schemas.WalletStatus) -> None:
    # Update wallet status
    db_wallet.status = status
    db.commit()
    db.refresh(db_wallet)
