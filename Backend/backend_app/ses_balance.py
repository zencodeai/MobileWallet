import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

from fastapi import HTTPException

from sqlalchemy.orm import Session

from ses_session import ISession
from app_utils import AppContext, SKDefinitions
import app_schemas as schemas
import app_models as models
from app_crud_transaction import create_transaction, update_transaction_status
from app_crud_wallet import update_wallet_status

class SessionBalance(ISession):
    # Provisioning session

    def _serialize_transaction(self, transaction: models.Transaction, ruid: str) -> bytes:
        # Serialize transaction into balance initialization node
        blob = transaction.amount.to_bytes(8, byteorder='big')
        blob += transaction.timestamp.to_bytes(8, byteorder='big')
        blob += base64.urlsafe_b64decode(transaction.uid)
        blob += base64.urlsafe_b64decode(transaction.cuid)
        blob += base64.urlsafe_b64decode(ruid)
        blob += secrets.token_bytes(32)

        # Compute hash
        hash = hashes.Hash(hashes.SHA256())
        hash.update(blob)
        blob += hash.finalize()

        return blob

    def _encrypt_tx(self, wallet: models.Wallet, tx: bytes) -> bytes:
        # Encrypt transaction blob
        # iv
        iv = bytes(self._ctx.sk_defs.SK_STORE_TX_IV.value)
        # Encrypt
        cipher = Cipher(algorithms.AES(self._wallet.tx_enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return tx[:self.AES_BLK_SIZE] + encryptor.update(tx[self.AES_BLK_SIZE:]) + encryptor.finalize()

    def _process_end(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Load wallet
        db_wallet = db.query(models.Wallet).filter(models.Wallet.id == self._wallet.id).first()
        # Load transaction
        db_transaction = db.query(models.Transaction).filter(models.Transaction.id == self._transaction.id).first()
        # Update wallet status
        db_wallet.status = schemas.WalletStatus.initialized
        # Update transaction status
        db_transaction.status = schemas.TransactionStatus.confirmed
        db_transaction.reason = 'balance initialized'
        # Commit changes
        db.commit()
        # Response
        rsp = schemas.ProcessingData(session_id=self.session_id, data=schemas.WalletStatus.initialized.value)
        # Remove session
        self.remove_session()
        # Return response object
        return rsp

    def _process_1(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Decode peer public key (TLS ServerKeyExchange format)
        self._process_cbk = self._process_err

        # Get client certificate
        cert = x509.load_der_x509_certificate(self._wallet.cl_cert)
        
        # Verify signature
        try:
            # Get signature and peer public key
            peer_pub_key_len = len(data) - self.MAX_SIG_SIZE
            signature = self._remove_padding(data[peer_pub_key_len:])
            peer_pub_key_bytes = data[:peer_pub_key_len]
            # Verify signature
            cert.public_key().verify(signature, peer_pub_key_bytes, ec.ECDSA(hashes.SHA256()))
            # Decode public key
            peer_pub_key_bytes = self._remove_padding(peer_pub_key_bytes)
            peer_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub_key_bytes[4:])
        except Exception as e:
            raise HTTPException(status_code=400, detail='Invalid input data')

        # Establish shared key
        server_pub_key = self._establish_shared_key(peer_pub_key)

        # Generate nonce
        self._nonce = secrets.token_bytes(self.NONCE_SIZE)

        # Get iv
        iv = base64.urlsafe_b64decode(self._wallet.uid)[:self.AES_BLK_SIZE]

        # Generate transaction
        self._transaction = create_transaction(
            db, 
            self._wallet, 
            'Balance initialization',
            f'Balance initialization for wallet {self._wallet.id}',
            schemas.TransactionType.balance,
            schemas.TransactionStatus.pending,
            self._wallet.balance,
            self._wallet.uid,
        )

        # Serialize transaction into balance initialization node
        tx = self._serialize_transaction(self._transaction, self._wallet.token)

        # Encrypt transaction node
        tx_cipher = self._encrypt_tx(self._wallet, tx)
    
        # Compute data hash
        hash_alg = hashes.SHA256()
        server_pub_key_pad = self._add_padding(server_pub_key)
        data_hash = hashes.Hash(hash_alg)
        data_hash.update(server_pub_key_pad)
        data_hash.update(self._nonce)
        data_hash.update(tx_cipher)
        data_sign = data_hash.finalize()

        # Sign data
        signature = self._backend_key.sign(data_sign, ec.ECDSA(utils.Prehashed(hash_alg)))
        
        # Verify signature
        try:
            self._backend_cert.public_key().verify(signature, data_sign, ec.ECDSA(utils.Prehashed(hash_alg)))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        # encrypt data
        plaintext = self._nonce + tx_cipher + self._add_padding(signature)

        # response blob
        rsp_bytes = server_pub_key_pad + self._encrypt_data(iv, plaintext)
        rsp_b64 = base64.urlsafe_b64encode(rsp_bytes)

        # Next step
        self._process_cbk = self._process_end

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=rsp_b64)

    @classmethod
    def create(cls, ctx: AppContext, wallet: models.Wallet) -> ISession:
        # Create session
        return cls(ctx, wallet)

    def __init__(self, ctx: AppContext, wallet: models.Wallet):
        super().__init__(ctx)
        self._get_backend_cert_key(ctx.sk_defs)
        self._wallet = wallet
        self._process_cbk = self._process_1

    def process(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process message
        return self._process_cbk(db, data)
