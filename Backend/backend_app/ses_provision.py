import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from fastapi import HTTPException

from sqlalchemy.orm import Session

from ses_session import ISession
from app_models import Wallet
from app_utils import AppContext, SKDefinitions
import app_schemas as schemas
from app_crud_wallet import update_wallet_status


class SessionProvision(ISession):
    # Provisioning session

    def _get_shared_iv(self, defs: SKDefinitions) -> None:
        # Get shared provisioning IV
        self._shared_iv = bytes(defs.SK_PROV_SHARED_IV.value)
        self._shared_wrapping_iv = bytes(defs.SK_UNWRAP_IV.value)
        self._shared_wrapping_data = bytes(defs.SK_UNWRAP_DATA.value)

    def _process_provisioning_request(self, data: bytes) -> None:
        # Process provisioning request message
        try:
            # Decrypt data
            plaintext = self._decrypt_data(self._shared_iv, data)
            # XOR plaintext with nonce
            token = bytes([a ^ b for a, b in zip(plaintext, self._nonce)]) 
            token_hash_in = plaintext[len(self._nonce):]
            # Verify token hash
            token_hash = hashes.Hash(hashes.SHA256())
            token_hash.update(token)
            token_hash_out = token_hash.finalize()
            if token_hash_in != token_hash_out:
                raise Exception("Invalid token")
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        # Compure shared IV
        self._compute_shared_iv(token)

    def _process_end(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Load wallet
        db_wallet = db.query(Wallet).filter(Wallet.id == self._wallet.id).first()
        # Update wallet status to 'provisioned'
        update_wallet_status(db, db_wallet, schemas.WalletStatus.provisioned)
        # Response
        rsp = schemas.ProcessingData(session_id=self.session_id, data=schemas.WalletStatus.provisioned.value)
        # Remove session
        self.remove_session()
        # Return response object
        return rsp

    def _process_2(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process provisioning request 
        self._process_cbk = self._process_err

        # Process provisioning request
        self._process_provisioning_request(data)

        # Add wallet uid to blob
        blob = base64.urlsafe_b64decode(self._wallet.uid)

        # Add persistence key to blob
        wrapped_key = self._wrap_blob(self._wallet.st_enc_key)
        blob = self._add_blob(blob, wrapped_key)

        # Add client key to blob
        wrapped_key = self._wrap_ecdsa_key(self._wallet.cl_sig_key)
        blob = self._add_blob(blob, wrapped_key)

        # Add client certificate to blob
        blob = self._add_blob(blob, self._wallet.cl_cert)

        # Add transaction encryption key to blob
        wrapped_key = self._wrap_blob(self._wallet.tx_enc_key)
        blob = self._add_blob(blob, wrapped_key)

        # Add transaction signature key to blob
        wrapped_key = self._wrap_ecdsa_key(self._wallet.tx_sig_key_prv)
        blob = self._add_blob(blob, wrapped_key)

        # Pad blob
        blob = self._add_padding(blob)

        # Compute signature
        signature = self._backend_key.sign(blob, ec.ECDSA(hashes.SHA256()))
        blob = blob + self._add_padding(signature)

        # XOR blob with nonce
        blob = bytes([a ^ b for a, b in zip(blob, self._nonce)]) + blob[len(self._nonce):]

        # Encrypt blob
        blob = self._encrypt_data(self._shared_iv, blob)

        # Encode blob
        blob_b64 = base64.urlsafe_b64encode(blob)

        # Next step
        self._process_cbk = self._process_end

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=blob_b64)

    def _process_1(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Decode peer public key (TLS ServerKeyExchange format)
        self._process_cbk = self._process_err

        try:
            peer_pub_key_bytes = self._remove_padding(data)
            peer_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub_key_bytes[4:])
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Establish shared key
        server_pub_key = self._establish_shared_key(peer_pub_key)

        # Generate nonce
        self._nonce = secrets.token_bytes(self.NONCE_SIZE)

        # Compute data hash
        hash_alg = hashes.SHA256()
        server_pub_key_pad = self._add_padding(server_pub_key)
        data_hash = hashes.Hash(hash_alg)
        data_hash.update(server_pub_key_pad)
        data_hash.update(self._nonce)
        data_sign = data_hash.finalize()

        # Sign data
        signature = self._backend_key.sign(data_sign, ec.ECDSA(utils.Prehashed(hash_alg)))
        
        # Verify signature
        try:
            self._backend_cert.public_key().verify(signature, data_sign, ec.ECDSA(utils.Prehashed(hash_alg)))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        # encrypt data
        plaintext = self._nonce + self._add_padding(signature)

        # response blob
        rsp_bytes = server_pub_key_pad + self._encrypt_data(self._shared_iv, plaintext)
        rsp_b64 = base64.urlsafe_b64encode(rsp_bytes)

        # Next step
        self._process_cbk = self._process_2

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=rsp_b64)

    @classmethod
    def create(cls, ctx: AppContext, wallet: Wallet) -> ISession:
        # Create session
        return cls(ctx, wallet)

    def __init__(self, ctx: AppContext, wallet: Wallet):
        super().__init__(ctx)
        self._get_shared_iv(ctx.sk_defs)
        self._get_backend_cert_key(ctx.sk_defs)
        self._wallet = wallet
        self._process_cbk = self._process_1

    def process(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process message
        return self._process_cbk(db, data)
