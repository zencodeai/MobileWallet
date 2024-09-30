import secrets
import uuid
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from sqlalchemy.orm import Session
from fastapi import HTTPException

from app_utils import AppContext, SKDefinitions
import app_schemas as schemas


# Session interface
class ISession(ABC):

    _session_map = {}

    # Constants
    AES_BLK_SIZE = 16
    NONCE_SIZE = 32
    MAX_SIG_SIZE = 80

    @classmethod
    def new_sesion_id(cls)->str:
        # Generate new session id
        session_id = str(uuid.uuid4())
        while session_id in cls._session_map:
            session_id = str(uuid.uuid4())
        return session_id

    def __init__(self, ctx: AppContext):
        self._ctx = ctx
        self._session_id = self.new_sesion_id()
        self._session_map[self._session_id] = self

    def remove_session(self):
        # Remove session from map
        del self._session_map[self.session_id]

    @property
    def ctx(self):
        return self._ctx

    @property
    def session_id(self):
        return self._session_id

    @classmethod
    def get_session(cls, session_id: str):
        return cls._session_map.get(session_id) if session_id in cls._session_map else None

    @abstractmethod
    def process(self, db: Session, data: bytes) -> schemas.ProcessingData:
        raise NotImplementedError

    def _get_backend_cert_key(self, defs: SKDefinitions) -> None:
        # Get backend certificate and key
        # Get certificate
        cert_bytes = bytes(defs.SK_BACKEND_CERT.value)
        cert = x509.load_der_x509_certificate(cert_bytes)

        # Get private key
        key_bytes = bytes(defs.SK_BACKEND_KEY.value)
        key = serialization.load_der_private_key(key_bytes, password=None)

        # Set backend certificate and key
        self._backend_cert = cert
        self._backend_key = key

    @classmethod
    def _remove_padding(cls, data: bytes) -> bytes:
        # Remove padding
        if len(data) <= cls.AES_BLK_SIZE or len(data) % cls.AES_BLK_SIZE != 0:
            raise Exception("Invalid padded data length")

        pad_len = data[-1]
        if pad_len > cls.AES_BLK_SIZE:
            raise Exception("Invalid padding")
        
        return data[:-pad_len]
    
    @classmethod
    def _add_padding(cls, data: bytes) -> bytes:
        # Add padding
        pad_len = cls.AES_BLK_SIZE - len(data) % cls.AES_BLK_SIZE
        return data + bytes([pad_len] * pad_len)
    
    @classmethod
    def _add_random_padding(cls, data: bytes) -> bytes:
        # Add random padding
        pad_len = cls.AES_BLK_SIZE - len(data) % cls.AES_BLK_SIZE
        return data + secrets.token_bytes(pad_len)

    def _encrypt_data(self, iv: bytes, data: bytes) -> bytes:
        # AES CBC encryption using shared key and iv
        cipher = Cipher(algorithms.AES(self._shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def _decrypt_data(self, iv: bytes, data: bytes) -> bytes:
        # AES CBC decryption using shared key and iv
        cipher = Cipher(algorithms.AES(self._shared_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def _wrap_blob(self, blob: bytes) -> bytes:
        # Pad blob
        blob_pad = self._add_padding(blob)
        # AES-GCM Encrypt blob
        cipher = Cipher(algorithms.AES(self._shared_key), modes.GCM(self._shared_wrapping_iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(self._shared_wrapping_data)
        return encryptor.update(blob_pad) + encryptor.finalize() + encryptor.tag

    def _wrap_ecdsa_key(self, key_blob: bytes) -> bytes:
        # Deserialize ecdsa key
        key = serialization.load_der_private_key(key_blob, password=None)
        # Serialize private key "RAW"
        prv_int = key.private_numbers().private_value
        prv_bytes = prv_int.to_bytes(32, 'big')
        # Serialize public key "ANSI X9.62"
        pub_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint)
        # Wrap blob
        return self._wrap_blob(prv_bytes + pub_bytes)

    def _establish_shared_key(self, peer_pub_key: ec.EllipticCurvePublicKey) -> bytes:
        # Generate private key
        server_key = ec.generate_private_key(ec.SECP256R1())
        # Compute shared secret
        shared_secret = server_key.exchange(ec.ECDH(), peer_pub_key)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_secret)
        self._shared_key = digest.finalize()[:self.AES_BLK_SIZE]
        # Public key serialization
        public_key_bytes = server_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint)

        # Return public key
        return bytes([len(public_key_bytes)]) + public_key_bytes

    def _add_blob(self, buffer: bytes, blob: bytes) -> bytes:
        # Add blob size (2 bytes, big endian) and blob to buffer
        buffer += len(blob).to_bytes(2, 'big')
        buffer += blob
        return buffer
    
    def _compute_shared_iv(self, data: bytes) -> None:
        # Compute shared IV
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        digest.update(self._nonce)
        hash = digest.finalize()
        # XOR hash halves
        self._shared_iv = bytes([a ^ b for a, b in zip(hash[:self.AES_BLK_SIZE], hash[self.AES_BLK_SIZE:])])

    def _process_err(self, db: Session, data: bytes) -> None:
        # Process error
        raise HTTPException(status_code=400, detail="Invalid data")
