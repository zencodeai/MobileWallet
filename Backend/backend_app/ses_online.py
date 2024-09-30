import secrets
import base64
from typing import List, Tuple, Any
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fastapi import HTTPException

from sqlalchemy.orm import Session

from ses_session import ISession
from ses_data import SessionDataRequest
from app_utils import AppContext, SKDefinitions
import app_schemas as schemas
import app_models as models
import app_types as types
from app_crud_transaction import create_transaction, create_transaction_with_uid, get_transaction_by_uid, update_transaction_status
from app_crud_wallet import update_wallet_status, get_wallet_by_uid
from app_crud_holder import get_holder_by_uid
from app_crud_merchant import get_merchant_by_uid
from app_crud_intermediary import get_intermediary_by_uid


class SessionOnline(ISession):
    # Provisioning session

    # Constants
    TX_NODE_SIZE = 176
    IUID_SIZE = 32
    TUID_REQUEST_DATA_SIZE = ISession.AES_BLK_SIZE + IUID_SIZE + ISession.MAX_SIG_SIZE
    TUID_RESPONSE_DATA_SIZE = ISession.AES_BLK_SIZE + (3 * IUID_SIZE) + ISession.MAX_SIG_SIZE
    TX_MSG_MIN_SIZE = IUID_SIZE + TX_NODE_SIZE + ISession.MAX_SIG_SIZE


    class TransactionNode:
    # Transaction node class

        def __init__(self, blob: bytes):
            # Deserialize transaction node
            self.amount = int.from_bytes(blob[:8], byteorder='big', signed=True)
            self.timestamp = int.from_bytes(blob[8:16], byteorder='big', signed=True)
            self.tuid = base64.urlsafe_b64encode(blob[16:48]).decode('utf-8')
            self.cuid = base64.urlsafe_b64encode(blob[48:80]).decode('utf-8')
            self.ruid = base64.urlsafe_b64encode(blob[80:112]).decode('utf-8')
            self.puid = blob[112:144]
            self.hash = blob[144:176]
            
            # Check hash
            hash = hashes.Hash(hashes.SHA256())
            hash.update(blob[:144])
            if hash.finalize() != self.hash:
                raise Exception('Invalid transaction node hash')
            
            # Compute blob hash
            hash = hashes.Hash(hashes.SHA256())
            hash.update(blob)
            self.blob_hash = hash.finalize()

    
    def _serialize_transaction_plain(self, transaction: models.Transaction, ruid: str) -> bytes:
        # Serialize transaction into balance initialization node
        blob = transaction.amount.to_bytes(8, byteorder='big', signed=True)
        blob += transaction.timestamp.to_bytes(8, byteorder='big', signed=True)
        blob += base64.urlsafe_b64decode(transaction.uid)
        blob += base64.urlsafe_b64decode(transaction.cuid)
        blob += base64.urlsafe_b64decode(ruid)
        blob += secrets.token_bytes(32)

        # Compute hash
        hash = hashes.Hash(hashes.SHA256())
        hash.update(blob)
        blob += hash.finalize()

        return blob

    def _serialize_transaction(self, transaction: models.Transaction, ruid: str) -> bytes:
        # Serialize transaction into balance initialization node
        blob = self._serialize_transaction_plain(transaction, ruid)

        # Encrypt transaction blob
        iv = bytes(self._ctx.sk_defs.SK_STORE_TX_IV.value)
        cipher = Cipher(algorithms.AES(self._wallet.tx_enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        blob_cypher = blob[:self.AES_BLK_SIZE] + encryptor.update(blob[self.AES_BLK_SIZE:]) + encryptor.finalize()

        return blob_cypher

    def _deserialize_transaction(self, tx_crypt: bytes) -> TransactionNode:
        # Decrypt transaction blob
        # iv
        iv = bytes(self._ctx.sk_defs.SK_STORE_TX_IV.value)
        # Decrypt
        cipher = Cipher(algorithms.AES(self._wallet.tx_enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        tx = tx_crypt[:self.AES_BLK_SIZE] + decryptor.update(tx_crypt[self.AES_BLK_SIZE:]) + decryptor.finalize()
        return self.TransactionNode(tx)

    def _deserialize_transaction_list(self, db: Session, data: bytes) -> List[TransactionNode]:
        # Process transaction list

        # Get signature and data
        data_len = len(data) - self.MAX_SIG_SIZE
        signature = self._remove_padding(data[data_len:])
        data = data[:data_len]
        # Verify signature
        self._tx_sig_key.public_key().verify(signature, data, ec.ECDSA(hashes.SHA256()))
    
        # Check iuid
        iuid = data[:self.IUID_SIZE]
        uid_bytes = base64.urlsafe_b64decode(self._wallet.uid)
        if iuid != uid_bytes:
            raise Exception('Invalid iuid')

        # check length
        data = data[self.IUID_SIZE:]
        if len(data) % self.TX_NODE_SIZE != 0 or len(data) == 0:
            raise Exception('Invalid transaction list length')
        
        # Split data into transaction nodes
        tx_list = []
        for i in range(0, len(data), self.TX_NODE_SIZE):
            tx_list.append(self._deserialize_transaction(data[i:i+self.TX_NODE_SIZE]))

        return tx_list

    def _get_record_by_uid(self, db: Session, uid: str)-> Tuple[types.CounterpartyType, Any]:
        # Get record by uid
        # Get holder
        db_wallet = get_wallet_by_uid(db, uid)
        if db_wallet:
            return types.CounterpartyType.holder, db_wallet
        # Get merchant
        db_merchant = get_merchant_by_uid(db, uid)
        if db_merchant:
            return types.CounterpartyType.merchant, db_merchant
        # Get intermediary
        db_intermediary = get_intermediary_by_uid(db, uid)
        if db_intermediary:
            return types.CounterpartyType.intermediary, db_intermediary
        # Get transaction
        db_transaction = get_transaction_by_uid(db, uid)
        if db_transaction:
            return types.CounterpartyType.transaction, db_transaction
        # Not found
        return type.CounterpartyType.none, None

    def _get_tx_by_uid(self, db: Session, uid: str) -> models.Transaction | None:
        # Get transaction by UID
        db_transaction = get_transaction_by_uid(db, uid)
        # Return transaction
        return db_transaction

    def _create_pending_offline_tx(self, db: Session, tx_node: TransactionNode) -> models.Transaction:
        # Create pending offline transaction
        db_transaction = create_transaction_with_uid(
            db,
            tx_node.tuid,
            self._wallet,
            'Offline transaction',
            f'Waiting for counterparty validation',
            schemas.TransactionType.offine,
            schemas.TransactionStatus.pending,
            tx_node.amount,
            tx_node.cuid,
            payload=tx_node.ruid,
        )
        # Return transaction
        return db_transaction        

    def _create_pending_online_tx(self, db: Session, amount: int, cuid: str) -> models.Transaction:
        # Get counterparty type and record by UID
        counter_party_type, db_record = self._get_record_by_uid(db, cuid)
        match counter_party_type:
            case types.CounterpartyType.wallet:
                db_wallet : models.Wallet = db_record
                type = schemas.TransactionType.w2w_pull if amount < 0 else schemas.TransactionType.w2w_push
                name = 'Wallet to wallet transaction'
                description = f'Wallet to wallet transaction for wallet {self._wallet.uid} and wallet {cuid}, {db_wallet.name}'
            case types.CounterpartyType.merchant:
                db_merchant : models.Merchant = db_record
                type = schemas.TransactionType.w2m_pull if amount < 0 else schemas.TransactionType.w2m_push
                name = 'Wallet to merchant transaction'
                description = f'Wallet to merchant transaction for wallet {self._wallet.uid} and merchant {cuid}, {db_merchant.name}'
            case types.CounterpartyType.intermediary:
                db_intermediary : models.Intermediary = db_record
                type = schemas.TransactionType.withdrawal if amount < 0 else schemas.TransactionType.deposit
                name = 'Wallet to intermediary transaction'
                description = f'Wallet to intermediary transaction for wallet {self._wallet.uid} and intermediary {cuid}, {db_intermediary.name}'
            case types.CounterpartyType.transaction:
                db_transaction : models.Transaction = db_record
                type = schemas.TransactionType.w2w_validation if db_transaction.type == schemas.TransactionType.w2w_pull or db_transaction.type == schemas.TransactionType.w2w_push else schemas.TransactionType.w2m_validation 
                name = 'Transaction validation'
                description = f'Transaction validation for wallet {self._wallet.uid} and transaction {cuid}, {db_transaction.name}'
            case _:
                HTTPException(status_code=400, detail=f'Invalid counterparty type {counter_party_type}')

        # Create pending transaction
        db_transaction = create_transaction(
            db,
            self._wallet,
            name,
            description,
            type,
            schemas.TransactionStatus.pending,
            amount,
            cuid,
        )
        # Return transaction
        return db_transaction

    def _create_unknown_tuid_tx(self, db: Session, tx_node: TransactionNode):
        # Create unknown tuid transaction
        # Create transaction
        db_transaction = create_transaction_with_uid(
            db,
            tx_node.tuid,
            self._wallet,
            'Unknown transaction',
            f'Unknown transaction for wallet {self._wallet.id}',
            schemas.TransactionType.offine,
            schemas.TransactionStatus.failed,
            tx_node.amount,
            tx_node.cuid,
            payload=tx_node.ruid,
        )

    def _create_error_tx(self, db: Session, description: str):
        # Create invalid transaction
        # Create transaction
        db_transaction = create_transaction(
            db,
            self._wallet,
            'Error',
            description,
            schemas.TransactionType.offine,
            schemas.TransactionStatus.failed,
            1,
            'error',
            payload='error',
        )


    def _process_offline_tx(self, db: Session, tx_node: TransactionNode, db_transaction: models.Transaction, new_offline_tx: bool):
        # Each side updates its balance
        if not new_offline_tx:
            if tx_node.cuid == self._wallet.uid:
                self._wallet.balance += tx_node.amount
                db_transaction.status = schemas.TransactionStatus.confirmed
                db_transaction.reason = 'offline transaction confirmed'
            else:
                db_transaction.status = schemas.TransactionStatus.failed
                db_transaction.reason = f'Invalid counterparty UID {tx_node.cuid}'
        else:
            db_transaction.status = schemas.TransactionStatus.pending
            db_transaction.reason = 'Waiting for counterparty validation'

    def _process_tx_balance(self, db: Session, tx_node: TransactionNode):
        # Check balance initialization node against transaction
        # Get transaction by UID
        db_transaction = self._get_tx_by_uid(db, tx_node.tuid)
        if not db_transaction:
            # Create unknown tuid transaction
            self._create_unknown_tuid_tx(db, tx_node)
            HTTPException(status_code=400, detail='Unknown transaction UID {tx_node.tuid}')
        # Check balance consistency
        if tx_node.amount != db_transaction.amount:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid balance initialization node balance {tx_node.amount}'
        # Check timestamp
        if tx_node.timestamp != db_transaction.timestamp:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid balance initialization node timestamp {tx_node.timestamp}'
        # Check tuid
        if tx_node.tuid != db_transaction.uid:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid balance initialization node tuid {tx_node.tuid}'
        # Check cuid
        if tx_node.cuid != db_transaction.cuid:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid balance initialization node cuid {tx_node.cuid}'
        # If transaction is not valid, exception
        if db_transaction.status == schemas.TransactionStatus.failed:
            db.commit()
            HTTPException(status_code=400, detail=db_transaction.reason)
        else:
            # Update transaction status
            db_transaction.status = schemas.TransactionStatus.confirmed
            db_transaction.reason = 'balance initialization confirmed'

    def _process_tx_w2w_validation(self, db: Session, tx_node: TransactionNode, db_validation_tx: models.Transaction):
        # Process w2w transaction
        # Get counterparty type and record by UID
        counter_party_type, db_record = self._get_record_by_uid(db, tx_node.cuid)
        # Check counterparty type
        if counter_party_type != types.CounterpartyType.transaction:
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid counterparty type {counter_party_type}'
            return
        db_transaction : models.Transaction = db_record
        # Check transaction type
        if db_transaction.type != schemas.TransactionType.w2w_pull and db_transaction.type != schemas.TransactionType.w2w_push:
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid transaction type {db_transaction.type}'
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = db_validation_tx.reason
            return
        # Check transaction status
        if db_transaction.status != schemas.TransactionStatus.pending:
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid transaction status {db_transaction.status}'
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = db_validation_tx.reason
            return
        # Transaction accepted?
        if tx_node.amount == db_transaction.amount:
            # Update transaction status to confirmed
            db_validation_tx.status = schemas.TransactionStatus.confirmed
            db_validation_tx.reason = 'transaction confirmed'
            db_transaction.status = schemas.TransactionStatus.confirmed
            db_transaction.reason = db_validation_tx.reason
            # Get counterparty wallet
            db_counterparty_wallet = get_wallet_by_uid(db, db_transaction.cuid)
            if not db_counterparty_wallet:
                # Create unknown cuid
                self._create_error_tx(db, f'Unknown wallet UID {db_transaction.cuid}')
                HTTPException(status_code=400, detail=f'Unknown wallet UID {db_transaction.cuid}')
            # Update balances
            db_counterparty_wallet.balance -= tx_node.amount
            db_validation_tx.wallet.balance += tx_node.amount
        elif tx_node.amount == 0:
            # Update transaction status to rejected
            db_transaction.status = schemas.TransactionStatus.rejected
            db_transaction.reason = 'transaction rejected'
            db_validation_tx.status = schemas.TransactionStatus.confirmed
            db_validation_tx.reason = 'transaction rejection comfirmed'
        else:
            # Inconsistent transaction amount
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid transaction amount {tx_node.amount}'
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = db_validation_tx.reason

    def _process_tx_w2m_validation(self, db: Session, tx_node: TransactionNode, db_validation_tx: models.Transaction):
        # Process w2w transaction
        # Get counterparty type and record by UID
        counter_party_type, db_record = self._get_record_by_uid(db, tx_node.cuid)
        # Check counterparty type
        if counter_party_type != types.CounterpartyType.transaction:
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid counterparty type {counter_party_type}'
            return
        db_transaction : models.Transaction = db_record
        # Check transaction type
        if db_transaction.type != schemas.TransactionType.w2m_pull and db_transaction.type != schemas.TransactionType.w2m_push:
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid transaction type {db_transaction.type}'
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = db_validation_tx.reason
            return
        # Check transaction status
        if db_transaction.status != schemas.TransactionStatus.pending:
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid transaction status {db_transaction.status}'
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = db_validation_tx.reason
            return
        # Transaction accepted?
        if tx_node.amount == db_transaction.amount:
            # Update transaction status to confirmed
            db_validation_tx.status = schemas.TransactionStatus.confirmed
            db_validation_tx.reason = 'transaction confirmed'
            db_transaction.status = schemas.TransactionStatus.confirmed
            db_transaction.reason = db_validation_tx.reason
            # Update balances
            db_transaction.wallet.balance -= tx_node.amount
            # TODO: Update merchant balance
        elif tx_node.amount == 0:
            # Update transaction status to rejected
            db_transaction.status = schemas.TransactionStatus.rejected
            db_transaction.reason = 'transaction rejected'
            db_validation_tx.status = schemas.TransactionStatus.confirmed
            db_validation_tx.reason = 'transaction rejection comfirmed'
        else:
            # Inconsistent transaction amount
            db_validation_tx.status = schemas.TransactionStatus.failed
            db_validation_tx.reason = f'Invalid transaction amount {tx_node.amount}'
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = db_validation_tx.reason

    def _process_tx_w2i_validation(self, db: Session, tx_node: TransactionNode, db_transaction: models.Transaction):
        # Process w2i transaction
        # Get counterparty type and record by UID
        counter_party_type, db_record = self._get_record_by_uid(db, tx_node.cuid)
        # Check counterparty type
        if counter_party_type != types.CounterpartyType.intermediary:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid counterparty type {counter_party_type}'
            return
        db_intermediary : models.Intermediary = db_record
        # Check transaction type
        if db_transaction.type != schemas.TransactionType.withdrawal and db_transaction.type != schemas.TransactionType.deposit:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid transaction type for a wallet to intermediary transaction: {db_transaction.type}'
            return
        # Check transaction status
        if db_transaction.status != schemas.TransactionStatus.pending:
            db_transaction.status = schemas.TransactionStatus.failed
            db_transaction.reason = f'Invalid transaction status {db_transaction.status}'
            return
        # Transaction accepted?
        db_transaction.status = schemas.TransactionStatus.confirmed
        db_transaction.reason = 'transaction confirmed'
        db_transaction.wallet.balance -= tx_node.amount
        # TODO: Update intermediary balance

    def _process_offline_tx_node(self, db: Session, tx_node: TransactionNode):
        # Process transaction node
        # Get transaction by UID
        db_transaction = self._get_tx_by_uid(db, tx_node.tuid)
        if not db_transaction:
            db_transaction = self._create_pending_offline_tx(db, tx_node)
            self._wallet.balance += tx_node.amount
        else:
            # Check transaction type
            if db_transaction.type != schemas.TransactionType.offine:
                db_transaction.status = schemas.TransactionStatus.failed
                db_transaction.reason = f'Invalid transaction type {db_transaction.type}'
                return
            # Check transaction status
            if db_transaction.status != schemas.TransactionStatus.pending:
                db_transaction.status = schemas.TransactionStatus.failed
                db_transaction.reason = f'Invalid transaction status {db_transaction.status}'
                return
            # Check cuid consistency
            if tx_node.cuid != db_transaction.cuid and tx_node.cuid != self._wallet.uid:
                db_transaction.status = schemas.TransactionStatus.failed
                db_transaction.reason = f'Invalid cuid {tx_node.cuid}'
                return
            # Transaction confirmed
            db_transaction.status = schemas.TransactionStatus.confirmed
            db_transaction.reason = 'offline transaction confirmed'
            self._wallet.balance += tx_node.amount

    def _process_offline_tx_list(self, db: Session, tx_list: List[TransactionNode]):
        # Process offline transaction list
        # Process balance initialization node
        self._process_tx_balance(db, tx_list[0])
        # Process transaction list
        for tx_node in tx_list[1:]:
            self._process_offline_tx_node(db, tx_node)
        db.commit()

    def _process_online_tx_node(self, db: Session, tx_node: TransactionNode):
        # Process transaction node
        # Get transaction by UID
        db_transaction = self._get_tx_by_uid(db, tx_node.tuid)
        if not db_transaction:
            # Create unknown tuid transaction
            self._create_unknown_tuid_tx(db, tx_node)
            HTTPException(status_code=400, detail='Unknown transaction UID {tx_node.tuid}')
        # Process transaction depending on type
        match db_transaction.type:
            case schemas.TransactionType.w2w_validation:
                # Process w2w validation transaction
                self._process_tx_w2w_validation(db, tx_node, db_transaction)
            case schemas.TransactionType.w2m_validation:
                # Process w2m validation transaction
                self._process_tx_w2m_validation(db, tx_node, db_transaction)
            case schemas.TransactionType.deposit | schemas.TransactionType.withdrawal:
                # Process w2i validation transaction
                self._process_tx_w2i_validation(db, tx_node, db_transaction)
            case schemas.TransactionType.w2w_pull | schemas.TransactionType.w2w_push | schemas.TransactionType.w2m_pull | schemas.TransactionType.w2m_push:
                pass
            case _:
                HTTPException(status_code=400, detail=f'Invalid transaction type {db_transaction.type}')

    def _process_online_tx_list(self, db: Session, tx_list: List[TransactionNode]):
        # Process online transaction list
        # Process balance initialization node
        self._process_tx_balance(db, tx_list[0])
        # Process transaction list
        for tx_node in tx_list[1:]:
            self._process_online_tx_node(db, tx_node)
        db.commit()

    def _get_balance_update_msg(self, db: Session) -> bytes:
        # Get balance update message
        # Get wallet
        db_wallet = db.query(models.Wallet).filter(models.Wallet.id == self._wallet.id).first()
        # Create transaction
        db_transaction = create_transaction(
            db,
            db_wallet,
            'Balance update',
            f'Balance update for wallet {db_wallet.uid}',
            schemas.TransactionType.balance,
            schemas.TransactionStatus.pending,
            db_wallet.balance,
            db_wallet.uid,
        )
        # Serialize transaction
        tx_node = self._serialize_transaction(db_transaction, db_wallet.token)
        # Compute signature
        signature = self._backend_key.sign(tx_node, ec.ECDSA(hashes.SHA256()))
        # Plain text
        plaintext = tx_node + self._add_padding(signature)
        # xor data with nonce
        data = bytes([a ^ b for a, b in zip(plaintext, self._nonce)]) + plaintext[len(self._nonce):]
        # Encrypt data
        data = self._encrypt_data(self._shared_iv, data)
        # Return data
        return data

    def _process_end(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Response
        rsp = schemas.ProcessingData(session_id=self.session_id, data=schemas.WalletStatus.initialized.value)
        # Remove session
        self.remove_session()
        # Return response object
        return rsp

    def _process_4(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process online transaction list
        self._process_cbk = self._process_1

        # Check min length
        if len(data) < self.TX_MSG_MIN_SIZE:
            raise HTTPException(status_code=400, detail='Invalid data length')
        
        # Decrypt data
        data = self._decrypt_data(self._shared_iv, data)

        # xor data with nonce
        data = bytes([a ^ b for a, b in zip(data, self._nonce)]) + data[len(self._nonce):]
        
        # Verify signature
        try:
            tx_list = self._deserialize_transaction_list(db, data)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        # Process offline transaction list
        self._process_online_tx_list(db, tx_list)

        # Get balance update message
        data = self._get_balance_update_msg(db)
        data_b64 = base64.urlsafe_b64encode(data)

        # Next step
        self._process_cbk = self._process_3

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=data_b64)
        
    def _process_3(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process TUID request
        self._process_cbk = self._process_1

        # Check message length
        if len(data) != self.TUID_REQUEST_DATA_SIZE:
            raise HTTPException(status_code=400, detail='Invalid data length')

        # Decrypt data
        data = self._decrypt_data(self._shared_iv, data)

        # xor data with nonce
        data = bytes([a ^ b for a, b in zip(data, self._nonce)]) + data[len(self._nonce):]
        
        # Get client certificate
        cert = x509.load_der_x509_certificate(self._wallet.cl_cert)

        # Verify signature
        try:
            # Get signature and data
            data_len = len(data) - self.MAX_SIG_SIZE
            signature = self._remove_padding(data[data_len:])
            data = data[:data_len]
            # Verify signature
            cert.public_key().verify(signature, data, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        # Get amount
        amount_bytes = data[:8]
        amount = int.from_bytes(amount_bytes, byteorder='big', signed=True)

        # Get counterparty UID
        cuid  = data[self.AES_BLK_SIZE:self.AES_BLK_SIZE+self.IUID_SIZE]
        cuid_b64 = base64.urlsafe_b64encode(cuid).decode('utf-8')
        
        # Create pending transaction
        db_transaction = self._create_pending_online_tx(db, amount, cuid_b64)

        # Serialize transaction
        tx_node = self._serialize_transaction_plain(db_transaction, self._wallet.token)

        # Extract reponse data from transaction node: amount, timestamp, tuid, cuid, ruid
        data_size = self.TUID_RESPONSE_DATA_SIZE - self.MAX_SIG_SIZE
        data = tx_node[:data_size]

        # Sign data
        signature = self._backend_key.sign(data, ec.ECDSA(hashes.SHA256()))
        
        # encrypt data
        plaintext = data + self._add_padding(signature)

        # xor data with nonce
        plaintext = bytes([a ^ b for a, b in zip(plaintext, self._nonce)]) + plaintext[len(self._nonce):]

        # Encrypt data
        rsp_bytes = self._encrypt_data(self._shared_iv, plaintext)
        rsp_b64 = base64.urlsafe_b64encode(rsp_bytes)

        # Next step
        self._process_cbk = self._process_4

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=rsp_b64)
        
    def _process_2(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process offline transaction list
        self._process_cbk = self._process_1

        # Check min length
        if len(data) < self.TX_MSG_MIN_SIZE:
            raise HTTPException(status_code=400, detail='Invalid data length')

        # Compute shared iv
        uid_bytes = base64.urlsafe_b64decode(self._wallet.uid)
        self._compute_shared_iv(uid_bytes)

        # Decrypt data
        data = self._decrypt_data(self._shared_iv, data)

        # xor data with nonce
        data = bytes([a ^ b for a, b in zip(data, self._nonce)]) + data[len(self._nonce):]
        
        # Get transaction signature key
        self._tx_sig_key = serialization.load_der_private_key(self._wallet.tx_sig_key_prv, password=None)

        # Deserialize transaction list
        try:
            tx_list = self._deserialize_transaction_list(db, data)
        except Exception as e:
            raise HTTPException(status_code=400, detail='Invalid input data')
        
        # Process offline transaction list
        self._process_offline_tx_list(db, tx_list)

        # Get balance update message
        data = self._get_balance_update_msg(db)
        data_b64 = base64.urlsafe_b64encode(data)

        # Next step
        self._process_cbk = self._process_3

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=data_b64)

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
        rsp_bytes = server_pub_key_pad + self._encrypt_data(iv, plaintext)
        rsp_b64 = base64.urlsafe_b64encode(rsp_bytes)

        # Next step
        self._process_cbk = self._process_2

        # Return response object
        return schemas.ProcessingData(session_id=self.session_id, data=rsp_b64)
    
    def process_session_data(self, db: Session, data_type: types.SessionDataType) -> schemas.ProcessingData:
        # Process session data request
        session_data_request = SessionDataRequest(db, self._wallet, data_type)
        session_data = session_data_request.request_session_data()
        # Convert data to json
        session_data_json = session_data.json()
        # Encode data to bytes
        data = self._add_padding(session_data_json.encode('utf-8'))
        # Compute signature
        signature = self._backend_key.sign(data, ec.ECDSA(hashes.SHA256()))
        # Plain text
        plaintext = data + self._add_padding(signature)
        # xor data with nonce
        data = bytes([a ^ b for a, b in zip(plaintext, self._nonce)]) + plaintext[len(self._nonce):]
        # Encrypt data
        data = self._encrypt_data(self._shared_iv, data)
        # Encode data
        data_b64 = base64.urlsafe_b64encode(data)
        # Return respinse
        return schemas.ProcessingData(session_id=self.session_id, data=data_b64)

    @classmethod
    def create(cls, ctx: AppContext, wallet: models.Wallet) -> ISession:
        # Create session
        return cls(ctx, wallet)

    def __init__(self, ctx: AppContext, wallet: models.Wallet):
        super().__init__(ctx)
        self._get_backend_cert_key(ctx.sk_defs)
        self._tx_sig_key = serialization.load_der_private_key(wallet.tx_sig_key_prv, password=None)
        self._wallet = wallet
        self._process_cbk = self._process_1

    def process(self, db: Session, data: bytes) -> schemas.ProcessingData:
        # Process message
        return self._process_cbk(db, data)
