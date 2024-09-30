#include "sk_session_offline_payor.hpp"

// Class factory
SKSessionPtr SKSessionOfflinePayor::Create(
    const SKCryptoPtr& spcrypto,
    const SKSecureStorePtr& spstore, 
    const SKRandomPtr& sprandom)
{
    SKInitContext ctx(spcrypto, spstore, sprandom);
    ctx.LoadContext();

    // Create session
    SKSessionPtr spsession = SKSessionPtr(new SKSessionOfflinePayor(ctx));

    // Return session
    return spsession;
}

// Get key sharing message
void SKSessionOfflinePayor::GetKeySharingMsg(SKBinaryBuffer& msg_out) {

    // Generate client ECDH parameters
    m_spcrypto->ECDHGetClientParams(msg_out);
    AddPadding(msg_out);

    // Compute signature
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> signature;
    m_spcrypto->ECDSAP256Sign(*m_spkey_inst_sig, msg_out, signature);
    AddPadding(signature);

    // Add signature to client parameters
    msg_out += signature;
}

// Process Key sharing response
void SKSessionOfflinePayor::ProcessKeySharingResponse(const SKBinaryBuffer& msg_in) {

    // Get parameters
    uint32_t offset = 0;
    const uint32_t params_size = GetFieldLength(msg_in, offset);
    SK_CHECK(params_size < msg_in.GetSize(), SK_ERROR_P2P_MSG, "Invalid message");

    // Get payee's parameters
    SKBinaryBufferView params(offset, params_size, msg_in);
    offset += params_size;
    const uint32_t header_size = offset;

    // Compute shared secret
    m_spcrypto->ECDHSetPublicKey(params);
    m_spcrypto->ECDHComputeSharedKey(m_keyid_sc);

    // Compute header hash
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> hash;
    SKBinaryBufferView header(0, header_size, msg_in);
    SKManagedSHA256Context::BlockSHA256(header, hash);

    // Check cipher size
    SK_CHECK(offset < msg_in.GetSize(), SK_ERROR_P2P_MSG, "Invalid message");
    const uint32_t cipher_size = msg_in.GetSize() - offset;

    // Prepare buffers
    SKBinaryBufferView cipher(offset, cipher_size, msg_in);
    SKStaticBinaryBuffer<MAX_KEY_SHARING_MSG_SIZE> plain;

    // Decrypt data
    {
        SKConstant<SK_P2P_SHARED_IV_SIZE> iv(SK_P2P_SHARED_IV);
        m_spcrypto->AES128CBCDecrypt(m_keyid_sc, iv.GetBuffer(), cipher, plain);
    }

    // Get header hash
    offset = 0;
    SKBinaryBufferView header_hash(offset, SKManagedSHA256Context::DIGEST_SIZE, plain);
    offset += SKManagedSHA256Context::DIGEST_SIZE;
    SK_CHECK(header_hash == hash, SK_ERROR_P2P_MSG, "Invalid message");

    // Get counterparty nonce
    SKBinaryBufferView nonce(offset, P2P_NONCE_SIZE, plain);
    offset += P2P_NONCE_SIZE;

    // Get counterparty IUID
    SKBinaryBufferView iuid(offset, IUID_SIZE, plain);
    offset += IUID_SIZE;

    // Get counterparty certificate
    SK_CHECK(offset + BLOCK_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE < plain.GetSize(), SK_ERROR_P2P_MSG, "Invalid message");
    const uint32_t cert_size = plain.GetSize() - offset - MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView cert(offset, cert_size, plain);
    offset += cert_size;

    // Get signature
    SKBinaryBufferView signature(offset, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    offset += MAX_ECDSA_P256_SIGNATURE_SIZE;

    // Check size
    SK_CHECK(offset == plain.GetSize(), SK_ERROR_P2P_MSG, "Invalid message");

    // Verify certificate
    RemovePadding(cert);
    SKCertChainPtr spcert = SKCertChain::Create(cert);
    VerifyCertificate(spcert);

    // Verify signature
    RemovePadding(signature);
    SKBinaryBufferView data(0, offset - MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    spcert->VerifySignature(signature, data);

    // Update state
    m_counterparty_nonce = nonce;
    m_counterparty_iuid = iuid;
    ComputeSharedIV(nonce, iuid);
    m_spchain = spcert;
    m_sprandom->Generate(NONCE_SIZE, m_nonce);
    m_tuid.Set(m_nonce.GetBuffer(), m_nonce.GetSize()); // ???
    m_tuid ^= m_counterparty_nonce;
}

// Get transaction data message
void SKSessionOfflinePayor::GetTransactionDataMsg(SKBinaryBuffer& msg_out) {

    // Add nonce
    SKStaticBinaryBuffer<MAX_TRANSACTION_BUFFER_SIZE> plain;
    SKBinaryBufferView nonce(0, NONCE_SIZE, plain);
    nonce = m_nonce;
    uint32_t offset = NONCE_SIZE;

    // Encode IUID
    SKBinaryBufferView iuid(offset, IUID_SIZE, plain);
    {
        SKStoreList::SKStoreKeyBuffer db_iuid_val(SK_DB_TX_IUID_VAL_HEX);
        SKStoreList::SKStoreKeyBuffer db_iuid_tag(SK_DB_TX_IUID_TAG_HEX);
        SKStoreValuePtr spiuid = SKStoreValue::Load(*m_spstore, m_spkey, db_iuid_val, db_iuid_tag);
        spiuid->Decrypt(iuid);
    }
    offset += IUID_SIZE;

    // Encode amount
    SKBinaryBufferView amount(offset, sizeof(uint64_t), plain);
    SKTransactionNode::int_to_binary(m_amount, amount);
    offset += sizeof(uint64_t);

    // Encode timestamp
    SKBinaryBufferView timestamp(offset, sizeof(uint64_t), plain);
    SKTransactionNode::int_to_binary(m_timestamp, timestamp);
    offset += sizeof(uint64_t);

    // Load instance certificate
    const uint32_t cert_view_size = plain.GetCapacity() - offset;
    SKBinaryBufferView cert(offset, cert_view_size, plain);
    {
        // Load certificate
        SKStoreKeyBuffer db_key(SK_DB_INST_CERT_VAL_HEX);
        SKStoreKeyBuffer db_key_tag(SK_DB_INST_CERT_TAG_HEX);
        SKStoreValuePtr spcert = SKStoreValue::Load(*m_spstore, m_spkey, db_key, db_key_tag);
        spcert->Decrypt(cert);

        // Verify certificate
        SKCertChainPtr spchain = SKCertChain::Create(cert);
        VerifyCertificate(spchain);
    }

    offset += cert.GetSize();

    // Add signature
    plain.UpdateSize(offset);
    SKBinaryBufferView signature(offset, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    m_spcrypto->ECDSAP256Sign(*m_spkey_inst_sig, plain, signature);
    AddPadding(signature);
    offset += MAX_ECDSA_P256_SIGNATURE_SIZE;

    // Encrypt message
    plain.UpdateSize(offset);
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, plain, msg_out);
}

// Process receipt message
void SKSessionOfflinePayor::ProcessReceiptMsg(const SKBinaryBuffer& msg_in) {

    // Check message size
    SK_CHECK(msg_in.GetSize() == RECEIPT_MSG_SIZE, SK_ERROR_P2P_MSG, "Invalid message");

    // Decrypt message
    SKStaticBinaryBuffer<RECEIPT_MSG_SIZE> msg;
    msg.UpdateSize(0);
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, msg_in, msg);
    msg.UpdateSize(RECEIPT_MSG_SIZE);

    // Get nonce
    SKBinaryBufferView nonce(0, NONCE_SIZE, msg);
    SK_CHECK(nonce == m_counterparty_nonce, SK_ERROR_P2P_MSG, "Invalid message");

    // Get signature
    SKBinaryBufferView signature(NONCE_SIZE, MAX_ECDSA_P256_SIGNATURE_SIZE, msg);
    RemovePadding(signature);

    // Verify signature
    m_spchain->VerifySignature(signature, nonce);

    // Add transaction to store
    SKTransactionNode tx(m_amount, m_timestamp, m_counterparty_iuid, m_tuid, nonce);
    uint64_t balance = GetBalance();
    BeginTransaction();
    AddTransaction(tx);
    CommitTransaction();
}

// Process message, update state and return response
void SKSessionOfflinePayor::ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    const uint32_t state_value = uint32_t(m_state);

    // Init state
    m_state = SK_ST_INVALID;

    switch (state_value)
    {
    case SK_ST_P2PS_RESP:
        ProcessKeySharingResponse(msg_in);
        GetTransactionDataMsg(msg_out);
        m_state = SK_ST_P2PS_RCPT;
        break;

    case SK_ST_P2PS_RCPT:
        ProcessReceiptMsg(msg_in);
        msg_out.Reset();
        m_state = SK_ST_DONE;
        break;

    default:
        SK_CHECK(false, SK_ERROR_ONLINE_INVALID_STATE, "Invalid state");
    }
}

// Start offline transaction
void SKSessionOfflinePayor::StartOfflineTransaction(const uint64_t amount, const uint64_t timestamp, SKBinaryBuffer& msg_out) {

    // Init state
    m_state = SK_ST_INVALID;

    // Set tx state
    m_amount = amount;
    m_timestamp = timestamp;

    // Get key sharing message
    GetKeySharingMsg(msg_out);

    m_state = SK_ST_P2PS_RESP;
}
