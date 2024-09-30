#include "sk_session_offline_payee.hpp"

// Class factory
SKSessionPtr SKSessionOfflinePayee::Create(
    const SKCryptoPtr& spcrypto,
    const SKSecureStorePtr& spstore, 
    const SKRandomPtr& sprandom)
{
    SKInitContext ctx(spcrypto, spstore, sprandom);
    ctx.LoadContext();

    // Create session
    SKSessionPtr spsession = SKSessionPtr(new SKSessionOfflinePayee(ctx));

    // Return session
    return spsession;
}

// Process Key sharing request message
void SKSessionOfflinePayee::ProcessKeySharingRequestMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    // Check message size
    const uint32_t msg_size = msg_in.GetSize();
    static const uint32_t min_size = BLOCK_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE;
    static const uint32_t max_size = 256 + MAX_ECDSA_P256_SIGNATURE_SIZE;
    SK_CHECK(msg_size >= min_size && msg_size <= max_size, SK_ERROR_P2P_MSG, "Invalid message");

    // Set ouput buffer size
    msg_out.SetSize(MAX_KEY_SHARING_MSG_SIZE);

    // Get client parameters
    const uint32_t params_size = msg_size - MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView params(0, params_size, msg_in);

    // Compute client signature hash (postponed verification)
    SKManagedSHA256Context::BlockSHA256(params, m_hash);
    
    // Get signature (verification postponed)
    msg_in.Extract(params_size, MAX_ECDSA_P256_SIGNATURE_SIZE, m_signature);

    // Get payee's ECDH parameters
    uint32_t offset = 0;
    SKBinaryBufferView public_key(offset, msg_out);
    RemovePadding(params);
    m_spcrypto->ECDHServerPublicKey(params, public_key);
    public_key.UpdateField(offset, msg_out);
    SKBinaryBufferView test_view(0, msg_out.GetSize(), msg_out);

    // Compute shared secret
    m_spcrypto->ECDHComputeSharedKey(m_keyid_sc);

    // Prepare cipher
    SKStaticBinaryBuffer<MAX_KEY_SHARING_MSG_SIZE> plain;
    offset = 0;

    // Add parameters hash
    SKBinaryBufferView hash(offset, SKManagedSHA256Context::DIGEST_SIZE, plain);
    SKManagedSHA256Context::BlockSHA256(msg_out, hash);
    offset += SKManagedSHA256Context::DIGEST_SIZE;

    // Add nonce
    SKBinaryBufferView nonce(offset, NONCE_SIZE, plain);
    m_sprandom->Generate(NONCE_SIZE, m_nonce);
    nonce = m_nonce;
    offset += NONCE_SIZE;

    // Add IUID
    SKBinaryBufferView iuid(offset, IUID_SIZE, plain);
    {
        SKStoreList::SKStoreKeyBuffer db_iuid_val(SK_DB_TX_IUID_VAL_HEX);
        SKStoreList::SKStoreKeyBuffer db_iuid_tag(SK_DB_TX_IUID_TAG_HEX);
        SKStoreValuePtr spiuid = SKStoreValue::Load(*m_spstore, m_spkey, db_iuid_val, db_iuid_tag);
        spiuid->Decrypt(iuid);
    }
    offset += IUID_SIZE;

    // Load instance certificate
    SKBinaryBufferView cert(offset, plain.GetCapacity() - offset, plain);
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
    plain.UpdateSize(offset);

    // Encrypt message
    {
        SKConstant<SK_P2P_SHARED_IV_SIZE> iv(SK_P2P_SHARED_IV);
        SKBinaryBufferView cipher(msg_out.GetSize(), plain.GetSize(), msg_out);
        m_spcrypto->AES128CBCEncrypt(m_keyid_sc, iv.GetBuffer(), plain, cipher);
    }
    msg_out.UpdateSize(msg_out.GetSize() + plain.GetSize());

    // Compute shared IV
    ComputeSharedIV(nonce, iuid);
}

// Process transaction data message
void SKSessionOfflinePayee::ProcessTransactionDataMsg(const SKBinaryBuffer& msg_in) {

    // Decrypt message
    SKStaticBinaryBuffer<MAX_KEY_SHARING_MSG_SIZE> plain;
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, msg_in, plain);

    // Get data 
    uint32_t offset = 0;

    // Get nonce
    SKBinaryBufferView nonce(offset, NONCE_SIZE, plain);
    offset += NONCE_SIZE;

    // Get IUID
    SKBinaryBufferView iuid(offset, IUID_SIZE, plain);
    offset += IUID_SIZE;

    // Get amount
    SKBinaryBufferView amount(offset, sizeof(uint64_t), plain);
    offset += sizeof(uint64_t);

    // Get timestamp
    SKBinaryBufferView timestamp(offset, sizeof(uint64_t), plain);
    offset += sizeof(uint64_t);

    // Get counterparty's certificate
    SK_CHECK(plain.GetSize() > offset + MAX_ECDSA_P256_SIGNATURE_SIZE, SK_ERROR_P2P_MSG, "Invalid message");
    const uint32_t cert_size = plain.GetSize() - offset - MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView cert(offset, cert_size, plain);
    offset += cert_size;

    // Get signature
    SKBinaryBufferView signature(offset, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    offset += MAX_ECDSA_P256_SIGNATURE_SIZE;
    SK_CHECK(offset == plain.GetSize(), SK_ERROR_P2P_MSG, "Invalid message");

    // Verify certificate
    SKCertChainPtr spchain = SKCertChain::Create(cert);
    VerifyCertificate(spchain);

    // Verify signature
    RemovePadding(signature);
    SKBinaryBufferView data(0, offset - MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    spchain->VerifySignature(signature, data);
    
    // Update state
    m_counterparty_nonce = nonce;
    m_counterparty_iuid = iuid;
    m_spchain = spchain;
    SKTransactionNode::binary_to_int(amount, m_amount);
    SKTransactionNode::binary_to_int(timestamp, m_timestamp);
    m_tuid.Set(m_nonce.GetBuffer(), m_nonce.GetSize()); // ???
    m_tuid ^= m_counterparty_nonce;
}

// Get receipt message
void SKSessionOfflinePayee::GetReceiptMsg(SKBinaryBuffer& msg_out) {

    // 
    SKStaticBinaryBuffer<RECEIPT_MSG_SIZE> msg;
    msg.UpdateSize(0);
    msg += m_nonce;
    msg.UpdateSize(NONCE_SIZE);

    // Compute signature
    SKBinaryBufferView signature(NONCE_SIZE, MAX_ECDSA_P256_SIGNATURE_SIZE, msg);
    m_spcrypto->ECDSAP256Sign(*m_spkey_inst_sig, msg, signature);
    AddPadding(signature);
    msg.UpdateSize(RECEIPT_MSG_SIZE);

    // Encrypt message
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, msg, msg_out);
}

// Process acknowledgement message
void SKSessionOfflinePayee::ProcessAcknowledgementMsg(const SKBinaryBuffer& msg_in) {

    // Add transaction to store
    SKTransactionNode tx(-m_amount, m_timestamp, m_counterparty_iuid, m_tuid, m_counterparty_nonce);
    uint64_t balance = GetBalance();
    BeginTransaction();
    AddTransaction(tx);
    CommitTransaction();
}

// Process message, update state and return response
void SKSessionOfflinePayee::ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    const uint32_t state_value = uint32_t(m_state);

    // Init state
    m_state = SK_ST_INVALID;

    switch (state_value)
    {
    case SK_ST_P2PR_PARAMS:
        ProcessKeySharingRequestMsg(msg_in, msg_out);
        m_state = SK_ST_P2PR_TXDATA;
        break;

    case SK_ST_P2PR_TXDATA:
        ProcessTransactionDataMsg(msg_in);
        GetReceiptMsg(msg_out);
        m_state = SK_ST_P2PR_ACK;
        break;

    case SK_ST_P2PR_ACK:
        ProcessAcknowledgementMsg(msg_in);
        msg_out.Reset();
        m_state = SK_ST_DONE;
        break;

    default:
        SK_CHECK(false, SK_ERROR_ONLINE_INVALID_STATE, "Invalid state");
    }
}

// Start offline transaction
void SKSessionOfflinePayee::StartOfflineTransaction() {

    m_state = SK_ST_P2PR_PARAMS;
}
