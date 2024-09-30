#include "sk_session_provision.hpp"
#include "sk_store_mgr.hpp"

// Class factory
SKSessionPtr SKSessionProvision::Create(
    const SKCryptoPtr& spcrypto,
    const SKSecureStorePtr& spstore, 
    const SKRandomPtr& sprandom)
{
    SKInitContext ctx(spcrypto, spstore, sprandom);

    // Create session
    SKSessionPtr spsession = SKSessionPtr(new SKSessionProvision(ctx));

    // Return session
    return spsession;
}

// Establish shared key
void SKSessionProvision::GetEstablishSharedKeyMsg(SKBinaryBuffer& msg_out)
{
    // Init state
    m_state = SK_ST_INVALID;

    // Start session
    StartSession(msg_out);

    // Update state
    m_state = SK_ST_PROV_SRV_RESP;
}

// Get provisioning token message 
void SKSessionProvision::GetProvisioningTokenMsg(const SKBinaryBuffer& token, SKBinaryBuffer& msg_out)
{
    // Init state
    m_state = SK_ST_INVALID;

    // Check token size
    SK_CHECK(token.GetSize() == PROVISIONING_TOKEN_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid token size");

    // Assemble message
    SKStaticBinaryBuffer<PROVISIONING_TOKEN_SIZE + DIGEST_SIZE> msg;
    msg.UpdateSize(0);

    msg += token;

    // Compute hash
    SKStaticBinaryBuffer<DIGEST_SIZE> hash;
    SKManagedSHA256Context::BlockSHA256(msg, hash);
    msg += hash;
    msg ^= m_nonce;

    // Encrypt data
    {
        SKConstant<SK_PROV_SHARED_IV_SIZE> iv_const(SK_PROV_SHARED_IV);
        iv_const.Unmask(SKConstant<SK_PROV_SHARED_IV_SIZE>(SK_PROV_SHARED_IV_MASK));
        iv_const.VerifyHash(SKConstant<32>(SK_PROV_SHARED_IV_CSUM));
        m_spcrypto->AES128CBCEncrypt(m_keyid_sc, iv_const.GetBuffer(), msg, msg_out);
    }

    // Update state
    m_state = SK_ST_PROV_PARAMS;
}

// Generate client ECDH parameters
void SKSessionProvision::StartSession(SKBinaryBuffer& client_params)
{
    // Get backend certificate
    SKConstant<SK_BACKEND_CERT_SIZE> cert(SK_BACKEND_CERT);
    cert.Unmask(SKConstant<SK_BACKEND_CERT_SIZE>(SK_BACKEND_CERT_MASK));
    cert.VerifyHash(SKConstant<32>(SK_BACKEND_CERT_CSUM));

    // Create instance
    SKCertChainPtr spchain = SKCertChainPtr(new SKCertChain());

    // Parse certificate
    spchain->Parse(cert.GetBuffer());
    m_spchain = spchain;

    // Generate client ECDH parameters
    m_spcrypto->ECDHGetClientParams(client_params);
    AddPadding(client_params);
}

// Process server response
void SKSessionProvision::ProcessServerResponse(const SKBinaryBuffer& server_response)
{
    // Check server response size
    static const uint32_t min_size = MAX_ECDSA_P256_SIGNATURE_SIZE + NONCE_SIZE + BLOCK_SIZE;
    const uint32_t server_response_size = server_response.GetSize();
    SK_CHECK(server_response_size > min_size && !(server_response_size % BLOCK_SIZE), SK_ERROR_INVALID_PARAMETER, "Invalid server response size");

    // Get parameters
    const uint32_t params_size = server_response_size - MAX_ECDSA_P256_SIGNATURE_SIZE - NONCE_SIZE;
    SKBinaryBufferView params(0, params_size, server_response);
    RemovePadding(params);
    
    // Process parameters
    m_spcrypto->ECDHSetPublicKey(params);

    // Compute shared secret
    m_spcrypto->ECDHComputeSharedKey(m_keyid_sc);

    // Decrypt data
    SKBinaryBufferView cipher(params_size, server_response_size - params_size, server_response);
    SKStaticBinaryBuffer<NONCE_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE> plain;

    // Decrypt data
    {
        SKConstant<SK_PROV_SHARED_IV_SIZE> iv_const(SK_PROV_SHARED_IV);
        iv_const.Unmask(SKConstant<SK_PROV_SHARED_IV_SIZE>(SK_PROV_SHARED_IV_MASK));
        iv_const.VerifyHash(SKConstant<32>(SK_PROV_SHARED_IV_CSUM));
        m_spcrypto->AES128CBCDecrypt(m_keyid_sc, iv_const.GetBuffer(), cipher, plain);
    }

    // Get nonce
    SKBinaryBufferView nonce(0, NONCE_SIZE, plain);
    m_nonce = nonce;

    // Get signature
    SKBinaryBufferView signature(NONCE_SIZE, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    RemovePadding(signature);

    // Verify signature
    SKBinaryBufferView params2(0, params_size, server_response);
    SKStaticBinaryBuffer<DIGEST_SIZE> hash;
    SKManagedSHA256Context hash_ctx;
    hash_ctx.Start();
    hash_ctx.Update(params2);
    hash_ctx.Update(m_nonce);
    hash_ctx.Finish(hash);
    
    m_spchain->VerifySignatureHash(signature, hash);
    
    // Compute IV
    ComputeIV(m_token);
}

// Process provisioning parameters
void SKSessionProvision::ProcessProvisioningParameters(const SKBinaryBuffer& msg_in)
{
    // Decrypt data
    SKStaticBinaryBuffer<MAX_PROVISIONING_PARAMS_SIZE> data;
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, msg_in, data);
    data ^= m_nonce;

    // Extract signature
    SK_CHECK(data.GetSize() > MAX_ECDSA_P256_SIGNATURE_SIZE, SK_ERROR_INVALID_PROV_DATA, "Invalid provisioning parameters size");
    const uint32_t data_size = data.GetSize() - MAX_ECDSA_P256_SIGNATURE_SIZE;

    // Extract IUID
    uint32_t offset = 0;
    SKBinaryBufferView iuid_view(offset, IUID_SIZE, data);
    offset += IUID_SIZE;

    // Extract persistence key
    const uint32_t storage_key_size = GetFieldLength(data, offset);
    SKBinaryBufferView storage_key_view(offset, storage_key_size, data);
    offset += storage_key_size;

    // Extract client ECDSA key pair
    const uint32_t ecdsa_key_pair_size = GetFieldLength(data, offset);
    SKBinaryBufferView ecdsa_key_pair_view(offset, ecdsa_key_pair_size, data);
    offset += ecdsa_key_pair_size;

    // Extract client certificate
    const uint32_t client_cert_size = GetFieldLength(data, offset);
    const uint32_t client_cert_offset = offset;
    SKBinaryBufferView client_cert_view(offset, client_cert_size, data);
    offset += client_cert_size;

    // Extract transaction encryption key
    const uint32_t key_tx_size = GetFieldLength(data, offset);
    SKBinaryBufferView key_tx_view(offset, key_tx_size, data);
    offset += key_tx_size;

    // Extract transaction signing key
    const uint32_t key_tx_sign_size = GetFieldLength(data, offset);
    SKBinaryBufferView key_tx_sign_view(offset, key_tx_sign_size, data);
    offset += key_tx_sign_size;

    // Skip padding
    offset += data.GetBuffer()[offset];

    // Check data size
    SK_CHECK(offset == data_size, SK_ERROR_INVALID_PROV_DATA, "Invalid provisioning parameters size");

    // Verify cetificate
    SKCertChainPtr spchain = SKCertChainPtr(new SKCertChain());
    spchain->Parse(client_cert_view);
    VerifyCertificate(spchain);
    // m_spchain = spchain;

    // Verify signature
    SKBinaryBufferView signature(data_size, MAX_ECDSA_P256_SIGNATURE_SIZE, data);
    RemovePadding(signature);
    data.UpdateSize(data_size);
    m_spchain->VerifySignature(signature, data);

    // Unwrap persistence key
    SKCrypto::SKKeyId key_id;
    m_spcrypto->UnwrapKeyAES128GCM(m_keyid_sc, storage_key_view, key_id); 

    // Unwrap client ECDSA key pair
    SKCrypto::SKKeyId key_id_ecdsa;
    m_spcrypto->UnwrapKeyECDSAP256(m_keyid_sc, ecdsa_key_pair_view, key_id_ecdsa);

    // Unwrap transaction encryption key
    SKCrypto::SKKeyId key_id_tx;
    m_spcrypto->UnwrapKeyAES128GCM(m_keyid_sc, key_tx_view, key_id_tx);

    // Unwrap transaction signing key
    SKCrypto::SKKeyId key_id_tx_sig;
    m_spcrypto->UnwrapKeyECDSAP256(m_keyid_sc, key_tx_sign_view, key_id_tx_sig);

    // Begin transaction
    BeginTransaction();

    // Store persistence key
    {
        SKStoreKeyBuffer db_key(SK_DB_TX_PER_KEY_HEX);
        m_spkey = SKStoreCryptoKey::Store(*m_spstore, m_spcrypto, key_id, db_key);
    }

    // Store client ECDSA key pair
    {
        SKStoreKeyBuffer db_key(SK_DB_INST_SIG_KEY_HEX);
        m_spkey_inst_sig = SKStoreCryptoKey::Store(*m_spstore, m_spcrypto, key_id_ecdsa, db_key);
    }

    // Store transaction encryption key
    {
        SKStoreKeyBuffer db_key(SK_DB_TX_ENC_KEY_HEX);
        m_spkey_tx_enc = SKStoreCryptoKey::Store(*m_spstore, m_spcrypto, key_id_tx, db_key);
    }

    // Store transaction signing key
    {
        SKStoreKeyBuffer db_key(SK_DB_TX_SIG_KEY_HEX);
        m_spkey_tx_sig = SKStoreCryptoKey::Store(*m_spstore, m_spcrypto, key_id_tx_sig, db_key);
    }

    // Store client certificate
    {
        SKBinaryBufferView cert_view(client_cert_offset, client_cert_size + BLOCK_SIZE, data);
        cert_view.UpdateSize(client_cert_size);
        AddPadding(cert_view);
        SKStoreKeyBuffer db_key(SK_DB_INST_CERT_VAL_HEX);
        SKStoreKeyBuffer db_key_tag(SK_DB_INST_CERT_TAG_HEX);
        SKStoreValue::Store(*m_spstore, m_spkey, db_key, db_key_tag, cert_view);
    }

    // Store IUID
    {
        SKStoreKeyBuffer db_key(SK_DB_TX_IUID_VAL_HEX);
        SKStoreKeyBuffer db_key_tag(SK_DB_TX_IUID_TAG_HEX);
        SKStoreValue::Store(*m_spstore, m_spkey, db_key, db_key_tag, iuid_view);
    }

    // Seed prng
    m_sprandom->UpdateSeed(m_nonce);

    // Compute IV
    SKBuffer32 iuid = iuid_view;
    ComputeIV(iuid);

    // Commit transaction
    CommitTransaction();
}

// Process message
void SKSessionProvision::ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    const uint32_t state_value = uint32_t(m_state);

    // Init state
    m_state = SK_ST_INVALID;

    switch (state_value)
    {
    case SK_ST_PROV_SRV_RESP:
        ProcessServerResponse(msg_in);
        GetProvisioningTokenMsg(m_token, msg_out);
        m_state = SK_ST_PROV_PARAMS;
        break;

    case SK_ST_PROV_PARAMS:
        ProcessProvisioningParameters(msg_in);
        msg_out.Reset();
        m_state = SK_ST_ONLINE_DONE;
        break;

    default:
        SK_CHECK(false, SK_ERROR_ONLINE_INVALID_STATE, "Invalid state");
    }
}

// Provision
void SKSessionProvision::Provision(const SKBinaryBuffer& token, SKBinaryBuffer& msg_out)
{
    // Init state
    m_state = SK_ST_INVALID;

    // Store token in session
    m_token = token;

    // Establish shared key
    GetEstablishSharedKeyMsg(msg_out);
}
