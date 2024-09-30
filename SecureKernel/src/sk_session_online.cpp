#include "sk_session_online.hpp"

// Class factory
SKSessionPtr SKSessionOnline::Create(
    const SKCryptoPtr& spcrypto,
    const SKSecureStorePtr& spstore, 
    const SKRandomPtr& sprandom)
{
    SKInitContext ctx(spcrypto, spstore, sprandom);
    ctx.LoadContext();

    // Create session
    SKSessionPtr spsession = SKSessionPtr(new SKSessionOnline(ctx));

    // Return session
    return spsession;
}

// Generate client ECDH parameters
void SKSessionOnline::StartSession(SKBinaryBuffer& client_params)
{
    // Get backend certificate
    SKConstant<SK_BACKEND_CERT_SIZE> cert(SK_BACKEND_CERT);
    cert.Unmask(SKConstant<SK_BACKEND_CERT_SIZE>(SK_BACKEND_CERT_MASK));
    cert.VerifyHash(SKConstant<32>(SK_BACKEND_CERT_CSUM));

    // Get DER encoded certificate size    

    // Create instance
    SKCertChainPtr spchain = SKCertChainPtr(new SKCertChain());

    // Parse certificate
    spchain->Parse(cert.GetBuffer());
    m_spchain = spchain;

    // Generate client ECDH parameters
    m_spcrypto->ECDHGetClientParams(client_params);
    AddPadding(client_params);

    // Compute signature
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> signature;
    m_spcrypto->ECDSAP256Sign(*m_spkey_inst_sig, client_params, signature);
    AddPadding(signature);

    // Add signature to client parameters
    client_params += signature;
}

// Process server params, establish shared key
void SKSessionOnline::ProcessServerParams(const SKBinaryBuffer& server_response, const uint32_t cipher_size, SKBinaryBuffer& plain) {

    // Check server response size
    const uint32_t min_size = cipher_size + BLOCK_SIZE;
    const uint32_t server_response_size = server_response.GetSize();
    SK_CHECK(server_response_size > min_size && !(server_response_size % BLOCK_SIZE), SK_ERROR_INVALID_PARAMETER, "Invalid server response size");

    // Load IUID
    SKBuffer32 iuid;
    {
        SKStoreList::SKStoreKeyBuffer db_iuid_val(SK_DB_TX_IUID_VAL_HEX);
        SKStoreList::SKStoreKeyBuffer db_iuid_tag(SK_DB_TX_IUID_TAG_HEX);
        SKStoreValuePtr spiuid = SKStoreValue::Load(*m_spstore, m_spkey, db_iuid_val, db_iuid_tag);
        spiuid->Decrypt(iuid);
    }

    // IV
    SKBinaryBufferView iv(0, BLOCK_SIZE, iuid);    

    // Process parameters
    const uint32_t params_size = server_response_size - cipher_size;
    SKBinaryBufferView params(0, params_size, server_response);
    RemovePadding(params);
    m_spcrypto->ECDHSetPublicKey(params);

    // Compute shared secret
    m_spcrypto->ECDHComputeSharedKey(m_keyid_sc);

    // Decrypt data
    SKBinaryBufferView cipher(params_size, cipher_size, server_response);
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, iv, cipher, plain);

    // Get nonce
    plain.Extract(0, NONCE_SIZE, m_nonce);

    // Verify data signature
    const uint32_t data_size = cipher_size - MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView data(0, data_size, plain);
    SKBinaryBufferView signature(data_size, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    RemovePadding(signature);

    // Verify signature
    params.UpdateSize(params_size);
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> hash;
    SKManagedSHA256Context hash_ctx;
    hash_ctx.Start();
    hash_ctx.Update(params);
    hash_ctx.Update(data);
    hash_ctx.Finish(hash);

    m_spchain->VerifySignatureHash(signature, hash);

    // Compute IV
    ComputeIV(iuid);
}


// ProcessMsg server response
void SKSessionOnline::ProcessServerResponse(const SKBinaryBuffer& server_response)
{
    // Cipher size
    static const uint32_t cipher_size = MAX_ECDSA_P256_SIGNATURE_SIZE + NONCE_SIZE;

    // Process server params, establish shared key
    SKStaticBinaryBuffer<cipher_size> plain;
    ProcessServerParams(server_response, cipher_size, plain);
}

// Process server response messae with transaction list initiaization
void SKSessionOnline::ProcessServerResponseBalance(const SKBinaryBuffer& server_response)
{
    // Cipher size
    static const uint32_t cipher_size = MAX_ECDSA_P256_SIGNATURE_SIZE + SKTransactionNode::TRANSACTION_NODE_SIZE + NONCE_SIZE;

    // Process server params, establish shared key
    SKStaticBinaryBuffer<cipher_size> plain;
    ProcessServerParams(server_response, cipher_size, plain);

    // Get balance node
    SKBinaryBufferView tx_balance(NONCE_SIZE, SKTransactionNode::TRANSACTION_NODE_SIZE, plain);

    // Begin transaction
    BeginTransaction();

    // Initialize transaction list
    Initialize(tx_balance);

    // Commit transaction
    CommitTransaction();
}

// Get transaction list
void SKSessionOnline::GetTransactionList(SKBinaryBuffer& tx_list)
{
    // Get transaction data
    SKDynamicBinaryBuffer tx_data(SKSession::MAX_TRANSACTION_BUFFER_SIZE);
    GetTransactionsData(tx_data);
    AddPadding(tx_data);

    // XOR first 32 bytes with nonce
    tx_data ^= m_nonce;

    // Check size
    const uint32_t tx_data_size = tx_data.GetSize();
    SK_CHECK(tx_data_size >= MIN_TX_DATA_SIZE, SK_ERROR_TX_LIST, "Invalid transaction data size");

    // Encrypt transaction data
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, tx_data, tx_list);
}

// Get TUID request data
void SKSessionOnline::GetTUIDRequestData(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& tuid_request_data)
{
    // Check CUID size
    const uint32_t cuid_size = cuid.GetSize();
    SK_CHECK(cuid_size == SKTransactionNode::CUID_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid CUID size");

    // Build request data
    SKStaticBinaryBuffer<TUID_REQUEST_DATA_SIZE> plain;
    plain.UpdateSize(TUID_REQUEST_DATA_SIZE);

    // Amount to network order
    SKBinaryBufferView tx_amount(0, sizeof(uint64_t), plain);
    SKTransactionNode::int_to_binary(amount, tx_amount);

    // Amount padding
    SKBinaryBufferView tx_amount_pad(sizeof(uint64_t), BLOCK_SIZE - sizeof(uint64_t), plain);
    m_sprandom->Generate(tx_amount_pad.GetCapacity(), tx_amount_pad);

    // Add CUID
    SKBinaryBufferView tx_cuid(BLOCK_SIZE, cuid_size, plain);
    tx_cuid = cuid;

    // Sign request data
    const uint32_t data_size = TUID_REQUEST_DATA_SIZE - MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView signature(data_size, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    SKBinaryBufferView data(0, data_size, plain);
    m_spcrypto->ECDSAP256Sign(*m_spkey_inst_sig, data, signature);
    AddPadding(signature);

    // Encrypt request data
    plain ^= m_nonce;
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, plain, tuid_request_data);
}

// ProcessMsg TUID response data
void SKSessionOnline::ProcessTUIDResponseData(const SKBinaryBuffer& tuid_response_data, uint64_t& amount, uint64_t& ts, SKBinaryBuffer& cuid, SKBinaryBuffer& tuid, SKBinaryBuffer& ruid)
{
    // Check size
    const uint32_t tuid_response_data_size = tuid_response_data.GetSize();
    SK_CHECK(tuid_response_data_size == TUID_RESPONSE_DATA_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid TUID response data size");

    // Decrypt response data
    SKDynamicBinaryBuffer plain;
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, tuid_response_data, plain);

    // XOR first 32 bytes with nonce
    plain ^= m_nonce;

    // Get data
    const uint32_t data_size = TUID_RESPONSE_DATA_SIZE - MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView data(0, data_size, plain);

    // Get signature
    SKBinaryBufferView signature(data_size, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    RemovePadding(signature);

    // Verify signature
    m_spchain->VerifySignature(signature, data);

    // Get amount
    int offset = 0;
    SKBinaryBufferView amount_net(offset, sizeof(uint64_t), plain);
    SKTransactionNode::binary_to_int(amount_net, amount);

    // Get timestamp
    offset += sizeof(uint64_t);
    SKBinaryBufferView ts_net(sizeof(uint64_t), sizeof(uint64_t), plain);
    SKTransactionNode::binary_to_int(ts_net, ts);

    // Get TUID
    offset += sizeof(uint64_t);
    plain.Extract(offset, SKTransactionNode::TUID_SIZE, tuid);

    // Get CUID
    offset += SKTransactionNode::TUID_SIZE;
    plain.Extract(offset, SKTransactionNode::CUID_SIZE, cuid);

    // Get RUID
    offset += SKTransactionNode::CUID_SIZE;
    plain.Extract(offset, SKTransactionNode::RUID_SIZE, ruid);
}

// ProcessMsg balance update data
void SKSessionOnline::ProcessBalanceUpdateData(const SKBinaryBuffer& balance_update_data)
{
    // Check size
    const uint32_t balance_update_data_size = balance_update_data.GetSize();
    SK_CHECK(balance_update_data_size == BALANCE_UPDATE_DATA_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid balance update data size");

    // Decrypt response data
    SKStaticBinaryBuffer<BALANCE_UPDATE_DATA_SIZE> plain;
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, balance_update_data, plain);

    // XOR first 32 bytes with nonce
    plain ^= m_nonce;

    // Get transaction data
    SKBinaryBufferView tx_balance(0, SKTransactionNode::TRANSACTION_NODE_SIZE, plain);

    // Get signature
    SKBinaryBufferView signature(SKTransactionNode::TRANSACTION_NODE_SIZE, MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    RemovePadding(signature);

    // Verify signature
    m_spchain->VerifySignature(signature, tx_balance);

    // Begin transaction
    BeginTransaction();

    // Initialize transaction list
    Initialize(tx_balance);

    // Commit transaction
    CommitTransaction();
}

// ProcessMsg TIUD response
void SKSessionOnline::ProcessTUIDResponse(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    uint64_t amount = 0;
    uint64_t ts = 0;
    SKBuffer32 cuid;
    SKBuffer32 tuid;
    SKBuffer32 ruid;
    
    // ProcessMsg TUID response data
    ProcessTUIDResponseData(msg_in, amount, ts, cuid, tuid, ruid);
    SK_CHECK(amount == m_amount && cuid == m_cuid, SK_ERROR_ONLINE_NEWTX_STATE, "Invalid transaction state");

    // New transaction node
    SKTransactionNode tx_node(amount, ts, cuid, tuid, ruid);

    // Begin transaction
    BeginTransaction();

    // Check tx list integrity (and get tail) 
    GetBalance();

    // Add transaction node
    AddTransaction(tx_node);

    // Get transaction list
    GetTransactionList(msg_out);

    // Discard local discard modifications
    RollbackTransaction();
}

// Establish shared key
void SKSessionOnline::GetEstablishSharedKeyMsg(SKBinaryBuffer& msg_out)
{
    // Start session
    StartSession(msg_out);
}

// Upload transaction list
void SKSessionOnline::GetUploadTransactionListMsg(SKBinaryBuffer& msg_out)
{
    // Get transaction list
    GetTransactionList(msg_out);
}

// New transaction
void SKSessionOnline::GetNewTransactionMsg(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& msg_out)
{
    // Clear new transaction state
    ClearNewTransactionState();

    // Get TUID request data
    GetTUIDRequestData(amount, cuid, msg_out);

    // Set new transaction state
    SetNewTransactionState(amount, 0, cuid);
}

// ProcessMsg message
void SKSessionOnline::ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    const uint32_t state_value = uint32_t(m_state);

    // Init state
    m_state = SK_ST_INVALID;

    switch (state_value)
    {
    case SK_ST_ONLINE_SRV_RESP:
        ProcessServerResponse(msg_in);
        GetUploadTransactionListMsg(msg_out);
        m_state = SK_ST_ONLINE_TX_RESP;
        break;
    
    case SK_ST_ONLINE_SRV_RESP_BALANCE:
        ProcessServerResponseBalance(msg_in);
        msg_out.Reset();
        m_state = SK_ST_ONLINE_DONE;
        break;

    case SK_ST_ONLINE_TX_RESP:
        ProcessBalanceUpdateData(msg_in);
        msg_out.Reset();
        m_state = SK_ST_ONLINE_DONE;
        break;

    case SK_ST_ONLINE_TUID_RESP:
        ProcessTUIDResponse(msg_in, msg_out);
        m_state = SK_ST_ONLINE_TX_RESP;
        break;

    default:
        SK_CHECK(false, SK_ERROR_ONLINE_INVALID_STATE, "Invalid state");
    }
}

// Start new online session with balance update
void SKSessionOnline::StartOnlineBalanceInitialization(SKBinaryBuffer& msg_out) {

    // Init state
    m_state = SK_ST_INVALID;

    // Establish shared key
    GetEstablishSharedKeyMsg(msg_out);

    // Update state
    m_state = SK_ST_ONLINE_SRV_RESP_BALANCE;
}

// Start new online session
void SKSessionOnline::StartOnlineSession(SKBinaryBuffer& msg_out) {

    // Init state
    m_state = SK_ST_INVALID;

    // Establish shared key
    GetEstablishSharedKeyMsg(msg_out);

    // Update state
    m_state = SK_ST_ONLINE_SRV_RESP;
}

// Start new online transaction
void SKSessionOnline::StartOnlineTransaction(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& msg_out) {

    // Init state
    m_state = SK_ST_INVALID;

    // New transaction
    GetNewTransactionMsg(amount, cuid, msg_out);

    // Update state
    m_state = SK_ST_ONLINE_TUID_RESP;
}
