#include <iostream>

#include "skt_utils.hpp"

// Test certificates
class SKTSessionOnline : public SKTTest, public SKTContext {

private:

    // Store name
    static const std::string STORE_NAME;

    // Backend store name
    static const std::string BACKEND_STORE_NAME;

    // Client context
    SKTContext m_client;

    // Prepare test environment
    void Prepare() {}

    // Post-test
    void Cleanup() {}

    // Run test
    void RunTest();

    // Process start online session message
    void ProcessStartOnlineSessionMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Process transaction list message
    void ProcessTransactionListMsg(const SKBinaryBuffer& msg_in);

    // Get balance update message
    void GetBalanceUpdateMsg(SKBinaryBuffer& msg_out);

    // Process TUID request message
    void ProcessTUIDRequestMsg(const uint64_t amount, const SKBinaryBuffer& cuid, const SKBinaryBuffer& msg_in);

    // Get TUID response message
    void GetTUIDResponseMsg(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& msg_out);

public:

    // Constructor
    SKTSessionOnline() : SKTContext(BACKEND_STORE_NAME), m_client(STORE_NAME) {}

    // Destructor
    ~SKTSessionOnline() {}
};

// Store name
const std::string SKTSessionOnline::STORE_NAME = "test.sqlite";

// Backend store name
const std::string SKTSessionOnline::BACKEND_STORE_NAME = "test_backend.sqlite";

// Process start online session message
void SKTSessionOnline::ProcessStartOnlineSessionMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    // Establish shared key and get server public key
    EstablishSharedKey(msg_in, msg_out);

    // Allocate plaintext buffer
    static const uint32_t plaintext_size = SKSession::NONCE_SIZE + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKStaticBinaryBuffer<plaintext_size> plaintext;
    plaintext.UpdateSize(plaintext_size);

    // Generate nonce
    SKBinaryBufferView nonce(0, SKSession::NONCE_SIZE, plaintext);
    m_sprandom->Generate(SKSession::NONCE_SIZE, nonce);
    m_nonce = nonce;

    // Compute data hash
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> hash;
    SKManagedSHA256Context hash_ctx;
    hash_ctx.Start();
    hash_ctx.Update(msg_out);
    hash_ctx.Update(nonce);
    hash_ctx.Finish(hash);

    // Sign data hash
    SKBinaryBufferView signature(SKSession::NONCE_SIZE, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plaintext);
    m_spkeypair_backend->SignHash(hash, signature);
    SKTTestCrypto::AddPadding(signature);

    // Encrypt plaintext
    SKBinaryBufferView iuid_view(0, SKSession::IUID_SIZE, m_iuid);
    const uint32_t public_key_size = msg_out.GetSize();
    msg_out.UpdateSize(public_key_size + plaintext_size);
    SKBinaryBufferView cipher(public_key_size, plaintext_size, msg_out);
    SKBinaryBufferView iv(0, SKSession::BLOCK_SIZE, m_iuid);    
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, iv, plaintext, cipher);

    // Update m_iv
    ComputeIV();
}

// Process transaction list message
void SKTSessionOnline::ProcessTransactionListMsg(const SKBinaryBuffer& msg_in) {

    // Min message size
    static const uint32_t min_msg_size = SKSession::IUID_SIZE + SKTransactionNode::TRANSACTION_NODE_SIZE + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SK_CHECK(msg_in.GetSize() >= min_msg_size, SK_ERROR_FAILED, "Invalid message size");

    // Decrypt message
    SKDynamicBinaryBuffer plain(SKSessionOnline::MAX_TRANSACTION_BUFFER_SIZE);
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, msg_in, plain);
    plain ^= m_nonce;

    // Get IUID
    SKBinaryBufferView iuid(0, SKSession::IUID_SIZE, plain);
    SK_CHECK(iuid == m_iuid, SK_ERROR_FAILED, "Invalid IUID");

    // Get transaction list
    const uint32_t tx_list_size = plain.GetSize() - SKSession::IUID_SIZE - SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SK_CHECK(tx_list_size % SKTransactionNode::TRANSACTION_NODE_SIZE == 0, SK_ERROR_FAILED, "Invalid transaction list size");
    SKBinaryBufferView tx_list(SKSession::IUID_SIZE, tx_list_size, plain);
        
    // Get signature
    SKBinaryBufferView signature(SKSession::IUID_SIZE + tx_list_size, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    SKTTestCrypto::RemovePadding(signature);

    // Verify signature
    SKBinaryBufferView tx_data(0, SKSession::IUID_SIZE + tx_list_size, plain);
    m_sptx_sig_key->Verify(tx_data, signature);
}

// Get balance update message
void SKTSessionOnline::GetBalanceUpdateMsg(SKBinaryBuffer& msg_out) {

    // Allocate plaintext buffer
    static const uint32_t plain_size = SKTransactionNode::TRANSACTION_NODE_SIZE + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKStaticBinaryBuffer<plain_size> plain;
    plain.UpdateSize(plain_size);

    // Set balance node
    SKBinaryBufferView node(0, SKTransactionNode::TRANSACTION_NODE_SIZE, plain);
    SerializeBalanceNode(node);

    // Compute signature
    SKBinaryBufferView signature(SKTransactionNode::TRANSACTION_NODE_SIZE, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    m_spkeypair_backend->Sign(node, signature);
    SKTTestCrypto::AddPadding(signature);

    // Encrypt plaintext
    plain ^= m_nonce;
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, plain, msg_out);
}

// Process TUID request message
void SKTSessionOnline::ProcessTUIDRequestMsg(const uint64_t amount, const SKBinaryBuffer& cuid, const SKBinaryBuffer& msg_in) {

    // Check message size
    static const uint32_t cipher_size = SKSessionOnline::TUID_REQUEST_DATA_SIZE;
    SK_CHECK(msg_in.GetSize() == cipher_size, SK_ERROR_FAILED, "Invalid message size");

    // Decrypt message
    SKDynamicBinaryBuffer plain(SKSessionOnline::TUID_REQUEST_DATA_SIZE);
    m_spcrypto->AES128CBCDecrypt(m_keyid_sc, m_iv, msg_in, plain);
    plain ^= m_nonce;

    // Check signature
    const uint32_t data_size = cipher_size - SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView data(0, data_size, plain);
    SKBinaryBufferView signature(data_size, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    SKTTestCrypto::RemovePadding(signature);
    m_spkeypair_client->Verify(data, signature);

    // Get amount
    uint64_t tx_amount = 0;
    SKBinaryBufferView amount_view(0, sizeof(uint64_t), data);
    SKTransactionNode::binary_to_int(amount_view, tx_amount);

    // Validate amount
    SK_CHECK(tx_amount == amount, SK_ERROR_FAILED, "Invalid amount");

    // Get CUID (skip amount padding)
    SKBinaryBufferView cuid_view(SKSession::BLOCK_SIZE, SKTransactionNode::CUID_SIZE, data);

    // Validate CUID
    SK_CHECK(cuid_view == cuid, SK_ERROR_FAILED, "Invalid CUID");
}

// Get TUID response message
void SKTSessionOnline::GetTUIDResponseMsg(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& msg_out) {

    // Allocate plaintext buffer
    static const uint32_t plain_size = SKSessionOnline::TUID_RESPONSE_DATA_SIZE;
    SKStaticBinaryBuffer<plain_size> plain;
    plain.UpdateSize(plain_size);

    // Create transaction node
    SKTransactionNode node(amount);
    node.UpdateCUID(cuid);
    SKStaticBinaryBuffer<SKTransactionNode::TUID_SIZE> tuid;
    m_sprandom->Generate(tuid.GetCapacity(), tuid);
    node.UpdateRUID(tuid);
    SKStaticBinaryBuffer<SKTransactionNode::RUID_SIZE> ruid;
    m_sprandom->Generate(ruid.GetCapacity(), ruid);
    node.UpdateRUID(ruid);
    
    // Set node
    SKBinaryBufferView node_view(0, SKTransactionNode::TRANSACTION_NODE_SIZE, plain);
    node.Serialize(node_view);

    // Compute signature
    const uint32_t data_size = plain_size - SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView data(0, data_size, plain);
    SKBinaryBufferView signature(data_size, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    m_spkeypair_backend->Sign(data, signature);
    SKTTestCrypto::AddPadding(signature);

    // Encrypt plaintext
    plain ^= m_nonce;
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, plain, msg_out);
}

// Run test
void SKTSessionOnline::RunTest() {

    // Create provisioning session
    SKSessionPtr spsession = m_client.CreateProvisioningSession();

    // Get client test certificate/key pair
    SKTKeyPairPtr spkeypair_client = SKTKeyPair::Create_SK_TEST_X509(m_sprandom, m_spcrypto);

    // Provision
    Provision(spsession, spkeypair_client);

    // Load keys
    LoadKeys();

    // Initialize balance
    SKDynamicBinaryBuffer msg_out(1024);
    SKDynamicBinaryBuffer msg_in(1024);
    
    // Create online session
    spsession = m_client.CreateOnlineSession();
    SKSessionOnline& session = dynamic_cast<SKSessionOnline&>(*spsession);

    // Start balance initalisation
    session.StartOnlineBalanceInitialization(msg_out);

    // Process balance initialization message
    ProcessBalanceInitMsg(msg_out, msg_in);

    // Process server response
    session.ProcessMsg(msg_in, msg_out);
    SK_CHECK(!msg_out.GetCapacity(), SK_ERROR_FAILED, "Invalid session state");

    // Execute 10 times
    for (int i = 0; i < 10; i++) {

        // Reset buffers
        msg_in.SetSize(1024);
        msg_out.SetSize(1024);

        // Start new online session
        session.StartOnlineSession(msg_out);
        ProcessStartOnlineSessionMsg(msg_out, msg_in);
        session.ProcessMsg(msg_in, msg_out);
        ProcessTransactionListMsg(msg_out);
        GetBalanceUpdateMsg(msg_in);
        session.ProcessMsg(msg_in, msg_out);
        SK_CHECK(!msg_out.GetCapacity(), SK_ERROR_FAILED, "Invalid session state");
    
        // Reset buffer
        msg_out.SetSize(SKSession::MAX_TRANSACTION_BUFFER_SIZE);

        // Perform online transaction
        const uint64_t amount = 100;
        SKStaticBinaryBuffer<SKTransactionNode::CUID_SIZE> tx_cuid;
        m_sprandom->Generate(SKTransactionNode::CUID_SIZE, tx_cuid);
        session.StartOnlineTransaction(amount, tx_cuid, msg_out);
        ProcessTUIDRequestMsg(amount, tx_cuid, msg_out);
        GetTUIDResponseMsg(amount, tx_cuid, msg_in);
        session.ProcessMsg(msg_in, msg_out);
        ProcessTransactionListMsg(msg_out);
        GetBalanceUpdateMsg(msg_in);
        session.ProcessMsg(msg_in, msg_out);
        SK_CHECK(!msg_out.GetCapacity(), SK_ERROR_FAILED, "Invalid session state");
    }
}

// Entry point.
int test_skt_session_online(int, char*[]) {
    
    // Create test
    SKTSessionOnline test;
    return test.Run();
}
