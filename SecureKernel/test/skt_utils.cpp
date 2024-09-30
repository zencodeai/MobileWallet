#include <iostream>
#include <iomanip>

// Generate a random byte array using mbedtls
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

#include "skt_utils.hpp"
#include "sk_crypto_mbedtls.hpp"

// Generate a random byte array
void generate_random_bytes(uint8_t* buffer, size_t length)
{
    // Initialize entropy source
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    // Initialize random number generator
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed random number generator
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    // Generate random bytes
    mbedtls_ctr_drbg_random(&ctr_drbg, buffer, length);

    // Free resources
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// Generate a random integer betwen min and max
uint32_t generate_random_int(uint32_t min, uint32_t max)
{
    // Generate random bytes
    uint8_t buffer[sizeof(uint32_t)];
    generate_random_bytes(buffer, sizeof(buffer));

    // Convert to integer
    int value = 0;
    for (int i = 0; i < sizeof(buffer); i++) {
        value = (value << 8) | buffer[i];
    }

    // Return value
    return min + (value % (max - min));
}

// Generate a random alphanumeric string object
std::string generate_random_string(size_t length)
{
    // Letter uppercase and number characters
    const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Generate random bytes
    uint8_t buffer[length];
    generate_random_bytes(buffer, sizeof(buffer));

    // Convert to string
    std::string value;
    for (int i = 0; i < sizeof(buffer); i++) {
        value += chars[buffer[i] % (sizeof(chars) - 1)];
    }

    // Return value
    return value;
}


// Formatted hexadecimal dump with offset and hex code and ASCII characters
void hexdump(const void* data, size_t size)
{
    // Cast data to byte array
    const uint8_t* bytes = (const uint8_t*)data;

    // Print data
    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0) {
            std::cout << std::endl << std::hex << std::setw(8) << std::setfill('0') << i << "  ";
        }
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i] << " ";
    }
    std::cout << std::endl;
}

// Utils test entry point.
int test_skt_utils(int, char*[]) {

    return 0;
}

// Run test
int SKTTest::Run()
{
    try {

        // Pre-test
        Prepare();

        // Test
        RunTest();
    }
    catch (SKException& error) {
        std::cout << "Error: " << error.what() << std::endl;
        return 1;
    }

    catch (std::exception& error) {
        std::cout << "Error: " << error.what() << std::endl;
        return 1;
    }

    catch (...) {
        std::cout << "Error: Unknown exception" << std::endl;
        return 1;
    }

    return 0;
}

// Prepare test environment
void SKTTestCrypto::Prepare()
{
    // Secure store pathname
    const std::string pathname = "test.sqlite";

    // Delete secure store using stl
    std::remove(pathname.c_str());

    // Instantiate secure store
    spstore = SKSecureStore::Create();

    // Create secure store
    spstore->Create(pathname.c_str());

    // Close secure store
    spstore->Close();

    // Open secure store
    spstore->Open(pathname.c_str());

    // Instantiate random number generator
    sprandom = SKRandom::Create(spstore);

    // Instantiate application key store factory parameters
    SKApplicationKeyStoreSimFactoryParameters params(spstore, sprandom);

    // Generate random byte string of length 32
    SKStaticBinaryBuffer<32> buffer;
    buffer.SetSize(32);
    generate_random_bytes(buffer.GetBuffer(), buffer.GetSize());

    // Update seed
    sprandom->UpdateSeed(buffer);

    // Instantiate application key store
    spappkeystore = SKApplicationKeyStore::Create(params);

    // Generate symmetric key
    spappkeystore->GenerateSymmetricKey(SK_APP_KEY_SYM);

    // Intantiate crypto instance
    spcrypto = SKCrypto::Create(SKCryptoMbedTLSParams(sprandom, spstore, spappkeystore));
}

// Fill buffer with random bytes
void SKTTest::GenerateRandomData(const uint32_t size, SKBinaryBuffer& buffer)
{
    // Set buffer size
    buffer.SetSize(size);

    // Generate random bytes
    generate_random_bytes(buffer.GetBuffer(), buffer.GetSize());
}

// Generate integer between min and max
uint32_t SKTTest::GenerateRandomInt(uint32_t min, uint32_t max)
{
    // Generate random integer
    return generate_random_int(min, max);
}

// ----------------------------------------------------------------------------------------------
// SKTTestCrypto class implementation

// Pad and wrap key blob
void SKTTestCrypto::WrapKeyStatic(const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& key_plain, SKBinaryBuffer& key_blob) {

    // AES block size
    const uint32_t aes_block_size = 16;

    // Tag size
    const uint32_t tag_size = 16;

    // Max blob size
    const uint32_t max_blob_size = 256;

    // Pad key
    const uint32_t padding_size = aes_block_size - (key_plain.GetSize() % aes_block_size);
    const uint32_t plain_size = key_plain.GetSize() + padding_size;
    SKDynamicBinaryBuffer key_padded(plain_size);
    SKDynamicBinaryBuffer padding(padding_size);
    padding.SetSize(padding_size);
    //generate_random_bytes(padding.GetBuffer(), padding.GetSize());
    memset(padding.GetBuffer(), padding_size, padding.GetSize());
    key_padded += key_plain;
    key_padded += padding;

    // Get IV from masked SK_WRAPPING_IV
    SKConstant<SK_UNWRAP_IV_SIZE> iv(SK_UNWRAP_IV);
    iv.Unmask(SKConstant<SK_UNWRAP_IV_SIZE>(SK_UNWRAP_IV_MASK));
    iv.VerifyHash(SKConstant<32>(SK_UNWRAP_IV_CSUM));

    // Get data from masked SK_UNWRAP_DATA
    SKConstant<SK_UNWRAP_DATA_SIZE> data(SK_UNWRAP_DATA);
    data.Unmask(SKConstant<SK_UNWRAP_DATA_SIZE>(SK_UNWRAP_DATA_MASK));
    data.VerifyHash(SKConstant<32>(SK_UNWRAP_DATA_CSUM));

    // Wrap key
    SKDynamicBinaryBuffer key_wrapped(max_blob_size);
    SKDynamicBinaryBuffer tag(tag_size);

    spcrypto->AES128GCMEncrypt(key_id, iv.GetBuffer(), data.GetBuffer(), key_padded, key_wrapped, tag);
    key_wrapped += tag;

    // Set key blob
    key_blob = key_wrapped;
}

// Add padding
void SKTTestCrypto::AddPadding(SKBinaryBuffer& buff) {

    // Get padding size
    const uint32_t padding_size = BLOCK_SIZE - (buff.GetSize() % BLOCK_SIZE);

    // Check capacity
    const uint32_t padded_size = buff.GetSize() + padding_size;
    SK_CHECK(buff.GetCapacity() >= padded_size, SK_ERROR_BUFFER_OVERFLOW, "Invalid padding");

    // Add padding
    memset(buff.GetBuffer() + buff.GetSize(), (uint8_t) padding_size, padding_size);
    buff.UpdateSize(padded_size);
}

// Remove padding
void SKTTestCrypto::RemovePadding(SKBinaryBuffer& buff) {

    // Check size
    const uint32_t padded_size = buff.GetSize();
    SK_CHECK(padded_size >= BLOCK_SIZE && !(padded_size % BLOCK_SIZE), SK_ERROR_TX_PADD, "Invalid padding");

    // Get padding size
    const uint32_t padding_size = buff.GetBuffer()[padded_size - 1];
    SK_CHECK(padding_size && padding_size <= BLOCK_SIZE, SK_ERROR_TX_PADD, "Invalid padding");

    // Update size
    buff.UpdateSize(buff.GetSize() - padding_size);
}

// Add field size to buffer
void SKTTestCrypto::AddFieldSize(const uint32_t size, SKBinaryBuffer& buff, uint32_t& offset) {

    // Check size
    SK_CHECK(size <= 1024, SK_ERROR_INVALID_PARAMETER, "Invalid message");

    // Get field size
    const uint16_t field_size = (uint16_t) size;

    // Get field size buffer
    SKBinaryBufferView field_size_net(offset, sizeof(uint16_t), buff);

    // Set field size
    uint8_t* const p = field_size_net.GetBuffer();
    p[0] = (uint8_t) (field_size >> 8);
    p[1] = (uint8_t) field_size;

    // Update offset
    offset += sizeof(uint16_t);
}

// ----------------------------------------------------------------------------------------------
// SKTKeyPair class implementation

// Parse PKCS#8 encoded private key
void SKTECDSAKeyPair::ParsePKCS8PrivateKey(const SKBinaryBuffer& pkey) {

    // Parse PKCS#8 encoded private key blob using mbedtls
    SKTPKContext ctx;
    int result = mbedtls_pk_parse_key(ctx.GetContext(), pkey.GetBuffer(), pkey.GetSize(), NULL, 0, ecdsa_prng, m_sprandom.get());
    SK_CHECK(result == 0, SK_ERROR_FAILED, "mbedtls_pk_parse_key failed");

    // Set context
    const mbedtls_ecp_keypair* pctx = mbedtls_pk_ec(*ctx.GetContext());
    result = mbedtls_ecdsa_from_keypair(&m_ctx, pctx);
    SK_CHECK(result == 0, SK_ERROR_FAILED, "mbedtls_ecdsa_from_keypair failed");
}

// Generate key pair
void SKTECDSAKeyPair::GenerateKeyPair() {

    // Generate ECDSA key pair
    int result = mbedtls_ecdsa_genkey(&m_ctx, MBEDTLS_ECP_DP_SECP256R1, ecdsa_prng, m_sprandom.get());
    SK_CHECK(result == 0, SK_ERROR_FAILED, "mbedtls_ecdsa_genkey failed");
}

// Verify unwrapped key
void SKTECDSAKeyPair::VerifyUnwrappedKey(const SKCrypto::SKKeyId key_id) {

    // Generate 1024 bytes random data
    SKDynamicBinaryBuffer data;
    SKTTest::GenerateRandomData(1024, data);

    // Sign data
    SKDynamicBinaryBuffer signature;
    Sign(data, signature);

    // Verify signature
    m_spcrypto->ECDSAP256Verify(key_id, data, signature);
}

// Sign data
void SKTECDSAKeyPair::Sign(const SKBinaryBuffer& data, SKBinaryBuffer& signature) {

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SKCryptoMbedTLS::SHA256_HASH_SIZE> hash;
    hash.SetSize(SKCryptoMbedTLS::SHA256_HASH_SIZE);
    mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);

    // Sign hash
    SignHash(hash, signature);
}

// Sign data
void SKTECDSAKeyPair::SignHash(const SKBinaryBuffer& hash, SKBinaryBuffer& signature) {

    // Check hash size
    SK_CHECK(hash.GetSize() == SKCryptoMbedTLS::SHA256_HASH_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid hash size");

    // Sign data
    size_t signatureSize = 0;
    signature.SetSize(MBEDTLS_ECDSA_MAX_LEN);
    int result = mbedtls_ecdsa_write_signature(
        &m_ctx, 
        MBEDTLS_MD_SHA256, 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize(),
        &signatureSize, 
        ecdsa_prng, m_sprandom.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_write_signature failed: %d", result);

    // Set signature size
    signature.UpdateSize(signatureSize);
}

// Verify signature
void SKTECDSAKeyPair::Verify(const SKBinaryBuffer& data, const SKBinaryBuffer& signature) {

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SKCryptoMbedTLS::SHA256_HASH_SIZE> hash;
    hash.SetSize(SKCryptoMbedTLS::SHA256_HASH_SIZE);
    mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);

    // Verify hash signature
    VerifyHash(hash, signature);
}

// Verify hash signature
void SKTECDSAKeyPair::VerifyHash(const SKBinaryBuffer& hash, const SKBinaryBuffer& signature) {

    // Check hash size
    SK_CHECK(hash.GetSize() == SKCryptoMbedTLS::SHA256_HASH_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid hash size");

    // Verify signature
    int result = mbedtls_ecdsa_read_signature(
        &m_ctx, 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_read_signature failed: %d", result);
}

// Wrap key pair
void SKTECDSAKeyPair::WrapECDSAKeyPair(const SKCrypto::SKKeyId key_id, SKBinaryBuffer& wrapped_key) {

    // Get 32 bytes private key
    SKDynamicBinaryBuffer privateKey(SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH);
    privateKey.SetSize(SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH);
    int result = mbedtls_mpi_write_binary(&(m_ctx.MBEDTLS_PRIVATE(d)), privateKey.GetBuffer(), SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_mpi_write_binary failed: %d", result);

    // Get 65 bytes public key 0x04 + 32 bytes x + 32 bytes y
    size_t olen = 0;
    SKDynamicBinaryBuffer publicKey(SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    publicKey.SetSize(SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    result = mbedtls_ecp_point_write_binary(
        &(m_ctx.MBEDTLS_PRIVATE(grp)), 
        &(m_ctx.MBEDTLS_PRIVATE(Q)),
        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, 
        publicKey.GetBuffer(), SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_write_binary failed: %d", result);

    // Create key blob
    SKDynamicBinaryBuffer keyBlob(SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH + SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    keyBlob += privateKey;
    keyBlob += publicKey;

    // Wrap key
    SKTTestCrypto::WrapKeyStatic(m_spcrypto, key_id, keyBlob, wrapped_key);
}

// ----------------------------------------------------------------------------------------------
// SKTContext class implementation

// Initialize
void SKTContext::Initialize(const std::string& store_pathname) {

    // Delete secure store using stl
    std::remove(store_pathname.c_str());

    // Instantiate secure store
    m_spstore = SKSecureStore::Create();

    // Create secure store
    m_spstore->Create(store_pathname.c_str());

    // Close secure store
    m_spstore->Close();

    // Open secure store
    m_spstore->Open(store_pathname.c_str());

    // Instantiate random number generator
    m_sprandom = SKRandom::Create(m_spstore);

    // Instantiate application key store factory parameters
    SKApplicationKeyStoreSimFactoryParameters params(m_spstore, m_sprandom);

    // Generate random byte string of length 32
    SKStaticBinaryBuffer<32> buffer;
    buffer.SetSize(32);
    generate_random_bytes(buffer.GetBuffer(), buffer.GetSize());

    // Update seed
    m_sprandom->UpdateSeed(buffer);

    // Instantiate application key store
    m_spappkeystore = SKApplicationKeyStore::Create(params);

    // Generate symmetric key
    m_spappkeystore->GenerateSymmetricKey(SK_APP_KEY_SYM);

    // Intantiate crypto instance
    m_spcrypto = SKCrypto::Create(SKCryptoMbedTLSParams(m_sprandom, m_spstore, m_spappkeystore));

    // Set store pathname
    m_store_pathname = store_pathname;
}

// Clear
void SKTContext::Clear() {

    // Delete loaded keys
    if (m_keyid_sc) {
        m_spcrypto->DeleteKey(m_keyid_sc);
    } 
    if (m_keypair_backend_id) {
        m_spcrypto->DeleteKey(m_keypair_backend_id);
    } 
    if (m_keypair_client_id) {
        m_spcrypto->DeleteKey(m_keypair_client_id);
    } 
    if (m_persistence_key_id) {
        m_spcrypto->DeleteKey(m_persistence_key_id);
    } 
    if (m_tx_key_id) {
        m_spcrypto->DeleteKey(m_tx_key_id);
    }
    if (m_tx_sig_key_id) {
        m_spcrypto->DeleteKey(m_tx_sig_key_id);
    }

    // Clear crypto instance
    m_spcrypto.reset();

    // Clear application key store
    m_spappkeystore.reset();

    // Clear random number generator
    m_sprandom.reset();

    // Clear secure store
    m_spstore.reset();

    // Remove secure store using stl
    if (!m_store_pathname.empty()) {

        std::remove(m_store_pathname.c_str());
        m_store_pathname.clear();
    }
}

// Process establish shared key message
void SKTContext::ProcessEstablishSharedKey(const SKBinaryBuffer& msg_in, SKBinaryBuffer& public_key) {

    // Process message
    SKBinaryBufferView client_params(0, msg_in.GetSize(), msg_in);
    SKTTestCrypto::RemovePadding(client_params);
    m_spcrypto->ECDHServerPublicKey(client_params, public_key);
    SKTTestCrypto::AddPadding(public_key);
    
    // Compute shared secret    
    m_spcrypto->ECDHComputeSharedKey(m_keyid_sc);
}

// Get server ECDH parameters message
void SKTContext::GetServerECDHParamsMsg(SKBinaryBuffer& msg_out) {

    // msg_out contains server's public key
    static const uint32_t cipher_size = SKSession::NONCE_SIZE + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    const uint32_t public_key_size = msg_out.GetSize();
    const uint32_t msg_size = public_key_size + cipher_size;

    // Generate nonce
    SKStaticBinaryBuffer<cipher_size> plain;
    SKBinaryBufferView nonce(0, SKSession::NONCE_SIZE, plain);
    SKTTest::GenerateRandomData(SKSession::NONCE_SIZE, nonce);
    m_nonce = nonce;

    // Get backend key pair
    m_spkeypair_backend = SKTKeyPair::Create_SK_BACKEND(m_sprandom, m_spcrypto);

    // Compute data hash
    SKBinaryBufferView public_key(0, public_key_size, msg_out);
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> data_hash;
    SKManagedSHA256Context hash_ctx;
    hash_ctx.Start();
    hash_ctx.Update(public_key);
    hash_ctx.Update(nonce);
    hash_ctx.Finish(data_hash);

    // Sign data
    SKBinaryBufferView signature(SKSession::NONCE_SIZE, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plain);   
    m_spkeypair_backend->SignHash(data_hash, signature);
    m_spkeypair_backend->VerifySignatureHash(signature, data_hash);
    SKTTestCrypto::AddPadding(signature);

    // Encrypt data
    plain.UpdateSize(cipher_size);
    SKBinaryBufferView cipher(public_key_size, cipher_size, msg_out);
    {
        SKConstant<SK_PROV_SHARED_IV_SIZE> iv_const(SK_PROV_SHARED_IV);
        iv_const.Unmask(SKConstant<SK_PROV_SHARED_IV_SIZE>(SK_PROV_SHARED_IV_MASK));
        iv_const.VerifyHash(SKConstant<32>(SK_PROV_SHARED_IV_CSUM));
        m_spcrypto->AES128CBCEncrypt(m_keyid_sc, iv_const.GetBuffer(), plain, cipher);
    }

    msg_out.UpdateSize(msg_size);
}

// Process provisioning request message
void SKTContext::ProcessProvisioningRequestMsg(const SKBinaryBuffer& msg_in) {

    static const int msg_size = SKSession::NONCE_SIZE + SKManagedSHA256Context::DIGEST_SIZE;
    SK_CHECK(msg_in.GetSize() == msg_size, SK_ERROR_INVALID_PARAMETER, "Invalid message size");

    // Decrypt token
    SKStaticBinaryBuffer<SKSessionProvision::MAX_PROVISIONING_PARAMS_SIZE> plain;
    {
        SKConstant<SK_PROV_SHARED_IV_SIZE> iv_const(SK_PROV_SHARED_IV);
        iv_const.Unmask(SKConstant<SK_PROV_SHARED_IV_SIZE>(SK_PROV_SHARED_IV_MASK));
        iv_const.VerifyHash(SKConstant<32>(SK_PROV_SHARED_IV_CSUM));
        m_spcrypto->AES128CBCDecrypt(m_keyid_sc, iv_const.GetBuffer(), msg_in, plain);
        plain ^= m_nonce;
    }

    // Extract token
    SKBinaryBufferView token(0, SKSessionProvision::PROVISIONING_TOKEN_SIZE, plain);

    // Extract hash
    SKBinaryBufferView token_hash(SKSessionProvision::PROVISIONING_TOKEN_SIZE, SKManagedSHA256Context::DIGEST_SIZE, plain);

    // Compute hash
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> hash;
    SKManagedSHA256Context::BlockSHA256(token, hash);

    // Verify hash
    SK_CHECK(hash == token_hash, SK_ERROR_INVALID_PARAMETER, "Invalid token hash");

    // Compute IV
    ComputeIV(token);
}

// Get provisioning parameters message
void SKTContext::GetProvisioningParametersMsg(SKBinaryBuffer& msg_out) {

    // Plain data buffer
    SKStaticBinaryBuffer<SKSessionProvision::MAX_PROVISIONING_PARAMS_SIZE> plain;

    // Generate persistence key
    m_sppersistence_key = SKTSymKey::Create(m_sprandom, m_spcrypto);

    // Generate tx encryption key
    m_sptx_key = SKTSymKey::Create(m_sprandom, m_spcrypto);

    // Generate tx signature key
    m_sptx_sig_key = SKTECDSAKeyPair::Create(m_sprandom, m_spcrypto);

    // Generate IUID
    SKBinaryBufferView iuid(0, SKSessionProvision::IUID_SIZE, plain);
    SKTTest::GenerateRandomData(SKSessionProvision::IUID_SIZE, iuid);
    m_iuid = iuid;

    plain.UpdateSize(SKSessionProvision::IUID_SIZE);

    // Add persistence key blob
    SKStaticBinaryBuffer<MAX_KEY_BLOB_SIZE> key_blob;
    m_sppersistence_key->WrapKey(m_keyid_sc, key_blob);
    AddBlob(key_blob, plain);

    // Add client ECDSA key pair
    m_spkeypair_client->WrapECDSAKeyPair(m_keyid_sc, key_blob);
    AddBlob(key_blob, plain);

    // Add client certificate
    AddBlob(m_spkeypair_client->GetCertificate(), plain);

    // Add tx encryption key blob
    m_sptx_key->WrapKey(m_keyid_sc, key_blob);
    AddBlob(key_blob, plain);

    // Add tx signature key blob
    m_sptx_sig_key->WrapECDSAKeyPair(m_keyid_sc, key_blob);
    AddBlob(key_blob, plain);

    // Add padding
    SKTTestCrypto::AddPadding(plain);

    // Add signature
    SKBinaryBufferView signature(plain.GetSize(), SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plain);
    m_spkeypair_backend->Sign(plain, signature);
    SKTTestCrypto::AddPadding(signature);
    plain.UpdateSize(plain.GetSize() + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE);

    // Encrypt data
    plain ^= m_nonce;
    msg_out = SKDynamicBinaryBuffer(plain.GetSize());
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, m_iv, plain, msg_out);
}

// Provision
void SKTContext::Provision(const SKSessionPtr& spsession, const SKTKeyPairPtr& spkeypair) {

    // Get provisioning session
    SKSessionProvision& session = dynamic_cast<SKSessionProvision&>(*spsession);

    // Store instance
    m_spkeypair_client = spkeypair;

    // Create a provisioning token
    SKStaticBinaryBuffer<SKSessionProvision::PROVISIONING_TOKEN_SIZE> token;
    m_sprandom->Generate(token.GetCapacity(), token);

    // Start provisioning
    SKDynamicBinaryBuffer msg_out;
    SKDynamicBinaryBuffer msg_in;
    session.Provision(token, msg_in);

    // Process server response
    ProcessEstablishSharedKey(msg_in, msg_out);
    GetServerECDHParamsMsg(msg_out);

    // Process provisioning requests
    session.ProcessMsg(msg_out, msg_in);

    // Get provisioning parameters
    ProcessProvisioningRequestMsg(msg_in);
    GetProvisioningParametersMsg(msg_out);

    // Process provisioning parameters
    session.ProcessMsg(msg_out, msg_in);
}

// Load keys in crypto instance
void SKTContext::LoadKeys() {

    // Generate wrapping/unwrapping key
    SKCrypto::SKKeyId key_id = 0;
    m_spcrypto->AES128GCMGenerateKey(key_id);

    m_spkeypair_backend->WrapAndLoad(key_id, m_keypair_backend_id);
    m_spkeypair_client->WrapAndLoad(key_id, m_keypair_client_id);
    m_sppersistence_key->WrapAndLoad(key_id, m_persistence_key_id);
    m_sptx_key->WrapAndLoad(key_id, m_tx_key_id);
    m_sptx_sig_key->WrapAndLoad(key_id, m_tx_sig_key_id);
}

// Serialize balance node
void SKTContext::SerializeBalanceNode(SKBinaryBuffer& tx_node_blob) {

    // Set buffer size
    tx_node_blob.UpdateSize(SKTransactionNode::TRANSACTION_NODE_SIZE);

    // Set fields
    SKStaticBinaryBuffer<SKTransactionNode::TUID_SIZE> field;   

    m_sprandom->Generate(SKTransactionNode::TUID_SIZE, field);
    m_tx_node.UpdateTUID(field);
    m_sprandom->Generate(SKTransactionNode::TUID_SIZE, field);
    m_tx_node.UpdateCUID(field);
    m_sprandom->Generate(SKTransactionNode::TUID_SIZE, field);
    m_tx_node.UpdateRUID(field);
    m_sprandom->Generate(SKTransactionNode::TUID_SIZE, field);
    m_tx_node.UpdatePUID(field);

    // Serialize node
    SKStaticBinaryBuffer<SKTransactionNode::TRANSACTION_NODE_SIZE> tx_node;
    m_tx_node.Serialize(tx_node);
    SKBinaryBufferView  tx_header(0, SKTransactionNode::HEADER_SIZE, tx_node_blob);
    tx_node.Extract(0, SKTransactionNode::HEADER_SIZE, tx_header);

    // Get IV from masked SK_STORE_TX_IV
    SKConstant<SK_STORE_TX_IV_SIZE> iv_const(SK_STORE_TX_IV);
    iv_const.Unmask(SKConstant<SK_STORE_TX_IV_SIZE>(SK_STORE_TX_IV_MASK));
    iv_const.VerifyHash(SKConstant<32>(SK_STORE_TX_IV_CSUM));

    // Encrypt node
    SKBinaryBufferView plain(SKTransactionNode::HEADER_SIZE, SKTransactionNode::TRANSACTION_NODE_SIZE - SKTransactionNode::HEADER_SIZE, tx_node);
    SKBinaryBufferView cipher(SKTransactionNode::HEADER_SIZE, SKTransactionNode::TRANSACTION_NODE_SIZE - SKTransactionNode::HEADER_SIZE, tx_node_blob);

    m_spcrypto->AES128CBCEncrypt(m_tx_key_id, iv_const.GetBuffer(), plain, cipher);
}

// Establish shared key
void SKTContext::EstablishSharedKey(const SKBinaryBuffer& msg_in, SKBinaryBuffer& public_key) {

    // Check message size
    static const uint32_t min_msg_size = SKSession::BLOCK_SIZE + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SK_CHECK(msg_in.GetSize() >= min_msg_size, SK_ERROR_INVALID_PARAMETER, "Invalid message size");

    // Get parameters
    const uint32_t params_size = msg_in.GetSize() - SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKBinaryBufferView params(0, params_size, msg_in);

    // Verify signature
    SKBinaryBufferView signature(params_size, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, msg_in);
    SKTTestCrypto::RemovePadding(signature);
    m_spkeypair_client->Verify(params, signature);

    // Get ECDH server public key
    SKTTestCrypto::RemovePadding(params);
    m_spcrypto->ECDHServerPublicKey(params, public_key);
    SKTTestCrypto::AddPadding(public_key);
    
    // Compute shared secret    
    m_spcrypto->ECDHComputeSharedKey(m_keyid_sc);
}

// Process balance initialization
void SKTContext::ProcessBalanceInitMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) {

    // Establish shared key and get server public key
    EstablishSharedKey(msg_in, msg_out);

    // Allocate plaintext buffer
    static const uint32_t plaintext_size = SKSession::NONCE_SIZE + SKTransactionNode::TRANSACTION_NODE_SIZE + SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE;
    SKStaticBinaryBuffer<plaintext_size> plaintext;
    plaintext.UpdateSize(plaintext_size);

    // Generate nonce
    SKBinaryBufferView nonce(0, SKSession::NONCE_SIZE, plaintext);
    m_sprandom->Generate(SKSession::NONCE_SIZE, nonce);
    m_nonce = nonce;

    // Generate transaction node
    SKBinaryBufferView node(SKSession::NONCE_SIZE, SKTransactionNode::TRANSACTION_NODE_SIZE, plaintext);
    SerializeBalanceNode(node);

    // Compute data hash
    SKBinaryBufferView data(0, plaintext_size - SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plaintext);    
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> hash;
    SKManagedSHA256Context hash_ctx;
    hash_ctx.Start();
    hash_ctx.Update(msg_out);
    hash_ctx.Update(data);
    hash_ctx.Finish(hash);

    // Sign data hash
    SKBinaryBufferView signature(SKSession::NONCE_SIZE + SKTransactionNode::TRANSACTION_NODE_SIZE, SKSession::MAX_ECDSA_P256_SIGNATURE_SIZE, plaintext);
    m_spkeypair_backend->SignHash(hash, signature);
    SKTTestCrypto::AddPadding(signature);

    // Encrypt plaintext
    const uint32_t public_key_size = msg_out.GetSize();
    msg_out.UpdateSize(public_key_size + plaintext_size);
    SKBinaryBufferView cipher(public_key_size, plaintext_size, msg_out);
    SKBinaryBufferView iv(0, SKSession::BLOCK_SIZE, m_iuid);    
    m_spcrypto->AES128CBCEncrypt(m_keyid_sc, iv, plaintext, cipher);

    // Update m_iv
    ComputeIV();
}

// Initialize balance
void SKTContext::InitializeBalance(SKTContext& client, const uint64_t balance) {

    // Load keys
    LoadKeys();

    // Initialize balance
    SKDynamicBinaryBuffer msg_out(1024);
    SKDynamicBinaryBuffer msg_in(1024);
    
    // Create online session
    SKSessionPtr spsession = client.CreateOnlineSession();
    SKSessionOnline& session = dynamic_cast<SKSessionOnline&>(*spsession);

    // Start balance initalisation
    session.StartOnlineBalanceInitialization(msg_out);

    // Process balance initialization message
    ProcessBalanceInitMsg(msg_out, msg_in);

    // Process server response
    session.ProcessMsg(msg_in, msg_out);
    SK_CHECK(!msg_out.GetCapacity(), SK_ERROR_FAILED, "Invalid session state");
}
