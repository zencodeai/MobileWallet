#pragma once

#include <memory>

#include "sk_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"
#include "sk_crypto.hpp"
#include "sk_crypto_mbedtls.hpp"
#include "sk_x509.hpp"
#include "sk_session_provision.hpp"
#include "sk_session_offline_payor.hpp"
#include "sk_session_offline_payee.hpp"
#include "sk_session_online.hpp"

// Generate a random byte array
void generate_random_bytes(uint8_t* buffer, size_t length);

// Generate a random integer betwen min and max
uint32_t generate_random_int(uint32_t min, uint32_t max);

// Generate a random alphanumeric string object
std::string generate_random_string(size_t length);

// Formatted hexadecimal dump with offset and hex code and ASCII characters
void hexdump(const void* data, size_t size);

// SKTTest class
class SKTTest {

private:

    // Prepeare test environment
    virtual void Prepare() {}

    // Post-test
    virtual void RunTest() {}

    // Test
    virtual void Cleanup() {}

public:

    // Destructor
    ~SKTTest() {Cleanup();}

    // Run test
    virtual int Run();

    // Fill buffer with random bytes
    static void GenerateRandomData(const uint32_t size, SKBinaryBuffer& buffer);

    // Generate integer between min and max
    static uint32_t GenerateRandomInt(uint32_t min, uint32_t max);
};

// SKTestCrypto class
class SKTTestCrypto : public SKTTest {

public:

    // Tag size
    static const size_t TAG_SIZE = 16;

    // IV size
    static const size_t IV_SIZE = 16;

    // Additional data size
    static const size_t AAD_SIZE = 32;

    // SHA256 hash size
    static const size_t SHA256_SIZE = 32;

    // BLOCK size
    static const size_t BLOCK_SIZE = 16;

private:

    // Prepare test environment
    virtual void Prepare();

    // Post-test
    virtual void RunTest() {}

    // Test
    virtual void Cleanup() {}

protected:

    // Secure store pathname
    const std::string pathname = "test.sqlite";

    // Context
    SKSecureStorePtr spstore;
    SKRandomPtr sprandom;
    SKApplicationKeyStorePtr spappkeystore;
    SKCryptoPtr spcrypto;

    // Pad and wrap key blob
    inline void WrapKey(const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& key_plain, SKBinaryBuffer& key_blob) {

        WrapKeyStatic(spcrypto, key_id, key_plain, key_blob);
    }

public:

    // Destructor
    ~SKTTestCrypto() {}

    // Pad and wrap key blob
    static void WrapKeyStatic(const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& key_plain, SKBinaryBuffer& key_blob);

    // Add padding
    static void AddPadding(SKBinaryBuffer& buff);

    // Remove padding
    static void RemovePadding(SKBinaryBuffer& buff);

    // Add field size to buffer
    static void AddFieldSize(const uint32_t size, SKBinaryBuffer& buff, uint32_t& offset);
};

// Instantiation macro
#define SKT_KEY_SYM(NAME) \
static SKTKeyPairPtr Create_##NAME(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto) { \
    SKConstant<NAME##_SIZE> key(NAME); \
    key.Unmask(SKConstant<NAME##_CERT_SIZE>(NAME##_MASK)); \
    key.VerifyHash(SKConstant<32>(NAME##_CSUM)); \
    return SKTSymKey::Create(sprandom, spcrypto, cert.GetBuffer(), key.GetBuffer()); \
}

// SKTSymKey shared pointer type
typedef std::shared_ptr<class SKTSymKey> SKTSymKeyPtr;

// Symmetric key class
class SKTSymKey {

public:

    // Key size
    static const size_t KEY_SIZE = 16;

    // Max wrapped key size
    static const size_t MAX_WRAPPED_KEY_SIZE = 128;

protected:

    // Key
    SKStaticBinaryBuffer<KEY_SIZE> m_key;

    // Random number generator
    SKRandomPtr m_sprandom;

    // Crypto instance
    SKCryptoPtr m_spcrypto;

    // Constructor
    SKTSymKey(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto, const SKBinaryBuffer& key) : 
        m_sprandom(sprandom),
        m_spcrypto(spcrypto),
        m_key(key) {

        if (!m_key.GetSize()) {

            // Generate key
            sprandom->Generate(KEY_SIZE, m_key);
        }
    }

public:

    static SKTSymKeyPtr Create(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto, const SKBinaryBuffer& key = SKDynamicBinaryBuffer()) {

        return SKTSymKeyPtr(new SKTSymKey(sprandom, spcrypto, key));
    }

    // Destructor
    ~SKTSymKey() {}

    // Get key
    const SKBinaryBuffer& GetKey() const {return m_key;}

    // Wrap key
    void WrapKey(const SKCrypto::SKKeyId key_id, SKBinaryBuffer& wrapped_key) {

        // Wrap key
        SKTTestCrypto::WrapKeyStatic(m_spcrypto, key_id, m_key, wrapped_key);
    }

    // Wrap and load
    void WrapAndLoad(const SKCrypto::SKKeyId key_id, SKCrypto::SKKeyId& key_id_new) {

        // Wrap key
        SKStaticBinaryBuffer<MAX_WRAPPED_KEY_SIZE> wrapped_key;
        WrapKey(key_id, wrapped_key);

        // Load key
        m_spcrypto->UnwrapKeyAES128GCM(key_id, wrapped_key, key_id_new);
    }

    // Generate key
    void GenerateKey() {

        // Generate key
        m_sprandom->Generate(KEY_SIZE, m_key);
    }
};

// Instantiation macro
#define SKT_KEY_PAIR(NAME) \
static SKTKeyPairPtr Create_##NAME(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto) { \
    SKConstant<NAME##_CERT_SIZE> cert(NAME##_CERT); \
    cert.Unmask(SKConstant<NAME##_CERT_SIZE>(NAME##_CERT_MASK)); \
    cert.VerifyHash(SKConstant<32>(NAME##_CERT_CSUM)); \
    SKConstant<NAME##_KEY_SIZE> key(NAME##_KEY); \
    key.Unmask(SKConstant<NAME##_KEY_SIZE>(NAME##_KEY_MASK)); \
    key.VerifyHash(SKConstant<32>(NAME##_KEY_CSUM)); \
    return SKTKeyPair::Create(sprandom, spcrypto, cert.GetBuffer(), key.GetBuffer()); \
}

// Managed mbedtls_pk_context context class
class SKTPKContext {

private:

    // Context
    mbedtls_pk_context m_ctx;

public:

    // Constructor
    SKTPKContext() {

        // Initialize context
        mbedtls_pk_init(&m_ctx);
    }

    // Destructor
    ~SKTPKContext() {

        // Free context
        mbedtls_pk_free(&m_ctx);
    }

    // Get context
    mbedtls_pk_context* GetContext() {

        return &m_ctx;
    }
};

// SKTECDSAKeyPair instance shared pointer type
typedef std::shared_ptr<class SKTECDSAKeyPair> SKTECDSAKeyPairPtr;

// ECDSA key pair class
class SKTECDSAKeyPair  {

public:

    // Max wrapped key size
    static const size_t MAX_WRAPPED_KEY_SIZE = 128;

protected:

    // Context
    mbedtls_ecdsa_context m_ctx;

    // Random number generator
    SKRandomPtr m_sprandom;

    // Crypto instance
    SKCryptoPtr m_spcrypto;

    // Parse PKCS#8 encoded private key
    void ParsePKCS8PrivateKey(const SKBinaryBuffer& pkey);

    // Generate key pair
    void GenerateKeyPair();

    // Constructor
    SKTECDSAKeyPair(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto, const SKBinaryBuffer& pkey) : 
        m_sprandom(sprandom),
        m_spcrypto(spcrypto) {

        // Initialize context
        mbedtls_ecdsa_init(&m_ctx);

        if (pkey.GetSize()) {

            // Parse PKCS#8 encoded private key
            ParsePKCS8PrivateKey(pkey);

        } else {

            // Generate key pair
            GenerateKeyPair();
        }
    }

public:

    static SKTECDSAKeyPairPtr Create(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto, const SKBinaryBuffer& pkey = SKDynamicBinaryBuffer()) {

        return SKTECDSAKeyPairPtr(new SKTECDSAKeyPair(sprandom, spcrypto, pkey));
    }

    // Destructor
    ~SKTECDSAKeyPair() {

        // Free context
        mbedtls_ecdsa_free(&m_ctx);
    }

    // Vertify key
    void VerifyUnwrappedKey(const SKCrypto::SKKeyId key_id);

    // Sign data
    void Sign(const SKBinaryBuffer& data, SKBinaryBuffer& signature);

    // Sign data hash
    void SignHash(const SKBinaryBuffer& hash, SKBinaryBuffer& signature);

    // Verify signature
    void Verify(const SKBinaryBuffer& data, const SKBinaryBuffer& signature);

    // Verify signature (hash)
    void VerifyHash(const SKBinaryBuffer& hash, const SKBinaryBuffer& signature);

    // Wrap key pair
    void WrapECDSAKeyPair(const SKCrypto::SKKeyId key_id, SKBinaryBuffer& wrapped_key);

    // Wrap and load
    void WrapAndLoad(const SKCrypto::SKKeyId key_id, SKCrypto::SKKeyId& key_id_new) {

        // Wrap key
        SKStaticBinaryBuffer<MAX_WRAPPED_KEY_SIZE> wrapped_key;
        WrapECDSAKeyPair(key_id, wrapped_key);

        // Load key
        m_spcrypto->UnwrapKeyECDSAP256(key_id, wrapped_key, key_id_new);
    }
};

// SKTKeyPair instance shared pointer type
typedef std::shared_ptr<class SKTKeyPair> SKTKeyPairPtr;

// ECDSA key pair class
class SKTKeyPair: public SKCertChain, public SKTECDSAKeyPair  {

protected:

    // DER encoded certificate
    SKDynamicBinaryBuffer m_cert;

    // Constructor
    SKTKeyPair(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto, const SKBinaryBuffer& cert, const SKBinaryBuffer& pkey) : 
        m_cert(cert),
        SKCertChain(cert),
        SKTECDSAKeyPair(sprandom, spcrypto, pkey) {
    }

public:

    static SKTKeyPairPtr Create(const SKRandomPtr& sprandom, const SKCryptoPtr& spcrypto, const SKBinaryBuffer& cert, const SKBinaryBuffer& pkey) {

        return SKTKeyPairPtr(new SKTKeyPair(sprandom, spcrypto, cert, pkey));
    }

    // Destructor
    ~SKTKeyPair() {}

    // Get certificate
    const SKBinaryBuffer& GetCertificate() const {return m_cert;}

    // Instantiation methods
    SKT_KEY_PAIR(SK_TEST1_X509);
    SKT_KEY_PAIR(SK_TEST2_X509);
    SKT_KEY_PAIR(SK_TEST_X509);
    SKT_KEY_PAIR(SK_BACKEND);
};

// SKTContext class
class SKTContext {

public:

    // Initial balance
    static const uint64_t INITIAL_BALANCE = 1000;

    // Max key blob size
    static const size_t MAX_KEY_BLOB_SIZE = 256;

protected:

    // Context
    std::string m_store_pathname;
    SKSecureStorePtr m_spstore;
    SKRandomPtr m_sprandom;
    SKApplicationKeyStorePtr m_spappkeystore;
    SKCryptoPtr m_spcrypto;

    // Provisioning context
    SKCrypto::SKKeyId m_keyid_sc;
    SKStaticBinaryBuffer<SKSession::NONCE_SIZE> m_nonce;
    SKStaticBinaryBuffer<SKSession::IV_SIZE> m_iv;
    SKStaticBinaryBuffer<SKSession::IUID_SIZE> m_iuid;
    SKTKeyPairPtr m_spkeypair_backend;
    SKTKeyPairPtr m_spkeypair_client;
    SKTSymKeyPtr m_sppersistence_key;
    SKTSymKeyPtr m_sptx_key;
    SKTECDSAKeyPairPtr m_sptx_sig_key;

    // Loaded keys id
    SKCrypto::SKKeyId m_keypair_backend_id;
    SKCrypto::SKKeyId m_keypair_client_id;
    SKCrypto::SKKeyId m_persistence_key_id;
    SKCrypto::SKKeyId m_tx_key_id;
    SKCrypto::SKKeyId m_tx_sig_key_id;

    // Balance record
    SKTransactionNode m_tx_node;

    // Initialize
    void Initialize(const std::string& store_pathname);

    // Clear
    void Clear();

    // Compute IV
    void ComputeIV(const SKBinaryBuffer& data) {

        SKManagedSHA256Context ctx;
        SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> hash;

        ctx.Start();
        ctx.Update(data);
        ctx.Update(m_nonce);
        ctx.Finish(hash);

        uint8_t* p = hash.GetBuffer();
        uint8_t* q = p + hash.GetCapacity() / 2;
        m_iv.SetSize(SKSession::IV_SIZE);
        uint8_t* r = m_iv.GetBuffer();

        for (size_t i = 0; i < SKSession::IV_SIZE; i++) {
            *r++ = *p++ ^ *q++;
        }
    }

    // Add blob
    void AddBlob(const SKBinaryBuffer& blob, SKBinaryBuffer& buff) {

        uint32_t offset = buff.GetSize();
        SK_CHECK((blob.GetSize() + offset + sizeof(uint16_t)) <  buff.GetCapacity(), SK_ERROR_INVALID_PARAMETER, "Invalid blob size");
        SKTTestCrypto::AddFieldSize(blob.GetSize(), buff, offset);
        buff.UpdateSize(offset);
        buff += blob;
    }

    // Process establish shared key message
    void ProcessEstablishSharedKey(const SKBinaryBuffer& msg_in, SKBinaryBuffer& public_key);

    // Get server ECDH parameters message
    void GetServerECDHParamsMsg(SKBinaryBuffer& msg_out);

    // Process provisioning request message
    void ProcessProvisioningRequestMsg(const SKBinaryBuffer& msg_in);

    // Get provisioning parameters message
    void GetProvisioningParametersMsg(SKBinaryBuffer& msg_out);

    // Serialize balance node
    void SerializeBalanceNode(SKBinaryBuffer& tx_node_blob);

    // Establish shared key
    void EstablishSharedKey(const SKBinaryBuffer& params, SKBinaryBuffer& public_key);

    // Process balance initialization
    void ProcessBalanceInitMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

public:

    // Constructor
    SKTContext(const std::string& store_pathname) : 
        m_keyid_sc(0), 
        m_keypair_backend_id(0), 
        m_keypair_client_id(0), 
        m_persistence_key_id(0), 
        m_tx_key_id(0), 
        m_tx_sig_key_id(0),
        m_tx_node(INITIAL_BALANCE)
    {
        Initialize(store_pathname);
    }

    // Destructor
    ~SKTContext() {

        Clear();
    }

    // Compute IV using client IUID and nonce
    void ComputeIV() { ComputeIV(m_iuid); }

    // Get secure store
    SKSecureStorePtr GetSecureStore() {return m_spstore;}

    // Get random
    SKRandomPtr GetRandom() {return m_sprandom;}

    // Get application key store
    SKApplicationKeyStorePtr GetApplicationKeyStore() {return m_spappkeystore;}

    // Get crypto
    SKCryptoPtr GetCrypto() {return m_spcrypto;}

    // Create provisioning session
    SKSessionPtr CreateProvisioningSession() {

        return SKSessionProvision::Create(m_spcrypto, m_spstore, m_sprandom);
    }

    // Create offline payor session
    SKSessionPtr CreateOfflinePayorSession() {

        return SKSessionOfflinePayor::Create(m_spcrypto, m_spstore, m_sprandom);
    }

    // Create offline payee session
    SKSessionPtr CreateOfflinePayeeSession() {

        return SKSessionOfflinePayee::Create(m_spcrypto, m_spstore, m_sprandom);
    }

    // Create online session
    SKSessionPtr CreateOnlineSession() {

        return SKSessionOnline::Create(m_spcrypto, m_spstore, m_sprandom);
    }

    // Provision
    void Provision(const SKSessionPtr& spsession, const SKTKeyPairPtr& spkeypair);

    // Load keys in crypto instance
    void LoadKeys();

    // Initialize balance
    void InitializeBalance(SKTContext& client, const uint64_t balance);
};
