#pragma once

#include <cstdint>
#include <cstdarg>
#include <map>

#include "mbedtls/platform.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdsa.h"

#include "sk_crypto.hpp"
#include "sk_app_key_store.hpp"
#include "sk_random.hpp"
#include "sk_secure_store.hpp"

// SKCryptoMbedTLSParams MBED tls parameters class
class SKCryptoMbedTLSParams : public SKCryptoParams {

private:

    // Random number generator
    SKRandomPtr m_sprng;

    // Secure store
    SKSecureStorePtr m_spsstore;

    // App key store
    SKApplicationKeyStorePtr m_spaks;

public:

    // Constructor
    SKCryptoMbedTLSParams(SKRandomPtr sprng, SKSecureStorePtr spsstore, SKApplicationKeyStorePtr spaks) : m_sprng(sprng), m_spsstore(spsstore), m_spaks(spaks) {}

    // Destructor
    virtual ~SKCryptoMbedTLSParams() {}

    // Get random number generator
    SKRandomPtr GetRandom() const { return m_sprng; }

    // Get secure store
    SKSecureStorePtr GetSecureStore() const { return m_spsstore; }

    // Get app key store
    SKApplicationKeyStorePtr GetAppKeyStore() const { return m_spaks; }
};

// ECDH context shared pointer type
typedef std::shared_ptr<class SKECDHContext> SKECDHContextPtr;

// ECDH key injection context
class SKECDHContext {

private:

    // Max params size
    static const uint32_t MAX_PARAMS_SIZE = 256;

    // ECDH context
    mbedtls_ecdh_context m_ctx;

    // Entropy source
    mbedtls_entropy_context m_entropy;

    // Initialize random number generator
    mbedtls_ctr_drbg_context m_ctr_drbg;


public:

    // Shared secret size
    static const uint32_t SHARED_SECRET_SIZE = 32;

    // Constructor
    SKECDHContext() { 
        
        // Initialize
        mbedtls_ecdh_init(&m_ctx); 
        mbedtls_entropy_init(&m_entropy);
        mbedtls_ctr_drbg_init(&m_ctr_drbg);

        // Initialize ECDH context
        int result = mbedtls_ecdh_setup(&m_ctx, MBEDTLS_ECP_DP_SECP256R1);
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdh_setup failed: %d", result);

        // Seed random number generator
        result = mbedtls_ctr_drbg_seed(&m_ctr_drbg, mbedtls_entropy_func, &m_entropy, NULL, 0);
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ctr_drbg_seed failed: %d", result);
    }

    // Destructor
    ~SKECDHContext() { 
        
        mbedtls_ecdh_free(&m_ctx);
        mbedtls_entropy_free(&m_entropy);
        mbedtls_ctr_drbg_free(&m_ctr_drbg); 
    }

    // Create client side ECDH parameters
    void MakeParams(SKBinaryBuffer& params) {

        // Make ECDH parameters
        params.SetSize(256);
        size_t olen = 0;        
        int result = mbedtls_ecdh_make_params(
            &m_ctx, 
            &olen,
            params.GetBuffer(), params.GetSize(),
            mbedtls_ctr_drbg_random, &m_ctr_drbg
        );
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdh_make_params failed: %d", result);
        params.UpdateSize(olen);
    }

    // Read client side ECDH parameters
    void ReadParams(const SKBinaryBuffer& params, SKBinaryBuffer& public_key) {

        // Set ECDH parameters
        const uint8_t* p = params.GetBuffer();
        const uint8_t* end = p + params.GetSize();
        int result = mbedtls_ecdh_read_params(
            &m_ctx, 
            &p, end
        );
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdh_read_params failed: %d", result);

        // Get public key
        public_key.SetSize(256);
        size_t olen = 0;
        result = mbedtls_ecdh_make_public(
            &m_ctx, 
            &olen,
            public_key.GetBuffer(), public_key.GetSize(),
            mbedtls_ctr_drbg_random, &m_ctr_drbg
        );
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdh_make_public failed: %d", result);
        public_key.UpdateSize(olen);
    }

    // Read server side ECDH public key
    void ReadPublicKey(const SKBinaryBuffer& public_key) {

        // Set ECDH public key
        int result = mbedtls_ecdh_read_public(
            &m_ctx, 
            public_key.GetBuffer(), public_key.GetSize()            
        );
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdh_read_public failed: %d", result);
    }

    // Compute shared secret
    void ComputeSharedSecret(SKBinaryBuffer& secret) {

        // Compute shared secret
        secret.SetSize(SHARED_SECRET_SIZE);
        size_t olen = 0;
        int result = mbedtls_ecdh_calc_secret(
            &m_ctx, 
            &olen,
            secret.GetBuffer(), secret.GetSize(),
            mbedtls_ctr_drbg_random, &m_ctr_drbg
        );
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdh_calc_secret failed: %d", result);
        secret.UpdateSize(olen);
    }
};

// AES GCM managed context
class SKAESGCMContext {

private:

    // AES-128-GCM context
    mbedtls_gcm_context m_ctx;

public:

    // Constructor
    SKAESGCMContext(const SKBinaryBuffer& key) { 
        
        // Initialize AES-128-GCM context
        mbedtls_gcm_init(&m_ctx);

        // Init context
        int result = mbedtls_gcm_setkey(&m_ctx, MBEDTLS_CIPHER_ID_AES, key.GetBuffer(), key.GetSize() * 8);
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_setkey failed: %d", result);
    }

    // Destructor
    ~SKAESGCMContext() { mbedtls_gcm_free(&m_ctx); }

    // Get context pointer
    mbedtls_gcm_context* GetContext() { return &m_ctx; }
};

// AES CBC managed context
class SKAESCBCContext {

public:

    enum Mode {
        ENCRYPT = MBEDTLS_AES_ENCRYPT,
        DECRYPT = MBEDTLS_AES_DECRYPT
    };

private:

    // AES-128-CBC context
    mbedtls_aes_context m_ctx;

public:

    // Constructor
    SKAESCBCContext(const SKBinaryBuffer& key, Mode mode) { 
        
        // Initialize AES-128-GCM context
        mbedtls_aes_init(&m_ctx);

        // Init context
        switch (mode) {
        case ENCRYPT: {
            int result = mbedtls_aes_setkey_enc(&m_ctx, key.GetBuffer(), key.GetSize() * 8);
            SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_aes_setkey_enc failed: %d", result);
            }
            break;
        case DECRYPT: {
            int result = mbedtls_aes_setkey_dec(&m_ctx, key.GetBuffer(), key.GetSize() * 8);
            SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_aes_setkey_dec failed: %d", result);
            }
            break;
        default:
            SK_CHECK(false, SK_ERROR_INVALID_PARAMETER, "Invalid mode: %d", mode);
        }
    }

    // Destructor
    ~SKAESCBCContext() { mbedtls_aes_free(&m_ctx); }

    // Get context pointer
    mbedtls_aes_context* GetContext() { return &m_ctx; }
};


// ECDSA managed context
class SKECDSAContext {

private:

    // Context
    mbedtls_ecdsa_context m_ctx;

public:

    // Constructor
    SKECDSAContext()
    {
        mbedtls_ecdsa_init(&m_ctx);
    }

    // Destructor
    ~SKECDSAContext()
    {
        mbedtls_ecdsa_free(&m_ctx);
    }

    // Get context
    mbedtls_ecdsa_context* GetContext()
    {
        return &m_ctx;
    }
};

// Key data shared pointer type
typedef std::shared_ptr<class SKKeyData> SKKeyDataPtr;

// Key data class
class SKKeyData {

public:

    enum SKKeyType {
        SK_KEY_TYPE_NONE = SK_CST_KEY_TYPE_NONE,
        SK_KEY_TYPE_AES_GCM_128 = SK_CST_KEY_TYPE_AES_GCM_128,
        SK_KEY_TYPE_ECDSA_P256 = SK_CST_KEY_TYPE_ECDSA_P256,
    };

private:

    // Key id
    SKCrypto::SKKeyId m_key_id;

    // Key value
    SKDynamicBinaryBuffer m_key;

    // Key type
    SKKeyType m_key_type;

public:

    // Constructor
    SKKeyData(const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& key, SKKeyType key_type) : m_key_id(key_id), m_key(key), m_key_type(key_type) {}

    // Constructor (key id and type only)
    SKKeyData(const SKCrypto::SKKeyId key_id, const SKKeyType key_type) : m_key_id(key_id), m_key_type(key_type) {}

    // Destructor
    virtual ~SKKeyData() {}

    // Get key id
    SKCrypto::SKKeyId GetKeyId() const { return m_key_id; } 

    // Get key value
    const SKBinaryBuffer& GetKey() const { return m_key; }

    // Get key type
    SKKeyType GetKeyType() const { return m_key_type; }
};

// MBED TLS based SKCrypto implementation
class SKCryptoMbedTLS : public SKCrypto {

public:

    // Tag size
    static const uint32_t TAG_SIZE = 16;

    // AES-128 key size
    static const uint32_t AES128_KEY_SIZE = 16;

    // AES-128 wrapped key size
    static const uint32_t AES128_WRAPPED_KEY_SIZE = 16 + 16 + TAG_SIZE;

    // P-256 key serialized key pair size
    static const uint32_t P256_KEY_BLOB_SIZE = 32 + 1 + 64;

    // AES-128 export blob size
    static const uint32_t AES128_EXPORT_BLOB_SIZE = 4 + 16 + 16 + TAG_SIZE;

    // P-256 export blob size
    static const uint32_t ECDSAP256_EXPORT_BLOB_SIZE = 4 + 32 + 1 + 64 + 15 + TAG_SIZE;

    // Max key size
    static const uint32_t MAX_KEY_SIZE = 256;

    // ECDSA private key length
    static const size_t ECDSA_PRIVATE_KEY_LENGTH = 32;

    // ECDSA public key length
    static const size_t ECDSA_PUBLIC_KEY_LENGTH = 65;

    // ECDSA P-256 wrapped key size
    static const uint32_t ECDSA_WRAPPED_KEY_SIZE = 32 + 1 + 64 + 15 + TAG_SIZE;

    // SHA256 hash size
    static const size_t SHA256_HASH_SIZE = 32;

private:

    // Type map key id to key data 
    typedef std::map<SKCrypto::SKKeyId, SKKeyDataPtr> SKKeyDataMap;

    // Random number generator
    SKRandomPtr m_sprng;

    // Secure store
    SKSecureStorePtr m_spsstore;

    // App key store
    SKApplicationKeyStorePtr m_spaks;

    // ECDH context
    SKECDHContextPtr m_specdh;

    // AES-128-GCM context
    mbedtls_gcm_context m_aes128gcm_ctx;

    // Key data map
    SKKeyDataMap m_keys;

    // Initialize context
    void InitContext();

    // Decrypt key using context
    void DecrypKey(const SKKeyData& key_data, SKBinaryBuffer& plain);

    // Encrypt key using context
    void EncryptKey(const SKBinaryBuffer& plain, SKKeyData& key_data);

    // Generate random bytes sequence (non-crypto)
    void GenerateByteString(const uint32_t size, uint8_t* buffer);

    // Generate UINT32 random number
    uint32_t GenerateRandomInt(const uint32_t min, const uint32_t max);

    // Add key to key data map
    SKKeyId AddKey(const SKBinaryBuffer& key, const SKKeyData::SKKeyType key_type);

    // Encrypt and Add key to key data map
    SKKeyId EncryptoAndAddKey(const SKBinaryBuffer& key, const SKKeyData::SKKeyType key_type);

    // Get key data from key id
    SKKeyData& GetKeyData(const SKKeyId key_id);

    // Get decrypted key from key id
    void GetDecryptedKey(const SKKeyId key_id, SKBinaryBuffer& key);

    // Remove padding from buffer
    void RemovePadding(SKBinaryBuffer& buff);

    // Unwrap key blob of type key_type using wrapping key key_id and add key to the key data map
    SKKeyId UnwrapKey(const SKKeyId key_id, const SKBinaryBuffer& key_blob, const SKKeyData::SKKeyType key_type);

    // Load ECDSA key pair from key map
    void LoadECDSAP256KeyPair(const SKKeyId key_id, SKECDSAContext& ctx);

    // Delete key from key data map
    void RemoveKey(const SKKeyId key_id);

    // INT32 to byte string
    void Int32ToByteString(const uint32_t value, uint8_t* const buffer) {
        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = value & 0xFF;
    }

    // Byte string to INT32
    uint32_t ByteStringToInt32(const uint8_t* const buffer) {
        return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    }
    
public:

    // Constructor
    SKCryptoMbedTLS(const SKCryptoMbedTLSParams& params) : m_sprng(params.GetRandom()), m_spsstore(params.GetSecureStore()), m_spaks(params.GetAppKeyStore()) {
            
        // Initialize AES-128-GCM context
        mbedtls_gcm_init(&m_aes128gcm_ctx);

        // Init context
        InitContext();
    }

    // Destructor
    ~SKCryptoMbedTLS() {

        // Free AES-128-GCM context
        mbedtls_gcm_free(&m_aes128gcm_ctx);
    }

    // ECDH 1: Get client params (client)
    void ECDHGetClientParams(SKBinaryBuffer& params);

    // ECDH 2: Get server public key (server)
    void ECDHServerPublicKey(const SKBinaryBuffer& params, SKBinaryBuffer& public_key);

    // ECDH 3: Set public key (client)
    void ECDHSetPublicKey(const SKBinaryBuffer& public_key);

    // ECDH 4: Compute shared key
    void ECDHComputeSharedKey(SKKeyId& key_id);

    // Generate AES-128 key
    void AES128GCMGenerateKey(SKKeyId& key_id);

    // AES-128-GCM encrypt
    void AES128GCMEncrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& data, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher, SKBinaryBuffer& tag);

    // AES-128-GCM decrypt
    void AES128GCMDecrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& data, const SKBinaryBuffer& cipher, const SKBinaryBuffer& tag, SKBinaryBuffer& plain);

    // AES-128-CBC encrypt
    void AES128CBCEncrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher);

    // AES-128-CBC decrypt
    void AES128CBCDecrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& cipher, SKBinaryBuffer& plain);

    // Export key
    void ExportKey(const SKKeyId key_id, SKBinaryBuffer& key);

    // Import key
    void ImportKey(const SKBinaryBuffer& key, SKKeyId& key_id);

    // Unwrap key AES-128-GCM
    void UnwrapKeyAES128GCM(const SKKeyId key_id, const SKBinaryBuffer& key_blob, SKKeyId& key_id_new);

    // Generate ECDSA P-256 key pair
    void ECDSAP256GenerateKeyPair(SKKeyId& key_id);

    // Sign data using ECDSA P-256 key
    void ECDSAP256Sign(const SKKeyId key_id, const SKBinaryBuffer& data, SKBinaryBuffer& signature);

    // Verify data using ECDSA P-256 key
    void ECDSAP256Verify(const SKKeyId key_id, const SKBinaryBuffer& data, const SKBinaryBuffer& signature);

    // ECDSA P-256 digest sign
    void ECDSAP256DigestSign(const SKKeyId key_id, const SKBinaryBuffer& dignest, SKBinaryBuffer& signature);

    // ECDSA P-256 dignest verify
    void ECDSAP256DigestVerify(const SKKeyId key_id, const SKBinaryBuffer& digest, const SKBinaryBuffer& signature);


    // Unwrap key ECDSA P-256
    void UnwrapKeyECDSAP256(const SKKeyId key_id, const SKBinaryBuffer& key_blob, SKKeyId& key_id_new);

    // Delete key
    void DeleteKey(const SKKeyId key_id);
};
