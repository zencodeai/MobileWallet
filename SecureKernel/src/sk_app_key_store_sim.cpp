#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "sk_app_key_store_sim.hpp"

#ifdef SKT_DEBUG
#define SK_MBEDTLS_ERROR(CODE) \
    do { \
        char _error[256]; \
        mbedtls_strerror(CODE, _error, sizeof(_error)); \
        printf("Error: %s\n", _error); \
        std::cout << "Error: " << &_error[0] << std::endl; \
    } while (0) 
#else
#define SK_MBEDTLS_ERROR(CODE) do { } while (0)
#endif

// Class factory (return smart pointer)
SKApplicationKeyStorePtr SKApplicationKeyStore::Create(const SKFactoryParameters& params)
{
    // Cast parameters
    const SKApplicationKeyStoreSimFactoryParameters& appParams = dynamic_cast<const SKApplicationKeyStoreSimFactoryParameters&>(params);

    // Create application key store
    return SKApplicationKeyStorePtr(new SKApplicationKeyStoreSim(appParams));
}

// Static IV
const unsigned char SKApplicationKeyStoreSim::AES_GCM_IV[] = SK_APPKEYS_SYM_IV;

// Static salt
const unsigned char SKApplicationKeyStoreSim::AES_GCM_SALT[] = SK_APPKEYS_SYM_SALT;

// Managed mbedtls_gcm_context
class SKApplicationKeyStoreSim::ManagedMbedtlsGcmContext
{   
private:

    // Context
    mbedtls_gcm_context m_ctx;

public:

    // Constructor
    ManagedMbedtlsGcmContext()
    {
        mbedtls_gcm_init(&m_ctx);
    }

    // Destructor
    ~ManagedMbedtlsGcmContext()
    {
        mbedtls_gcm_free(&m_ctx);
    }

    // Get context
    mbedtls_gcm_context* GetContext()
    {
        return &m_ctx;
    }
};

// Managed ecdsa context
class SKApplicationKeyStoreSim::ManagedMbedtlsEcdsaContext
{  
private:

    // Context
    mbedtls_ecdsa_context m_ctx;

public:

    // Constructor
    ManagedMbedtlsEcdsaContext()
    {
        mbedtls_ecdsa_init(&m_ctx);
    }

    // Destructor
    ~ManagedMbedtlsEcdsaContext()
    {
        mbedtls_ecdsa_free(&m_ctx);
    }

    // Get context
    mbedtls_ecdsa_context* GetContext()
    {
        return &m_ctx;
    }
};

// Generate ECDSA key pair
void SKApplicationKeyStoreSim::GenerateEcdsaKeyPair(const char* key, ManagedMbedtlsEcdsaContext& ctx) {

    // Begin transaction
    m_secureStore->BeginTransaction();

    // Delete key if exists
    if (m_secureStore->HasKey(key))
    {
        m_secureStore->DeleteKey(key);
    }

    // Generate key pair
    int result = mbedtls_ecdsa_genkey(ctx.GetContext(), MBEDTLS_ECP_DP_SECP256R1, ecdsa_prng, m_random.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_genkey failed: %d", result);

    // Get 32 bytes private key
    SKDynamicBinaryBuffer privateKey(ECDSA_PRIVATE_KEY_LENGTH);
    privateKey.SetSize(ECDSA_PRIVATE_KEY_LENGTH);
    result = mbedtls_mpi_write_binary(&ctx.GetContext()->MBEDTLS_PRIVATE(d), privateKey.GetBuffer(), ECDSA_PRIVATE_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_mpi_write_binary failed: %d", result);

    // Get 65 bytes public key 0x04 + 32 bytes x + 32 bytes y
    size_t olen = 0;
    SKDynamicBinaryBuffer publicKey(ECDSA_PUBLIC_KEY_LENGTH);
    publicKey.SetSize(ECDSA_PUBLIC_KEY_LENGTH);
    result = mbedtls_ecp_point_write_binary(
        &ctx.GetContext()->MBEDTLS_PRIVATE(grp), 
        &ctx.GetContext()->MBEDTLS_PRIVATE(Q), 
        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, 
        publicKey.GetBuffer(), ECDSA_PUBLIC_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_write_binary failed: %d", result);

    // Create key blob
    SKDynamicBinaryBuffer keyBlob(ECDSA_PRIVATE_KEY_LENGTH + ECDSA_PUBLIC_KEY_LENGTH);
    keyBlob += privateKey;
    keyBlob += publicKey;
    
    // Store key blob
    m_secureStore->SetKey(key, keyBlob);

    // Commit transaction
    m_secureStore->CommitTransaction();
} 

// Load ECDSA key pair from store
void SKApplicationKeyStoreSim::LoadEcdsaKeyPair(const char* key, ManagedMbedtlsEcdsaContext& ctx) {

    // Load key blob
    SKDynamicBinaryBuffer keyBlob;
    m_secureStore->GetKey(key, keyBlob);

    // Get private key
    SKDynamicBinaryBuffer privateKey(ECDSA_PRIVATE_KEY_LENGTH);
    keyBlob.Extract(0, ECDSA_PRIVATE_KEY_LENGTH, privateKey);

    // Get public key
    SKDynamicBinaryBuffer publicKey(ECDSA_PUBLIC_KEY_LENGTH);
    keyBlob.Extract(ECDSA_PRIVATE_KEY_LENGTH, ECDSA_PUBLIC_KEY_LENGTH, publicKey);

    // Set group
    int result = mbedtls_ecp_group_load(&ctx.GetContext()->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_group_load failed: %d", result);

    // Set private key
    result = mbedtls_mpi_read_binary(&ctx.GetContext()->MBEDTLS_PRIVATE(d), privateKey.GetBuffer(), ECDSA_PRIVATE_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_mpi_read_binary failed: %d", result);

    // Set public key (skip 0x04)
    result = mbedtls_ecp_point_read_binary(
        &ctx.GetContext()->MBEDTLS_PRIVATE(grp), 
        &ctx.GetContext()->MBEDTLS_PRIVATE(Q), 
        publicKey.GetBuffer(), ECDSA_PUBLIC_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_read_binary failed: %d", result);

    // Check public key
    result = mbedtls_ecp_check_pubkey(&ctx.GetContext()->MBEDTLS_PRIVATE(grp), &ctx.GetContext()->MBEDTLS_PRIVATE(Q));
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_check_pubkey failed: %d", result);
}

// Constructor
SKApplicationKeyStoreSim::SKApplicationKeyStoreSim(const SKApplicationKeyStoreSimFactoryParameters& params) :
    m_secureStore(params.GetSecureStore()),
    m_random(params.GetRandom())
{
}

// Destructor
SKApplicationKeyStoreSim::~SKApplicationKeyStoreSim()
{
}

// Generate symmetric key
void SKApplicationKeyStoreSim::GenerateSymmetricKey(const char* key)
{
    // Begin transaction
    m_secureStore->BeginTransaction();

    // Delete key if exists
    if (m_secureStore->HasKey(key))
    {
        m_secureStore->DeleteKey(key);
    }

    // Generate key
    SKStaticBinaryBuffer<SYMMETRIC_KEY_LENGTH> buffer;
    m_random->Generate(buffer.GetCapacity(), buffer);

    // Set key
    m_secureStore->SetKey(key, buffer);

    // Commit transaction
    m_secureStore->CommitTransaction();
}

// AES-GCM data encryption using Mbed TLS
void SKApplicationKeyStoreSim::Encrypt(const char* key, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher) {

    // Init context
    ManagedMbedtlsGcmContext ctx;

    // Ckeck plain size
    const uint32_t plainSize = plain.GetSize(); 
    SK_CHECK(plainSize && !(plainSize % 16) && plainSize <= MAX_PLAIN_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid plain size");

    // Set cipher size
    cipher.SetSize(plain.GetSize() + AES_GCM_TAG_LENGTH);

    // Get key
    SKStaticBinaryBuffer<SYMMETRIC_KEY_LENGTH> buffer;
    m_secureStore->GetKey(key, buffer);

    int result = mbedtls_gcm_setkey(ctx.GetContext(), MBEDTLS_CIPHER_ID_AES, buffer.GetBuffer(), buffer.GetSize() * 8);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_setkey failed: %d", result);

    result = mbedtls_gcm_crypt_and_tag(
        ctx.GetContext(), 
        MBEDTLS_GCM_ENCRYPT, 
        plain.GetSize(), 
        AES_GCM_IV, sizeof(AES_GCM_IV), 
        AES_GCM_SALT, sizeof(AES_GCM_SALT), 
        plain.GetBuffer(), cipher.GetBuffer(), 
        AES_GCM_TAG_LENGTH, cipher.GetBuffer() + plainSize);
    SK_MBEDTLS_ERROR(result);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_crypt_and_tag failed: %d", result);
}

// AES-GCM data decryption using Mbed TLS
void SKApplicationKeyStoreSim::Decrypt(const char* key, const SKBinaryBuffer& cipher, SKBinaryBuffer& plain) {

    // Init context
    ManagedMbedtlsGcmContext ctx;

    // Ckeck cipher size
    const uint32_t cipherSize = cipher.GetSize();
    const uint32_t cipherDataSize = cipherSize - AES_GCM_TAG_LENGTH;
    SK_CHECK(cipherSize && !(cipherSize % 16) && cipherSize > AES_GCM_TAG_LENGTH, SK_ERROR_INVALID_PARAMETER, "Invalid cipher size");

    // Set plain size
    plain.SetSize(cipher.GetSize() - 16);

    // Get key
    SKStaticBinaryBuffer<SYMMETRIC_KEY_LENGTH> buffer;
    m_secureStore->GetKey(key, buffer);

    int result = mbedtls_gcm_setkey(ctx.GetContext(), MBEDTLS_CIPHER_ID_AES, buffer.GetBuffer(), buffer.GetSize() * 8);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_setkey failed: %d", result);

    result = mbedtls_gcm_auth_decrypt(
        ctx.GetContext(), 
        cipherDataSize, 
        AES_GCM_IV, sizeof(AES_GCM_IV), 
        AES_GCM_SALT, sizeof(AES_GCM_SALT), 
        cipher.GetBuffer() + cipherDataSize, AES_GCM_TAG_LENGTH, 
        cipher.GetBuffer(), plain.GetBuffer());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_auth_decrypt failed: %d", result);
}

// Generate asymmetric key pair
void SKApplicationKeyStoreSim::GenerateAsymmetricKeyPair(const char* key) {

    // Init context
    ManagedMbedtlsEcdsaContext ctx;

    // Generate key pair
    GenerateEcdsaKeyPair(key, ctx);
}

// Sign data using ECDSA
void SKApplicationKeyStoreSim::Sign(const char* key, const SKBinaryBuffer& data, SKBinaryBuffer& signature) {

    // Init context
    ManagedMbedtlsEcdsaContext ctx;

    // Load key pair
    LoadEcdsaKeyPair(key, ctx);

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SHA256_DIGEST_LENGTH> hash;
    hash.SetSize(SHA256_DIGEST_LENGTH);
    mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);

    // Sign data
    size_t signatureSize = 0;
    signature.SetSize(MBEDTLS_ECDSA_MAX_LEN);
    int result = mbedtls_ecdsa_write_signature(
        ctx.GetContext(), 
        MBEDTLS_MD_SHA256, 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize(),
        &signatureSize, 
        ecdsa_prng, m_random.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_write_signature failed: %d", result);

    // Set signature size
    signature.UpdateSize(signatureSize);
}

// Verify data signature using ECDSA
void SKApplicationKeyStoreSim::Verify(const char* key, const SKBinaryBuffer& data, const SKBinaryBuffer& signature) {

    // Init context
    ManagedMbedtlsEcdsaContext ctx;

    // Load key pair
    LoadEcdsaKeyPair(key, ctx);

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SHA256_DIGEST_LENGTH> hash;
    hash.SetSize(SHA256_DIGEST_LENGTH);
    mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);

    // Verify signature
    int result = mbedtls_ecdsa_read_signature(
        ctx.GetContext(), 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_read_signature failed: %d", result);
}

// Get public key
void SKApplicationKeyStoreSim::GetPublicKey(const char* key, SKBinaryBuffer& publicKey) {

    // Init context
    ManagedMbedtlsEcdsaContext ctx;

    // Load key pair
    LoadEcdsaKeyPair(key, ctx);

    // Get public key
    size_t size = 0;
    publicKey.SetSize(ECDSA_PUBLIC_KEY_LENGTH);
    int result = mbedtls_ecp_point_write_binary(
        &ctx.GetContext()->MBEDTLS_PRIVATE(grp), 
        &ctx.GetContext()->MBEDTLS_PRIVATE(Q), 
        MBEDTLS_ECP_PF_UNCOMPRESSED, 
        &size, 
        publicKey.GetBuffer(), 
        publicKey.GetSize());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_write_binary failed: %d", result);
}
