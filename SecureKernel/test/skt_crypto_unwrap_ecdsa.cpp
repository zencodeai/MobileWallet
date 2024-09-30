#include <iostream>

#include "skt_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"
#include "sk_crypto.hpp"
#include "sk_crypto_mbedtls.hpp"

#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"
#include "mbedtls/ecdsa.h"

// ECDSA managed context
class SKTECDSAContext {

private:

    // Context
    mbedtls_ecdsa_context m_ctx;

public:

    // Constructor
    SKTECDSAContext()
    {
        mbedtls_ecdsa_init(&m_ctx);
    }

    // Destructor
    ~SKTECDSAContext()
    {
        mbedtls_ecdsa_free(&m_ctx);
    }

    // Get context
    mbedtls_ecdsa_context* GetContext()
    {
        return &m_ctx;
    }
};

// Test crypto unwrap ECDSA key pair class
class SKTestCryptoUnwrapECDSA : public SKTTestCrypto {

private:

    // Context
    mbedtls_ecdsa_context m_ctx;

    // Vertify key
    void VerifyUnwrappedKey(const SKCrypto::SKKeyId key_id, SKTECDSAContext& ctx);

    // Generate ECDSA key pair
    void GenerateKeyPair(SKTECDSAContext& ctx);

    // Sign data
    void Sign(SKTECDSAContext& ctx, const SKBinaryBuffer& data, SKBinaryBuffer& signature);

    // Verify signature
    void Verify(SKTECDSAContext& ctx, const SKBinaryBuffer& data, const SKBinaryBuffer& signature);

    // Wrap key pair
    void WrapECDSAKeyPair(const SKCrypto::SKKeyId key_id, SKTECDSAContext& ctx, SKBinaryBuffer& wrapped_key);

    // Run test
    virtual void RunTest();
};

// Verify unwrapped key
void SKTestCryptoUnwrapECDSA::VerifyUnwrappedKey(const SKCrypto::SKKeyId key_id, SKTECDSAContext& ctx) {

    // Generate 1024 bytes random data
    SKDynamicBinaryBuffer data;
    GenerateRandomData(1024, data);

    // Sign data
    SKDynamicBinaryBuffer signature;
    Sign(ctx, data, signature);

    // Verify signature
    spcrypto->ECDSAP256Verify(key_id, data, signature);
}

// Generate ECDSA key pair
void SKTestCryptoUnwrapECDSA::GenerateKeyPair(SKTECDSAContext& ctx) {

    // Generate ECDSA key pair
    int result = mbedtls_ecdsa_genkey(ctx.GetContext(), MBEDTLS_ECP_DP_SECP256R1, ecdsa_prng, sprandom.get());
    SK_CHECK(result == 0, SK_ERROR_FAILED, "mbedtls_ecdsa_genkey failed");
}

// Sign data
void SKTestCryptoUnwrapECDSA::Sign(SKTECDSAContext& ctx, const SKBinaryBuffer& data, SKBinaryBuffer& signature) {

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SKCryptoMbedTLS::SHA256_HASH_SIZE> hash;
    hash.SetSize(SKCryptoMbedTLS::SHA256_HASH_SIZE);
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
        ecdsa_prng, sprandom.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_write_signature failed: %d", result);

    // Set signature size
    signature.UpdateSize(signatureSize);
}

// Verify signature
void SKTestCryptoUnwrapECDSA::Verify(SKTECDSAContext& ctx, const SKBinaryBuffer& data, const SKBinaryBuffer& signature) {

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SKCryptoMbedTLS::SHA256_HASH_SIZE> hash;
    hash.SetSize(SKCryptoMbedTLS::SHA256_HASH_SIZE);
    mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);

    // Verify signature
    int result = mbedtls_ecdsa_read_signature(
        ctx.GetContext(), 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_read_signature failed: %d", result);
}

// Wrap key pair
void SKTestCryptoUnwrapECDSA::WrapECDSAKeyPair(const SKCrypto::SKKeyId key_id, SKTECDSAContext& ctx, SKBinaryBuffer& wrapped_key) {

    // Get 32 bytes private key
    SKDynamicBinaryBuffer privateKey(SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH);
    privateKey.SetSize(SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH);
    int result = mbedtls_mpi_write_binary(&ctx.GetContext()->MBEDTLS_PRIVATE(d), privateKey.GetBuffer(), SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_mpi_write_binary failed: %d", result);

    // Get 65 bytes public key 0x04 + 32 bytes x + 32 bytes y
    size_t olen = 0;
    SKDynamicBinaryBuffer publicKey(SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    publicKey.SetSize(SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    result = mbedtls_ecp_point_write_binary(
        &ctx.GetContext()->MBEDTLS_PRIVATE(grp), 
        &ctx.GetContext()->MBEDTLS_PRIVATE(Q), 
        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, 
        publicKey.GetBuffer(), SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_write_binary failed: %d", result);

    // Create key blob
    SKDynamicBinaryBuffer keyBlob(SKCryptoMbedTLS::ECDSA_PRIVATE_KEY_LENGTH + SKCryptoMbedTLS::ECDSA_PUBLIC_KEY_LENGTH);
    keyBlob += privateKey;
    keyBlob += publicKey;

    // Wrap key
    WrapKey(key_id, keyBlob, wrapped_key);
}

// Run test
void SKTestCryptoUnwrapECDSA::RunTest() {

    // Execute 100 times
    for (int i = 0; i < 100; ++i) { 

        // ECDSA context
        SKTECDSAContext ctx;

        // Generate ECDSA key pair
        GenerateKeyPair(ctx);

        // Generate wrapping key
        SKCrypto::SKKeyId key_id = 0;
        spcrypto->AES128GCMGenerateKey(key_id);

        // Wrap ECDSA key pair
        SKDynamicBinaryBuffer wrapped_key;
        WrapECDSAKeyPair(key_id, ctx, wrapped_key);

        // Unwrap key
        SKCrypto::SKKeyId key_id_new = 0;
        spcrypto->UnwrapKeyECDSAP256(key_id, wrapped_key, key_id_new);

        // Verify unwrapped key
        VerifyUnwrappedKey(key_id_new, ctx);
    }
}

// Entry point.
int test_skt_crypto_unwrap_ecdsa(int, char*[]) {

    SKTestCryptoUnwrapECDSA test;
    return test.Run();
}
