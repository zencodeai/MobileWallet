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

// Test crypto unwrap AES class
class SKTestCryptoUnwrapAES : public SKTTestCrypto {

private:

    // Vertify key
    void verify(const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& key);

    // Run test
    virtual void RunTest();
};

// Vertify key
void SKTestCryptoUnwrapAES::verify(const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& key) {

    // Init aes gcm context
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // AES block size
    const uint32_t aes_block_size = 16;

    // Data size
    const uint32_t data_size = 32;

    // Tag size
    const uint32_t tag_size = 16;

    // Create random iv
    SKDynamicBinaryBuffer iv(aes_block_size);
    iv.SetSize(aes_block_size);
    generate_random_bytes(iv.GetBuffer(), iv.GetSize());

    // Create random data
    SKDynamicBinaryBuffer data(data_size);
    data.SetSize(data_size);
    generate_random_bytes(data.GetBuffer(), data.GetSize());

    // Create random plain text
    SKDynamicBinaryBuffer plain(1024);
    plain.SetSize(1024);
    generate_random_bytes(plain.GetBuffer(), plain.GetSize());

    // Encrypt data using mbedtls AES-GCM
    SKDynamicBinaryBuffer tag(tag_size);
    tag.SetSize(tag_size);
    SKDynamicBinaryBuffer cipher(plain.GetSize());
    cipher.SetSize(plain.GetSize());
    
    // Set key in aes gcm context
    int result = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.GetBuffer(), key.GetSize() * 8);
    SK_CHECK(result == 0, SK_ERROR_FAILED, "mbedtls_gcm_setkey failed");

    // Encrypt data using mbedtls AES-GCM
    result = mbedtls_gcm_crypt_and_tag(
        &ctx, 
        MBEDTLS_GCM_ENCRYPT, 
        plain.GetSize(), 
        iv.GetBuffer(), iv.GetSize(), 
        data.GetBuffer(), data.GetSize(),
        plain.GetBuffer(), cipher.GetBuffer(),
        tag_size, tag.GetBuffer());
    SK_CHECK(result == 0, SK_ERROR_FAILED, "mbedtls_gcm_crypt_and_tag failed");

    // Decrypt data usin SKCrypto
    SKDynamicBinaryBuffer plain2(plain.GetSize());
    plain2.SetSize(plain.GetSize());

    spcrypto->AES128GCMDecrypt(key_id, iv, data, cipher, tag, plain2);

    // Compare plain text
    SK_CHECK(plain == plain2, SK_ERROR_FAILED, "Plain text mismatch");

    mbedtls_gcm_free(&ctx);
}

// Run test
void SKTestCryptoUnwrapAES::RunTest() {

    // Execute 100 times
    for (int i = 0; i < 100; ++i) { 
        
        // Generate key
        SKCrypto::SKKeyId key_id;
        spcrypto->AES128GCMGenerateKey(key_id);
        
        // Generate 48 bytes key blob    
        SKDynamicBinaryBuffer key;
        key.SetSize(16);
        generate_random_bytes(key.GetBuffer(), key.GetSize());

        // Wrap key
        SKDynamicBinaryBuffer keyblob;
        WrapKey(key_id, key, keyblob);

        // Import key
        SKCrypto::SKKeyId key_id_new;
        spcrypto->UnwrapKeyAES128GCM(key_id, keyblob, key_id_new);

        // Verify key
        verify(key_id_new, key);

        // Delete keys
        spcrypto->DeleteKey(key_id);
        spcrypto->DeleteKey(key_id_new);            
    }
}

// Entry point.
int test_skt_crypto_unwrap_aes(int, char*[]) {

    SKTestCryptoUnwrapAES test;
    return test.Run();
}
