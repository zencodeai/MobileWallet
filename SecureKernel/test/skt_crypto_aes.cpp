#include <iostream>

#include "skt_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"
#include "sk_crypto.hpp"
#include "sk_crypto_mbedtls.hpp"

// Test crypto AES class
class SKTTestCryptoAES : public SKTTestCrypto {

private:

    // Run test
    virtual void RunTest();

};

// Run test
void SKTTestCryptoAES::RunTest() {

        // Execute 100 times
    for (int i = 0; i < 100; ++i) {

        // Generate key
        SKCrypto::SKKeyId key_id;
        spcrypto->AES128GCMGenerateKey(key_id);

        // Generate random iv
        SKStaticBinaryBuffer<16> iv;
        iv.SetSize(16);
        generate_random_bytes(iv.GetBuffer(), iv.GetSize());

        // Generate random data
        SKStaticBinaryBuffer<32> data;
        data.SetSize(32);
        generate_random_bytes(data.GetBuffer(), data.GetSize());

        // Genarate random plain text
        SKDynamicBinaryBuffer plain(1024);
        plain.SetSize(1024);
        generate_random_bytes(plain.GetBuffer(), plain.GetSize());

        // Encrypt
        SKDynamicBinaryBuffer cipher;
        SKDynamicBinaryBuffer tag;
        spcrypto->AES128GCMEncrypt(key_id, iv, data, plain, cipher, tag);

        // Decrypt
        SKDynamicBinaryBuffer plain2;
        spcrypto->AES128GCMDecrypt(key_id, iv, data, cipher, tag, plain2);

        // Compare plain text
        SK_CHECK(plain == plain2, SK_ERROR_FAILED, "plain text mismatch");

        // Export key
        SKDynamicBinaryBuffer key;
        spcrypto->ExportKey(key_id, key);

        // Delete key
        spcrypto->DeleteKey(key_id);

        // Import key
        SKCrypto::SKKeyId key_id2;
        spcrypto->ImportKey(key, key_id2);

        // Generate random iv
        generate_random_bytes(iv.GetBuffer(), iv.GetSize());

        // Generate random data
        generate_random_bytes(data.GetBuffer(), data.GetSize());

        // Ganarate random plain text
        generate_random_bytes(plain.GetBuffer(), plain.GetSize());

        // Encrypt
        spcrypto->AES128GCMEncrypt(key_id2, iv, data, plain, cipher, tag);

        // Decrypt
        spcrypto->AES128GCMDecrypt(key_id2, iv, data, cipher, tag, plain2);

        // Compare plain text
        SK_CHECK(plain == plain2, SK_ERROR_FAILED, "plain text mismatch");

        // Delete key
        spcrypto->DeleteKey(key_id2);
    }
}

// Entry point.
int test_skt_crypto_aes(int, char*[]) {
    
        // Create test
        SKTTestCryptoAES test;
        return test.Run();
}
