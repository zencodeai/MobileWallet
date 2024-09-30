#include <iostream>

#include "skt_utils.hpp"
#include "sk_persistence.hpp"

// Test persistence class (keys)
class SKTTestPersistenceKey : public SKTTestCrypto {

private:

    // Run test
    virtual void RunTest();

};

// Run test
void SKTTestPersistenceKey::RunTest() {

        // Execute 100 times
    for (int i = 0; i < 100; ++i) {

        // Generate key
        SKCrypto::SKKeyId key_id;
        spcrypto->AES128GCMGenerateKey(key_id);

        // Store key
        SKStoreCryptoKeyPtr spkey = SKStoreCryptoKey::Store(*spstore, spcrypto, key_id, SK_DB_TEST_SYM);

        // Load key
        SKStoreCryptoKeyPtr spkey2 = SKStoreCryptoKey::Load(*spstore, spcrypto, SK_DB_TEST_SYM);

        // Generate 1024 bytes of random data
        SKDynamicBinaryBuffer plain;
        GenerateRandomData(1024, plain);

        // Generate random iv
        SKStaticBinaryBuffer<IV_SIZE> iv;
        iv.SetSize(16);
        generate_random_bytes(iv.GetBuffer(), iv.GetSize());

        // Generate random data
        SKStaticBinaryBuffer<AAD_SIZE> data;
        data.SetSize(32);
        generate_random_bytes(data.GetBuffer(), data.GetSize());

        // Tag buffer
        SKStaticBinaryBuffer<TAG_SIZE> tag;

        // Encrypt data
        SKDynamicBinaryBuffer cipher;
        spcrypto->AES128GCMEncrypt(key_id, iv, data, plain, cipher, tag);

        // Decrypt data using loaded key
        SKDynamicBinaryBuffer plain2;

        SKCryptoPtr spcrypto2 = *spkey2;
        spcrypto2->AES128GCMDecrypt(*spkey2, iv, data, cipher, tag, plain2);

        // Compare plain and plain2
        SK_CHECK(plain == plain2, SK_ERROR_FAILED, "Inconsistent plain text");

        // Delete keys
        spcrypto2->DeleteKey(*spkey2);
        spcrypto->DeleteKey(key_id);
    }
}

// Entry point.
int test_skt_persistence_key(int, char*[]) {
    
        // Create test
        SKTTestPersistenceKey test;
        return test.Run();
}
