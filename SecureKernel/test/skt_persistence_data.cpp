#include <iostream>

#include "skt_utils.hpp"
#include "sk_persistence.hpp"

// Test persistence class (keys)
class SKTTestPersistenceData : public SKTTestCrypto {

private:

    // Run test
    virtual void RunTest();

};

// Run test
void SKTTestPersistenceData::RunTest() {

        // Execute 100 times
    for (int i = 0; i < 100; ++i) {

        // Generate key
        SKCrypto::SKKeyId key_id;
        spcrypto->AES128GCMGenerateKey(key_id);

        // Store key
        SKStoreKey<SK_DB_TEST_SYM_SIZE> db_key_id(SK_DB_TEST_SYM_HEX);
        SKStoreCryptoKeyPtr spkey = SKStoreCryptoKey::Store(*spstore, spcrypto, key_id, db_key_id);

        // Load key
        SKStoreCryptoKeyPtr spkey2 = SKStoreCryptoKey::Load(*spstore, spcrypto, db_key_id);

        // Generate 1024 bytes of random data
        SKDynamicBinaryBuffer plain;
        GenerateRandomData(1024, plain);

        // Store data and tag
        SKStoreKey<SK_DB_TEST_VAL_SIZE> db_val_id(SK_DB_TEST_VAL_HEX);
        SKStoreKey<SK_DB_TEST_TAG_SIZE> db_tag_id(SK_DB_TEST_TAG_HEX);
        SKStoreValuePtr spvalue = SKStoreValue::Store(*spstore, spkey, db_val_id, db_tag_id, plain);

        // Load data and tag
        SKStoreValuePtr spvalue2 = SKStoreValue::Load(*spstore, spkey2, db_val_id, db_tag_id);

        // Decrypt data
        SKDynamicBinaryBuffer plain2;
        spvalue2->Decrypt(plain2);

        // Compare data
        SK_CHECK(plain == plain2, SK_ERROR_FAILED, "Data mismatch");

        // Delete keys
        SKCryptoPtr spcrypto2 = *spkey2;
        spcrypto2->DeleteKey(*spkey2);
        spcrypto->DeleteKey(key_id);
    }
}

// Entry point.
int test_skt_persistence_data(int, char*[]) {
    
        // Create test
        SKTTestPersistenceData test;
        return test.Run();
}
