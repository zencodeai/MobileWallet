#include <iostream>

#include "skt_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"
#include "sk_crypto.hpp"
#include "sk_crypto_mbedtls.hpp"

// Test crypto ECDSA class
class SKTTestCryptoECDSA : public SKTTestCrypto {

private:

    // Run test
    virtual void RunTest();

};

// Run test
void SKTTestCryptoECDSA::RunTest() {

    // Execute 100 times
    for (int i = 0; i < 100; ++i) {

        // Generate ECDSA key pair
        SKCrypto::SKKeyId key_id;
        spcrypto->ECDSAP256GenerateKeyPair(key_id);

        // Generate random data
        SKDynamicBinaryBuffer data;
        data.SetSize(1024);
        generate_random_bytes(data.GetBuffer(), data.GetSize());

        // Sign data
        SKDynamicBinaryBuffer signature;
        spcrypto->ECDSAP256Sign(key_id, data, signature);

        // Verify signature
        spcrypto->ECDSAP256Verify(key_id, data, signature);

        // Export key pair
        SKDynamicBinaryBuffer keypair;
        spcrypto->ExportKey(key_id, keypair);

        // Delete key
        spcrypto->DeleteKey(key_id);

        // Import key pair
        spcrypto->ImportKey(keypair, key_id);

        // Sign and verify again
        spcrypto->ECDSAP256Sign(key_id, data, signature);
        spcrypto->ECDSAP256Verify(key_id, data, signature);

        // Delete key
        spcrypto->DeleteKey(key_id);
    }
}

// Entry point.
int test_skt_crypto_ecdsa(int, char*[]) {
    
        // Create test
        SKTTestCryptoECDSA test;
        return test.Run();
}
