#include <iostream>

#include "skt_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"
#include "sk_crypto.hpp"
#include "sk_crypto_mbedtls.hpp"

// ECDH test class
class SKTTestCryptoECDH : public SKTTestCrypto {

private:

    // Run test
    virtual void RunTest();

};

// Run test
void SKTTestCryptoECDH::RunTest() {

    // Intantiate crypto instances
    SKCryptoPtr spcrypto1 = SKCrypto::Create(SKCryptoMbedTLSParams(sprandom, spstore, spappkeystore));
    SKCryptoPtr spcrypto2 = SKCrypto::Create(SKCryptoMbedTLSParams(sprandom, spstore, spappkeystore));

    // Execute 100 times
    for (int i = 0; i < 100; ++i) {

        // Start ECDH key exchange
        SKDynamicBinaryBuffer params;
        spcrypto1->ECDHGetClientParams(params);

        // Get server public key
        SKDynamicBinaryBuffer public_key;
        spcrypto2->ECDHServerPublicKey(params, public_key);

        // Set public key
        spcrypto1->ECDHSetPublicKey(public_key);

        // Compute shared key
        SKCrypto::SKKeyId key_id1;
        spcrypto1->ECDHComputeSharedKey(key_id1);

        // Compute shared key
        SKCrypto::SKKeyId key_id2;
        spcrypto2->ECDHComputeSharedKey(key_id2);
        
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
        spcrypto1->AES128GCMEncrypt(key_id1, iv, data, plain, cipher, tag);

        // Decrypt
        SKDynamicBinaryBuffer plain2;
        spcrypto2->AES128GCMDecrypt(key_id2, iv, data, cipher, tag, plain2);

        // Compare plain text
        SK_CHECK(plain == plain2, SK_ERROR_FAILED, "plain text mismatch");

        // Delete keys
        spcrypto1->DeleteKey(key_id1);
        spcrypto2->DeleteKey(key_id2);
    }
}

// Entry point
int test_skt_crypto_ecdh(int, char*[]) {

    SKTTestCryptoECDH test;
    return test.Run();
}

