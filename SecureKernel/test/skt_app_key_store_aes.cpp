
#include <iostream>

#include "skt_utils.hpp"
#include "sk_secure_store.hpp"
#include "sk_random.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"

// App keystore test entry point.
int test_skt_app_key_store_aes(int, char*[]) {

    // Secure store pathname
    const std::string pathname = "test.sqlite";

    try {

        // Delete secure store using stl
        std::remove(pathname.c_str());

        // Instantiate secure store
        SKSecureStorePtr spstore = SKSecureStore::Create();

        // Create secure store
        spstore->Create(pathname.c_str());

        // Close secure store
        spstore->Close();

        // Open secure store
        spstore->Open(pathname.c_str());

        // Instantiate random number generator
        SKRandomPtr sprandom = SKRandom::Create(spstore);
        
        // Instantiate application key store factory parameters
        SKApplicationKeyStoreSimFactoryParameters params(spstore, sprandom);

        // Generate random byte string of length 32
        SKStaticBinaryBuffer<32> buffer;
        buffer.SetSize(32);
        generate_random_bytes(buffer.GetBuffer(), buffer.GetSize());

        // Update seed
        sprandom->UpdateSeed(buffer);

        // Instantiate application key store
        SKApplicationKeyStorePtr spappkeystore = SKApplicationKeyStore::Create(params);

        // Generate symmetric key
        spappkeystore->GenerateSymmetricKey(SK_APP_KEY_SYM);

        // Execute 100 times
        for (int i = 0; i < 100; ++i) {

            // Generate 1024 bytes of random data
            SKDynamicBinaryBuffer plain;
            plain.SetSize(1024);
            generate_random_bytes(plain.GetBuffer(), plain.GetSize());

            // Encrypt data
            SKDynamicBinaryBuffer cipher;
            spappkeystore->Encrypt(SK_APP_KEY_SYM, plain, cipher);

            // Decrypt data
            SKDynamicBinaryBuffer decrypted;
            spappkeystore->Decrypt(SK_APP_KEY_SYM, cipher, decrypted);

            // Compare decrypted data with original data
            SK_CHECK(plain == decrypted, SK_ERROR_FAILED, "Decrypted data does not match original data");
        }
    }
    catch (SKException& error) {
        std::cout << "Error: " << error.what() << std::endl;
        return 1;
    }

    catch (std::exception& error) {
        std::cout << "Error: " << error.what() << std::endl;
        return 1;
    }

    catch (...) {
        std::cout << "Error: Unknown exception" << std::endl;
        return 1;
    }

    return 0;
}

