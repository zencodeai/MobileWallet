#include "skt_utils.hpp"
#include "sk_secure_store.hpp"

// Secure store test entry point.
int test_skt_secure_store(int, char*[])
{
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

        // Close secure store
        spstore->Close();

        // Open secure store
        spstore->Open(pathname.c_str());

        // Loop 100 times
        for (int i = 0; i < 100; i++) {

            // Generate random key
            const std::string key = generate_random_string(16);

            // Generate random integer
            const uint32_t size = generate_random_int(100, 1024);

            // Create byte array of random size
            SKDynamicBinaryBuffer buffer(size);

            // Generate random bytes
            generate_random_bytes(buffer.GetBuffer(), buffer.GetSize());

            // Has value?
            SK_CHECK(!spstore->HasKey(key.c_str()), SK_ERROR_FAILED, "HasKey failed");

            // Set value
            spstore->SetKey(key.c_str(), buffer);

            // Has value?
            SK_CHECK(spstore->HasKey(key.c_str()), SK_ERROR_FAILED, "HasKey failed");

            // Get value
            SKDynamicBinaryBuffer value; 
            spstore->GetKey(key.c_str(), value);

            // Compare values
            // value.GetBuffer()[0]++;
            SK_CHECK(buffer == value, SK_ERROR_FAILED, "GetKey failed");

            // Begin transaction
            spstore->BeginTransaction();

            // Delete value
            spstore->DeleteKey(key.c_str());

            // Rollback transaction
            spstore->RollbackTransaction();

            // Has value?
            SK_CHECK(spstore->HasKey(key.c_str()), SK_ERROR_FAILED, "HasKey failed");

            // Get value
            value.Reset();
            spstore->GetKey(key.c_str(), value);

            // Compare values
            SK_CHECK(buffer == value, SK_ERROR_FAILED, "GetKey failed");

            // Begin transaction
            spstore->BeginTransaction();

            // Delete value
            spstore->DeleteKey(key.c_str());

            // Commit transaction
            spstore->CommitTransaction();

            // Has value?
            SK_CHECK(!spstore->HasKey(key.c_str()), SK_ERROR_FAILED, "HasKey failed");
        }

        // Generate random key
        const std::string key = generate_random_string(16);
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
