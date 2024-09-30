#include <iostream>

#include "skt_utils.hpp"

// Test certificates
class SKTSessionProvision : public SKTTest, public SKTContext {

public:


private:

    // Store name
    static const std::string STORE_NAME;

    // Backend store name
    static const std::string BACKEND_STORE_NAME;

    // Backend context
    SKTContext m_backend;

    // Prepare test environment
    void Prepare() {}

    // Post-test
    void Cleanup() {}

    // Run test
    void RunTest();

public:

    // Constructor
    SKTSessionProvision() : SKTContext(STORE_NAME), m_backend(BACKEND_STORE_NAME) {}

    // Destructor
    ~SKTSessionProvision() {}
};

// Store name
const std::string SKTSessionProvision::STORE_NAME = "test.sqlite";

// Backend store name
const std::string SKTSessionProvision::BACKEND_STORE_NAME = "test_backend.sqlite";

// Run test
void SKTSessionProvision::RunTest() {

    // Execute 10 times
    for (int i = 0; i < 10; i++) {

        // Client context
        SKTContext client(STORE_NAME);

        // Backend context
        SKTContext backend(BACKEND_STORE_NAME);

        // Create provisioning session
        SKSessionPtr spsession = client.CreateProvisioningSession();

        // Get client test certificate/key pair
        SKTKeyPairPtr spkeypair_client = SKTKeyPair::Create_SK_TEST_X509(backend.GetRandom(), backend.GetCrypto());

        // Provision
        backend.Provision(spsession, spkeypair_client);
    }
}

// Entry point.
int test_skt_session_provision(int, char*[]) {
    
    // Create test
    SKTSessionProvision test;
    return test.Run();
}
