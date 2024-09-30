#include <iostream>

#include "skt_utils.hpp"

// Test certificates
class SKTSessionOffline : public SKTTest {

public:

    // Initial balance
    static const uint64_t INITIAL_BALANCE = 1000;

private:

    // Store names
    static const std::string STORE_PAYOR;
    static const std::string STORE_PAYEE;
    static const std::string STORE_BAKND_PAYOR;
    static const std::string STORE_BAKND_PAYEE;

    // Client payor context
    SKTContext m_client_payor;

    // Client payor context
    SKTContext m_client_payee;

    // Prepare test environment
    void Prepare() {}

    // Post-test
    void Cleanup() {}

    // Run test
    void RunTest();

public:

    // Constructor
    SKTSessionOffline() : m_client_payor(STORE_PAYOR), m_client_payee(STORE_PAYEE) {}

    // Destructor
    ~SKTSessionOffline() {}
};

// Store names
const std::string SKTSessionOffline::STORE_PAYOR = "test_payor.sqlite";
const std::string SKTSessionOffline::STORE_PAYEE = "test_payee.sqlite";
const std::string SKTSessionOffline::STORE_BAKND_PAYOR = "test_backend_payor.sqlite";
const std::string SKTSessionOffline::STORE_BAKND_PAYEE = "test_backend_payee.sqlite";

// Run test
void SKTSessionOffline::RunTest() {

    // Provision payor
    SKTContext backend_payor(STORE_BAKND_PAYOR);
    SKSessionPtr spsession_payor_prov = m_client_payor.CreateProvisioningSession();
    SKTKeyPairPtr spkeypair_payor = SKTKeyPair::Create_SK_TEST1_X509(backend_payor.GetRandom(), backend_payor.GetCrypto());
    backend_payor.Provision(spsession_payor_prov, spkeypair_payor);
    backend_payor.InitializeBalance(m_client_payor, INITIAL_BALANCE);

    // Provision payee
    SKTContext backend_payee(STORE_BAKND_PAYEE);
    SKSessionPtr spsession_payee_prov = m_client_payee.CreateProvisioningSession();
    SKTKeyPairPtr spkeypair_payee = SKTKeyPair::Create_SK_TEST2_X509(backend_payee.GetRandom(), backend_payee.GetCrypto());
    backend_payee.Provision(spsession_payee_prov, spkeypair_payee);
    backend_payee.InitializeBalance(m_client_payee, INITIAL_BALANCE);

    // Create payor session
    SKSessionPtr spsession_payor = m_client_payor.CreateOfflinePayorSession();
    SKSessionOfflinePayor& session_payor = dynamic_cast<SKSessionOfflinePayor&>(*spsession_payor);

    // Create payee session
    SKSessionPtr spsession_payee = m_client_payee.CreateOfflinePayeeSession();
    SKSessionOfflinePayee& session_payee = dynamic_cast<SKSessionOfflinePayee&>(*spsession_payee);

    // Initialize buffers
    SKDynamicBinaryBuffer msg_out(1024);
    SKDynamicBinaryBuffer msg_in(1024);

    // Payor: initiate payment
    uint64_t amount = 100;
    uint64_t timestamp = SKUtils::GetTimestamp();
    session_payor.StartOfflineTransaction(amount, timestamp, msg_out);

    // Payee : prepare to receive payment
    session_payee.StartOfflineTransaction();

    // Process messages
    do {

        // Payee: process message
        session_payee.ProcessMsg(msg_out, msg_in);

        if (msg_in.GetCapacity() == 0) {
            break;
        }

        // Payor: process message
        session_payor.ProcessMsg(msg_in, msg_out);

    } while (true);

    SK_CHECK(!msg_out.GetCapacity(), SK_ERROR_FAILED, "Invalid session state");
    SK_CHECK(!msg_in.GetCapacity(), SK_ERROR_FAILED, "Invalid session state");

    uint64_t balance_payor = session_payor.GetBalance();
    SK_CHECK(balance_payor == INITIAL_BALANCE - amount, SK_ERROR_FAILED, "Invalid balance");
    uint64_t balance_payee = session_payee.GetBalance();
    SK_CHECK(balance_payee == INITIAL_BALANCE + amount, SK_ERROR_FAILED, "Invalid balance");
}

// Entry point.
int test_skt_session_offline(int, char*[]) {
    
    // Create test
    SKTSessionOffline test;
    return test.Run();
}
