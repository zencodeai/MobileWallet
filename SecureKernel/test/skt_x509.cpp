#include <iostream>
#include <map>
#include <list>
#include <memory>

#include "sk_x509.hpp"
#include "skt_utils.hpp"

// Test certificates
class SKTTestX509 : public SKTTestCrypto {

public:


private:

    // Get certificate
    SKCertChainPtr GetCertChain(const SKBinaryBuffer& cert) {

        // Create instance
        SKCertChainPtr spchain = SKCertChainPtr(new SKCertChain());

        // Parse certificate
        spchain->Parse(cert);

        // Return instance
        return spchain;
    }

    // Get test certificate
    SKCertChainPtr GetTestCertificate() {

        SKConstant<SK_TEST_X509_CERT_SIZE> cert(SK_TEST_X509_CERT);
        cert.Unmask(SKConstant<SK_TEST_X509_CERT_SIZE>(SK_TEST_X509_CERT_MASK));
        cert.VerifyHash(SKConstant<32>(SK_TEST_X509_CERT_CSUM));

        return GetCertChain(cert.GetBuffer());
    }

    // Get root certificate
    SKCertChainPtr GetRootCertificate() {
            
        SKConstant<SK_ROOT_CERT_SIZE> cert(SK_ROOT_CERT);
        cert.Unmask(SKConstant<SK_ROOT_CERT_SIZE>(SK_ROOT_CERT_MASK));
        cert.VerifyHash(SKConstant<32>(SK_ROOT_CERT_CSUM));

        return GetCertChain(cert.GetBuffer());
    }

    // Run test
    virtual void RunTest();
};

// Run test
void SKTTestX509::RunTest() {

    SKCertChainPtr spcert = GetTestCertificate();
    SKCertChainPtr sprcert = GetRootCertificate();

    // Verify certificate
    sprcert->VerifyChain(*spcert);
}

// Entry point.
int test_skt_x509(int, char*[]) {
    
    // Create test
    SKTTestX509 test;
    return test.Run();
}
