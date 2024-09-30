#pragma once

#include <memory>

#include "sk_session.hpp"

// Online session class
class SKSessionProvision : public SKSession
{

public:

    // Provisioning token size
    static const uint32_t PROVISIONING_TOKEN_SIZE = 32;

    // Digest size
    static const uint32_t DIGEST_SIZE = SKManagedSHA256Context::DIGEST_SIZE;

    // Max provisioning parameters size
    static const uint32_t MAX_PROVISIONING_PARAMS_SIZE = 2048;

    // Max wrapped key size
    static const uint32_t MAX_WRAPPED_KEY_SIZE = 256;

protected:

    // Unwrapping key id
    SKCrypto::SKKeyId m_keyid_unwrap;

    // Token
    SKBuffer32 m_token;

    // Constructor
    SKSessionProvision(const SKInitContext& ctx) : SKSession(ctx), m_keyid_unwrap(0) {}

    // Get establish shared key message
    void GetEstablishSharedKeyMsg(SKBinaryBuffer& msg_out);

    // Get provisioning token message
    void GetProvisioningTokenMsg(const SKBinaryBuffer& token, SKBinaryBuffer& msg_out);

    // Start session
    void StartSession(SKBinaryBuffer& client_params);

    // Process server response
    void ProcessServerResponse(const SKBinaryBuffer& server_response);

    // Process provisioning parameters
    void ProcessProvisioningParameters(const SKBinaryBuffer& msg_in);

public:

    // Class factory
    static SKSessionPtr Create(
        const SKCryptoPtr& spcrypto,
        const SKSecureStorePtr& spstore, 
        const SKRandomPtr& sprandom);

    // Destructor
    ~SKSessionProvision() {}

    // Process message
    void ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Provision
    void Provision(const SKBinaryBuffer& token, SKBinaryBuffer& msg_out);
};
