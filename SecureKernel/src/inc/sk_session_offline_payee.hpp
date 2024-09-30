#pragma once

#include "sk_session_offline.hpp"

// Online session class
class SKSessionOfflinePayee : public SKSessionOffline
{

public:


protected:

    // Client ECDH parameters hash (verification postponed)
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> m_hash;

    // Signature for postponed verification
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> m_signature;

    // Constructor
    SKSessionOfflinePayee(const SKInitContext& ctx) : SKSessionOffline(ctx) {}

    // Process Key sharing request message
    void ProcessKeySharingRequestMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Process transaction data message
    void ProcessTransactionDataMsg(const SKBinaryBuffer& msg_in);

    // Get receipt message
    void GetReceiptMsg(SKBinaryBuffer& msg_out);

    // Process acknowledgement message
    void ProcessAcknowledgementMsg(const SKBinaryBuffer& msg_in);

public:

    // Class factory
    static SKSessionPtr Create(
        const SKCryptoPtr& spcrypto,
        const SKSecureStorePtr& spstore, 
        const SKRandomPtr& sprandom);

    // Destructor
    ~SKSessionOfflinePayee() {}

    // ProcessMsg message
    void ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Start offline transaction
    void StartOfflineTransaction();
};