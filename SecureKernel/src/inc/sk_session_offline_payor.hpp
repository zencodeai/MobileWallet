#pragma once

#include "sk_session_offline.hpp"

// Online session class
class SKSessionOfflinePayor : public SKSessionOffline
{

public:


protected:

    // Constructor
    SKSessionOfflinePayor(const SKInitContext& ctx) : SKSessionOffline(ctx) {}

    // Get key sharing message
    void GetKeySharingMsg(SKBinaryBuffer& msg_out);

    // Process Key sharing response
    void ProcessKeySharingResponse(const SKBinaryBuffer& msg_in);

    // Get transaction data message
    void GetTransactionDataMsg(SKBinaryBuffer& msg_out);

    // Process receipt message
    void ProcessReceiptMsg(const SKBinaryBuffer& msg_in);

public:

    // Class factory
    static SKSessionPtr Create(
        const SKCryptoPtr& spcrypto,
        const SKSecureStorePtr& spstore, 
        const SKRandomPtr& sprandom);

    // Destructor
    ~SKSessionOfflinePayor() {}

    // ProcessMsg message
    void ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Start offline transaction
    void StartOfflineTransaction(const uint64_t amount, const uint64_t timestamp, SKBinaryBuffer& msg_out);
};
