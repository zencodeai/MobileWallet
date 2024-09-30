#pragma once

#include <memory>

#include "sk_session.hpp"

// Online session class
class SKSessionOnline : public SKSession
{

public:

    // Minimum transaction data size
    static const uint32_t MIN_TX_DATA_SIZE = IUID_SIZE + SKTransactionNode::TRANSACTION_NODE_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE; 

    // TUID request data size
    static const uint32_t TUID_REQUEST_DATA_SIZE = BLOCK_SIZE + SKTransactionNode::CUID_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE;

    // TUID response data size
    static const uint32_t TUID_RESPONSE_DATA_SIZE = BLOCK_SIZE + SKTransactionNode::CUID_SIZE + SKTransactionNode::TUID_SIZE + SKTransactionNode::RUID_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE;

    // Balance update data size
    static const uint32_t BALANCE_UPDATE_DATA_SIZE = SKTransactionNode::TRANSACTION_NODE_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE;

protected:

    // New transaction state
    uint64_t m_amount;
    uint64_t m_ts;
    SKBuffer32 m_cuid;

    // Constructor
    SKSessionOnline(const SKInitContext& ctx) : SKSession(ctx) {}

    // Clear new transaction state
    void ClearNewTransactionState() {

        m_amount = 0;
        m_ts = 0;
        m_cuid.Reset();
    }

    // Set new transaction state
    void SetNewTransactionState(const uint64_t amount, const uint64_t ts, const SKBinaryBuffer& cuid) {

        m_amount = amount;
        m_ts = ts;
        m_cuid = cuid;
    }

    // Start session
    void StartSession(SKBinaryBuffer& client_params);

    // Process server params, establish shared key
    void ProcessServerParams(const SKBinaryBuffer& server_response, const uint32_t cipher_size, SKBinaryBuffer& plain);

    // Process server response message
    void ProcessServerResponse(const SKBinaryBuffer& server_response);

    // Process server response messae with transaction list initiaization
    void ProcessServerResponseBalance(const SKBinaryBuffer& server_response);

    // Get transaction list
    void GetTransactionList(SKBinaryBuffer& tx_list);

    // Get TUID request data
    void GetTUIDRequestData(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& tuid_request_data);

    // ProcessMsg TUID response data
    void ProcessTUIDResponseData(const SKBinaryBuffer& tuid_response_data, uint64_t& amount, uint64_t& ts, SKBinaryBuffer& cuid, SKBinaryBuffer& tuid, SKBinaryBuffer& ruid);

    // ProcessMsg balance update data
    void ProcessBalanceUpdateData(const SKBinaryBuffer& balance_update_data);

    // ProcessMsg TUID response
    void ProcessTUIDResponse(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Establish shared key
    void GetEstablishSharedKeyMsg(SKBinaryBuffer& msg_out);

    // Upload transaction list
    void GetUploadTransactionListMsg(SKBinaryBuffer& msg_out);

    // New transaction
    void GetNewTransactionMsg(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& msg_out);

public:

    // Class factory
    static SKSessionPtr Create(
        const SKCryptoPtr& spcrypto,
        const SKSecureStorePtr& spstore, 
        const SKRandomPtr& sprandom);

    // Destructor
    ~SKSessionOnline() {}

    // ProcessMsg message
    void ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out);

    // Start new online session with balance update
    void StartOnlineBalanceInitialization(SKBinaryBuffer& msg_out);

    // Start new online session
    void StartOnlineSession(SKBinaryBuffer& msg_out);

    // Start new online transaction
    void StartOnlineTransaction(const uint64_t amount, const SKBinaryBuffer& cuid, SKBinaryBuffer& msg_out);
};
