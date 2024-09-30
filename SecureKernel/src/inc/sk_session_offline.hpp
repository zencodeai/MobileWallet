#pragma once

#include "sk_session.hpp"

// Online session class
class SKSessionOffline : public SKSession
{

public:

    // Max key sharing massge size
    static const uint32_t MAX_KEY_SHARING_MSG_SIZE = 1024;

    // P2P nonce size
    static const uint32_t P2P_NONCE_SIZE = 32;

    // Receipt message size
    static const uint32_t RECEIPT_MSG_SIZE = NONCE_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE;

protected:

    // Transaction amount
    uint64_t m_amount;

    // Transaction timestamp
    uint64_t m_timestamp;

    // Counterparty's nonce
    SKBuffer32 m_counterparty_nonce;

    // Counterparty's iuid
    SKBuffer32 m_counterparty_iuid;

    // Transaction uid
    SKBuffer32 m_tuid;

    // Compute IV
    void ComputeSharedIV(const SKBuffer32& nonce, const SKBuffer32& iuid) {

        SKManagedSHA256Context ctx;
        SKBuffer32 hash;

        ctx.Start();
        ctx.Update(nonce);
        ctx.Update(iuid);
        ctx.Finish(hash);

        uint8_t* p = hash.GetBuffer();
        uint8_t* q = p + hash.GetCapacity() / 2;
        m_iv.SetSize(IV_SIZE);
        uint8_t* r = m_iv.GetBuffer();

        for (size_t i = 0; i < IV_SIZE; i++) {
            *r++ = *p++ ^ *q++;
        }
    }

    // Constructor
    SKSessionOffline(const SKInitContext& ctx) : SKSession(ctx) {}

public:

    // Destructor
    virtual ~SKSessionOffline() {}
};
