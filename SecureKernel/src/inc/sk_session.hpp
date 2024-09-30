#pragma once

#include "sk_utils.hpp"
#include "sk_crypto.hpp"
#include "sk_transaction_list.hpp"
#include "sk_x509.hpp"

// Online state class
class SKSessionState
{
protected:

    // State
    uint32_t m_state;

public:

    // Constructor
    SKSessionState(const uint32_t state = SK_ST_RESET) : m_state(state) {}

    // Copy constructor
    SKSessionState(const SKSessionState& other) : m_state(other.m_state) {}

    // Convert to uint32_t
    operator uint32_t() const { return m_state; }

    // Assignment operator
    SKSessionState& operator=(const SKSessionState& other) {
        m_state = other.m_state;
        return *this;
    }

    // Assignment operator (uint32_t)
    SKSessionState& operator=(const uint32_t state) {
        m_state = state;
        return *this;
    }
};

// SKSession class shared pointer
typedef std::shared_ptr<class SKSession> SKSessionPtr;

// Session class
class SKSession : public SKTransactionList
{
public:

    // Max SCDH params size
    static const size_t MAX_ECDH_PARAMS_SIZE = 256;

    // Nonce size
    static const size_t NONCE_SIZE = 32;

    // IV size
    static const size_t IV_SIZE = 16;

    // 32 bytes static buffer type
    typedef SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> SKBuffer32;

    // 16 bytes static buffer type
    typedef SKStaticBinaryBuffer<IV_SIZE> SKBuffer16;

    // 8 bytes static buffer type
    typedef SKStaticBinaryBuffer<sizeof(uint64_t)> SKBuffer8;

protected:

    // Initialization context
    struct SKInitContext
    {
        // Context parameters
        SKCryptoPtr m_spcrypto;
        SKSecureStorePtr m_spstore; 
        SKRandomPtr m_sprandom;
        SKStoreCryptoKeyPtr m_spkey_store;
        SKStoreCryptoKeyPtr m_spkey_tx_enc; 
        SKStoreCryptoKeyPtr m_spkey_tx_sig;
        SKStoreCryptoKeyPtr m_spkey_inst_sig;

        // Constructor
        SKInitContext(
            const SKCryptoPtr& spcrypto,
            const SKSecureStorePtr& spstore, 
            const SKRandomPtr& sprandom)
            : m_spcrypto(spcrypto), m_spstore(spstore), m_sprandom(sprandom), 
            m_spkey_store(nullptr), m_spkey_tx_enc(nullptr), m_spkey_tx_sig(nullptr), m_spkey_inst_sig(nullptr) {}

        // Load context
        void LoadContext() {

            // Get persistence key
            SKStoreKeyBuffer db_key_store(SK_DB_TX_PER_KEY_HEX);
            m_spkey_store = SKStoreCryptoKey::Load(*m_spstore, m_spcrypto, db_key_store);

            // Get transaction data encryption key
            SKStoreKeyBuffer db_key_tx_enc(SK_DB_TX_ENC_KEY_HEX);
            m_spkey_tx_enc = SKStoreCryptoKey::Load(*m_spstore, m_spcrypto, db_key_tx_enc);

            // Get transaction data signature key
            SKStoreKeyBuffer db_key_tx_sig(SK_DB_TX_SIG_KEY_HEX);
            m_spkey_tx_sig = SKStoreCryptoKey::Load(*m_spstore, m_spcrypto, db_key_tx_sig);

            // Get instance signature key
            SKStoreKeyBuffer db_key_inst_sig(SK_DB_INST_SIG_KEY_HEX);
            m_spkey_inst_sig = SKStoreCryptoKey::Load(*m_spstore, m_spcrypto, db_key_inst_sig);
        }
    };

    // Session state
    SKSessionState m_state;

    // Crypto module instance
    SKCryptoPtr m_spcrypto;

    // Secure channle key id
    SKCrypto::SKKeyId m_keyid_sc;

    // Counterparty certificate
    SKCertChainPtr m_spchain;

    // Session nonce
    SKBuffer32 m_nonce;

    // Session IV
    SKBuffer16 m_iv;

    // Instance signature key pair
    SKStoreCryptoKeyPtr m_spkey_inst_sig;

    // Compute IV
    void ComputeIV(SKBuffer32& iuid) {

        SKManagedSHA256Context ctx;
        SKBuffer32 hash;

        ctx.Start();
        ctx.Update(iuid);
        ctx.Update(m_nonce);
        ctx.Finish(hash);

        uint8_t* p = hash.GetBuffer();
        uint8_t* q = p + hash.GetCapacity() / 2;
        m_iv.SetSize(IV_SIZE);
        uint8_t* r = m_iv.GetBuffer();

        for (size_t i = 0; i < IV_SIZE; i++) {
            *r++ = *p++ ^ *q++;
        }
    }

    // Get 16 bits field length
    uint32_t GetFieldLength(const SKBinaryBuffer& buffer, uint32_t& offset) {

        SKBinaryBufferView len_net(offset, sizeof(uint16_t), buffer);

        const uint8_t* p = len_net.GetBuffer();
        const uint32_t len = (((uint32_t) p[0]) << 8) | p[1];

        offset += sizeof(uint16_t);
        return len;
    }

    // Add 16 bits field length
    void SetFieldLength(const uint32_t size, SKBinaryBuffer& buffer, uint32_t& offset) {

        SK_CHECK(size <= MAX_TRANSACTION_BUFFER_SIZE, SK_ERROR_P2P_MSG, "Invalid message");
        SKBinaryBufferView len_net(offset, sizeof(uint16_t), buffer);

        uint8_t* const p = len_net.GetBuffer();
        p[0] = (uint8_t) (size >> 8);
        p[1] = (uint8_t) size;

        offset += sizeof(uint16_t);
    }

    // Begin transaction
    void BeginTransaction() {

        m_spstore->BeginTransaction();
    }

    // Commit transaction
    void CommitTransaction() {

        m_spstore->CommitTransaction();
    }

    // Rollback transaction
    void RollbackTransaction() {

        m_spstore->RollbackTransaction();
    }

    // Verify certificate
    void VerifyCertificate(const SKCertChainPtr& spchain) {

        SKConstant<SK_ROOT_CERT_SIZE> cert(SK_ROOT_CERT);
        cert.Unmask(SKConstant<SK_ROOT_CERT_SIZE>(SK_ROOT_CERT_MASK));
        cert.VerifyHash(SKConstant<32>(SK_ROOT_CERT_CSUM));

        SKCertChain root;
        root.Parse(cert.GetBuffer());
        root.VerifyChain(*spchain);
    }

    // Constructor
    SKSession(const SKInitContext& ctx) : 
        m_spcrypto(ctx.m_spcrypto), m_keyid_sc(0), m_spkey_inst_sig(ctx.m_spkey_inst_sig), 
        SKTransactionList(ctx.m_spstore, ctx.m_sprandom, ctx.m_spkey_store, ctx.m_spkey_tx_enc, ctx.m_spkey_tx_sig) {}

public:

    // Destructor
    virtual ~SKSession() {}

    // Process message, update state and return response
    virtual void ProcessMsg(const SKBinaryBuffer& msg_in, SKBinaryBuffer& msg_out) = 0;
};
