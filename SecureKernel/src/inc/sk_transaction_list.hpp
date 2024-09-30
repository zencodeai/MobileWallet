#pragma once

#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"
#include "sk_persistence.hpp"

#include "mbedtls/sha256.h"

// Managed SHA256 context
class SKManagedSHA256Context {

public:

    // Digest size
    static const uint32_t DIGEST_SIZE = 32;

private:

    // SHA256 context
    mbedtls_sha256_context m_sha256_ctx;

public:

    // Constructor
    SKManagedSHA256Context() {
        mbedtls_sha256_init(&m_sha256_ctx);
    }

    // Destructor
    ~SKManagedSHA256Context() {
        mbedtls_sha256_free(&m_sha256_ctx);
    }

    // Start
    void Start() {
        int result = mbedtls_sha256_starts(&m_sha256_ctx, 0);
        SK_CHECK(result == 0, SK_ERROR_CATEGORY_MTLS, "mbedtls_sha256_starts failed");
    }

    // Update
    void Update(const SKBinaryBuffer& input) {
        int result = mbedtls_sha256_update(&m_sha256_ctx, input.GetBuffer(), input.GetSize());
        SK_CHECK(result == 0, SK_ERROR_CATEGORY_MTLS, "mbedtls_sha256_update failed");
    }

    // Finish
    void Finish(SKBinaryBuffer& output) {
        output.SetSize(DIGEST_SIZE);
        int result = mbedtls_sha256_finish(&m_sha256_ctx, output.GetBuffer());
        SK_CHECK(result == 0, SK_ERROR_CATEGORY_MTLS, "mbedtls_sha256_finish failed");
    }

    // Block SHA256
    static void BlockSHA256(const SKBinaryBuffer& input, SKBinaryBuffer& output) {
        output.SetSize(DIGEST_SIZE);
        int result = mbedtls_sha256(input.GetBuffer(), input.GetSize(), output.GetBuffer(), 0);
        SK_CHECK(result == 0, SK_ERROR_CATEGORY_MTLS, "mbedtls_sha256 failed");
    }
};

// Balance class
union SKBalance {

public:

    static const uint64_t MAX_AMOUNT = 1000000;

protected:

    union sk_amount_t {

        uint64_t amount_u;
        int64_t amount_s;

        sk_amount_t(int64_t amount) : amount_s(amount) {}
        sk_amount_t(uint64_t amount) : amount_u(amount) {}
        int64_t abs() { return amount_s < 0 ? -amount_s : amount_s; }
    };

    int64_t m_amount;

public:

    // To int64_t
    static inline int64_t to_int64_t(uint64_t amount) {

        sk_amount_t val(amount);
        SK_CHECK(val.abs() <= MAX_AMOUNT, SK_ERROR_TX_AMNT, "Invalid amount");
        return val.amount_s;
    }

    SKBalance(uint64_t amount = 0) {

        m_amount = to_int64_t(amount);
    }

    // Assign operator
    void operator = (uint64_t amount) {

        m_amount = to_int64_t(amount);
    }

    // Substract operator
    void operator -= (uint64_t amount) {

        m_amount -= to_int64_t(amount);
        SK_CHECK(m_amount >= 0, SK_ERROR_TX_AMNT, "Invalid amount");
    }

    // Add operator
    void operator += (uint64_t amount) {

        m_amount += to_int64_t(amount);
        SK_CHECK(m_amount >= 0, SK_ERROR_TX_AMNT, "Invalid amount");
    }

    // Negate operator
    void operator - () {

        m_amount = -m_amount;
    }

    // Get amount
    uint64_t GetAmount() {

        sk_amount_t val(m_amount);
        return val.amount_u;
    }

    // Convert to uint64_t
    operator uint64_t() {

        return GetAmount();
    }
};

// ----------------------------------------------------------------------------------------
// Transaction node structure:
//
// ---------------+------+--------------------------------------+----------------+---------
// Field          | Size | Description                          | Confidentality | Integrity
// ---------------+------+--------------------------------------+----------------+---------
// Balance/Amount | 8    | Balance/amount (big endian)          | Plain          | Checksum
// Timestamp      | 8    | Timestamp (big endian)               | Plain          | Checksum
// TUID           | 32   | Transaction unique identifier        | K.tr           | Checksum
// CUID           | 32   | Counterparty unique identifier       | K.tr           | Checksum
// RUID           | 32   | Transaction couterparty receipt      | K.tr           | Checksum
// PUID           | 32   | SHA256 of previous node (rnd if head)| K.tr           | Checksum
// Checksum       | 32   | SHA256 of all previous fields        | K.tr           | K.tr
// ---------------+------+--------------------------------------+----------------+---------
// Notes:
// TUID = Nonce.A ^ Nonce.B
// RUID = Receipt received from counterparty
// Commit takes place when TUID is validated by counterparty
// ----------------------------------------------------------------------------------------

class SKTransactionNode {

public:

    // Max amount
    static const uint64_t MAX_AMOUNT = SKBalance::MAX_AMOUNT;

    // Amount size
    static const uint32_t AMOUNT_SIZE = sizeof(uint64_t);

    // Timestamp size
    static const uint32_t TIMESTAMP_SIZE = sizeof(uint64_t);

    // Header size
    static const uint32_t HEADER_SIZE = AMOUNT_SIZE + TIMESTAMP_SIZE;

    // TUID size
    static const uint32_t TUID_SIZE = 32;

    // CUID size
    static const uint32_t CUID_SIZE = 32;

    // RUID size
    static const uint32_t RUID_SIZE = 32;

    // PUID size
    static const uint32_t PUID_SIZE = 32;

    // Checksum size
    static const uint32_t CHECKSUM_SIZE = 32;

    // Transaction node size
    static const uint32_t TRANSACTION_NODE_SIZE = AMOUNT_SIZE + TIMESTAMP_SIZE + TUID_SIZE + CUID_SIZE + RUID_SIZE + PUID_SIZE + CHECKSUM_SIZE;

protected:

    // Amount
    uint64_t m_amount;

    // Timestamp
    uint64_t m_timestamp;

    // Transaction unique identifier
    SKStaticBinaryBuffer<TUID_SIZE> m_tuid;

    // Counterparty unique identifier
    SKStaticBinaryBuffer<CUID_SIZE> m_cuid;

    // Counterparty receipt
    SKStaticBinaryBuffer<RUID_SIZE> m_ruid;

    // Previous node unique identifier
    SKStaticBinaryBuffer<PUID_SIZE> m_puid;

    // Checksum
    SKStaticBinaryBuffer<CHECKSUM_SIZE> m_checksum;

public:

    // integer to network order binary
    template <typename T> static void int_to_binary(T val, SKBinaryBuffer& output) {

        // Check size
        SK_CHECK(sizeof(T) == 4 || sizeof(T) == 8, SK_ERROR_INVALID_PARAMETER, "Invalid size");

        output.SetSize(sizeof(T));
        uint8_t* buff = output.GetBuffer();

        if (sizeof(T) == 8) {

            buff[7] = (uint8_t) val;
            val >>= 8;
            buff[6] = (uint8_t) val;
            val >>= 8;
            buff[5] = (uint8_t) val;
            val >>= 8;
            buff[4] = (uint8_t) val;
            val >>= 8;
        }

        buff[3] = (uint8_t) val;
        val >>= 8;
        buff[2] = (uint8_t) val;
        val >>= 8;
        buff[1] = (uint8_t) val;
        val >>= 8;
        buff[0] = (uint8_t) val;
    } 

    // Network order binary to integer
    template <typename T> static void binary_to_int(const SKBinaryBuffer& input, T& val) {

        // Check size
        SK_CHECK(sizeof(T) == 4 || sizeof(T) == 8, SK_ERROR_INVALID_PARAMETER, "Invalid size");
        SK_CHECK(input.GetSize() == sizeof(T), SK_ERROR_INVALID_PARAMETER, "Invalid size");

        const uint8_t* buff = input.GetBuffer();

        val = buff[0];
        val = (val << 8) | buff[1];
        val = (val << 8) | buff[2];
        val = (val << 8) | buff[3];

        if (sizeof(T) == 8) {

            val = (val << 8) | buff[4];
            val = (val << 8) | buff[5];
            val = (val << 8) | buff[6];
            val = (val << 8) | buff[7];            
        }
    }

    // Compute checksum
    void ComputeChecksum(SKBinaryBuffer& checksum);

    // Verify checksum
    void VerifyChecksum();

    // Constructor
    SKTransactionNode(const uint64_t amount) : m_amount(amount) {

        // Check amount
        SKBalance balance(amount);
    
        // Get timestamp
        m_timestamp = SKUtils::GetTimestamp();

        // Update TUID size
        m_tuid.SetSize(TUID_SIZE);

        // Update CUID size
        m_cuid.SetSize(CUID_SIZE);

        // Update RUID size
        m_ruid.SetSize(RUID_SIZE);

        // Update PUID size
        m_puid.SetSize(PUID_SIZE);

        // Compute checksum
        ComputeChecksum(m_checksum);
    }

    // Constructor
    SKTransactionNode(
        const uint64_t amount, 
        const uint64_t timestamp, 
        const SKBinaryBuffer& cuid, 
        const SKBinaryBuffer& tuid, 
        const SKBinaryBuffer& ruid) : m_amount(amount), m_timestamp(timestamp), m_cuid(cuid), m_tuid(tuid), m_ruid(ruid) {

        // Check amount
        SKBalance balance(amount);

        // Get timestamp
        m_timestamp = SKUtils::GetTimestamp();

        // Update PUID size
        m_puid.SetSize(PUID_SIZE);

        // Checksum updated added whaen PUID is updated
    }

    // Get amount
    uint64_t GetAmount() const {
        return m_amount;
    }

    // Get timestamp
    uint64_t GetTimestamp() const {
        return m_timestamp;
    }

    // Update TUID
    void UpdateTUID(const SKBinaryBuffer& tuid) {

        // Check size
        SK_CHECK(tuid.GetSize() == TUID_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid size");

        // Update TUID
        m_tuid = tuid;

        // Compute checksum
        ComputeChecksum(m_checksum);
    }

    // Update CUID
    void UpdateCUID(const SKBinaryBuffer& cuid) {

        // Check size
        SK_CHECK(cuid.GetSize() == CUID_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid size");

        // Update CUID
        m_cuid = cuid;

        // Compute checksum
        ComputeChecksum(m_checksum);
    }

    // Update RUID
    void UpdateRUID(const SKBinaryBuffer& ruid) {

        // Check size
        SK_CHECK(ruid.GetSize() == RUID_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid size");

        // Update RUID
        m_ruid = ruid;

        // Compute checksum
        ComputeChecksum(m_checksum);
    }

    // Update PUID
    void UpdatePUID(const SKBinaryBuffer& puid) {

        // Check size
        SK_CHECK(puid.GetSize() == PUID_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid size");

        // Update PUID
        m_puid = puid;

        // Compute checksum
        ComputeChecksum(m_checksum);
    }

    // Serialize transaction data
    void Serialize(SKBinaryBuffer& buffer);
};

// Transactions list
class SKTransactionList : protected SKStoreList {

public:

    // IUID size
    static const uint32_t IUID_SIZE = 32;

    // Max transaction list size
    static const uint32_t MAX_TRANSACTION_LIST_SIZE = 128;

    // Max ECDSA P-256 signature size including padding
    static const uint32_t MAX_ECDSA_P256_SIGNATURE_SIZE = 80;

    // Max transaction buffer size
    static const uint32_t MAX_TRANSACTION_BUFFER_SIZE = IUID_SIZE + MAX_TRANSACTION_LIST_SIZE * SKTransactionNode::TRANSACTION_NODE_SIZE + MAX_ECDSA_P256_SIGNATURE_SIZE;

    // Tag size
    static const uint32_t TAG_SIZE = 16;

    // Block size
    static const uint32_t BLOCK_SIZE = 16;

protected:

    // SHA256 context
    SKManagedSHA256Context m_sha256_ctx;

    // Transaction encryption key
    SKStoreCryptoKeyPtr m_spkey_tx_enc;

    // Transaction list signature key
    SKStoreCryptoKeyPtr m_spkey_tx_sig;

    // PUID
    SKStaticBinaryBuffer<SKTransactionNode::PUID_SIZE> m_puid;

    // Encrypt transcation data
    void EncryptTransactionData(const SKBinaryBuffer& tx_data, SKBinaryBuffer& tx_data_enc);

    // Add padding
    void AddPadding(SKBinaryBuffer& buff);

    // Remove padding
    void RemovePadding(SKBinaryBuffer& buff);

public:

    // Constructor
    SKTransactionList(
        const SKSecureStorePtr& spstore, 
        const SKRandomPtr& sprandom, 
        const SKStoreCryptoKeyPtr& spkey,
        const SKStoreCryptoKeyPtr& spkey_tx_enc, 
        const SKStoreCryptoKeyPtr& spkey_tx_sig) : 
        SKStoreList(spstore, sprandom, spkey),
        m_spkey_tx_enc(spkey_tx_enc), 
        m_spkey_tx_sig(spkey_tx_sig) {}

    // Initialize transaction list
    void Initialize(const SKBinaryBuffer& balance_data);

    // Get balance
    uint64_t GetBalance();

    // Add transaction
    void AddTransaction(SKTransactionNode& tx_node);

    // Get transactions data
    void GetTransactionsData(SKBinaryBuffer& tx_data);
};
