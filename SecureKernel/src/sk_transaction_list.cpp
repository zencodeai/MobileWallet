#include "sk_utils.hpp"
#include "sk_transaction_list.hpp"

// update checksum
void SKTransactionNode::ComputeChecksum(SKBinaryBuffer& checksum) {

    // Managed SHA256 context
    SKManagedSHA256Context sha256_ctx;

    // Start
    sha256_ctx.Start();

    // Amount to network byte order
    SKStaticBinaryBuffer<AMOUNT_SIZE> amount_buffer;
    int_to_binary(m_amount, amount_buffer);

    // Timestamp to network byte order
    SKStaticBinaryBuffer<TIMESTAMP_SIZE> timestamp_buffer;
    int_to_binary(m_timestamp, timestamp_buffer);

    // Update
    sha256_ctx.Update(amount_buffer);
    sha256_ctx.Update(timestamp_buffer);
    sha256_ctx.Update(m_tuid);
    sha256_ctx.Update(m_cuid);
    sha256_ctx.Update(m_ruid);
    sha256_ctx.Update(m_puid);

    // Finish
    sha256_ctx.Finish(checksum);
}

// Verify checksum
void SKTransactionNode::VerifyChecksum() {

    // Compute checksum
    SKStaticBinaryBuffer<CHECKSUM_SIZE> checksum;
    ComputeChecksum(checksum);

    // Verify against m_checksum in constant time
    uint32_t result = 0;
    uint8_t* p = checksum.GetBuffer();
    uint8_t* q = m_checksum.GetBuffer();

    for(uint32_t i = 0; i < CHECKSUM_SIZE; ++i, ++p, ++q) {
        result |= *p ^ *q;
    }

    // Check result
    SK_CHECK(result == 0, SK_ERROR_TX_CHKS, "Invalid checksum");
}

// Serialize transaction node
void SKTransactionNode::Serialize(SKBinaryBuffer& buffer) {

    // Update checksum
    VerifyChecksum();

    // Amount to network byte order
    SKStaticBinaryBuffer<AMOUNT_SIZE> amount_buffer;
    int_to_binary(m_amount, amount_buffer);

    // Timestamp to network byte order
    SKStaticBinaryBuffer<TIMESTAMP_SIZE> timestamp_buffer;
    int_to_binary(m_timestamp, timestamp_buffer);

    // Set ouput buffer size
    buffer.SetSize(TRANSACTION_NODE_SIZE);
    buffer.UpdateSize(0);

    // Serialize data
    buffer += amount_buffer;
    buffer += timestamp_buffer;
    buffer += m_tuid;
    buffer += m_cuid;
    buffer += m_ruid;
    buffer += m_puid;
    buffer += m_checksum;
}

// Encrypt transcation data
void SKTransactionList::EncryptTransactionData(const SKBinaryBuffer& tx_data, SKBinaryBuffer& tx_data_enc) {

    // Get IV from masked SK_STORE_TX_IV
    SKConstant<SK_STORE_TX_IV_SIZE> iv(SK_STORE_TX_IV);
    iv.Unmask(SKConstant<SK_STORE_TX_IV_SIZE>(SK_STORE_TX_IV_MASK));
    iv.VerifyHash(SKConstant<32>(SK_STORE_TX_IV_CSUM));

    // Key id
    const SKCrypto::SKKeyId key_id = *m_spkey_tx_enc;

    // Crypto object
    const SKCryptoPtr& spcrypto = *m_spkey_tx_enc;

    // Get header
    const uint32_t header_size = SKTransactionNode::AMOUNT_SIZE + SKTransactionNode::TIMESTAMP_SIZE;
    SKBinaryBufferView header(0, header_size, tx_data);

    // Get plain text to encrypt
    const uint32_t plain_size = SKTransactionNode::TRANSACTION_NODE_SIZE - header_size;
    SKBinaryBufferView plain(header_size, plain_size, tx_data);

    // Encrypt value
    SKStaticBinaryBuffer<plain_size> cipher;
    spcrypto->AES128CBCEncrypt(
        key_id,
        iv.GetBuffer(),
        plain,
        cipher);

    tx_data_enc.SetSize(SKTransactionNode::TRANSACTION_NODE_SIZE);
    tx_data_enc.UpdateSize(0);
    tx_data_enc += header;
    tx_data_enc += cipher;
}

// Add padding
void SKTransactionList::AddPadding(SKBinaryBuffer& buff) {

    // Get padding size
    const uint32_t padding_size = BLOCK_SIZE - (buff.GetSize() % BLOCK_SIZE);

    // Check capacity
    const uint32_t padded_size = buff.GetSize() + padding_size;
    SK_CHECK(buff.GetCapacity() >= padded_size, SK_ERROR_BUFFER_OVERFLOW, "Invalid padding");

    // Add padding
    memset(buff.GetBuffer() + buff.GetSize(), (uint8_t) padding_size, padding_size);
    buff.UpdateSize(padded_size);
}

// Remove padding
void SKTransactionList::RemovePadding(SKBinaryBuffer& buff) {

    // Check size
    const uint32_t padded_size = buff.GetSize();
    SK_CHECK(padded_size >= BLOCK_SIZE && !(padded_size % BLOCK_SIZE), SK_ERROR_TX_PADD, "Invalid padding");

    // Get padding size
    const uint32_t padding_size = buff.GetBuffer()[padded_size - 1];
    SK_CHECK(padding_size && padding_size <= BLOCK_SIZE, SK_ERROR_TX_PADD, "Invalid padding");

    // Update size
    buff.UpdateSize(buff.GetSize() - padding_size);
}

// Initialize transaction list
void SKTransactionList::Initialize(const SKBinaryBuffer& balance_data) {

    SKManagedSHA256Context sha256_ctx;

    // Check size
    SK_CHECK(balance_data.GetSize() == SKTransactionNode::TRANSACTION_NODE_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid size");

    // DB keys
    SKStoreKeyBuffer db_key_head_val(SK_DB_TX_HEAD_VAL_HEX);
    SKStoreKeyBuffer db_key_head_tag(SK_DB_TX_HEAD_TAG_HEX);
    SKStoreKeyBuffer db_key_sig_val(SK_DB_TX_SIG_VAL_HEX);
    SKStoreKeyBuffer db_key_sig_tag(SK_DB_TX_SIG_TAG_HEX);
    SKStoreKeyBuffer db_key_iuid_val(SK_DB_TX_IUID_VAL_HEX);
    SKStoreKeyBuffer db_key_iuid_tag(SK_DB_TX_IUID_TAG_HEX);

    // Delete existing list
    Delete(db_key_head_val, db_key_head_tag);

    // Create db keys for head
    SKDBKeyBuffer db_key_data_val;
    SKDBKeyBuffer db_key_data_tag;

    GenerateDBKey(db_key_data_val);
    GenerateDBKey(db_key_data_tag);

    // Get instance UID
    SKStaticBinaryBuffer<IUID_SIZE> iuid;
    SKStoreValuePtr spiuid = SKStoreValue::Load(*m_spstore, m_spkey, db_key_iuid_val, db_key_iuid_tag);
    spiuid->Decrypt(iuid);

    // Compute hash
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> digest;
    sha256_ctx.Start();
    sha256_ctx.Update(iuid);
    sha256_ctx.Update(balance_data);
    sha256_ctx.Finish(digest);

    // Store data
    SKStoreValue::Store(*m_spstore, m_spkey, db_key_data_val, db_key_data_tag, balance_data);

    // Compute signature
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> signature;
    SKCryptoPtr spcrypto = *m_spkey_tx_sig;
    spcrypto->ECDSAP256DigestSign(*m_spkey_tx_sig, digest, signature);

    // Store signature
    AddPadding(signature);
    SKStoreValue::Store(*m_spstore, m_spkey, db_key_sig_val, db_key_sig_tag, signature);

    // Initialize list
    SKStoreList::Initialize(db_key_head_val, db_key_head_tag, db_key_data_val, db_key_data_tag);
}

// Get balance
uint64_t SKTransactionList::GetBalance() {

    SKBalance balance;
    uint64_t timestamp_last = 0;
    const uint64_t timestamp_cur = SKUtils::GetTimestamp();
    bool start = true;
    SKManagedSHA256Context sha256_ctx;

    // DB keys
    SKStoreKeyBuffer db_key_head_val(SK_DB_TX_HEAD_VAL_HEX);
    SKStoreKeyBuffer db_key_head_tag(SK_DB_TX_HEAD_TAG_HEX);
    SKStoreKeyBuffer db_key_sig_val(SK_DB_TX_SIG_VAL_HEX);
    SKStoreKeyBuffer db_key_sig_tag(SK_DB_TX_SIG_TAG_HEX);
    SKStoreKeyBuffer db_key_iuid_val(SK_DB_TX_IUID_VAL_HEX);
    SKStoreKeyBuffer db_key_iuid_tag(SK_DB_TX_IUID_TAG_HEX);

    // Initialize hash contexts
    m_sha256_ctx.Start();
    sha256_ctx.Start();

    // Get instance UID
    SKStaticBinaryBuffer<IUID_SIZE> iuid;
    SKStoreValuePtr spiuid = SKStoreValue::Load(*m_spstore, m_spkey, db_key_iuid_val, db_key_iuid_tag);
    spiuid->Decrypt(iuid);

    m_sha256_ctx.Update(iuid);
    sha256_ctx.Update(iuid);

    // Iterate
    SKDBKeyBuffer db_key_data_val;
    SKDBKeyBuffer db_key_data_tag;
    SKStaticBinaryBuffer<SKTransactionNode::TRANSACTION_NODE_SIZE> data;
    SKStoreValuePtr spnode; 

    Start(db_key_head_val, db_key_head_tag);

    do {
        // Get node
        spnode = Next(db_key_data_val, db_key_data_tag);

        // Load data
        SKStoreValuePtr spdata = SKStoreValue::Load(*m_spstore, m_spkey, db_key_data_val, db_key_data_tag);

        // Decrypt data
        spdata->Decrypt(data);

        // Get amount
        SKStaticBinaryBuffer<SKTransactionNode::AMOUNT_SIZE> amount_buffer;
        data.Extract(0, SKTransactionNode::AMOUNT_SIZE, amount_buffer);
        uint64_t amount = 0;
        SKTransactionNode::binary_to_int(amount_buffer, amount);

        SK_CHECK(amount > 0, SK_ERROR_TX_AMNT, "Invalid amount");

        // Get timestamp
        SKStaticBinaryBuffer<SKTransactionNode::TIMESTAMP_SIZE> timestamp_buffer;
        data.Extract(SKTransactionNode::AMOUNT_SIZE, SKTransactionNode::TIMESTAMP_SIZE, timestamp_buffer);
        uint64_t timestamp = 0;
        SKTransactionNode::binary_to_int(timestamp_buffer, timestamp);

        if (start) {

            balance = amount;
            timestamp_last = timestamp;
            start = false;

        } else {

            // Check and update balance
            balance -= amount;

            // Check timestamp
            SK_CHECK(timestamp_last < timestamp, SK_ERROR_TX_TIME, "Invalid timestamp");
            SK_CHECK(timestamp_cur > timestamp, SK_ERROR_TX_TIME, "Invalid timestamp");
            timestamp_last = timestamp;
        }

        // Update digests
        m_sha256_ctx.Update(data);
        sha256_ctx.Update(data);
    }
    while(spnode);

    // Compute digest
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> digest;
    sha256_ctx.Finish(digest);

    // Get signature
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> signature;
    SKStoreValuePtr spsig = SKStoreValue::Load(*m_spstore, m_spkey, db_key_sig_val, db_key_sig_tag);
    spsig->Decrypt(signature);
    RemovePadding(signature);

    // Verify signature
    SKCryptoPtr spcrypto = *m_spkey_tx_sig;
    spcrypto->ECDSAP256DigestVerify(*m_spkey_tx_sig, digest, signature);

    // Update state
    SKManagedSHA256Context::BlockSHA256(data, m_puid);

    // Return balance
    return balance;
}

// Add transaction
void SKTransactionList::AddTransaction(SKTransactionNode& tx_node) {

    // Set PIUD
    tx_node.UpdatePUID(m_puid);

    // Serialize transaction data
    SKStaticBinaryBuffer<SKTransactionNode::TRANSACTION_NODE_SIZE> tx_data;
    tx_node.Serialize(tx_data);

    // Encrypt transaction data
    SKStaticBinaryBuffer<SKTransactionNode::TRANSACTION_NODE_SIZE> tx_data_enc;
    EncryptTransactionData(tx_data, tx_data_enc);

    // Get digest
    SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> digest;
    m_sha256_ctx.Update(tx_data_enc);
    m_sha256_ctx.Finish(digest);

    // Compute signature
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> signature;
    SKCryptoPtr spcrypto = *m_spkey_tx_sig;
    spcrypto->ECDSAP256DigestSign(*m_spkey_tx_sig, digest, signature);

    // Create db keys for the new node
    SKDBKeyBuffer db_key_data_val;
    SKDBKeyBuffer db_key_data_tag;

    GenerateDBKey(db_key_data_val);
    GenerateDBKey(db_key_data_tag);

    // Store data
    SKStoreValue::Store(*m_spstore, m_spkey, db_key_data_val, db_key_data_tag, tx_data_enc);

    // Store signature
    SKStoreKeyBuffer db_key_sig_val(SK_DB_TX_SIG_VAL_HEX);
    SKStoreKeyBuffer db_key_sig_tag(SK_DB_TX_SIG_TAG_HEX);

    AddPadding(signature);
    SKStoreValue::Store(*m_spstore, m_spkey, db_key_sig_val, db_key_sig_tag, signature);

    // Add node to list
    Add(db_key_data_val, db_key_data_tag);
}

// Get transactions data
void SKTransactionList::GetTransactionsData(SKBinaryBuffer& tx_data) {

    // DB keys
    SKStoreKeyBuffer db_key_head_val(SK_DB_TX_HEAD_VAL_HEX);
    SKStoreKeyBuffer db_key_head_tag(SK_DB_TX_HEAD_TAG_HEX);
    SKStoreKeyBuffer db_key_sig_val(SK_DB_TX_SIG_VAL_HEX);
    SKStoreKeyBuffer db_key_sig_tag(SK_DB_TX_SIG_TAG_HEX);
    SKStoreKeyBuffer db_key_iuid_val(SK_DB_TX_IUID_VAL_HEX);
    SKStoreKeyBuffer db_key_iuid_tag(SK_DB_TX_IUID_TAG_HEX);

    // Start iteration
    tx_data.UpdateSize(0);
    Start(db_key_head_val, db_key_head_tag);

    // Add instance UID
    SKStaticBinaryBuffer<IUID_SIZE> iuid;
    SKStoreValuePtr spiuid = SKStoreValue::Load(*m_spstore, m_spkey, db_key_iuid_val, db_key_iuid_tag);
    spiuid->Decrypt(iuid);

    tx_data += iuid;

    // Iterate
    SKDBKeyBuffer db_key_data_val;
    SKDBKeyBuffer db_key_data_tag;
    SKStaticBinaryBuffer<SKTransactionNode::TRANSACTION_NODE_SIZE> data;
    SKStoreValuePtr spnode; 
    
    do {
        // Get node
        spnode = Next(db_key_data_val, db_key_data_tag);

        // Load data
        SKStoreValuePtr spdata = SKStoreValue::Load(*m_spstore, m_spkey, db_key_data_val, db_key_data_tag);

        // Decrypt data
        spdata->Decrypt(data);

        // Append data
        tx_data += data;
    }
    while(spnode);

    // Get signature
    SKStaticBinaryBuffer<MAX_ECDSA_P256_SIGNATURE_SIZE> signature;
    SKStoreValuePtr spsig = SKStoreValue::Load(*m_spstore, m_spkey, db_key_sig_val, db_key_sig_tag);
    spsig->Decrypt(signature);

    // Append signature
    RemovePadding(signature);
    tx_data += signature;
}
