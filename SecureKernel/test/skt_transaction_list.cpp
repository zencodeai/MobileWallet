#include <iostream>
#include <map>
#include <list>
#include <memory>

#include "skt_utils.hpp"
#include "sk_transaction_list.hpp"

// Transaction node
class SKTransactionNodeTest : public SKTransactionNode {

public:

    // Constructor
    SKTransactionNodeTest(uint64_t amount) : SKTransactionNode(amount) {}

    // Deserailization constructor
    SKTransactionNodeTest(const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& buffer) : SKTransactionNode(0) {

        Deserialize(spcrypto, key_id, buffer);
    }

    // Deserialize transaction node
    void Deserialize(const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id, const SKBinaryBuffer& buffer) {

        SKStaticBinaryBuffer<AMOUNT_SIZE> amount_buffer;
        SKStaticBinaryBuffer<TIMESTAMP_SIZE> timestamp_buffer;
        SKStaticBinaryBuffer<CHECKSUM_SIZE> checksum;

        // Check data size
        SK_CHECK(buffer.GetSize() == TRANSACTION_NODE_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid size");

        // Get IV from masked SK_STORE_TX_IV
        SKConstant<SK_STORE_TX_IV_SIZE> iv(SK_STORE_TX_IV);
        iv.Unmask(SKConstant<SK_STORE_TX_IV_SIZE>(SK_STORE_TX_IV_MASK));
        iv.VerifyHash(SKConstant<32>(SK_STORE_TX_IV_CSUM));

        // Decrypt data
        const uint32_t header_size = AMOUNT_SIZE + TIMESTAMP_SIZE;
        SKBinaryBufferView tx_header(0, header_size, buffer);
        SKBinaryBufferView tx_cipher(header_size, TRANSACTION_NODE_SIZE - header_size, buffer);
        SKDynamicBinaryBuffer tx_plain;
        spcrypto->AES128CBCDecrypt(
            key_id,
            iv.GetBuffer(),
            tx_cipher,
            tx_plain);

        SKDynamicBinaryBuffer tx_data(TRANSACTION_NODE_SIZE);
        tx_data.UpdateSize(0);
        tx_data += tx_header;
        tx_data += tx_plain;

        // Deserialize data
        tx_data.Extract(0, AMOUNT_SIZE, amount_buffer);
        uint32_t offset = AMOUNT_SIZE;
        tx_data.Extract(offset, TIMESTAMP_SIZE, timestamp_buffer);
        offset += TIMESTAMP_SIZE;
        tx_data.Extract(offset, TUID_SIZE, m_tuid);
        offset += TUID_SIZE;
        tx_data.Extract(offset, CUID_SIZE, m_cuid);
        offset += CUID_SIZE;
        tx_data.Extract(offset, RUID_SIZE, m_ruid);
        offset += RUID_SIZE;
        tx_data.Extract(offset, PUID_SIZE, m_puid);
        offset += PUID_SIZE;
        tx_data.Extract(offset, CHECKSUM_SIZE, checksum);

        // Amount from network byte order
        binary_to_int(amount_buffer, m_amount);

        // Timestamp from network byte order
        binary_to_int(timestamp_buffer, m_timestamp);

        // Update checksum
        ComputeChecksum(m_checksum);

        // Verify checksum
        SK_CHECK(m_checksum == checksum, SK_ERROR_INVALID_PARAMETER, "Invalid checksum");
    }

    // Compare nodes
    bool operator==(const SKTransactionNodeTest& node) const {

        return m_checksum == node.m_checksum;
    }
};

// Test persistence class (list)
class SKTTestTransactionList : public SKTTestCrypto {

public:

    // Test transation nodes count
    static const uint32_t TEST_TX_NODES_COUNT = 10;

private:

    // Transaction node shared pointer type
    typedef std::shared_ptr<class SKTransactionNodeTest> SKTransactionNodePtr;

    // 32 bytes static buffer type
    typedef SKStaticBinaryBuffer<SKManagedSHA256Context::DIGEST_SIZE> SKBuffer;

    // Transaction node list
    std::list<SKTransactionNodePtr> m_tx_list;

    // Fill buffer with random data
    void FillBuffer(SKBinaryBuffer& buffer) {

        GenerateRandomData(buffer.GetCapacity(), buffer);
    }

    // Generate random transaction node
    SKTransactionNodePtr GenerateRandomNode(uint64_t amount) {

        // Create node
        SKTransactionNodePtr spnode(new SKTransactionNodeTest(amount));

        // Fill node
        SKBuffer tuid;
        SKBuffer cuid;
        SKBuffer ruid;

        FillBuffer(tuid);
        FillBuffer(cuid);
        FillBuffer(ruid);

        spnode->UpdateTUID(tuid);
        spnode->UpdateCUID(cuid);
        spnode->UpdateRUID(ruid);

        return spnode;
    }    

    // Generate list of random transaction nodes
    void GenerateRandomList(uint32_t count = TEST_TX_NODES_COUNT, uint64_t amount_max = 100) {

        // Balance
        const uint64_t balance = count * amount_max;

        // Clear list
        m_tx_list.clear();

        // Head node
        m_tx_list.push_back(GenerateRandomNode(balance));
    
        // Generate nodes
        for (uint32_t i = 0; i < count; ++i) {
            m_tx_list.push_back(GenerateRandomNode(GenerateRandomInt(1, amount_max)));
        }
    }

    // Encrypt node
    void EncryptNode(const SKCrypto::SKKeyId key_id, const SKTransactionNodePtr& spnode, SKBinaryBuffer& tx_cipher) {

        // Get IV from masked SK_WRAPPING_IV
        SKConstant<SK_STORE_TX_IV_SIZE> iv(SK_STORE_TX_IV);
        iv.Unmask(SKConstant<SK_STORE_TX_IV_SIZE>(SK_STORE_TX_IV_MASK));
        iv.VerifyHash(SKConstant<32>(SK_STORE_TX_IV_CSUM));

        // Serialize node
        SKDynamicBinaryBuffer tx_data;
        spnode->Serialize(tx_data);
    
        // Get header
        const uint32_t header_size = SKTransactionNode::AMOUNT_SIZE + SKTransactionNode::TIMESTAMP_SIZE;
        SKStaticBinaryBuffer<header_size> header;
        tx_data.Extract(0, header_size, header);

        // Get plain text to encrypt
        const uint32_t plain_size = SKTransactionNode::TRANSACTION_NODE_SIZE - header_size;
        SKStaticBinaryBuffer<plain_size> plain;
        tx_data.Extract(header_size, plain_size, plain);

        // Encrypt value
        SKStaticBinaryBuffer<plain_size> cipher;
        spcrypto->AES128CBCEncrypt(
            key_id,
            iv.GetBuffer(),
            plain,
            cipher);

        tx_cipher.SetSize(SKTransactionNode::TRANSACTION_NODE_SIZE);
        tx_cipher.UpdateSize(0);
        tx_cipher += header;
        tx_cipher += cipher;
    }

    // Get test data balance
    uint64_t GetBalance() {

        // Get balance
        uint64_t balance  = m_tx_list.front()->GetAmount();

        // Iterate over nodes
        auto it = m_tx_list.begin();
        ++it;
        for (; it != m_tx_list.end(); ++it) {

            balance -= (*it)->GetAmount();
        }

        return balance;
    }

    // Run test
    virtual void RunTest();
};

// Run test
void SKTTestTransactionList::RunTest() {

    SKBuffer iuid;
    SKCrypto::SKKeyId key_id;
    SKCrypto::SKKeyId key_id_tx_enc;
    SKCrypto::SKKeyId key_id_tx_sig;
    SKStoreCryptoKeyPtr spkey;
    SKStoreCryptoKeyPtr spkey_tx_enc;
    SKStoreCryptoKeyPtr spkey_tx_sig; 

    // Generate keys
    spcrypto->AES128GCMGenerateKey(key_id);
    spcrypto->AES128GCMGenerateKey(key_id_tx_enc);
    spcrypto->ECDSAP256GenerateKeyPair(key_id_tx_sig);

    // Store keys
    SKStoreList::SKStoreKeyBuffer db_key(SK_DB_TX_PER_KEY_HEX);
    spkey = SKStoreCryptoKey::Store(*spstore, spcrypto, key_id, db_key);

    SKStoreList::SKStoreKeyBuffer db_key_tx_enc(SK_DB_TX_ENC_KEY_HEX);
    spkey_tx_enc = SKStoreCryptoKey::Store(*spstore, spcrypto, key_id_tx_enc, db_key_tx_enc);

    SKStoreList::SKStoreKeyBuffer db_key_tx_sig(SK_DB_TX_SIG_KEY_HEX);
    spkey_tx_sig = SKStoreCryptoKey::Store(*spstore, spcrypto, key_id_tx_sig, db_key_tx_sig);

    // Store IUID
    FillBuffer(iuid);
    SKStoreList::SKStoreKeyBuffer db_iuid_val(SK_DB_TX_IUID_VAL_HEX);
    SKStoreList::SKStoreKeyBuffer db_iuid_tag(SK_DB_TX_IUID_TAG_HEX);
    SKStoreValue::Store(*spstore, spkey, db_iuid_val, db_iuid_tag, iuid);

    // Instantiate transaction list
    SKTransactionList tx_list(spstore, sprandom, spkey, spkey_tx_enc, spkey_tx_sig);

    // Execute 10 times
    for (int i = 0; i < 1; ++i) {

        // Generate random transactions list
        GenerateRandomList();

        // Serialize and encryt head
        SKDynamicBinaryBuffer tx_balance_data;
        EncryptNode(key_id_tx_enc, m_tx_list.front(), tx_balance_data);

        // Initialize transaction list
        tx_list.Initialize(tx_balance_data);

        // Iterate over nodes
        auto it = m_tx_list.begin();
        uint64_t balance = (*it)->GetAmount();
        ++it;

        for (; it != m_tx_list.end(); ++it) {

            // Get balance
            uint64_t balance_list = tx_list.GetBalance();
            SK_CHECK(balance_list == balance, SK_ERROR_FAILED, "Balance mismatch");

            // Add transaction
            tx_list.AddTransaction(**it);

            // Update balance
            balance -= (*it)->GetAmount();
        }

        // Get transaction list
        SKDynamicBinaryBuffer tx_list_data(SKTransactionList::MAX_TRANSACTION_BUFFER_SIZE);
        tx_list.GetTransactionsData(tx_list_data);

        // Compute transaction count
        const uint32_t tx_size = tx_list_data.GetSize();
        const uint32_t tx_pad_size = SKTransactionList::BLOCK_SIZE - (tx_size % SKTransactionList::BLOCK_SIZE);
        const uint32_t tx_sig_size = SKTransactionList::MAX_ECDSA_P256_SIGNATURE_SIZE - tx_pad_size;
        const uint32_t tx_count = (tx_size - tx_sig_size - SKTransactionList::IUID_SIZE) / SKTransactionNode::TRANSACTION_NODE_SIZE;
        SK_CHECK(tx_count == TEST_TX_NODES_COUNT + 1, SK_ERROR_FAILED, "Invalid transaction count");

        // Verify signature
        const uint32_t tx_sig_offset = tx_size - tx_sig_size;
        SKBinaryBufferView tx_signature(tx_sig_offset, tx_sig_size, tx_list_data);
        SKBinaryBufferView tx_data(0, tx_sig_offset, tx_list_data);

        spcrypto->ECDSAP256Verify(key_id_tx_sig, tx_data, tx_signature);

        // Check IUID
        SKBinaryBufferView tx_iuid(0, SKTransactionList::IUID_SIZE, tx_list_data);
        SK_CHECK(tx_iuid == iuid, SK_ERROR_FAILED, "Invalid IUID");

        // Iterate over nodes
        int32_t offset = SKTransactionList::IUID_SIZE;
        for (it = m_tx_list.begin(); it != m_tx_list.end(); ++it) {

            // Get transaction node
            SKBinaryBufferView tx_node(offset, SKTransactionNode::TRANSACTION_NODE_SIZE, tx_list_data);

            // Deserialize node
            SKTransactionNodeTest node(spcrypto, key_id_tx_enc, tx_node);

            // Compare nodes
            SK_CHECK(node == **it, SK_ERROR_FAILED, "Invalid transaction node");

            // Update offset
            offset += SKTransactionNode::TRANSACTION_NODE_SIZE;
        }
    }
}

// Entry point.
int test_skt_transaction_list(int, char*[]) {
    
    // Create test
    SKTTestTransactionList test;
    return test.Run();
}
