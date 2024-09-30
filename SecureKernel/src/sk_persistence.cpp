#include "sk_persistence.hpp"

// Load from store
SKStoreCryptoKeyPtr SKStoreCryptoKey::Load(SKSecureStore& store, const SKCryptoPtr& spcrypto, const char* key) {

    // Key blob
    SKStaticBinaryBuffer<MAX_KEY_BLOB_SIZE> key_blob;

    // Load key blob from store
    store.GetKey(key, key_blob);

    // Import key
    SKCrypto::SKKeyId key_id = 0;
    spcrypto->ImportKey(key_blob, key_id);

    // Create object
    SKStoreCryptoKeyPtr spkey(new SKStoreCryptoKey(spcrypto, key_id));

    // Return key
    return spkey;
}

// Store key
SKStoreCryptoKeyPtr SKStoreCryptoKey::Store(SKSecureStore& store, const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id, const char* key) {
    
    // Export key
    SKStaticBinaryBuffer<MAX_KEY_BLOB_SIZE> key_blob;
    spcrypto->ExportKey(key_id, key_blob);

    // Store key blob
    store.SetKey(key, key_blob);

    // Create object
    SKStoreCryptoKeyPtr spkey(new SKStoreCryptoKey(spcrypto, key_id));

    // Return key
    return spkey;
}

// Load from store
SKStoreValuePtr SKStoreValue::Load(SKSecureStore& store, const SKStoreCryptoKeyPtr& spkey, const char* key_value, const char* key_tag) {

    // Create object
    SKStoreValuePtr spvalue(new SKStoreValue(spkey));

    // Load value from store
    store.GetKey(key_value, spvalue->m_value);

    // Load tag from store
    store.GetKey(key_tag, spvalue->m_tag);

    // Return value
    return spvalue;
}

// Store value
SKStoreValuePtr SKStoreValue::Store(SKSecureStore& store, const SKStoreCryptoKeyPtr& spkey, const char* key_value, const char* key_tag, const SKBinaryBuffer& value) {

    // Get IV from masked SK_WRAPPING_IV
    SKConstant<SK_STORE_VAL_IV_SIZE> iv(SK_STORE_VAL_IV);
    iv.Unmask(SKConstant<SK_STORE_VAL_IV_SIZE>(SK_STORE_VAL_IV_MASK));
    iv.VerifyHash(SKConstant<32>(SK_STORE_VAL_IV_CSUM));

    // Get data from masked SK_UNWRAP_DATA
    SKConstant<SK_STORE_VAL_DATA_SIZE> data(SK_STORE_VAL_DATA);
    data.Unmask(SKConstant<SK_STORE_VAL_DATA_SIZE>(SK_STORE_VAL_DATA_MASK));
    data.VerifyHash(SKConstant<32>(SK_STORE_VAL_DATA_CSUM));

    // Key id
    const SKCrypto::SKKeyId key_id = *spkey;

    // Crypto object
    const SKCryptoPtr& spcrypto = *spkey;

    // Create object
    SKStoreValuePtr spvalue(new SKStoreValue(spkey));

    // Encrypt value
    spcrypto->AES128GCMEncrypt(
        key_id, 
        iv.GetBuffer(), data.GetBuffer(), 
        value, 
        spvalue->m_value,
        spvalue->m_tag);

    // Store value
    store.SetKey(key_value, spvalue->m_value);

    // Store tag
    store.SetKey(key_tag, spvalue->m_tag);

    // Return value
    return spvalue;
}

// Decrypt value
void SKStoreValue::Decrypt(SKBinaryBuffer& value) const {

    // Get IV from masked SK_WRAPPING_IV
    SKConstant<SK_STORE_VAL_IV_SIZE> iv(SK_STORE_VAL_IV);
    iv.Unmask(SKConstant<SK_STORE_VAL_IV_SIZE>(SK_STORE_VAL_IV_MASK));
    iv.VerifyHash(SKConstant<32>(SK_STORE_VAL_IV_CSUM));

    // Get data from masked SK_UNWRAP_DATA
    SKConstant<SK_STORE_VAL_DATA_SIZE> data(SK_STORE_VAL_DATA);
    data.Unmask(SKConstant<SK_STORE_VAL_DATA_SIZE>(SK_STORE_VAL_DATA_MASK));
    data.VerifyHash(SKConstant<32>(SK_STORE_VAL_DATA_CSUM));

    // Key id
    const SKCrypto::SKKeyId key_id = *m_spkey;

    // Crypto object
    const SKCryptoPtr& spcrypto = *m_spkey;

    // Decrypt value
    spcrypto->AES128GCMDecrypt(
        key_id, 
        iv.GetBuffer(), data.GetBuffer(), 
        m_value, 
        m_tag, 
        value);
}

// Generate db key (avoid collisions)
void SKStoreList::GenerateDBKey(SKBinaryBuffer& db_key) {

    const uint32_t size = DB_KEY_SIZE;
    const uint8_t range0 = 'Z' - 'N' + 1;
    const uint8_t range1 = '9' - '0' + 'Z' - 'A' + 2;

    do {
        // Generate random key
        m_sprandom->Generate(size + 1, db_key);

        uint8_t* p = db_key.GetBuffer();
        *p = 'N' + ((*p) % range0);
        p ++;

        for (uint32_t i = 1; i < size; ++i, ++p) {

            *p %= range1;
            *p += (*p < 10) ? '0' : 'A' - 10;        
        }

        // Null terminate
        *p = 0;
    }
    while (m_spstore->HasKey(db_key));

    // Update size, exclude null terminator
    db_key.UpdateSize(size);
}

// Create node
SKStoreValuePtr SKStoreList::CreateNode(
        const char* db_key_prev_val, 
        const char* db_key_prev_tag, 
        const SKBinaryBuffer& db_key_data_val, 
        const SKBinaryBuffer& db_key_data_tag) {

    // Node size
    const uint32_t size = 4 * DB_KEY_SIZE;

    // Generate next node value db key
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_next_val;
    GenerateDBKey(db_key_next_val);

    // Generate next node tag db key
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_next_tag;
    GenerateDBKey(db_key_next_tag);

    // Generate node record content
    SKStaticBinaryBuffer<size> node;
    node += db_key_next_val;
    node += db_key_next_tag;
    node += db_key_data_val;
    node += db_key_data_tag;

    // Store node record
    return SKStoreValue::Store(*m_spstore, m_spkey, db_key_prev_val, db_key_prev_tag, node);
}

// Decrypto and read node
void SKStoreList::ReadNode(
    const SKStoreValuePtr& spnode, 
    SKBinaryBuffer& db_key_next_val,
    SKBinaryBuffer& db_key_next_tag,
    SKBinaryBuffer& db_key_data_val,
    SKBinaryBuffer& db_key_data_tag) {

    // Node size
    const uint32_t size = 5 * DB_KEY_SIZE;

    // Decrypt node
    SKStaticBinaryBuffer<size> node;
    spnode->Decrypt(node);

    // Extract next key
    node.Extract(0, DB_KEY_SIZE, db_key_next_val);
    
    // Extract next tag
    node.Extract(DB_KEY_SIZE, DB_KEY_SIZE, db_key_next_tag);

    // Extract data value key
    node.Extract(2 * DB_KEY_SIZE, DB_KEY_SIZE, db_key_data_val);

    // Extract data tag key
    node.Extract(3 * DB_KEY_SIZE, DB_KEY_SIZE, db_key_data_tag);
}

// Initialize list
void SKStoreList::Initialize(
        const char* db_key_head_val, 
        const char* db_key_head_tag, 
        const SKBinaryBuffer& db_key_data_val, 
        const SKBinaryBuffer& db_key_data_tag) {

    // Create node record
    SKStoreValuePtr spvalue = CreateNode(db_key_head_val, db_key_head_tag, db_key_data_val, db_key_data_tag);

    m_spnode = nullptr;
    m_sptail = spvalue;
}

// Start iteration
void SKStoreList::Start(const char* db_key_head_val, const char* db_key_head_tag) {

    m_spnode = nullptr;
    m_sptail = nullptr;

    // Key exists?
    if (m_spstore->HasKey(db_key_head_val)) {

        // Load value
        m_spnode = SKStoreValue::Load(*m_spstore, m_spkey, db_key_head_val, db_key_head_tag);
    }
}

// Next iteration
SKStoreValuePtr SKStoreList::Next(SKBinaryBuffer& db_key_data_val, SKBinaryBuffer& db_key_data_tag) {

    // Node size
    const uint32_t size = 5 * DB_KEY_SIZE;

    // End of list?
    if (!m_spnode) {

        return nullptr;
    }

    // Current node
    SKStoreValuePtr spnode = m_spnode;

    // Read node
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_next_val;
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_next_tag;
    
    ReadNode(spnode, db_key_next_val, db_key_next_tag, db_key_data_val, db_key_data_tag);

    // Next key exists?
    if (m_spstore->HasKey(db_key_next_val)) {

        // Load next value
        m_spnode = SKStoreValue::Load(*m_spstore, m_spkey, db_key_next_val, db_key_next_tag);
    }
    else {

        // End of list
        m_sptail = spnode;
        m_spnode = nullptr;
    }

    // Return value
    return m_spnode;
}

// Append value
void SKStoreList::Add(const SKBinaryBuffer& db_key_data_val, const SKBinaryBuffer& db_key_data_tag) {

    // There must be a tail
    SK_CHECK(m_sptail, SK_ERROR_INVALID_STATE, "No tail record");

    // Read tail
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_next_val;
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_next_tag;
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_temp_val;
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_temp_tag;

    ReadNode(m_sptail, db_key_next_val, db_key_next_tag, db_key_temp_val, db_key_temp_tag);

    // Create node record
    m_sptail = CreateNode(db_key_next_val, db_key_next_tag, db_key_data_val, db_key_data_tag);
}

// Delete list
void SKStoreList::Delete(const char* db_key_head_val, const char* db_key_head_tag) {

    // Iterate
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_node_val;
    SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_node_tag;

    // Initialize
    db_key_node_val.Set((const uint8_t*) db_key_head_val, DB_KEY_SIZE);
    db_key_node_tag.Set((const uint8_t*) db_key_head_tag, DB_KEY_SIZE);

    // Iterate while there are nodes
    while (m_spstore->HasKey(db_key_node_val)) {

        // Load node
        SKStoreValuePtr spnode = SKStoreValue::Load(*m_spstore, m_spkey, db_key_node_val, db_key_node_tag);

        // Delete node
        m_spstore->DeleteKey(db_key_node_val);

        // Delete node tag
        m_spstore->DeleteKey(db_key_node_tag);

        // Read node
        SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_data_val;
        SKStaticBinaryBuffer<DB_KEY_SIZE + 1> db_key_data_tag;

        ReadNode(spnode, db_key_node_val, db_key_node_tag, db_key_data_val, db_key_data_tag);

        // Delete data
        m_spstore->DeleteKey(db_key_data_val);

        // Delete data tag
        m_spstore->DeleteKey(db_key_data_tag);
    }
}
