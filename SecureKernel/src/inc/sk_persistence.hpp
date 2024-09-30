#pragma once

#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"
#include "sk_crypto.hpp"
#include "sk_random.hpp"
#include "sk_secure_store.hpp"

// Store key class template
template <size_t SIZE> class SKStoreKey {

private:
    
    // Key
    SKStaticBinaryBuffer<SIZE> m_buffer;

public:

    // Constructor
    SKStoreKey(int first, ...) {

        // Initialize buffer
        m_buffer.SetSize(SIZE);

        // Copy data
        uint8_t* p = m_buffer.GetBuffer();
        *(p ++) = (uint8_t) first;
        std::va_list args;
        va_start(args, first);
        for (int i = 1; i < SIZE; i++) {
            *(p ++) = (uint8_t) va_arg(args, int);
        }
        va_end(args);
    }

    // Cast to char* operator
    operator const char*() const {

        return (const char*) m_buffer.GetBuffer();
    }
};

// Crypto key shared pointer type
typedef std::shared_ptr<class SKStoreCryptoKey> SKStoreCryptoKeyPtr;

// Crypto key store object class
class SKStoreCryptoKey {

private:

    // Max key blob size
    static const size_t MAX_KEY_BLOB_SIZE = 256;

    // Key id
    SKCrypto::SKKeyId m_key_id;

    // Shared pointer to crypto object
    SKCryptoPtr m_spcrypto;

    // Constructor
    SKStoreCryptoKey(const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id) : m_spcrypto(spcrypto), m_key_id(key_id) {}

public:

    // Load from store
    static SKStoreCryptoKeyPtr Load(SKSecureStore& store, const SKCryptoPtr& spcrypto, const char* key);

    // Store key
    static SKStoreCryptoKeyPtr Store(SKSecureStore& store, const SKCryptoPtr& spcrypto, const SKCrypto::SKKeyId key_id, const char* key);

    // Convert to key id
    operator SKCrypto::SKKeyId() const {

        return m_key_id;
    }

    // Convert to crypto object
    operator SKCryptoPtr() const {

        return m_spcrypto;
    }
};

// Store value class shared pointer type
typedef std::shared_ptr<class SKStoreValue> SKStoreValuePtr;

// Store value class
class SKStoreValue {

private:

    // Tag size
    static const size_t TAG_SIZE = 16;

    // Value buffer
    SKDynamicBinaryBuffer m_value;

    // Tag buffer
    SKStaticBinaryBuffer<TAG_SIZE> m_tag;

    // Shared pointer to crypto key object
    SKStoreCryptoKeyPtr m_spkey;

    // Constructor
    SKStoreValue(const SKStoreCryptoKeyPtr& spkey) : m_spkey(spkey) {}

public:

    // Load from store
    static SKStoreValuePtr Load(SKSecureStore& store, const SKStoreCryptoKeyPtr& spkey, const char* key_value, const char* key_tag);

    // Store value
    static SKStoreValuePtr Store(SKSecureStore& store, const SKStoreCryptoKeyPtr& spkey, const char* key_value, const char* key_tag, const SKBinaryBuffer& value);

    // Decrypt value
    void Decrypt(SKBinaryBuffer& value) const;

    // Get value
    SKBinaryBuffer& GetValue() {

        return m_value;
    }

    // Get tag
    SKBinaryBuffer& GetTag() {

        return m_tag;
    }
};

// Store list class
class SKStoreList {

protected:

    // Secure store key size
    static const size_t DB_KEY_SIZE = 16;

    // Store shared pointer
    SKSecureStorePtr m_spstore;

    // Key
    SKStoreCryptoKeyPtr m_spkey;

    // Random number generator
    SKRandomPtr m_sprandom;

    // Current node
    SKStoreValuePtr m_spnode;

    // Tail
    SKStoreValuePtr m_sptail;

    // Generate db key (avoid collisions)
    void GenerateDBKey(SKBinaryBuffer& db_key);

    // Create node
    SKStoreValuePtr CreateNode(
        const char* db_key_prev_val, 
        const char* db_key_prev_tag, 
        const SKBinaryBuffer& db_key_data_val, 
        const SKBinaryBuffer& db_key_data_tag);

    // Decrypto and read node
    void ReadNode(
        const SKStoreValuePtr& spnode, 
        SKBinaryBuffer& db_key_next_val,
        SKBinaryBuffer& db_key_next_tag,
        SKBinaryBuffer& db_key_data_val,
        SKBinaryBuffer& db_key_data_tag);

public:

    // DB key buffer data type
    typedef SKStaticBinaryBuffer<DB_KEY_SIZE + 1> SKDBKeyBuffer;

    // Store key buffer data type
    typedef SKStoreKey<DB_KEY_SIZE + 1> SKStoreKeyBuffer;

    // Constructor
    SKStoreList(const SKSecureStorePtr& spstore, const SKRandomPtr& sprandom, const SKStoreCryptoKeyPtr& spkey) : 
        m_spstore(spstore), 
        m_sprandom(sprandom), 
        m_spkey(spkey) {}

    // Initialize list
    void Initialize(
        const char* db_key_head_val, 
        const char* db_key_head_tag, 
        const SKBinaryBuffer& db_key_data_val, 
        const SKBinaryBuffer& db_key_data_tag);

    // Start iteration
    void Start(const char* db_key_head_val, const char* db_key_head_tag);

    // Next iteration
    SKStoreValuePtr Next(SKBinaryBuffer& db_key_data_val, SKBinaryBuffer& db_key_data_tag);

    // Add value to list
    void Add(const SKBinaryBuffer& db_key_data_val, const SKBinaryBuffer& db_key_data_tag);

    // Delete list
    void Delete(const char* db_key_head_val, const char* db_key_head_tag);
};
