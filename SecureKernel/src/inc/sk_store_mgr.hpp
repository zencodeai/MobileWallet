#pragma once

#include <memory>

#include "sk_utils.hpp"
#include "sk_crypto.hpp"
#include "sk_app_key_store.hpp"
#include "sk_transaction_list.hpp"

// Shared pointer to SKStoreManager
typedef std::shared_ptr<class SKStoreManager> SKStoreManagerPtr;

// Store manager interface class
class SKStoreManager
{
protected:

    // Crypto module instance
    SKCryptoPtr m_spcrypto;

    // PRNG instance
    SKRandomPtr m_sprandom;

    // App key store
    SKApplicationKeyStorePtr m_spappkeystore;

    // Store instance
    SKSecureStorePtr m_spstore;

    // Constructor
    SKStoreManager(const SKCryptoPtr& spcrypto, const SKRandomPtr sprandom, const SKApplicationKeyStorePtr& spappkeystore) :
        m_spcrypto(spcrypto),
        m_sprandom(sprandom),
        m_spappkeystore(spappkeystore)
    {
    }

public:

    // Destructor
    virtual ~SKStoreManager() {}

    // Create store manager
    static SKStoreManagerPtr Create(const SKCryptoPtr& spcrypto, const SKRandomPtr sprandom, const SKApplicationKeyStorePtr& spappkeystore);

    // Create store
    virtual void CreateStore() = 0;
};
