#pragma once

#include "sk_store_mgr.hpp"

// Generic store manager class
class SKStoreManagerGeneric : public SKStoreManager
{
protected:

    // Constructor
    SKStoreManagerGeneric(const SKCryptoPtr& spcrypto, const SKRandomPtr sprandom, const SKApplicationKeyStorePtr& spappkeystore) :
        SKStoreManager(spcrypto, sprandom, spappkeystore)
    {
    }

public:

    // Destructor
    virtual ~SKStoreManagerGeneric() {}

    // Create store manager
    static SKStoreManagerPtr Create(const SKCryptoPtr& spcrypto, const SKRandomPtr sprandom, const SKApplicationKeyStorePtr& spappkeystore);

    // Create store
    void CreateStore();
};
