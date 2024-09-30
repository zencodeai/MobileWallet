#include <unistd.h>

#include "sk_store_mgr_generic.hpp"

// Create store manager
SKStoreManagerPtr SKStoreManagerGeneric::Create(const SKCryptoPtr& spcrypto, const SKRandomPtr sprandom, const SKApplicationKeyStorePtr& spappkeystore)
{
    return SKStoreManagerPtr(new SKStoreManagerGeneric(spcrypto, sprandom, spappkeystore));
}

// Create store
void SKStoreManagerGeneric::CreateStore()
{
    SKConstant<SK_STORE_PATHNAME_SIZE> store_pathname(SK_STORE_PATHNAME_HEX);

    // Check if store already exists using GNU C library access() function
    SK_CHECK(access(store_pathname.GetBuffer(), F_OK) != 0, SK_ERROR_STORE_EXISTS, "Store already exists");

    // Instantiate secure store module
    SKSecureStorePtr spstore = SKSecureStore::Create();

    // Create secure store
    spstore->Create(store_pathname.GetBuffer());

    // Set secure store
    m_spstore = spstore;
}
