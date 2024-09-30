#include "mbedtls/hmac_drbg.h"
#include "mbedtls/entropy.h"
#include "sk_random.hpp"

// Class implementation using HMAC-DRBG
class SKRandomHMACDRBG : public SKRandom
{
private:

    // State size
    static const uint32_t STATE_SIZE = 32;

    // Entropy context
    mbedtls_entropy_context m_entropy;

    // HMAC-DRBG context
    mbedtls_hmac_drbg_context m_hmacDRBG;

    // Store
    SKSecureStorePtr m_store;

    // Seed
    void Seed(const uint8_t* buffer, const uint32_t size);

public:

    // Constructor
    SKRandomHMACDRBG(SKSecureStorePtr& store);

    // Destructor
    ~SKRandomHMACDRBG();

    // Update seed
    void UpdateSeed(const SKBinaryBuffer& seed);

    // Update seed
    void UpdateSeed(const uint8_t* seed, const uint32_t size);

    // Generate random byte array
    void Generate(const uint32_t size, SKBinaryBuffer& buffer);

    // Store state
    void StoreState();

    // Restore state
    void RestoreState();
};

// Class factory (return smart pointer)
SKRandomPtr SKRandom::Create(SKSecureStorePtr& store)
{
    // Return smart pointer
    return SKRandomPtr(new SKRandomHMACDRBG(store));
}

// Seed
void SKRandomHMACDRBG::Seed(const uint8_t* buffer, const uint32_t size)
{
    // Add entropy
    int ret = mbedtls_entropy_update_manual(&m_entropy, buffer, size);
    SK_CHECK(ret == 0, SK_ERROR_RND, "mbedtls_entropy_update_manual failed: %d", ret);

    // Seed
    ret = mbedtls_hmac_drbg_seed(&m_hmacDRBG, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), mbedtls_entropy_func, &m_entropy, NULL, 0);
    SK_CHECK(ret == 0, SK_ERROR_RND, "mbedtls_hmac_drbg_seed failed: %d", ret);
}

// Constructor
SKRandomHMACDRBG::SKRandomHMACDRBG(SKSecureStorePtr& store)
{
    // Store
    m_store = store;

    // Initialize entropy
    mbedtls_entropy_init(&m_entropy);

    // Initialize HMAC-DRBG
    mbedtls_hmac_drbg_init(&m_hmacDRBG);
}

// Destructor
SKRandomHMACDRBG::~SKRandomHMACDRBG()
{
    // Free entropy
    mbedtls_entropy_free(&m_entropy);

    // Free HMAC-DRBG
    mbedtls_hmac_drbg_free(&m_hmacDRBG);
}   

// Update seed
void SKRandomHMACDRBG::UpdateSeed(const SKBinaryBuffer& seed)
{
    // Update seed
    UpdateSeed(seed.GetBuffer(), seed.GetSize());
}

// Update seed
void SKRandomHMACDRBG::UpdateSeed(const uint8_t* seed, const uint32_t size)
{
    // Seed
    Seed(seed, size);

    // Store state
    StoreState();
}

// Generate random byte array
void SKRandomHMACDRBG::Generate(const uint32_t size, SKBinaryBuffer& buffer)
{
    // Check size
    SK_CHECK(size > 0, SK_ERROR_INVALID_PARAMETER, "Invalid size: %d", size);

    // Resize buffer
    buffer.SetSize(size);

    // Generate
    int ret = mbedtls_hmac_drbg_random(&m_hmacDRBG, buffer.GetBuffer(), size);
    SK_CHECK(ret == 0, SK_ERROR_RND, "mbedtls_hmac_drbg_random failed: %d", ret);

    // Store state
    StoreState();
}

// Store state
void SKRandomHMACDRBG::StoreState()
{
    // Generate 32 byte random seed
    SKStaticBinaryBuffer<STATE_SIZE> buffer;
    buffer.SetSize(STATE_SIZE);
    int ret = mbedtls_hmac_drbg_random(&m_hmacDRBG, buffer.GetBuffer(), STATE_SIZE);
    SK_CHECK(ret == 0, SK_ERROR_RND, "mbedtls_hmac_drbg_random failed: %d", ret);

    // Store state in store
    m_store->SetKey(SK_DB_PRNG, buffer);
}

// Restore state
void SKRandomHMACDRBG::RestoreState()
{
    // Read state from store
    SKStaticBinaryBuffer<STATE_SIZE> buffer;
    m_store->GetKey(SK_DB_PRNG, buffer);

    // Seed
    Seed(buffer.GetBuffer(), buffer.GetSize());
}

// PRNG callback for ECDSA
int ecdsa_prng(void * ctx, unsigned char *output, size_t size) {

    SKRandom* random = (SKRandom*) ctx;

    SKDynamicBinaryBuffer buffer(size);

    random->Generate(size, buffer);

    memcpy(output, buffer.GetBuffer(), size);

    return 0;
}
