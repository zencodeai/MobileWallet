#pragma once

#include <memory>
#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"
#include "sk_secure_store.hpp"

// SKReandom shared pointer type
typedef std::shared_ptr<class SKRandom> SKRandomPtr;

// Psuedo random number generator interface
class SKRandom
{
    public:

        // Destructor
        virtual ~SKRandom() {}

        // Update seed
        virtual void UpdateSeed(const SKBinaryBuffer& seed) = 0;
        
        // Update seed
        virtual void UpdateSeed(const uint8_t* seed, const uint32_t size) = 0;

        // Generate random byte array
        virtual void Generate(const uint32_t size, SKBinaryBuffer& buffer) = 0;

        // Store state
        virtual void StoreState() = 0;

        // Restore state
        virtual void RestoreState() = 0;

        // Class factory (return smart pointer)
        static SKRandomPtr Create(SKSecureStorePtr& store);
};

// ECDSA PRNG callback
extern "C" {

    int ecdsa_prng(void * ctx, unsigned char *output, size_t size);
}
