#pragma once

#include "sk_app_key_store.hpp"
#include "sk_random.hpp"
#include "sk_secure_store.hpp"

// Application Key store simulated facroty parameters class
class SKApplicationKeyStoreSimFactoryParameters : public SKFactoryParameters
{
private:

    // Secure store
    SKSecureStorePtr m_secureStore;

    // Random number generator
    SKRandomPtr m_random;

public:

    // Constructor
    SKApplicationKeyStoreSimFactoryParameters(const SKSecureStorePtr& secureStore, const SKRandomPtr& random) :
        m_secureStore(secureStore),
        m_random(random)
    {
    }

    // Copy constructor
    SKApplicationKeyStoreSimFactoryParameters(const SKApplicationKeyStoreSimFactoryParameters& params) :
        m_secureStore(params.m_secureStore),
        m_random(params.m_random)
    {
    }

    // Assignment operator
    SKApplicationKeyStoreSimFactoryParameters& operator=(const SKApplicationKeyStoreSimFactoryParameters& params)
    {
        if (this != &params)
        {
            m_secureStore = params.m_secureStore;
            m_random = params.m_random;
        }
        return *this;
    }

    // Destructor
    ~SKApplicationKeyStoreSimFactoryParameters()
    {
    }

    // Get secure store
    SKSecureStorePtr GetSecureStore() const
    {
        return m_secureStore;
    }

    // Get random number generator
    SKRandomPtr GetRandom() const
    {
        return m_random;
    }
};

// Application Key store simulated class
class SKApplicationKeyStoreSim : public SKApplicationKeyStore
{
private:

    // AES-GCM tag length
    static const size_t AES_GCM_TAG_LENGTH = 16;

    // Symmetric key length
    static const size_t SYMMETRIC_KEY_LENGTH = 16;

    // Max plain size
    static const size_t MAX_PLAIN_SIZE = 0xFFFF - 16;

    // ECDSA private key length
    static const size_t ECDSA_PRIVATE_KEY_LENGTH = 32;

    // ECDSA public key length
    static const size_t ECDSA_PUBLIC_KEY_LENGTH = 65;

    // ECDSA signature length
    static const size_t ECDSA_SIGNATURE_LENGTH = (2 * ECDSA_PRIVATE_KEY_LENGTH + 9);

    // SHA256 digest length
    static const size_t SHA256_DIGEST_LENGTH = 32;

    // Static IV
    static const unsigned char AES_GCM_IV[];

    // Static salt
    static const unsigned char AES_GCM_SALT[];

    // Secure store
    SKSecureStorePtr m_secureStore;

    // Random number generator
    SKRandomPtr m_random;

    // Managed aes gcm context
    class ManagedMbedtlsGcmContext;

    // Managed ecdsa context
    class ManagedMbedtlsEcdsaContext;

    // Generate ECDSA key pair
    void GenerateEcdsaKeyPair(const char* key, ManagedMbedtlsEcdsaContext& ctx);

    // Load ECDSA key pair from store
    void LoadEcdsaKeyPair(const char* key, ManagedMbedtlsEcdsaContext& ctx);

public:

    // Constructor
    SKApplicationKeyStoreSim(const SKApplicationKeyStoreSimFactoryParameters& params);

    // Destructor
    ~SKApplicationKeyStoreSim();

    // Generate symmetric key
    void GenerateSymmetricKey(const char* key);

    // AES-GCM data encryption using Mbed TLS
    void Encrypt(const char* key, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher);
    
    // AES-GCM data decryption using Mbed TLS
    void Decrypt(const char* key, const SKBinaryBuffer& cipher, SKBinaryBuffer& plain);

    // Generate asymmetric key pair
    void GenerateAsymmetricKeyPair(const char* key);

    // Sign data using ECDSA
    void Sign(const char* key, const SKBinaryBuffer& data, SKBinaryBuffer& signature);

    // Verify data signature using ECDSA
    void Verify(const char* key, const SKBinaryBuffer& data, const SKBinaryBuffer& signature);

    // Get public key
    void GetPublicKey(const char* key, SKBinaryBuffer& buffer);
};
