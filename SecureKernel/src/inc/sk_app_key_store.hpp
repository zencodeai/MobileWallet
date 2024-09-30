#pragma once

#include <memory>
#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"

// Factory  parameters class interface
class SKFactoryParameters
{
public:

    // Destructor
    virtual ~SKFactoryParameters() {}
};

// SKApplicationKeyStore shared pointer type
typedef std::shared_ptr<class SKApplicationKeyStore> SKApplicationKeyStorePtr;

// Application Key store interface
class SKApplicationKeyStore
{
public:

    // Destructor
    virtual ~SKApplicationKeyStore() {}

    // Generate symmetric key
    virtual void GenerateSymmetricKey(const char* key) = 0;

    // Encrypt data
    virtual void Encrypt(const char* key, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher) = 0;

    // Decrypt data
    virtual void Decrypt(const char* key, const SKBinaryBuffer& cipher, SKBinaryBuffer& plain) = 0;

    // Generate asymmetric key pair
    virtual void GenerateAsymmetricKeyPair(const char* key) = 0;

    // Sign data
    virtual void Sign(const char* key, const SKBinaryBuffer& data, SKBinaryBuffer& signature) = 0;

    // Verify data
    virtual void Verify(const char* key, const SKBinaryBuffer& data, const SKBinaryBuffer& signature) = 0;

    // Get public key
    virtual void GetPublicKey(const char* key, SKBinaryBuffer& buffer) = 0;

    // Class factory (return smart pointer)
    static SKApplicationKeyStorePtr Create(const SKFactoryParameters& params);
};
