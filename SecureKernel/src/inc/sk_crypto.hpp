#pragma once

#include <memory>

#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"

// SKCrypto shared pointer type
typedef std::shared_ptr<class SKCrypto> SKCryptoPtr;

// SKCryptoParams parameters interface class
class SKCryptoParams {
public:

    // Destructor
    virtual ~SKCryptoParams() {}
};

// Crypto mobule interface
class SKCrypto {

    public:

    // Key id type
    typedef uint32_t SKKeyId;

    // Destructor
    virtual ~SKCrypto() {}

    // Class factory
    static SKCryptoPtr Create(const SKCryptoParams& params);

    // ECDH 1: Get client params (client)
    virtual void ECDHGetClientParams(SKBinaryBuffer& params) = 0;

    // ECDH 2: Get server public key (server)
    virtual void ECDHServerPublicKey(const SKBinaryBuffer& params, SKBinaryBuffer& public_key) = 0;

    // ECDH 3: Set public key (client)
    virtual void ECDHSetPublicKey(const SKBinaryBuffer& public_key) = 0;

    // ECDH 4: Compute shared key
    virtual void ECDHComputeSharedKey(SKKeyId& key_id) = 0;

    // Generate AES-128 key
    virtual void AES128GCMGenerateKey(SKKeyId& key_id) = 0;

    // AES-128-GCM encrypt
    virtual void AES128GCMEncrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& data, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher, SKBinaryBuffer& tag) = 0;

    // AES-128-GCM decrypt
    virtual void AES128GCMDecrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& data, const SKBinaryBuffer& cipher, const SKBinaryBuffer& tag, SKBinaryBuffer& plain) = 0;

    // AES-128-CBC encrypt
    virtual void AES128CBCEncrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher) = 0;

    // AES-128-CBC decrypt
    virtual void AES128CBCDecrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& cipher, SKBinaryBuffer& plain) = 0;

    // Export key
    virtual void ExportKey(const SKKeyId key_id, SKBinaryBuffer& key) = 0;

    // Import key
    virtual void ImportKey(const SKBinaryBuffer& key, SKKeyId& key_id) = 0;

    // Unwrap key AES-128-GCM
    virtual void UnwrapKeyAES128GCM(const SKKeyId key_id, const SKBinaryBuffer& key_blob, SKKeyId& key_id_new) = 0;

    // Generate ECDSA P-256 key pair
    virtual void ECDSAP256GenerateKeyPair(SKKeyId& key_id) = 0;

    // ECDSA P-256 sign
    virtual void ECDSAP256Sign(const SKKeyId key_id, const SKBinaryBuffer& data, SKBinaryBuffer& signature) = 0;

    // ECDSA P-256 verify
    virtual void ECDSAP256Verify(const SKKeyId key_id, const SKBinaryBuffer& data, const SKBinaryBuffer& signature) = 0;

    // ECDSA P-256 digest sign
    virtual void ECDSAP256DigestSign(const SKKeyId key_id, const SKBinaryBuffer& dignest, SKBinaryBuffer& signature) = 0;

    // ECDSA P-256 dignest verify
    virtual void ECDSAP256DigestVerify(const SKKeyId key_id, const SKBinaryBuffer& digest, const SKBinaryBuffer& signature) = 0;

    // Unwrap key ECDSA P-256
    virtual void UnwrapKeyECDSAP256(const SKKeyId key_id, const SKBinaryBuffer& key_blob, SKKeyId& key_id_new) = 0;

    // Delete key
    virtual void DeleteKey(const SKKeyId key_id) = 0;
};
