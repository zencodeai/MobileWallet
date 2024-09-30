# pragma once

#include <memory>

#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"

#include "mbedtls/x509_crt.h"
#include "mbedtls/sha256.h"

// SKCertificate class shared pointer
typedef std::shared_ptr<class SKCertChain> SKCertChainPtr;

// X509 certificate chain class
class SKCertChain
{
    public:

        // Hash size
        static const uint32_t HASH_SIZE = 32;

    protected:

        // Certificate chain struct
        mbedtls_x509_crt m_cert;

    public:

    // Create certificate chain
    static SKCertChainPtr Create(const SKBinaryBuffer& cert) {

        return SKCertChainPtr(new SKCertChain(cert));
    }

    // Create certificate chain
    static SKCertChainPtr Create() {

        return SKCertChainPtr(new SKCertChain());
    }

    // Constructor
    SKCertChain() {

        // Initialize certificate structure
        mbedtls_x509_crt_init(&m_cert);
    }

    // Constructor
    SKCertChain(const SKBinaryBuffer& cert) : SKCertChain() {

        // Parse certificate
        Parse(cert);
    }

    // Parse certificate and add to chain
    void Parse(const SKBinaryBuffer& cert) {

        // Parse certificate
        int result = mbedtls_x509_crt_parse_der(&m_cert, cert.GetBuffer(), cert.GetSize());
        SK_CHECK(!result, SK_ERROR_CERT_PARSE, "mbedtls_x509_crt_parse_der failed: %d", result);
    }

    // Get DER encoded certificate size (padded)
    static const uint32_t GetDERSize(const SKBinaryBuffer& cert) {

        static const uint32_t MIN_CERT_SIZE = 1 + 1 + 2; // SEQUENCE(1) + length

        uint32_t size = 0;

        // Check certificate size
        SK_CHECK(cert.GetSize() >= MIN_CERT_SIZE, SK_ERROR_CERT_PARSE, "Invalid certificate size: %d", cert.GetSize());

        // Compute certificate size
        uint8_t* p = cert.GetBuffer();
        SK_CHECK(*p++ == 0x30, SK_ERROR_CERT_PARSE, "Unexpected certificate format");

        if (*p & 0x80) {
            uint32_t length_size = *p++ & 0x7F;
            SK_CHECK(length_size <= 2, SK_ERROR_CERT_PARSE, "Invalid certificate length size: %d", length_size);
            for (uint32_t i = 0; i < length_size; i++) {
                size = (size << 8) | *p++;
            }

            size += 2 + length_size;
        }
        else {

            size = 2 + (*p++);
        }        

        // Round up to 16 bytes
        size += 16 - size % 16;

        // Check certificate size
        SK_CHECK(cert.GetSize() >= size, SK_ERROR_CERT_PARSE, "Invalid certificate size: %d", cert.GetSize());

        // Return size
        return size;
    }

    // Verify certificate chain
    void VerifyChain(const SKCertChain& chain) {

        // Verify certificate chain
        uint32_t flags = 0;
        int result = mbedtls_x509_crt_verify(const_cast<mbedtls_x509_crt*>(&chain.m_cert), &m_cert, NULL, NULL, &flags, NULL, NULL);
        SK_CHECK(!result && flags != ((uint32_t) -1), SK_ERROR_CERT_VERIFY, "mbedtls_x509_crt_verify failed: %d", result);
    }

    // Verify signature hash
    void VerifySignatureHash(const SKBinaryBuffer& signature, const SKBinaryBuffer& hash) {

        // Verify signature using certificate public key context
        int result = mbedtls_pk_verify(&m_cert.pk, MBEDTLS_MD_SHA256, hash.GetBuffer(), hash.GetSize(), signature.GetBuffer(), signature.GetSize());
        SK_CHECK(!result, SK_ERROR_CERT_SIGN, "mbedtls_pk_verify failed: %d", result);
    }

    // Verify signature
    void VerifySignature(const SKBinaryBuffer& signature, const SKBinaryBuffer& data) {

        SKStaticBinaryBuffer<HASH_SIZE> hash;
        const int result = mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);

        VerifySignatureHash(signature, hash);
    }

    // Destructor
    ~SKCertChain() {

        mbedtls_x509_crt_free(&m_cert);
    }
};
