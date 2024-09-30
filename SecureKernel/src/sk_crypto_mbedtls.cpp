#include "sk_crypto_mbedtls.hpp"

// Class factory
SKCryptoPtr SKCrypto::Create(const SKCryptoParams& params)
{
    // Cast params to SKCryptoMbedTLSParams
    const SKCryptoMbedTLSParams& mbed_params = dynamic_cast<const SKCryptoMbedTLSParams&>(params);

    // Create SKCryptoMbedTLS instance
    return SKCryptoPtr(new SKCryptoMbedTLS(mbed_params));
}

// Initialize context
void SKCryptoMbedTLS::InitContext()
{
    // Encrypt static key using app key store
    const uint8_t static_key[] = SK_CRYPTO_STATC_KEY;
    SKStaticBinaryBuffer<16> plain;
    plain.Set(static_key, sizeof(static_key));
    SKStaticBinaryBuffer<256> cipher;
    m_spaks->Encrypt(SK_APP_KEY_SYM, plain, cipher);

    // Compute SHA256 hash of static key and keep 16 first bytes
    SKStaticBinaryBuffer<32> hash;
    hash.SetSize(32);
    int result = mbedtls_sha256(static_key, sizeof(static_key), hash.GetBuffer(), 0);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_sha256 failed: %d", result);
    hash.UpdateSize(16);

    // Init AES-128-GCM context
    result = mbedtls_gcm_setkey(&m_aes128gcm_ctx, MBEDTLS_CIPHER_ID_AES, hash.GetBuffer(), hash.GetSize() * 8);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_setkey failed: %d", result);
}

// Decrypt key using context
void SKCryptoMbedTLS::DecrypKey(const SKKeyData& key_data, SKBinaryBuffer& plain)
{
    const uint8_t iv[] = SK_CRYPTO_STATC_KEY_MASK;
    const uint8_t data[] = SK_CRYPTO_STATC_KEY_CSUM;

    // Decrypt key
    const SKBinaryBuffer& cipher = key_data.GetKey();
    const uint32_t cipher_size = cipher.GetSize() - TAG_SIZE;
    SKStaticBinaryBuffer<16> tag;
    tag.Set(cipher.GetBuffer() + cipher_size, TAG_SIZE);
    plain.SetSize(cipher_size);
    int result = mbedtls_gcm_auth_decrypt(
        &m_aes128gcm_ctx,
        cipher_size,
        iv, sizeof(iv),
        data, sizeof(data),
        tag.GetBuffer(), tag.GetSize(),
        cipher.GetBuffer(), 
        plain.GetBuffer()
    );
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_auth_decrypt failed: %d", result);

    // Set plain size depending on key type
    switch (key_data.GetKeyType()) {

        // AES-128-GCM key
        case SKKeyData::SK_KEY_TYPE_AES_GCM_128:
            plain.UpdateSize(AES128_KEY_SIZE);
            break;

        // ECDSA P-256 key
        case SKKeyData::SK_KEY_TYPE_ECDSA_P256:
            plain.UpdateSize(P256_KEY_BLOB_SIZE);
            break;

        // Invalid key type
        default:
            SK_CHECK(false, SK_ERROR_INVALID_STATE, "Invalid key type: %08X", key_data.GetKeyType());
    }
}

// Encrypt key using context
void SKCryptoMbedTLS::EncryptKey(const SKBinaryBuffer& plain, SKKeyData& key_data)
{
    const uint8_t iv[] = SK_CRYPTO_STATC_KEY_MASK;
    const uint8_t data[] = SK_CRYPTO_STATC_KEY_CSUM;

    // Random padding
    SKStaticBinaryBuffer<AES128_KEY_SIZE> padding;
    padding.SetSize(AES128_KEY_SIZE);
    GenerateByteString(AES128_KEY_SIZE, padding.GetBuffer());

    // Prepare plain text
    SKStaticBinaryBuffer<MAX_KEY_SIZE> plain_buffer;
    plain_buffer = plain;
    
    // Add padding
    const uint32_t padding_size = AES128_KEY_SIZE - (plain.GetSize() % AES128_KEY_SIZE);
    padding.UpdateSize(padding_size);
    plain_buffer += padding;

    // Encrypt key
    const uint32_t plain_size = plain_buffer.GetSize();
    const uint32_t cipher_size = plain_size + TAG_SIZE;
    SKBinaryBuffer& cipher = const_cast<SKBinaryBuffer&>(key_data.GetKey());
    cipher.SetSize(cipher_size);

    // Encrypt key
    int result = mbedtls_gcm_crypt_and_tag(
        &m_aes128gcm_ctx,
        MBEDTLS_GCM_ENCRYPT,
        plain_size,
        iv, sizeof(iv),
        data, sizeof(data),
        plain.GetBuffer(), 
        cipher.GetBuffer(),
        TAG_SIZE, cipher.GetBuffer() + plain_size
    );
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_crypt_and_tag failed: %d", result);
}

// Generate random bytes sequence (non-crypto)
void SKCryptoMbedTLS::GenerateByteString(const uint32_t size, uint8_t* const buffer)
{
    // Initialize entropy source
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    // Initialize random number generator
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    try {

        // Seed random number generator
        int result = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ctr_drbg_seed failed: %d", result);

        // Generate random bytes
        result = mbedtls_ctr_drbg_random(&ctr_drbg, buffer, size);
        SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ctr_drbg_random failed: %d", result);
    }
    catch (const SKException& e) {

        // Free resources
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        // Rethrow exception
        throw e;
    }

    // Free resources
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// Generate UINT32 random number
uint32_t SKCryptoMbedTLS::GenerateRandomInt(const uint32_t min, const uint32_t max)
{
    // Generate random bytes
    uint8_t buffer[sizeof(uint32_t)];
    GenerateByteString(sizeof(buffer), buffer);

    // Convert to integer
    int value = 0;
    for (int i = 0; i < sizeof(buffer); i++) {
        value = (value << 8) | buffer[i];
    }

    // Return value
    return min + (value % (max - min));
}

// Add key to key data map
SKCrypto::SKKeyId SKCryptoMbedTLS::AddKey(const SKBinaryBuffer& key, const SKKeyData::SKKeyType key_type)
{
    // Generate random key id
    SKCrypto::SKKeyId key_id = GenerateRandomInt(INT32_MAX, UINT32_MAX);

    // Check if key id already exists
    SKKeyDataMap::iterator it = m_keys.find(key_id);
    while (it != m_keys.end()) {
        key_id = GenerateRandomInt(INT32_MAX, UINT32_MAX);
        it = m_keys.find(key_id);
    }

    // Create key data object
    SKKeyDataPtr key_data = SKKeyDataPtr(new SKKeyData(key_id, key, key_type));

    // Add key data to map
    m_keys[key_id] = key_data;

    // Return key id
    return key_id;
}

// Add key to key data map
SKCrypto::SKKeyId SKCryptoMbedTLS::EncryptoAndAddKey(const SKBinaryBuffer& key, const SKKeyData::SKKeyType key_type)
{
    // Generate random key id
    SKCrypto::SKKeyId key_id = GenerateRandomInt(INT32_MAX, UINT32_MAX);

    // Check if key id already exists
    SKKeyDataMap::iterator it = m_keys.find(key_id);
    while (it != m_keys.end()) {
        key_id = GenerateRandomInt(INT32_MAX, UINT32_MAX);
        it = m_keys.find(key_id);
    }

    // Create key data object
    SKKeyDataPtr key_data = SKKeyDataPtr(new SKKeyData(key_id, key_type));

    // Encrypt key
    EncryptKey(key, *key_data);

    // Add key data to map
    m_keys[key_id] = key_data;

    // Return key id
    return key_id;
}

// Get key data from key id
SKKeyData& SKCryptoMbedTLS::GetKeyData(const SKCrypto::SKKeyId key_id)
{
    // Find key data
    SKKeyDataMap::iterator it = m_keys.find(key_id);
    SK_CHECK(it != m_keys.end(), SK_ERROR_INVALID_PARAMETER, "Key not found: %d", key_id);

    // Return key data
    return *it->second;
}

// Get decrypted key from key id
void SKCryptoMbedTLS::GetDecryptedKey(const SKCrypto::SKKeyId key_id, SKBinaryBuffer& key)
{
    // Get key data
    SKKeyData& key_data = GetKeyData(key_id);

    // Decrypt key
    DecrypKey(key_data, key);
}

// Remove padding
void SKCryptoMbedTLS::RemovePadding(SKBinaryBuffer& buff) {

    // Check size
    const uint32_t padded_size = buff.GetSize();
    SK_CHECK(padded_size >= AES128_KEY_SIZE && !(padded_size % AES128_KEY_SIZE), SK_ERROR_INVALID_PARAMETER, "Invalid padding");

    // Get padding size
    const uint32_t padding_size = buff.GetBuffer()[padded_size - 1];
    SK_CHECK(padding_size && padding_size <= AES128_KEY_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid padding");

    // Update size
    buff.UpdateSize(buff.GetSize() - padding_size);
}

// Unwrap key blob of type key_type using wrapping key key_id and add key to the key data map
SKCrypto::SKKeyId SKCryptoMbedTLS::UnwrapKey(const SKKeyId key_id, const SKBinaryBuffer& key_blob, const SKKeyData::SKKeyType key_type) {

    // Get IV from masked SK_WRAPPING_IV
    SKConstant<SK_UNWRAP_IV_SIZE> iv(SK_UNWRAP_IV);
    iv.Unmask(SKConstant<SK_UNWRAP_IV_SIZE>(SK_UNWRAP_IV_MASK));
    iv.VerifyHash(SKConstant<32>(SK_UNWRAP_IV_CSUM));

    // Get and veirfy data from masked SK_UNWRAP_DATA
    SKConstant<SK_UNWRAP_DATA_SIZE> data(SK_UNWRAP_DATA);
    data.Unmask(SKConstant<SK_UNWRAP_DATA_SIZE>(SK_UNWRAP_DATA_MASK));
    data.VerifyHash(SKConstant<32>(SK_UNWRAP_DATA_CSUM));

    // Get tag from key blob
    SKStaticBinaryBuffer<TAG_SIZE> tag;
    key_blob.Extract(key_blob.GetSize() - TAG_SIZE, TAG_SIZE, tag);
    
    // Get encrypted key from key blob
    SKStaticBinaryBuffer<MAX_KEY_SIZE> encrypted_key;
    key_blob.Extract(0, key_blob.GetSize() - TAG_SIZE, encrypted_key);

    // Decrypt key
    SKStaticBinaryBuffer<MAX_KEY_SIZE> key;
    AES128GCMDecrypt(key_id, iv.GetBuffer(), data.GetBuffer(), encrypted_key, tag, key);

    // Remove padding
    // const uint32_t padding_size = AES128_KEY_SIZE - (key.GetSize() % AES128_KEY_SIZE);
    // key.UpdateSize(key.GetSize() - padding_size);
    RemovePadding(key);

    // Add key to key data map
    return EncryptoAndAddKey(key, key_type);
}

// Load ECDSA key pair from key map
void SKCryptoMbedTLS::LoadECDSAP256KeyPair(const SKKeyId key_id, SKECDSAContext& ctx)
{
    // Get key data
    SKStaticBinaryBuffer<MAX_KEY_SIZE> key_blob;
    GetDecryptedKey(key_id, key_blob);

    // Extract private key
    SKStaticBinaryBuffer<ECDSA_PRIVATE_KEY_LENGTH> private_key;
    key_blob.Extract(0, ECDSA_PRIVATE_KEY_LENGTH, private_key);

    // Extract public key
    SKStaticBinaryBuffer<ECDSA_PUBLIC_KEY_LENGTH> public_key;
    key_blob.Extract(ECDSA_PRIVATE_KEY_LENGTH, ECDSA_PUBLIC_KEY_LENGTH, public_key);

    // Set group
    int result = mbedtls_ecp_group_load(&ctx.GetContext()->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_group_load failed: %d", result);

    // Set private key
    result = mbedtls_mpi_read_binary(&ctx.GetContext()->MBEDTLS_PRIVATE(d), private_key.GetBuffer(), ECDSA_PRIVATE_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_mpi_read_binary failed: %d", result);

    // Set public key (skip 0x04)
    result = mbedtls_ecp_point_read_binary(
        &ctx.GetContext()->MBEDTLS_PRIVATE(grp), 
        &ctx.GetContext()->MBEDTLS_PRIVATE(Q), 
        public_key.GetBuffer(), ECDSA_PUBLIC_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_read_binary failed: %d", result);

    // Check public key
    result = mbedtls_ecp_check_pubkey(&ctx.GetContext()->MBEDTLS_PRIVATE(grp), &ctx.GetContext()->MBEDTLS_PRIVATE(Q));
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_check_pubkey failed: %d", result);
}

// Delete key from key data map
void SKCryptoMbedTLS::RemoveKey(const SKCrypto::SKKeyId key_id)
{
    // Find key data
    SKKeyDataMap::iterator it = m_keys.find(key_id);
    SK_CHECK(it != m_keys.end(), SK_ERROR_INVALID_PARAMETER, "Key not found: %d", key_id);

    // Delete key data
    m_keys.erase(it);
}

// ECDH 1: Get client params (client)
void SKCryptoMbedTLS::ECDHGetClientParams(SKBinaryBuffer& params)
{
    // Create ECDH context
    m_specdh = SKECDHContextPtr(new SKECDHContext());

    // Make ECDH parameters
    m_specdh->MakeParams(params);
} 

// ECDH 2: Get server public key (server)
void SKCryptoMbedTLS::ECDHServerPublicKey(const SKBinaryBuffer& params, SKBinaryBuffer& public_key)
{
    // Create ECDH context
    m_specdh = SKECDHContextPtr(new SKECDHContext());

    // Read client side ECDH parameters
    m_specdh->ReadParams(params, public_key);
}

// ECDH 3: Set public key (client)
void SKCryptoMbedTLS::ECDHSetPublicKey(const SKBinaryBuffer& public_key)
{
    // Read server side ECDH public key
    m_specdh->ReadPublicKey(public_key);
}

// ECDH 4: Compute shared key
void SKCryptoMbedTLS::ECDHComputeSharedKey(SKKeyId& key_id)
{
    // Compute shared secret
    SKStaticBinaryBuffer<SKECDHContext::SHARED_SECRET_SIZE> secret;
    m_specdh->ComputeSharedSecret(secret);

    // Compute SHA256 hash of shared secret and keep 16 first bytes
    SKStaticBinaryBuffer<32> hash;
    int result = mbedtls_sha256(secret.GetBuffer(), secret.GetSize(), hash.GetBuffer(), 0);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_sha256 failed: %d", result);
    hash.UpdateSize(16);

    // Add key
    key_id = EncryptoAndAddKey(hash, SKKeyData::SK_KEY_TYPE_AES_GCM_128);
}

// Generate AES-128 key
void SKCryptoMbedTLS::AES128GCMGenerateKey(SKKeyId& key_id)
{
    // Generate random key
    SKStaticBinaryBuffer<AES128_KEY_SIZE> key;
    key.SetSize(AES128_KEY_SIZE);
    GenerateByteString(AES128_KEY_SIZE, key.GetBuffer());

    // Add key
    key_id = EncryptoAndAddKey(key, SKKeyData::SK_KEY_TYPE_AES_GCM_128);
}

// AES-128-GCM encrypt
void SKCryptoMbedTLS::AES128GCMEncrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& data, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher, SKBinaryBuffer& tag)
{
    // Check iv size
    SK_CHECK(iv.GetSize() >= 12, SK_ERROR_INVALID_PARAMETER, "Invalid iv size: %d", iv.GetSize());

    // Check data size
    SK_CHECK(data.GetSize() >= 16, SK_ERROR_INVALID_PARAMETER, "Invalid data size: %d", data.GetSize());

    // Data must be padded to AES-128 block size
    SK_CHECK(plain.GetSize() % AES128_KEY_SIZE == 0, SK_ERROR_INVALID_PARAMETER, "Invalid data size: %d", plain.GetSize());

    // Get decryped key
    SKStaticBinaryBuffer<MAX_KEY_SIZE> key;
    GetDecryptedKey(key_id, key);

    // Schedule key
    SKAESGCMContext aes128gcm_ctx(key);

    // Encrypt data
    const uint32_t plain_size = plain.GetSize();
    tag.SetSize(TAG_SIZE);
    cipher.SetSize(plain_size);
    int result = mbedtls_gcm_crypt_and_tag(
        aes128gcm_ctx.GetContext(),
        MBEDTLS_GCM_ENCRYPT,
        plain_size,
        iv.GetBuffer(), iv.GetSize(),
        data.GetBuffer(), data.GetSize(),
        plain.GetBuffer(), 
        cipher.GetBuffer(),
        TAG_SIZE, tag.GetBuffer()
    );    
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_crypt_and_tag failed: %d", result);
}

// AES-128-GCM decrypt
void SKCryptoMbedTLS::AES128GCMDecrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& data, const SKBinaryBuffer& cipher, const SKBinaryBuffer& tag, SKBinaryBuffer& plain)
{
    // Check iv size
    SK_CHECK(iv.GetSize() >= 12, SK_ERROR_INVALID_PARAMETER, "Invalid iv size: %d", iv.GetSize());

    // Check data size
    SK_CHECK(data.GetSize() >= 16, SK_ERROR_INVALID_PARAMETER, "Invalid data size: %d", data.GetSize());

    // Check tag size
    SK_CHECK(tag.GetSize() == TAG_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid tag size: %d", tag.GetSize());

    // Cipher must be a multiple of AES-128 block size
    SK_CHECK(cipher.GetSize() % AES128_KEY_SIZE == 0, SK_ERROR_INVALID_PARAMETER, "Invalid cipher size: %d", cipher.GetSize());

    // Get decryped key
    SKStaticBinaryBuffer<MAX_KEY_SIZE> key;
    GetDecryptedKey(key_id, key);

    // Schedule key
    SKAESGCMContext aes128gcm_ctx(key);

    // Decrypt data
    const uint32_t cipher_size = cipher.GetSize();
    plain.SetSize(cipher_size);
    int result = mbedtls_gcm_auth_decrypt(
        aes128gcm_ctx.GetContext(),
        cipher_size,
        iv.GetBuffer(), iv.GetSize(),
        data.GetBuffer(), data.GetSize(),
        tag.GetBuffer(), tag.GetSize(),
        cipher.GetBuffer(), 
        plain.GetBuffer()
    );
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_gcm_auth_decrypt failed: %d", result);
}   

// AES-128-CBC encrypt
void SKCryptoMbedTLS::AES128CBCEncrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& plain, SKBinaryBuffer& cipher) {

        // Check iv size
    SK_CHECK(iv.GetSize() == 16, SK_ERROR_INVALID_PARAMETER, "Invalid iv size: %d", iv.GetSize());

    // Data must be padded to AES-128 block size
    SK_CHECK(plain.GetSize() % AES128_KEY_SIZE == 0, SK_ERROR_INVALID_PARAMETER, "Invalid data size: %d", plain.GetSize());

    // Get decryped key
    SKStaticBinaryBuffer<MAX_KEY_SIZE> key;
    GetDecryptedKey(key_id, key);

    // Schedule key
    SKAESCBCContext aes128cbc_ctx(key, SKAESCBCContext::ENCRYPT);

    // IV is updated after each call to mbedtls_aes_crypt_cbc
    SKStaticBinaryBuffer<16> iv_copy(iv);

    // Encrypt data
    const uint32_t plain_size = plain.GetSize();
    cipher.SetSize(plain_size);
    int result = mbedtls_aes_crypt_cbc(
        aes128cbc_ctx.GetContext(),
        MBEDTLS_AES_ENCRYPT,
        plain_size,
        iv_copy.GetBuffer(),
        plain.GetBuffer(), 
        cipher.GetBuffer()
    );    
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_aes_crypt_cbc failed: %d", result);
}

// AES-128-CBC decrypt
void SKCryptoMbedTLS::AES128CBCDecrypt(const SKKeyId key_id, const SKBinaryBuffer& iv, const SKBinaryBuffer& cipher, SKBinaryBuffer& plain) {

    // Check iv size
    SK_CHECK(iv.GetSize() == 16, SK_ERROR_INVALID_PARAMETER, "Invalid iv size: %d", iv.GetSize());

    // Cipher must be a multiple of AES-128 block size
    SK_CHECK(cipher.GetSize() % AES128_KEY_SIZE == 0, SK_ERROR_INVALID_PARAMETER, "Invalid cipher size: %d", cipher.GetSize());

    // Get decryped key
    SKStaticBinaryBuffer<MAX_KEY_SIZE> key;
    GetDecryptedKey(key_id, key);

    // Schedule key
    SKAESCBCContext aes128cbc_ctx(key, SKAESCBCContext::DECRYPT);

    // IV is updated after each call to mbedtls_aes_crypt_cbc
    SKStaticBinaryBuffer<16> iv_copy(iv);

    // Decrypt data
    const uint32_t cipher_size = cipher.GetSize();
    plain.SetSize(cipher_size);
    int result = mbedtls_aes_crypt_cbc(
        aes128cbc_ctx.GetContext(),
        MBEDTLS_AES_DECRYPT,
        cipher_size,
        iv_copy.GetBuffer(),
        cipher.GetBuffer(), 
        plain.GetBuffer()
    );    
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_aes_crypt_cbc failed: %d", result);
}

// Export key
void SKCryptoMbedTLS::ExportKey(const SKKeyId key_id, SKBinaryBuffer& key)
{
    // Get key data
    SKKeyData& key_data = GetKeyData(key_id);

    // Get encrypted key
    const SKBinaryBuffer& cipher = key_data.GetKey();

    // Get key type
    const SKKeyData::SKKeyType key_type = key_data.GetKeyType();

    // Get buffer size
    const uint32_t buffer_size = cipher.GetSize() + sizeof(uint32_t);

    // Allocate buffer
    key.SetSize(buffer_size);

    // Set key type
    uint8_t* buffer = key.GetBuffer();
    Int32ToByteString(key_type, buffer);
    buffer += sizeof(uint32_t);

    // Set key
    memcpy(buffer, cipher.GetBuffer(), cipher.GetSize());
}

// Import key
void SKCryptoMbedTLS::ImportKey(const SKBinaryBuffer& key, SKKeyId& key_id)
{
    // Key size is at least 36 bytes
    SK_CHECK(key.GetSize() >= 36, SK_ERROR_INVALID_PARAMETER, "Invalid key size: %d", key.GetSize());

    // Get key type
    const uint8_t* buffer = key.GetBuffer();
    const SKKeyData::SKKeyType key_type = (SKKeyData::SKKeyType)ByteStringToInt32(buffer);
    buffer += sizeof(uint32_t);

    // Check key type
    switch (key_type) {

        // AES-128-GCM key
        case SKKeyData::SK_KEY_TYPE_AES_GCM_128:
            // Check AES blob size
            SK_CHECK(key.GetSize() == AES128_EXPORT_BLOB_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid blob size: %d", key.GetSize());
            break;

        // ECDSA P-256 key
        case SKKeyData::SK_KEY_TYPE_ECDSA_P256:
            // Check P-256 blob size
            SK_CHECK(key.GetSize() == ECDSAP256_EXPORT_BLOB_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid blob size: %d", key.GetSize());
            break;

        // Invalid key type
        default:
            SK_CHECK(false, SK_ERROR_INVALID_PARAMETER, "Invalid key type: %d", key_type);
    }

    // Get key
    SKStaticBinaryBuffer<256> cipher;
    cipher.Set(buffer, key.GetSize() - sizeof(uint32_t));

    // Add key to key data map
    key_id = AddKey(cipher, key_type);
}

// Unwrap key AES-128-GCM
void SKCryptoMbedTLS::UnwrapKeyAES128GCM(const SKKeyId key_id, const SKBinaryBuffer& key_blob, SKKeyId& key_id_new) {

    // Check key blob size
    SK_CHECK(key_blob.GetSize() == AES128_WRAPPED_KEY_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid blob size: %d", key_blob.GetSize());

    // Unwrap key blop
    key_id_new = UnwrapKey(key_id, key_blob, SKKeyData::SK_KEY_TYPE_AES_GCM_128);
}

// Generate ECDSA P-256 key pair
void SKCryptoMbedTLS::ECDSAP256GenerateKeyPair(SKKeyId& key_id)
{
    // Context
    SKECDSAContext ctx;

    // Generate key pair
    int result = mbedtls_ecdsa_genkey(ctx.GetContext(), MBEDTLS_ECP_DP_SECP256R1, ecdsa_prng, m_sprng.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_genkey failed: %d", result);

    // Get 32 bytes private key
    SKDynamicBinaryBuffer privateKey(ECDSA_PRIVATE_KEY_LENGTH);
    privateKey.SetSize(ECDSA_PRIVATE_KEY_LENGTH);
    result = mbedtls_mpi_write_binary(&ctx.GetContext()->MBEDTLS_PRIVATE(d), privateKey.GetBuffer(), ECDSA_PRIVATE_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_mpi_write_binary failed: %d", result);

    // Get 65 bytes public key 0x04 + 32 bytes x + 32 bytes y
    size_t olen = 0;
    SKDynamicBinaryBuffer publicKey(ECDSA_PUBLIC_KEY_LENGTH);
    publicKey.SetSize(ECDSA_PUBLIC_KEY_LENGTH);
    result = mbedtls_ecp_point_write_binary(
        &ctx.GetContext()->MBEDTLS_PRIVATE(grp), 
        &ctx.GetContext()->MBEDTLS_PRIVATE(Q), 
        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, 
        publicKey.GetBuffer(), ECDSA_PUBLIC_KEY_LENGTH);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecp_point_write_binary failed: %d", result);

    // Create key blob
    SKDynamicBinaryBuffer keyBlob(ECDSA_PRIVATE_KEY_LENGTH + ECDSA_PUBLIC_KEY_LENGTH);
    keyBlob += privateKey;
    keyBlob += publicKey;

    // Add key to key data map
    key_id = EncryptoAndAddKey(keyBlob, SKKeyData::SK_KEY_TYPE_ECDSA_P256);
}

// Sign data using ECDSA P-256 key
void SKCryptoMbedTLS::ECDSAP256Sign(const SKKeyId key_id, const SKBinaryBuffer& data, SKBinaryBuffer& signature)
{
    // Load key in context
    SKECDSAContext ctx;
    LoadECDSAP256KeyPair(key_id, ctx);

    // Compute SHA256 hash of data
    SKStaticBinaryBuffer<SHA256_HASH_SIZE> hash;
    hash.SetSize(SHA256_HASH_SIZE);
    int result = mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_sha256 failed: %d", result);

    // Sign hash
    signature.SetSize(MBEDTLS_ECDSA_MAX_LEN);
    size_t sig_len = 0;
    result = mbedtls_ecdsa_write_signature(
        ctx.GetContext(), 
        MBEDTLS_MD_SHA256, 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize(),
        &sig_len, 
        ecdsa_prng, m_sprng.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_write_signature failed: %d", result);

    // Set signature size
    signature.UpdateSize(sig_len);
}

// Verify data using ECDSA P-256 key
void SKCryptoMbedTLS::ECDSAP256Verify(const SKKeyId key_id, const SKBinaryBuffer& data, const SKBinaryBuffer& signature)
{
    // Load key in context
    SKECDSAContext ctx;
    LoadECDSAP256KeyPair(key_id, ctx);

    // Compute SHA256 hash
    SKStaticBinaryBuffer<SHA256_HASH_SIZE> hash;
    hash.SetSize(SHA256_HASH_SIZE);
    int result = mbedtls_sha256(data.GetBuffer(), data.GetSize(), hash.GetBuffer(), 0);
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_sha256 failed: %d", result);

    // Verify signature
    result = mbedtls_ecdsa_read_signature(
        ctx.GetContext(), 
        hash.GetBuffer(), hash.GetSize(), 
        signature.GetBuffer(), signature.GetSize());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_read_signature failed: %d", result);
}

// Sign digest using ECDSA P-256 key
void SKCryptoMbedTLS::ECDSAP256DigestSign(const SKKeyId key_id, const SKBinaryBuffer& digest, SKBinaryBuffer& signature)
{
    // Check digest size
    SK_CHECK(digest.GetSize() == SHA256_HASH_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid digest size: %d", digest.GetSize());


    // Load key in context
    SKECDSAContext ctx;
    LoadECDSAP256KeyPair(key_id, ctx);

    // Sign hash
    signature.SetSize(MBEDTLS_ECDSA_MAX_LEN);
    size_t sig_len = 0;
    int result = mbedtls_ecdsa_write_signature(
        ctx.GetContext(), 
        MBEDTLS_MD_SHA256, 
        digest.GetBuffer(), digest.GetSize(), 
        signature.GetBuffer(), signature.GetSize(),
        &sig_len, 
        ecdsa_prng, m_sprng.get());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_write_signature failed: %d", result);

    // Set signature size
    signature.UpdateSize(sig_len);
}

// Verify digest signature using ECDSA P-256 key
void SKCryptoMbedTLS::ECDSAP256DigestVerify(const SKKeyId key_id, const SKBinaryBuffer& digest, const SKBinaryBuffer& signature)
{

    // Check digest size
    SK_CHECK(digest.GetSize() == SHA256_HASH_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid digest size: %d", digest.GetSize());

    // Load key in context
    SKECDSAContext ctx;
    LoadECDSAP256KeyPair(key_id, ctx);

    // Verify signature
    int result = mbedtls_ecdsa_read_signature(
        ctx.GetContext(), 
        digest.GetBuffer(), digest.GetSize(), 
        signature.GetBuffer(), signature.GetSize());
    SK_CHECK(!result, SK_ERROR_MBEDTLS, "mbedtls_ecdsa_read_signature failed: %d", result);
}

// Unwrap key ECDSA P-256
void SKCryptoMbedTLS::UnwrapKeyECDSAP256(const SKKeyId key_id, const SKBinaryBuffer& key_blob, SKKeyId& key_id_new) {

    // Check key blob size
    SK_CHECK(key_blob.GetSize() == ECDSA_WRAPPED_KEY_SIZE, SK_ERROR_INVALID_PARAMETER, "Invalid blob size: %d", key_blob.GetSize());

    // Unwrap key blop
    key_id_new = UnwrapKey(key_id, key_blob, SKKeyData::SK_KEY_TYPE_ECDSA_P256);
}

// Delete key
void SKCryptoMbedTLS::DeleteKey(const SKKeyId key_id)
{
    // Renove key from key data map
    RemoveKey(key_id);
}
