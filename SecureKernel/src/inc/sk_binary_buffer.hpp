#pragma once

#include <string.h>
#include <cstdarg>

#include "sk_utils.hpp"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

// Binary buffer class interface
class SKBinaryBuffer {

    // Compare buffer
    SKBoolean compare(const SKBinaryBuffer& buffer) const {
        if (GetSize() != buffer.GetSize()) {
            return SKBoolean(SK_FALSE);
        }

        if (GetSize() == 0) {
            return SKBoolean(SK_TRUE);
        }

        return SKBoolean((memcmp(GetBuffer(), buffer.GetBuffer(), GetSize()) == 0) ? SK_TRUE : SK_FALSE);
    }

public:

    // Clear buffer
    virtual void Clear() = 0;

    // Reset buffer
    virtual void Reset() = 0;

    // Add buffer to buffer
    virtual void operator+=(const SKBinaryBuffer& buffer) = 0;

    // Copy buffer
    virtual void operator=(const SKBinaryBuffer& buffer) = 0;

    // Compare buffer
    SKBoolean operator==(const SKBinaryBuffer& buffer) const {
        return compare(buffer);
    }

    // Compare buffer
    SKBoolean operator!=(const SKBinaryBuffer& buffer) const {
        return !compare(buffer);
    }

    // XOR buffer
    void operator^=(const SKBinaryBuffer& buffer) const {
        const uint32_t this_size = GetSize();
        const uint32_t buffer_size = buffer.GetSize();
        
        if (!this_size || !buffer_size) {
            return;
        }

        const uint32_t size = (this_size < buffer_size) ? this_size : buffer_size;

        uint8_t* p = GetBuffer();
        const uint8_t* q = buffer.GetBuffer();
        for (int i = 0; i < size; i++) {
            *(p++) ^= *(q++);
        }
    }

    // Set size
    virtual void SetSize(const uint32_t size) = 0;

    // Change size
    virtual void UpdateSize(const uint32_t size) = 0;

    // Set
    virtual void Set(const uint8_t* buffer, const uint32_t size) = 0;

    // Get buffer
    virtual uint8_t* GetBuffer() const = 0;

    // Convert to const char*
    virtual operator const char*() const = 0;

    // Get buffer size
    virtual uint32_t GetSize() const = 0;

    // Get buffer capacity
    virtual uint32_t GetCapacity() const = 0;

    // Extract data
    virtual void Extract(const uint32_t offset, const uint32_t size, SKBinaryBuffer& buffer) const = 0;
};

// Static Binary buffer class template (for static buffers)
template <uint32_t capacity> class SKStaticBinaryBuffer: public SKBinaryBuffer {

private:

    uint32_t m_size;
    uint8_t m_buffer[capacity];

    // Zeroize buffer
    void Zeroize() {
        mbedtls_platform_zeroize(m_buffer, capacity);
    }

    // Copy buffer
    void Copy(const SKBinaryBuffer& buffer) {

        Reset();

        const uint32_t size = buffer.GetSize();
        SK_CHECK(size <= capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");

        if (!size) {

            return;
        }

        memcpy(m_buffer, buffer.GetBuffer(), size);
        m_size = size;
    }


public:

    // Constructor
    SKStaticBinaryBuffer() {

        Reset();
    }

    // Copy constructor
    SKStaticBinaryBuffer(const SKBinaryBuffer& buffer) {

        Copy(buffer);
    }

    // Set constructor
    SKStaticBinaryBuffer(const uint8_t* buffer, const uint32_t size) {

        Set(buffer, size);
    }

    // Destructor
    ~SKStaticBinaryBuffer() {

        Reset();
    }

    // Clear buffer
    void Clear() {

        Reset();
    }

    // Reset buffer
    void Reset() {
        Zeroize();
        m_size = 0;
    }

    // Add buffer to buffer
    void operator+=(const SKBinaryBuffer& buffer) {

        const uint32_t size = buffer.GetSize();

        if (!size) {
            return;
        }

        SK_CHECK(m_size + size <= capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
        memcpy(m_buffer + m_size, buffer.GetBuffer(), size);
        m_size += size;
    }

    // Copy buffer
    void operator=(const SKBinaryBuffer& buffer) {

        Copy(buffer);
    }

    // Set size
    void SetSize(const uint32_t size) {

        SK_CHECK(size <= capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");

        Clear();
        if (!size) {
            return;
        }

        m_size = size;
    }

    // Change size
    void UpdateSize(const uint32_t size) {

        SK_CHECK(size <= capacity, SK_ERROR_INVALID_PARAMETER, "Invalid size: %d", size);

        m_size = size;
    }

    // Set
    void Set(const uint8_t* buffer, const uint32_t size) {

        SK_CHECK(size <= capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");

        Clear();
        if (!size) {
            return;
        }

        memcpy(m_buffer, buffer, size);
        m_size = size;
    }

    // Get buffer
    uint8_t* GetBuffer() const {

        return (uint8_t*)(&m_buffer[0]);
    }

    // Convert to const char*
    operator const char*() const {

        SK_CHECK(strnlen((const char*)(&m_buffer[0]), capacity) < capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
        return (const char*)(&m_buffer[0]);
    }

    // Get buffer size
    uint32_t GetSize() const {

        return m_size;
    }

    // Get buffer capacity
    uint32_t GetCapacity() const {

        return capacity;
    }

    // Extract data
    void Extract(const uint32_t offset, const uint32_t size, SKBinaryBuffer& buffer) const {

        SK_CHECK(offset + size <= m_size, SK_ERROR_INVALID_PARAMETER, "Invalid parameter");

        buffer.Set(m_buffer + offset, size);
    }
};

// Inlined Dynamic binary buffer class  with capacity
class SKDynamicBinaryBuffer: public SKBinaryBuffer {

private:

    uint32_t m_capacity;
    uint32_t m_size;
    uint8_t* m_buffer;

    // Zeroize buffer
    void Zeroize() {

        if (m_buffer && m_capacity) {

            mbedtls_platform_zeroize(m_buffer, m_capacity);
        }
    }

   // Initialize buffer
    void Initialize(uint32_t capacity) {

        m_capacity = capacity;
        m_size = 0;

        if (!m_capacity) {

            m_buffer = nullptr;
            return;
        }

        m_buffer = new uint8_t[m_capacity];
        Zeroize();
    }

    // Copy buffer
    void Copy(const SKBinaryBuffer& buffer) {

        Reset();

        const uint32_t capacity = buffer.GetCapacity();
        const uint32_t size = buffer.GetSize();

        if (!capacity) {

            return;
        }

        Initialize(capacity);

        if (!size) {

            return;
        }

        memcpy(m_buffer, buffer.GetBuffer(), size);
        m_size = size;
    }

public:

    // Constructor
    SKDynamicBinaryBuffer(uint32_t capacity = 0) {

        Initialize(capacity);
    }

    // Copy constructor
    SKDynamicBinaryBuffer(const SKBinaryBuffer& buffer) {

        Initialize(0);
        Copy(buffer);
    }

    // Set constructor
    SKDynamicBinaryBuffer(const uint8_t* buffer, const uint32_t size) {

        Initialize(0);
        Set(buffer, size);
    }

    // Destructor
    ~SKDynamicBinaryBuffer() {

        Reset();
    }

    // Clear buffer
    void Clear() {

        Zeroize();
        m_size = 0;
    }

    // Reset buffer
    void Reset() {

        Clear();

        if (m_buffer) {

            delete[] m_buffer;
        }

        m_buffer = nullptr;
        m_capacity = 0;
    }

    // Add buffer to buffer
    void operator+=(const SKBinaryBuffer& buffer) {

        const uint32_t size = buffer.GetSize();

        if (!size) {
            return;
        }

        SK_CHECK(m_buffer && m_capacity, SK_ERROR_INVALID_STATE, "Invalid state")
        SK_CHECK(m_size + size <= m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
        memcpy(m_buffer + m_size, buffer.GetBuffer(), size);
        m_size += size;
    }

    // Copy buffer
    void operator=(const SKBinaryBuffer& buffer) {

        Copy(buffer);
    }

    // Set size
    void SetSize(const uint32_t size) {

        if (!size) {

            return;
        }

        if (m_buffer) {

            SK_CHECK(size <= m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
            Clear();

        } else {

            Initialize(size);
        }

        m_size = size;
    }

    // Change size
    void UpdateSize(const uint32_t size) {

        SK_CHECK(size <= m_capacity, SK_ERROR_INVALID_PARAMETER, "Invalid size: %d", size);
        m_size = size;
    }

    // Set
    void Set(const uint8_t* buffer, const uint32_t size) {

        if (!size) {

            return;
        }

        if (m_buffer) {

            SK_CHECK(size <= m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
            Clear();

        } else {

            Initialize(size);
        }

        memcpy(m_buffer, buffer, size);
        m_size = size;
    }

    // Get buffer
    uint8_t* GetBuffer() const {

        return m_buffer;
    }

    // Convert to const char*
    operator const char*() const {

        if (!m_buffer) {

            return nullptr;
        }

        SK_CHECK(strnlen((const char*)(&m_buffer[0]), m_capacity) < m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
        return (const char*)(&m_buffer[0]);
    }

    // Get buffer size
    uint32_t GetSize() const {

        return m_size;
    }

    // Get buffer capacity
    uint32_t GetCapacity() const {

        return m_capacity;
    }

    // Extract data
    void Extract(const uint32_t offset, const uint32_t size, SKBinaryBuffer& buffer) const {

        SK_CHECK(offset + size <= m_size, SK_ERROR_INVALID_PARAMETER, "Invalid parameter");

        buffer.Set(m_buffer + offset, size);
    }
};

// Weak reference to another buffer
class SKBinaryBufferView: public SKBinaryBuffer {

private:

    uint32_t m_capacity;
    uint32_t m_size;
    uint8_t* m_buffer;

    // Zeroize buffer
    void Zeroize() {

        mbedtls_platform_zeroize(m_buffer, m_capacity);
    }

public:

    // Constructor
    SKBinaryBufferView(const uint32_t offset, const uint32_t size, const SKBinaryBuffer& buffer) {

        // Check parameters
        SK_CHECK(offset + size <= buffer.GetCapacity(), SK_ERROR_INVALID_PARAMETER, "Invalid parameter");
        SK_CHECK(buffer.GetBuffer() && size, SK_ERROR_INVALID_PARAMETER, "Invalid parameter");

        // Initialize
        m_capacity = size;
        m_size = size;
        m_buffer = (uint8_t*)buffer.GetBuffer() + offset;
    }

    // Set constructor
    SKBinaryBufferView(uint8_t* buffer, const uint32_t size) {

        // Check parameters
        SK_CHECK(buffer && size, SK_ERROR_INVALID_PARAMETER, "Invalid parameter");

        // Initialize
        m_capacity = size;
        m_size = size;
        m_buffer = buffer;
    }

    // Field constructor
    SKBinaryBufferView(const uint32_t offset, const SKBinaryBuffer& buffer) {

        // Check parameters
        SK_CHECK(offset + sizeof(uint16_t) < buffer.GetCapacity(), SK_ERROR_INVALID_PARAMETER, "Invalid parameter");
        SK_CHECK(buffer.GetBuffer(), SK_ERROR_INVALID_PARAMETER, "Invalid parameter");

        // Initialize
        m_capacity = buffer.GetCapacity() - offset - sizeof(uint16_t);
        m_size = m_capacity;
        m_buffer = (uint8_t*)buffer.GetBuffer() + offset + sizeof(uint16_t);
    }

    // Update field
    void UpdateField(uint32_t& offset, SKBinaryBuffer& buffer) {

        // Check parameters
        SK_CHECK(offset + sizeof(uint16_t) < buffer.GetCapacity(), SK_ERROR_INVALID_PARAMETER, "Invalid parameter");
        SK_CHECK(buffer.GetBuffer(), SK_ERROR_INVALID_PARAMETER, "Invalid parameter");

        // Set field length
        m_buffer[-2] = (uint8_t) (m_size >> 8);
        m_buffer[-1] = (uint8_t) m_size;

        // Update offset
        offset += m_size + sizeof(uint16_t);

        // Update buffer
        buffer.UpdateSize(offset);
    }

    // Clear buffer
    void Clear() {

        Zeroize();
        m_size = 0;
    }

    // Reset buffer
    void Reset() {

        Clear();
    }

    // Add buffer to buffer
    void operator+=(const SKBinaryBuffer& buffer) {

        const uint32_t size = buffer.GetSize();

        if (!size) {
            return;
        }

        SK_CHECK(m_size + size <= m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
        memcpy(m_buffer + m_size, buffer.GetBuffer(), size);
        m_size += size;
    }

    // Copy buffer
    void operator=(const SKBinaryBuffer& buffer) {

        Clear();

        const uint32_t capacity = buffer.GetCapacity();
        const uint32_t size = buffer.GetSize();
        const uint8_t* pbuffer = buffer.GetBuffer();

        if (!capacity || !size || !pbuffer) {

            return;
        }
        
        memcpy(m_buffer, pbuffer, size);
        m_size = size;
    }

    // Set size
    void SetSize(const uint32_t size) {

        Clear();
        UpdateSize(size);
    }

    // Change size
    void UpdateSize(const uint32_t size) {

        SK_CHECK(size <= m_capacity, SK_ERROR_INVALID_PARAMETER, "Invalid size: %d", size);
        m_size = size;
    }

    // Set
    void Set(const uint8_t* buffer, const uint32_t size) {

        SK_CHECK(buffer, SK_ERROR_INVALID_PARAMETER, "Invalid parameter");
        SK_CHECK(size <= m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");

        Clear();

        if (!size) {

            return;
        }

        memcpy(m_buffer, buffer, size);
        m_size = size;
    }

    // Get buffer
    uint8_t* GetBuffer() const {

        return m_buffer;
    }

    // Convert to const char*
    operator const char*() const {

        SK_CHECK(strnlen((const char*)(&m_buffer[0]), m_capacity) < m_capacity, SK_ERROR_BUFFER_OVERFLOW, "Buffer overflow");
        return (const char*)(&m_buffer[0]);
    }

    // Get buffer size
    uint32_t GetSize() const {

        return m_size;
    }

    // Get buffer capacity
    uint32_t GetCapacity() const {

        return m_capacity;
    }

    // Extract data
    void Extract(const uint32_t offset, const uint32_t size, SKBinaryBuffer& buffer) const {

        SK_CHECK(offset + size <= m_size, SK_ERROR_INVALID_PARAMETER, "Invalid parameter");
        buffer.Set(m_buffer + offset, size);
    }
};

// Constant arrays class
template<size_t SIZE> class SKConstant
{

private:

    SKStaticBinaryBuffer<SIZE> m_buffer;

public:

    // Checksum size
    static const size_t HASH_SIZE = 32;

    // Constructor
    SKConstant(int first, ...) {

        // Initialize buffer
        m_buffer.SetSize(SIZE);

        // Copy data
        uint8_t* p = m_buffer.GetBuffer();
        *(p ++) = (uint8_t) first;
        std::va_list args;
        va_start(args, first);
        for (int i = 1; i < SIZE; i++) {
            *(p ++) = (uint8_t) va_arg(args, int);
        }
        va_end(args);
    }

    // Unmask buffer
    void Unmask(const SKConstant<SIZE>& mask) {

        // Unmask data
        uint8_t* p = m_buffer.GetBuffer();
        const uint8_t* q = mask.GetBuffer().GetBuffer();
        for (int i = 0; i < SIZE; i++) {
            *(p++) ^= *(q++);
        }
    }

    // Verify hash
    void VerifyHash(const SKConstant<HASH_SIZE>& hash) {

        uint8_t sha256[HASH_SIZE];

        // Calculate SHA256
        mbedtls_sha256(m_buffer.GetBuffer(), SIZE, sha256, 0);

        // Verify hash
        const uint32_t size = m_buffer.GetSize();
        uint8_t* pdata = m_buffer.GetBuffer();
        uint8_t* p = sha256;
        const uint8_t* q = hash.GetBuffer().GetBuffer();
        for (int i = 0; i < sizeof(sha256); i++) {
            pdata[((i * 33) + pdata[i]) % size] ^= *(p++) ^ *(q++);
        }
    }

    // Get buffer
    const SKBinaryBuffer& GetBuffer() const {
        return m_buffer;
    }
};
