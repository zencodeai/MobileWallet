#pragma once

#include <memory>
#include "sk_utils.hpp"
#include "sk_binary_buffer.hpp"
#include "sqlite3.h"

// SKSecureStore shared pointer type
typedef std::shared_ptr<class SKSecureStore> SKSecureStorePtr;

// Secure store interface
class SKSecureStore
{
public:

    // Destructor
    virtual ~SKSecureStore() {}

    // Create secure store
    virtual void Create(const char* path) = 0;

    // Open secure store
    virtual void Open(const char* path) = 0;

    // Close secure store
    virtual void Close() = 0;

    // Has key
    virtual bool HasKey(const char* key) = 0;

    // Get key
    virtual void GetKey(const char* key, SKBinaryBuffer& buffer) = 0;

    // Set key
    virtual void SetKey(const char* key, const SKBinaryBuffer& buffer) = 0;

    // Delete key
    virtual void DeleteKey(const char* key) = 0;

    // Begin transaction
    virtual void BeginTransaction() = 0;

    // Commit transaction
    virtual void CommitTransaction() = 0;

    // Rollback transaction
    virtual void RollbackTransaction() = 0;

    // Class factory
    static SKSecureStorePtr Create();
};
