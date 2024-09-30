#include "sk_secure_store.hpp"

extern "C" {

    #include "sqlite3.h"
}

// SQLite secure store class
class SKSQLiteSecureStore : public SKSecureStore
{
private:

    sqlite3* m_db;

    // Create table
    void CreateTable();

    // Drop table
    void DropTable();

public:

    // Constructor
    SKSQLiteSecureStore();

    // Destructor
    ~SKSQLiteSecureStore();

    // Create secure store
    void Create(const char* path);

    // Open secure store
    void Open(const char* path);

    // Close secure store
    void Close();

    // Has key
    bool HasKey(const char* key);

    // Get key
    void GetKey(const char* key, SKBinaryBuffer& buffer);

    // Set key
    void SetKey(const char* key, const SKBinaryBuffer& buffer);

    // Delete key
    void DeleteKey(const char* key);

    // Begin transaction
    void BeginTransaction();

    // Commit transaction
    void CommitTransaction();

    // Rollback transaction
    void RollbackTransaction();
};

// Class factory (return smart pointer)
SKSecureStorePtr SKSecureStore::Create() {
    return SKSecureStorePtr(new SKSQLiteSecureStore());
}

// SQLite KEY, VALUE statement class
class SQLiteKeyValStatement {

private:

    sqlite3_stmt* m_stmt;

public:

    // Constructor
    SQLiteKeyValStatement(sqlite3* db, const char* sql) {
        const int result = sqlite3_prepare_v2(db, sql, -1, &m_stmt, NULL);
        SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to prepare statement");
    }

    // Destructor
    ~SQLiteKeyValStatement() {

        if (m_stmt) {
            sqlite3_finalize(m_stmt);
        }
    }

    // Bind key
    void BindKey(const char* key) {
        const int result = sqlite3_bind_text(m_stmt, 1, key, -1, SQLITE_STATIC);
        SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to bind key");
    }

    // Bind value
    void BindValue(const void* value, uint32_t size) {
        const int result = sqlite3_bind_blob(m_stmt, 2, value, size, SQLITE_STATIC);
        SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to bind value");
    }

    // Execute
    int Execute() {
        // Execute statement
        int ret = sqlite3_step(m_stmt);
        // Check for error
        SK_CHECK(ret == SQLITE_DONE || ret == SQLITE_ROW, SK_ERROR_SQLITE, "Failed to execute statement");
        return ret;
    }

    // Get value size
    uint32_t GetValueSize() {
        return sqlite3_column_bytes(m_stmt, 0);
    }

    // Get count value
    uint32_t GetCountValue() {
        return sqlite3_column_int(m_stmt, 0);
    }

    // Read value
    void ReadValue(void* value, uint32_t* size) {

        // Get value size
        *size = sqlite3_column_bytes(m_stmt, 0);

        // Copy value
        memcpy(value, sqlite3_column_blob(m_stmt, 0), *size);
    }
};


// Create table
void SKSQLiteSecureStore::CreateTable() {

    // Create table query
    const char* query = "CREATE TABLE IF NOT EXISTS KEYS (KEY TEXT PRIMARY KEY, VALUE BLOB);";

    // Execute query
    const int result = sqlite3_exec(m_db, query, NULL, NULL, NULL);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to create table");
}

// Drop table
void SKSQLiteSecureStore::DropTable() {

    // Drop table query
    const char* query = "DROP TABLE IF EXISTS KEYS;";

    // Execute query
    const int result = sqlite3_exec(m_db, query, NULL, NULL, NULL);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to drop table");
}

// Constructor
SKSQLiteSecureStore::SKSQLiteSecureStore() : m_db(NULL) {}

// Destructor
SKSQLiteSecureStore::~SKSQLiteSecureStore() {

    // Close secure store
    Close();
}

// Create secure store
void SKSQLiteSecureStore::Create(const char* path) {

    // Close secure store
    Close();

    // Create database
    const int result = sqlite3_open(path, &m_db);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to create database");

    // Create table
    CreateTable();
}

// Open secure store
void SKSQLiteSecureStore::Open(const char* path) {

    // Close secure store
    Close();

    // Open database
    const int result = sqlite3_open(path, &m_db);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to open database");
}

// Close secure store
void SKSQLiteSecureStore::Close() {

    // Close database
    if (m_db) {
        const int result = sqlite3_close(m_db);
        SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to close database");
        m_db = NULL;
    }
}

// Has key
bool SKSQLiteSecureStore::HasKey(const char* key) {

    // Has key query
    const char* query = "SELECT COUNT(*) FROM KEYS WHERE KEY = ?;";

    // Create statement
    SQLiteKeyValStatement stmt(m_db, query);

    // Bind key
    stmt.BindKey(key);

    // Execute statement
    int result = stmt.Execute();
    SK_CHECK(result == SQLITE_ROW, SK_ERROR_SQLITE, "Failed to check key");
    const uint32_t count = stmt.GetCountValue();

    // Done if no rows
    result = stmt.Execute();
    SK_CHECK(result == SQLITE_DONE, SK_ERROR_SQLITE, "Unexpected result");
    
    return count > 0;
}

// Get key
void SKSQLiteSecureStore::GetKey(const char* key, SKBinaryBuffer& buffer) {

    // Get key query
    const char* query = "SELECT VALUE FROM KEYS WHERE KEY = ?;";

    // Create statement
    SQLiteKeyValStatement stmt(m_db, query);

    // Bind key
    stmt.BindKey(key);

    // Execute statement
    int result = stmt.Execute();
    SK_CHECK(result == SQLITE_ROW, SK_ERROR_SQLITE, "Failed to get key");
    
    // Read value
    uint32_t size = stmt.GetValueSize();
    buffer.SetSize(size);
    stmt.ReadValue(buffer.GetBuffer(), &size);

    // Only one row should be returned
    result = stmt.Execute();
    SK_CHECK(result == SQLITE_DONE, SK_ERROR_SQLITE, "Should be only one row");
}

// Set key
void SKSQLiteSecureStore::SetKey(const char* key, const SKBinaryBuffer& buffer) {

    // Set key query
    const char* query = "INSERT OR REPLACE INTO KEYS (KEY, VALUE) VALUES (?, ?);";

    // Create statement
    SQLiteKeyValStatement stmt(m_db, query);

    // Bind key
    stmt.BindKey(key);

    // Bind value
    stmt.BindValue(buffer.GetBuffer(), buffer.GetSize());

    // Execute statement
    const bool result = stmt.Execute();
    SK_CHECK(result, SK_ERROR_SQLITE, "Failed to set key");
}

// Delete key
void SKSQLiteSecureStore::DeleteKey(const char* key) {

    // Delete key query
    const char* query = "DELETE FROM KEYS WHERE KEY = ?;";

    // Create statement
    SQLiteKeyValStatement stmt(m_db, query);

    // Bind key
    stmt.BindKey(key);

    // Execute statement
    const bool result = stmt.Execute();
    SK_CHECK(result, SK_ERROR_SQLITE, "Failed to delete key");

    // Check if key was deleted
    SK_CHECK(sqlite3_changes(m_db) > 0, SK_ERROR_SQLITE, "Failed to delete key");
}

// Start transaction
void SKSQLiteSecureStore::BeginTransaction() {

    // Begin transaction query
    const char* query = "BEGIN TRANSACTION;";

    // Execute query
    const int result = sqlite3_exec(m_db, query, NULL, NULL, NULL);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to begin transaction");
}

// Commit transaction
void SKSQLiteSecureStore::CommitTransaction() {

    // Commit transaction query
    const char* query = "COMMIT TRANSACTION;";

    // Execute query
    const int result = sqlite3_exec(m_db, query, NULL, NULL, NULL);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to commit transaction");
}

// Rollback transaction
void SKSQLiteSecureStore::RollbackTransaction() {

    // Rollback transaction query
    const char* query = "ROLLBACK TRANSACTION;";

    // Execute query
    const int result = sqlite3_exec(m_db, query, NULL, NULL, NULL);
    SK_CHECK(result == SQLITE_OK, SK_ERROR_SQLITE, "Failed to rollback transaction");
}
