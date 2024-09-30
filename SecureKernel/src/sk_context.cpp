#include "sk.h"

#include <fstream>

#include "sk_binary_buffer.hpp"
#include "sk_session_provision.hpp"
#include "sk_session_online.hpp"
#include "sk_session_offline_payor.hpp"
#include "sk_session_offline_payee.hpp"
#include "sk_app_key_store.hpp"
#include "sk_app_key_store_sim.hpp"
#include "sk_crypto.hpp"
#include "sk_crypto_mbedtls.hpp"
#include "sk_utils_platform.hpp"

/* Context class */
class SKContext {

public:

    // Maximum size of the input buffer
    static const size_t MAX_IN_LEN = 2048;

    // Maximum size of the output buffer
    static const size_t MAX_OUT_LEN = SKSession::MAX_TRANSACTION_BUFFER_SIZE;

    // Set error code 
    static void set_error_code(const uint32_t error_code, unsigned char* out, size_t* out_len) {

        static const uint32_t error_msg_size = 2 * sizeof(uint32_t);

        if (out == NULL || out_len == NULL || *out_len < error_msg_size) {

            if (out_len != NULL)
                *out_len = 0;
            return;
        }

        uint32_t* p = (uint32_t*)out;
        p[0] = SK_ERROR_API;
        p[1] = error_code;
        *out_len = error_msg_size;
    }

protected:

    // Error code
    uint32_t m_error_code;

    // State
    uint32_t m_state;

    // Secure store
    SKSecureStorePtr m_spstore;

    // PRNG
    SKRandomPtr m_sprandom;

    // Application key store
    SKApplicationKeyStorePtr m_spappkeystore;

    // Crypto API
    SKCryptoPtr m_spcrypto;

    // Current session
    SKSessionPtr m_spsession;

    // Store pathname
    std::string m_store_pathname;

    // Get secure store pathname
    virtual std::string GetSecureStorePathname() {

        if (m_store_pathname.empty()) {

            // Get application directory
            m_store_pathname = SKGetStoreFilePath(SK_STORE_PATHNAME);
        }

        return m_store_pathname;
    }

    // Create application key store
    virtual void CreateApplicationKeyStore(const bool store_exists) {

        // Instantiate application key store
        m_spappkeystore = SKApplicationKeyStore::Create(
            SKApplicationKeyStoreSimFactoryParameters(m_spstore, m_sprandom));

        // Seed prng
        uint64_t ts = SKUtils::GetTimestamp();
        SKBinaryBufferView seed((uint8_t*)&ts, sizeof(ts));
        m_sprandom->UpdateSeed(seed);

        if (!store_exists) {

            // Generate symmetric key
            m_spappkeystore->GenerateSymmetricKey(SK_APP_KEY_SYM);
        }
    }

    // Create crypto instance
    virtual void CreateCryptoInstance() {

        m_spcrypto = SKCrypto::Create(SKCryptoMbedTLSParams(m_sprandom, m_spstore, m_spappkeystore));
    }

    // Check if store has IUID
    virtual bool StoreHasIUID() {

        SKStoreList::SKStoreKeyBuffer db_iuid_val(SK_DB_TX_IUID_VAL_HEX);
        return m_spstore->HasKey(db_iuid_val);
    }

    // Check if store has balance
    virtual bool StoreHasBalance() {

        SKStoreList::SKStoreKeyBuffer db_balance_val(SK_DB_TX_HEAD_VAL_HEX);
        return m_spstore->HasKey(db_balance_val);
    }

    // Initialize secure kernel
    virtual void Initialize();

    // Execute command
    void ExecuteCommand(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff);

    // Execute command in provisioning state
    void ExecuteCommandProv(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff);

    // Execute command in balance initialization state
    void ExecuteCommandInit(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff);

    // Execute command in ready state
    void ExecuteCommandReady(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff);

    // Get status command
    void CmdGetStatus(const SKBinaryBuffer& params, SKBinaryBuffer& out_buff);

public:

    SKContext() : m_error_code(SK_ERROR_API), m_state(SK_CTX_INV) {

    }

    ~SKContext() {
    }

    // Call secure kernel
    void Call(const unsigned char* in, const size_t in_len, unsigned char* out, size_t* out_len);
};

// Initialize secure kernel
void SKContext::Initialize() {
 
    std::string store_pathname = GetSecureStorePathname();
    bool store_exists = false;

    try {

        // Instantiate secure store
        m_spstore = SKSecureStore::Create();

        // Check if file exists
        std::ifstream f(store_pathname.c_str());

        // Create store if it does not exist
        store_exists = f.good();
        if (!store_exists) {

            // Create secure store
            m_spstore->Create(store_pathname.c_str());

            // Close secure store
            m_spstore->Close();
        }

        // Open secure store
        m_spstore->Open(store_pathname.c_str());

        // Instantiate random number generator
        m_sprandom = SKRandom::Create(m_spstore);

        // Create application key store
        CreateApplicationKeyStore(store_exists);

        // Create crypto instance
        CreateCryptoInstance();

        // Check if store has IUID
        if (!StoreHasIUID()) {

            // Provision secure kernel
            m_state = SK_CTX_PROV;
        }
        // Check if store has balance
        else if (!StoreHasBalance()) {

            // Wait for balance update
            m_state = SK_CTX_INIT;
        }
        else {

            // Secure kernel is ready
            m_state = SK_CTX_READY;
        }

        // Clear error code
        m_error_code = 0;
    } 
    catch(const SKException& e) {

        m_error_code = e.GetCode();
        m_state = SK_CTX_ERROR;
    }
    catch(...) {

        m_error_code = SK_ERROR_FAILED;
        m_state = SK_CTX_ERROR;
    }

    // Delete store on error if it was created
    if (m_state == SK_CTX_ERROR && !store_exists) {

        remove(store_pathname.c_str());
    }
}

// Get status command
void SKContext::CmdGetStatus(const SKBinaryBuffer& params, SKBinaryBuffer& out_buff) {

    // Check parameters
    SK_CHECK(params.GetSize() == 0, SK_ERROR_INVALID_PARAMETER, "Invalid parameters");

    // Get status
    SKBinaryBufferView status_view(0, sizeof(uint32_t), out_buff);
    uint32_t* p = (uint32_t*)status_view.GetBuffer();
    *p = m_state;
    out_buff.UpdateSize(sizeof(uint32_t));
}

// Execute command in provisioning state
void SKContext::ExecuteCommandProv(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff) {

    // Execute high level commands
    switch(cmd) {

        case SK_CMD_ONLINE: {

                m_spsession = SKSessionProvision::Create(m_spcrypto, m_spstore, m_sprandom);
                SKSessionProvision& session = *dynamic_cast<SKSessionProvision*>(m_spsession.get());
                session.Provision(params, out_buff);
            }
            break;

        case SK_CMD_OFFLINE: {

                m_spsession = nullptr;
                m_state = SK_CTX_PROV;
            }
            break;

        case SK_CMD_PROCESS_MSG: {

                SK_CHECK(nullptr != m_spsession, SK_ERROR_API, "Invalid session");
                m_spsession->ProcessMsg(params, out_buff);

                // Done?
                if (!out_buff.GetSize()) {

                    // Update state
                    m_spsession = nullptr;
                    m_state = SK_CTX_INIT;
                }
            }
            break;

        default:
            SK_CHECK(false, SK_ERROR_API, "Invalid provisioning command");
    }
}

// Execute command in balance initialization state
void SKContext::ExecuteCommandInit(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff) {

    // Execute high level commands
    switch(cmd) {

        case SK_CMD_ONLINE: {

                SK_CHECK(params.GetSize() == 0, SK_ERROR_INVALID_PARAMETER, "Invalid parameters");
                m_spsession = SKSessionOnline::Create(m_spcrypto, m_spstore, m_sprandom);
                SKSessionOnline& session = *dynamic_cast<SKSessionOnline*>(m_spsession.get());
                session.StartOnlineBalanceInitialization(out_buff);
            }
            break;

        case SK_CMD_OFFLINE: {

                m_spsession = nullptr;
                m_state = SK_CTX_INIT;
            }
            break;

        case SK_CMD_PROCESS_MSG: {

                SK_CHECK(nullptr != m_spsession, SK_ERROR_API, "Invalid session");
                SK_CHECK(params.GetSize() != 0, SK_ERROR_INVALID_PARAMETER, "Invalid parameters");
                m_spsession->ProcessMsg(params, out_buff);

                // Done?
                if (!out_buff.GetSize()) {

                    // Update state
                    m_spsession = nullptr;
                    m_state = SK_CTX_READY;
                }
            }
            break;

        default:
            SK_CHECK(false, SK_ERROR_API, "Invalid balance initialization command");
    }
}

// Execute command in ready state
void SKContext::ExecuteCommandReady(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff) {

    // Check params size

    // Execute high level commands
    switch(cmd) {

        case SK_CMD_ONLINE: {

                SK_CHECK(params.GetSize() == 0, SK_ERROR_INVALID_PARAMETER, "Invalid parameters");
                m_spsession = SKSessionOnline::Create(m_spcrypto, m_spstore, m_sprandom);
                SKSessionOnline& session = *dynamic_cast<SKSessionOnline*>(m_spsession.get());
                session.StartOnlineSession(out_buff);
            }
            break;

        case SK_CMD_OFFLINE:
            SK_CHECK(params.GetSize() == 0, SK_ERROR_INVALID_PARAMETER, "Invalid parameters");
            m_spsession = nullptr;
            break;

        case SK_CMD_TX_ONLINE: {
                
                SK_CHECK(nullptr != m_spsession, SK_ERROR_API, "Invalid session");
                SKBinaryBufferView amount_view(0, sizeof(uint64_t), params);
                SKBinaryBufferView cuid_view(sizeof(uint64_t), params.GetSize() - sizeof(uint64_t), params);
                const uint64_t amount = *(uint64_t*)amount_view.GetBuffer();
                SKSessionOnline& session = *dynamic_cast<SKSessionOnline*>(m_spsession.get());
                session.StartOnlineTransaction(amount, cuid_view, out_buff);
            }
            break;

        case SK_CMD_TX_OFFLINE_PAYOR: {

                m_spsession = SKSessionOfflinePayor::Create(m_spcrypto, m_spstore, m_sprandom);
                SKBinaryBufferView amount_view(0, sizeof(uint64_t), params);
                const uint64_t amount = *(uint64_t*)amount_view.GetBuffer();
                uint64_t ts = SKUtils::GetTimestamp();
                SKSessionOfflinePayor& session = *dynamic_cast<SKSessionOfflinePayor*>(m_spsession.get());
                session.StartOfflineTransaction(amount, ts, out_buff);
            }
            break;

        case SK_CMD_TX_OFFLINE_PAYEE: {

                m_spsession = SKSessionOfflinePayee::Create(m_spcrypto, m_spstore, m_sprandom);
                SKBinaryBufferView amount_view(0, sizeof(uint64_t), params);
                const uint64_t amount = *(uint64_t*)amount_view.GetBuffer();
                uint64_t ts = SKUtils::GetTimestamp();
                SKSessionOfflinePayee& session = *dynamic_cast<SKSessionOfflinePayee*>(m_spsession.get());
                session.StartOfflineTransaction();
            }
            break;

        case SK_CMD_PROCESS_MSG: {

                SK_CHECK(nullptr != m_spsession, SK_ERROR_API, "Invalid session");
                m_spsession->ProcessMsg(params, out_buff);
            }
            break;

        default:
            SK_CHECK(false, SK_ERROR_API, "Invalid provisioning command");
    }
}

// Execute command
void SKContext::ExecuteCommand(const uint32_t cmd, const SKBinaryBuffer& params, SKBinaryBuffer& out_buff) {

    // Execute high level commands
    switch(cmd) {

        case SK_CMD_STATUS:
            CmdGetStatus(params, out_buff);
            return;

        default:;
    }

    // Execute depending on state
    switch(m_state) {

        case SK_CTX_PROV:
            ExecuteCommandProv(cmd, params, out_buff);
            break;

        case SK_CTX_INIT:
            ExecuteCommandInit(cmd, params, out_buff);
            break;

        case SK_CTX_READY:
            ExecuteCommandReady(cmd, params, out_buff);
            break;

        default: {

            SK_CHECK(false, SK_ERROR_API, "Invalid secure kernel state");
        }
    }
}


// Call secure kernel
void SKContext::Call(const unsigned char* in, const size_t in_len, unsigned char* out, size_t* out_len) {

    // Initialize secure kernel if needed
    if (m_state == SK_CTX_INV) {

        Initialize();
    }

    // Check parameters
    if (in == NULL || in_len < sizeof(uint32_t) || out == NULL || out_len == NULL || in_len > MAX_IN_LEN || *out_len > MAX_OUT_LEN) {

        set_error_code(SK_ERROR_INVALID_PARAMETER, out, out_len);
        return;
    }

    // Error state?
    if (m_state == SK_CTX_ERROR) {

        set_error_code(m_error_code, out, out_len);
        return;
    }

    // Call secure kernel
    try
    {
        SKBinaryBufferView in_buff(const_cast<uint8_t*>(in), in_len);
        SKBinaryBufferView out_buff(out, *out_len);

        // Get command
        SKBinaryBufferView cmd_view(0, sizeof(uint32_t), in_buff);
        const uint32_t cmd = *(uint32_t*)cmd_view.GetBuffer();

        // Get parameters
        const uint32_t params_size = in_len - sizeof(uint32_t);

        if (params_size > 0) {

            SKBinaryBufferView params_view(sizeof(uint32_t), params_size, in_buff);
            ExecuteCommand(cmd, params_view, out_buff);
        } else {

            SKDynamicBinaryBuffer params_buff;
            ExecuteCommand(cmd, params_buff, out_buff);
        }

        // Update out_len
        *out_len = out_buff.GetSize();
    }
    catch(const SKException& e) {

        set_error_code(e.GetCode(), out, out_len);
    }
    catch(...) {

        set_error_code(SK_ERROR_FAILED, out, out_len);
    }
}

// Context instance
static SKContext context;

// API call
void sk_call(const unsigned char* in, const size_t in_len, unsigned char* out, size_t* out_len) {

    context.Call(in, in_len, out, out_len);
}
