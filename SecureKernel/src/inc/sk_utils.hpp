#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <stdint.h>
#include "sk_definitions.hpp"

// Enable debug mode
#define SK_DEBUG

// Secure kernel exception class
class SKException : public std::exception {

private:

    uint32_t m_code;
    std::string m_message;

public:

    // Constructor
    SKException(uint32_t code) {
        m_code = code;
    }

    // Get code
    uint32_t GetCode() const {
        return m_code;
    }

    // What
    const char * what() throw() {
        // Return error code to stl hex string
        std::stringstream sstr;
        sstr << "0x" << std::hex << std::setw(8) << std::setfill('0') << m_code;
        m_message = sstr.str();

        // Return string
        return m_message.c_str();
    }
};

// Throw excpetion variadic macro
#ifdef SK_DEBUG
#include <iostream>
#include <stdarg.h>
// Class that takes a variable number of arguments and formats them into a string
class SKErrorMessage {

private:

    char m_message[1024];

public:

    // Constructor
    SKErrorMessage(const char* message, ...) {

        // Initialize variable arguments
        va_list args;
        va_start(args, message);

        // Format message
        vsnprintf(m_message, sizeof(m_message), message, args);

        // End variable arguments
        va_end(args);
    }

    // Get message
    const char* GetMessage() {
        return m_message;
    }

    // Get message
    operator const char* () {
        return m_message;
    }
};  // SKErrorMessage

#define SK_LOG(message, ...) { SKErrorMessage msg(message, ## __VA_ARGS__); std::cerr << "### Log : " << __FILE__ << " (" << __LINE__ << ") " << msg << std::endl; }
#define SK_THROW(code, message, ...) { SKErrorMessage msg(message, ## __VA_ARGS__); std::cerr << "### Exception : " << __FILE__ << " (" << __LINE__ << ") " << msg << std::endl; throw SKException(code); }
#else 
#define SK_LOG(message, ...) { }
#define SK_THROW(code, message, ...) { throw SKException(code); }
#endif // DEBUG

// Check condition
#define SK_CHECK(condition, code, message, ...) { if (!(condition)) { SK_THROW(code, message, ## __VA_ARGS__); } }

// Boolean class
class SKBoolean {

private:

    uint32_t m_value;

    // Check state
    inline void check() {
        SK_CHECK(m_value == SK_FALSE || m_value == SK_TRUE, SK_ERROR_INVALID_STATE, "Invalid boolean value");
    }

    // To bool
    inline bool to_bool() {
        check();
        return m_value == SK_TRUE;
    }

    inline void assign(const uint32_t value) {
        SK_CHECK(value == SK_FALSE || value == SK_TRUE, SK_ERROR_INVALID_PARAMETER, "Invalid boolean value");
        m_value = value;
    }

public:

    // Constructor
    SKBoolean(const uint32_t value) {
        assign(value);
    }

    // Copy constructor
    SKBoolean(const SKBoolean& other) {
        assign(other.m_value);
    }

    // Assignment operator
    SKBoolean& operator=(const SKBoolean& other) {
        assign(other.m_value);
        return *this;
    }

    // Invert operator
    SKBoolean& operator!() {
        check();
        m_value = (m_value == SK_TRUE) ? SK_FALSE : SK_TRUE;
        return *this;
    }

    // Conveert to bool
    inline operator bool() {
        return to_bool();
    }
};

// Misc utility functions
class SKUtils {

private:

    // Constructor
    SKUtils() {}

public:

    // Get timestamp
    static uint64_t GetTimestamp();
};
