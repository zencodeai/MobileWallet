# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.19)

set(CMAKE_CXX_STANDARD 11)

# ------------------------------------------------------------------------------
# Secure kernel project
project(sk_plugin VERSION 0.1.0 LANGUAGES C CXX)

# ------------------------------------------------------------------------------
# Secure kernel sources dir
set(SK_HOME_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
set(SK_SRC_DIR ${SK_HOME_DIR}/src)
set(SK_INC_DIR ${SK_SRC_DIR}/inc)
set(SK_INC_PUBLIC_DIR ${SK_HOME_DIR}/include)
set(SK_EXT_DIR ${CMAKE_CURRENT_LIST_DIR}/ext)

# Secure kernel source list
set(SK_SRC
    ${SK_SRC_DIR}/sk_app_key_store.cpp
    ${SK_SRC_DIR}/sk_app_key_store_sim.cpp
    ${SK_SRC_DIR}/sk_binary_buffer.cpp
    ${SK_SRC_DIR}/sk_context.cpp
    ${SK_SRC_DIR}/sk_crypto_mbedtls.cpp
    ${SK_SRC_DIR}/sk_persistence.cpp
    ${SK_SRC_DIR}/sk_random.cpp
    ${SK_SRC_DIR}/sk_secure_store.cpp
    ${SK_SRC_DIR}/sk_session.cpp
    ${SK_SRC_DIR}/sk_session_offline.cpp
    ${SK_SRC_DIR}/sk_session_offline_payee.cpp
    ${SK_SRC_DIR}/sk_session_offline_payor.cpp
    ${SK_SRC_DIR}/sk_session_online.cpp
    ${SK_SRC_DIR}/sk_session_provision.cpp
    ${SK_SRC_DIR}/sk_store_mgr_generic.cpp
    ${SK_SRC_DIR}/sk_transaction_list.cpp
    ${SK_SRC_DIR}/sk_utils.cpp
    ${SK_SRC_DIR}/sk_x509.cpp
)

# ------------------------------------------------------------------------------
# Platform specific sources depending on CMAKE_SYSTEM_NAME value
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message("Android platform detected")
    set(SK_SRC ${SK_SRC}
        ${SK_SRC_DIR}/sk_utils_platform_android.cpp
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message("iOS platform detected")
    set(SK_SRC ${SK_SRC}
        ${SK_SRC_DIR}/sk_utils_platform_ios.cpp
    )
else()
    message("Assume Linux/OSX desktop")
    set(SK_SRC ${SK_SRC}
        ${SK_SRC_DIR}/sk_utils_platform_ux.cpp
    )
endif()

# ------------------------------------------------------------------------------
# SQLite sources dir
set(SQLITE_SRC_DIR ${SK_EXT_DIR}/sqlite-amalgamation-3410200)
set(SQLITE_INC_DIR ${SQLITE_SRC_DIR})

# Source list from dir
set(SQLITE_SRC ${SQLITE_SRC_DIR}/sqlite3.c)

# ------------------------------------------------------------------------------
# Include MBED-TLS build
# Set build options
option(ENABLE_PROGRAMS "Disable programs" Off)
option(ENABLE_TESTING "Disable testing" Off)

# Add PIC option to MBED-TLS build for GCC
if(CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(${CMAKE_SHARED_LIBRARY_C_FLAGS})
endif()

# Add MBED-TLS build
add_subdirectory(${SK_EXT_DIR}/mbedtls-3.4.0)

# Set MBED-TLS include dir
set(MBEDTLS_INC_DIR ${SK_EXT_DIR}/mbedtls-3.4.0/include)

# ------------------------------------------------------------------------------
# Configure Secure kernel project

# Add shared library
add_library(${PROJECT_NAME} SHARED ${SK_SRC} ${SQLITE_SRC})

# Set public include directories
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER ${SK_INC_PUBLIC_DIR}/${PROJECT_NAME}.h)

# Add private include directories
target_include_directories(${PROJECT_NAME} PRIVATE ${SK_INC_DIR} ${SQLITE_INC_DIR} ${MBEDTLS_INC_DIR})

# Add public include directories
target_include_directories(${PROJECT_NAME} PUBLIC ${SK_INC_PUBLIC_DIR})

# Link MBED-TLS
target_link_libraries(${PROJECT_NAME} mbedtls)

# Set version
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

# Hide all symbols by default
set_target_properties(${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden)

# Define DART_SHARED_LIB
target_compile_definitions(${PROJECT_NAME} PUBLIC DART_SHARED_LIB)
