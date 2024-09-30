
# ------------------------------------------------------------------------------
# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# ------------------------------------------------------------------------------
# Secure kernel project
# project(sk_app VERSION 0.1.0 LANGUAGES C CXX)
project(sk_app)

# ------------------------------------------------------------------------------
# Secure kernel sources dir
set(SK_HOME_DIR ${CMAKE_CURRENT_LIST_DIR})
set(SK_SRC_DIR ${SK_HOME_DIR}/src)
set(SK_INC_DIR ${SK_SRC_DIR}/inc)
set(SK_INC_PUBLIC_DIR ${SK_HOME_DIR}/include)
set(SK_EXT_DIR ${CMAKE_CURRENT_LIST_DIR}/ext)

# ------------------------------------------------------------------------------
# Secure kernel source list
set(SK_SRC
        ${SK_HOME_DIR}/sk_app.cpp
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
        ${SK_SRC_DIR}/sk_utils_platform_android.cpp
        ${SK_SRC_DIR}/sk_x509.cpp
        )

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
# if(CMAKE_COMPILER_IS_GNUCC)
#     add_compile_options(${CMAKE_SHARED_LIBRARY_C_FLAGS})
# endif()

# Add MBED-TLS build
add_subdirectory(${SK_EXT_DIR}/mbedtls-3.4.0)

# Set MBED-TLS include dir
set(MBEDTLS_INC_DIR ${SK_EXT_DIR}/mbedtls-3.4.0/include)

# ------------------------------------------------------------------------------
# Configure Secure kernel project

# Add shared library
add_library(${PROJECT_NAME} SHARED ${SK_SRC} ${SQLITE_SRC})

# Add private include directories
target_include_directories(${PROJECT_NAME} PRIVATE
        ${SK_INC_PUBLIC_DIR}
        ${SK_INC_DIR}
        ${SQLITE_INC_DIR}
        ${MBEDTLS_INC_DIR})

# Link platform and third party libraries
target_link_libraries(${PROJECT_NAME}
        android
        log
        mbedtls
        stdc++)

# Set C++ standard
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 17)

# If argument SK_STRIP_SYMBOLS is set, strip symbols
if (SK_STRIP_SYMBOLS)
    target_compile_options(${PROJECT_NAME} PRIVATE "-fvisibility=hidden")
    target_link_options(${PROJECT_NAME} PRIVATE "-Wl,--exclude-libs,ALL" "-Wl,-Bsymbolic" "-fvisibility=hidden")
endif ()
