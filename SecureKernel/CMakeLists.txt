cmake_minimum_required(VERSION 3.9)

set(CMAKE_CXX_STANDARD 11)

# ------------------------------------------------------------------------------
# Secure kernel project
project(sk VERSION 0.1.0 LANGUAGES C CXX)

message("--------------------------")
message("Compiler info:")
message(">    ${CMAKE_C_COMPILER}")
message(">    ${CMAKE_C_COMPILER_ID}")
message(">    ${CMAKE_COMPILER_IS_GNUCC}")
message(">    ${CMAKE_SHARED_LIBRARY_C_FLAGS}")
message("--------------------------")

# ------------------------------------------------------------------------------
# Secure kernel sources dir
set(SK_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(SK_INC_DIR ${SK_SRC_DIR}/inc)
set(SK_INC_PUBLIC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Build source list from dir
# file(GLOB_RECURSE SK_SRC ${SK_SRC_DIR}/*.cpp)
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
# SQLite sources dir
set(SQLITE_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ext/sqlite-amalgamation-3410200)
set(SQLITE_INC_DIR ${SQLITE_SRC_DIR})

# Source list from dir
set(SQLITE_SRC ${SQLITE_SRC_DIR}/sqlite3.c)

# ------------------------------------------------------------------------------
# Include MBED-TLS build
# Set build options
set(ENABLE_PROGRAMS Off)
set(ENABLE_TESTING Off)

# Add PIC option to MBED-TLS build for GCC
if(CMAKE_COMPILER_IS_GNUCC)
  add_compile_options(${CMAKE_SHARED_LIBRARY_C_FLAGS})
endif()

# Add MBED-TLS build
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ext/mbedtls-3.4.0)

# Set MBED-TLS include dir
set(MBEDTLS_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ext/mbedtls-3.4.0/include)

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

# ------------------------------------------------------------------------------
# Test project
project(skt_test VERSION 0.1.0 LANGUAGES C CXX)

# Add CTest
include(CTest)
enable_testing()

# create the testing file and list of tests
set(SKT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
set(TEST_DRIVER skt_test.cpp)

create_test_sourcelist (TEST_SRC ${TEST_DRIVER}
    test/skt_utils.cpp
    test/skt_secure_store.cpp
    test/skt_random.cpp
    test/skt_app_key_store_aes.cpp
    test/skt_app_key_store_ecdsa.cpp
    test/skt_crypto_aes.cpp
    test/skt_crypto_ecdh.cpp    
    test/skt_crypto_ecdsa.cpp
    test/skt_crypto_unwrap_aes.cpp    
    test/skt_crypto_unwrap_ecdsa.cpp
    test/skt_persistence_key.cpp
    test/skt_persistence_data.cpp
    test/skt_persistence_list.cpp
    test/skt_transaction_list.cpp
    test/skt_x509.cpp
    test/skt_session_provision.cpp
    test/skt_session_online.cpp
    test/skt_session_offline.cpp
    )

# Add the executable
add_executable (${PROJECT_NAME} ${TEST_SRC} ${SK_SRC} ${SQLITE_SRC})

# Add private include directories
target_include_directories(${PROJECT_NAME} PRIVATE ${SK_INC_DIR} ${SQLITE_INC_DIR} ${MBEDTLS_INC_DIR})

# Add public include directories
target_include_directories(${PROJECT_NAME} PUBLIC ${SK_INC_PUBLIC_DIR})

# Link MBED-TLS
target_link_libraries(${PROJECT_NAME} mbedtls)

# remove the test driver source file
set (CTEST_LIST ${TEST_SRC})
remove (CTEST_LIST ${TEST_DRIVER})

# Add all the ADD_TEST for each test
foreach (test ${CTEST_LIST})
  get_filename_component (TName ${test} NAME_WE)
  add_test (NAME ${TName} COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build/${PROJECT_NAME} test/${TName})
endforeach ()
