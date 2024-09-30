
# ------------------------------------------------------------------------------
# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# ------------------------------------------------------------------------------
# Secure kernel project
project(sk_lib)

# ------------------------------------------------------------------------------
# Configure build type, check envoronement
enable_language(CXX)
enable_language(OBJC)

MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} )
MESSAGE( STATUS "CMAKE_OBJC_FLAGS: " ${CMAKE_OBJC_FLAGS} )

# Add some sanitary checks that the toolchain is actually working!
include(CheckCXXSymbolExists)
check_cxx_symbol_exists(kqueue sys/event.h HAVE_KQUEUE)
if(NOT HAVE_KQUEUE)
  message(STATUS "kqueue NOT found!")
else()
  message(STATUS "kqueue found!")
endif()

find_library(APPKIT_LIBRARY AppKit)
if (NOT APPKIT_LIBRARY)
  message(STATUS "AppKit.framework NOT found!")
else()
  message(STATUS "AppKit.framework found! ${APPKIT_LIBRARY}")
endif()

find_library(FOUNDATION_LIBRARY Foundation)
if (NOT FOUNDATION_LIBRARY)
  message(STATUS "Foundation.framework NOT found!")
else()
  message(STATUS "Foundation.framework found! ${FOUNDATION_LIBRARY}")
endif()

find_library(UIKIT_LIBRARY UIKit)
if (NOT UIKIT_LIBRARY)
  message(STATUS "UIKit.framework NOT found!")
else()
  message(STATUS "UIKit.framework found! ${UIKIT_LIBRARY}")
endif()

# Hook up XCTest for the supported plaforms (all but WatchOS)
if(NOT PLATFORM MATCHES ".*WATCHOS.*")
  # Use the standard find_package, broken between 3.14.0 and 3.14.4 at least for XCtest...
  find_package(XCTest)
  # Fallback: Try to find XCtest as host package via toochain macro (should always work)
  find_host_package(XCTest REQUIRED)
endif()

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
        ${SK_SRC_DIR}/sk_utils_platform_ios.cpp
        ${SK_SRC_DIR}/sk_x509.cpp
        ${SK_HOME_DIR}/wrapper.mm
        )

# ------------------------------------------------------------------------------
# All symbols are hidden by default
add_compile_options(-fvisibility=hidden)

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
add_library(${PROJECT_NAME} STATIC ${SK_SRC} ${SQLITE_SRC})
target_compile_definitions(${PROJECT_NAME} PUBLIC IS_BUILDING_SHARED)

# Add private include directories
target_include_directories(${PROJECT_NAME} PRIVATE
        ${SK_INC_PUBLIC_DIR}
        ${SK_INC_DIR}
        ${SQLITE_INC_DIR}
        ${MBEDTLS_INC_DIR})

# Link platform and third party libraries
target_link_libraries(${PROJECT_NAME}
        ${FOUNDATION_LIBRARY}
        mbedtls
        stdc++)

# Export only symbols in public include directory
set_target_properties(${PROJECT_NAME} PROPERTIES
        PUBLIC_HEADER "${SK_HOME_DIR}/sk_lib-Bridging-Header.h")

# Set C++ standard
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 17)

# Strip local symbols
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-s")

# ------------------------------------------------------------------------------
# Set signing identity: /usr/bin/env xcrun security find-identity -v -p codesigning
message(STATUS "Setting signing identity")
set(CODE_SIGN_IDENTITY "FA90D1C72C722F1C2D9BF6742C7AAB01E35A59F1")
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ${CODE_SIGN_IDENTITY})
set(CMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "X9B6WFZH85")
set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_STYLE "Manual")
set(CMAKE_XCODE_ATTRIBUTE_OTHER_CODE_SIGN_FLAGS "--timestamp=none")
set(PROVISIONING_PROFILE_SPECIFIER "sk_lib")

# ------------------------------------------------------------------------------
# Install path
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/lib CACHE PATH "Install path" FORCE)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

# ------------------------------------------------------------------------------
# Debug symbols set in XCode project
set_xcode_property(${PROJECT_NAME} GCC_GENERATE_DEBUGGING_SYMBOLS YES "All")

# ------------------------------------------------------------------------------
# Installation
message(STATUS "Installing to ${CMAKE_INSTALL_PREFIX}")
install(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        ARCHIVE DESTINATION lib/static)
