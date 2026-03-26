# libpqc-dyber BoringSSL Integration
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

cmake_minimum_required(VERSION 3.16)
project(pqc_boringssl VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

# Find BoringSSL — it does not ship a find-module; locate by hint.
set(BORINGSSL_ROOT "" CACHE PATH "Root of BoringSSL build tree")

find_path(BORINGSSL_INCLUDE_DIR openssl/ssl.h
    HINTS
        "${BORINGSSL_ROOT}/include"
        "$ENV{BORINGSSL_DIR}/include"
        "/usr/local/include"
        "/usr/include"
)
if(NOT BORINGSSL_INCLUDE_DIR)
    message(FATAL_ERROR
        "BoringSSL headers not found. Set BORINGSSL_ROOT or BORINGSSL_DIR.")
endif()
message(STATUS "BoringSSL include: ${BORINGSSL_INCLUDE_DIR}")

find_library(BORINGSSL_SSL_LIBRARY
    NAMES ssl
    HINTS
        "${BORINGSSL_ROOT}/lib"
        "${BORINGSSL_ROOT}/build/ssl"
        "$ENV{BORINGSSL_DIR}/lib"
)
find_library(BORINGSSL_CRYPTO_LIBRARY
    NAMES crypto
    HINTS
        "${BORINGSSL_ROOT}/lib"
        "${BORINGSSL_ROOT}/build/crypto"
        "$ENV{BORINGSSL_DIR}/lib"
)
if(NOT BORINGSSL_SSL_LIBRARY OR NOT BORINGSSL_CRYPTO_LIBRARY)
    message(FATAL_ERROR
        "BoringSSL libraries not found. Set BORINGSSL_ROOT.")
endif()
message(STATUS "BoringSSL ssl:    ${BORINGSSL_SSL_LIBRARY}")
message(STATUS "BoringSSL crypto: ${BORINGSSL_CRYPTO_LIBRARY}")

# Find libpqc
if(TARGET pqc)
    set(LIBPQC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../include")
    set(LIBPQC_LIBRARY pqc)
    message(STATUS "Using libpqc from parent build tree")
else()
    find_path(LIBPQC_INCLUDE_DIR pqc/pqc.h
        HINTS
            "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
            "$ENV{LIBPQC_DIR}/include"
            "/usr/local/include"
            "/usr/include"
    )
    find_library(LIBPQC_LIBRARY
        NAMES pqc pqc_static libpqc
        HINTS
            "${CMAKE_CURRENT_SOURCE_DIR}/../../build"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../build/Release"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../build/Debug"
            "$ENV{LIBPQC_DIR}/lib"
            "/usr/local/lib"
            "/usr/lib"
    )
    if(NOT LIBPQC_INCLUDE_DIR OR NOT LIBPQC_LIBRARY)
        message(FATAL_ERROR
            "libpqc not found. Set LIBPQC_DIR or build from the parent project.")
    endif()
    message(STATUS "Found libpqc: ${LIBPQC_LIBRARY}")
endif()

# --------------------------------------------------------------------------
# Library
# --------------------------------------------------------------------------

set(PQC_BORINGSSL_SOURCES
    src/pqc_boringssl.c
    src/pqc_boringssl_kem.c
    src/pqc_boringssl_sig.c
)

option(PQC_BORINGSSL_SHARED "Build as shared library" OFF)

if(PQC_BORINGSSL_SHARED)
    add_library(pqc_boringssl SHARED ${PQC_BORINGSSL_SOURCES})
    target_compile_definitions(pqc_boringssl PRIVATE PQC_BORINGSSL_DLL_EXPORT)
else()
    add_library(pqc_boringssl STATIC ${PQC_BORINGSSL_SOURCES})
endif()

target_include_directories(pqc_boringssl
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${LIBPQC_INCLUDE_DIR}
        ${BORINGSSL_INCLUDE_DIR}
)

target_link_libraries(pqc_boringssl
    PUBLIC
        ${BORINGSSL_SSL_LIBRARY}
        ${BORINGSSL_CRYPTO_LIBRARY}
    PRIVATE
        ${LIBPQC_LIBRARY}
)

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqc_boringssl PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(pqc_boringssl PRIVATE /W4)
endif()

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------

install(TARGETS pqc_boringssl
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES src/pqc_boringssl.h
    DESTINATION include/pqc
)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

option(PQC_BORINGSSL_BUILD_TESTS "Build BoringSSL integration tests" ON)

if(PQC_BORINGSSL_BUILD_TESTS)
    enable_testing()

    add_executable(test_boringssl tests/test_boringssl.c)
    target_include_directories(test_boringssl PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${LIBPQC_INCLUDE_DIR}
        ${BORINGSSL_INCLUDE_DIR}
    )
    target_link_libraries(test_boringssl PRIVATE
        pqc_boringssl
        ${LIBPQC_LIBRARY}
        ${BORINGSSL_SSL_LIBRARY}
        ${BORINGSSL_CRYPTO_LIBRARY}
    )

    add_test(NAME boringssl_integration_test COMMAND test_boringssl)
endif()
