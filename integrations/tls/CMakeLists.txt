# libpqc-dyber TLS Integration Layer
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

cmake_minimum_required(VERSION 3.16)
project(pqc_tls VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

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

# Optional: OpenSSL or BoringSSL for classical crypto in hybrid groups.
# If not found, hybrid groups that require X25519/P-256 are disabled.
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION} — hybrid groups enabled")
    set(PQC_TLS_HAVE_OPENSSL ON)
else()
    message(STATUS "OpenSSL not found — hybrid groups require external classical crypto")
    set(PQC_TLS_HAVE_OPENSSL OFF)
endif()

# --------------------------------------------------------------------------
# Library
# --------------------------------------------------------------------------

set(PQC_TLS_SOURCES
    src/pqc_tls.c
    src/pqc_tls_groups.c
    src/pqc_tls_sigalgs.c
    src/pqc_tls12.c
)

option(PQC_TLS_SHARED "Build as shared library" OFF)

if(PQC_TLS_SHARED)
    add_library(pqc_tls SHARED ${PQC_TLS_SOURCES})
    target_compile_definitions(pqc_tls PRIVATE PQC_TLS_DLL_EXPORT)
else()
    add_library(pqc_tls STATIC ${PQC_TLS_SOURCES})
endif()

target_include_directories(pqc_tls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${LIBPQC_INCLUDE_DIR}
)

target_link_libraries(pqc_tls PRIVATE ${LIBPQC_LIBRARY})

if(PQC_TLS_HAVE_OPENSSL)
    target_compile_definitions(pqc_tls PRIVATE PQC_TLS_HAVE_OPENSSL=1)
    target_include_directories(pqc_tls PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(pqc_tls PRIVATE OpenSSL::Crypto)
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqc_tls PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(pqc_tls PRIVATE /W4)
endif()

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------

install(TARGETS pqc_tls
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES src/pqc_tls.h
    DESTINATION include/pqc
)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

option(PQC_TLS_BUILD_TESTS "Build TLS integration tests" ON)

if(PQC_TLS_BUILD_TESTS)
    enable_testing()

    add_executable(test_tls_keyshare tests/test_tls_keyshare.c)
    target_include_directories(test_tls_keyshare PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${LIBPQC_INCLUDE_DIR}
    )
    target_link_libraries(test_tls_keyshare PRIVATE
        pqc_tls
        ${LIBPQC_LIBRARY}
    )
    if(PQC_TLS_HAVE_OPENSSL)
        target_include_directories(test_tls_keyshare PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(test_tls_keyshare PRIVATE OpenSSL::Crypto)
    endif()

    add_test(NAME tls_keyshare_test COMMAND test_tls_keyshare)
endif()
