# libpqc-dyber OpenSSL 3.x Provider
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

cmake_minimum_required(VERSION 3.16)
project(pqc_provider VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

# Find OpenSSL 3.0+
find_package(OpenSSL 3.0 REQUIRED)
if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(FATAL_ERROR "OpenSSL 3.0+ is required, found ${OPENSSL_VERSION}")
endif()
message(STATUS "Found OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_INCLUDE_DIR}")

# Find libpqc — either as a sibling build target or installed library
if(TARGET pqc)
    # Building as part of the libpqc-dyber tree
    set(LIBPQC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../include")
    set(LIBPQC_LIBRARY pqc)
    message(STATUS "Using libpqc from parent build tree")
else()
    # Standalone build — look for installed libpqc
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
        message(FATAL_ERROR "libpqc not found. Set LIBPQC_DIR or build from the parent project.")
    endif()
    message(STATUS "Found libpqc: ${LIBPQC_LIBRARY}")
endif()

# --------------------------------------------------------------------------
# Provider shared library
# --------------------------------------------------------------------------

set(PROVIDER_SOURCES
    src/pqc_provider.c
    src/pqc_keymgmt_prov.c
    src/pqc_kem_prov.c
    src/pqc_sig_prov.c
    src/pqc_tls_groups.c
)

add_library(pqc_provider MODULE ${PROVIDER_SOURCES})

target_include_directories(pqc_provider PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBPQC_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pqc_provider PRIVATE
    ${LIBPQC_LIBRARY}
    OpenSSL::Crypto
)

# Remove "lib" prefix on Unix so the file is pqc_provider.so not libpqc_provider.so
set_target_properties(pqc_provider PROPERTIES
    PREFIX ""
    OUTPUT_NAME "pqc_provider"
)

# On Windows, produce pqc_provider.dll
if(WIN32)
    set_target_properties(pqc_provider PROPERTIES
        SUFFIX ".dll"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqc_provider PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(pqc_provider PRIVATE /W4)
endif()

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------

# Determine the OpenSSL modules directory
execute_process(
    COMMAND ${OPENSSL_EXECUTABLE} version -d
    OUTPUT_VARIABLE OPENSSL_DIR_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(OPENSSL_DIR_OUTPUT MATCHES "OPENSSLDIR: \"([^\"]+)\"")
    set(OPENSSL_DIR_DEFAULT "${CMAKE_MATCH_1}")
endif()

set(OSSL_MODULES_DIR "${OPENSSL_DIR_DEFAULT}/../lib/ossl-modules"
    CACHE PATH "OpenSSL modules directory")

install(TARGETS pqc_provider
    LIBRARY DESTINATION "${OSSL_MODULES_DIR}"
    RUNTIME DESTINATION "${OSSL_MODULES_DIR}"
)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

option(PQC_PROVIDER_BUILD_TESTS "Build OpenSSL provider tests" ON)

if(PQC_PROVIDER_BUILD_TESTS)
    enable_testing()

    add_executable(test_openssl_provider tests/test_openssl_provider.c)
    target_include_directories(test_openssl_provider PRIVATE
        ${LIBPQC_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
    )
    target_link_libraries(test_openssl_provider PRIVATE
        OpenSSL::Crypto
        ${LIBPQC_LIBRARY}
    )

    # Set environment so the test can find the provider
    add_test(NAME openssl_provider_test COMMAND test_openssl_provider)
    set_tests_properties(openssl_provider_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:pqc_provider>"
    )
endif()
