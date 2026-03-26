# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# CMake build for the header-only C++ bindings.

cmake_minimum_required(VERSION 3.14)
project(pqc-cpp
    VERSION 0.1.0
    LANGUAGES CXX
    DESCRIPTION "C++ bindings for libpqc-dyber"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Header-only library target
# ---------------------------------------------------------------------------

add_library(pqc_cpp INTERFACE)
add_library(pqc::cpp ALIAS pqc_cpp)

target_include_directories(pqc_cpp INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(pqc_cpp INTERFACE cxx_std_17)

# The C++ headers include the C headers from the main project.
# When used as a subdirectory of the main project, the C library target
# provides these automatically. When used standalone, find the installed
# C library via find_package or manual paths.
if(TARGET pqc)
    target_link_libraries(pqc_cpp INTERFACE pqc)
else()
    find_library(PQC_LIBRARY NAMES pqc)
    find_path(PQC_INCLUDE_DIR NAMES pqc/pqc.h)
    if(PQC_LIBRARY AND PQC_INCLUDE_DIR)
        target_link_libraries(pqc_cpp INTERFACE ${PQC_LIBRARY})
        target_include_directories(pqc_cpp INTERFACE ${PQC_INCLUDE_DIR})
    else()
        message(FATAL_ERROR
            "Could not find libpqc. Build and install the main project first, "
            "or add this directory as a subdirectory of the main CMake build.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

option(PQC_CPP_BUILD_TESTS "Build C++ binding tests" ON)

if(PQC_CPP_BUILD_TESTS)
    enable_testing()

    add_executable(test_kem_cpp tests/test_kem.cpp)
    target_link_libraries(test_kem_cpp PRIVATE pqc_cpp)
    add_test(NAME test_kem_cpp COMMAND test_kem_cpp)

    add_executable(test_sig_cpp tests/test_sig.cpp)
    target_link_libraries(test_sig_cpp PRIVATE pqc_cpp)
    add_test(NAME test_sig_cpp COMMAND test_sig_cpp)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

install(DIRECTORY include/pqc
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(TARGETS pqc_cpp
    EXPORT pqc_cpp-targets
)

install(EXPORT pqc_cpp-targets
    FILE pqc_cpp-targets.cmake
    NAMESPACE pqc::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/pqc_cpp
)
