# libpqc-dyber test suite
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

# Unit tests
set(PQC_TEST_SOURCES "")

if(PQC_ENABLE_KEM_MLKEM)
    list(APPEND PQC_TEST_SOURCES unit/test_mlkem.c)
endif()
if(PQC_ENABLE_SIG_MLDSA)
    list(APPEND PQC_TEST_SOURCES unit/test_mldsa.c)
endif()
if(PQC_ENABLE_SIG_SLHDSA)
    list(APPEND PQC_TEST_SOURCES unit/test_slhdsa.c)
endif()
if(PQC_ENABLE_SIG_FNDSA)
    list(APPEND PQC_TEST_SOURCES unit/test_fndsa.c)
endif()

# Common test runner
add_executable(test_kem unit/test_kem_all.c)
target_link_libraries(test_kem PRIVATE pqc_static)
target_include_directories(test_kem PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_kem COMMAND test_kem)

add_executable(test_sig unit/test_sig_all.c)
target_link_libraries(test_sig PRIVATE pqc_static)
target_include_directories(test_sig PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_sig COMMAND test_sig)

# Hash tests
add_executable(test_hash unit/test_hash.c)
target_link_libraries(test_hash PRIVATE pqc_static)
target_include_directories(test_hash PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_hash COMMAND test_hash)

# Integration tests
add_executable(test_integration integration/test_roundtrip.c)
target_link_libraries(test_integration PRIVATE pqc_static)
target_include_directories(test_integration PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_integration COMMAND test_integration)

# Quick FN-DSA test (for development/debugging)
add_executable(test_fndsa_quick unit/test_fndsa_quick.c)
target_link_libraries(test_fndsa_quick PRIVATE pqc_static)
target_include_directories(test_fndsa_quick PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_fndsa_quick COMMAND test_fndsa_quick)

# Benchmarks (not added to CTest by default)
if(PQC_BUILD_BENCHMARKS)
    # Common include path for bench_common.h
    set(BENCH_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/bench ${PQC_INCLUDE_DIRS})

    # Internal hash headers needed by bench_hash and bench_all
    set(BENCH_INTERNAL_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../src/core/common/hash)

    add_executable(bench_kem bench/bench_kem.c)
    target_link_libraries(bench_kem PRIVATE pqc_static)
    target_include_directories(bench_kem PRIVATE ${BENCH_INCLUDE_DIRS})

    add_executable(bench_sig bench/bench_sig.c)
    target_link_libraries(bench_sig PRIVATE pqc_static)
    target_include_directories(bench_sig PRIVATE ${BENCH_INCLUDE_DIRS})

    add_executable(bench_hash bench/bench_hash.c)
    target_link_libraries(bench_hash PRIVATE pqc_static)
    target_include_directories(bench_hash PRIVATE ${BENCH_INCLUDE_DIRS} ${BENCH_INTERNAL_DIRS})

    add_executable(bench_all bench/bench_all.c)
    target_link_libraries(bench_all PRIVATE pqc_static)
    target_include_directories(bench_all PRIVATE ${BENCH_INCLUDE_DIRS} ${BENCH_INTERNAL_DIRS})

    # Link math library on non-Windows platforms (for sqrt in stats)
    if(NOT WIN32)
        target_link_libraries(bench_kem PRIVATE m)
        target_link_libraries(bench_sig PRIVATE m)
        target_link_libraries(bench_hash PRIVATE m)
        target_link_libraries(bench_all PRIVATE m)
    endif()

    # Link psapi on Windows for memory tracking
    if(WIN32)
        target_link_libraries(bench_kem PRIVATE psapi)
        target_link_libraries(bench_sig PRIVATE psapi)
        target_link_libraries(bench_hash PRIVATE psapi)
        target_link_libraries(bench_all PRIVATE psapi)
    endif()
endif()
