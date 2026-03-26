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

# Benchmarks (not added to CTest by default)
if(PQC_BUILD_BENCHMARKS)
    add_executable(bench_kem bench/bench_kem.c)
    target_link_libraries(bench_kem PRIVATE pqc_static)
    target_include_directories(bench_kem PRIVATE ${PQC_INCLUDE_DIRS})

    add_executable(bench_sig bench/bench_sig.c)
    target_link_libraries(bench_sig PRIVATE pqc_static)
    target_include_directories(bench_sig PRIVATE ${PQC_INCLUDE_DIRS})
endif()
