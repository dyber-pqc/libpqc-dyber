# libpqc-dyber test suite
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT

# Common test runner
add_executable(test_kem unit/test_kem_all.c)
target_link_libraries(test_kem PRIVATE pqc_static)
target_include_directories(test_kem PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_kem COMMAND test_kem)
set_tests_properties(test_kem PROPERTIES TIMEOUT 120)

add_executable(test_sig unit/test_sig_all.c)
target_link_libraries(test_sig PRIVATE pqc_static)
target_include_directories(test_sig PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_sig COMMAND test_sig)
set_tests_properties(test_sig PROPERTIES TIMEOUT 1800)

# Hash tests
add_executable(test_hash unit/test_hash.c)
target_link_libraries(test_hash PRIVATE pqc_static)
target_include_directories(test_hash PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_hash COMMAND test_hash)
# Labelled "kat": checks published FIPS 180-4, FIPS 202 and RFC 4231 vectors.
set_tests_properties(test_hash PROPERTIES TIMEOUT 30 LABELS kat)

# Integration tests
add_executable(test_integration integration/test_roundtrip.c)
target_link_libraries(test_integration PRIVATE pqc_static)
target_include_directories(test_integration PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_integration COMMAND test_integration)
set_tests_properties(test_integration PROPERTIES TIMEOUT 30)

# FN-DSA round trip. Key generation is a known failure (CHANGELOG.md), so
# this is registered as an *expected* failure, judged by its output rather
# than its exit status: it passes only if both parameter sets report the
# known key-generation failure and no sanitizer reported an error. Plain
# WILL_FAIL would also accept a crash. When FN-DSA key generation starts
# working the KNOWN FAILURE lines disappear and this fails; then drop these
# properties so the test checks the round trip normally.
add_executable(test_fndsa_quick unit/test_fndsa_quick.c)
target_link_libraries(test_fndsa_quick PRIVATE pqc_static)
target_include_directories(test_fndsa_quick PRIVATE ${PQC_INCLUDE_DIRS})
add_test(NAME test_fndsa_quick COMMAND test_fndsa_quick)
set_tests_properties(test_fndsa_quick PROPERTIES
    TIMEOUT 120
    LABELS known-failure
    PASS_REGULAR_EXPRESSION "KNOWN FAILURE: FN-DSA-512 key generation[^\n]*\nKNOWN FAILURE: FN-DSA-1024 key generation"
    FAIL_REGULAR_EXPRESSION "Sanitizer|runtime error:|PASS: |FAIL: "
    SKIP_REGULAR_EXPRESSION "FN-DSA not in this build")

# BIKE against the official round 4 KATs (see tests/kat/test_kat_bike.c).
# Labelled "kat": regenerates the NIST response files and compares hashes.
if(PQC_ENABLE_KEM_BIKE)
    add_executable(test_kat_bike kat/test_kat_bike.c kat/nist_drbg.c)
    target_link_libraries(test_kat_bike PRIVATE pqc_static)
    target_include_directories(test_kat_bike PRIVATE
        ${PQC_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    add_test(NAME test_kat_bike COMMAND test_kat_bike)
    set_tests_properties(test_kat_bike PROPERTIES TIMEOUT 1800 LABELS kat)
endif()

# ML-KEM against NIST's ACVP vectors (see tests/kat/test_kat_mlkem.c).
if(PQC_ENABLE_KEM_MLKEM)
    add_executable(test_kat_mlkem kat/test_kat_mlkem.c)
    target_link_libraries(test_kat_mlkem PRIVATE pqc_static)
    target_include_directories(test_kat_mlkem PRIVATE
        ${PQC_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    add_test(NAME test_kat_mlkem
             COMMAND test_kat_mlkem ${CMAKE_CURRENT_SOURCE_DIR}/kat/mlkem_acvp.txt)
    set_tests_properties(test_kat_mlkem PROPERTIES
        TIMEOUT 300 LABELS kat SKIP_RETURN_CODE 77)
endif()

# Security audit regression tests.
# Needs the internal source tree for the address/parameter invariants.
add_executable(test_security_audit unit/test_security_audit.c)
target_link_libraries(test_security_audit PRIVATE pqc_static)
target_include_directories(test_security_audit PRIVATE
    ${PQC_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
# The XMSS groups link against internal symbols, so they can only be
# built when the algorithm is compiled in.
if(PQC_ENABLE_SIG_XMSS)
    target_compile_definitions(test_security_audit PRIVATE PQC_TEST_XMSS_INTERNALS=1)
endif()
if(PQC_ENABLE_SIG_SLHDSA)
    target_compile_definitions(test_security_audit PRIVATE PQC_TEST_SLHDSA_INTERNALS=1)
endif()
add_test(NAME test_security_audit COMMAND test_security_audit)
# The stateful-signature groups rebuild a full Merkle tree per operation
# (XMSS re-runs treehash on every signature), which is slow enough under
# MemorySanitizer to exceed a 600 s budget. The work is inherent to what
# is being asserted, so allow for it rather than reduce coverage.
set_tests_properties(test_security_audit PROPERTIES TIMEOUT 1800)

# Known-answer tests for the classical half of the hybrid schemes
# (X25519, Ed25519, ECDH/ECDSA P-256) against RFC 7748, RFC 8032,
# RFC 6979 and NIST CAVP vectors. Needs the internal source tree because
# the primitives are not part of the public API, and only exists when the
# hybrid schemes are compiled in.
if(PQC_ENABLE_HYBRID)
    add_executable(test_hybrid_classical unit/test_hybrid_classical.c)
    target_link_libraries(test_hybrid_classical PRIVATE pqc_static)
    target_include_directories(test_hybrid_classical PRIVATE
        ${PQC_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    add_test(NAME test_hybrid_classical COMMAND test_hybrid_classical)
    set_tests_properties(test_hybrid_classical PROPERTIES TIMEOUT 300 LABELS kat)
endif()

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

# Interoperability with an independent implementation (OpenSSL >= 3.5).
# Labelled "interop", not "kat": it needs an external OpenSSL, and returns
# 77 (skipped) where that OpenSSL lacks ML-DSA / SLH-DSA.
add_executable(pqc_sig_tool interop/pqc_sig_tool.c)
target_link_libraries(pqc_sig_tool PRIVATE pqc_static)
target_include_directories(pqc_sig_tool PRIVATE ${PQC_INCLUDE_DIRS})
find_package(Python3 COMPONENTS Interpreter QUIET)
find_program(PQC_OPENSSL_EXECUTABLE openssl)
if(Python3_Interpreter_FOUND AND PQC_OPENSSL_EXECUTABLE)
    add_test(NAME test_openssl_interop
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/interop/openssl_interop.py
                     $<TARGET_FILE:pqc_sig_tool>
                     --openssl ${PQC_OPENSSL_EXECUTABLE})
    set_tests_properties(test_openssl_interop PROPERTIES
                         TIMEOUT 900 LABELS interop SKIP_RETURN_CODE 77)
endif()

# Constant-time check (ctgrind). Run through tests/ct/run_ctgrind.py, which
# starts one Valgrind process per algorithm; see that script.
if(PQC_ENABLE_CT_TESTING)
    add_executable(test_ct ct/test_ct.c)
    target_link_libraries(test_ct PRIVATE pqc_static)
    target_include_directories(test_ct PRIVATE ${PQC_INCLUDE_DIRS})
endif()

# libFuzzer targets; see tests/fuzz/*.c for the input layouts. Each is also
# registered as a short smoke test (a fixed number of runs from an empty
# corpus) so that a fuzzer build that crashes immediately fails ctest.
if(PQC_BUILD_FUZZERS)
    foreach(fz fuzz_sig_verify fuzz_kem)
        add_executable(${fz} fuzz/${fz}.c)
        target_link_libraries(${fz} PRIVATE pqc_static)
        target_include_directories(${fz} PRIVATE ${PQC_INCLUDE_DIRS})
        target_compile_options(${fz} PRIVATE -fsanitize=fuzzer)
        target_link_options(${fz} PRIVATE -fsanitize=fuzzer)
        add_test(NAME ${fz}_smoke COMMAND ${fz} -runs=2000 -seed=1)
        set_tests_properties(${fz}_smoke PROPERTIES TIMEOUT 1800 LABELS fuzz)
    endforeach()
endif()
