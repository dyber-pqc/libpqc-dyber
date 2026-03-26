/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Basic tests for the C++ KEM wrapper.
 */

#include <cassert>
#include <cstdio>
#include <string>

#include <pqc/pqc.hpp>

static void test_kem_properties() {
    pqc::KEM kem("ML-KEM-768");

    assert(kem.algorithm() == "ML-KEM-768");
    assert(kem.public_key_size() > 0);
    assert(kem.secret_key_size() > 0);
    assert(kem.ciphertext_size() > 0);
    assert(kem.shared_secret_size() > 0);

    std::printf("[PASS] test_kem_properties\n");
}

static void test_kem_keygen_encaps_decaps() {
    pqc::KEM kem("ML-KEM-768");

    auto [pk, sk] = kem.keygen();
    assert(pk.size() == kem.public_key_size());
    assert(sk.size() == kem.secret_key_size());

    auto [ct, ss_enc] = kem.encaps(pk);
    assert(ct.size() == kem.ciphertext_size());
    assert(ss_enc.size() == kem.shared_secret_size());

    auto ss_dec = kem.decaps(ct, sk);
    assert(ss_dec.size() == kem.shared_secret_size());
    assert(ss_enc == ss_dec);

    std::printf("[PASS] test_kem_keygen_encaps_decaps\n");
}

static void test_kem_invalid_algorithm() {
    bool caught = false;
    try {
        pqc::KEM kem("INVALID-ALGORITHM-NAME");
    } catch (const pqc::Error& e) {
        caught = true;
        assert(e.status() == PQC_ERROR_NOT_SUPPORTED);
    }
    assert(caught);

    std::printf("[PASS] test_kem_invalid_algorithm\n");
}

static void test_kem_move() {
    pqc::KEM kem1("ML-KEM-768");
    auto [pk, sk] = kem1.keygen();

    // Move construct
    pqc::KEM kem2(std::move(kem1));
    assert(kem2.algorithm() == "ML-KEM-768");

    // Encaps/decaps still work after move
    auto [ct, ss_enc] = kem2.encaps(pk);
    auto ss_dec = kem2.decaps(ct, sk);
    assert(ss_enc == ss_dec);

    std::printf("[PASS] test_kem_move\n");
}

static void test_kem_algorithm_listing() {
    auto algorithms = pqc::kem_algorithms();
    assert(!algorithms.empty());

    bool found_mlkem = false;
    for (const auto& name : algorithms) {
        if (name == "ML-KEM-768") {
            found_mlkem = true;
        }
    }
    assert(found_mlkem);
    assert(pqc::kem_is_enabled("ML-KEM-768"));

    std::printf("[PASS] test_kem_algorithm_listing\n");
}

int main() {
    pqc::LibraryGuard guard;

    test_kem_properties();
    test_kem_keygen_encaps_decaps();
    test_kem_invalid_algorithm();
    test_kem_move();
    test_kem_algorithm_listing();

    std::printf("\nAll KEM tests passed.\n");
    return 0;
}
