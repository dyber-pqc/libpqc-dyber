/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Basic tests for the C++ Signature wrapper.
 */

#include <cassert>
#include <cstdio>
#include <string>

#include <pqc/pqc.hpp>

static const pqc::Bytes test_message = {
    'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ',
    't', 'e', 's', 't', ' ', 'm', 'e', 's', 's', 'a',
    'g', 'e', '.',
};

static void test_sig_properties() {
    pqc::Signature sig("ML-DSA-65");

    assert(sig.algorithm() == "ML-DSA-65");
    assert(sig.public_key_size() > 0);
    assert(sig.secret_key_size() > 0);
    assert(sig.max_signature_size() > 0);
    assert(!sig.is_stateful());

    std::printf("[PASS] test_sig_properties\n");
}

static void test_sig_sign_verify() {
    pqc::Signature sig("ML-DSA-65");

    auto [pk, sk] = sig.keygen();
    assert(pk.size() == sig.public_key_size());
    assert(sk.size() == sig.secret_key_size());

    auto signature = sig.sign(test_message, sk);
    assert(!signature.empty());
    assert(signature.size() <= sig.max_signature_size());

    bool valid = sig.verify(test_message, signature, pk);
    assert(valid);

    std::printf("[PASS] test_sig_sign_verify\n");
}

static void test_sig_verify_tampered() {
    pqc::Signature sig("ML-DSA-65");

    auto [pk, sk] = sig.keygen();
    auto signature = sig.sign(test_message, sk);

    // Tamper with the message
    pqc::Bytes tampered = test_message;
    tampered[0] ^= 0xFF;

    bool valid = sig.verify(tampered, signature, pk);
    assert(!valid);

    std::printf("[PASS] test_sig_verify_tampered\n");
}

static void test_sig_invalid_algorithm() {
    bool caught = false;
    try {
        pqc::Signature sig("INVALID-ALGORITHM-NAME");
    } catch (const pqc::Error& e) {
        caught = true;
        assert(e.status() == PQC_ERROR_NOT_SUPPORTED);
    }
    assert(caught);

    std::printf("[PASS] test_sig_invalid_algorithm\n");
}

static void test_sig_move() {
    pqc::Signature sig1("ML-DSA-65");
    auto [pk, sk] = sig1.keygen();

    pqc::Signature sig2(std::move(sig1));
    assert(sig2.algorithm() == "ML-DSA-65");

    auto signature = sig2.sign(test_message, sk);
    bool valid = sig2.verify(test_message, signature, pk);
    assert(valid);

    std::printf("[PASS] test_sig_move\n");
}

static void test_sig_algorithm_listing() {
    auto algorithms = pqc::sig_algorithms();
    assert(!algorithms.empty());

    bool found_mldsa = false;
    for (const auto& name : algorithms) {
        if (name == "ML-DSA-65") {
            found_mldsa = true;
        }
    }
    assert(found_mldsa);
    assert(pqc::sig_is_enabled("ML-DSA-65"));

    std::printf("[PASS] test_sig_algorithm_listing\n");
}

static void test_sig_raw_pointer_api() {
    pqc::Signature sig("ML-DSA-65");
    auto [pk, sk] = sig.keygen();

    const uint8_t raw_msg[] = "raw pointer message";
    std::size_t raw_len = sizeof(raw_msg) - 1;

    auto signature = sig.sign(raw_msg, raw_len, sk);
    bool valid = sig.verify(raw_msg, raw_len, signature, pk);
    assert(valid);

    std::printf("[PASS] test_sig_raw_pointer_api\n");
}

int main() {
    pqc::LibraryGuard guard;

    test_sig_properties();
    test_sig_sign_verify();
    test_sig_verify_tampered();
    test_sig_invalid_algorithm();
    test_sig_move();
    test_sig_algorithm_listing();
    test_sig_raw_pointer_api();

    std::printf("\nAll Signature tests passed.\n");
    return 0;
}
