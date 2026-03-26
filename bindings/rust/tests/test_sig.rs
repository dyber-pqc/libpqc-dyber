// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Integration tests for the Signature wrapper.

use pqc_dyber::{init, cleanup, Sig};

fn setup() {
    let _ = init();
}

#[test]
fn test_sig_mldsa65_roundtrip() {
    setup();

    let sig = Sig::new("ML-DSA-65").expect("failed to create ML-DSA-65 context");
    assert_eq!(sig.algorithm(), "ML-DSA-65");

    let (pk, sk) = sig.keygen().expect("keygen failed");
    assert_eq!(pk.len(), sig.public_key_size());
    assert_eq!(sk.len(), sig.secret_key_size());

    let message = b"test message for ML-DSA-65";
    let signature = sig.sign(message, &sk).expect("sign failed");
    assert!(signature.len() <= sig.max_signature_size());

    sig.verify(message, &signature, &pk).expect("verify failed");

    cleanup();
}

#[test]
fn test_sig_mldsa44_roundtrip() {
    setup();

    let sig = Sig::new("ML-DSA-44").expect("failed to create ML-DSA-44 context");

    let (pk, sk) = sig.keygen().expect("keygen failed");
    let message = b"hello pqc";
    let signature = sig.sign(message, &sk).expect("sign failed");

    sig.verify(message, &signature, &pk).expect("verify failed");

    cleanup();
}

#[test]
fn test_sig_mldsa87_roundtrip() {
    setup();

    let sig = Sig::new("ML-DSA-87").expect("failed to create ML-DSA-87 context");

    let (pk, sk) = sig.keygen().expect("keygen failed");
    let message = b"ML-DSA-87 test";
    let signature = sig.sign(message, &sk).expect("sign failed");

    sig.verify(message, &signature, &pk).expect("verify failed");

    cleanup();
}

#[test]
fn test_sig_verify_wrong_message() {
    setup();

    let sig = Sig::new("ML-DSA-65").expect("failed to create context");

    let (pk, sk) = sig.keygen().expect("keygen failed");
    let signature = sig.sign(b"correct message", &sk).expect("sign failed");

    let result = sig.verify(b"wrong message", &signature, &pk);
    assert!(result.is_err(), "verification should fail with wrong message");

    cleanup();
}

#[test]
fn test_sig_unsupported_algorithm() {
    setup();
    let result = Sig::new("NONEXISTENT-SIG");
    assert!(result.is_err());
    cleanup();
}

#[test]
fn test_sig_wrong_key_size() {
    setup();

    let sig = Sig::new("ML-DSA-65").expect("failed to create context");
    let bad_sk = vec![0u8; 10]; // wrong size

    let result = sig.sign(b"test", &bad_sk);
    assert!(result.is_err());

    cleanup();
}

#[test]
fn test_sig_is_stateful() {
    setup();

    let sig = Sig::new("ML-DSA-65").expect("ML-DSA-65");
    assert!(!sig.is_stateful(), "ML-DSA-65 should not be stateful");

    cleanup();
}

#[test]
fn test_sig_algorithm_enumeration() {
    setup();

    let count = pqc_dyber::sig_algorithm_count();
    assert!(count > 0, "should have at least one signature algorithm");

    for i in 0..count {
        let name = pqc_dyber::sig_algorithm_name(i);
        assert!(name.is_some(), "algorithm index {} should have a name", i);
    }

    cleanup();
}
