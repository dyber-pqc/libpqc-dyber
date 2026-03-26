// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Integration tests for the KEM wrapper.

use pqc_dyber::{init, cleanup, Kem};

fn setup() {
    let _ = init();
}

#[test]
fn test_kem_mlkem768_roundtrip() {
    setup();

    let kem = Kem::new("ML-KEM-768").expect("failed to create ML-KEM-768 context");
    assert_eq!(kem.algorithm(), "ML-KEM-768");

    let (pk, sk) = kem.keygen().expect("keygen failed");
    assert_eq!(pk.len(), kem.public_key_size());
    assert_eq!(sk.len(), kem.secret_key_size());

    let (ct, ss_enc) = kem.encaps(&pk).expect("encaps failed");
    assert_eq!(ct.len(), kem.ciphertext_size());
    assert_eq!(ss_enc.len(), kem.shared_secret_size());

    let ss_dec = kem.decaps(&ct, &sk).expect("decaps failed");
    assert_eq!(ss_enc, ss_dec);

    cleanup();
}

#[test]
fn test_kem_mlkem512_roundtrip() {
    setup();

    let kem = Kem::new("ML-KEM-512").expect("failed to create ML-KEM-512 context");

    let (pk, sk) = kem.keygen().expect("keygen failed");
    let (ct, ss_enc) = kem.encaps(&pk).expect("encaps failed");
    let ss_dec = kem.decaps(&ct, &sk).expect("decaps failed");

    assert_eq!(ss_enc, ss_dec);

    cleanup();
}

#[test]
fn test_kem_mlkem1024_roundtrip() {
    setup();

    let kem = Kem::new("ML-KEM-1024").expect("failed to create ML-KEM-1024 context");

    let (pk, sk) = kem.keygen().expect("keygen failed");
    let (ct, ss_enc) = kem.encaps(&pk).expect("encaps failed");
    let ss_dec = kem.decaps(&ct, &sk).expect("decaps failed");

    assert_eq!(ss_enc, ss_dec);

    cleanup();
}

#[test]
fn test_kem_unsupported_algorithm() {
    setup();
    let result = Kem::new("NONEXISTENT-KEM");
    assert!(result.is_err());
    cleanup();
}

#[test]
fn test_kem_wrong_key_size() {
    setup();

    let kem = Kem::new("ML-KEM-768").expect("failed to create KEM context");
    let bad_pk = vec![0u8; 10]; // wrong size

    let result = kem.encaps(&bad_pk);
    assert!(result.is_err());

    cleanup();
}

#[test]
fn test_kem_security_level() {
    setup();

    let kem = Kem::new("ML-KEM-768").expect("ML-KEM-768");
    assert!(kem.security_level() >= 1 && kem.security_level() <= 5);

    cleanup();
}

#[test]
fn test_kem_algorithm_enumeration() {
    setup();

    let count = pqc_dyber::kem_algorithm_count();
    assert!(count > 0, "should have at least one KEM algorithm");

    for i in 0..count {
        let name = pqc_dyber::kem_algorithm_name(i);
        assert!(name.is_some(), "algorithm index {} should have a name", i);
    }

    cleanup();
}
