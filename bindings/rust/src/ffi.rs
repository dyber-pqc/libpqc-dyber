// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Raw FFI bindings to the libpqc C API.
//!
//! These are unsafe, low-level declarations. Prefer the safe wrappers in
//! [`crate::kem`], [`crate::sig`], and [`crate::hybrid`].

use std::os::raw::{c_char, c_int, c_void};

/// Status codes returned by libpqc functions.
pub type PqcStatus = i32;

pub const PQC_OK: PqcStatus = 0;
pub const PQC_ERROR: PqcStatus = -1;
pub const PQC_ERROR_INVALID_ARGUMENT: PqcStatus = -2;
pub const PQC_ERROR_ALLOC: PqcStatus = -3;
pub const PQC_ERROR_NOT_SUPPORTED: PqcStatus = -4;
pub const PQC_ERROR_INVALID_KEY: PqcStatus = -5;
pub const PQC_ERROR_VERIFICATION_FAILED: PqcStatus = -6;
pub const PQC_ERROR_DECAPSULATION_FAILED: PqcStatus = -7;
pub const PQC_ERROR_RNG_FAILED: PqcStatus = -8;
pub const PQC_ERROR_BUFFER_TOO_SMALL: PqcStatus = -9;
pub const PQC_ERROR_INTERNAL: PqcStatus = -10;
pub const PQC_ERROR_STATE_EXHAUSTED: PqcStatus = -11;

/// Algorithm type classification.
pub type PqcAlgType = i32;

pub const PQC_ALG_TYPE_KEM: PqcAlgType = 1;
pub const PQC_ALG_TYPE_SIG: PqcAlgType = 2;
pub const PQC_ALG_TYPE_SIG_STATEFUL: PqcAlgType = 3;
pub const PQC_ALG_TYPE_HYBRID_KEM: PqcAlgType = 4;
pub const PQC_ALG_TYPE_HYBRID_SIG: PqcAlgType = 5;

/// Security level (NIST categories 1-5).
pub type PqcSecurityLevel = i32;

pub const PQC_SECURITY_LEVEL_1: PqcSecurityLevel = 1;
pub const PQC_SECURITY_LEVEL_2: PqcSecurityLevel = 2;
pub const PQC_SECURITY_LEVEL_3: PqcSecurityLevel = 3;
pub const PQC_SECURITY_LEVEL_4: PqcSecurityLevel = 4;
pub const PQC_SECURITY_LEVEL_5: PqcSecurityLevel = 5;

/// Opaque KEM context.
#[repr(C)]
pub struct PqcKem {
    _opaque: [u8; 0],
}

/// Opaque Signature context.
#[repr(C)]
pub struct PqcSig {
    _opaque: [u8; 0],
}

/// Algorithm info structure.
#[repr(C)]
pub struct PqcAlgorithmInfo {
    pub name: *const c_char,
    pub alg_type: PqcAlgType,
    pub security_level: PqcSecurityLevel,
    pub nist_standard: *const c_char,
    pub enabled: c_int,
}

/// Custom RNG callback type.
pub type PqcRngCallback =
    Option<unsafe extern "C" fn(buf: *mut u8, len: usize, ctx: *mut c_void) -> PqcStatus>;

extern "C" {
    // ---- Library lifecycle ----
    pub fn pqc_init() -> PqcStatus;
    pub fn pqc_cleanup();

    // ---- Version ----
    pub fn pqc_version() -> *const c_char;
    pub fn pqc_version_major() -> c_int;
    pub fn pqc_version_minor() -> c_int;
    pub fn pqc_version_patch() -> c_int;

    // ---- Error codes ----
    pub fn pqc_status_string(status: PqcStatus) -> *const c_char;

    // ---- Secure memory ----
    pub fn pqc_malloc(size: usize) -> *mut c_void;
    pub fn pqc_calloc(count: usize, size: usize) -> *mut c_void;
    pub fn pqc_free(ptr: *mut c_void, size: usize);
    pub fn pqc_memzero(ptr: *mut c_void, size: usize);
    pub fn pqc_memcmp_ct(a: *const c_void, b: *const c_void, len: usize) -> c_int;

    // ---- Random ----
    pub fn pqc_randombytes(buf: *mut u8, len: usize) -> PqcStatus;
    pub fn pqc_set_rng(callback: PqcRngCallback, ctx: *mut c_void) -> PqcStatus;

    // ---- Algorithm enumeration ----
    pub fn pqc_kem_algorithm_count() -> c_int;
    pub fn pqc_kem_algorithm_name(index: c_int) -> *const c_char;
    pub fn pqc_kem_is_enabled(algorithm: *const c_char) -> c_int;

    pub fn pqc_sig_algorithm_count() -> c_int;
    pub fn pqc_sig_algorithm_name(index: c_int) -> *const c_char;
    pub fn pqc_sig_is_enabled(algorithm: *const c_char) -> c_int;

    pub fn pqc_algorithm_info(name: *const c_char, info: *mut PqcAlgorithmInfo) -> PqcStatus;

    // ---- KEM context ----
    pub fn pqc_kem_new(algorithm: *const c_char) -> *mut PqcKem;
    pub fn pqc_kem_free(kem: *mut PqcKem);

    // ---- KEM properties ----
    pub fn pqc_kem_algorithm(kem: *const PqcKem) -> *const c_char;
    pub fn pqc_kem_public_key_size(kem: *const PqcKem) -> usize;
    pub fn pqc_kem_secret_key_size(kem: *const PqcKem) -> usize;
    pub fn pqc_kem_ciphertext_size(kem: *const PqcKem) -> usize;
    pub fn pqc_kem_shared_secret_size(kem: *const PqcKem) -> usize;
    pub fn pqc_kem_security_level(kem: *const PqcKem) -> PqcSecurityLevel;

    // ---- KEM operations ----
    pub fn pqc_kem_keygen(
        kem: *const PqcKem,
        public_key: *mut u8,
        secret_key: *mut u8,
    ) -> PqcStatus;

    pub fn pqc_kem_encaps(
        kem: *const PqcKem,
        ciphertext: *mut u8,
        shared_secret: *mut u8,
        public_key: *const u8,
    ) -> PqcStatus;

    pub fn pqc_kem_decaps(
        kem: *const PqcKem,
        shared_secret: *mut u8,
        ciphertext: *const u8,
        secret_key: *const u8,
    ) -> PqcStatus;

    // ---- Signature context ----
    pub fn pqc_sig_new(algorithm: *const c_char) -> *mut PqcSig;
    pub fn pqc_sig_free(sig: *mut PqcSig);

    // ---- Signature properties ----
    pub fn pqc_sig_algorithm(sig: *const PqcSig) -> *const c_char;
    pub fn pqc_sig_public_key_size(sig: *const PqcSig) -> usize;
    pub fn pqc_sig_secret_key_size(sig: *const PqcSig) -> usize;
    pub fn pqc_sig_max_signature_size(sig: *const PqcSig) -> usize;
    pub fn pqc_sig_security_level(sig: *const PqcSig) -> PqcSecurityLevel;
    pub fn pqc_sig_is_stateful(sig: *const PqcSig) -> c_int;

    // ---- Signature operations ----
    pub fn pqc_sig_keygen(
        sig: *const PqcSig,
        public_key: *mut u8,
        secret_key: *mut u8,
    ) -> PqcStatus;

    pub fn pqc_sig_sign(
        sig: *const PqcSig,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> PqcStatus;

    pub fn pqc_sig_verify(
        sig: *const PqcSig,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> PqcStatus;

    pub fn pqc_sig_sign_stateful(
        sig: *const PqcSig,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *mut u8,
    ) -> PqcStatus;

    // ---- Hybrid enumeration ----
    pub fn pqc_hybrid_kem_count() -> c_int;
    pub fn pqc_hybrid_kem_name(index: c_int) -> *const c_char;
    pub fn pqc_hybrid_sig_count() -> c_int;
    pub fn pqc_hybrid_sig_name(index: c_int) -> *const c_char;
}
