// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! # pqc-dyber
//!
//! Safe Rust bindings for the **libpqc-dyber** post-quantum cryptography library.
//!
//! This crate provides access to NIST-standardized and candidate post-quantum
//! key encapsulation mechanisms (KEMs) and digital signature algorithms through
//! a unified, memory-safe API.
//!
//! ## Quick Start
//!
//! ```no_run
//! use pqc_dyber::{Kem, Sig, init, cleanup};
//!
//! init().expect("library init");
//!
//! // Key Encapsulation
//! let kem = Kem::new("ML-KEM-768").expect("kem");
//! let (pk, sk) = kem.keygen().expect("keygen");
//! let (ct, ss1) = kem.encaps(&pk).expect("encaps");
//! let ss2 = kem.decaps(&ct, &sk).expect("decaps");
//! assert_eq!(ss1, ss2);
//!
//! // Digital Signatures
//! let sig = Sig::new("ML-DSA-65").expect("sig");
//! let (pk, sk) = sig.keygen().expect("keygen");
//! let signature = sig.sign(b"hello", &sk).expect("sign");
//! sig.verify(b"hello", &signature, &pk).expect("verify");
//!
//! cleanup();
//! ```

pub mod error;
pub mod ffi;
pub mod hybrid;
pub mod kem;
pub mod sig;

pub use error::{Error, Result};
pub use hybrid::{hybrid_kem_algorithms, hybrid_sig_algorithms};
pub use kem::Kem;
pub use sig::Sig;

/// Initialize the libpqc library. Must be called before any other operations.
pub fn init() -> Result<()> {
    let status = unsafe { ffi::pqc_init() };
    error::check_status(status)
}

/// Clean up the libpqc library. Should be called when done.
pub fn cleanup() {
    unsafe { ffi::pqc_cleanup() };
}

/// Return the version string of the underlying C library.
pub fn version() -> &'static str {
    unsafe {
        let ptr = ffi::pqc_version();
        std::ffi::CStr::from_ptr(ptr)
            .to_str()
            .unwrap_or("unknown")
    }
}

/// Return the number of available KEM algorithms.
pub fn kem_algorithm_count() -> usize {
    unsafe { ffi::pqc_kem_algorithm_count() as usize }
}

/// Return the name of the KEM algorithm at `index`.
pub fn kem_algorithm_name(index: usize) -> Option<&'static str> {
    unsafe {
        let ptr = ffi::pqc_kem_algorithm_name(index as i32);
        if ptr.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr(ptr).to_str().ok()
        }
    }
}

/// Return the number of available signature algorithms.
pub fn sig_algorithm_count() -> usize {
    unsafe { ffi::pqc_sig_algorithm_count() as usize }
}

/// Return the name of the signature algorithm at `index`.
pub fn sig_algorithm_name(index: usize) -> Option<&'static str> {
    unsafe {
        let ptr = ffi::pqc_sig_algorithm_name(index as i32);
        if ptr.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr(ptr).to_str().ok()
        }
    }
}
