// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Hybrid scheme helpers.
//!
//! Hybrid algorithms combine a post-quantum scheme with a classical one
//! (e.g., ML-KEM-768 + X25519). They use the same [`Kem`](crate::Kem) and
//! [`Sig`](crate::Sig) types -- just pass the hybrid algorithm name.
//!
//! This module provides convenience functions for discovering available
//! hybrid algorithms.

use crate::ffi;

/// Return a list of all available hybrid KEM algorithm names.
pub fn hybrid_kem_algorithms() -> Vec<&'static str> {
    let count = unsafe { ffi::pqc_hybrid_kem_count() };
    let mut names = Vec::with_capacity(count as usize);
    for i in 0..count {
        let ptr = unsafe { ffi::pqc_hybrid_kem_name(i) };
        if !ptr.is_null() {
            if let Ok(s) = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str() {
                names.push(s);
            }
        }
    }
    names
}

/// Return a list of all available hybrid signature algorithm names.
pub fn hybrid_sig_algorithms() -> Vec<&'static str> {
    let count = unsafe { ffi::pqc_hybrid_sig_count() };
    let mut names = Vec::with_capacity(count as usize);
    for i in 0..count {
        let ptr = unsafe { ffi::pqc_hybrid_sig_name(i) };
        if !ptr.is_null() {
            if let Ok(s) = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str() {
                names.push(s);
            }
        }
    }
    names
}
