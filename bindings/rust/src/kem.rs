// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Safe wrapper around the libpqc KEM API.

use crate::error::{self, Error, Result};
use crate::ffi;
use std::ffi::CString;
use std::ptr;

/// A Key Encapsulation Mechanism context.
///
/// Wraps a `PQC_KEM` handle and provides safe key generation,
/// encapsulation, and decapsulation operations.
///
/// # Example
///
/// ```no_run
/// use pqc_dyber::Kem;
///
/// let kem = Kem::new("ML-KEM-768").unwrap();
/// let (pk, sk) = kem.keygen().unwrap();
/// let (ct, ss_enc) = kem.encaps(&pk).unwrap();
/// let ss_dec = kem.decaps(&ct, &sk).unwrap();
/// assert_eq!(ss_enc, ss_dec);
/// ```
pub struct Kem {
    ctx: *mut ffi::PqcKem,
}

// SAFETY: The underlying C context is internally synchronized and does not
// hold thread-local state; it is safe to move across threads.
unsafe impl Send for Kem {}
unsafe impl Sync for Kem {}

impl Kem {
    /// Create a new KEM context for the given algorithm name.
    ///
    /// Returns [`Error::NotSupported`] if the algorithm is unknown or disabled.
    pub fn new(algorithm: &str) -> Result<Self> {
        let c_alg =
            CString::new(algorithm).map_err(|_| Error::InvalidArgument)?;
        let ctx = unsafe { ffi::pqc_kem_new(c_alg.as_ptr()) };
        if ctx.is_null() {
            Err(Error::NotSupported)
        } else {
            Ok(Kem { ctx })
        }
    }

    /// The algorithm name string.
    pub fn algorithm(&self) -> &str {
        unsafe {
            let ptr = ffi::pqc_kem_algorithm(self.ctx);
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .unwrap_or("unknown")
        }
    }

    /// Size of a public key in bytes.
    pub fn public_key_size(&self) -> usize {
        unsafe { ffi::pqc_kem_public_key_size(self.ctx) }
    }

    /// Size of a secret key in bytes.
    pub fn secret_key_size(&self) -> usize {
        unsafe { ffi::pqc_kem_secret_key_size(self.ctx) }
    }

    /// Size of a ciphertext in bytes.
    pub fn ciphertext_size(&self) -> usize {
        unsafe { ffi::pqc_kem_ciphertext_size(self.ctx) }
    }

    /// Size of the shared secret in bytes.
    pub fn shared_secret_size(&self) -> usize {
        unsafe { ffi::pqc_kem_shared_secret_size(self.ctx) }
    }

    /// NIST security level (1-5).
    pub fn security_level(&self) -> i32 {
        unsafe { ffi::pqc_kem_security_level(self.ctx) }
    }

    /// Generate a keypair.
    ///
    /// Returns `(public_key, secret_key)`.
    pub fn keygen(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk_len = self.public_key_size();
        let sk_len = self.secret_key_size();
        let mut pk = vec![0u8; pk_len];
        let mut sk = vec![0u8; sk_len];

        let status = unsafe {
            ffi::pqc_kem_keygen(self.ctx, pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        error::check_status(status)?;
        Ok((pk, sk))
    }

    /// Encapsulate a shared secret using a public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    pub fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if pk.len() != self.public_key_size() {
            return Err(Error::InvalidArgument);
        }

        let ct_len = self.ciphertext_size();
        let ss_len = self.shared_secret_size();
        let mut ct = vec![0u8; ct_len];
        let mut ss = vec![0u8; ss_len];

        let status = unsafe {
            ffi::pqc_kem_encaps(
                self.ctx,
                ct.as_mut_ptr(),
                ss.as_mut_ptr(),
                pk.as_ptr(),
            )
        };
        error::check_status(status)?;
        Ok((ct, ss))
    }

    /// Decapsulate a ciphertext using a secret key to recover the shared secret.
    pub fn decaps(&self, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
        if ct.len() != self.ciphertext_size() {
            return Err(Error::InvalidArgument);
        }
        if sk.len() != self.secret_key_size() {
            return Err(Error::InvalidArgument);
        }

        let ss_len = self.shared_secret_size();
        let mut ss = vec![0u8; ss_len];

        let status = unsafe {
            ffi::pqc_kem_decaps(
                self.ctx,
                ss.as_mut_ptr(),
                ct.as_ptr(),
                sk.as_ptr(),
            )
        };
        error::check_status(status)?;
        Ok(ss)
    }

    /// Return the raw FFI pointer. Use with caution.
    pub fn as_ptr(&self) -> *const ffi::PqcKem {
        self.ctx
    }
}

impl Drop for Kem {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { ffi::pqc_kem_free(self.ctx) };
            self.ctx = ptr::null_mut();
        }
    }
}
