// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Safe wrapper around the libpqc Signature API.

use crate::error::{self, Error, Result};
use crate::ffi;
use std::ffi::CString;
use std::ptr;

/// A Digital Signature context.
///
/// Wraps a `PQC_SIG` handle and provides safe key generation,
/// signing, and verification operations.
///
/// # Example
///
/// ```no_run
/// use pqc_dyber::Sig;
///
/// let sig = Sig::new("ML-DSA-65").unwrap();
/// let (pk, sk) = sig.keygen().unwrap();
/// let signature = sig.sign(b"hello world", &sk).unwrap();
/// sig.verify(b"hello world", &signature, &pk).unwrap();
/// ```
pub struct Sig {
    ctx: *mut ffi::PqcSig,
}

// SAFETY: The underlying C context is internally synchronized and does not
// hold thread-local state; it is safe to move across threads.
unsafe impl Send for Sig {}
unsafe impl Sync for Sig {}

impl Sig {
    /// Create a new signature context for the given algorithm name.
    ///
    /// Returns [`Error::NotSupported`] if the algorithm is unknown or disabled.
    pub fn new(algorithm: &str) -> Result<Self> {
        let c_alg =
            CString::new(algorithm).map_err(|_| Error::InvalidArgument)?;
        let ctx = unsafe { ffi::pqc_sig_new(c_alg.as_ptr()) };
        if ctx.is_null() {
            Err(Error::NotSupported)
        } else {
            Ok(Sig { ctx })
        }
    }

    /// The algorithm name string.
    pub fn algorithm(&self) -> &str {
        unsafe {
            let ptr = ffi::pqc_sig_algorithm(self.ctx);
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .unwrap_or("unknown")
        }
    }

    /// Size of a public key in bytes.
    pub fn public_key_size(&self) -> usize {
        unsafe { ffi::pqc_sig_public_key_size(self.ctx) }
    }

    /// Size of a secret key in bytes.
    pub fn secret_key_size(&self) -> usize {
        unsafe { ffi::pqc_sig_secret_key_size(self.ctx) }
    }

    /// Maximum possible signature size in bytes.
    pub fn max_signature_size(&self) -> usize {
        unsafe { ffi::pqc_sig_max_signature_size(self.ctx) }
    }

    /// NIST security level (1-5).
    pub fn security_level(&self) -> i32 {
        unsafe { ffi::pqc_sig_security_level(self.ctx) }
    }

    /// Whether this is a stateful signature scheme (e.g., LMS, XMSS).
    pub fn is_stateful(&self) -> bool {
        unsafe { ffi::pqc_sig_is_stateful(self.ctx) != 0 }
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
            ffi::pqc_sig_keygen(self.ctx, pk.as_mut_ptr(), sk.as_mut_ptr())
        };
        error::check_status(status)?;
        Ok((pk, sk))
    }

    /// Sign a message.
    ///
    /// Returns the signature bytes (length may be shorter than `max_signature_size`).
    pub fn sign(&self, message: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
        if sk.len() != self.secret_key_size() {
            return Err(Error::InvalidArgument);
        }

        let max_sig = self.max_signature_size();
        let mut sig_buf = vec![0u8; max_sig];
        let mut sig_len: usize = 0;

        let status = unsafe {
            ffi::pqc_sig_sign(
                self.ctx,
                sig_buf.as_mut_ptr(),
                &mut sig_len,
                message.as_ptr(),
                message.len(),
                sk.as_ptr(),
            )
        };
        error::check_status(status)?;
        sig_buf.truncate(sig_len);
        Ok(sig_buf)
    }

    /// Verify a signature on a message.
    ///
    /// Returns `Ok(())` if valid, or [`Error::VerificationFailed`] if invalid.
    pub fn verify(&self, message: &[u8], signature: &[u8], pk: &[u8]) -> Result<()> {
        if pk.len() != self.public_key_size() {
            return Err(Error::InvalidArgument);
        }

        let status = unsafe {
            ffi::pqc_sig_verify(
                self.ctx,
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
                pk.as_ptr(),
            )
        };
        error::check_status(status)
    }

    /// Sign with a stateful scheme. The `sk` buffer is modified in-place to
    /// advance the internal state.
    ///
    /// Only valid for stateful algorithms (LMS, XMSS). Returns
    /// [`Error::NotSupported`] conceptually if the algorithm is not stateful
    /// (the C library returns the appropriate error).
    pub fn sign_stateful(&self, message: &[u8], sk: &mut [u8]) -> Result<Vec<u8>> {
        if sk.len() != self.secret_key_size() {
            return Err(Error::InvalidArgument);
        }

        let max_sig = self.max_signature_size();
        let mut sig_buf = vec![0u8; max_sig];
        let mut sig_len: usize = 0;

        let status = unsafe {
            ffi::pqc_sig_sign_stateful(
                self.ctx,
                sig_buf.as_mut_ptr(),
                &mut sig_len,
                message.as_ptr(),
                message.len(),
                sk.as_mut_ptr(),
            )
        };
        error::check_status(status)?;
        sig_buf.truncate(sig_len);
        Ok(sig_buf)
    }

    /// Return the raw FFI pointer. Use with caution.
    pub fn as_ptr(&self) -> *const ffi::PqcSig {
        self.ctx
    }
}

impl Drop for Sig {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { ffi::pqc_sig_free(self.ctx) };
            self.ctx = ptr::null_mut();
        }
    }
}
