// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Error types wrapping `pqc_status_t`.

use crate::ffi;
use std::fmt;

/// Result type alias for libpqc operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error returned by libpqc operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Generic error.
    Generic,
    /// An argument was invalid (null pointer, bad length, etc.).
    InvalidArgument,
    /// Memory allocation failed.
    Alloc,
    /// The requested algorithm is not supported or not enabled.
    NotSupported,
    /// The provided key is invalid or malformed.
    InvalidKey,
    /// Signature verification failed.
    VerificationFailed,
    /// KEM decapsulation failed (implicit rejection may have occurred).
    DecapsulationFailed,
    /// The random number generator failed.
    RngFailed,
    /// A provided buffer was too small.
    BufferTooSmall,
    /// An internal library error occurred.
    Internal,
    /// Stateful signature scheme: signing state is exhausted.
    StateExhausted,
    /// Unknown status code from the C library.
    Unknown(i32),
}

impl Error {
    /// Create an [`Error`] from a raw `pqc_status_t` value.
    pub fn from_status(code: ffi::PqcStatus) -> Self {
        match code {
            ffi::PQC_ERROR => Error::Generic,
            ffi::PQC_ERROR_INVALID_ARGUMENT => Error::InvalidArgument,
            ffi::PQC_ERROR_ALLOC => Error::Alloc,
            ffi::PQC_ERROR_NOT_SUPPORTED => Error::NotSupported,
            ffi::PQC_ERROR_INVALID_KEY => Error::InvalidKey,
            ffi::PQC_ERROR_VERIFICATION_FAILED => Error::VerificationFailed,
            ffi::PQC_ERROR_DECAPSULATION_FAILED => Error::DecapsulationFailed,
            ffi::PQC_ERROR_RNG_FAILED => Error::RngFailed,
            ffi::PQC_ERROR_BUFFER_TOO_SMALL => Error::BufferTooSmall,
            ffi::PQC_ERROR_INTERNAL => Error::Internal,
            ffi::PQC_ERROR_STATE_EXHAUSTED => Error::StateExhausted,
            other => Error::Unknown(other),
        }
    }

    /// Return the raw `pqc_status_t` value.
    pub fn as_status(&self) -> ffi::PqcStatus {
        match self {
            Error::Generic => ffi::PQC_ERROR,
            Error::InvalidArgument => ffi::PQC_ERROR_INVALID_ARGUMENT,
            Error::Alloc => ffi::PQC_ERROR_ALLOC,
            Error::NotSupported => ffi::PQC_ERROR_NOT_SUPPORTED,
            Error::InvalidKey => ffi::PQC_ERROR_INVALID_KEY,
            Error::VerificationFailed => ffi::PQC_ERROR_VERIFICATION_FAILED,
            Error::DecapsulationFailed => ffi::PQC_ERROR_DECAPSULATION_FAILED,
            Error::RngFailed => ffi::PQC_ERROR_RNG_FAILED,
            Error::BufferTooSmall => ffi::PQC_ERROR_BUFFER_TOO_SMALL,
            Error::Internal => ffi::PQC_ERROR_INTERNAL,
            Error::StateExhausted => ffi::PQC_ERROR_STATE_EXHAUSTED,
            Error::Unknown(code) => *code,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = unsafe {
            let ptr = ffi::pqc_status_string(self.as_status());
            if ptr.is_null() {
                return write!(f, "pqc error (status {})", self.as_status());
            }
            std::ffi::CStr::from_ptr(ptr)
        };
        write!(f, "{}", msg.to_string_lossy())
    }
}

impl std::error::Error for Error {}

/// Check a `pqc_status_t` and convert non-OK values into [`Error`].
pub(crate) fn check_status(status: ffi::PqcStatus) -> Result<()> {
    if status == ffi::PQC_OK {
        Ok(())
    } else {
        Err(Error::from_status(status))
    }
}
