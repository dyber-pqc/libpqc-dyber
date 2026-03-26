# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# R wrapper functions for libpqc.

#' Get the library version string.
#' @return A character string.
#' @export
pqc_version <- function() {
  .Call(C_pqc_version)
}

#' List all available KEM algorithm names.
#' @return A character vector of algorithm names.
#' @export
pqc_kem_algorithms <- function() {
  .Call(C_pqc_kem_algorithms)
}

#' List all available signature algorithm names.
#' @return A character vector of algorithm names.
#' @export
pqc_sig_algorithms <- function() {
  .Call(C_pqc_sig_algorithms)
}

#' Create a new KEM context.
#' @param algorithm Character string, e.g. "ML-KEM-768".
#' @return An external pointer representing the KEM context.
#' @export
kem_new <- function(algorithm) {
  stopifnot(is.character(algorithm), length(algorithm) == 1)
  .Call(C_kem_new, algorithm)
}

#' Generate a KEM keypair.
#' @param kem External pointer from \code{kem_new}.
#' @return A list with components \code{public_key} and \code{secret_key} (raw vectors).
#' @export
kem_keygen <- function(kem) {
  .Call(C_kem_keygen, kem)
}

#' KEM encapsulation.
#' @param kem External pointer from \code{kem_new}.
#' @param public_key Raw vector (public key).
#' @return A list with components \code{ciphertext} and \code{shared_secret} (raw vectors).
#' @export
kem_encaps <- function(kem, public_key) {
  stopifnot(is.raw(public_key))
  .Call(C_kem_encaps, kem, public_key)
}

#' KEM decapsulation.
#' @param kem External pointer from \code{kem_new}.
#' @param ciphertext Raw vector.
#' @param secret_key Raw vector.
#' @return A raw vector containing the shared secret.
#' @export
kem_decaps <- function(kem, ciphertext, secret_key) {
  stopifnot(is.raw(ciphertext), is.raw(secret_key))
  .Call(C_kem_decaps, kem, ciphertext, secret_key)
}

#' Create a new signature context.
#' @param algorithm Character string, e.g. "ML-DSA-65".
#' @return An external pointer representing the signature context.
#' @export
sig_new <- function(algorithm) {
  stopifnot(is.character(algorithm), length(algorithm) == 1)
  .Call(C_sig_new, algorithm)
}

#' Generate a signature keypair.
#' @param sig External pointer from \code{sig_new}.
#' @return A list with components \code{public_key} and \code{secret_key} (raw vectors).
#' @export
sig_keygen <- function(sig) {
  .Call(C_sig_keygen, sig)
}

#' Sign a message.
#' @param sig External pointer from \code{sig_new}.
#' @param message Raw vector (the message to sign).
#' @param secret_key Raw vector (the signer's secret key).
#' @return A raw vector containing the signature.
#' @export
sig_sign <- function(sig, message, secret_key) {
  stopifnot(is.raw(message), is.raw(secret_key))
  .Call(C_sig_sign, sig, message, secret_key)
}

#' Verify a signature.
#' @param sig External pointer from \code{sig_new}.
#' @param message Raw vector.
#' @param signature Raw vector.
#' @param public_key Raw vector.
#' @return Logical: TRUE if valid, FALSE otherwise.
#' @export
sig_verify <- function(sig, message, signature, public_key) {
  stopifnot(is.raw(message), is.raw(signature), is.raw(public_key))
  .Call(C_sig_verify, sig, message, signature, public_key)
}
