/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ECDSA over NIST P-256 (FIPS 186-5).
 */

#ifndef PQC_ECDSA_P256_H
#define PQC_ECDSA_P256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECDSA_P256_PUBLIC_KEY_BYTES  64  /* X(32) || Y(32), no 04 prefix */
#define ECDSA_P256_SECRET_KEY_BYTES 64  /* scalar(32) || pubkey X(32) */
#define ECDSA_P256_SIGNATURE_BYTES  64  /* r(32) || s(32) */

/**
 * Generate an ECDSA-P256 keypair.
 * pk = X(32) || Y(32)  (raw affine coordinates)
 * sk = scalar(32) || X(32)  (private scalar + public x-coordinate for nonce gen)
 * Returns 0 on success.
 */
int ecdsa_p256_keygen(uint8_t pk[64], uint8_t sk[64]);

/**
 * Sign a message with ECDSA-P256 (deterministic per RFC 6979).
 * sig = r(32) || s(32), big-endian.
 * Returns 0 on success.
 */
int ecdsa_p256_sign(uint8_t sig[64], const uint8_t *msg, size_t msglen,
                     const uint8_t sk[64]);

/**
 * Verify an ECDSA-P256 signature.
 * Returns 0 if valid, -1 otherwise.
 */
int ecdsa_p256_verify(const uint8_t *msg, size_t msglen,
                       const uint8_t sig[64], const uint8_t pk[64]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_ECDSA_P256_H */
