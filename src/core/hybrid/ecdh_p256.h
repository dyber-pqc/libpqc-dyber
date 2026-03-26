/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ECDH over NIST P-256.
 */

#ifndef PQC_ECDH_P256_H
#define PQC_ECDH_P256_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ECDH_P256_PUBLIC_KEY_BYTES  65  /* 04 || X(32) || Y(32) */
#define ECDH_P256_SECRET_KEY_BYTES 32
#define ECDH_P256_SHARED_SECRET_BYTES 32

/**
 * Generate an ECDH-P256 keypair.
 * sk is 32 random bytes (scalar).
 * pk is the uncompressed point (65 bytes: 04 || x || y).
 * Returns 0 on success.
 */
int ecdh_p256_keygen(uint8_t pk[65], uint8_t sk[32]);

/**
 * Compute the ECDH shared secret.
 * ss = SHA-256(x-coordinate of sk * pk).
 * Returns 0 on success.
 */
int ecdh_p256_shared_secret(uint8_t ss[32], const uint8_t pk[65],
                             const uint8_t sk[32]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_ECDH_P256_H */
