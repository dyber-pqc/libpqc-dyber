/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 */

#ifndef PQC_X25519_H
#define PQC_X25519_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X25519_PUBLIC_KEY_BYTES  32
#define X25519_SECRET_KEY_BYTES  32
#define X25519_SHARED_SECRET_BYTES 32

/**
 * Generate an X25519 keypair.
 * sk is filled with 32 random bytes, pk = X25519(sk, 9).
 * Returns 0 on success.
 */
int x25519_keygen(uint8_t pk[32], uint8_t sk[32]);

/**
 * Compute the shared secret: ss = X25519(sk, pk).
 * Returns 0 on success, -1 if the result is the all-zero point.
 */
int x25519_shared_secret(uint8_t ss[32], const uint8_t pk[32],
                          const uint8_t sk[32]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_X25519_H */
