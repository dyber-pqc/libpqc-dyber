/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Ed25519 digital signatures (RFC 8032).
 */

#ifndef PQC_ED25519_H
#define PQC_ED25519_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ED25519_PUBLIC_KEY_BYTES  32
#define ED25519_SECRET_KEY_BYTES  32
#define ED25519_SIGNATURE_BYTES   64

/**
 * Generate an Ed25519 keypair.
 * sk is filled with 32 random bytes, pk is derived via SHA-512.
 * Returns 0 on success.
 */
int ed25519_keygen(uint8_t pk[32], uint8_t sk[32]);

/**
 * Sign a message. sig is 64 bytes. Deterministic (RFC 8032).
 * Returns 0 on success.
 */
int ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msglen,
                  const uint8_t sk[32]);

/**
 * Verify a signature.
 * Returns 0 if valid, -1 otherwise.
 */
int ed25519_verify(const uint8_t *msg, size_t msglen,
                    const uint8_t sig[64], const uint8_t pk[32]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_ED25519_H */
