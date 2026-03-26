/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Keccak-f[1600] permutation primitives for libpqc-dyber.
 *
 * Copyright (c) 2024-2026 Dyber, Inc.
 * Licensed under the Apache License, Version 2.0 or the MIT license,
 * at your option.
 */

#ifndef PQC_KECCAK_H
#define PQC_KECCAK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Number of rounds in the Keccak-f[1600] permutation.
 */
#define PQC_KECCAK_ROUNDS 24

/*
 * State size: 25 lanes of 64 bits each = 1600 bits = 200 bytes.
 */
#define PQC_KECCAK_STATE_LANES 25
#define PQC_KECCAK_STATE_BYTES 200

/**
 * Initialise a Keccak state to all zeros.
 *
 * @param state  Pointer to 25 x uint64_t.
 */
void pqc_keccak_init(uint64_t state[PQC_KECCAK_STATE_LANES]);

/**
 * Apply the full Keccak-f[1600] permutation (24 rounds) in place.
 *
 * @param state  Pointer to 25 x uint64_t.
 */
void pqc_keccak_f1600(uint64_t state[PQC_KECCAK_STATE_LANES]);

/**
 * Absorb arbitrary-length data into the sponge state.
 *
 * The caller must have initialised @p state beforehand with
 * pqc_keccak_init().  @p rate is the sponge rate **in bytes**
 * (e.g. 168 for SHAKE-128, 136 for SHA3-256 / SHAKE-256).
 *
 * After absorbing, the domain-separation / padding byte has NOT yet
 * been applied -- the caller (sha3.c) is responsible for that.
 *
 * @param state    25 x uint64_t Keccak state.
 * @param rate     Sponge rate in bytes (must be <= 200).
 * @param data     Input data.
 * @param datalen  Length of input data in bytes.
 */
void pqc_keccak_absorb(uint64_t state[PQC_KECCAK_STATE_LANES],
                        size_t rate,
                        const uint8_t *data,
                        size_t datalen);

/**
 * Squeeze arbitrary-length output from the sponge state.
 *
 * The caller must have finalised absorption (applied domain-separation
 * padding and the final permutation call) before squeezing.
 *
 * @param state   25 x uint64_t Keccak state.
 * @param rate    Sponge rate in bytes.
 * @param out     Output buffer.
 * @param outlen  Number of bytes to squeeze.
 */
void pqc_keccak_squeeze(uint64_t state[PQC_KECCAK_STATE_LANES],
                         size_t rate,
                         uint8_t *out,
                         size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* PQC_KECCAK_H */
