/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Shared helpers for the libFuzzer targets in this directory.
 */
#ifndef PQC_FUZZ_COMMON_H
#define PQC_FUZZ_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"

/*
 * Deterministic RNG, reseeded per algorithm before its key generation, so
 * that a crashing input reproduces with the same keys whichever
 * algorithms happened to be initialised before it.
 */
static uint64_t fuzz_rng_state;

static pqc_status_t fuzz_rng(uint8_t *buf, size_t len, void *ctx)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < len; i++) {
        fuzz_rng_state ^= fuzz_rng_state << 13;
        fuzz_rng_state ^= fuzz_rng_state >> 7;
        fuzz_rng_state ^= fuzz_rng_state << 17;
        buf[i] = (uint8_t)fuzz_rng_state;
    }
    return PQC_OK;
}

static void fuzz_reseed(uint32_t salt)
{
    fuzz_rng_state = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)salt << 32 | salt);
    if (!fuzz_rng_state) fuzz_rng_state = 1;
}

/*
 * Exactly `len` bytes on the heap, filled from the fuzz input (repeated if
 * the input is shorter, zero if it is empty). Exact-size allocations let
 * AddressSanitizer catch a read past the advertised length.
 */
static uint8_t *fuzz_fill(size_t len, const uint8_t *data, size_t size)
{
    uint8_t *p = (uint8_t *)malloc(len ? len : 1);
    size_t i;
    if (!p) abort();
    for (i = 0; i < len; i++)
        p[i] = size ? data[i % size] : 0;
    return p;
}

/*
 * Key generation (and, for signatures, the first signature) is skipped
 * for these, because under ASan it costs tens of seconds or more and that
 * cost lands on whichever input first selects the algorithm, where
 * libFuzzer would report it as a timeout:
 *
 *   Classic McEliece          key generation
 *   LMS H15+ / XMSS 16, 20    trees of 2^15 leaves and more
 *   SLH-DSA / SPHINCS+ SHAKE  "s" sets: 30-85 s to sign under ASan; the
 *                             "f" sets run the same verification code
 *   FN-DSA                    key generation fails (known issue) after
 *                             up to 25 s
 *
 * They are still fuzzed with attacker-chosen public keys and signatures.
 * Matched as substrings.
 */
static int fuzz_keygen_too_slow(const char *name)
{
    static const char *slow[] = {
        "Classic-McEliece-", "LMS-SHA256-H15", "LMS-SHA256-H20",
        "LMS-SHA256-H25", "XMSS-SHA2-16-", "XMSS-SHA2-20-",
        "-SHAKE-128s", "-SHAKE-192s", "-SHAKE-256s", "FN-DSA-", NULL
    };
    int i;
    for (i = 0; slow[i]; i++)
        if (strstr(name, slow[i]) != NULL)
            return 1;
    return 0;
}

#endif /* PQC_FUZZ_COMMON_H */
