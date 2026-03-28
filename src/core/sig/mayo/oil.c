/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO - Oil space computation.
 *
 * The oil subspace O is an o-dimensional subspace of GF(16)^n.
 * It is derived deterministically from the secret key seed using
 * SHAKE-256 and stored as a v x o matrix over GF(16).
 */

#include <string.h>
#include <stdint.h>
#include "pqc/common.h"
#include "mayo.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Compute the oil subspace matrix from the secret key seed.            */
/*                                                                      */
/* oil: output buffer of v*o GF(16) elements (unpacked).                */
/* sk_seed: compact secret key seed.                                    */
/* params: MAYO parameter set.                                          */
/* ------------------------------------------------------------------ */

void mayo_compute_oil_space(uint8_t *oil, const uint8_t *sk_seed,
                            const mayo_params_t *params)
{
    int v = params->v;
    int o = params->o;
    size_t oil_size = (size_t)v * (size_t)o;
    uint8_t buf[PQC_MAYO_MAX_V * PQC_MAYO_MAX_O];
    size_t packed_len = (oil_size + 1) / 2;
    size_t i;

    /*
     * Expand the secret seed into the oil matrix via SHAKE-256.
     * We generate packed GF(16) elements (2 per byte) then unpack.
     */
    pqc_shake256(buf, packed_len, sk_seed, (size_t)params->seed_len);

    for (i = 0; i < oil_size; i++) {
        if (i % 2 == 0) {
            oil[i] = (buf[i / 2] >> 4) & 0x0F;
        } else {
            oil[i] = buf[i / 2] & 0x0F;
        }
    }

    pqc_memzero(buf, sizeof(buf));
}
