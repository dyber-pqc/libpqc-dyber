/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Rounding and decomposition for ML-DSA (FIPS 204).
 */

#include "core/sig/mldsa/rounding.h"
#include "core/sig/mldsa/mldsa_params.h"

/* ------------------------------------------------------------------ */
/* Power2Round (Algorithm 35 in FIPS 204)                               */
/* ------------------------------------------------------------------ */

int32_t pqc_mldsa_power2round(int32_t *a0, int32_t a)
{
    int32_t a1;

    a1 = (a + (1 << (PQC_MLDSA_D - 1)) - 1) >> PQC_MLDSA_D;
    *a0 = a - (a1 << PQC_MLDSA_D);
    return a1;
}

/* ------------------------------------------------------------------ */
/* Decompose (Algorithm 36 in FIPS 204)                                 */
/* ------------------------------------------------------------------ */

int32_t pqc_mldsa_decompose(int32_t *a0, int32_t a, int32_t gamma2)
{
    int32_t a1;

    a1 = (a + 127) >> 7;

    if (gamma2 == (PQC_MLDSA_Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else { /* gamma2 == (q-1)/88 */
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    *a0 = a - a1 * 2 * gamma2;
    *a0 -= (((PQC_MLDSA_Q - 1) / 2 - *a0) >> 31) & PQC_MLDSA_Q;
    return a1;
}

/* ------------------------------------------------------------------ */
/* MakeHint (Algorithm 37 in FIPS 204)                                  */
/* ------------------------------------------------------------------ */

unsigned pqc_mldsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2)
{
    if (a0 > gamma2 || a0 < -gamma2 ||
        (a0 == -gamma2 && a1 != 0))
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* UseHint (Algorithm 38 in FIPS 204)                                   */
/* ------------------------------------------------------------------ */

int32_t pqc_mldsa_use_hint(int32_t a, unsigned hint, int32_t gamma2)
{
    int32_t a0, a1;

    a1 = pqc_mldsa_decompose(&a0, a, gamma2);
    if (hint == 0)
        return a1;

    if (gamma2 == (PQC_MLDSA_Q - 1) / 32) {
        if (a0 > 0)
            return (a1 + 1) & 15;
        else
            return (a1 - 1) & 15;
    } else { /* gamma2 == (q-1)/88 */
        if (a0 > 0)
            return (a1 == 43) ? 0 : a1 + 1;
        else
            return (a1 == 0) ? 43 : a1 - 1;
    }
}
