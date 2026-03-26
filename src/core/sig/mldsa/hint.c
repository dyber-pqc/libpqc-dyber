/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hint packing/unpacking for ML-DSA signatures (FIPS 204).
 */

#include <string.h>

#include "core/sig/mldsa/hint.h"
#include "core/sig/mldsa/mldsa_params.h"

/* ------------------------------------------------------------------ */
/* Pack hint vector into signature bytes.                               */
/*                                                                      */
/* Format (omega + k bytes total):                                      */
/*   First omega bytes: indices of nonzero hint coefficients,           */
/*   padded with zeros.                                                 */
/*   Last k bytes: cumulative counts of hints per polynomial.           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_pack_hint(uint8_t *sig_hint,
                          const pqc_mldsa_polyveck *h,
                          unsigned k, unsigned omega)
{
    unsigned i, j, cnt;

    memset(sig_hint, 0, omega + k);

    cnt = 0;
    for (i = 0; i < k; i++) {
        for (j = 0; j < PQC_MLDSA_N; j++) {
            if (h->vec[i].coeffs[j] != 0) {
                sig_hint[cnt++] = (uint8_t)j;
            }
        }
        sig_hint[omega + i] = (uint8_t)cnt;
    }
}

/* ------------------------------------------------------------------ */
/* Unpack hint vector from signature bytes.                             */
/* Returns 0 on success, -1 on invalid encoding.                        */
/* ------------------------------------------------------------------ */

int pqc_mldsa_unpack_hint(pqc_mldsa_polyveck *h,
                           const uint8_t *sig_hint,
                           unsigned k, unsigned omega)
{
    unsigned i, j, idx;
    unsigned prev_cnt, cnt;

    /* Zero out all hint polynomials */
    for (i = 0; i < k; i++)
        memset(h->vec[i].coeffs, 0, sizeof(h->vec[i].coeffs));

    prev_cnt = 0;
    for (i = 0; i < k; i++) {
        cnt = (unsigned)sig_hint[omega + i];

        /* Count must be monotonically non-decreasing and <= omega */
        if (cnt < prev_cnt || cnt > omega)
            return -1;

        for (j = prev_cnt; j < cnt; j++) {
            idx = (unsigned)sig_hint[j];

            /* Indices within a polynomial must be strictly increasing */
            if (j > prev_cnt && idx <= (unsigned)sig_hint[j - 1])
                return -1;

            if (idx >= PQC_MLDSA_N)
                return -1;

            h->vec[i].coeffs[idx] = 1;
        }

        prev_cnt = cnt;
    }

    /* Remaining index bytes must be zero */
    for (j = prev_cnt; j < omega; j++) {
        if (sig_hint[j] != 0)
            return -1;
    }

    return 0;
}
