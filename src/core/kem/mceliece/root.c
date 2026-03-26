/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Root finding.
 *
 * Evaluates a polynomial at all support elements to find its roots.
 * Used in Patterson's decoding algorithm to find error locations.
 */

#include <string.h>
#include "mceliece.h"

/* ------------------------------------------------------------------ */
/* Evaluate polynomial at all support elements                         */
/* ------------------------------------------------------------------ */

/*
 * Evaluate polynomial f(x) = f[0] + f[1]*x + ... + f[deg]*x^deg
 * at each support element alpha_i = support[i].
 *
 * out[i] = f(support[i]) for i in [0, n).
 *
 * Uses Horner's method for each evaluation point.
 */
void root_eval(gf_t *out, const gf_t *f, int deg,
               const uint16_t *support, int n, int m)
{
    for (int i = 0; i < n; i++) {
        gf_t alpha = (gf_t)support[i];
        gf_t val = f[deg];

        for (int j = deg - 1; j >= 0; j--) {
            val = gf_add(gf_mul(val, alpha, m), f[j]);
        }

        out[i] = val;
    }
}
