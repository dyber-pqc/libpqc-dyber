/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO - Vinegar variable sampling and substitution.
 *
 * In the signing process, the signer first samples random values for
 * the vinegar variables, then substitutes them into the multivariate
 * quadratic system to obtain a linear system in the oil variables.
 */

#include <string.h>
#include <stdint.h>
#include "mayo.h"
#include "core/common/hash/sha3.h"
#include "pqc/rand.h"

/* ------------------------------------------------------------------ */
/* Sample random GF(16) vinegar values.                                 */
/*                                                                      */
/* v_vals: output array of v_count GF(16) elements.                     */
/* salt: optional salt for domain separation.                           */
/* salt_len: length of salt (0 if unused).                              */
/* ------------------------------------------------------------------ */

void mayo_sample_vinegar(uint8_t *v_vals, int v_count,
                         const uint8_t *salt, size_t salt_len)
{
    size_t packed_len = ((size_t)v_count + 1) / 2;
    uint8_t buf[256];
    int i;

    (void)salt;
    (void)salt_len;

    /* Generate random bytes, then unpack to GF(16) elements */
    pqc_randombytes(buf, packed_len);

    for (i = 0; i < v_count; i++) {
        if (i % 2 == 0) {
            v_vals[i] = (buf[i / 2] >> 4) & 0x0F;
        } else {
            v_vals[i] = buf[i / 2] & 0x0F;
        }
    }

    pqc_memzero(buf, sizeof(buf));
}

/* ------------------------------------------------------------------ */
/* Substitute vinegar values into the MQ system.                        */
/*                                                                      */
/* Given the multivariate quadratic map P consisting of m quadratic     */
/* polynomials in n = v + o variables over GF(16), substitute the       */
/* vinegar values to produce a linear system in the o oil variables.     */
/*                                                                      */
/* target: output m x (o+1) augmented matrix (m equations, o unknowns). */
/* P: the public/central map as m upper-triangular matrices, each       */
/*    stored as n*(n+1)/2 GF(16) elements in row-major upper-tri order. */
/* v_vals: the v vinegar values.                                        */
/* params: MAYO parameters.                                             */
/* ------------------------------------------------------------------ */

void mayo_vinegar_substitute(uint8_t *target, const uint8_t *P,
                             const uint8_t *v_vals,
                             const mayo_params_t *params)
{
    int m = params->m;
    int n = params->n;
    int v = params->v;
    int o = params->o;
    int eq, i, j;

    /* Number of upper-triangular entries per polynomial */
    int tri_size = n * (n + 1) / 2;

    memset(target, 0, (size_t)m * (size_t)(o + 1));

    for (eq = 0; eq < m; eq++) {
        const uint8_t *poly = P + eq * tri_size;
        uint8_t constant = 0;
        int idx = 0;

        /*
         * The polynomial p_eq(x_0, ..., x_{n-1}) is stored as upper-
         * triangular coefficients: p_{i,j} for 0 <= i <= j < n.
         *
         * After substituting vinegar variables x_0..x_{v-1}:
         * - (i < v, j < v):  contributes to constant term
         * - (i < v, j >= v): contributes linear coefficient for oil var j-v
         * - (i >= v, j >= v): contributes to quadratic oil terms (set to 0
         *                     in MAYO because we solve a linear system)
         */
        for (i = 0; i < n; i++) {
            for (j = i; j < n; j++) {
                uint8_t coeff = poly[idx++];
                if (coeff == 0) continue;

                if (i < v && j < v) {
                    /* Both vinegar: constant term */
                    constant = gf16_add(constant,
                        gf16_mul(coeff, gf16_mul(v_vals[i], v_vals[j])));
                } else if (i < v && j >= v) {
                    /* One vinegar, one oil: linear term for oil var (j - v) */
                    target[eq * (o + 1) + (j - v)] = gf16_add(
                        target[eq * (o + 1) + (j - v)],
                        gf16_mul(coeff, v_vals[i])
                    );
                }
                /* (i >= v, j >= v): quadratic in oil; ignored for linear solve */
            }
        }

        /* The constant goes into the augmented column */
        target[eq * (o + 1) + o] = constant;
    }
}
