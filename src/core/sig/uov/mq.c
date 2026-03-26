/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV - Multivariate quadratic evaluation.
 *
 * Evaluates a system of m multivariate quadratic polynomials in n
 * variables over GF(256).  Each polynomial is stored as an upper-
 * triangular matrix of coefficients (n*(n+1)/2 elements).
 */

#include <string.h>
#include <stdint.h>
#include "uov.h"

/* ------------------------------------------------------------------ */
/* Evaluate the MQ system P at vector x, producing m GF(256) outputs.   */
/*                                                                      */
/* P: m polynomials, each stored as n*(n+1)/2 upper-triangular          */
/*    coefficients in row-major order.                                  */
/* x: input vector of n GF(256) elements.                               */
/* result: output vector of m GF(256) elements.                         */
/* ------------------------------------------------------------------ */

void uov_mq_evaluate(uint8_t *result, const uint8_t *P,
                      const uint8_t *x, int n, int m)
{
    int eq, i, j;
    int tri_size = n * (n + 1) / 2;

    memset(result, 0, (size_t)m);

    for (eq = 0; eq < m; eq++) {
        const uint8_t *poly = P + eq * tri_size;
        uint8_t val = 0;
        int idx = 0;

        for (i = 0; i < n; i++) {
            for (j = i; j < n; j++) {
                uint8_t coeff = poly[idx++];
                if (coeff != 0) {
                    val = gf256_add(val,
                        gf256_mul(coeff, gf256_mul(x[i], x[j])));
                }
            }
        }
        result[eq] = val;
    }
}
