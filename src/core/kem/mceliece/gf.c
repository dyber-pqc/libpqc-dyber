/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Galois field GF(2^m) arithmetic.
 *
 * Supports m=12 (for mceliece348864) and m=13 (for all others).
 * Uses log/antilog tables for multiplication, with irreducible polynomials:
 *   m=12: x^12 + x^6 + x^4 + x + 1  (0x1053)
 *   m=13: x^13 + x^4 + x^3 + x + 1  (0x201B)
 */

#include <string.h>
#include "mceliece.h"

/* ------------------------------------------------------------------ */
/* Irreducible polynomials over GF(2)                                  */
/* ------------------------------------------------------------------ */

#define GF12_POLY  0x1053u   /* x^12 + x^6 + x^4 + x + 1 */
#define GF13_POLY  0x201Bu   /* x^13 + x^4 + x^3 + x + 1 */

/* ------------------------------------------------------------------ */
/* Log/exp tables: indexed by m (12 or 13)                             */
/* ------------------------------------------------------------------ */

static uint16_t gf_log_table[2][MCELIECE_MAX_FIELD];
static uint16_t gf_exp_table[2][2 * MCELIECE_MAX_FIELD];
static int gf_tables_init[2] = {0, 0};

static int m_to_idx(int m)
{
    return (m == 12) ? 0 : 1;
}

/*
 * Build log and exp (antilog) tables for GF(2^m).
 */
void gf_init_tables(int m)
{
    int idx = m_to_idx(m);
    uint32_t poly = (m == 12) ? GF12_POLY : GF13_POLY;
    int field_size = 1 << m;
    uint32_t a = 1;

    if (gf_tables_init[idx])
        return;

    memset(gf_log_table[idx], 0, sizeof(gf_log_table[idx]));
    memset(gf_exp_table[idx], 0, sizeof(gf_exp_table[idx]));

    for (int i = 0; i < field_size - 1; i++) {
        gf_exp_table[idx][i] = (uint16_t)a;
        gf_log_table[idx][a] = (uint16_t)i;
        a <<= 1;
        if (a & (uint32_t)field_size)
            a ^= poly;
    }

    /* Extend exp table for easy modular reduction */
    for (int i = field_size - 1; i < 2 * field_size; i++) {
        gf_exp_table[idx][i] = gf_exp_table[idx][i - (field_size - 1)];
    }

    gf_tables_init[idx] = 1;
}

/* ------------------------------------------------------------------ */
/* GF(2^m) operations                                                  */
/* ------------------------------------------------------------------ */

gf_t gf_add(gf_t a, gf_t b)
{
    return a ^ b;
}

gf_t gf_mul(gf_t a, gf_t b, int m)
{
    int idx = m_to_idx(m);

    if (a == 0 || b == 0)
        return 0;

    int la = gf_log_table[idx][a];
    int lb = gf_log_table[idx][b];

    return gf_exp_table[idx][la + lb];
}

gf_t gf_sq(gf_t a, int m)
{
    return gf_mul(a, a, m);
}

gf_t gf_inv(gf_t a, int m)
{
    int idx = m_to_idx(m);
    int field_size = 1 << m;

    if (a == 0)
        return 0; /* undefined, but handle gracefully */

    int la = gf_log_table[idx][a];
    return gf_exp_table[idx][(field_size - 1) - la];
}

gf_t gf_sqrt(gf_t a, int m)
{
    int idx = m_to_idx(m);
    int field_size = 1 << m;

    if (a == 0)
        return 0;

    /*
     * In GF(2^m), sqrt(a) = a^(2^(m-1)).
     * Using log/exp: log(sqrt(a)) = log(a) * 2^(m-1) mod (field_size - 1).
     */
    int la = gf_log_table[idx][a];
    int half = field_size >> 1;  /* 2^(m-1) */
    int result_log = (int)(((uint32_t)la * (uint32_t)half) % (uint32_t)(field_size - 1));
    return gf_exp_table[idx][result_log];
}

gf_t gf_frac(gf_t num, gf_t den, int m)
{
    return gf_mul(num, gf_inv(den, m), m);
}
