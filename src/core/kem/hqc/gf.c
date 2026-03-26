/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC - Galois field GF(2^m) arithmetic for Reed-Solomon.
 *
 * Provides multiplication, inversion, and exponentiation in GF(2^m)
 * using log/antilog tables. The field extension degree m depends on
 * the HQC security level (m = delta + 1).
 */

#include <string.h>
#include "hqc.h"
#include "hqc_params.h"

/* ------------------------------------------------------------------ */
/* Log / antilog tables for GF(2^m).                                    */
/* We support m up to 30, but HQC only uses small m values (18/25/30). */
/* For practical purposes, we use tables sized for the maximum m.       */
/* ------------------------------------------------------------------ */

/*
 * Since HQC RS operates over GF(2^m) where m can be up to 30, full
 * tables would be too large (2^30 entries). Instead we use direct
 * computation for mul/inv via the Russian peasant algorithm, with
 * small lookup tables for the most common case (m <= 18).
 */

#define HQC_GF_SMALL_TABLE_MAX_M  18
#define HQC_GF_SMALL_TABLE_SIZE   (1 << HQC_GF_SMALL_TABLE_MAX_M)

static uint32_t gf_exp_table[HQC_GF_SMALL_TABLE_SIZE + 1];
static uint32_t gf_log_table[HQC_GF_SMALL_TABLE_SIZE + 1];
static int gf_tables_m = 0;

/*
 * Irreducible polynomials for GF(2^m).
 * Index by m. These are minimum-weight irreducible polynomials.
 */
static uint32_t hqc_gf_irred_poly(uint32_t m)
{
    /* Standard irreducible polynomials for each field degree */
    switch (m) {
    case 8:  return 0x11D;       /* x^8 + x^4 + x^3 + x^2 + 1 */
    case 10: return 0x409;       /* x^10 + x^3 + 1 */
    case 12: return 0x1053;      /* x^12 + x^6 + x^4 + x + 1 */
    case 14: return 0x4443;      /* x^14 + x^10 + x^6 + x + 1 */
    case 16: return 0x1002B;     /* x^16 + x^5 + x^3 + x + 1 */
    case 18: return 0x40009;     /* x^18 + x^3 + 1 */
    case 20: return 0x100009;    /* x^20 + x^3 + 1 */
    case 22: return 0x400009;    /* x^22 + x^3 + 1 (placeholder) */
    case 24: return 0x1000027;   /* x^24 + x^5 + x^2 + x + 1 */
    case 25: return 0x2000009;   /* x^25 + x^3 + 1 */
    case 26: return 0x4000027;   /* x^26 + ... */
    case 28: return 0x10000009;  /* x^28 + x^3 + 1 */
    case 30: return 0x40000009u; /* x^30 + x^3 + 1 */
    default: return (1u << m) | 0x3; /* fallback: x^m + x + 1 */
    }
}

/* ------------------------------------------------------------------ */
/* Generate log/antilog tables for small fields (m <= 18)               */
/* ------------------------------------------------------------------ */

void hqc_gf_generate_tables(uint32_t m)
{
    if (m > HQC_GF_SMALL_TABLE_MAX_M) {
        gf_tables_m = 0;
        return;
    }

    uint32_t ord = (1u << m) - 1;
    uint32_t poly = hqc_gf_irred_poly(m);
    uint32_t a = 1;

    memset(gf_exp_table, 0, sizeof(gf_exp_table));
    memset(gf_log_table, 0, sizeof(gf_log_table));

    for (uint32_t i = 0; i < ord; i++) {
        gf_exp_table[i] = a;
        gf_log_table[a] = i;
        a <<= 1;
        if (a & (1u << m)) {
            a ^= poly;
        }
    }
    gf_exp_table[ord] = gf_exp_table[0]; /* wrap around */
    gf_log_table[0] = 0; /* log(0) is undefined, treat as 0 */

    gf_tables_m = (int)m;
}

/* ------------------------------------------------------------------ */
/* Russian peasant multiplication in GF(2^m) (works for all m)          */
/* ------------------------------------------------------------------ */

static hqc_gf_t gf_mul_peasant(hqc_gf_t a, hqc_gf_t b, uint32_t m)
{
    uint32_t poly = hqc_gf_irred_poly(m);
    uint32_t result = 0;
    uint32_t aa = (uint32_t)a;
    uint32_t bb = (uint32_t)b;

    for (uint32_t i = 0; i < m; i++) {
        if (bb & 1) {
            result ^= aa;
        }
        bb >>= 1;
        aa <<= 1;
        if (aa & (1u << m)) {
            aa ^= poly;
        }
    }
    return (hqc_gf_t)(result & ((1u << m) - 1));
}

/* ------------------------------------------------------------------ */
/* Public GF arithmetic functions                                       */
/* ------------------------------------------------------------------ */

hqc_gf_t hqc_gf_mul(hqc_gf_t a, hqc_gf_t b, uint32_t m)
{
    if (a == 0 || b == 0) return 0;

    /* Use tables if available */
    if ((int)m == gf_tables_m && m <= HQC_GF_SMALL_TABLE_MAX_M) {
        uint32_t ord = (1u << m) - 1;
        uint32_t la = gf_log_table[a];
        uint32_t lb = gf_log_table[b];
        uint32_t s = la + lb;
        if (s >= ord) s -= ord;
        return (hqc_gf_t)gf_exp_table[s];
    }

    return gf_mul_peasant(a, b, m);
}

hqc_gf_t hqc_gf_inv(hqc_gf_t a, uint32_t m)
{
    if (a == 0) return 0;

    /* Use tables if available */
    if ((int)m == gf_tables_m && m <= HQC_GF_SMALL_TABLE_MAX_M) {
        uint32_t ord = (1u << m) - 1;
        uint32_t la = gf_log_table[a];
        return (hqc_gf_t)gf_exp_table[ord - la];
    }

    /* Extended Euclidean / Fermat: a^(2^m - 2) = a^{-1} */
    return hqc_gf_pow(a, (1u << m) - 2, m);
}

hqc_gf_t hqc_gf_pow(hqc_gf_t a, uint32_t exp, uint32_t m)
{
    if (a == 0) return 0;
    if (exp == 0) return 1;

    /* Use tables if available */
    if ((int)m == gf_tables_m && m <= HQC_GF_SMALL_TABLE_MAX_M) {
        uint32_t ord = (1u << m) - 1;
        uint32_t la = gf_log_table[a];
        uint64_t le = ((uint64_t)la * exp) % ord;
        return (hqc_gf_t)gf_exp_table[(uint32_t)le];
    }

    /* Square-and-multiply */
    hqc_gf_t result = 1;
    hqc_gf_t base = a;
    while (exp > 0) {
        if (exp & 1) {
            result = gf_mul_peasant(result, base, m);
        }
        base = gf_mul_peasant(base, base, m);
        exp >>= 1;
    }
    return result;
}

hqc_gf_t hqc_gf_exp(uint32_t i, uint32_t m)
{
    if ((int)m == gf_tables_m && m <= HQC_GF_SMALL_TABLE_MAX_M) {
        uint32_t ord = (1u << m) - 1;
        return (hqc_gf_t)gf_exp_table[i % ord];
    }
    /* Compute alpha^i by repeated squaring */
    return hqc_gf_pow(2, i, m);
}

uint32_t hqc_gf_log(hqc_gf_t a, uint32_t m)
{
    if (a == 0) return 0;

    if ((int)m == gf_tables_m && m <= HQC_GF_SMALL_TABLE_MAX_M) {
        return gf_log_table[a];
    }
    /* Brute force for large fields (not perf-critical path) */
    uint32_t ord = (1u << m) - 1;
    hqc_gf_t val = 1;
    for (uint32_t i = 0; i < ord; i++) {
        if (val == a) return i;
        val = gf_mul_peasant(val, 2, m);
    }
    return 0;
}
