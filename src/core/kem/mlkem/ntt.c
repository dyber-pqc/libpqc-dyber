/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Number Theoretic Transform for ML-KEM (FIPS 203).
 *
 * q = 3329, primitive 256th root of unity zeta = 17.
 * Twiddle factors are stored in Montgomery form (multiplied by 2^16 mod q).
 * The table is indexed in bit-reversed order as required by the
 * Cooley-Tukey (forward) and Gentleman-Sande (inverse) butterflies.
 */

#include "core/kem/mlkem/ntt.h"
#include "core/kem/mlkem/reduce.h"

/*
 * Precomputed zetas[i] = (17^{BitRev_7(i)}) * 2^16  (mod q)
 * for i in 0..127.  zetas[0] is unused by convention (the first
 * butterfly layer uses zetas[1] onward).
 *
 * Generated from the FIPS 203 specification, Table 2.
 */
const int16_t pqc_mlkem_zetas[128] = {
     2285,  2571,  2970,  1812,  1493,  1422,   287,   202,
     3158,   622,  1577,   182,   962,  2127,  1855,  1468,
      573,  2004,   264,   383,  2500,  1458,  1727,  3199,
     2648,  1017,   732,   608,  1787,   411,  3124,  1758,
     1223,   652,  2777,  1015,  2036,  1491,  3047,  1785,
      516,  3321,  3009,  2663,  1711,  2167,   126,  1469,
     2476,  3239,  3058,   830,   107,  1908,  3082,  2378,
     2931,   961,  1821,  2604,   448,  2264,   677,  2054,
     2226,   430,   555,   843,  2078,   871,  1550,   105,
      422,   587,   177,  3094,  3038,  2869,  1574,  1653,
     3083,   778,  1159,  3182,  2552,  1483,  2727,  1119,
     1739,   644,  2457,   349,   418,   329,  3173,  3254,
      817,  1097,   603,   610,  1322,  2044,  1864,   384,
     2114,  3193,  1218,  1994,  2455,   220,  2142,  1670,
     2144,  1799,  2051,   794,  1819,  2475,  2459,   478,
     3221,  3116,   756,  2504,   199,  2648,   139,  1063
};

/* ------------------------------------------------------------------ */
/*  Butterfly helpers (signed 16-bit, Montgomery multiply)              */
/* ------------------------------------------------------------------ */

static int16_t fqmul(int16_t a, int16_t b)
{
    return pqc_mlkem_montgomery_reduce((int32_t)a * b);
}

/* ------------------------------------------------------------------ */
/*  Forward NTT (Cooley-Tukey, decimation-in-time)                      */
/* ------------------------------------------------------------------ */

void pqc_mlkem_ntt(int16_t r[256])
{
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = pqc_mlkem_zetas[k++];
            for (j = start; j < start + len; j++) {
                t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j]       = r[j] + t;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Inverse NTT (Gentleman-Sande, decimation-in-frequency)              */
/* ------------------------------------------------------------------ */

void pqc_mlkem_invntt(int16_t r[256])
{
    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441; /* 128^{-1} * 2^16 mod q */

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = pqc_mlkem_zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j]       = pqc_mlkem_barrett_reduce(t + r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len] - t);
            }
        }
    }

    for (j = 0; j < 256; j++) {
        r[j] = fqmul(r[j], f);
    }
}

/* ------------------------------------------------------------------ */
/*  Base-case multiplication (degree-1 polynomial product)              */
/* ------------------------------------------------------------------ */

void pqc_mlkem_basemul(int16_t r[2],
                        const int16_t a[2],
                        const int16_t b[2],
                        int16_t zeta)
{
    r[0]  = fqmul(a[1], b[1]);
    r[0]  = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);

    r[1]  = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
