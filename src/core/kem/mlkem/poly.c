/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial operations for ML-KEM (FIPS 203).
 */

#include <string.h>

#include "core/kem/mlkem/poly.h"
#include "core/kem/mlkem/ntt.h"
#include "core/kem/mlkem/reduce.h"

/* ================================================================= */
/*  NTT domain conversions                                             */
/* ================================================================= */

void pqc_mlkem_poly_ntt(pqc_mlkem_poly *p)
{
    pqc_mlkem_ntt(p->coeffs);
    pqc_mlkem_poly_reduce(p);
}

void pqc_mlkem_poly_invntt(pqc_mlkem_poly *p)
{
    pqc_mlkem_invntt(p->coeffs);
}

void pqc_mlkem_poly_basemul_montgomery(pqc_mlkem_poly *r,
                                        const pqc_mlkem_poly *a,
                                        const pqc_mlkem_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N / 4; i++) {
        pqc_mlkem_basemul(&r->coeffs[4 * i],
                           &a->coeffs[4 * i],
                           &b->coeffs[4 * i],
                           pqc_mlkem_zetas[64 + i]);
        pqc_mlkem_basemul(&r->coeffs[4 * i + 2],
                           &a->coeffs[4 * i + 2],
                           &b->coeffs[4 * i + 2],
                           -pqc_mlkem_zetas[64 + i]);
    }
}

void pqc_mlkem_poly_tomont(pqc_mlkem_poly *p)
{
    unsigned int i;
    const int16_t f = (1ULL << 32) % PQC_MLKEM_Q; /* 2^32 mod q = 1353 */

    for (i = 0; i < PQC_MLKEM_N; i++) {
        p->coeffs[i] = pqc_mlkem_montgomery_reduce((int32_t)p->coeffs[i] * f);
    }
}

/* ================================================================= */
/*  Arithmetic                                                         */
/* ================================================================= */

void pqc_mlkem_poly_add(pqc_mlkem_poly *r,
                         const pqc_mlkem_poly *a,
                         const pqc_mlkem_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void pqc_mlkem_poly_sub(pqc_mlkem_poly *r,
                         const pqc_mlkem_poly *a,
                         const pqc_mlkem_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

void pqc_mlkem_poly_reduce(pqc_mlkem_poly *p)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N; i++) {
        p->coeffs[i] = pqc_mlkem_barrett_reduce(p->coeffs[i]);
    }
}

/* ================================================================= */
/*  Serialisation (12-bit uncompressed encoding)                       */
/* ================================================================= */

/*
 * ByteEncode_12: pack 256 coefficients (each in [0, q)) into 384 bytes.
 * Two coefficients fit in three bytes.
 */
void pqc_mlkem_poly_tobytes(uint8_t buf[PQC_MLKEM_POLYBYTES],
                             const pqc_mlkem_poly *p)
{
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < PQC_MLKEM_N / 2; i++) {
        /* Ensure coefficients are in [0, q) */
        t0 = (uint16_t)p->coeffs[2 * i];
        t1 = (uint16_t)p->coeffs[2 * i + 1];

        /* Conditional addition of q for negative values */
        t0 += ((int16_t)t0 >> 15) & PQC_MLKEM_Q;
        t1 += ((int16_t)t1 >> 15) & PQC_MLKEM_Q;

        buf[3 * i + 0] = (uint8_t)(t0 >> 0);
        buf[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        buf[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

/*
 * ByteDecode_12: unpack 384 bytes into 256 coefficients.
 */
void pqc_mlkem_poly_frombytes(pqc_mlkem_poly *p,
                               const uint8_t buf[PQC_MLKEM_POLYBYTES])
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N / 2; i++) {
        p->coeffs[2 * i]     = (int16_t)(((uint16_t)buf[3 * i + 0] >> 0) |
                                          ((uint16_t)buf[3 * i + 1] << 8)) & 0xFFF;
        p->coeffs[2 * i + 1] = (int16_t)(((uint16_t)buf[3 * i + 1] >> 4) |
                                          ((uint16_t)buf[3 * i + 2] << 4)) & 0xFFF;
    }
}

/* ================================================================= */
/*  Compression / Decompression                                        */
/* ================================================================= */

/*
 * Compress: round(2^d / q * x) mod 2^d
 *         = round(x * 2^d / q) & ((1 << d) - 1)
 *
 * We compute this as: ((x << d) + q/2) / q
 */
void pqc_mlkem_poly_compress(uint8_t *buf,
                              const pqc_mlkem_poly *p,
                              unsigned int d)
{
    unsigned int i, j;
    uint16_t t[8];

    if (d == 4) {
        for (i = 0; i < PQC_MLKEM_N / 2; i++) {
            for (j = 0; j < 2; j++) {
                int16_t u = p->coeffs[2 * i + j];
                u += (u >> 15) & PQC_MLKEM_Q;
                t[j] = (uint16_t)((((uint32_t)u << 4) + PQC_MLKEM_Q / 2) / PQC_MLKEM_Q);
                t[j] &= 0xF;
            }
            buf[i] = (uint8_t)(t[0] | (t[1] << 4));
        }
    } else if (d == 5) {
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t u = p->coeffs[8 * i + j];
                u += (u >> 15) & PQC_MLKEM_Q;
                t[j] = (uint16_t)((((uint32_t)u << 5) + PQC_MLKEM_Q / 2) / PQC_MLKEM_Q);
                t[j] &= 0x1F;
            }
            buf[5 * i + 0] = (uint8_t)( t[0]       | (t[1] << 5));
            buf[5 * i + 1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            buf[5 * i + 2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
            buf[5 * i + 3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            buf[5 * i + 4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
        }
    } else if (d == 10) {
        for (i = 0; i < PQC_MLKEM_N / 4; i++) {
            for (j = 0; j < 4; j++) {
                int16_t u = p->coeffs[4 * i + j];
                u += (u >> 15) & PQC_MLKEM_Q;
                t[j] = (uint16_t)((((uint32_t)u << 10) + PQC_MLKEM_Q / 2) / PQC_MLKEM_Q);
                t[j] &= 0x3FF;
            }
            buf[5 * i + 0] = (uint8_t)(t[0] >> 0);
            buf[5 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            buf[5 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            buf[5 * i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            buf[5 * i + 4] = (uint8_t)(t[3] >> 2);
        }
    } else if (d == 11) {
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t u = p->coeffs[8 * i + j];
                u += (u >> 15) & PQC_MLKEM_Q;
                t[j] = (uint16_t)((((uint32_t)u << 11) + PQC_MLKEM_Q / 2) / PQC_MLKEM_Q);
                t[j] &= 0x7FF;
            }
            buf[11 * i +  0] = (uint8_t)(t[0] >>  0);
            buf[11 * i +  1] = (uint8_t)((t[0] >> 8) | (t[1] << 3));
            buf[11 * i +  2] = (uint8_t)((t[1] >> 5) | (t[2] << 6));
            buf[11 * i +  3] = (uint8_t)(t[2] >>  2);
            buf[11 * i +  4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
            buf[11 * i +  5] = (uint8_t)((t[3] >> 7) | (t[4] << 4));
            buf[11 * i +  6] = (uint8_t)((t[4] >> 4) | (t[5] << 7));
            buf[11 * i +  7] = (uint8_t)(t[5] >>  1);
            buf[11 * i +  8] = (uint8_t)((t[5] >> 9) | (t[6] << 2));
            buf[11 * i +  9] = (uint8_t)((t[6] >> 6) | (t[7] << 5));
            buf[11 * i + 10] = (uint8_t)(t[7] >>  3);
        }
    }
}

void pqc_mlkem_poly_decompress(pqc_mlkem_poly *p,
                                const uint8_t *buf,
                                unsigned int d)
{
    unsigned int i, j;

    if (d == 4) {
        for (i = 0; i < PQC_MLKEM_N / 2; i++) {
            p->coeffs[2 * i + 0] = (int16_t)((((uint16_t)(buf[i] & 0x0F)) * PQC_MLKEM_Q + 8) >> 4);
            p->coeffs[2 * i + 1] = (int16_t)((((uint16_t)(buf[i] >> 4))    * PQC_MLKEM_Q + 8) >> 4);
        }
    } else if (d == 5) {
        uint16_t t[8];
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            t[0] = (uint16_t)( buf[5 * i + 0] >> 0)       & 0x1F;
            t[1] = (uint16_t)((buf[5 * i + 0] >> 5) | (buf[5 * i + 1] << 3)) & 0x1F;
            t[2] = (uint16_t)( buf[5 * i + 1] >> 2)       & 0x1F;
            t[3] = (uint16_t)((buf[5 * i + 1] >> 7) | (buf[5 * i + 2] << 1)) & 0x1F;
            t[4] = (uint16_t)((buf[5 * i + 2] >> 4) | (buf[5 * i + 3] << 4)) & 0x1F;
            t[5] = (uint16_t)( buf[5 * i + 3] >> 1)       & 0x1F;
            t[6] = (uint16_t)((buf[5 * i + 3] >> 6) | (buf[5 * i + 4] << 2)) & 0x1F;
            t[7] = (uint16_t)( buf[5 * i + 4] >> 3)       & 0x1F;
            for (j = 0; j < 8; j++) {
                p->coeffs[8 * i + j] = (int16_t)(((uint32_t)t[j] * PQC_MLKEM_Q + 16) >> 5);
            }
        }
    } else if (d == 10) {
        uint16_t t[4];
        for (i = 0; i < PQC_MLKEM_N / 4; i++) {
            t[0] = (uint16_t)(( buf[5 * i + 0]       | ((uint16_t)buf[5 * i + 1] << 8))) & 0x3FF;
            t[1] = (uint16_t)(((buf[5 * i + 1] >> 2) | ((uint16_t)buf[5 * i + 2] << 6))) & 0x3FF;
            t[2] = (uint16_t)(((buf[5 * i + 2] >> 4) | ((uint16_t)buf[5 * i + 3] << 4))) & 0x3FF;
            t[3] = (uint16_t)(((buf[5 * i + 3] >> 6) | ((uint16_t)buf[5 * i + 4] << 2))) & 0x3FF;
            for (j = 0; j < 4; j++) {
                p->coeffs[4 * i + j] = (int16_t)(((uint32_t)t[j] * PQC_MLKEM_Q + 512) >> 10);
            }
        }
    } else if (d == 11) {
        uint16_t t[8];
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            t[0] = (uint16_t)(( buf[11*i+ 0]       | ((uint16_t)buf[11*i+ 1] << 8))) & 0x7FF;
            t[1] = (uint16_t)(((buf[11*i+ 1] >> 3) | ((uint16_t)buf[11*i+ 2] << 5))) & 0x7FF;
            t[2] = (uint16_t)(((buf[11*i+ 2] >> 6) | ((uint16_t)buf[11*i+ 3] << 2) | ((uint16_t)buf[11*i+4] << 10))) & 0x7FF;
            t[3] = (uint16_t)(((buf[11*i+ 4] >> 1) | ((uint16_t)buf[11*i+ 5] << 7))) & 0x7FF;
            t[4] = (uint16_t)(((buf[11*i+ 5] >> 4) | ((uint16_t)buf[11*i+ 6] << 4))) & 0x7FF;
            t[5] = (uint16_t)(((buf[11*i+ 6] >> 7) | ((uint16_t)buf[11*i+ 7] << 1) | ((uint16_t)buf[11*i+8] << 9))) & 0x7FF;
            t[6] = (uint16_t)(((buf[11*i+ 8] >> 2) | ((uint16_t)buf[11*i+ 9] << 6))) & 0x7FF;
            t[7] = (uint16_t)(((buf[11*i+ 9] >> 5) | ((uint16_t)buf[11*i+10] << 3))) & 0x7FF;
            for (j = 0; j < 8; j++) {
                p->coeffs[8 * i + j] = (int16_t)(((uint32_t)t[j] * PQC_MLKEM_Q + 1024) >> 11);
            }
        }
    }
}

/* ================================================================= */
/*  Message encoding / decoding                                        */
/* ================================================================= */

/*
 * Decode a 32-byte message into a polynomial.
 * Each bit i of the message becomes coefficient
 *   p[i] = bit * round(q/2) = bit * 1665
 */
void pqc_mlkem_poly_frommsg(pqc_mlkem_poly *p,
                             const uint8_t msg[PQC_MLKEM_SYMBYTES])
{
    unsigned int i, j;
    int16_t mask;

    for (i = 0; i < PQC_MLKEM_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            mask = -((int16_t)(msg[i] >> j) & 1);
            p->coeffs[8 * i + j] = mask & (int16_t)((PQC_MLKEM_Q + 1) / 2);
        }
    }
}

/*
 * Encode a polynomial to a 32-byte message.
 * Each coefficient is mapped to 0 or 1 based on proximity to 0 vs q/2.
 *
 * Compress_1(x) = round(2*x/q) mod 2
 */
void pqc_mlkem_poly_tomsg(uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const pqc_mlkem_poly *p)
{
    unsigned int i, j;
    uint32_t t;

    for (i = 0; i < PQC_MLKEM_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            int16_t u = p->coeffs[8 * i + j];
            u += (u >> 15) & PQC_MLKEM_Q;
            t = (((uint32_t)u << 1) + PQC_MLKEM_Q / 2) / PQC_MLKEM_Q;
            msg[i] |= (uint8_t)((t & 1) << j);
        }
    }
}
