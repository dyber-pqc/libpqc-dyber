/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial operations for ML-KEM (FIPS 203).
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#include <stdint.h>
#include <string.h>
#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/poly.h"
#include "core/kem/mlkem/ntt.h"
#include "core/kem/mlkem/reduce.h"
#include "core/kem/mlkem/cbd.h"
#include "core/kem/mlkem/verify.h"
#include "core/common/hash/sha3.h"

/*************************************************
* Name:        pqc_mlkem_poly_compress
*
* Description: Compression and subsequent serialization of a polynomial.
*              Uses the reference's optimized constant-time compression.
*
* Arguments:   - uint8_t *r: pointer to output byte array
*              - const pqc_mlkem_poly *a: pointer to input polynomial
*              - unsigned int d: compression bits (4, 5, 10, or 11)
**************************************************/
void pqc_mlkem_poly_compress(uint8_t *r,
                              const pqc_mlkem_poly *a,
                              unsigned int d)
{
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];

    if (d == 4) {
        /* KYBER_POLYCOMPRESSEDBYTES == 128 case */
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                /* map to positive standard representatives */
                u  = a->coeffs[8 * i + j];
                u += (u >> 15) & PQC_MLKEM_Q;
                d0 = u << 4;
                d0 += 1665;
                d0 *= 80635;
                d0 >>= 28;
                t[j] = d0 & 0xf;
            }

            r[0] = t[0] | (t[1] << 4);
            r[1] = t[2] | (t[3] << 4);
            r[2] = t[4] | (t[5] << 4);
            r[3] = t[6] | (t[7] << 4);
            r += 4;
        }
    } else if (d == 5) {
        /* KYBER_POLYCOMPRESSEDBYTES == 160 case */
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                /* map to positive standard representatives */
                u  = a->coeffs[8 * i + j];
                u += (u >> 15) & PQC_MLKEM_Q;
                d0 = u << 5;
                d0 += 1664;
                d0 *= 40318;
                d0 >>= 27;
                t[j] = d0 & 0x1f;
            }

            r[0] = (t[0] >> 0) | (t[1] << 5);
            r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[2] = (t[3] >> 1) | (t[4] << 4);
            r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[4] = (t[6] >> 2) | (t[7] << 3);
            r += 5;
        }
    } else if (d == 10) {
        /* polyvec compress, du=10 */
        uint16_t t16[4];
        uint64_t d064;
        for (i = 0; i < PQC_MLKEM_N / 4; i++) {
            for (j = 0; j < 4; j++) {
                u  = a->coeffs[4 * i + j];
                u += ((int16_t)u >> 15) & PQC_MLKEM_Q;
                d064 = u;
                d064 <<= 10;
                d064 += 1665;
                d064 *= 1290167;
                d064 >>= 32;
                t16[j] = d064 & 0x3ff;
            }

            r[0] = (t16[0] >> 0);
            r[1] = (t16[0] >> 8) | (t16[1] << 2);
            r[2] = (t16[1] >> 6) | (t16[2] << 4);
            r[3] = (t16[2] >> 4) | (t16[3] << 6);
            r[4] = (t16[3] >> 2);
            r += 5;
        }
    } else { /* d == 11 */
        /* polyvec compress, du=11 */
        uint16_t t16[8];
        uint64_t d064;
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                u  = a->coeffs[8 * i + j];
                u += ((int16_t)u >> 15) & PQC_MLKEM_Q;
                d064 = u;
                d064 <<= 11;
                d064 += 1664;
                d064 *= 645084;
                d064 >>= 31;
                t16[j] = d064 & 0x7ff;
            }

            r[ 0] = (t16[0] >>  0);
            r[ 1] = (t16[0] >>  8) | (t16[1] << 3);
            r[ 2] = (t16[1] >>  5) | (t16[2] << 6);
            r[ 3] = (t16[2] >>  2);
            r[ 4] = (t16[2] >> 10) | (t16[3] << 1);
            r[ 5] = (t16[3] >>  7) | (t16[4] << 4);
            r[ 6] = (t16[4] >>  4) | (t16[5] << 7);
            r[ 7] = (t16[5] >>  1);
            r[ 8] = (t16[5] >>  9) | (t16[6] << 2);
            r[ 9] = (t16[6] >>  6) | (t16[7] << 5);
            r[10] = (t16[7] >>  3);
            r += 11;
        }
    }
}

/*************************************************
* Name:        pqc_mlkem_poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of pqc_mlkem_poly_compress
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*              - unsigned int d: compression bits (4, 5, 10, or 11)
**************************************************/
void pqc_mlkem_poly_decompress(pqc_mlkem_poly *r,
                                const uint8_t *a,
                                unsigned int d)
{
    unsigned int i;

    if (d == 4) {
        /* KYBER_POLYCOMPRESSEDBYTES == 128 case */
        for (i = 0; i < PQC_MLKEM_N / 2; i++) {
            r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * PQC_MLKEM_Q) + 8) >> 4;
            r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * PQC_MLKEM_Q) + 8) >> 4;
            a += 1;
        }
    } else if (d == 5) {
        /* KYBER_POLYCOMPRESSEDBYTES == 160 case */
        unsigned int j;
        uint8_t t[8];
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            t[0] = (a[0] >> 0);
            t[1] = (a[0] >> 5) | (a[1] << 3);
            t[2] = (a[1] >> 2);
            t[3] = (a[1] >> 7) | (a[2] << 1);
            t[4] = (a[2] >> 4) | (a[3] << 4);
            t[5] = (a[3] >> 1);
            t[6] = (a[3] >> 6) | (a[4] << 2);
            t[7] = (a[4] >> 3);
            a += 5;

            for (j = 0; j < 8; j++)
                r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 31) * PQC_MLKEM_Q + 16) >> 5;
        }
    } else if (d == 10) {
        /* polyvec decompress, du=10 */
        unsigned int j;
        uint16_t t16[4];
        for (i = 0; i < PQC_MLKEM_N / 4; i++) {
            t16[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
            t16[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
            t16[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
            t16[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;

            for (j = 0; j < 4; j++)
                r->coeffs[4 * i + j] = ((uint32_t)(t16[j] & 0x3FF) * PQC_MLKEM_Q + 512) >> 10;
        }
    } else { /* d == 11 */
        /* polyvec decompress, du=11 */
        unsigned int j;
        uint16_t t16[8];
        for (i = 0; i < PQC_MLKEM_N / 8; i++) {
            t16[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
            t16[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
            t16[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
            t16[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
            t16[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
            t16[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
            t16[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
            t16[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
            a += 11;

            for (j = 0; j < 8; j++)
                r->coeffs[8 * i + j] = ((uint32_t)(t16[j] & 0x7FF) * PQC_MLKEM_Q + 1024) >> 11;
        }
    }
}

/*************************************************
* Name:        pqc_mlkem_poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for PQC_MLKEM_POLYBYTES bytes)
*              - const pqc_mlkem_poly *a: pointer to input polynomial
**************************************************/
void pqc_mlkem_poly_tobytes(uint8_t r[PQC_MLKEM_POLYBYTES],
                             const pqc_mlkem_poly *a)
{
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < PQC_MLKEM_N / 2; i++) {
        /* map to positive standard representatives */
        t0  = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & PQC_MLKEM_Q;
        t1 = a->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & PQC_MLKEM_Q;
        r[3 * i + 0] = (t0 >> 0);
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = (t1 >> 4);
    }
}

/*************************************************
* Name:        pqc_mlkem_poly_frombytes
*
* Description: De-serialization of a polynomial;
*              inverse of pqc_mlkem_poly_tobytes
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of PQC_MLKEM_POLYBYTES bytes)
**************************************************/
void pqc_mlkem_poly_frombytes(pqc_mlkem_poly *r,
                               const uint8_t a[PQC_MLKEM_POLYBYTES])
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N / 2; i++) {
        r->coeffs[2 * i]     = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

/*************************************************
* Name:        pqc_mlkem_poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void pqc_mlkem_poly_frommsg(pqc_mlkem_poly *r,
                             const uint8_t msg[PQC_MLKEM_SYMBYTES])
{
    unsigned int i, j;

    for (i = 0; i < PQC_MLKEM_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = 0;
            pqc_mlkem_cmov_int16(r->coeffs + 8 * i + j,
                                  ((PQC_MLKEM_Q + 1) / 2),
                                  (msg[i] >> j) & 1);
        }
    }
}

/*************************************************
* Name:        pqc_mlkem_poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const pqc_mlkem_poly *a: pointer to input polynomial
**************************************************/
void pqc_mlkem_poly_tomsg(uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const pqc_mlkem_poly *a)
{
    unsigned int i, j;
    uint32_t t;

    for (i = 0; i < PQC_MLKEM_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t  = a->coeffs[8 * i + j];
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
* Name:        pqc_mlkem_poly_getnoise_eta1
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter eta1
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*              - uint8_t nonce: one-byte input nonce
*              - unsigned int eta1: CBD parameter (2 or 3)
**************************************************/
void pqc_mlkem_poly_getnoise_eta1(pqc_mlkem_poly *r,
                                    const uint8_t seed[PQC_MLKEM_SYMBYTES],
                                    uint8_t nonce,
                                    unsigned int eta1)
{
    uint8_t buf[3 * PQC_MLKEM_N / 4]; /* max: eta1=3 -> 192 bytes */
    uint8_t extkey[PQC_MLKEM_SYMBYTES + 1];
    size_t buflen = eta1 * PQC_MLKEM_N / 4;

    memcpy(extkey, seed, PQC_MLKEM_SYMBYTES);
    extkey[PQC_MLKEM_SYMBYTES] = nonce;

    pqc_shake256(buf, buflen, extkey, PQC_MLKEM_SYMBYTES + 1);
    pqc_mlkem_cbd_eta(r, buf, eta1);
}

/*************************************************
* Name:        pqc_mlkem_poly_getnoise_eta2
*
* Description: Sample a polynomial deterministically from a seed and a nonce,
*              with output polynomial close to centered binomial distribution
*              with parameter eta2 (always 2)
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *seed: pointer to input seed
*              - uint8_t nonce: one-byte input nonce
**************************************************/
void pqc_mlkem_poly_getnoise_eta2(pqc_mlkem_poly *r,
                                    const uint8_t seed[PQC_MLKEM_SYMBYTES],
                                    uint8_t nonce)
{
    uint8_t buf[2 * PQC_MLKEM_N / 4]; /* eta2=2 -> 128 bytes */
    uint8_t extkey[PQC_MLKEM_SYMBYTES + 1];

    memcpy(extkey, seed, PQC_MLKEM_SYMBYTES);
    extkey[PQC_MLKEM_SYMBYTES] = nonce;

    pqc_shake256(buf, sizeof(buf), extkey, PQC_MLKEM_SYMBYTES + 1);
    pqc_mlkem_cbd2(r, buf);
}

/*************************************************
* Name:        pqc_mlkem_poly_ntt
*
* Description: Computes negacyclic number-theoretic transform (NTT) of
*              a polynomial in place;
*              inputs assumed to be in normal order, output in bitreversed order
*
* Arguments:   - pqc_mlkem_poly *r: pointer to in/output polynomial
**************************************************/
void pqc_mlkem_poly_ntt(pqc_mlkem_poly *r)
{
    pqc_mlkem_ntt(r->coeffs);
    pqc_mlkem_poly_reduce(r);
}

/*************************************************
* Name:        pqc_mlkem_poly_invntt
*
* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
*              of a polynomial in place;
*              inputs assumed to be in bitreversed order, output in normal order
*
* Arguments:   - pqc_mlkem_poly *r: pointer to in/output polynomial
**************************************************/
void pqc_mlkem_poly_invntt(pqc_mlkem_poly *r)
{
    pqc_mlkem_invntt(r->coeffs);
}

/*************************************************
* Name:        pqc_mlkem_poly_basemul_montgomery
*
* Description: Multiplication of two polynomials in NTT domain
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const pqc_mlkem_poly *a: pointer to first input polynomial
*              - const pqc_mlkem_poly *b: pointer to second input polynomial
**************************************************/
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

/*************************************************
* Name:        pqc_mlkem_poly_tomont
*
* Description: Inplace conversion of all coefficients of a polynomial
*              from normal domain to Montgomery domain
*
* Arguments:   - pqc_mlkem_poly *r: pointer to input/output polynomial
**************************************************/
void pqc_mlkem_poly_tomont(pqc_mlkem_poly *r)
{
    unsigned int i;
    const int16_t f = (int16_t)((1ULL << 32) % PQC_MLKEM_Q);
    for (i = 0; i < PQC_MLKEM_N; i++)
        r->coeffs[i] = pqc_mlkem_montgomery_reduce((int32_t)r->coeffs[i] * f);
}

/*************************************************
* Name:        pqc_mlkem_poly_reduce
*
* Description: Applies Barrett reduction to all coefficients of a polynomial
*
* Arguments:   - pqc_mlkem_poly *r: pointer to input/output polynomial
**************************************************/
void pqc_mlkem_poly_reduce(pqc_mlkem_poly *r)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N; i++)
        r->coeffs[i] = pqc_mlkem_barrett_reduce(r->coeffs[i]);
}

/*************************************************
* Name:        pqc_mlkem_poly_add
*
* Description: Add two polynomials; no modular reduction is performed
*
* Arguments: - pqc_mlkem_poly *r: pointer to output polynomial
*            - const pqc_mlkem_poly *a: pointer to first input polynomial
*            - const pqc_mlkem_poly *b: pointer to second input polynomial
**************************************************/
void pqc_mlkem_poly_add(pqc_mlkem_poly *r,
                         const pqc_mlkem_poly *a,
                         const pqc_mlkem_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
* Name:        pqc_mlkem_poly_sub
*
* Description: Subtract two polynomials; no modular reduction is performed
*
* Arguments: - pqc_mlkem_poly *r: pointer to output polynomial
*            - const pqc_mlkem_poly *a: pointer to first input polynomial
*            - const pqc_mlkem_poly *b: pointer to second input polynomial
**************************************************/
void pqc_mlkem_poly_sub(pqc_mlkem_poly *r,
                         const pqc_mlkem_poly *a,
                         const pqc_mlkem_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLKEM_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
