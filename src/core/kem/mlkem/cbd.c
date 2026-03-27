/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Centered Binomial Distribution sampling for ML-KEM (FIPS 203).
 *
 * CBD_eta(B) produces a polynomial whose coefficients are in
 * {-eta, ..., eta}, sampled from 2*eta bits each.
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#include <stdint.h>
#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/cbd.h"

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4])
{
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order.
*              This function is only needed for Kyber-512 (eta1=3)
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
static uint32_t load24_littleendian(const uint8_t x[3])
{
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}

/*************************************************
* Name:        pqc_mlkem_cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
void pqc_mlkem_cbd2(pqc_mlkem_poly *r, const uint8_t buf[128])
{
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < PQC_MLKEM_N / 8; i++) {
        t  = load32_littleendian(buf + 4 * i);
        d  = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++) {
            a = (d >> (4 * j + 0)) & 0x3;
            b = (d >> (4 * j + 2)) & 0x3;
            r->coeffs[8 * i + j] = a - b;
        }
    }
}

/*************************************************
* Name:        pqc_mlkem_cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3.
*              This function is only needed for ML-KEM-512
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
void pqc_mlkem_cbd3(pqc_mlkem_poly *r, const uint8_t buf[192])
{
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < PQC_MLKEM_N / 4; i++) {
        t  = load24_littleendian(buf + 3 * i);
        d  = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; j++) {
            a = (d >> (6 * j + 0)) & 0x7;
            b = (d >> (6 * j + 3)) & 0x7;
            r->coeffs[4 * i + j] = a - b;
        }
    }
}

/*************************************************
* Name:        pqc_mlkem_cbd_eta
*
* Description: Dispatch to cbd2 or cbd3 based on eta parameter.
*
* Arguments:   - pqc_mlkem_poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
*              - unsigned int eta: CBD parameter (2 or 3)
**************************************************/
void pqc_mlkem_cbd_eta(pqc_mlkem_poly *r, const uint8_t *buf, unsigned int eta)
{
    if (eta == 2) {
        pqc_mlkem_cbd2(r, buf);
    } else { /* eta == 3 */
        pqc_mlkem_cbd3(r, buf);
    }
}
