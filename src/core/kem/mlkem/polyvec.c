/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial vector operations for ML-KEM (FIPS 203).
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#include <stdint.h>
#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/poly.h"
#include "core/kem/mlkem/polyvec.h"

/*************************************************
* Name:        pqc_mlkem_polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*              - const pqc_mlkem_polyvec *a: pointer to input vector of polynomials
*              - unsigned int k: number of polynomials in vector
*              - unsigned int d: compression bits per coefficient
**************************************************/
void pqc_mlkem_polyvec_compress(uint8_t *r,
                                 const pqc_mlkem_polyvec *a,
                                 unsigned int k,
                                 unsigned int d)
{
    unsigned int i;
    size_t poly_compressed = (size_t)(PQC_MLKEM_N * d) / 8;

    for (i = 0; i < k; i++)
        pqc_mlkem_poly_compress(r + i * poly_compressed, &a->vec[i], d);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of pqc_mlkem_polyvec_compress
*
* Arguments:   - pqc_mlkem_polyvec *r: pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*              - unsigned int k: number of polynomials in vector
*              - unsigned int d: compression bits per coefficient
**************************************************/
void pqc_mlkem_polyvec_decompress(pqc_mlkem_polyvec *r,
                                   const uint8_t *a,
                                   unsigned int k,
                                   unsigned int d)
{
    unsigned int i;
    size_t poly_compressed = (size_t)(PQC_MLKEM_N * d) / 8;

    for (i = 0; i < k; i++)
        pqc_mlkem_poly_decompress(&r->vec[i], a + i * poly_compressed, d);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*              - const pqc_mlkem_polyvec *a: pointer to input vector of polynomials
*              - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_tobytes(uint8_t *r,
                                const pqc_mlkem_polyvec *a,
                                unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_tobytes(r + i * PQC_MLKEM_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of pqc_mlkem_polyvec_tobytes
*
* Arguments:   - pqc_mlkem_polyvec *r: pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*              - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_frombytes(pqc_mlkem_polyvec *r,
                                  const uint8_t *a,
                                  unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_frombytes(&r->vec[i], a + i * PQC_MLKEM_POLYBYTES);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - pqc_mlkem_polyvec *r: pointer to in/output vector of polynomials
*              - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_ntt(pqc_mlkem_polyvec *r, unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_invntt
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - pqc_mlkem_polyvec *r: pointer to in/output vector of polynomials
*              - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_invntt(pqc_mlkem_polyvec *r, unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_invntt(&r->vec[i]);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - pqc_mlkem_poly *r: pointer to output polynomial
*            - const pqc_mlkem_polyvec *a: pointer to first input vector of polynomials
*            - const pqc_mlkem_polyvec *b: pointer to second input vector of polynomials
*            - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_basemul_acc_montgomery(pqc_mlkem_poly *r,
                                               const pqc_mlkem_polyvec *a,
                                               const pqc_mlkem_polyvec *b,
                                               unsigned int k)
{
    unsigned int i;
    pqc_mlkem_poly t;

    pqc_mlkem_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < k; i++) {
        pqc_mlkem_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        pqc_mlkem_poly_add(r, r, &t);
    }

    pqc_mlkem_poly_reduce(r);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials
*
* Arguments:   - pqc_mlkem_polyvec *r: pointer to input/output polynomial
*              - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_reduce(pqc_mlkem_polyvec *r, unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        pqc_mlkem_polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - pqc_mlkem_polyvec *r: pointer to output vector of polynomials
*            - const pqc_mlkem_polyvec *a: pointer to first input vector of polynomials
*            - const pqc_mlkem_polyvec *b: pointer to second input vector of polynomials
*            - unsigned int k: number of polynomials in vector
**************************************************/
void pqc_mlkem_polyvec_add(pqc_mlkem_polyvec *r,
                            const pqc_mlkem_polyvec *a,
                            const pqc_mlkem_polyvec *b,
                            unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
