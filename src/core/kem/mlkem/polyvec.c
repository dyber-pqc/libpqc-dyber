/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial vector operations for ML-KEM (FIPS 203).
 */

#include "core/kem/mlkem/polyvec.h"
#include "core/kem/mlkem/poly.h"

/* ================================================================= */
/*  NTT domain conversions                                             */
/* ================================================================= */

void pqc_mlkem_polyvec_ntt(pqc_mlkem_polyvec *v, unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_ntt(&v->vec[i]);
    }
}

void pqc_mlkem_polyvec_invntt(pqc_mlkem_polyvec *v, unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_invntt(&v->vec[i]);
    }
}

/* ================================================================= */
/*  Arithmetic                                                         */
/* ================================================================= */

/*
 * Inner product in NTT domain: r = sum_{i=0}^{k-1} a->vec[i] * b->vec[i]
 * Result is accumulated in Montgomery form.
 */
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

void pqc_mlkem_polyvec_add(pqc_mlkem_polyvec *r,
                            const pqc_mlkem_polyvec *a,
                            const pqc_mlkem_polyvec *b,
                            unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void pqc_mlkem_polyvec_reduce(pqc_mlkem_polyvec *v, unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_reduce(&v->vec[i]);
    }
}

/* ================================================================= */
/*  Serialisation (12-bit uncompressed)                                */
/* ================================================================= */

void pqc_mlkem_polyvec_tobytes(uint8_t *buf,
                                const pqc_mlkem_polyvec *v,
                                unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_tobytes(buf + i * PQC_MLKEM_POLYBYTES, &v->vec[i]);
    }
}

void pqc_mlkem_polyvec_frombytes(pqc_mlkem_polyvec *v,
                                  const uint8_t *buf,
                                  unsigned int k)
{
    unsigned int i;
    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_frombytes(&v->vec[i], buf + i * PQC_MLKEM_POLYBYTES);
    }
}

/* ================================================================= */
/*  Compression / Decompression                                        */
/* ================================================================= */

void pqc_mlkem_polyvec_compress(uint8_t *buf,
                                 const pqc_mlkem_polyvec *v,
                                 unsigned int k,
                                 unsigned int d)
{
    unsigned int i;
    size_t poly_compressed = (size_t)(PQC_MLKEM_N * d) / 8;

    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_compress(buf + i * poly_compressed, &v->vec[i], d);
    }
}

void pqc_mlkem_polyvec_decompress(pqc_mlkem_polyvec *v,
                                   const uint8_t *buf,
                                   unsigned int k,
                                   unsigned int d)
{
    unsigned int i;
    size_t poly_compressed = (size_t)(PQC_MLKEM_N * d) / 8;

    for (i = 0; i < k; i++) {
        pqc_mlkem_poly_decompress(&v->vec[i], buf + i * poly_compressed, d);
    }
}
