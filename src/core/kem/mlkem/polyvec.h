/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial vector operations for ML-KEM (FIPS 203).
 * A polyvec is a vector of k polynomials (k in {2,3,4}).
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#ifndef PQC_MLKEM_POLYVEC_H
#define PQC_MLKEM_POLYVEC_H

#include <stddef.h>
#include <stdint.h>

#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/poly.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Polynomial vector type                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    pqc_mlkem_poly vec[PQC_MLKEM_K_MAX];
} pqc_mlkem_polyvec;

/* ------------------------------------------------------------------ */
/*  Compression / decompression                                         */
/* ------------------------------------------------------------------ */

void pqc_mlkem_polyvec_compress(uint8_t *r,
                                 const pqc_mlkem_polyvec *a,
                                 unsigned int k,
                                 unsigned int d);

void pqc_mlkem_polyvec_decompress(pqc_mlkem_polyvec *r,
                                   const uint8_t *a,
                                   unsigned int k,
                                   unsigned int d);

/* ------------------------------------------------------------------ */
/*  Serialisation (uncompressed, 12-bit encoding)                       */
/* ------------------------------------------------------------------ */

void pqc_mlkem_polyvec_tobytes(uint8_t *r,
                                const pqc_mlkem_polyvec *a,
                                unsigned int k);

void pqc_mlkem_polyvec_frombytes(pqc_mlkem_polyvec *r,
                                  const uint8_t *a,
                                  unsigned int k);

/* ------------------------------------------------------------------ */
/*  NTT domain conversions                                              */
/* ------------------------------------------------------------------ */

void pqc_mlkem_polyvec_ntt(pqc_mlkem_polyvec *r, unsigned int k);
void pqc_mlkem_polyvec_invntt(pqc_mlkem_polyvec *r, unsigned int k);

/* ------------------------------------------------------------------ */
/*  Arithmetic                                                          */
/* ------------------------------------------------------------------ */

/** Inner product of two polyvecs in NTT domain: r = sum(a[i] * b[i]). */
void pqc_mlkem_polyvec_basemul_acc_montgomery(pqc_mlkem_poly *r,
                                               const pqc_mlkem_polyvec *a,
                                               const pqc_mlkem_polyvec *b,
                                               unsigned int k);

void pqc_mlkem_polyvec_reduce(pqc_mlkem_polyvec *r, unsigned int k);

void pqc_mlkem_polyvec_add(pqc_mlkem_polyvec *r,
                            const pqc_mlkem_polyvec *a,
                            const pqc_mlkem_polyvec *b,
                            unsigned int k);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_POLYVEC_H */
