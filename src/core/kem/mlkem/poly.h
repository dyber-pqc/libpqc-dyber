/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial operations for ML-KEM (FIPS 203).
 * A polynomial is an element of Z_q[X]/(X^256 + 1).
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#ifndef PQC_MLKEM_POLY_H
#define PQC_MLKEM_POLY_H

#include <stddef.h>
#include <stdint.h>

#include "core/kem/mlkem/mlkem_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Polynomial type                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    int16_t coeffs[PQC_MLKEM_N];
} pqc_mlkem_poly;

/* ------------------------------------------------------------------ */
/*  Compression / decompression                                         */
/* ------------------------------------------------------------------ */

/**
 * Compress polynomial to d bits per coefficient and write to buf.
 * buf must be at least 256*d/8 bytes.
 * d must be one of {4, 5, 10, 11}.
 */
void pqc_mlkem_poly_compress(uint8_t *buf,
                              const pqc_mlkem_poly *p,
                              unsigned int d);

/**
 * Decompress polynomial from d-bit encoding.
 * buf must be at least 256*d/8 bytes.
 * d must be one of {4, 5, 10, 11}.
 */
void pqc_mlkem_poly_decompress(pqc_mlkem_poly *p,
                                const uint8_t *buf,
                                unsigned int d);

/* ------------------------------------------------------------------ */
/*  Serialisation (uncompressed, 12-bit encoding)                       */
/* ------------------------------------------------------------------ */

/** Encode polynomial to byte array (12 bits per coefficient). */
void pqc_mlkem_poly_tobytes(uint8_t r[PQC_MLKEM_POLYBYTES],
                             const pqc_mlkem_poly *a);

/** Decode polynomial from byte array. */
void pqc_mlkem_poly_frombytes(pqc_mlkem_poly *r,
                               const uint8_t a[PQC_MLKEM_POLYBYTES]);

/* ------------------------------------------------------------------ */
/*  Message encoding / decoding (1-bit per coefficient)                 */
/* ------------------------------------------------------------------ */

/** Decode 32-byte message to polynomial (1 bit -> coefficient). */
void pqc_mlkem_poly_frommsg(pqc_mlkem_poly *r,
                             const uint8_t msg[PQC_MLKEM_SYMBYTES]);

/** Encode polynomial to 32-byte message. */
void pqc_mlkem_poly_tomsg(uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const pqc_mlkem_poly *a);

/* ------------------------------------------------------------------ */
/*  Noise sampling                                                      */
/* ------------------------------------------------------------------ */

/**
 * Sample a polynomial deterministically from a seed and a nonce,
 * with output polynomial close to centered binomial distribution
 * with parameter eta1.
 */
void pqc_mlkem_poly_getnoise_eta1(pqc_mlkem_poly *r,
                                    const uint8_t seed[PQC_MLKEM_SYMBYTES],
                                    uint8_t nonce,
                                    unsigned int eta1);

/**
 * Sample a polynomial deterministically from a seed and a nonce,
 * with output polynomial close to centered binomial distribution
 * with parameter eta2 (always 2).
 */
void pqc_mlkem_poly_getnoise_eta2(pqc_mlkem_poly *r,
                                    const uint8_t seed[PQC_MLKEM_SYMBYTES],
                                    uint8_t nonce);

/* ------------------------------------------------------------------ */
/*  NTT domain conversions                                              */
/* ------------------------------------------------------------------ */

/** Forward NTT (in-place). */
void pqc_mlkem_poly_ntt(pqc_mlkem_poly *r);

/** Inverse NTT (in-place), with multiplication by Montgomery factor. */
void pqc_mlkem_poly_invntt(pqc_mlkem_poly *r);

/**
 * Point-wise multiplication of two NTT-domain polynomials.
 * r = a * b  (in NTT domain, Montgomery form).
 */
void pqc_mlkem_poly_basemul_montgomery(pqc_mlkem_poly *r,
                                        const pqc_mlkem_poly *a,
                                        const pqc_mlkem_poly *b);

/**
 * Multiply every coefficient by the Montgomery factor 2^16 mod q
 * to convert from normal to Montgomery domain.
 */
void pqc_mlkem_poly_tomont(pqc_mlkem_poly *r);

/* ------------------------------------------------------------------ */
/*  Arithmetic                                                          */
/* ------------------------------------------------------------------ */

/** Apply Barrett reduction to every coefficient. */
void pqc_mlkem_poly_reduce(pqc_mlkem_poly *r);

void pqc_mlkem_poly_add(pqc_mlkem_poly *r,
                         const pqc_mlkem_poly *a,
                         const pqc_mlkem_poly *b);

void pqc_mlkem_poly_sub(pqc_mlkem_poly *r,
                         const pqc_mlkem_poly *a,
                         const pqc_mlkem_poly *b);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_POLY_H */
