/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) internal interface.
 *
 * This header declares the internal functions shared between the
 * FN-DSA compilation units (keygen, sign, verify, codec, sampler,
 * NTRU solver, FFT).
 */

#ifndef PQC_FNDSA_H
#define PQC_FNDSA_H

#include <stddef.h>
#include <stdint.h>

#include "fndsa_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Sampler context                                                      */
/* ------------------------------------------------------------------ */

/*
 * Sampler context.  The internal layout must be visible so callers
 * (sign.c) can allocate it on the stack.  The PRNG is a SHAKE-256
 * incremental context.
 */
#include "core/common/hash/sha3.h"

typedef struct fndsa_sampler_ctx {
    pqc_shake256_ctx shake_ctx;  /* internal PRNG */
    double           sigma_min;
} fndsa_sampler_ctx_t;

/*
 * Initialise the sampler with a seed and the minimum sigma.
 */
void fndsa_sampler_init(fndsa_sampler_ctx_t *ctx,
                        const uint8_t *seed, size_t seed_len,
                        double sigma_min);

/*
 * Sample an integer from the discrete Gaussian D_{Z, mu, sigma}.
 */
int32_t fndsa_sampler_sample(fndsa_sampler_ctx_t *ctx,
                             double mu, double sigma);

/* ------------------------------------------------------------------ */
/* NTRU solver                                                          */
/* ------------------------------------------------------------------ */

/*
 * Solve the NTRU equation  f*G - g*F = q  mod (x^n + 1).
 *
 * f, g:  input polynomials (int32_t, degree < 2^logn).
 * F, G:  output polynomials.
 * tmp:   workspace (at least FNDSA_TMP_SIZE(logn) bytes).
 *
 * Returns 0 on success, nonzero on failure.
 */
int fndsa_solve_ntru(unsigned logn,
                     const int32_t *f, const int32_t *g,
                     int32_t *F, int32_t *G,
                     double *tmp);

/* ------------------------------------------------------------------ */
/* Codec: encoding and decoding                                         */
/* ------------------------------------------------------------------ */

/* Compressed signature encoding/decoding. */
size_t fndsa_comp_encode(uint8_t *out, size_t max_out,
                         const int16_t *s2, unsigned logn);
int    fndsa_comp_decode(int16_t *s2, const uint8_t *sig, size_t siglen,
                         unsigned logn);

/* Secret-key polynomial encoding (trim_i8). */
size_t fndsa_trim_i8_encode(uint8_t *out, size_t max_out,
                            const int8_t *vals, size_t count, unsigned bits);
int    fndsa_trim_i8_decode(int8_t *vals, size_t count, unsigned bits,
                            const uint8_t *in, size_t inlen);

/* Public-key encoding/decoding (14-bit coefficients mod q). */
size_t fndsa_pk_encode(uint8_t *out, size_t max_out,
                       const uint16_t *h, unsigned logn);
int    fndsa_pk_decode(uint16_t *h, const uint8_t *pk, size_t pklen,
                       unsigned logn);

/* Secret-key full encoding/decoding. */
size_t fndsa_sk_encode(uint8_t *out, size_t max_out,
                       const int8_t *f, const int8_t *g, const int8_t *F,
                       unsigned logn);
int    fndsa_sk_decode(int8_t *f, int8_t *g, int8_t *F,
                       const uint8_t *sk, size_t sklen,
                       unsigned logn);

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int fndsa_keygen(uint8_t *pk, size_t pk_max,
                 uint8_t *sk, size_t sk_max,
                 unsigned logn);

/* ------------------------------------------------------------------ */
/* Signature generation                                                 */
/* ------------------------------------------------------------------ */

int fndsa_sign(uint8_t *sig, size_t *siglen, size_t sig_max,
               const uint8_t *msg, size_t msglen,
               const uint8_t *sk, size_t sklen,
               unsigned logn);

/* ------------------------------------------------------------------ */
/* Signature verification                                               */
/* ------------------------------------------------------------------ */

int fndsa_verify(const uint8_t *msg, size_t msglen,
                 const uint8_t *sig, size_t siglen,
                 const uint8_t *pk, size_t pklen,
                 unsigned logn);

#ifdef __cplusplus
}
#endif

#endif /* PQC_FNDSA_H */
