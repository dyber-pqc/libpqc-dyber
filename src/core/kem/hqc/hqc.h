/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC internal interface.
 */

#ifndef PQC_HQC_H
#define PQC_HQC_H

#include <stddef.h>
#include <stdint.h>
#include "hqc_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* GF(2^m) arithmetic (gf.c)                                            */
/* ------------------------------------------------------------------ */

typedef uint16_t hqc_gf_t;

void hqc_gf_generate_tables(uint32_t m);
hqc_gf_t hqc_gf_mul(hqc_gf_t a, hqc_gf_t b, uint32_t m);
hqc_gf_t hqc_gf_inv(hqc_gf_t a, uint32_t m);
hqc_gf_t hqc_gf_pow(hqc_gf_t a, uint32_t exp, uint32_t m);
hqc_gf_t hqc_gf_exp(uint32_t i, uint32_t m);
uint32_t  hqc_gf_log(hqc_gf_t a, uint32_t m);

/* ------------------------------------------------------------------ */
/* Reed-Solomon codec (reed_solomon.c)                                  */
/* ------------------------------------------------------------------ */

void hqc_rs_encode(uint8_t *codeword, const uint8_t *message,
                   const hqc_params_t *params);
int  hqc_rs_decode(uint8_t *message, const uint8_t *codeword,
                   const hqc_params_t *params);

/* ------------------------------------------------------------------ */
/* Reed-Muller codec (reed_muller.c)                                    */
/* ------------------------------------------------------------------ */

void hqc_rm_encode(uint8_t *codeword, uint8_t message_byte);
uint8_t hqc_rm_decode(const uint8_t *codeword);

/* ------------------------------------------------------------------ */
/* Concatenated code (code.c)                                           */
/* ------------------------------------------------------------------ */

void hqc_code_encode(uint8_t *encoded, const uint8_t *message,
                     const hqc_params_t *params);
int  hqc_code_decode(uint8_t *message, const uint8_t *encoded,
                     const hqc_params_t *params);

/* ------------------------------------------------------------------ */
/* Parsing / serialization (parsing.c)                                  */
/* ------------------------------------------------------------------ */

void hqc_pk_pack(uint8_t *pk, const uint8_t *seed,
                 const uint64_t *h, const hqc_params_t *params);
void hqc_pk_unpack(uint8_t *seed, uint64_t *h,
                   const uint8_t *pk, const hqc_params_t *params);

void hqc_sk_pack(uint8_t *sk, const uint8_t *seed,
                 const uint8_t *pk, const hqc_params_t *params);
void hqc_sk_unpack(uint8_t *seed, uint8_t *pk,
                   const uint8_t *sk, const hqc_params_t *params);

void hqc_ct_pack(uint8_t *ct, const uint64_t *u, const uint64_t *v,
                 const uint8_t *salt, const hqc_params_t *params);
void hqc_ct_unpack(uint64_t *u, uint64_t *v, uint8_t *salt,
                   const uint8_t *ct, const hqc_params_t *params);

/* ------------------------------------------------------------------ */
/* Sparse vector operations                                             */
/* ------------------------------------------------------------------ */

void hqc_vect_set_random_fixed_weight(uint64_t *v, uint32_t weight,
                                       uint32_t n,
                                       const uint8_t *seed, size_t seedlen);
void hqc_vect_set_random(uint64_t *v, uint32_t n,
                         const uint8_t *seed, size_t seedlen);
void hqc_vect_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                  uint32_t n);
void hqc_vect_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                  uint32_t n);

/* ------------------------------------------------------------------ */
/* Core KEM operations                                                  */
/* ------------------------------------------------------------------ */

void hqc_keygen_internal(uint8_t *pk, uint8_t *sk,
                         const hqc_params_t *params);
void hqc_encaps_internal(uint8_t *ct, uint8_t *ss,
                         const uint8_t *pk,
                         const hqc_params_t *params);
int  hqc_decaps_internal(uint8_t *ss, const uint8_t *ct,
                         const uint8_t *sk,
                         const hqc_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PQC_HQC_H */
