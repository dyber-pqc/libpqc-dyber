/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece internal interface.
 */

#ifndef PQC_MCELIECE_H
#define PQC_MCELIECE_H

#include <stddef.h>
#include <stdint.h>

#include "mceliece_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* GF(2^m) types and arithmetic  (gf.c)                               */
/* ------------------------------------------------------------------ */

typedef uint16_t gf_t;

/* Basic field operations */
gf_t gf_add(gf_t a, gf_t b);
gf_t gf_mul(gf_t a, gf_t b, int m);
gf_t gf_sq(gf_t a, int m);
gf_t gf_inv(gf_t a, int m);
gf_t gf_sqrt(gf_t a, int m);
gf_t gf_frac(gf_t num, gf_t den, int m);

/* Initialize log/exp tables for GF(2^m) */
void gf_init_tables(int m);

/* ------------------------------------------------------------------ */
/* Benes network  (benes.c)                                           */
/* ------------------------------------------------------------------ */

/*
 * Apply permutation via Benes network.
 * bits: control bits array
 * r:    data array of size 1 << lgs, entries are bytes
 * lgs:  log2 of the number of elements
 * rev:  0 = forward, 1 = reverse
 */
void benes_apply(const uint8_t *bits, uint8_t *r, int lgs, int rev);

/* ------------------------------------------------------------------ */
/* Control bits  (controlbits.c)                                      */
/* ------------------------------------------------------------------ */

/*
 * Compute control bits for a Benes network from a permutation.
 * out:  output control bits, size (2*lgs - 1) * (1 << (lgs-1)) bits
 * pi:   permutation array, size 1 << lgs
 * lgs:  log2 of permutation size
 */
void controlbits_from_permutation(uint8_t *out, const uint16_t *pi, int lgs);

/* ------------------------------------------------------------------ */
/* Goppa code  (goppa.c)                                              */
/* ------------------------------------------------------------------ */

/*
 * Generate a random irreducible polynomial of degree t over GF(2^m).
 * g: output polynomial coefficients [0..t], g[t] = 1 (monic).
 * Returns 0 on success, -1 on failure.
 */
int goppa_gen_irr_poly(gf_t *g, int t, int m);

/*
 * Create the parity-check matrix H in systematic form.
 * T: output systematic part (k rows, n-k columns packed in bytes).
 * g: Goppa polynomial.
 * perm: support permutation.
 * Returns 0 on success, -1 if systematic form not achievable.
 */
int goppa_systematic_matrix(uint8_t *T, const gf_t *g,
                            const uint16_t *perm,
                            const mceliece_params_t *p);

/* ------------------------------------------------------------------ */
/* Root finding  (root.c)                                             */
/* ------------------------------------------------------------------ */

/*
 * Evaluate polynomial f of degree deg at all field elements.
 * out[i] = f(alpha_i) for i in [0, n).
 */
void root_eval(gf_t *out, const gf_t *f, int deg,
               const uint16_t *support, int n, int m);

/* ------------------------------------------------------------------ */
/* Encrypt  (encrypt.c)                                               */
/* ------------------------------------------------------------------ */

/*
 * Encrypt: compute syndrome s = H * e^T from a random weight-t error.
 * ct:  output ciphertext (syndrome)
 * e:   output error vector (as bit-packed bytes), size ceil(n/8)
 * pk:  public key (systematic part T)
 * p:   parameters
 * Returns 0 on success.
 */
int mceliece_encrypt(uint8_t *ct, uint8_t *e,
                     const uint8_t *pk, const mceliece_params_t *p);

/* ------------------------------------------------------------------ */
/* Decrypt  (decrypt.c)                                               */
/* ------------------------------------------------------------------ */

/*
 * Decrypt: recover error vector from syndrome using Patterson's algorithm.
 * e:   output error vector (bit-packed), size ceil(n/8)
 * ct:  ciphertext (syndrome)
 * sk_g: Goppa polynomial coefficients
 * sk_perm: support permutation
 * p:   parameters
 * Returns 0 on success, -1 on decoding failure.
 */
int mceliece_decrypt(uint8_t *e, const uint8_t *ct,
                     const gf_t *sk_g, const uint16_t *sk_perm,
                     const mceliece_params_t *p);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MCELIECE_H */
