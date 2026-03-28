/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU - OWCPA (one-way CPA) encryption scheme.
 *
 * Key generation:
 *   Choose small f, g. Compute h = p*g*f^{-1} mod q.
 *   Public key: h. Secret key: (f, h, f_inv_mod3).
 *
 * Encryption:
 *   c = r*h + m mod q  (where m is lifted mod-p message).
 *
 * Decryption:
 *   a = c*f mod q, center-lift, reduce mod p to get m.
 *
 * Secret key layout:
 *   [packed f (trits)] [packed h (q-coeffs)] [packed f_inv_mod3 (trits)]
 */

#include <string.h>
#include "ntru.h"
#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* OWCPA Key Generation                                                */
/* ------------------------------------------------------------------ */

int ntru_owcpa_keygen(uint8_t *pk, uint8_t *sk,
                      const ntru_params_t *p)
{
    ntru_poly_t f, g, h;
    ntru_poly_t f_inv_q, f_inv_3;
    uint8_t seed[32];
    int rc;

    /* Generate f: small ternary polynomial with f(1) invertible mod q and mod 3 */
    int attempts = 0;
    while (attempts < 100) {
        attempts++;

        if (pqc_randombytes(seed, 32) != PQC_OK)
            return -1;

        if (p->is_hrss) {
            ntru_sample_ternary(&f, seed, 32, p->n);
            /* For HRSS, set f = 1 + 3*f to ensure invertibility mod 3 */
            for (int i = 0; i < p->n; i++)
                f.coeffs[i] = (int16_t)(3 * f.coeffs[i]);
            f.coeffs[0] = (int16_t)(f.coeffs[0] + 1);
        } else {
            ntru_sample_fixed_weight(&f, seed, 32, p->n, p->weight);
            /* For HPS, f = 1 + 3*f_small */
            for (int i = 0; i < p->n; i++)
                f.coeffs[i] = (int16_t)(3 * f.coeffs[i]);
            f.coeffs[0] = (int16_t)(f.coeffs[0] + 1);
        }

        /* Try to invert f mod q */
        rc = ntru_poly_inv_mod_q(&f_inv_q, &f, p);
        if (rc != 0)
            continue;

        /* Try to invert f mod 3 */
        rc = ntru_poly_inv_mod3(&f_inv_3, &f, p->n);
        if (rc != 0)
            continue;

        break;
    }

    if (attempts >= 100)
        return -1;

    /* Generate g: small ternary polynomial */
    if (pqc_randombytes(seed, 32) != PQC_OK)
        return -1;

    if (p->is_hrss) {
        ntru_sample_ternary(&g, seed, 32, p->n);
    } else {
        ntru_sample_fixed_weight(&g, seed, 32, p->n, p->weight);
    }

    /* h = p * g * f^{-1} mod q */
    /* First compute p * g */
    ntru_poly_t pg;
    for (int i = 0; i < p->n; i++) {
        pg.coeffs[i] = (int16_t)((NTRU_P * g.coeffs[i]) & (p->q - 1));
    }

    /* h = pg * f_inv_q mod q */
    ntru_poly_mul(&h, &pg, &f_inv_q, p);

    /* Pack public key: h */
    ntru_pack_poly_q(pk, &h, p);

    /* Pack secret key: f (trits) || h (q-coeffs) || f_inv_3 (trits) */
    int f_trit_bytes = (p->n + 4) / 5;
    int h_q_bytes = (p->n * p->log_q + 7) / 8;

    ntru_poly_t f_trits;
    ntru_poly_zero(&f_trits);
    /* Store original small f (before 3f+1 transformation) for recovery */
    for (int i = 0; i < p->n; i++) {
        /* f was 1 + 3*f_small, so f_small = (f - 1) / 3 at index 0, f/3 elsewhere */
        int val = f.coeffs[i];
        if (i == 0) val -= 1;
        f_trits.coeffs[i] = (int16_t)(val / 3);
    }

    int offset = 0;
    ntru_pack_trits(sk + offset, &f_trits, p->n);
    offset += f_trit_bytes;
    ntru_pack_poly_q(sk + offset, &h, p);
    offset += h_q_bytes;
    ntru_pack_trits(sk + offset, &f_inv_3, p->n);

    /* Zeroize sensitive data */
    pqc_memzero(&f, sizeof(f));
    pqc_memzero(&f_inv_q, sizeof(f_inv_q));
    pqc_memzero(&f_inv_3, sizeof(f_inv_3));
    pqc_memzero(seed, sizeof(seed));

    return 0;
}

/* ------------------------------------------------------------------ */
/* OWCPA Encryption                                                    */
/* ------------------------------------------------------------------ */

int ntru_owcpa_encrypt(uint8_t *ct, const ntru_poly_t *r,
                       const ntru_poly_t *m, const uint8_t *pk,
                       const ntru_params_t *p)
{
    ntru_poly_t h, rh, c;

    /* Unpack h from public key */
    ntru_unpack_poly_q(&h, pk, p);

    /* c = r * h mod q */
    ntru_poly_mul(&rh, r, &h, p);

    /* c = r*h + m mod q */
    ntru_poly_add(&c, &rh, m, p);

    /* Pack ciphertext */
    ntru_pack_poly_q(ct, &c, p);

    return 0;
}

/* ------------------------------------------------------------------ */
/* OWCPA Decryption                                                    */
/* ------------------------------------------------------------------ */

int ntru_owcpa_decrypt(ntru_poly_t *m, const uint8_t *ct,
                       const uint8_t *sk, const ntru_params_t *p)
{
    ntru_poly_t c, f, f_inv_3, a;
    ntru_poly_t f_trits;

    /* Unpack secret key components */
    int f_trit_bytes = (p->n + 4) / 5;
    int h_q_bytes = (p->n * p->log_q + 7) / 8;

    int offset = 0;
    ntru_unpack_trits(&f_trits, sk + offset, p->n);
    offset += f_trit_bytes;
    /* Skip h */
    offset += h_q_bytes;
    ntru_unpack_trits(&f_inv_3, sk + offset, p->n);

    /* Reconstruct f = 1 + 3*f_trits */
    for (int i = 0; i < p->n; i++) {
        f.coeffs[i] = (int16_t)(3 * f_trits.coeffs[i]);
    }
    f.coeffs[0] = (int16_t)(f.coeffs[0] + 1);

    /* Unpack ciphertext */
    ntru_unpack_poly_q(&c, ct, p);

    /* a = c * f mod q */
    ntru_poly_mul(&a, &c, &f, p);

    /* Center-lift: coefficients to [-q/2, q/2) */
    ntru_poly_mod_q(&a, p);

    /* Reduce mod p=3 */
    ntru_poly_mod3(&a, p->n);

    /* m = a * f^{-1} mod 3 (in Z_3[x]/(x^n - 1)) */
    /* Use schoolbook multiplication mod 3 */
    ntru_poly_zero(m);
    for (int i = 0; i < p->n; i++) {
        if (a.coeffs[i] == 0) continue;
        for (int j = 0; j < p->n; j++) {
            int idx = i + j;
            if (idx >= p->n) idx -= p->n;
            m->coeffs[idx] = (int16_t)(m->coeffs[idx] + a.coeffs[i] * f_inv_3.coeffs[j]);
        }
    }
    ntru_poly_mod3(m, p->n);

    pqc_memzero(&f, sizeof(f));
    pqc_memzero(&f_inv_3, sizeof(f_inv_3));

    return 0;
}
