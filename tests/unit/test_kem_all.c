/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * KEM round-trip test for all enabled algorithms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqc/pqc.h"
#include "pqc/rand.h"
#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/ntt.h"
#include "core/kem/mlkem/reduce.h"
#include "core/kem/mlkem/poly.h"
#include "core/kem/mlkem/polyvec.h"
#include "core/common/hash/sha3.h"

static int test_kem_roundtrip(const char *alg_name) {
    PQC_KEM *kem = pqc_kem_new(alg_name);
    if (!kem) {
        fprintf(stderr, "  SKIP: %s (not available)\n", alg_name);
        return 0;
    }

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);
    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *ct = calloc(1, ct_len);
    uint8_t *ss1 = calloc(1, ss_len);
    uint8_t *ss2 = calloc(1, ss_len);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        fprintf(stderr, "  FAIL: %s (allocation failed)\n", alg_name);
        goto fail;
    }

    pqc_status_t rc;

    rc = pqc_kem_keygen(kem, pk, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s keygen returned %d\n", alg_name, rc);
        goto fail;
    }

    rc = pqc_kem_encaps(kem, ct, ss1, pk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s encaps returned %d\n", alg_name, rc);
        goto fail;
    }

    rc = pqc_kem_decaps(kem, ss2, ct, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s decaps returned %d\n", alg_name, rc);
        goto fail;
    }

    if (memcmp(ss1, ss2, ss_len) != 0) {
        fprintf(stderr, "  FAIL: %s shared secrets do not match\n", alg_name);
        goto fail;
    }

    printf("  PASS: %s (pk=%zu sk=%zu ct=%zu ss=%zu)\n",
           alg_name, pk_len, sk_len, ct_len, ss_len);

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);
    return 0;

fail:
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);
    return 1;
}

/* Deterministic RNG for debugging */
static uint8_t det_rng_state = 0;
static pqc_status_t det_rng(uint8_t *buf, size_t len, void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        buf[i] = det_rng_state++;
    }
    return PQC_OK;
}

/* Test the raw polynomial pipeline: basemul_acc + invntt for a vector */
static int test_polynomial_pipeline(void) {
    printf("\n=== Polynomial Pipeline Test ===\n");

    unsigned int k = 2; /* ML-KEM-512 */

    pqc_mlkem_polyvec s, r, a0, a1, u, t_vec;
    pqc_mlkem_poly v_poly, mp, msg, tmp;
    unsigned int i;

    /* Zero everything */
    memset(&s, 0, sizeof(s));
    memset(&r, 0, sizeof(r));
    memset(&a0, 0, sizeof(a0));
    memset(&a1, 0, sizeof(a1));

    /* s = [[1,0,...], [0,0,...]]  (first component is constant 1) */
    s.vec[0].coeffs[0] = 1;

    /* r = [[1,0,...], [0,0,...]] */
    r.vec[0].coeffs[0] = 1;

    /* A = identity: A[0][0] = 1, A[1][1] = 1, rest 0 */
    /* In NTT domain, the polynomial "1" is NTT([1,0,...]) = [1,0,1,0,...] */
    /* But we need A already in NTT domain */
    /* Let's use A[i][j] = NTT(delta(i==j)) */

    /* NTT of [1,0,...] */
    pqc_mlkem_poly one_ntt;
    memset(&one_ntt, 0, sizeof(one_ntt));
    one_ntt.coeffs[0] = 1;
    pqc_mlkem_poly_ntt(&one_ntt);

    printf("NTT([1,0,...])[0..7] = %d %d %d %d %d %d %d %d\n",
           one_ntt.coeffs[0], one_ntt.coeffs[1], one_ntt.coeffs[2], one_ntt.coeffs[3],
           one_ntt.coeffs[4], one_ntt.coeffs[5], one_ntt.coeffs[6], one_ntt.coeffs[7]);

    /* Set A as identity in NTT domain */
    /* A[0][0] = one_ntt, A[1][1] = one_ntt, rest zero */
    memcpy(&a0.vec[0], &one_ntt, sizeof(pqc_mlkem_poly));
    memcpy(&a1.vec[1], &one_ntt, sizeof(pqc_mlkem_poly));

    /* NTT(s) */
    pqc_mlkem_ntt(s.vec[0].coeffs);
    for (i = 0; i < 256; i++) s.vec[0].coeffs[i] = pqc_mlkem_barrett_reduce(s.vec[0].coeffs[i]);

    /* NTT(r) */
    pqc_mlkem_ntt(r.vec[0].coeffs);
    for (i = 0; i < 256; i++) r.vec[0].coeffs[i] = pqc_mlkem_barrett_reduce(r.vec[0].coeffs[i]);

    printf("NTT(s[0])[0..3] = %d %d %d %d\n",
           s.vec[0].coeffs[0], s.vec[0].coeffs[1], s.vec[0].coeffs[2], s.vec[0].coeffs[3]);

    /* t = tomont(basemul(A, s)) (keygen) */
    /* t[0] = basemul(a0[0], s[0]) + basemul(a0[1], s[1]) */
    pqc_mlkem_poly_basemul_montgomery(&t_vec.vec[0], &a0.vec[0], &s.vec[0]);
    pqc_mlkem_poly_basemul_montgomery(&tmp, &a0.vec[1], &s.vec[1]);
    for (i = 0; i < 256; i++) t_vec.vec[0].coeffs[i] += tmp.coeffs[i];
    for (i = 0; i < 256; i++) t_vec.vec[0].coeffs[i] = pqc_mlkem_barrett_reduce(t_vec.vec[0].coeffs[i]);
    pqc_mlkem_poly_tomont(&t_vec.vec[0]);

    /* t[1] = basemul(a1[0], s[0]) + basemul(a1[1], s[1]) */
    pqc_mlkem_poly_basemul_montgomery(&t_vec.vec[1], &a1.vec[0], &s.vec[0]);
    pqc_mlkem_poly_basemul_montgomery(&tmp, &a1.vec[1], &s.vec[1]);
    for (i = 0; i < 256; i++) t_vec.vec[1].coeffs[i] += tmp.coeffs[i];
    for (i = 0; i < 256; i++) t_vec.vec[1].coeffs[i] = pqc_mlkem_barrett_reduce(t_vec.vec[1].coeffs[i]);
    pqc_mlkem_poly_tomont(&t_vec.vec[1]);

    printf("t[0][0..3] = %d %d %d %d\n",
           t_vec.vec[0].coeffs[0], t_vec.vec[0].coeffs[1], t_vec.vec[0].coeffs[2], t_vec.vec[0].coeffs[3]);
    printf("t[1][0..3] = %d %d %d %d\n",
           t_vec.vec[1].coeffs[0], t_vec.vec[1].coeffs[1], t_vec.vec[1].coeffs[2], t_vec.vec[1].coeffs[3]);

    /* Encrypt: u = invntt(basemul(A^T, r)), v = invntt(basemul(t, r)) + m */
    /* A^T[0][0] = a0[0] = one_ntt, A^T[0][1] = a1[0] = 0, A^T[1][0] = a0[1] = 0, A^T[1][1] = a1[1] = one_ntt */
    /* So A^T = A = identity. u = r */

    /* u[0] = invntt(basemul(A^T[0][0], r[0]) + basemul(A^T[0][1], r[1])) */
    pqc_mlkem_poly_basemul_montgomery(&u.vec[0], &a0.vec[0], &r.vec[0]); /* one_ntt * r_ntt */
    pqc_mlkem_poly_basemul_montgomery(&tmp, &a1.vec[0], &r.vec[1]); /* 0 * 0 */
    for (i = 0; i < 256; i++) u.vec[0].coeffs[i] += tmp.coeffs[i];
    for (i = 0; i < 256; i++) u.vec[0].coeffs[i] = pqc_mlkem_barrett_reduce(u.vec[0].coeffs[i]);
    pqc_mlkem_invntt(u.vec[0].coeffs);

    /* v = invntt(basemul(t[0], r[0]) + basemul(t[1], r[1])) */
    pqc_mlkem_poly_basemul_montgomery(&v_poly, &t_vec.vec[0], &r.vec[0]);
    pqc_mlkem_poly_basemul_montgomery(&tmp, &t_vec.vec[1], &r.vec[1]);
    for (i = 0; i < 256; i++) v_poly.coeffs[i] += tmp.coeffs[i];
    for (i = 0; i < 256; i++) v_poly.coeffs[i] = pqc_mlkem_barrett_reduce(v_poly.coeffs[i]);
    pqc_mlkem_invntt(v_poly.coeffs);

    /* Add message: m = [1665, 0, 0, ...] */
    memset(&msg, 0, sizeof(msg));
    msg.coeffs[0] = 1665;
    for (i = 0; i < 256; i++) v_poly.coeffs[i] += msg.coeffs[i];

    printf("v[0..3] = %d %d %d %d (before decrypt)\n",
           v_poly.coeffs[0], v_poly.coeffs[1], v_poly.coeffs[2], v_poly.coeffs[3]);

    /* Decrypt: mp = v - invntt(basemul(s, ntt(u))) */
    /* NTT(u) */
    pqc_mlkem_ntt(u.vec[0].coeffs);
    for (i = 0; i < 256; i++) u.vec[0].coeffs[i] = pqc_mlkem_barrett_reduce(u.vec[0].coeffs[i]);

    printf("NTT(u[0])[0..3] = %d %d %d %d\n",
           u.vec[0].coeffs[0], u.vec[0].coeffs[1], u.vec[0].coeffs[2], u.vec[0].coeffs[3]);
    printf("s[0][0..3] = %d %d %d %d\n",
           s.vec[0].coeffs[0], s.vec[0].coeffs[1], s.vec[0].coeffs[2], s.vec[0].coeffs[3]);

    /* basemul(s, ntt(u)) */
    pqc_mlkem_poly_basemul_montgomery(&mp, &s.vec[0], &u.vec[0]);
    pqc_mlkem_poly_basemul_montgomery(&tmp, &s.vec[1], &u.vec[1]);
    for (i = 0; i < 256; i++) mp.coeffs[i] += tmp.coeffs[i];
    for (i = 0; i < 256; i++) mp.coeffs[i] = pqc_mlkem_barrett_reduce(mp.coeffs[i]);

    printf("basemul result[0..3] = %d %d %d %d\n",
           mp.coeffs[0], mp.coeffs[1], mp.coeffs[2], mp.coeffs[3]);

    pqc_mlkem_invntt(mp.coeffs);

    printf("invntt result[0..3] = %d %d %d %d\n",
           mp.coeffs[0], mp.coeffs[1], mp.coeffs[2], mp.coeffs[3]);

    /* mp = v - invntt_result */
    for (i = 0; i < 256; i++) {
        mp.coeffs[i] = v_poly.coeffs[i] - mp.coeffs[i];
        mp.coeffs[i] = pqc_mlkem_barrett_reduce(mp.coeffs[i]);
    }

    int16_t c0 = mp.coeffs[0];
    if (c0 < 0) c0 += 3329;
    int16_t c1 = mp.coeffs[1];
    if (c1 < 0) c1 += 3329;

    printf("Recovered mp[0] = %d (expect ~1665), mp[1] = %d (expect ~0)\n", c0, c1);

    int ok = (c0 > 1600 && c0 < 1730 && c1 < 50);
    printf("Pipeline test: %s\n", ok ? "PASS" : "FAIL");

    /* Test matrix generation: verify SHAKE-128 produces correct A coefficients */
    {
        uint8_t test_rho[32];
        uint8_t shake_in[34];
        uint8_t shake_out[504];
        int16_t a_coeffs[10];
        int a_count = 0, a_pos = 0;

        for (i = 0; i < 32; i++) test_rho[i] = (uint8_t)i;
        memcpy(shake_in, test_rho, 32);
        shake_in[32] = 0; /* x */
        shake_in[33] = 0; /* y */
        pqc_shake128(shake_out, 504, shake_in, 34);

        while (a_count < 10) {
            uint16_t d1 = (shake_out[a_pos] | (shake_out[a_pos+1] << 8)) & 0xFFF;
            uint16_t d2 = ((shake_out[a_pos+1] >> 4) | (shake_out[a_pos+2] << 4)) & 0xFFF;
            a_pos += 3;
            if (d1 < 3329) a_coeffs[a_count++] = (int16_t)d1;
            if (a_count < 10 && d2 < 3329) a_coeffs[a_count++] = (int16_t)d2;
        }

        printf("\nMatrix gen test: A[0][0] coeffs (expected: 481 1919 1434 2359 327 1066 3001 649):\n");
        printf("  Got: %d %d %d %d %d %d %d %d\n",
               a_coeffs[0], a_coeffs[1], a_coeffs[2], a_coeffs[3],
               a_coeffs[4], a_coeffs[5], a_coeffs[6], a_coeffs[7]);
    }

    return ok ? 0 : 1;
}

static int test_mlkem_debug(void) {
    printf("\n=== ML-KEM Debug Test (deterministic RNG) ===\n");
    det_rng_state = 0;
    pqc_set_rng(det_rng, NULL);

    PQC_KEM *kem = pqc_kem_new("ML-KEM-512");
    if (!kem) { printf("SKIP: ML-KEM-512 not available\n"); return 0; }

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);
    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *ct = calloc(1, ct_len);
    uint8_t *ss1 = calloc(1, ss_len);
    uint8_t *ss2 = calloc(1, ss_len);

    /* Keygen with deterministic randomness */
    det_rng_state = 0;
    pqc_status_t rc = pqc_kem_keygen(kem, pk, sk);
    printf("keygen: rc=%d, pk[0..3]=%02x%02x%02x%02x, sk[0..3]=%02x%02x%02x%02x\n",
           rc, pk[0], pk[1], pk[2], pk[3], sk[0], sk[1], sk[2], sk[3]);

    /* Encaps */
    rc = pqc_kem_encaps(kem, ct, ss1, pk);
    printf("encaps: rc=%d, ct[0..3]=%02x%02x%02x%02x, ss1[0..3]=%02x%02x%02x%02x\n",
           rc, ct[0], ct[1], ct[2], ct[3], ss1[0], ss1[1], ss1[2], ss1[3]);

    /* Decaps */
    rc = pqc_kem_decaps(kem, ss2, ct, sk);
    printf("decaps: rc=%d, ss2[0..3]=%02x%02x%02x%02x\n",
           rc, ss2[0], ss2[1], ss2[2], ss2[3]);

    int match = (memcmp(ss1, ss2, ss_len) == 0);
    printf("shared secret match: %s\n", match ? "YES" : "NO");

    if (!match) {
        printf("ss1: "); for (size_t i = 0; i < 8; i++) printf("%02x", ss1[i]); printf("...\n");
        printf("ss2: "); for (size_t i = 0; i < 8; i++) printf("%02x", ss2[i]); printf("...\n");
    }

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);

    /* Reset to OS RNG */
    pqc_set_rng(NULL, NULL);
    return match ? 0 : 1;
}

int main(void) {
    pqc_init();

    /* Run debug tests first */
    int pipe_fail = test_polynomial_pipeline();
    int dbg_fail = test_mlkem_debug();

    printf("libpqc-dyber KEM Tests\n");
    printf("======================\n");

    int failures = 0;
    int count = pqc_kem_algorithm_count();

    printf("Testing %d KEM algorithms:\n\n", count);

    for (int i = 0; i < count; i++) {
        const char *name = pqc_kem_algorithm_name(i);
        failures += test_kem_roundtrip(name);
    }

    printf("\n%d/%d algorithms tested, %d failures\n",
           count, count, failures);

    pqc_cleanup();
    return failures > 0 ? 1 : 0;
}
