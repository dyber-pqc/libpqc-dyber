/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM - full implementation.
 *
 * FrodoKEM is a lattice-based KEM built on the Learning With Errors
 * (LWE) problem over unstructured matrices. The public key is
 * (seedA, B = A*S + E) where A is generated from seedA. Encapsulation
 * picks fresh S', E', E'' and computes B' = S'*A + E', V = S'*B + E'' + encode(mu).
 * Decapsulation recovers mu = decode(V - B'*S), then re-encapsulates to verify.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/common/hash/sha3.h"
#include "core/common/hash/sha2.h"
#include "frodo.h"
#include "frodo_params.h"

/* ------------------------------------------------------------------ */
/* Helper: hash for pk fingerprint                                      */
/* ------------------------------------------------------------------ */

static void frodo_hash_pk(uint8_t *pkh, const uint8_t *pk,
                          uint32_t pk_bytes, uint32_t len_pkh)
{
    if (len_pkh <= 32) {
        uint8_t hash[32];
        pqc_shake256(hash, 32, pk, pk_bytes);
        memcpy(pkh, hash, len_pkh);
    } else {
        pqc_shake256(pkh, len_pkh, pk, pk_bytes);
    }
}

/* ------------------------------------------------------------------ */
/* Helper: generate A based on mode                                     */
/* ------------------------------------------------------------------ */

static void frodo_gen_a(uint16_t *A, uint32_t n, const uint8_t *seed,
                        frodo_matrix_a_mode_t mode)
{
    if (mode == FRODO_MATRIX_A_AES) {
        frodo_gen_matrix_aes(A, n, seed);
    } else {
        frodo_gen_matrix_shake(A, n, seed);
    }
}

/* ------------------------------------------------------------------ */
/* Internal keygen                                                      */
/*                                                                      */
/* pk = (seedA, B = A*S + E)                                           */
/* sk = (s || pk || S^T || pkh)                                        */
/* ------------------------------------------------------------------ */

void frodo_keygen_internal(uint8_t *pk, uint8_t *sk,
                           const frodo_params_t *params,
                           const uint16_t *cdf, uint32_t cdf_len)
{
    uint32_t n     = params->n;
    uint32_t n_bar = FRODO_N_BAR;
    uint32_t q     = params->q;
    uint32_t log_q = params->log_q;

    /* Allocate matrices */
    size_t a_size = (size_t)n * n;
    size_t s_size = (size_t)n * n_bar;
    size_t e_size = (size_t)n * n_bar;
    size_t b_size = (size_t)n * n_bar;

    uint16_t *A = (uint16_t *)calloc(a_size, sizeof(uint16_t));
    uint16_t *S = (uint16_t *)calloc(s_size, sizeof(uint16_t));
    uint16_t *E = (uint16_t *)calloc(e_size, sizeof(uint16_t));
    uint16_t *B = (uint16_t *)calloc(b_size, sizeof(uint16_t));
    uint16_t *S_T = (uint16_t *)calloc(s_size, sizeof(uint16_t));

    if (!A || !S || !E || !B || !S_T) {
        free(A); free(S); free(E); free(B); free(S_T);
        return;
    }

    /* Generate random seedA and seedSE */
    uint8_t seedA[FRODO_SEED_A_BYTES];
    uint8_t s_val[FRODO_MAX_LEN_S]; /* random s for implicit rejection */
    uint8_t seedSE[FRODO_MAX_LEN_K]; /* will be expanded */

    pqc_randombytes(seedA, FRODO_SEED_A_BYTES);
    pqc_randombytes(s_val, params->len_s);
    pqc_randombytes(seedSE, params->len_seedse);

    /* Expand seedSE for S and E generation */
    uint8_t seedSE_expanded[1 + 64]; /* 0x5F || SHAKE(seedSE) */
    seedSE_expanded[0] = 0x5F;
    pqc_shake256(seedSE_expanded + 1, 64, seedSE, params->len_seedse);

    /* Generate matrix A */
    frodo_gen_a(A, n, seedA, params->matrix_a_mode);

    /* Sample S (n x n_bar) and E (n x n_bar) */
    frodo_sample_noise(S, n, n_bar, seedSE_expanded, 65, 0, q, cdf, cdf_len);
    frodo_sample_noise(E, n, n_bar, seedSE_expanded, 65, 1, q, cdf, cdf_len);

    /* B = A * S + E mod q */
    frodo_matrix_mul(B, A, n, n, S, n_bar, q);
    frodo_matrix_add(B, B, E, n, n_bar, q);

    /* Pack public key: pk = seedA || pack(B) */
    memcpy(pk, seedA, FRODO_SEED_A_BYTES);
    {
        uint32_t b_packed_bytes = (n * n_bar * log_q + 7) / 8;
        frodo_pack(pk + FRODO_SEED_A_BYTES, B, n * n_bar, log_q);
        (void)b_packed_bytes;
    }

    /* Compute S^T */
    frodo_matrix_transpose(S_T, S, n, n_bar);

    /* Hash public key */
    uint8_t pkh[FRODO_MAX_LEN_PKH];
    frodo_hash_pk(pkh, pk, params->pk_bytes, params->len_pkh);

    /* Pack secret key: sk = s || pk || pack(S^T) || pkh */
    {
        uint32_t offset = 0;
        memcpy(sk + offset, s_val, params->len_s);
        offset += params->len_s;
        memcpy(sk + offset, pk, params->pk_bytes);
        offset += params->pk_bytes;
        /* Pack S^T: n_bar rows, n cols */
        frodo_pack(sk + offset, S_T, n_bar * n, log_q);
        offset += (n_bar * n * log_q + 7) / 8;
        memcpy(sk + offset, pkh, params->len_pkh);
    }

    /* Cleanup */
    pqc_memzero(S, s_size * sizeof(uint16_t));
    pqc_memzero(E, e_size * sizeof(uint16_t));
    pqc_memzero(S_T, s_size * sizeof(uint16_t));
    pqc_memzero(seedSE, sizeof(seedSE));
    pqc_memzero(seedSE_expanded, sizeof(seedSE_expanded));
    pqc_memzero(s_val, sizeof(s_val));
    free(A); free(S); free(E); free(B); free(S_T);
}

/* ------------------------------------------------------------------ */
/* Internal encaps                                                      */
/*                                                                      */
/* ct = (C1 = S'*A + E', C2 = S'*B + E'' + encode(mu))                */
/* ss = SHAKE(C1 || C2 || k || pkh) where k = SHAKE(mu || pkh)         */
/* ------------------------------------------------------------------ */

void frodo_encaps_internal(uint8_t *ct, uint8_t *ss,
                           const uint8_t *pk,
                           const frodo_params_t *params,
                           const uint16_t *cdf, uint32_t cdf_len)
{
    uint32_t n     = params->n;
    uint32_t n_bar = FRODO_N_BAR;
    uint32_t q     = params->q;
    uint32_t log_q = params->log_q;
    uint32_t b_param = params->b;
    uint32_t len_mu = params->len_mu;     /* bits */
    uint32_t mu_bytes = (len_mu + 7) / 8;

    /* Unpack pk: seedA || B_packed */
    const uint8_t *seedA = pk;
    const uint8_t *B_packed = pk + FRODO_SEED_A_BYTES;

    /* Allocate matrices */
    uint16_t *A   = (uint16_t *)calloc((size_t)n * n, sizeof(uint16_t));
    uint16_t *B   = (uint16_t *)calloc((size_t)n * n_bar, sizeof(uint16_t));
    uint16_t *Sp  = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *Ep  = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *Epp = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *C1  = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *C2  = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *V   = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *enc_mu = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));

    if (!A || !B || !Sp || !Ep || !Epp || !C1 || !C2 || !V || !enc_mu) {
        free(A); free(B); free(Sp); free(Ep); free(Epp);
        free(C1); free(C2); free(V); free(enc_mu);
        return;
    }

    /* Generate A */
    frodo_gen_a(A, n, seedA, params->matrix_a_mode);

    /* Unpack B */
    frodo_unpack(B, B_packed, n * n_bar, log_q);

    /* Generate random mu */
    uint8_t mu[FRODO_MAX_LEN_MU / 8 + 1];
    pqc_randombytes(mu, mu_bytes);

    /* Hash pk */
    uint8_t pkh[FRODO_MAX_LEN_PKH];
    frodo_hash_pk(pkh, pk, params->pk_bytes, params->len_pkh);

    /* Derive seedSE and k: SHAKE(mu || pkh) -> seedSE || k */
    uint8_t G_out[64]; /* seedSE || k */
    {
        pqc_shake256_ctx gctx;
        pqc_shake256_init(&gctx);
        pqc_shake256_absorb(&gctx, mu, mu_bytes);
        pqc_shake256_absorb(&gctx, pkh, params->len_pkh);
        pqc_shake256_finalize(&gctx);
        pqc_shake256_squeeze(&gctx, G_out, params->len_seedse + params->len_k);
    }
    uint8_t *seedSE = G_out;
    uint8_t *k_val  = G_out + params->len_seedse;

    /* Expand seedSE */
    uint8_t seedSE_expanded[1 + 64];
    seedSE_expanded[0] = 0x96;
    pqc_shake256(seedSE_expanded + 1, 64, seedSE, params->len_seedse);

    /* Sample S' (n_bar x n), E' (n_bar x n), E'' (n_bar x n_bar) */
    frodo_sample_noise(Sp,  n_bar, n,     seedSE_expanded, 65, 0, q, cdf, cdf_len);
    frodo_sample_noise(Ep,  n_bar, n,     seedSE_expanded, 65, 1, q, cdf, cdf_len);
    frodo_sample_noise(Epp, n_bar, n_bar, seedSE_expanded, 65, 2, q, cdf, cdf_len);

    /* C1 = S' * A + E' mod q */
    frodo_matrix_mul(C1, Sp, n_bar, n, A, n, q);
    frodo_matrix_add(C1, C1, Ep, n_bar, n, q);

    /* V = S' * B + E'' mod q */
    frodo_matrix_mul(V, Sp, n_bar, n, B, n_bar, q);
    frodo_matrix_add(V, V, Epp, n_bar, n_bar, q);

    /* Encode mu */
    frodo_encode(enc_mu, mu, len_mu, b_param, q);

    /* C2 = V + encode(mu) mod q */
    frodo_matrix_add(C2, V, enc_mu, n_bar, n_bar, q);

    /* Pack ciphertext: ct = pack(C1) || pack(C2) */
    {
        uint32_t c1_packed = (n_bar * n * log_q + 7) / 8;
        frodo_pack(ct, C1, n_bar * n, log_q);
        frodo_pack(ct + c1_packed, C2, n_bar * n_bar, log_q);
    }

    /* Compute shared secret: ss = SHAKE(ct || k || pkh) */
    {
        pqc_shake256_ctx sctx;
        pqc_shake256_init(&sctx);
        pqc_shake256_absorb(&sctx, ct, params->ct_bytes);
        pqc_shake256_absorb(&sctx, k_val, params->len_k);
        pqc_shake256_absorb(&sctx, pkh, params->len_pkh);
        pqc_shake256_finalize(&sctx);
        pqc_shake256_squeeze(&sctx, ss, params->len_ss);
    }

    /* Cleanup */
    pqc_memzero(mu, sizeof(mu));
    pqc_memzero(G_out, sizeof(G_out));
    pqc_memzero(seedSE_expanded, sizeof(seedSE_expanded));
    pqc_memzero(Sp, (size_t)n_bar * n * sizeof(uint16_t));
    free(A); free(B); free(Sp); free(Ep); free(Epp);
    free(C1); free(C2); free(V); free(enc_mu);
}

/* ------------------------------------------------------------------ */
/* Internal decaps                                                      */
/*                                                                      */
/* Recover mu from (C1, C2) using secret S^T:                          */
/* M = C2 - C1 * S, mu = decode(M).                                    */
/* Then re-encapsulate and compare to verify.                           */
/* ------------------------------------------------------------------ */

int frodo_decaps_internal(uint8_t *ss, const uint8_t *ct,
                          const uint8_t *sk,
                          const frodo_params_t *params,
                          const uint16_t *cdf, uint32_t cdf_len)
{
    uint32_t n     = params->n;
    uint32_t n_bar = FRODO_N_BAR;
    uint32_t q     = params->q;
    uint32_t log_q = params->log_q;
    uint32_t b_param = params->b;
    uint32_t len_mu = params->len_mu;
    uint32_t mu_bytes = (len_mu + 7) / 8;

    /* Unpack secret key: s || pk || S_T_packed || pkh */
    uint32_t sk_offset = 0;
    const uint8_t *s_val = sk + sk_offset;
    sk_offset += params->len_s;
    const uint8_t *pk_stored = sk + sk_offset;
    sk_offset += params->pk_bytes;
    const uint8_t *S_T_packed = sk + sk_offset;
    sk_offset += (n_bar * n * log_q + 7) / 8;
    const uint8_t *pkh = sk + sk_offset;

    /* Unpack S^T (n_bar x n) */
    uint16_t *S_T = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *S   = (uint16_t *)calloc((size_t)n * n_bar, sizeof(uint16_t));
    uint16_t *C1  = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *C2  = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *M   = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *C1S = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));

    if (!S_T || !S || !C1 || !C2 || !M || !C1S) {
        free(S_T); free(S); free(C1); free(C2); free(M); free(C1S);
        return -1;
    }

    frodo_unpack(S_T, S_T_packed, n_bar * n, log_q);
    /* S = transpose(S^T) -> (n x n_bar) */
    frodo_matrix_transpose(S, S_T, n_bar, n);

    /* Unpack ciphertext: C1 || C2 */
    uint32_t c1_packed_bytes = (n_bar * n * log_q + 7) / 8;
    frodo_unpack(C1, ct, n_bar * n, log_q);
    frodo_unpack(C2, ct + c1_packed_bytes, n_bar * n_bar, log_q);

    /* M = C2 - C1 * S mod q */
    frodo_matrix_mul(C1S, C1, n_bar, n, S, n_bar, q);
    frodo_matrix_sub(M, C2, C1S, n_bar, n_bar, q);

    /* Decode mu' */
    uint8_t mu_prime[FRODO_MAX_LEN_MU / 8 + 1];
    memset(mu_prime, 0, sizeof(mu_prime));
    frodo_decode(mu_prime, M, len_mu, b_param, q);

    /* Re-derive seedSE' and k': G(mu' || pkh) */
    uint8_t G_out[64];
    {
        pqc_shake256_ctx gctx;
        pqc_shake256_init(&gctx);
        pqc_shake256_absorb(&gctx, mu_prime, mu_bytes);
        pqc_shake256_absorb(&gctx, pkh, params->len_pkh);
        pqc_shake256_finalize(&gctx);
        pqc_shake256_squeeze(&gctx, G_out, params->len_seedse + params->len_k);
    }
    uint8_t *seedSE_prime = G_out;
    uint8_t *k_prime      = G_out + params->len_seedse;

    /* Expand seedSE' */
    uint8_t seedSE_expanded[1 + 64];
    seedSE_expanded[0] = 0x96;
    pqc_shake256(seedSE_expanded + 1, 64, seedSE_prime, params->len_seedse);

    /* Re-sample S', E', E'' */
    uint16_t *Sp_p  = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *Ep_p  = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *Epp_p = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));

    if (!Sp_p || !Ep_p || !Epp_p) {
        free(S_T); free(S); free(C1); free(C2); free(M); free(C1S);
        free(Sp_p); free(Ep_p); free(Epp_p);
        return -1;
    }

    frodo_sample_noise(Sp_p,  n_bar, n,     seedSE_expanded, 65, 0, q, cdf, cdf_len);
    frodo_sample_noise(Ep_p,  n_bar, n,     seedSE_expanded, 65, 1, q, cdf, cdf_len);
    frodo_sample_noise(Epp_p, n_bar, n_bar, seedSE_expanded, 65, 2, q, cdf, cdf_len);

    /* Re-generate A and B */
    const uint8_t *seedA = pk_stored;
    const uint8_t *B_packed = pk_stored + FRODO_SEED_A_BYTES;

    uint16_t *A  = (uint16_t *)calloc((size_t)n * n, sizeof(uint16_t));
    uint16_t *B  = (uint16_t *)calloc((size_t)n * n_bar, sizeof(uint16_t));
    uint16_t *C1_p = (uint16_t *)calloc((size_t)n_bar * n, sizeof(uint16_t));
    uint16_t *C2_p = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *V_p  = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));
    uint16_t *enc_mu = (uint16_t *)calloc((size_t)n_bar * n_bar, sizeof(uint16_t));

    if (!A || !B || !C1_p || !C2_p || !V_p || !enc_mu) {
        free(S_T); free(S); free(C1); free(C2); free(M); free(C1S);
        free(Sp_p); free(Ep_p); free(Epp_p);
        free(A); free(B); free(C1_p); free(C2_p); free(V_p); free(enc_mu);
        return -1;
    }

    frodo_gen_a(A, n, seedA, params->matrix_a_mode);
    frodo_unpack(B, B_packed, n * n_bar, log_q);

    /* C1' = Sp' * A + Ep' */
    frodo_matrix_mul(C1_p, Sp_p, n_bar, n, A, n, q);
    frodo_matrix_add(C1_p, C1_p, Ep_p, n_bar, n, q);

    /* V' = Sp' * B + Epp' */
    frodo_matrix_mul(V_p, Sp_p, n_bar, n, B, n_bar, q);
    frodo_matrix_add(V_p, V_p, Epp_p, n_bar, n_bar, q);

    /* C2' = V' + encode(mu') */
    frodo_encode(enc_mu, mu_prime, len_mu, b_param, q);
    frodo_matrix_add(C2_p, V_p, enc_mu, n_bar, n_bar, q);

    /* Compare C1 == C1' and C2 == C2' (constant time) */
    int valid = 1;
    {
        /* Pack both and compare bytes */
        uint8_t *ct_prime = (uint8_t *)calloc(params->ct_bytes, 1);
        if (ct_prime) {
            frodo_pack(ct_prime, C1_p, n_bar * n, log_q);
            frodo_pack(ct_prime + c1_packed_bytes, C2_p, n_bar * n_bar, log_q);
            if (pqc_memcmp_ct(ct, ct_prime, params->ct_bytes) != 0) {
                valid = 0;
            }
            free(ct_prime);
        } else {
            valid = 0;
        }
    }

    /* Compute shared secret */
    if (valid) {
        /* ss = SHAKE(ct || k' || pkh) */
        pqc_shake256_ctx sctx;
        pqc_shake256_init(&sctx);
        pqc_shake256_absorb(&sctx, ct, params->ct_bytes);
        pqc_shake256_absorb(&sctx, k_prime, params->len_k);
        pqc_shake256_absorb(&sctx, pkh, params->len_pkh);
        pqc_shake256_finalize(&sctx);
        pqc_shake256_squeeze(&sctx, ss, params->len_ss);
    } else {
        /* Implicit rejection: ss = SHAKE(ct || s || pkh) */
        pqc_shake256_ctx sctx;
        pqc_shake256_init(&sctx);
        pqc_shake256_absorb(&sctx, ct, params->ct_bytes);
        pqc_shake256_absorb(&sctx, s_val, params->len_s);
        pqc_shake256_absorb(&sctx, pkh, params->len_pkh);
        pqc_shake256_finalize(&sctx);
        pqc_shake256_squeeze(&sctx, ss, params->len_ss);
    }

    /* Cleanup */
    pqc_memzero(mu_prime, sizeof(mu_prime));
    pqc_memzero(G_out, sizeof(G_out));
    pqc_memzero(seedSE_expanded, sizeof(seedSE_expanded));
    pqc_memzero(S, (size_t)n * n_bar * sizeof(uint16_t));
    pqc_memzero(S_T, (size_t)n_bar * n * sizeof(uint16_t));
    pqc_memzero(Sp_p, (size_t)n_bar * n * sizeof(uint16_t));

    free(S_T); free(S); free(C1); free(C2); free(M); free(C1S);
    free(Sp_p); free(Ep_p); free(Epp_p);
    free(A); free(B); free(C1_p); free(C2_p); free(V_p); free(enc_mu);

    return valid ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Per-variant wrappers                                                 */
/* ------------------------------------------------------------------ */

/* --- FrodoKEM-640 --- */

static pqc_status_t frodo640aes_keygen(uint8_t *pk, uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_640(&p, FRODO_MATRIX_A_AES);
    frodo_keygen_internal(pk, sk, &p, frodo_640_cdf, FRODO_640_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo640aes_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    frodo_params_t p;
    frodo_params_init_640(&p, FRODO_MATRIX_A_AES);
    frodo_encaps_internal(ct, ss, pk, &p, frodo_640_cdf, FRODO_640_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo640aes_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_640(&p, FRODO_MATRIX_A_AES);
    int rc = frodo_decaps_internal(ss, ct, sk, &p, frodo_640_cdf, FRODO_640_CDF_LEN);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t frodo640shake_keygen(uint8_t *pk, uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_640(&p, FRODO_MATRIX_A_SHAKE);
    frodo_keygen_internal(pk, sk, &p, frodo_640_cdf, FRODO_640_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo640shake_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    frodo_params_t p;
    frodo_params_init_640(&p, FRODO_MATRIX_A_SHAKE);
    frodo_encaps_internal(ct, ss, pk, &p, frodo_640_cdf, FRODO_640_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo640shake_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_640(&p, FRODO_MATRIX_A_SHAKE);
    int rc = frodo_decaps_internal(ss, ct, sk, &p, frodo_640_cdf, FRODO_640_CDF_LEN);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

/* --- FrodoKEM-976 --- */

static pqc_status_t frodo976aes_keygen(uint8_t *pk, uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_976(&p, FRODO_MATRIX_A_AES);
    frodo_keygen_internal(pk, sk, &p, frodo_976_cdf, FRODO_976_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo976aes_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    frodo_params_t p;
    frodo_params_init_976(&p, FRODO_MATRIX_A_AES);
    frodo_encaps_internal(ct, ss, pk, &p, frodo_976_cdf, FRODO_976_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo976aes_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_976(&p, FRODO_MATRIX_A_AES);
    int rc = frodo_decaps_internal(ss, ct, sk, &p, frodo_976_cdf, FRODO_976_CDF_LEN);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t frodo976shake_keygen(uint8_t *pk, uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_976(&p, FRODO_MATRIX_A_SHAKE);
    frodo_keygen_internal(pk, sk, &p, frodo_976_cdf, FRODO_976_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo976shake_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    frodo_params_t p;
    frodo_params_init_976(&p, FRODO_MATRIX_A_SHAKE);
    frodo_encaps_internal(ct, ss, pk, &p, frodo_976_cdf, FRODO_976_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo976shake_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_976(&p, FRODO_MATRIX_A_SHAKE);
    int rc = frodo_decaps_internal(ss, ct, sk, &p, frodo_976_cdf, FRODO_976_CDF_LEN);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

/* --- FrodoKEM-1344 --- */

static pqc_status_t frodo1344aes_keygen(uint8_t *pk, uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_1344(&p, FRODO_MATRIX_A_AES);
    frodo_keygen_internal(pk, sk, &p, frodo_1344_cdf, FRODO_1344_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo1344aes_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    frodo_params_t p;
    frodo_params_init_1344(&p, FRODO_MATRIX_A_AES);
    frodo_encaps_internal(ct, ss, pk, &p, frodo_1344_cdf, FRODO_1344_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo1344aes_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_1344(&p, FRODO_MATRIX_A_AES);
    int rc = frodo_decaps_internal(ss, ct, sk, &p, frodo_1344_cdf, FRODO_1344_CDF_LEN);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t frodo1344shake_keygen(uint8_t *pk, uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_1344(&p, FRODO_MATRIX_A_SHAKE);
    frodo_keygen_internal(pk, sk, &p, frodo_1344_cdf, FRODO_1344_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo1344shake_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    frodo_params_t p;
    frodo_params_init_1344(&p, FRODO_MATRIX_A_SHAKE);
    frodo_encaps_internal(ct, ss, pk, &p, frodo_1344_cdf, FRODO_1344_CDF_LEN);
    return PQC_OK;
}

static pqc_status_t frodo1344shake_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    frodo_params_t p;
    frodo_params_init_1344(&p, FRODO_MATRIX_A_SHAKE);
    int rc = frodo_decaps_internal(ss, ct, sk, &p, frodo_1344_cdf, FRODO_1344_CDF_LEN);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t frodo640aes_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_640_AES,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = FRODO_640_PK_BYTES,
    .secret_key_size   = FRODO_640_SK_BYTES,
    .ciphertext_size   = FRODO_640_CT_BYTES,
    .shared_secret_size = FRODO_640_LEN_SS,
    .keygen = frodo640aes_keygen,
    .encaps = frodo640aes_encaps,
    .decaps = frodo640aes_decaps,
};

static const pqc_kem_vtable_t frodo640shake_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_640_SHAKE,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = FRODO_640_PK_BYTES,
    .secret_key_size   = FRODO_640_SK_BYTES,
    .ciphertext_size   = FRODO_640_CT_BYTES,
    .shared_secret_size = FRODO_640_LEN_SS,
    .keygen = frodo640shake_keygen,
    .encaps = frodo640shake_encaps,
    .decaps = frodo640shake_decaps,
};

static const pqc_kem_vtable_t frodo976aes_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_976_AES,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = FRODO_976_PK_BYTES,
    .secret_key_size   = FRODO_976_SK_BYTES,
    .ciphertext_size   = FRODO_976_CT_BYTES,
    .shared_secret_size = FRODO_976_LEN_SS,
    .keygen = frodo976aes_keygen,
    .encaps = frodo976aes_encaps,
    .decaps = frodo976aes_decaps,
};

static const pqc_kem_vtable_t frodo976shake_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_976_SHAKE,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = FRODO_976_PK_BYTES,
    .secret_key_size   = FRODO_976_SK_BYTES,
    .ciphertext_size   = FRODO_976_CT_BYTES,
    .shared_secret_size = FRODO_976_LEN_SS,
    .keygen = frodo976shake_keygen,
    .encaps = frodo976shake_encaps,
    .decaps = frodo976shake_decaps,
};

static const pqc_kem_vtable_t frodo1344aes_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_1344_AES,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = FRODO_1344_PK_BYTES,
    .secret_key_size   = FRODO_1344_SK_BYTES,
    .ciphertext_size   = FRODO_1344_CT_BYTES,
    .shared_secret_size = FRODO_1344_LEN_SS,
    .keygen = frodo1344aes_keygen,
    .encaps = frodo1344aes_encaps,
    .decaps = frodo1344aes_decaps,
};

static const pqc_kem_vtable_t frodo1344shake_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_1344_SHAKE,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = FRODO_1344_PK_BYTES,
    .secret_key_size   = FRODO_1344_SK_BYTES,
    .ciphertext_size   = FRODO_1344_CT_BYTES,
    .shared_secret_size = FRODO_1344_LEN_SS,
    .keygen = frodo1344shake_keygen,
    .encaps = frodo1344shake_encaps,
    .decaps = frodo1344shake_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_frodo_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&frodo640aes_vtable);
    rc |= pqc_kem_add_vtable(&frodo640shake_vtable);
    rc |= pqc_kem_add_vtable(&frodo976aes_vtable);
    rc |= pqc_kem_add_vtable(&frodo976shake_vtable);
    rc |= pqc_kem_add_vtable(&frodo1344aes_vtable);
    rc |= pqc_kem_add_vtable(&frodo1344shake_vtable);
    return rc;
}
