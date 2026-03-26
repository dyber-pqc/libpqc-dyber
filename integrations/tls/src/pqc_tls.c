/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * TLS Integration — Main key-share lifecycle and hybrid combiner
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#include "pqc_tls.h"
#include "pqc_tls_internal.h"

#include <pqc/kem.h>
#include <pqc/sig.h>
#include <pqc/common.h>
#include <pqc/algorithms.h>

#include <string.h>
#include <stdlib.h>

#ifdef PQC_TLS_HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/curve25519.h>
#endif

/* -------------------------------------------------------------------------- */
/* Classical crypto (conditionally compiled with OpenSSL / BoringSSL)           */
/* -------------------------------------------------------------------------- */

#ifdef PQC_TLS_HAVE_OPENSSL

int pqc_tls_classical_keygen(int type,
                              uint8_t *pub, size_t *pub_len,
                              uint8_t *priv, size_t *priv_len)
{
    if (type == PQC_TLS_CLASSICAL_X25519) {
        /* X25519: priv = 32 random bytes, pub = X25519(priv, basepoint) */
        X25519_keypair(pub, priv);
        *pub_len  = 32;
        *priv_len = 32;
        return 0;
    }

    if (type == PQC_TLS_CLASSICAL_P256) {
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec)
            return -1;
        if (!EC_KEY_generate_key(ec)) {
            EC_KEY_free(ec);
            return -1;
        }
        const EC_POINT *pt  = EC_KEY_get0_public_key(ec);
        const EC_GROUP *grp = EC_KEY_get0_group(ec);
        *pub_len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED,
                                       pub, 65, NULL);
        const BIGNUM *bn = EC_KEY_get0_private_key(ec);
        *priv_len = (size_t)BN_num_bytes(bn);
        BN_bn2bin(bn, priv);
        EC_KEY_free(ec);
        return 0;
    }

    return -1;
}

int pqc_tls_classical_derive(int type,
                              const uint8_t *priv, size_t priv_len,
                              const uint8_t *peer_pub, size_t peer_pub_len,
                              uint8_t *ss, size_t *ss_len)
{
    (void)priv_len;

    if (type == PQC_TLS_CLASSICAL_X25519) {
        (void)peer_pub_len;
        if (!X25519(ss, priv, peer_pub))
            return -1;
        *ss_len = 32;
        return 0;
    }

    if (type == PQC_TLS_CLASSICAL_P256) {
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec)
            return -1;
        const EC_GROUP *grp = EC_KEY_get0_group(ec);

        BIGNUM *bn = BN_bin2bn(priv, (int)priv_len, NULL);
        if (!bn || !EC_KEY_set_private_key(ec, bn)) {
            BN_free(bn);
            EC_KEY_free(ec);
            return -1;
        }
        BN_free(bn);

        EC_POINT *peer = EC_POINT_new(grp);
        if (!peer || !EC_POINT_oct2point(grp, peer, peer_pub,
                                          peer_pub_len, NULL)) {
            EC_POINT_free(peer);
            EC_KEY_free(ec);
            return -1;
        }

        int ret = ECDH_compute_key(ss, 32, peer, ec, NULL);
        EC_POINT_free(peer);
        EC_KEY_free(ec);
        if (ret <= 0)
            return -1;
        *ss_len = 32;
        return 0;
    }

    return -1;
}

/* SHA-256 based combiner for hybrid shared secrets */
static int combine_secrets(const uint8_t *c_ss, size_t c_len,
                            const uint8_t *p_ss, size_t p_len,
                            uint8_t *out, size_t *out_len)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, c_ss, c_len);
    SHA256_Update(&sha, p_ss, p_len);
    SHA256_Final(out, &sha);
    *out_len = 32;
    return 0;
}

#else /* !PQC_TLS_HAVE_OPENSSL */

/* Stubs when no classical crypto library is linked */
int pqc_tls_classical_keygen(int type,
                              uint8_t *pub, size_t *pub_len,
                              uint8_t *priv, size_t *priv_len)
{
    (void)type; (void)pub; (void)pub_len;
    (void)priv; (void)priv_len;
    return -1; /* not available */
}

int pqc_tls_classical_derive(int type,
                              const uint8_t *priv, size_t priv_len,
                              const uint8_t *peer_pub, size_t peer_pub_len,
                              uint8_t *ss, size_t *ss_len)
{
    (void)type; (void)priv; (void)priv_len;
    (void)peer_pub; (void)peer_pub_len;
    (void)ss; (void)ss_len;
    return -1;
}

/*
 * Fallback combiner: simple concatenation when no hash library is
 * available. The TLS KDF will hash the combined secret anyway.
 */
static int combine_secrets(const uint8_t *c_ss, size_t c_len,
                            const uint8_t *p_ss, size_t p_len,
                            uint8_t *out, size_t *out_len)
{
    memcpy(out, c_ss, c_len);
    memcpy(out + c_len, p_ss, p_len);
    *out_len = c_len + p_len;
    return 0;
}

#endif /* PQC_TLS_HAVE_OPENSSL */

/* -------------------------------------------------------------------------- */
/* Key-share lifecycle                                                         */
/* -------------------------------------------------------------------------- */

PQC_TLS_KeyShare *pqc_tls_keyshare_new(uint16_t group_id)
{
    const pqc_tls_group_def_t *gd = pqc_tls_find_group(group_id);
    if (!gd)
        return NULL;

    PQC_TLS_KeyShare *ks = calloc(1, sizeof(*ks));
    if (!ks)
        return NULL;

    ks->group = gd;

    ks->kem = pqc_kem_new(gd->pqc_algorithm);
    if (!ks->kem) {
        free(ks);
        return NULL;
    }

    return ks;
}

void pqc_tls_keyshare_free(PQC_TLS_KeyShare *ks)
{
    if (!ks)
        return;

    if (ks->pqc_pk) {
        pqc_memzero(ks->pqc_pk, ks->group->pqc_pk_size);
        free(ks->pqc_pk);
    }
    if (ks->pqc_sk) {
        pqc_memzero(ks->pqc_sk, pqc_kem_secret_key_size(ks->kem));
        free(ks->pqc_sk);
    }
    if (ks->classical_priv) {
        pqc_memzero(ks->classical_priv, ks->classical_priv_len);
        free(ks->classical_priv);
    }
    if (ks->classical_pub)
        free(ks->classical_pub);

    pqc_kem_free(ks->kem);
    pqc_memzero(ks, sizeof(*ks));
    free(ks);
}

/* -------------------------------------------------------------------------- */
/* Client: generate key share for ClientHello                                  */
/* -------------------------------------------------------------------------- */

int pqc_tls_keyshare_generate(PQC_TLS_KeyShare *ks,
                               uint8_t *key_share_out,
                               size_t *key_share_len)
{
    if (!ks || !key_share_out || !key_share_len)
        return -1;

    const pqc_tls_group_def_t *gd = ks->group;
    size_t needed = gd->pqc_pk_size;
    if (gd->is_hybrid)
        needed += gd->classical_pk_size;

    if (*key_share_len < needed)
        return -1;

    size_t offset = 0;

    /* Classical component (if hybrid) */
    if (gd->is_hybrid) {
        ks->classical_pub  = malloc(gd->classical_pk_size);
        ks->classical_priv = malloc(64); /* large enough for any key */
        if (!ks->classical_pub || !ks->classical_priv)
            return -1;

        if (pqc_tls_classical_keygen(gd->classical_type,
                                      ks->classical_pub,
                                      &ks->classical_pub_len,
                                      ks->classical_priv,
                                      &ks->classical_priv_len) != 0)
            return -1;

        memcpy(key_share_out, ks->classical_pub, ks->classical_pub_len);
        offset = ks->classical_pub_len;
    }

    /* PQC component */
    size_t pk_sz = pqc_kem_public_key_size(ks->kem);
    size_t sk_sz = pqc_kem_secret_key_size(ks->kem);

    ks->pqc_pk = malloc(pk_sz);
    ks->pqc_sk = malloc(sk_sz);
    if (!ks->pqc_pk || !ks->pqc_sk)
        return -1;

    if (pqc_kem_keygen(ks->kem, ks->pqc_pk, ks->pqc_sk) != PQC_OK)
        return -1;

    memcpy(key_share_out + offset, ks->pqc_pk, pk_sz);
    *key_share_len = offset + pk_sz;
    ks->generated = 1;

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Server: encapsulate — process client share, produce server share + secret   */
/* -------------------------------------------------------------------------- */

int pqc_tls_keyshare_encapsulate(
        PQC_TLS_KeyShare *ks,
        const uint8_t *client_share, size_t client_share_len,
        uint8_t *server_share_out, size_t *server_share_len,
        uint8_t *shared_secret_out, size_t *shared_secret_len)
{
    if (!ks || !client_share || !server_share_out ||
        !server_share_len || !shared_secret_out || !shared_secret_len)
        return -1;

    const pqc_tls_group_def_t *gd = ks->group;

    size_t c_offset = 0; /* offset into client_share for PQC pk */
    size_t s_offset = 0; /* offset into server_share for PQC ct */

    uint8_t classical_ss[64];
    size_t  classical_ss_len = 0;

    /* --- hybrid classical component --- */
    if (gd->is_hybrid) {
        c_offset = gd->classical_pk_size;
        if (client_share_len < c_offset + gd->pqc_pk_size)
            return -1;

        /* Generate server ephemeral classical key */
        uint8_t s_pub[65];
        size_t  s_pub_len = 0;
        uint8_t s_priv[64];
        size_t  s_priv_len = 0;

        if (pqc_tls_classical_keygen(gd->classical_type,
                                      s_pub, &s_pub_len,
                                      s_priv, &s_priv_len) != 0)
            return -1;

        /* Derive classical shared secret */
        if (pqc_tls_classical_derive(gd->classical_type,
                                      s_priv, s_priv_len,
                                      client_share, c_offset,
                                      classical_ss,
                                      &classical_ss_len) != 0) {
            pqc_memzero(s_priv, sizeof(s_priv));
            return -1;
        }

        /* Write classical server public key */
        memcpy(server_share_out, s_pub, s_pub_len);
        s_offset = s_pub_len;
        pqc_memzero(s_priv, sizeof(s_priv));
    } else {
        if (client_share_len < gd->pqc_pk_size)
            return -1;
    }

    /* --- PQC encapsulation --- */
    const uint8_t *pqc_pk = client_share + c_offset;

    size_t ct_sz = pqc_kem_ciphertext_size(ks->kem);
    size_t ss_sz = pqc_kem_shared_secret_size(ks->kem);

    if (*server_share_len < s_offset + ct_sz)
        return -1;

    uint8_t *pqc_ss = malloc(ss_sz);
    if (!pqc_ss)
        return -1;

    if (pqc_kem_encaps(ks->kem,
                        server_share_out + s_offset,
                        pqc_ss,
                        pqc_pk) != PQC_OK) {
        free(pqc_ss);
        return -1;
    }

    *server_share_len = s_offset + ct_sz;

    /* --- combine shared secrets --- */
    if (gd->is_hybrid) {
        if (combine_secrets(classical_ss, classical_ss_len,
                            pqc_ss, ss_sz,
                            shared_secret_out,
                            shared_secret_len) != 0) {
            pqc_memzero(pqc_ss, ss_sz);
            free(pqc_ss);
            return -1;
        }
    } else {
        if (*shared_secret_len < ss_sz) {
            pqc_memzero(pqc_ss, ss_sz);
            free(pqc_ss);
            return -1;
        }
        memcpy(shared_secret_out, pqc_ss, ss_sz);
        *shared_secret_len = ss_sz;
    }

    pqc_memzero(classical_ss, sizeof(classical_ss));
    pqc_memzero(pqc_ss, ss_sz);
    free(pqc_ss);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Client: decapsulate — process server share, recover shared secret           */
/* -------------------------------------------------------------------------- */

int pqc_tls_keyshare_decapsulate(
        PQC_TLS_KeyShare *ks,
        const uint8_t *server_share, size_t server_share_len,
        uint8_t *shared_secret_out, size_t *shared_secret_len)
{
    if (!ks || !server_share || !shared_secret_out || !shared_secret_len)
        return -1;
    if (!ks->generated)
        return -1;

    const pqc_tls_group_def_t *gd = ks->group;

    size_t s_offset = 0; /* offset into server_share for PQC ct */

    uint8_t classical_ss[64];
    size_t  classical_ss_len = 0;

    /* --- hybrid classical component --- */
    if (gd->is_hybrid) {
        s_offset = gd->classical_pk_size;
        if (server_share_len < s_offset + gd->pqc_ct_size)
            return -1;

        if (pqc_tls_classical_derive(gd->classical_type,
                                      ks->classical_priv,
                                      ks->classical_priv_len,
                                      server_share, s_offset,
                                      classical_ss,
                                      &classical_ss_len) != 0)
            return -1;
    } else {
        if (server_share_len < gd->pqc_ct_size)
            return -1;
    }

    /* --- PQC decapsulation --- */
    const uint8_t *ct = server_share + s_offset;
    size_t ss_sz = pqc_kem_shared_secret_size(ks->kem);

    uint8_t *pqc_ss = malloc(ss_sz);
    if (!pqc_ss)
        return -1;

    if (pqc_kem_decaps(ks->kem, pqc_ss, ct, ks->pqc_sk) != PQC_OK) {
        free(pqc_ss);
        return -1;
    }

    /* --- combine --- */
    if (gd->is_hybrid) {
        if (combine_secrets(classical_ss, classical_ss_len,
                            pqc_ss, ss_sz,
                            shared_secret_out,
                            shared_secret_len) != 0) {
            pqc_memzero(pqc_ss, ss_sz);
            free(pqc_ss);
            return -1;
        }
    } else {
        if (*shared_secret_len < ss_sz) {
            pqc_memzero(pqc_ss, ss_sz);
            free(pqc_ss);
            return -1;
        }
        memcpy(shared_secret_out, pqc_ss, ss_sz);
        *shared_secret_len = ss_sz;
    }

    pqc_memzero(classical_ss, sizeof(classical_ss));
    pqc_memzero(pqc_ss, ss_sz);
    free(pqc_ss);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Signature helpers                                                           */
/* -------------------------------------------------------------------------- */

int pqc_tls_sign(uint16_t sig_alg,
                  const uint8_t *sk, size_t sk_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t *sig_out, size_t *sig_len)
{
    const pqc_tls_sigalg_def_t *sa = pqc_tls_find_sigalg(sig_alg);
    if (!sa)
        return -1;
    if (sk_len < sa->sk_size)
        return -1;

    PQC_SIG *sig = pqc_sig_new(sa->pqc_algorithm);
    if (!sig)
        return -1;

    pqc_status_t rc = pqc_sig_sign(sig, sig_out, sig_len,
                                    msg, msg_len, sk);
    pqc_sig_free(sig);
    return rc == PQC_OK ? 0 : -1;
}

int pqc_tls_verify(uint16_t sig_alg,
                    const uint8_t *pk, size_t pk_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sig, size_t sig_len)
{
    const pqc_tls_sigalg_def_t *sa = pqc_tls_find_sigalg(sig_alg);
    if (!sa)
        return -1;
    if (pk_len < sa->pk_size)
        return -1;

    PQC_SIG *sig_ctx = pqc_sig_new(sa->pqc_algorithm);
    if (!sig_ctx)
        return -1;

    pqc_status_t rc = pqc_sig_verify(sig_ctx, msg, msg_len,
                                      sig, sig_len, pk);
    pqc_sig_free(sig_ctx);
    return rc == PQC_OK ? 0 : -1;
}

/* -------------------------------------------------------------------------- */
/* Size queries                                                                */
/* -------------------------------------------------------------------------- */

size_t pqc_tls_group_client_share_size(uint16_t group_id)
{
    const pqc_tls_group_def_t *gd = pqc_tls_find_group(group_id);
    if (!gd)
        return 0;
    return gd->pqc_pk_size + (gd->is_hybrid ? gd->classical_pk_size : 0);
}

size_t pqc_tls_group_server_share_size(uint16_t group_id)
{
    const pqc_tls_group_def_t *gd = pqc_tls_find_group(group_id);
    if (!gd)
        return 0;
    return gd->pqc_ct_size + (gd->is_hybrid ? gd->classical_pk_size : 0);
}

size_t pqc_tls_group_shared_secret_size(uint16_t group_id)
{
    const pqc_tls_group_def_t *gd = pqc_tls_find_group(group_id);
    if (!gd)
        return 0;
    if (gd->is_hybrid)
        return 32; /* SHA-256 output */
    return gd->pqc_ss_size;
}

const char *pqc_tls_group_name(uint16_t group_id)
{
    const pqc_tls_group_def_t *gd = pqc_tls_find_group(group_id);
    return gd ? gd->name : NULL;
}

const char *pqc_tls_sigalg_name(uint16_t sig_alg)
{
    const pqc_tls_sigalg_def_t *sa = pqc_tls_find_sigalg(sig_alg);
    return sa ? sa->name : NULL;
}
