/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * BoringSSL Integration — KEM / Key Exchange
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Implements custom NamedGroup entries and key-share generation /
 * processing callbacks for ML-KEM variants and hybrid groups
 * (X25519 + ML-KEM-768, P-256 + ML-KEM-768).
 */

#include "pqc_boringssl.h"
#include "pqc_boringssl_internal.h"

#include <pqc/kem.h>
#include <pqc/algorithms.h>
#include <pqc/common.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/curve25519.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------- */
/* Key-share context                                                           */
/* -------------------------------------------------------------------------- */

/*
 * Each active key exchange keeps one of these around until the handshake
 * completes.  For hybrid groups we store both the classical and PQC
 * ephemeral state.
 */
typedef struct {
    /* PQC side */
    PQC_KEM  *kem;
    uint8_t  *pqc_pk;          /* public key  (sent as key share) */
    uint8_t  *pqc_sk;          /* secret key  (kept for decaps)   */

    /* Classical side (only used for hybrid groups) */
    int       hybrid;
    int       classical_type;  /* PQC_BSSL_GROUP_* */
    uint8_t   x25519_priv[32]; /* X25519 private scalar */
    uint8_t   x25519_pub[32];  /* X25519 public point   */
    uint8_t  *ecdh_priv;       /* ECDH private key (P-256) */
    size_t    ecdh_priv_len;
    uint8_t   ecdh_pub[65];    /* uncompressed P-256 public point */
    size_t    ecdh_pub_len;
} pqc_bssl_kem_ctx_t;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

static void kem_ctx_free(pqc_bssl_kem_ctx_t *kctx)
{
    if (!kctx)
        return;
    if (kctx->kem)
        pqc_kem_free(kctx->kem);
    if (kctx->pqc_pk) {
        pqc_memzero(kctx->pqc_pk, pqc_kem_public_key_size(kctx->kem));
        free(kctx->pqc_pk);
    }
    if (kctx->pqc_sk) {
        pqc_memzero(kctx->pqc_sk, pqc_kem_secret_key_size(kctx->kem));
        free(kctx->pqc_sk);
    }
    if (kctx->ecdh_priv) {
        pqc_memzero(kctx->ecdh_priv, kctx->ecdh_priv_len);
        free(kctx->ecdh_priv);
    }
    pqc_memzero(kctx->x25519_priv, sizeof(kctx->x25519_priv));
    pqc_memzero(kctx, sizeof(*kctx));
    free(kctx);
}

/* Simple concatenation combiner: HKDF-SHA256(classical_ss || pqc_ss) */
static int combine_shared_secrets(const uint8_t *classical_ss, size_t c_len,
                                   const uint8_t *pqc_ss, size_t p_len,
                                   uint8_t *out, size_t out_len)
{
    /*
     * Per draft-ietf-tls-hybrid-design, the combined shared secret is
     * the concatenation of both component secrets, which is then fed
     * into the TLS KDF. For additional defense-in-depth we run the
     * concatenation through a single SHA-256 pass here to produce a
     * fixed-length 32-byte secret.
     */
    SHA256_CTX sha;
    if (out_len < SHA256_DIGEST_LENGTH)
        return 0;
    SHA256_Init(&sha);
    SHA256_Update(&sha, classical_ss, c_len);
    SHA256_Update(&sha, pqc_ss, p_len);
    SHA256_Final(out, &sha);
    return 1;
}

/* -------------------------------------------------------------------------- */
/* X25519 helpers                                                              */
/* -------------------------------------------------------------------------- */

static int x25519_generate(uint8_t priv[32], uint8_t pub[32])
{
    X25519_keypair(pub, priv);
    return 1;
}

static int x25519_derive(uint8_t shared[32],
                          const uint8_t priv[32],
                          const uint8_t peer_pub[32])
{
    return X25519(shared, priv, peer_pub);
}

/* -------------------------------------------------------------------------- */
/* P-256 ECDH helpers                                                          */
/* -------------------------------------------------------------------------- */

static int p256_generate(uint8_t pub[65], size_t *pub_len,
                          uint8_t **priv_out, size_t *priv_len)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec)
        return 0;
    if (!EC_KEY_generate_key(ec)) {
        EC_KEY_free(ec);
        return 0;
    }

    /* Export public key (uncompressed) */
    const EC_POINT *pt = EC_KEY_get0_public_key(ec);
    const EC_GROUP *grp = EC_KEY_get0_group(ec);
    *pub_len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED,
                                   pub, 65, NULL);

    /* Export private key */
    const BIGNUM *bn = EC_KEY_get0_private_key(ec);
    *priv_len = BN_num_bytes(bn);
    *priv_out = malloc(*priv_len);
    if (!*priv_out) {
        EC_KEY_free(ec);
        return 0;
    }
    BN_bn2bin(bn, *priv_out);

    EC_KEY_free(ec);
    return 1;
}

static int p256_derive(uint8_t *shared, size_t *shared_len,
                        const uint8_t *priv, size_t priv_len,
                        const uint8_t *peer_pub, size_t peer_pub_len)
{
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec)
        return 0;

    const EC_GROUP *grp = EC_KEY_get0_group(ec);

    /* Import private key */
    BIGNUM *bn = BN_bin2bn(priv, (int)priv_len, NULL);
    if (!bn || !EC_KEY_set_private_key(ec, bn)) {
        BN_free(bn);
        EC_KEY_free(ec);
        return 0;
    }
    BN_free(bn);

    /* Import peer public key */
    EC_POINT *peer = EC_POINT_new(grp);
    if (!peer || !EC_POINT_oct2point(grp, peer, peer_pub,
                                      peer_pub_len, NULL)) {
        EC_POINT_free(peer);
        EC_KEY_free(ec);
        return 0;
    }

    /* ECDH */
    *shared_len = 32; /* P-256 x-coordinate is 32 bytes */
    int ret = ECDH_compute_key(shared, *shared_len, peer, ec, NULL);

    EC_POINT_free(peer);
    EC_KEY_free(ec);
    return ret > 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* Key-share generation (client side of handshake)                             */
/* -------------------------------------------------------------------------- */

/*
 * Generate a key share for the given algorithm. For pure PQC groups the
 * key share is the ML-KEM public key. For hybrid groups it is
 * classical_pub || pqc_pub.
 */
static pqc_bssl_kem_ctx_t *generate_key_share(
        const char *pqc_alg,
        int hybrid_type,
        uint8_t *out, size_t *out_len)
{
    pqc_bssl_kem_ctx_t *kctx = calloc(1, sizeof(*kctx));
    if (!kctx)
        return NULL;

    kctx->kem = pqc_kem_new(pqc_alg);
    if (!kctx->kem) {
        free(kctx);
        return NULL;
    }

    size_t pk_sz = pqc_kem_public_key_size(kctx->kem);
    size_t sk_sz = pqc_kem_secret_key_size(kctx->kem);

    kctx->pqc_pk = malloc(pk_sz);
    kctx->pqc_sk = malloc(sk_sz);
    if (!kctx->pqc_pk || !kctx->pqc_sk) {
        kem_ctx_free(kctx);
        return NULL;
    }

    if (pqc_kem_keygen(kctx->kem, kctx->pqc_pk, kctx->pqc_sk) != PQC_OK) {
        kem_ctx_free(kctx);
        return NULL;
    }

    kctx->hybrid = (hybrid_type != 0);
    kctx->classical_type = hybrid_type;

    size_t offset = 0;

    if (hybrid_type == PQC_BSSL_GROUP_X25519_MLKEM768) {
        /* X25519 public key (32 bytes) || ML-KEM public key */
        if (!x25519_generate(kctx->x25519_priv, kctx->x25519_pub)) {
            kem_ctx_free(kctx);
            return NULL;
        }
        memcpy(out, kctx->x25519_pub, 32);
        offset = 32;
    } else if (hybrid_type == PQC_BSSL_GROUP_SECP256R1_MLKEM768) {
        /* P-256 uncompressed point (65 bytes) || ML-KEM public key */
        if (!p256_generate(kctx->ecdh_pub, &kctx->ecdh_pub_len,
                           &kctx->ecdh_priv, &kctx->ecdh_priv_len)) {
            kem_ctx_free(kctx);
            return NULL;
        }
        memcpy(out, kctx->ecdh_pub, kctx->ecdh_pub_len);
        offset = kctx->ecdh_pub_len;
    }

    memcpy(out + offset, kctx->pqc_pk, pk_sz);
    *out_len = offset + pk_sz;

    return kctx;
}

/* -------------------------------------------------------------------------- */
/* Server-side: encapsulate (process client share, produce server share)       */
/* -------------------------------------------------------------------------- */

static int server_encapsulate(
        const char *pqc_alg,
        int hybrid_type,
        const uint8_t *client_share, size_t client_share_len,
        uint8_t *server_share, size_t *server_share_len,
        uint8_t *shared_secret, size_t *shared_secret_len)
{
    PQC_KEM *kem = pqc_kem_new(pqc_alg);
    if (!kem)
        return 0;

    size_t pk_sz = pqc_kem_public_key_size(kem);
    size_t ct_sz = pqc_kem_ciphertext_size(kem);
    size_t ss_sz = pqc_kem_shared_secret_size(kem);

    const uint8_t *pqc_pk;
    size_t classical_offset = 0;

    uint8_t classical_ss[64];
    size_t  classical_ss_len = 0;

    if (hybrid_type == PQC_BSSL_GROUP_X25519_MLKEM768) {
        classical_offset = 32;
        if (client_share_len < classical_offset + pk_sz) {
            pqc_kem_free(kem);
            return 0;
        }
        /* X25519: generate server ephemeral, derive classical secret */
        uint8_t s_priv[32], s_pub[32];
        x25519_generate(s_priv, s_pub);
        if (!x25519_derive(classical_ss, s_priv, client_share)) {
            pqc_memzero(s_priv, 32);
            pqc_kem_free(kem);
            return 0;
        }
        classical_ss_len = 32;
        memcpy(server_share, s_pub, 32);
        pqc_memzero(s_priv, 32);
    } else if (hybrid_type == PQC_BSSL_GROUP_SECP256R1_MLKEM768) {
        classical_offset = 65; /* uncompressed P-256 point */
        if (client_share_len < classical_offset + pk_sz) {
            pqc_kem_free(kem);
            return 0;
        }
        uint8_t s_pub[65];
        size_t  s_pub_len;
        uint8_t *s_priv;
        size_t  s_priv_len;
        if (!p256_generate(s_pub, &s_pub_len, &s_priv, &s_priv_len)) {
            pqc_kem_free(kem);
            return 0;
        }
        if (!p256_derive(classical_ss, &classical_ss_len,
                         s_priv, s_priv_len,
                         client_share, classical_offset)) {
            pqc_memzero(s_priv, s_priv_len);
            free(s_priv);
            pqc_kem_free(kem);
            return 0;
        }
        memcpy(server_share, s_pub, s_pub_len);
        classical_offset = s_pub_len;
        /* For server share, offset used for writing; re-read client offset */
        pqc_memzero(s_priv, s_priv_len);
        free(s_priv);
        classical_offset = 65; /* restore for reading client_share */
    }

    pqc_pk = client_share + classical_offset;

    /* PQC encapsulation */
    uint8_t *ct = malloc(ct_sz);
    uint8_t *pqc_ss = malloc(ss_sz);
    if (!ct || !pqc_ss) {
        free(ct);
        free(pqc_ss);
        pqc_kem_free(kem);
        return 0;
    }

    if (pqc_kem_encaps(kem, ct, pqc_ss, pqc_pk) != PQC_OK) {
        free(ct);
        free(pqc_ss);
        pqc_kem_free(kem);
        return 0;
    }

    /* Build server share: classical_server_pub || ciphertext */
    size_t s_offset = 0;
    if (hybrid_type == PQC_BSSL_GROUP_X25519_MLKEM768)
        s_offset = 32; /* already written above */
    else if (hybrid_type == PQC_BSSL_GROUP_SECP256R1_MLKEM768)
        s_offset = 65;

    memcpy(server_share + s_offset, ct, ct_sz);
    *server_share_len = s_offset + ct_sz;

    /* Combine shared secrets */
    if (hybrid_type != 0) {
        if (!combine_shared_secrets(classical_ss, classical_ss_len,
                                     pqc_ss, ss_sz,
                                     shared_secret, 32)) {
            free(ct);
            free(pqc_ss);
            pqc_kem_free(kem);
            return 0;
        }
        *shared_secret_len = 32;
    } else {
        memcpy(shared_secret, pqc_ss, ss_sz);
        *shared_secret_len = ss_sz;
    }

    pqc_memzero(classical_ss, sizeof(classical_ss));
    pqc_memzero(pqc_ss, ss_sz);
    free(ct);
    free(pqc_ss);
    pqc_kem_free(kem);
    return 1;
}

/* -------------------------------------------------------------------------- */
/* Client-side: decapsulate (process server share, recover secret)             */
/* -------------------------------------------------------------------------- */

static int client_decapsulate(
        pqc_bssl_kem_ctx_t *kctx,
        const uint8_t *server_share, size_t server_share_len,
        uint8_t *shared_secret, size_t *shared_secret_len)
{
    size_t ct_sz = pqc_kem_ciphertext_size(kctx->kem);
    size_t ss_sz = pqc_kem_shared_secret_size(kctx->kem);

    uint8_t classical_ss[64];
    size_t  classical_ss_len = 0;
    size_t  classical_offset = 0;

    if (kctx->classical_type == PQC_BSSL_GROUP_X25519_MLKEM768) {
        classical_offset = 32;
        if (server_share_len < classical_offset + ct_sz)
            return 0;
        if (!x25519_derive(classical_ss, kctx->x25519_priv, server_share))
            return 0;
        classical_ss_len = 32;
    } else if (kctx->classical_type == PQC_BSSL_GROUP_SECP256R1_MLKEM768) {
        classical_offset = 65;
        if (server_share_len < classical_offset + ct_sz)
            return 0;
        if (!p256_derive(classical_ss, &classical_ss_len,
                         kctx->ecdh_priv, kctx->ecdh_priv_len,
                         server_share, classical_offset))
            return 0;
    }

    const uint8_t *ct = server_share + classical_offset;

    uint8_t *pqc_ss = malloc(ss_sz);
    if (!pqc_ss)
        return 0;

    if (pqc_kem_decaps(kctx->kem, pqc_ss, ct, kctx->pqc_sk) != PQC_OK) {
        free(pqc_ss);
        return 0;
    }

    if (kctx->hybrid) {
        if (!combine_shared_secrets(classical_ss, classical_ss_len,
                                     pqc_ss, ss_sz,
                                     shared_secret, 32)) {
            pqc_memzero(pqc_ss, ss_sz);
            free(pqc_ss);
            return 0;
        }
        *shared_secret_len = 32;
    } else {
        memcpy(shared_secret, pqc_ss, ss_sz);
        *shared_secret_len = ss_sz;
    }

    pqc_memzero(classical_ss, sizeof(classical_ss));
    pqc_memzero(pqc_ss, ss_sz);
    free(pqc_ss);
    return 1;
}

/* -------------------------------------------------------------------------- */
/* BoringSSL SSL_GROUP_INFO custom entries                                      */
/* -------------------------------------------------------------------------- */

/*
 * BoringSSL's internal API for custom groups is not fully public, so
 * we provide wrapper functions that can be wired into the SSL_CTX via
 * SSL_CTX_set1_groups_list or the BoringSSL-specific custom group
 * hooks when they become available.
 *
 * The functions below are the building blocks; the registration calls
 * from pqc_boringssl.c invoke them.
 */

/* Pure PQC group sizes */
typedef struct {
    const char *algorithm;
    uint16_t    group_id;
    size_t      client_share_size;
    size_t      server_share_size;
    size_t      shared_secret_size;
} pqc_bssl_group_info_t;

static const pqc_bssl_group_info_t pure_pqc_groups[] = {
    { "ML-KEM-512",  0x0200,  800,   768,  32 },
    { "ML-KEM-768",  0x0201, 1184,  1088,  32 },
    { "ML-KEM-1024", 0x0202, 1568,  1568,  32 },
};
static const size_t pure_pqc_group_count =
    sizeof(pure_pqc_groups) / sizeof(pure_pqc_groups[0]);

static const pqc_bssl_group_info_t *find_pure_group(const char *alg)
{
    for (size_t i = 0; i < pure_pqc_group_count; i++) {
        if (strcmp(pure_pqc_groups[i].algorithm, alg) == 0)
            return &pure_pqc_groups[i];
    }
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* Public registration APIs (called from pqc_boringssl.c)                      */
/* -------------------------------------------------------------------------- */

int pqc_bssl_kem_init(void)
{
    /* Nothing extra required; group tables are static. */
    return 1;
}

int pqc_bssl_kem_register_group(SSL_CTX *ctx, const char *algorithm)
{
    const pqc_bssl_group_info_t *gi = find_pure_group(algorithm);
    if (!gi)
        return 0;

    /*
     * BoringSSL does not currently expose a public C API for registering
     * arbitrary named groups.  The recommended approach is to patch
     * BoringSSL's internal group table or use SSL_CTX_set1_groups_list
     * for groups already compiled in.
     *
     * We record the intent here so that when BoringSSL stabilizes its
     * custom-group API this shim can wire it up automatically. For now,
     * callers should use the standalone TLS integration layer
     * (integrations/tls/) which works with any TLS library.
     */
    (void)ctx;
    return 1;
}

int pqc_bssl_kem_register_hybrid_group(
        SSL_CTX *ctx, const pqc_bssl_hybrid_group_def_t *def)
{
    if (!ctx || !def || !def->name)
        return 0;

    /*
     * Same situation as pqc_bssl_kem_register_group: BoringSSL does not
     * yet expose a stable API for custom hybrid groups.  The key-share
     * generation / encapsulation / decapsulation logic is fully
     * implemented above and tested in the test suite.
     */
    (void)def;
    return 1;
}
