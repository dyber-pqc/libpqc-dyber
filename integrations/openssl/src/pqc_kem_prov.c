/*
 * libpqc-dyber OpenSSL 3.x Provider — KEM Operations
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Implements OSSL_OP_KEM dispatch for all PQC KEM algorithms.
 */

#include "pqc_provider.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

/* ========================================================================== */
/* KEM operation context                                                       */
/* ========================================================================== */

typedef struct {
    PQC_PROV_CTX *provctx;
    PQC_PROV_KEY *key;           /* borrowed reference — we up_ref */
    PQC_KEM      *kem;           /* owned copy for the operation */
    int           op;            /* 0 = unset, 1 = encaps, 2 = decaps */
} PQC_KEM_CTX;

/* ========================================================================== */
/* newctx / freectx                                                            */
/* ========================================================================== */

static void *pqc_kem_newctx(void *provctx)
{
    PQC_KEM_CTX *ctx = OPENSSL_zalloc(sizeof(PQC_KEM_CTX));
    if (ctx != NULL)
        ctx->provctx = (PQC_PROV_CTX *)provctx;
    return ctx;
}

static void pqc_kem_freectx(void *vctx)
{
    PQC_KEM_CTX *ctx = (PQC_KEM_CTX *)vctx;
    if (ctx == NULL)
        return;
    if (ctx->kem != NULL)
        pqc_kem_free(ctx->kem);
    if (ctx->key != NULL)
        pqc_prov_key_free(ctx->key);
    OPENSSL_free(ctx);
}

static void *pqc_kem_dupctx(void *vctx)
{
    PQC_KEM_CTX *src = (PQC_KEM_CTX *)vctx;
    PQC_KEM_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(PQC_KEM_CTX));
    if (dst == NULL)
        return NULL;

    dst->provctx = src->provctx;
    dst->op = src->op;

    if (src->key != NULL) {
        pqc_prov_key_up_ref(src->key);
        dst->key = src->key;
    }

    if (src->key != NULL) {
        dst->kem = pqc_kem_new(src->key->algorithm);
        if (dst->kem == NULL) {
            pqc_kem_freectx(dst);
            return NULL;
        }
    }

    return dst;
}

/* ========================================================================== */
/* encapsulate_init / encapsulate                                              */
/* ========================================================================== */

static int pqc_kem_encapsulate_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    PQC_KEM_CTX *ctx = (PQC_KEM_CTX *)vctx;
    PQC_PROV_KEY *key = (PQC_PROV_KEY *)vkey;

    (void)params;

    if (ctx == NULL || key == NULL)
        return 0;
    if (key->type != PQC_PROV_KEY_KEM || !key->has_public)
        return 0;

    /* Take a reference to the key */
    pqc_prov_key_up_ref(key);
    if (ctx->key != NULL)
        pqc_prov_key_free(ctx->key);
    ctx->key = key;

    /* Create our own KEM context for the operation */
    if (ctx->kem != NULL)
        pqc_kem_free(ctx->kem);
    ctx->kem = pqc_kem_new(key->algorithm);
    if (ctx->kem == NULL)
        return 0;

    ctx->op = 1; /* encapsulate */
    return 1;
}

static int pqc_kem_encapsulate(void *vctx,
                                unsigned char *out, size_t *outlen,
                                unsigned char *secret, size_t *secretlen)
{
    PQC_KEM_CTX *ctx = (PQC_KEM_CTX *)vctx;

    if (ctx == NULL || ctx->kem == NULL || ctx->key == NULL || ctx->op != 1)
        return 0;

    size_t ct_size = pqc_kem_ciphertext_size(ctx->kem);
    size_t ss_size = pqc_kem_shared_secret_size(ctx->kem);

    /* If out is NULL, caller is querying the required buffer sizes */
    if (out == NULL || secret == NULL) {
        if (outlen != NULL)
            *outlen = ct_size;
        if (secretlen != NULL)
            *secretlen = ss_size;
        return 1;
    }

    if (*outlen < ct_size || *secretlen < ss_size)
        return 0;

    pqc_status_t rc = pqc_kem_encaps(ctx->kem, out, secret,
                                      ctx->key->public_key);
    if (rc != PQC_OK)
        return 0;

    *outlen = ct_size;
    *secretlen = ss_size;
    return 1;
}

/* ========================================================================== */
/* decapsulate_init / decapsulate                                              */
/* ========================================================================== */

static int pqc_kem_decapsulate_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    PQC_KEM_CTX *ctx = (PQC_KEM_CTX *)vctx;
    PQC_PROV_KEY *key = (PQC_PROV_KEY *)vkey;

    (void)params;

    if (ctx == NULL || key == NULL)
        return 0;
    if (key->type != PQC_PROV_KEY_KEM || !key->has_private)
        return 0;

    pqc_prov_key_up_ref(key);
    if (ctx->key != NULL)
        pqc_prov_key_free(ctx->key);
    ctx->key = key;

    if (ctx->kem != NULL)
        pqc_kem_free(ctx->kem);
    ctx->kem = pqc_kem_new(key->algorithm);
    if (ctx->kem == NULL)
        return 0;

    ctx->op = 2; /* decapsulate */
    return 1;
}

static int pqc_kem_decapsulate(void *vctx,
                                unsigned char *secret, size_t *secretlen,
                                const unsigned char *in, size_t inlen)
{
    PQC_KEM_CTX *ctx = (PQC_KEM_CTX *)vctx;

    if (ctx == NULL || ctx->kem == NULL || ctx->key == NULL || ctx->op != 2)
        return 0;

    size_t ss_size = pqc_kem_shared_secret_size(ctx->kem);
    size_t ct_size = pqc_kem_ciphertext_size(ctx->kem);

    /* Size query */
    if (secret == NULL) {
        if (secretlen != NULL)
            *secretlen = ss_size;
        return 1;
    }

    if (*secretlen < ss_size)
        return 0;
    if (inlen != ct_size)
        return 0;

    pqc_status_t rc = pqc_kem_decaps(ctx->kem, secret, in,
                                      ctx->key->secret_key);
    if (rc != PQC_OK)
        return 0;

    *secretlen = ss_size;
    return 1;
}

/* ========================================================================== */
/* get_ctx_params / gettable_ctx_params                                        */
/* ========================================================================== */

static const OSSL_PARAM pqc_kem_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqc_kem_gettable_ctx_params(void *vctx,
                                                      void *provctx)
{
    (void)vctx;
    (void)provctx;
    return pqc_kem_ctx_params;
}

static int pqc_kem_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PQC_KEM_CTX *ctx = (PQC_KEM_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_KEM_PARAM_OPERATION);
    if (p != NULL) {
        const char *op_name = (ctx->op == 1) ? "encapsulate"
                            : (ctx->op == 2) ? "decapsulate"
                            : "none";
        if (!OSSL_PARAM_set_utf8_string(p, op_name))
            return 0;
    }

    return 1;
}

static int pqc_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *pqc_kem_settable_ctx_params(void *vctx,
                                                      void *provctx)
{
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    (void)vctx;
    (void)provctx;
    return empty;
}

/* ========================================================================== */
/* KEM dispatch functions                                                      */
/* ========================================================================== */

static const OSSL_DISPATCH pqc_kem_dispatch[] = {
    { OSSL_FUNC_KEM_NEWCTX,             (void (*)(void))pqc_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX,            (void (*)(void))pqc_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX,             (void (*)(void))pqc_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,   (void (*)(void))pqc_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE,        (void (*)(void))pqc_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,   (void (*)(void))pqc_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE,        (void (*)(void))pqc_kem_decapsulate },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,     (void (*)(void))pqc_kem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,(void (*)(void))pqc_kem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,     (void (*)(void))pqc_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,(void (*)(void))pqc_kem_settable_ctx_params },
    { 0, NULL }
};

/* ========================================================================== */
/* OSSL_ALGORITHM KEM table                                                    */
/* ========================================================================== */

const OSSL_ALGORITHM pqc_kem_table[] = {
    /* ML-KEM (FIPS 203) */
    { "ML-KEM-512",              "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "ML-KEM-768",              "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "ML-KEM-1024",             "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* HQC */
    { "HQC-128",                 "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "HQC-192",                 "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "HQC-256",                 "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* BIKE */
    { "BIKE-L1",                 "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "BIKE-L3",                 "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "BIKE-L5",                 "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* Classic McEliece */
    { "Classic-McEliece-348864", "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "Classic-McEliece-460896", "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "Classic-McEliece-6688128","provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "Classic-McEliece-6960119","provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "Classic-McEliece-8192128","provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* FrodoKEM */
    { "FrodoKEM-640-AES",       "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "FrodoKEM-640-SHAKE",     "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "FrodoKEM-976-AES",       "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "FrodoKEM-976-SHAKE",     "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "FrodoKEM-1344-AES",      "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "FrodoKEM-1344-SHAKE",    "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* NTRU */
    { "NTRU-HPS-2048-509",      "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "NTRU-HPS-2048-677",      "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "NTRU-HPS-4096-821",      "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "NTRU-HRSS-701",          "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* NTRUPrime */
    { "sntrup761",              "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "sntrup857",              "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "sntrup953",              "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "sntrup1013",             "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "sntrup1277",             "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* Hybrid KEMs */
    { "ML-KEM-768+X25519",      "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    { "ML-KEM-1024+P256",       "provider=libpqc-dyber", pqc_kem_dispatch, "" },
    /* sentinel */
    { NULL, NULL, NULL, NULL }
};
