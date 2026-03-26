/*
 * libpqc-dyber OpenSSL 3.x Provider — Signature Operations
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Implements OSSL_OP_SIGNATURE dispatch for all PQC signature algorithms.
 * PQC signatures are message-based (not digest-based), so DigestSign/Verify
 * collects the full message and then calls pqc_sig_sign/verify in one shot.
 */

#include "pqc_provider.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

/* ========================================================================== */
/* Signature operation context                                                 */
/* ========================================================================== */

typedef struct {
    PQC_PROV_CTX *provctx;
    PQC_PROV_KEY *key;           /* borrowed ref, up_ref'd */
    PQC_SIG      *sig;           /* owned copy for the operation */
    int           op;            /* 0 = unset, 1 = sign, 2 = verify */

    /* Message accumulator for DigestSign/DigestVerify */
    unsigned char *msg_buf;
    size_t         msg_len;
    size_t         msg_alloc;
} PQC_SIG_CTX;

/* ========================================================================== */
/* newctx / freectx / dupctx                                                   */
/* ========================================================================== */

static void *pqc_prov_sig_newctx(void *provctx, const char *propq)
{
    PQC_SIG_CTX *ctx;
    (void)propq;

    ctx = OPENSSL_zalloc(sizeof(PQC_SIG_CTX));
    if (ctx != NULL)
        ctx->provctx = (PQC_PROV_CTX *)provctx;
    return ctx;
}

static void pqc_prov_sig_freectx(void *vctx)
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;
    if (ctx == NULL)
        return;
    if (ctx->sig != NULL)
        pqc_sig_free(ctx->sig);
    if (ctx->key != NULL)
        pqc_prov_key_free(ctx->key);
    if (ctx->msg_buf != NULL) {
        OPENSSL_cleanse(ctx->msg_buf, ctx->msg_alloc);
        OPENSSL_free(ctx->msg_buf);
    }
    OPENSSL_free(ctx);
}

static void *pqc_prov_sig_dupctx(void *vctx)
{
    PQC_SIG_CTX *src = (PQC_SIG_CTX *)vctx;
    PQC_SIG_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(PQC_SIG_CTX));
    if (dst == NULL)
        return NULL;

    dst->provctx = src->provctx;
    dst->op = src->op;

    if (src->key != NULL) {
        pqc_prov_key_up_ref(src->key);
        dst->key = src->key;
    }

    if (src->key != NULL) {
        dst->sig = pqc_sig_new(src->key->algorithm);
        if (dst->sig == NULL) {
            pqc_prov_sig_freectx(dst);
            return NULL;
        }
    }

    if (src->msg_buf != NULL && src->msg_len > 0) {
        dst->msg_buf = OPENSSL_malloc(src->msg_alloc);
        if (dst->msg_buf == NULL) {
            pqc_prov_sig_freectx(dst);
            return NULL;
        }
        memcpy(dst->msg_buf, src->msg_buf, src->msg_len);
        dst->msg_len = src->msg_len;
        dst->msg_alloc = src->msg_alloc;
    }

    return dst;
}

/* ========================================================================== */
/* Helper: set up the context with a key                                       */
/* ========================================================================== */

static int pqc_prov_sig_setup(PQC_SIG_CTX *ctx, PQC_PROV_KEY *key, int op)
{
    if (ctx == NULL || key == NULL)
        return 0;
    if (key->type != PQC_PROV_KEY_SIG)
        return 0;

    pqc_prov_key_up_ref(key);
    if (ctx->key != NULL)
        pqc_prov_key_free(ctx->key);
    ctx->key = key;

    if (ctx->sig != NULL)
        pqc_sig_free(ctx->sig);
    ctx->sig = pqc_sig_new(key->algorithm);
    if (ctx->sig == NULL)
        return 0;

    ctx->op = op;

    /* Reset message buffer */
    ctx->msg_len = 0;

    return 1;
}

/* ========================================================================== */
/* sign_init / sign                                                            */
/* ========================================================================== */

static int pqc_prov_sig_sign_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[])
{
    (void)params;
    return pqc_prov_sig_setup((PQC_SIG_CTX *)vctx, (PQC_PROV_KEY *)vkey, 1);
}

static int pqc_prov_sig_sign(void *vctx,
                              unsigned char *sig_out, size_t *siglen,
                              size_t sigsize,
                              const unsigned char *tbs, size_t tbslen)
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->sig == NULL || ctx->key == NULL || ctx->op != 1)
        return 0;

    size_t max_sig = pqc_sig_max_signature_size(ctx->sig);

    /* Size query */
    if (sig_out == NULL) {
        *siglen = max_sig;
        return 1;
    }

    if (sigsize < max_sig)
        return 0;
    if (!ctx->key->has_private)
        return 0;

    pqc_status_t rc = pqc_sig_sign(ctx->sig, sig_out, siglen,
                                    tbs, tbslen,
                                    ctx->key->secret_key);
    return (rc == PQC_OK) ? 1 : 0;
}

/* ========================================================================== */
/* verify_init / verify                                                        */
/* ========================================================================== */

static int pqc_prov_sig_verify_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    (void)params;
    return pqc_prov_sig_setup((PQC_SIG_CTX *)vctx, (PQC_PROV_KEY *)vkey, 2);
}

static int pqc_prov_sig_verify(void *vctx,
                                const unsigned char *sig_in, size_t siglen,
                                const unsigned char *tbs, size_t tbslen)
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->sig == NULL || ctx->key == NULL || ctx->op != 2)
        return 0;
    if (!ctx->key->has_public)
        return 0;

    pqc_status_t rc = pqc_sig_verify(ctx->sig, tbs, tbslen,
                                      sig_in, siglen,
                                      ctx->key->public_key);
    return (rc == PQC_OK) ? 1 : 0;
}

/* ========================================================================== */
/* DigestSign: message accumulation mode                                       */
/* ========================================================================== */

static int pqc_sig_digest_sign_init(void *vctx, const char *mdname,
                                     void *vkey, const OSSL_PARAM params[])
{
    (void)mdname; /* PQC sigs are not digest-based */
    (void)params;
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;

    if (!pqc_prov_sig_setup(ctx, (PQC_PROV_KEY *)vkey, 1))
        return 0;

    return 1;
}

static int pqc_sig_digest_sign_update(void *vctx,
                                       const unsigned char *data,
                                       size_t datalen)
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;
    if (ctx == NULL || datalen == 0)
        return (ctx != NULL) ? 1 : 0;

    size_t needed = ctx->msg_len + datalen;
    if (needed > ctx->msg_alloc) {
        size_t new_alloc = (needed < 4096) ? 4096 : needed * 2;
        unsigned char *new_buf = OPENSSL_realloc(ctx->msg_buf, new_alloc);
        if (new_buf == NULL)
            return 0;
        ctx->msg_buf = new_buf;
        ctx->msg_alloc = new_alloc;
    }
    memcpy(ctx->msg_buf + ctx->msg_len, data, datalen);
    ctx->msg_len += datalen;
    return 1;
}

static int pqc_sig_digest_sign_final(void *vctx,
                                      unsigned char *sig_out, size_t *siglen,
                                      size_t sigsize)
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->sig == NULL || ctx->key == NULL)
        return 0;

    size_t max_sig = pqc_sig_max_signature_size(ctx->sig);

    if (sig_out == NULL) {
        *siglen = max_sig;
        return 1;
    }

    if (sigsize < max_sig)
        return 0;
    if (!ctx->key->has_private)
        return 0;

    pqc_status_t rc = pqc_sig_sign(ctx->sig, sig_out, siglen,
                                    ctx->msg_buf, ctx->msg_len,
                                    ctx->key->secret_key);
    return (rc == PQC_OK) ? 1 : 0;
}

/* ========================================================================== */
/* DigestVerify: message accumulation mode                                     */
/* ========================================================================== */

static int pqc_sig_digest_verify_init(void *vctx, const char *mdname,
                                       void *vkey, const OSSL_PARAM params[])
{
    (void)mdname;
    (void)params;
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;

    if (!pqc_prov_sig_setup(ctx, (PQC_PROV_KEY *)vkey, 2))
        return 0;

    return 1;
}

static int pqc_sig_digest_verify_update(void *vctx,
                                         const unsigned char *data,
                                         size_t datalen)
{
    /* Reuse the same accumulator logic */
    return pqc_sig_digest_sign_update(vctx, data, datalen);
}

static int pqc_sig_digest_verify_final(void *vctx,
                                        const unsigned char *sig_in,
                                        size_t siglen)
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->sig == NULL || ctx->key == NULL)
        return 0;
    if (!ctx->key->has_public)
        return 0;

    pqc_status_t rc = pqc_sig_verify(ctx->sig,
                                      ctx->msg_buf, ctx->msg_len,
                                      sig_in, siglen,
                                      ctx->key->public_key);
    return (rc == PQC_OK) ? 1 : 0;
}

/* ========================================================================== */
/* ctx params                                                                  */
/* ========================================================================== */

static const OSSL_PARAM pqc_sig_ctx_gettable[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqc_sig_gettable_ctx_params(void *vctx,
                                                      void *provctx)
{
    (void)vctx;
    (void)provctx;
    return pqc_sig_ctx_gettable;
}

static int pqc_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PQC_SIG_CTX *ctx = (PQC_SIG_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        /* PQC algorithms don't use an AlgorithmIdentifier DER blob in the
         * traditional sense; return the algorithm name as a placeholder. */
        if (ctx->key != NULL) {
            if (!OSSL_PARAM_set_utf8_string(p, ctx->key->algorithm))
                return 0;
        }
    }

    return 1;
}

static int pqc_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *pqc_sig_settable_ctx_params(void *vctx,
                                                      void *provctx)
{
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    (void)vctx;
    (void)provctx;
    return empty;
}

/* ========================================================================== */
/* Signature dispatch table                                                    */
/* ========================================================================== */

static const OSSL_DISPATCH pqc_sig_dispatch[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,               (void (*)(void))pqc_prov_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,              (void (*)(void))pqc_prov_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,               (void (*)(void))pqc_prov_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,            (void (*)(void))pqc_prov_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,                 (void (*)(void))pqc_prov_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,          (void (*)(void))pqc_prov_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,               (void (*)(void))pqc_prov_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,     (void (*)(void))pqc_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,   (void (*)(void))pqc_sig_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,    (void (*)(void))pqc_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,   (void (*)(void))pqc_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))pqc_sig_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,  (void (*)(void))pqc_sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,       (void (*)(void))pqc_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,  (void (*)(void))pqc_sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,       (void (*)(void))pqc_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,  (void (*)(void))pqc_sig_settable_ctx_params },
    { 0, NULL }
};

/* ========================================================================== */
/* OSSL_ALGORITHM signature table                                              */
/* ========================================================================== */

const OSSL_ALGORITHM pqc_signature_table[] = {
    /* ML-DSA (FIPS 204) */
    { "ML-DSA-44",               "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "ML-DSA-65",               "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "ML-DSA-87",               "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* SLH-DSA (FIPS 205) — SHA2 */
    { "SLH-DSA-SHA2-128s",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHA2-128f",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHA2-192s",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHA2-192f",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHA2-256s",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHA2-256f",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* SLH-DSA — SHAKE */
    { "SLH-DSA-SHAKE-128s",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHAKE-128f",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHAKE-192s",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHAKE-192f",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHAKE-256s",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SLH-DSA-SHAKE-256f",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* FN-DSA (Falcon) */
    { "FN-DSA-512",             "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "FN-DSA-1024",            "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* SPHINCS+ (legacy) — SHA2 */
    { "SPHINCS+-SHA2-128s",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHA2-128f",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHA2-192s",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHA2-192f",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHA2-256s",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHA2-256f",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* SPHINCS+ — SHAKE */
    { "SPHINCS+-SHAKE-128s",    "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHAKE-128f",    "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHAKE-192s",    "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHAKE-192f",    "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHAKE-256s",    "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SPHINCS+-SHAKE-256f",    "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* MAYO */
    { "MAYO-1",                 "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "MAYO-2",                 "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "MAYO-3",                 "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "MAYO-5",                 "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* UOV */
    { "UOV-Is",                 "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "UOV-IIIs",               "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "UOV-Vs",                 "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* SNOVA */
    { "SNOVA-24-5-4",           "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SNOVA-25-8-3",           "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "SNOVA-28-17-3",          "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* CROSS */
    { "CROSS-RSDP-128-fast",   "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "CROSS-RSDP-128-small",  "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "CROSS-RSDP-192-fast",   "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "CROSS-RSDP-192-small",  "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "CROSS-RSDP-256-fast",   "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "CROSS-RSDP-256-small",  "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* Stateful hash-based */
    { "LMS-SHA256-H10",        "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "LMS-SHA256-H15",        "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "LMS-SHA256-H20",        "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "LMS-SHA256-H25",        "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "XMSS-SHA2-10-256",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "XMSS-SHA2-16-256",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "XMSS-SHA2-20-256",      "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* Hybrid signatures */
    { "ML-DSA-65+Ed25519",     "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    { "ML-DSA-87+P256",        "provider=libpqc-dyber", pqc_sig_dispatch, "" },
    /* sentinel */
    { NULL, NULL, NULL, NULL }
};
