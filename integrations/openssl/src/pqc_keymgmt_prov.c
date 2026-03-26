/*
 * libpqc-dyber OpenSSL 3.x Provider — Key Management
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Implements OSSL_OP_KEYMGMT for all PQC KEM and signature algorithms.
 * Each algorithm gets its own keymgmt entry, but they all share the same
 * dispatch functions — the algorithm name is captured at newctx time.
 */

#include "pqc_provider.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

/* ========================================================================== */
/* Key generation context                                                      */
/* ========================================================================== */

typedef struct {
    PQC_PROV_CTX *provctx;
    char          algorithm[128];
    int           is_kem;  /* 1 = KEM, 0 = SIG */
} PQC_KEYMGMT_GEN_CTX;

/* ========================================================================== */
/* keymgmt_new: allocate a blank key object                                    */
/* ========================================================================== */

static void *pqc_keymgmt_new(void *provctx)
{
    (void)provctx;
    return pqc_prov_key_new();
}

/* ========================================================================== */
/* keymgmt_free                                                                */
/* ========================================================================== */

static void pqc_keymgmt_free(void *keydata)
{
    pqc_prov_key_free((PQC_PROV_KEY *)keydata);
}

/* ========================================================================== */
/* keymgmt_has: check if key has public/private parts                          */
/* ========================================================================== */

static int pqc_keymgmt_has(const void *keydata, int selection)
{
    const PQC_PROV_KEY *key = (const PQC_PROV_KEY *)keydata;
    int ok = 1;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && key->has_public;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && key->has_private;

    return ok;
}

/* ========================================================================== */
/* keymgmt_match: check if two keys are the same                               */
/* ========================================================================== */

static int pqc_keymgmt_match(const void *keydata1, const void *keydata2,
                              int selection)
{
    const PQC_PROV_KEY *k1 = (const PQC_PROV_KEY *)keydata1;
    const PQC_PROV_KEY *k2 = (const PQC_PROV_KEY *)keydata2;

    if (k1 == NULL || k2 == NULL)
        return 0;
    if (strcmp(k1->algorithm, k2->algorithm) != 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (k1->public_key_len != k2->public_key_len)
            return 0;
        if (k1->public_key == NULL || k2->public_key == NULL)
            return 0;
        if (memcmp(k1->public_key, k2->public_key, k1->public_key_len) != 0)
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (k1->secret_key_len != k2->secret_key_len)
            return 0;
        if (k1->secret_key == NULL || k2->secret_key == NULL)
            return 0;
        if (CRYPTO_memcmp(k1->secret_key, k2->secret_key, k1->secret_key_len) != 0)
            return 0;
    }

    return 1;
}

/* ========================================================================== */
/* keymgmt_import / export                                                     */
/* ========================================================================== */

static const OSSL_PARAM pqc_keymgmt_import_export_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqc_keymgmt_import_types(int selection)
{
    (void)selection;
    return pqc_keymgmt_import_export_types;
}

static const OSSL_PARAM *pqc_keymgmt_export_types(int selection)
{
    (void)selection;
    return pqc_keymgmt_import_export_types;
}

static int pqc_keymgmt_import(void *keydata, int selection,
                               const OSSL_PARAM params[])
{
    PQC_PROV_KEY *key = (PQC_PROV_KEY *)keydata;
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            size_t len = 0;
            if (!OSSL_PARAM_get_octet_string(p, (void **)&key->public_key, 0, &len))
                return 0;
            key->public_key_len = len;
            key->has_public = 1;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            size_t len = 0;
            if (!OSSL_PARAM_get_octet_string(p, (void **)&key->secret_key, 0, &len))
                return 0;
            key->secret_key_len = len;
            key->has_private = 1;
        }
    }

    return 1;
}

static int pqc_keymgmt_export(void *keydata, int selection,
                               OSSL_CALLBACK *param_cb, void *cbarg)
{
    PQC_PROV_KEY *key = (PQC_PROV_KEY *)keydata;
    OSSL_PARAM params[3];
    int idx = 0;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, key->public_key, key->public_key_len);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, key->secret_key, key->secret_key_len);
    }

    params[idx] = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

/* ========================================================================== */
/* keymgmt_get_params: report key properties                                   */
/* ========================================================================== */

static const OSSL_PARAM pqc_keymgmt_gettable[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqc_keymgmt_gettable_params(void *provctx)
{
    (void)provctx;
    return pqc_keymgmt_gettable;
}

static int pqc_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    PQC_PROV_KEY *key = (PQC_PROV_KEY *)keydata;
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        int bits = key->security_bits * 2; /* rough: sec_bits * 2 */
        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, key->security_bits))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        /*
         * For KEM: max_size = ciphertext size
         * For SIG: max_size = max signature size
         */
        size_t max_size = 0;
        if (key->type == PQC_PROV_KEY_KEM && key->kem != NULL)
            max_size = pqc_kem_ciphertext_size(key->kem);
        else if (key->type == PQC_PROV_KEY_SIG && key->sig != NULL)
            max_size = pqc_sig_max_signature_size(key->sig);
        if (!OSSL_PARAM_set_size_t(p, max_size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, key->algorithm))
        return 0;

    return 1;
}

/* ========================================================================== */
/* keymgmt_gen_init / gen_set_params / gen / gen_cleanup — key generation       */
/* ========================================================================== */

/*
 * gen_init is called with an algorithm-specific selection.
 * The algorithm name is passed as the "algorithm" property from the
 * OSSL_ALGORITHM entry; we recover it via the provctx+selection.
 *
 * In practice, we create per-algorithm dispatch tables (below) that
 * each call into a common gen_init with the algorithm name baked in.
 */

static void *pqc_keymgmt_gen_init_common(void *provctx, int selection,
                                          const char *algorithm, int is_kem)
{
    PQC_KEYMGMT_GEN_CTX *gctx;
    (void)selection;

    gctx = OPENSSL_zalloc(sizeof(PQC_KEYMGMT_GEN_CTX));
    if (gctx == NULL)
        return NULL;

    gctx->provctx = (PQC_PROV_CTX *)provctx;
    strncpy(gctx->algorithm, algorithm, sizeof(gctx->algorithm) - 1);
    gctx->is_kem = is_kem;
    return gctx;
}

static int pqc_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void)genctx;
    (void)params;
    /* No tunable gen parameters for now */
    return 1;
}

static const OSSL_PARAM *pqc_keymgmt_gen_settable_params(void *genctx,
                                                          void *provctx)
{
    static const OSSL_PARAM empty[] = { OSSL_PARAM_END };
    (void)genctx;
    (void)provctx;
    return empty;
}

static void *pqc_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    PQC_KEYMGMT_GEN_CTX *gctx = (PQC_KEYMGMT_GEN_CTX *)genctx;
    PQC_PROV_KEY *key = NULL;
    pqc_status_t rc;

    (void)cb;
    (void)cbarg;

    if (gctx == NULL)
        return NULL;

    key = pqc_prov_key_new();
    if (key == NULL)
        return NULL;

    strncpy(key->algorithm, gctx->algorithm, sizeof(key->algorithm) - 1);

    if (gctx->is_kem) {
        key->type = PQC_PROV_KEY_KEM;
        key->kem = pqc_kem_new(gctx->algorithm);
        if (key->kem == NULL)
            goto err;

        key->public_key_len = pqc_kem_public_key_size(key->kem);
        key->secret_key_len = pqc_kem_secret_key_size(key->kem);
        key->security_bits  = pqc_security_bits_from_level(
                                  pqc_kem_security_level(key->kem));

        key->public_key = OPENSSL_malloc(key->public_key_len);
        key->secret_key = OPENSSL_malloc(key->secret_key_len);
        if (key->public_key == NULL || key->secret_key == NULL)
            goto err;

        rc = pqc_kem_keygen(key->kem, key->public_key, key->secret_key);
        if (rc != PQC_OK)
            goto err;
    } else {
        key->type = PQC_PROV_KEY_SIG;
        key->sig = pqc_sig_new(gctx->algorithm);
        if (key->sig == NULL)
            goto err;

        key->public_key_len = pqc_sig_public_key_size(key->sig);
        key->secret_key_len = pqc_sig_secret_key_size(key->sig);
        key->security_bits  = pqc_security_bits_from_level(
                                  pqc_sig_security_level(key->sig));

        key->public_key = OPENSSL_malloc(key->public_key_len);
        key->secret_key = OPENSSL_malloc(key->secret_key_len);
        if (key->public_key == NULL || key->secret_key == NULL)
            goto err;

        rc = pqc_sig_keygen(key->sig, key->public_key, key->secret_key);
        if (rc != PQC_OK)
            goto err;
    }

    key->has_public  = 1;
    key->has_private = 1;
    return key;

err:
    pqc_prov_key_free(key);
    return NULL;
}

static void pqc_keymgmt_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

/* ========================================================================== */
/* keymgmt_dup: duplicate a key                                                */
/* ========================================================================== */

static void *pqc_keymgmt_dup(const void *keydata, int selection)
{
    const PQC_PROV_KEY *src = (const PQC_PROV_KEY *)keydata;
    PQC_PROV_KEY *dst;

    if (src == NULL)
        return NULL;

    dst = pqc_prov_key_new();
    if (dst == NULL)
        return NULL;

    dst->type = src->type;
    strncpy(dst->algorithm, src->algorithm, sizeof(dst->algorithm) - 1);
    dst->security_bits = src->security_bits;

    /* Duplicate the underlying PQC context */
    if (src->type == PQC_PROV_KEY_KEM && src->kem != NULL) {
        dst->kem = pqc_kem_new(src->algorithm);
        if (dst->kem == NULL)
            goto err;
    }
    if (src->type == PQC_PROV_KEY_SIG && src->sig != NULL) {
        dst->sig = pqc_sig_new(src->algorithm);
        if (dst->sig == NULL)
            goto err;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && src->has_public) {
        dst->public_key_len = src->public_key_len;
        dst->public_key = OPENSSL_malloc(src->public_key_len);
        if (dst->public_key == NULL)
            goto err;
        memcpy(dst->public_key, src->public_key, src->public_key_len);
        dst->has_public = 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && src->has_private) {
        dst->secret_key_len = src->secret_key_len;
        dst->secret_key = OPENSSL_malloc(src->secret_key_len);
        if (dst->secret_key == NULL)
            goto err;
        memcpy(dst->secret_key, src->secret_key, src->secret_key_len);
        dst->has_private = 1;
    }

    return dst;

err:
    pqc_prov_key_free(dst);
    return NULL;
}

/* ========================================================================== */
/* Per-algorithm gen_init wrappers                                             */
/* ========================================================================== */

/*
 * We use an X-macro pattern to generate per-algorithm gen_init functions
 * and the corresponding dispatch tables.  The OSSL_ALGORITHM table at the
 * bottom ties everything together.
 */

#define DECLARE_KEM_KEYMGMT(ossl_name, c_suffix)                             \
    static void *pqc_keymgmt_kem_##c_suffix##_gen_init(void *provctx,        \
                                                         int selection,      \
                                                         const OSSL_PARAM p[])\
    {                                                                         \
        (void)p;                                                              \
        return pqc_keymgmt_gen_init_common(provctx, selection,                \
                                           ossl_name, 1);                     \
    }                                                                         \
    static const OSSL_DISPATCH pqc_keymgmt_kem_##c_suffix##_fns[] = {         \
        { OSSL_FUNC_KEYMGMT_NEW,              (void (*)(void))pqc_keymgmt_new },             \
        { OSSL_FUNC_KEYMGMT_FREE,             (void (*)(void))pqc_keymgmt_free },            \
        { OSSL_FUNC_KEYMGMT_HAS,              (void (*)(void))pqc_keymgmt_has },             \
        { OSSL_FUNC_KEYMGMT_MATCH,            (void (*)(void))pqc_keymgmt_match },           \
        { OSSL_FUNC_KEYMGMT_IMPORT,           (void (*)(void))pqc_keymgmt_import },          \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,     (void (*)(void))pqc_keymgmt_import_types },    \
        { OSSL_FUNC_KEYMGMT_EXPORT,           (void (*)(void))pqc_keymgmt_export },          \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,     (void (*)(void))pqc_keymgmt_export_types },    \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,       (void (*)(void))pqc_keymgmt_get_params },      \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,  (void (*)(void))pqc_keymgmt_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,         (void (*)(void))pqc_keymgmt_kem_##c_suffix##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,   (void (*)(void))pqc_keymgmt_gen_set_params },  \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))pqc_keymgmt_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN,              (void (*)(void))pqc_keymgmt_gen },             \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,      (void (*)(void))pqc_keymgmt_gen_cleanup },     \
        { OSSL_FUNC_KEYMGMT_DUP,              (void (*)(void))pqc_keymgmt_dup },             \
        { 0, NULL }                                                           \
    };

#define DECLARE_SIG_KEYMGMT(ossl_name, c_suffix)                             \
    static void *pqc_keymgmt_sig_##c_suffix##_gen_init(void *provctx,        \
                                                         int selection,      \
                                                         const OSSL_PARAM p[])\
    {                                                                         \
        (void)p;                                                              \
        return pqc_keymgmt_gen_init_common(provctx, selection,                \
                                           ossl_name, 0);                     \
    }                                                                         \
    static const OSSL_DISPATCH pqc_keymgmt_sig_##c_suffix##_fns[] = {         \
        { OSSL_FUNC_KEYMGMT_NEW,              (void (*)(void))pqc_keymgmt_new },             \
        { OSSL_FUNC_KEYMGMT_FREE,             (void (*)(void))pqc_keymgmt_free },            \
        { OSSL_FUNC_KEYMGMT_HAS,              (void (*)(void))pqc_keymgmt_has },             \
        { OSSL_FUNC_KEYMGMT_MATCH,            (void (*)(void))pqc_keymgmt_match },           \
        { OSSL_FUNC_KEYMGMT_IMPORT,           (void (*)(void))pqc_keymgmt_import },          \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,     (void (*)(void))pqc_keymgmt_import_types },    \
        { OSSL_FUNC_KEYMGMT_EXPORT,           (void (*)(void))pqc_keymgmt_export },          \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,     (void (*)(void))pqc_keymgmt_export_types },    \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,       (void (*)(void))pqc_keymgmt_get_params },      \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,  (void (*)(void))pqc_keymgmt_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,         (void (*)(void))pqc_keymgmt_sig_##c_suffix##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,   (void (*)(void))pqc_keymgmt_gen_set_params },  \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))pqc_keymgmt_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN,              (void (*)(void))pqc_keymgmt_gen },             \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,      (void (*)(void))pqc_keymgmt_gen_cleanup },     \
        { OSSL_FUNC_KEYMGMT_DUP,              (void (*)(void))pqc_keymgmt_dup },             \
        { 0, NULL }                                                           \
    };

/* --- KEM keymgmt declarations --- */
DECLARE_KEM_KEYMGMT("ML-KEM-512",              mlkem512)
DECLARE_KEM_KEYMGMT("ML-KEM-768",              mlkem768)
DECLARE_KEM_KEYMGMT("ML-KEM-1024",             mlkem1024)
DECLARE_KEM_KEYMGMT("HQC-128",                 hqc128)
DECLARE_KEM_KEYMGMT("HQC-192",                 hqc192)
DECLARE_KEM_KEYMGMT("HQC-256",                 hqc256)
DECLARE_KEM_KEYMGMT("BIKE-L1",                 bikeL1)
DECLARE_KEM_KEYMGMT("BIKE-L3",                 bikeL3)
DECLARE_KEM_KEYMGMT("BIKE-L5",                 bikeL5)
DECLARE_KEM_KEYMGMT("Classic-McEliece-348864", mce348864)
DECLARE_KEM_KEYMGMT("Classic-McEliece-460896", mce460896)
DECLARE_KEM_KEYMGMT("Classic-McEliece-6688128",mce6688128)
DECLARE_KEM_KEYMGMT("Classic-McEliece-6960119",mce6960119)
DECLARE_KEM_KEYMGMT("Classic-McEliece-8192128",mce8192128)
DECLARE_KEM_KEYMGMT("FrodoKEM-640-AES",        frodo640aes)
DECLARE_KEM_KEYMGMT("FrodoKEM-640-SHAKE",      frodo640shake)
DECLARE_KEM_KEYMGMT("FrodoKEM-976-AES",        frodo976aes)
DECLARE_KEM_KEYMGMT("FrodoKEM-976-SHAKE",      frodo976shake)
DECLARE_KEM_KEYMGMT("FrodoKEM-1344-AES",       frodo1344aes)
DECLARE_KEM_KEYMGMT("FrodoKEM-1344-SHAKE",     frodo1344shake)
DECLARE_KEM_KEYMGMT("NTRU-HPS-2048-509",       ntruhps2048509)
DECLARE_KEM_KEYMGMT("NTRU-HPS-2048-677",       ntruhps2048677)
DECLARE_KEM_KEYMGMT("NTRU-HPS-4096-821",       ntruhps4096821)
DECLARE_KEM_KEYMGMT("NTRU-HRSS-701",           ntruhrss701)
DECLARE_KEM_KEYMGMT("sntrup761",               sntrup761)
DECLARE_KEM_KEYMGMT("sntrup857",               sntrup857)
DECLARE_KEM_KEYMGMT("sntrup953",               sntrup953)
DECLARE_KEM_KEYMGMT("sntrup1013",              sntrup1013)
DECLARE_KEM_KEYMGMT("sntrup1277",              sntrup1277)
DECLARE_KEM_KEYMGMT("ML-KEM-768+X25519",       mlkem768_x25519)
DECLARE_KEM_KEYMGMT("ML-KEM-1024+P256",        mlkem1024_p256)

/* --- Signature keymgmt declarations --- */
DECLARE_SIG_KEYMGMT("ML-DSA-44",               mldsa44)
DECLARE_SIG_KEYMGMT("ML-DSA-65",               mldsa65)
DECLARE_SIG_KEYMGMT("ML-DSA-87",               mldsa87)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHA2-128s",       slhdsa_sha2_128s)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHA2-128f",       slhdsa_sha2_128f)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHA2-192s",       slhdsa_sha2_192s)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHA2-192f",       slhdsa_sha2_192f)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHA2-256s",       slhdsa_sha2_256s)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHA2-256f",       slhdsa_sha2_256f)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHAKE-128s",      slhdsa_shake_128s)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHAKE-128f",      slhdsa_shake_128f)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHAKE-192s",      slhdsa_shake_192s)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHAKE-192f",      slhdsa_shake_192f)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHAKE-256s",      slhdsa_shake_256s)
DECLARE_SIG_KEYMGMT("SLH-DSA-SHAKE-256f",      slhdsa_shake_256f)
DECLARE_SIG_KEYMGMT("FN-DSA-512",              fndsa512)
DECLARE_SIG_KEYMGMT("FN-DSA-1024",             fndsa1024)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHA2-128s",      sphincs_sha2_128s)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHA2-128f",      sphincs_sha2_128f)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHA2-192s",      sphincs_sha2_192s)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHA2-192f",      sphincs_sha2_192f)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHA2-256s",      sphincs_sha2_256s)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHA2-256f",      sphincs_sha2_256f)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHAKE-128s",     sphincs_shake_128s)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHAKE-128f",     sphincs_shake_128f)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHAKE-192s",     sphincs_shake_192s)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHAKE-192f",     sphincs_shake_192f)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHAKE-256s",     sphincs_shake_256s)
DECLARE_SIG_KEYMGMT("SPHINCS+-SHAKE-256f",     sphincs_shake_256f)
DECLARE_SIG_KEYMGMT("MAYO-1",                  mayo1)
DECLARE_SIG_KEYMGMT("MAYO-2",                  mayo2)
DECLARE_SIG_KEYMGMT("MAYO-3",                  mayo3)
DECLARE_SIG_KEYMGMT("MAYO-5",                  mayo5)
DECLARE_SIG_KEYMGMT("UOV-Is",                  uov_i)
DECLARE_SIG_KEYMGMT("UOV-IIIs",                uov_iii)
DECLARE_SIG_KEYMGMT("UOV-Vs",                  uov_v)
DECLARE_SIG_KEYMGMT("SNOVA-24-5-4",            snova_24_5_4)
DECLARE_SIG_KEYMGMT("SNOVA-25-8-3",            snova_25_8_3)
DECLARE_SIG_KEYMGMT("SNOVA-28-17-3",           snova_28_17_3)
DECLARE_SIG_KEYMGMT("CROSS-RSDP-128-fast",     cross_rsdp_128_fast)
DECLARE_SIG_KEYMGMT("CROSS-RSDP-128-small",    cross_rsdp_128_small)
DECLARE_SIG_KEYMGMT("CROSS-RSDP-192-fast",     cross_rsdp_192_fast)
DECLARE_SIG_KEYMGMT("CROSS-RSDP-192-small",    cross_rsdp_192_small)
DECLARE_SIG_KEYMGMT("CROSS-RSDP-256-fast",     cross_rsdp_256_fast)
DECLARE_SIG_KEYMGMT("CROSS-RSDP-256-small",    cross_rsdp_256_small)
DECLARE_SIG_KEYMGMT("LMS-SHA256-H10",          lms_sha256_h10)
DECLARE_SIG_KEYMGMT("LMS-SHA256-H15",          lms_sha256_h15)
DECLARE_SIG_KEYMGMT("LMS-SHA256-H20",          lms_sha256_h20)
DECLARE_SIG_KEYMGMT("LMS-SHA256-H25",          lms_sha256_h25)
DECLARE_SIG_KEYMGMT("XMSS-SHA2-10-256",        xmss_sha2_10_256)
DECLARE_SIG_KEYMGMT("XMSS-SHA2-16-256",        xmss_sha2_16_256)
DECLARE_SIG_KEYMGMT("XMSS-SHA2-20-256",        xmss_sha2_20_256)
DECLARE_SIG_KEYMGMT("ML-DSA-65+Ed25519",       mldsa65_ed25519)
DECLARE_SIG_KEYMGMT("ML-DSA-87+P256",          mldsa87_p256)

/* ========================================================================== */
/* OSSL_ALGORITHM keymgmt table                                                */
/* ========================================================================== */

#define KEM_KEYMGMT_ENTRY(ossl_name, c_suffix) \
    { ossl_name, "provider=libpqc-dyber", pqc_keymgmt_kem_##c_suffix##_fns, "" },
#define SIG_KEYMGMT_ENTRY(ossl_name, c_suffix) \
    { ossl_name, "provider=libpqc-dyber", pqc_keymgmt_sig_##c_suffix##_fns, "" },

const OSSL_ALGORITHM pqc_keymgmt_table[] = {
    /* KEM keymgmt */
    KEM_KEYMGMT_ENTRY("ML-KEM-512",              mlkem512)
    KEM_KEYMGMT_ENTRY("ML-KEM-768",              mlkem768)
    KEM_KEYMGMT_ENTRY("ML-KEM-1024",             mlkem1024)
    KEM_KEYMGMT_ENTRY("HQC-128",                 hqc128)
    KEM_KEYMGMT_ENTRY("HQC-192",                 hqc192)
    KEM_KEYMGMT_ENTRY("HQC-256",                 hqc256)
    KEM_KEYMGMT_ENTRY("BIKE-L1",                 bikeL1)
    KEM_KEYMGMT_ENTRY("BIKE-L3",                 bikeL3)
    KEM_KEYMGMT_ENTRY("BIKE-L5",                 bikeL5)
    KEM_KEYMGMT_ENTRY("Classic-McEliece-348864", mce348864)
    KEM_KEYMGMT_ENTRY("Classic-McEliece-460896", mce460896)
    KEM_KEYMGMT_ENTRY("Classic-McEliece-6688128",mce6688128)
    KEM_KEYMGMT_ENTRY("Classic-McEliece-6960119",mce6960119)
    KEM_KEYMGMT_ENTRY("Classic-McEliece-8192128",mce8192128)
    KEM_KEYMGMT_ENTRY("FrodoKEM-640-AES",        frodo640aes)
    KEM_KEYMGMT_ENTRY("FrodoKEM-640-SHAKE",      frodo640shake)
    KEM_KEYMGMT_ENTRY("FrodoKEM-976-AES",        frodo976aes)
    KEM_KEYMGMT_ENTRY("FrodoKEM-976-SHAKE",      frodo976shake)
    KEM_KEYMGMT_ENTRY("FrodoKEM-1344-AES",       frodo1344aes)
    KEM_KEYMGMT_ENTRY("FrodoKEM-1344-SHAKE",     frodo1344shake)
    KEM_KEYMGMT_ENTRY("NTRU-HPS-2048-509",       ntruhps2048509)
    KEM_KEYMGMT_ENTRY("NTRU-HPS-2048-677",       ntruhps2048677)
    KEM_KEYMGMT_ENTRY("NTRU-HPS-4096-821",       ntruhps4096821)
    KEM_KEYMGMT_ENTRY("NTRU-HRSS-701",           ntruhrss701)
    KEM_KEYMGMT_ENTRY("sntrup761",               sntrup761)
    KEM_KEYMGMT_ENTRY("sntrup857",               sntrup857)
    KEM_KEYMGMT_ENTRY("sntrup953",               sntrup953)
    KEM_KEYMGMT_ENTRY("sntrup1013",              sntrup1013)
    KEM_KEYMGMT_ENTRY("sntrup1277",              sntrup1277)
    KEM_KEYMGMT_ENTRY("ML-KEM-768+X25519",       mlkem768_x25519)
    KEM_KEYMGMT_ENTRY("ML-KEM-1024+P256",        mlkem1024_p256)
    /* Signature keymgmt */
    SIG_KEYMGMT_ENTRY("ML-DSA-44",               mldsa44)
    SIG_KEYMGMT_ENTRY("ML-DSA-65",               mldsa65)
    SIG_KEYMGMT_ENTRY("ML-DSA-87",               mldsa87)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHA2-128s",       slhdsa_sha2_128s)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHA2-128f",       slhdsa_sha2_128f)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHA2-192s",       slhdsa_sha2_192s)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHA2-192f",       slhdsa_sha2_192f)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHA2-256s",       slhdsa_sha2_256s)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHA2-256f",       slhdsa_sha2_256f)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHAKE-128s",      slhdsa_shake_128s)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHAKE-128f",      slhdsa_shake_128f)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHAKE-192s",      slhdsa_shake_192s)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHAKE-192f",      slhdsa_shake_192f)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHAKE-256s",      slhdsa_shake_256s)
    SIG_KEYMGMT_ENTRY("SLH-DSA-SHAKE-256f",      slhdsa_shake_256f)
    SIG_KEYMGMT_ENTRY("FN-DSA-512",              fndsa512)
    SIG_KEYMGMT_ENTRY("FN-DSA-1024",             fndsa1024)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHA2-128s",      sphincs_sha2_128s)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHA2-128f",      sphincs_sha2_128f)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHA2-192s",      sphincs_sha2_192s)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHA2-192f",      sphincs_sha2_192f)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHA2-256s",      sphincs_sha2_256s)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHA2-256f",      sphincs_sha2_256f)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHAKE-128s",     sphincs_shake_128s)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHAKE-128f",     sphincs_shake_128f)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHAKE-192s",     sphincs_shake_192s)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHAKE-192f",     sphincs_shake_192f)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHAKE-256s",     sphincs_shake_256s)
    SIG_KEYMGMT_ENTRY("SPHINCS+-SHAKE-256f",     sphincs_shake_256f)
    SIG_KEYMGMT_ENTRY("MAYO-1",                  mayo1)
    SIG_KEYMGMT_ENTRY("MAYO-2",                  mayo2)
    SIG_KEYMGMT_ENTRY("MAYO-3",                  mayo3)
    SIG_KEYMGMT_ENTRY("MAYO-5",                  mayo5)
    SIG_KEYMGMT_ENTRY("UOV-Is",                  uov_i)
    SIG_KEYMGMT_ENTRY("UOV-IIIs",                uov_iii)
    SIG_KEYMGMT_ENTRY("UOV-Vs",                  uov_v)
    SIG_KEYMGMT_ENTRY("SNOVA-24-5-4",            snova_24_5_4)
    SIG_KEYMGMT_ENTRY("SNOVA-25-8-3",            snova_25_8_3)
    SIG_KEYMGMT_ENTRY("SNOVA-28-17-3",           snova_28_17_3)
    SIG_KEYMGMT_ENTRY("CROSS-RSDP-128-fast",     cross_rsdp_128_fast)
    SIG_KEYMGMT_ENTRY("CROSS-RSDP-128-small",    cross_rsdp_128_small)
    SIG_KEYMGMT_ENTRY("CROSS-RSDP-192-fast",     cross_rsdp_192_fast)
    SIG_KEYMGMT_ENTRY("CROSS-RSDP-192-small",    cross_rsdp_192_small)
    SIG_KEYMGMT_ENTRY("CROSS-RSDP-256-fast",     cross_rsdp_256_fast)
    SIG_KEYMGMT_ENTRY("CROSS-RSDP-256-small",    cross_rsdp_256_small)
    SIG_KEYMGMT_ENTRY("LMS-SHA256-H10",          lms_sha256_h10)
    SIG_KEYMGMT_ENTRY("LMS-SHA256-H15",          lms_sha256_h15)
    SIG_KEYMGMT_ENTRY("LMS-SHA256-H20",          lms_sha256_h20)
    SIG_KEYMGMT_ENTRY("LMS-SHA256-H25",          lms_sha256_h25)
    SIG_KEYMGMT_ENTRY("XMSS-SHA2-10-256",        xmss_sha2_10_256)
    SIG_KEYMGMT_ENTRY("XMSS-SHA2-16-256",        xmss_sha2_16_256)
    SIG_KEYMGMT_ENTRY("XMSS-SHA2-20-256",        xmss_sha2_20_256)
    SIG_KEYMGMT_ENTRY("ML-DSA-65+Ed25519",       mldsa65_ed25519)
    SIG_KEYMGMT_ENTRY("ML-DSA-87+P256",          mldsa87_p256)
    /* sentinel */
    { NULL, NULL, NULL, NULL }
};
