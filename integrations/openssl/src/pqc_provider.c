/*
 * libpqc-dyber OpenSSL 3.x Provider — Main Entry Point
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Registers all libpqc-dyber PQC algorithms as an OpenSSL provider:
 *   - KEM:        ML-KEM-512/768/1024, HQC, BIKE, McEliece, FrodoKEM, NTRU,
 *                 NTRUPrime, and hybrid KEMs (X25519+ML-KEM-768, P256+ML-KEM-1024)
 *   - Signature:  ML-DSA-44/65/87, SLH-DSA, FN-DSA, SPHINCS+, MAYO, UOV,
 *                 SNOVA, CROSS, LMS, XMSS, and hybrid signatures
 *   - Key Mgmt:   Corresponding keymgmt for all algorithms
 */

#include "pqc_provider.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <string.h>
#include <stdio.h>

/* ========================================================================== */
/* Algorithm info tables                                                       */
/* ========================================================================== */

const PQC_KEM_ALG_INFO pqc_kem_algorithms[] = {
    /* ML-KEM (FIPS 203) */
    { "ML-KEM-512",              PQC_KEM_ML_KEM_512,            128 },
    { "ML-KEM-768",              PQC_KEM_ML_KEM_768,            192 },
    { "ML-KEM-1024",             PQC_KEM_ML_KEM_1024,           256 },
    /* HQC */
    { "HQC-128",                 PQC_KEM_HQC_128,               128 },
    { "HQC-192",                 PQC_KEM_HQC_192,               192 },
    { "HQC-256",                 PQC_KEM_HQC_256,               256 },
    /* BIKE */
    { "BIKE-L1",                 PQC_KEM_BIKE_L1,               128 },
    { "BIKE-L3",                 PQC_KEM_BIKE_L3,               192 },
    { "BIKE-L5",                 PQC_KEM_BIKE_L5,               256 },
    /* Classic McEliece */
    { "Classic-McEliece-348864", PQC_KEM_MCELIECE_348864,       128 },
    { "Classic-McEliece-460896", PQC_KEM_MCELIECE_460896,       192 },
    { "Classic-McEliece-6688128",PQC_KEM_MCELIECE_6688128,      256 },
    { "Classic-McEliece-6960119",PQC_KEM_MCELIECE_6960119,      256 },
    { "Classic-McEliece-8192128",PQC_KEM_MCELIECE_8192128,      256 },
    /* FrodoKEM */
    { "FrodoKEM-640-AES",       PQC_KEM_FRODO_640_AES,          128 },
    { "FrodoKEM-640-SHAKE",     PQC_KEM_FRODO_640_SHAKE,        128 },
    { "FrodoKEM-976-AES",       PQC_KEM_FRODO_976_AES,          192 },
    { "FrodoKEM-976-SHAKE",     PQC_KEM_FRODO_976_SHAKE,        192 },
    { "FrodoKEM-1344-AES",      PQC_KEM_FRODO_1344_AES,        256 },
    { "FrodoKEM-1344-SHAKE",    PQC_KEM_FRODO_1344_SHAKE,      256 },
    /* NTRU */
    { "NTRU-HPS-2048-509",      PQC_KEM_NTRU_HPS_2048_509,     128 },
    { "NTRU-HPS-2048-677",      PQC_KEM_NTRU_HPS_2048_677,     192 },
    { "NTRU-HPS-4096-821",      PQC_KEM_NTRU_HPS_4096_821,     256 },
    { "NTRU-HRSS-701",          PQC_KEM_NTRU_HRSS_701,         192 },
    /* NTRUPrime */
    { "sntrup761",              PQC_KEM_NTRUPRIME_SNTRUP761,    128 },
    { "sntrup857",              PQC_KEM_NTRUPRIME_SNTRUP857,    192 },
    { "sntrup953",              PQC_KEM_NTRUPRIME_SNTRUP953,    192 },
    { "sntrup1013",             PQC_KEM_NTRUPRIME_SNTRUP1013,   256 },
    { "sntrup1277",             PQC_KEM_NTRUPRIME_SNTRUP1277,   256 },
    /* Hybrid KEMs */
    { "ML-KEM-768+X25519",      PQC_KEM_HYBRID_MLKEM768_X25519, 192 },
    { "ML-KEM-1024+P256",       PQC_KEM_HYBRID_MLKEM1024_P256,  256 },
    { NULL, NULL, 0 } /* sentinel */
};
const size_t pqc_kem_algorithm_count =
    (sizeof(pqc_kem_algorithms) / sizeof(pqc_kem_algorithms[0])) - 1;

const PQC_SIG_ALG_INFO pqc_sig_algorithms[] = {
    /* ML-DSA (FIPS 204) */
    { "ML-DSA-44",                 PQC_SIG_ML_DSA_44,               128, 0 },
    { "ML-DSA-65",                 PQC_SIG_ML_DSA_65,               192, 0 },
    { "ML-DSA-87",                 PQC_SIG_ML_DSA_87,               256, 0 },
    /* SLH-DSA (FIPS 205) — SHA2 */
    { "SLH-DSA-SHA2-128s",        PQC_SIG_SLH_DSA_SHA2_128S,       128, 0 },
    { "SLH-DSA-SHA2-128f",        PQC_SIG_SLH_DSA_SHA2_128F,       128, 0 },
    { "SLH-DSA-SHA2-192s",        PQC_SIG_SLH_DSA_SHA2_192S,       192, 0 },
    { "SLH-DSA-SHA2-192f",        PQC_SIG_SLH_DSA_SHA2_192F,       192, 0 },
    { "SLH-DSA-SHA2-256s",        PQC_SIG_SLH_DSA_SHA2_256S,       256, 0 },
    { "SLH-DSA-SHA2-256f",        PQC_SIG_SLH_DSA_SHA2_256F,       256, 0 },
    /* SLH-DSA — SHAKE */
    { "SLH-DSA-SHAKE-128s",       PQC_SIG_SLH_DSA_SHAKE_128S,      128, 0 },
    { "SLH-DSA-SHAKE-128f",       PQC_SIG_SLH_DSA_SHAKE_128F,      128, 0 },
    { "SLH-DSA-SHAKE-192s",       PQC_SIG_SLH_DSA_SHAKE_192S,      192, 0 },
    { "SLH-DSA-SHAKE-192f",       PQC_SIG_SLH_DSA_SHAKE_192F,      192, 0 },
    { "SLH-DSA-SHAKE-256s",       PQC_SIG_SLH_DSA_SHAKE_256S,      256, 0 },
    { "SLH-DSA-SHAKE-256f",       PQC_SIG_SLH_DSA_SHAKE_256F,      256, 0 },
    /* FN-DSA (Falcon) */
    { "FN-DSA-512",                PQC_SIG_FN_DSA_512,              128, 0 },
    { "FN-DSA-1024",               PQC_SIG_FN_DSA_1024,             256, 0 },
    /* SPHINCS+ (legacy names) — SHA2 */
    { "SPHINCS+-SHA2-128s",        PQC_SIG_SPHINCS_SHA2_128S,       128, 0 },
    { "SPHINCS+-SHA2-128f",        PQC_SIG_SPHINCS_SHA2_128F,       128, 0 },
    { "SPHINCS+-SHA2-192s",        PQC_SIG_SPHINCS_SHA2_192S,       192, 0 },
    { "SPHINCS+-SHA2-192f",        PQC_SIG_SPHINCS_SHA2_192F,       192, 0 },
    { "SPHINCS+-SHA2-256s",        PQC_SIG_SPHINCS_SHA2_256S,       256, 0 },
    { "SPHINCS+-SHA2-256f",        PQC_SIG_SPHINCS_SHA2_256F,       256, 0 },
    /* SPHINCS+ — SHAKE */
    { "SPHINCS+-SHAKE-128s",       PQC_SIG_SPHINCS_SHAKE_128S,      128, 0 },
    { "SPHINCS+-SHAKE-128f",       PQC_SIG_SPHINCS_SHAKE_128F,      128, 0 },
    { "SPHINCS+-SHAKE-192s",       PQC_SIG_SPHINCS_SHAKE_192S,      192, 0 },
    { "SPHINCS+-SHAKE-192f",       PQC_SIG_SPHINCS_SHAKE_192F,      192, 0 },
    { "SPHINCS+-SHAKE-256s",       PQC_SIG_SPHINCS_SHAKE_256S,      256, 0 },
    { "SPHINCS+-SHAKE-256f",       PQC_SIG_SPHINCS_SHAKE_256F,      256, 0 },
    /* MAYO */
    { "MAYO-1",                    PQC_SIG_MAYO_1,                  128, 0 },
    { "MAYO-2",                    PQC_SIG_MAYO_2,                  128, 0 },
    { "MAYO-3",                    PQC_SIG_MAYO_3,                  192, 0 },
    { "MAYO-5",                    PQC_SIG_MAYO_5,                  256, 0 },
    /* UOV */
    { "UOV-Is",                    PQC_SIG_UOV_I,                   128, 0 },
    { "UOV-IIIs",                  PQC_SIG_UOV_III,                 192, 0 },
    { "UOV-Vs",                    PQC_SIG_UOV_V,                   256, 0 },
    /* SNOVA */
    { "SNOVA-24-5-4",              PQC_SIG_SNOVA_24_5_4,            128, 0 },
    { "SNOVA-25-8-3",              PQC_SIG_SNOVA_25_8_3,            192, 0 },
    { "SNOVA-28-17-3",             PQC_SIG_SNOVA_28_17_3,           256, 0 },
    /* CROSS */
    { "CROSS-RSDP-128-fast",      PQC_SIG_CROSS_RSDP_128_FAST,     128, 0 },
    { "CROSS-RSDP-128-small",     PQC_SIG_CROSS_RSDP_128_SMALL,    128, 0 },
    { "CROSS-RSDP-192-fast",      PQC_SIG_CROSS_RSDP_192_FAST,     192, 0 },
    { "CROSS-RSDP-192-small",     PQC_SIG_CROSS_RSDP_192_SMALL,    192, 0 },
    { "CROSS-RSDP-256-fast",      PQC_SIG_CROSS_RSDP_256_FAST,     256, 0 },
    { "CROSS-RSDP-256-small",     PQC_SIG_CROSS_RSDP_256_SMALL,    256, 0 },
    /* Stateful hash-based signatures */
    { "LMS-SHA256-H10",           PQC_SIG_LMS_SHA256_H10,          128, 1 },
    { "LMS-SHA256-H15",           PQC_SIG_LMS_SHA256_H15,          128, 1 },
    { "LMS-SHA256-H20",           PQC_SIG_LMS_SHA256_H20,          128, 1 },
    { "LMS-SHA256-H25",           PQC_SIG_LMS_SHA256_H25,          128, 1 },
    { "XMSS-SHA2-10-256",         PQC_SIG_XMSS_SHA2_10_256,        128, 1 },
    { "XMSS-SHA2-16-256",         PQC_SIG_XMSS_SHA2_16_256,        128, 1 },
    { "XMSS-SHA2-20-256",         PQC_SIG_XMSS_SHA2_20_256,        128, 1 },
    /* Hybrid signatures */
    { "ML-DSA-65+Ed25519",        PQC_SIG_HYBRID_MLDSA65_ED25519,  192, 0 },
    { "ML-DSA-87+P256",           PQC_SIG_HYBRID_MLDSA87_P256,     256, 0 },
    { NULL, NULL, 0, 0 } /* sentinel */
};
const size_t pqc_sig_algorithm_count =
    (sizeof(pqc_sig_algorithms) / sizeof(pqc_sig_algorithms[0])) - 1;

/* ========================================================================== */
/* Algorithm lookup helpers                                                    */
/* ========================================================================== */

const PQC_KEM_ALG_INFO *pqc_find_kem_alg(const char *name)
{
    for (size_t i = 0; i < pqc_kem_algorithm_count; i++) {
        if (strcmp(pqc_kem_algorithms[i].ossl_name, name) == 0)
            return &pqc_kem_algorithms[i];
    }
    return NULL;
}

const PQC_SIG_ALG_INFO *pqc_find_sig_alg(const char *name)
{
    for (size_t i = 0; i < pqc_sig_algorithm_count; i++) {
        if (strcmp(pqc_sig_algorithms[i].ossl_name, name) == 0)
            return &pqc_sig_algorithms[i];
    }
    return NULL;
}

/* ========================================================================== */
/* PQC_PROV_KEY allocation/refcount                                            */
/* ========================================================================== */

PQC_PROV_KEY *pqc_prov_key_new(void)
{
    PQC_PROV_KEY *key = OPENSSL_zalloc(sizeof(PQC_PROV_KEY));
    if (key != NULL)
        key->references = 1;
    return key;
}

int pqc_prov_key_up_ref(PQC_PROV_KEY *key)
{
    if (key == NULL)
        return 0;
    key->references++;
    return 1;
}

void pqc_prov_key_free(PQC_PROV_KEY *key)
{
    if (key == NULL)
        return;
    if (--key->references > 0)
        return;

    if (key->kem != NULL)
        pqc_kem_free(key->kem);
    if (key->sig != NULL)
        pqc_sig_free(key->sig);
    if (key->public_key != NULL) {
        OPENSSL_cleanse(key->public_key, key->public_key_len);
        OPENSSL_free(key->public_key);
    }
    if (key->secret_key != NULL) {
        OPENSSL_cleanse(key->secret_key, key->secret_key_len);
        OPENSSL_free(key->secret_key);
    }
    OPENSSL_free(key);
}

/* ========================================================================== */
/* Provider information callbacks                                              */
/* ========================================================================== */

#define PQC_PROV_NAME    "libpqc-dyber"
#define PQC_PROV_VERSION "0.1.0"
#define PQC_PROV_BUILDINFO "libpqc-dyber OpenSSL 3.x PQC provider"

static OSSL_FUNC_provider_gettable_params_fn pqc_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn      pqc_prov_get_params;
static OSSL_FUNC_provider_query_operation_fn pqc_prov_query_operation;
static OSSL_FUNC_provider_get_capabilities_fn pqc_prov_get_capabilities;
static OSSL_FUNC_provider_teardown_fn        pqc_prov_teardown;

static const OSSL_PARAM pqc_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME,       OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION,     OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO,   OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS,      OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pqc_prov_gettable_params(void *provctx)
{
    (void)provctx;
    return pqc_param_types;
}

static int pqc_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PQC_PROV_NAME))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PQC_PROV_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PQC_PROV_BUILDINFO))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

/* ========================================================================== */
/* Query operations                                                            */
/* ========================================================================== */

static const OSSL_ALGORITHM *pqc_prov_query_operation(void *provctx,
                                                       int operation_id,
                                                       int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return pqc_keymgmt_table;
    case OSSL_OP_KEM:
        return pqc_kem_table;
    case OSSL_OP_SIGNATURE:
        return pqc_signature_table;
    default:
        return NULL;
    }
}

/* ========================================================================== */
/* Capabilities (TLS group registration)                                       */
/* ========================================================================== */

static int pqc_prov_get_capabilities(void *provctx,
                                      const char *capability,
                                      OSSL_CALLBACK *cb,
                                      void *arg)
{
    (void)provctx;

    if (strcmp(capability, "TLS-GROUP") == 0) {
        const OSSL_PARAM *group_params = pqc_tls_group_capability(provctx);
        if (group_params == NULL)
            return 1; /* no groups to report, but not an error */

        /*
         * Each group is described by a set of OSSL_PARAM, terminated by
         * OSSL_PARAM_END.  We iterate through the flat array in chunks.
         */
        const OSSL_PARAM *p = group_params;
        while (p->key != NULL) {
            /* Find the end of this group's parameter set */
            const OSSL_PARAM *start = p;
            while (p->key != NULL)
                p++;
            if (!cb(start, arg))
                return 0;
            p++; /* skip the OSSL_PARAM_END */
        }
        return 1;
    }

    return 0;
}

/* ========================================================================== */
/* Provider teardown                                                           */
/* ========================================================================== */

static void pqc_prov_teardown(void *provctx)
{
    PQC_PROV_CTX *ctx = (PQC_PROV_CTX *)provctx;
    pqc_cleanup();
    OPENSSL_free(ctx);
}

/* ========================================================================== */
/* Provider dispatch table                                                     */
/* ========================================================================== */

static const OSSL_DISPATCH pqc_provider_dispatch[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,  (void (*)(void))pqc_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,       (void (*)(void))pqc_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,  (void (*)(void))pqc_prov_query_operation },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))pqc_prov_get_capabilities },
    { OSSL_FUNC_PROVIDER_TEARDOWN,         (void (*)(void))pqc_prov_teardown },
    { 0, NULL }
};

/* ========================================================================== */
/* OSSL_provider_init — the single exported entry point                        */
/* ========================================================================== */

#if defined(_WIN32)
__declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    PQC_PROV_CTX *ctx;

    /* Initialize libpqc */
    if (pqc_init() != PQC_OK)
        return 0;

    /* Allocate provider context */
    ctx = OPENSSL_zalloc(sizeof(PQC_PROV_CTX));
    if (ctx == NULL) {
        pqc_cleanup();
        return 0;
    }
    ctx->handle = handle;

    /* Extract core functions we might need */
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            ctx->core_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            ctx->core_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            break;
        }
    }

    *out = pqc_provider_dispatch;
    *provctx = ctx;
    return 1;
}
