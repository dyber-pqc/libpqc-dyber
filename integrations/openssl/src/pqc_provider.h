/*
 * libpqc-dyber OpenSSL 3.x Provider — Internal Header
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#ifndef PQC_PROVIDER_H
#define PQC_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>

#include <pqc/pqc.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Provider context                                                            */
/* -------------------------------------------------------------------------- */

typedef struct pqc_prov_ctx_s {
    const OSSL_CORE_HANDLE *handle;
    OSSL_FUNC_core_get_params_fn *core_get_params;
    OSSL_FUNC_core_get_libctx_fn *core_get_libctx;
} PQC_PROV_CTX;

/* -------------------------------------------------------------------------- */
/* Key types                                                                   */
/* -------------------------------------------------------------------------- */

typedef enum {
    PQC_PROV_KEY_KEM = 1,
    PQC_PROV_KEY_SIG = 2,
} pqc_prov_key_type_t;

typedef struct pqc_prov_key_s {
    pqc_prov_key_type_t type;
    char algorithm[128];
    int references;

    /* KEM context (non-NULL if type == KEM) */
    PQC_KEM *kem;
    /* SIG context (non-NULL if type == SIG) */
    PQC_SIG *sig;

    /* Key material */
    uint8_t *public_key;
    size_t   public_key_len;
    uint8_t *secret_key;
    size_t   secret_key_len;

    /* Indicates which parts of the key are populated */
    int has_public;
    int has_private;

    /* Security level (NIST category) */
    int security_bits;
} PQC_PROV_KEY;

/* -------------------------------------------------------------------------- */
/* Algorithm descriptor tables                                                 */
/* -------------------------------------------------------------------------- */

/*
 * KEM algorithm descriptor — maps an OpenSSL algorithm name to libpqc name
 * and records key/ciphertext/shared-secret sizes.
 */
typedef struct {
    const char *ossl_name;    /* Name registered with OpenSSL */
    const char *pqc_name;     /* Name passed to pqc_kem_new() */
    int         security_bits;
} PQC_KEM_ALG_INFO;

/*
 * Signature algorithm descriptor.
 */
typedef struct {
    const char *ossl_name;
    const char *pqc_name;
    int         security_bits;
    int         is_stateful;
} PQC_SIG_ALG_INFO;

/* Global algorithm tables — defined in pqc_provider.c */
extern const PQC_KEM_ALG_INFO pqc_kem_algorithms[];
extern const size_t            pqc_kem_algorithm_count;

extern const PQC_SIG_ALG_INFO pqc_sig_algorithms[];
extern const size_t            pqc_sig_algorithm_count;

/* -------------------------------------------------------------------------- */
/* Sub-provider dispatch tables                                                */
/* -------------------------------------------------------------------------- */

/* Key management — defined in pqc_keymgmt_prov.c */
extern const OSSL_ALGORITHM pqc_keymgmt_table[];

/* KEM operations — defined in pqc_kem_prov.c */
extern const OSSL_ALGORITHM pqc_kem_table[];

/* Signature operations — defined in pqc_sig_prov.c */
extern const OSSL_ALGORITHM pqc_signature_table[];

/* -------------------------------------------------------------------------- */
/* TLS group registration — defined in pqc_tls_groups.c                        */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char *name;           /* Group name (e.g., "X25519MLKEM768") */
    const char *kem_algorithm;  /* Underlying KEM algorithm name */
    unsigned int group_id;      /* IANA TLS group identifier */
    int          security_bits;
    int          min_tls;       /* Minimum TLS version (TLS 1.3 = 0x0304) */
    int          max_tls;       /* Maximum TLS version */
    int          max_dtls;      /* Maximum DTLS version (0 = not supported) */
    int          is_kem;        /* Always 1 for KEM groups */
} PQC_TLS_GROUP_INFO;

extern const PQC_TLS_GROUP_INFO pqc_tls_groups[];
extern const size_t              pqc_tls_group_count;

const OSSL_PARAM *pqc_tls_group_capability(void *provctx);

/* -------------------------------------------------------------------------- */
/* Helper functions                                                            */
/* -------------------------------------------------------------------------- */

/* Find a KEM algorithm by OpenSSL name */
const PQC_KEM_ALG_INFO *pqc_find_kem_alg(const char *name);

/* Find a SIG algorithm by OpenSSL name */
const PQC_SIG_ALG_INFO *pqc_find_sig_alg(const char *name);

/* Security bits from NIST level */
static inline int pqc_security_bits_from_level(pqc_security_level_t level)
{
    switch (level) {
    case PQC_SECURITY_LEVEL_1: return 128;
    case PQC_SECURITY_LEVEL_2: return 128;
    case PQC_SECURITY_LEVEL_3: return 192;
    case PQC_SECURITY_LEVEL_4: return 192;
    case PQC_SECURITY_LEVEL_5: return 256;
    default:                   return 128;
    }
}

/* Allocate a new PQC_PROV_KEY */
PQC_PROV_KEY *pqc_prov_key_new(void);

/* Reference counting */
int pqc_prov_key_up_ref(PQC_PROV_KEY *key);
void pqc_prov_key_free(PQC_PROV_KEY *key);

#ifdef __cplusplus
}
#endif

#endif /* PQC_PROVIDER_H */
