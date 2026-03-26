/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * TLS Integration — Internal declarations
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#ifndef PQC_TLS_INTERNAL_H
#define PQC_TLS_INTERNAL_H

#include "pqc_tls.h"
#include <pqc/kem.h>
#include <pqc/sig.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Group definition table (pqc_tls_groups.c)                                   */
/* -------------------------------------------------------------------------- */

typedef struct {
    uint16_t    group_id;
    const char *name;
    const char *pqc_algorithm;      /* libpqc algorithm name */
    int         is_hybrid;
    int         classical_type;     /* 0 = none, 1 = X25519, 2 = P-256 */
    size_t      classical_pk_size;
    size_t      classical_sk_size;  /* not on wire; for internal use */
    size_t      classical_ss_size;
    size_t      pqc_pk_size;        /* client share contribution */
    size_t      pqc_ct_size;        /* server share contribution */
    size_t      pqc_ss_size;
    int         security_level;     /* NIST level 1-5 */
} pqc_tls_group_def_t;

/* Retrieve the group definition for a given group ID. Returns NULL if
 * the group is not recognized. */
const pqc_tls_group_def_t *pqc_tls_find_group(uint16_t group_id);

/* Return the number of supported groups. */
size_t pqc_tls_group_count(void);

/* Return the i-th group definition. */
const pqc_tls_group_def_t *pqc_tls_group_at(size_t index);

/* -------------------------------------------------------------------------- */
/* Signature algorithm table (pqc_tls_sigalgs.c)                               */
/* -------------------------------------------------------------------------- */

typedef struct {
    uint16_t    sigalg_id;
    const char *name;
    const char *pqc_algorithm;      /* libpqc algorithm name */
    size_t      pk_size;
    size_t      sk_size;
    size_t      max_sig_size;
    int         security_level;
} pqc_tls_sigalg_def_t;

/* Retrieve the sigalg definition for a given SignatureScheme code. */
const pqc_tls_sigalg_def_t *pqc_tls_find_sigalg(uint16_t sigalg_id);

/* Return the number of supported signature algorithms. */
size_t pqc_tls_sigalg_count(void);

/* Return the i-th sigalg definition. */
const pqc_tls_sigalg_def_t *pqc_tls_sigalg_at(size_t index);

/* -------------------------------------------------------------------------- */
/* Classical crypto helpers (pqc_tls.c, conditionally compiled)                */
/* -------------------------------------------------------------------------- */

#define PQC_TLS_CLASSICAL_X25519   1
#define PQC_TLS_CLASSICAL_P256     2

/* Generate a classical keypair. pub/priv must be pre-allocated. */
int pqc_tls_classical_keygen(int type,
                              uint8_t *pub, size_t *pub_len,
                              uint8_t *priv, size_t *priv_len);

/* Derive a classical shared secret. */
int pqc_tls_classical_derive(int type,
                              const uint8_t *priv, size_t priv_len,
                              const uint8_t *peer_pub, size_t peer_pub_len,
                              uint8_t *ss, size_t *ss_len);

/* -------------------------------------------------------------------------- */
/* Key-share context (opaque struct)                                           */
/* -------------------------------------------------------------------------- */

struct pqc_tls_keyshare_s {
    const pqc_tls_group_def_t *group;

    /* PQC ephemeral state */
    PQC_KEM  *kem;
    uint8_t  *pqc_pk;
    uint8_t  *pqc_sk;

    /* Classical ephemeral state (hybrid only) */
    uint8_t  *classical_pub;
    size_t    classical_pub_len;
    uint8_t  *classical_priv;
    size_t    classical_priv_len;

    int       generated; /* non-zero after pqc_tls_keyshare_generate */
};

#ifdef __cplusplus
}
#endif

#endif /* PQC_TLS_INTERNAL_H */
