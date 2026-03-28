/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Internal Signature vtable and registration.
 */

#ifndef PQC_SIG_INTERNAL_H
#define PQC_SIG_INTERNAL_H

#include "pqc/common.h"
#include "pqc/sig.h"

typedef struct {
    const char *algorithm_name;
    pqc_security_level_t security_level;
    const char *nist_standard;
    int is_stateful;

    size_t public_key_size;
    size_t secret_key_size;
    size_t max_signature_size;

    pqc_status_t (*keygen)(uint8_t *pk, uint8_t *sk);
    pqc_status_t (*sign)(uint8_t *sig, size_t *siglen,
                         const uint8_t *msg, size_t msglen,
                         const uint8_t *sk);
    pqc_status_t (*verify)(const uint8_t *msg, size_t msglen,
                           const uint8_t *sig, size_t siglen,
                           const uint8_t *pk);
    /* For stateful schemes */
    pqc_status_t (*sign_stateful)(uint8_t *sig, size_t *siglen,
                                  const uint8_t *msg, size_t msglen,
                                  uint8_t *sk);
} pqc_sig_vtable_t;

struct pqc_sig_s {
    const pqc_sig_vtable_t *vtable;
};

int pqc_sig_add_vtable(const pqc_sig_vtable_t *vt);
int pqc_sig_register_all(void);
const pqc_sig_vtable_t *pqc_sig_find_vtable(const char *algorithm);

/* Algorithm family registration */
#ifdef PQC_ENABLE_SIG_MLDSA
int pqc_sig_mldsa_register(void);
#endif
#ifdef PQC_ENABLE_SIG_SLHDSA
int pqc_sig_slhdsa_register(void);
#endif
#ifdef PQC_ENABLE_SIG_FNDSA
int pqc_sig_fndsa_register(void);
#endif
#ifdef PQC_ENABLE_SIG_SPHINCSPLUS
int pqc_sig_sphincsplus_register(void);
#endif
#ifdef PQC_ENABLE_SIG_MAYO
int pqc_sig_mayo_register(void);
#endif
#ifdef PQC_ENABLE_SIG_UOV
int pqc_sig_uov_register(void);
#endif
#ifdef PQC_ENABLE_SIG_SNOVA
int pqc_sig_snova_register(void);
#endif
#ifdef PQC_ENABLE_SIG_CROSS
int pqc_sig_cross_register(void);
#endif
#ifdef PQC_ENABLE_SIG_LMS
int pqc_sig_lms_register(void);
#endif
#ifdef PQC_ENABLE_SIG_XMSS
int pqc_sig_xmss_register(void);
#endif

/* Hybrid SIG registration */
#if defined(PQC_ENABLE_HYBRID_SIG) || defined(PQC_ENABLE_HYBRID)
int pqc_hybrid_sig_register(void);
#endif

#define PQC_SIG_MAX_ALGORITHMS 128

#endif /* PQC_SIG_INTERNAL_H */
