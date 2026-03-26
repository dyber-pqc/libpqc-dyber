/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Unified Signature dispatcher and algorithm registry.
 */

#include <string.h>
#include <stdlib.h>

#include "pqc/sig.h"
#include "pqc/algorithms.h"
#include "pqc/pqc_config.h"
#include "core/sig/sig_internal.h"

static const pqc_sig_vtable_t *sig_vtables[PQC_SIG_MAX_ALGORITHMS];
static int sig_count = 0;
static int sig_initialized = 0;

int pqc_sig_add_vtable(const pqc_sig_vtable_t *vt) {
    if (sig_count >= PQC_SIG_MAX_ALGORITHMS) {
        return -1;
    }
    sig_vtables[sig_count++] = vt;
    return 0;
}

int pqc_sig_register_all(void) {
    if (sig_initialized) return 0;
    sig_initialized = 1;

#ifdef PQC_ENABLE_SIG_MLDSA
    pqc_sig_mldsa_register();
#endif
#ifdef PQC_ENABLE_SIG_SLHDSA
    pqc_sig_slhdsa_register();
#endif
#ifdef PQC_ENABLE_SIG_FNDSA
    pqc_sig_fndsa_register();
#endif
#ifdef PQC_ENABLE_SIG_SPHINCSPLUS
    pqc_sig_sphincsplus_register();
#endif
#ifdef PQC_ENABLE_SIG_MAYO
    pqc_sig_mayo_register();
#endif
#ifdef PQC_ENABLE_SIG_UOV
    pqc_sig_uov_register();
#endif
#ifdef PQC_ENABLE_SIG_SNOVA
    pqc_sig_snova_register();
#endif
#ifdef PQC_ENABLE_SIG_CROSS
    pqc_sig_cross_register();
#endif
#ifdef PQC_ENABLE_SIG_LMS
    pqc_sig_lms_register();
#endif
#ifdef PQC_ENABLE_SIG_XMSS
    pqc_sig_xmss_register();
#endif

    return 0;
}

const pqc_sig_vtable_t *pqc_sig_find_vtable(const char *algorithm) {
    pqc_sig_register_all();
    for (int i = 0; i < sig_count; i++) {
        if (strcmp(sig_vtables[i]->algorithm_name, algorithm) == 0) {
            return sig_vtables[i];
        }
    }
    return NULL;
}

/* Public API */

PQC_SIG *pqc_sig_new(const char *algorithm) {
    if (!algorithm) return NULL;

    const pqc_sig_vtable_t *vt = pqc_sig_find_vtable(algorithm);
    if (!vt) return NULL;

    PQC_SIG *sig = (PQC_SIG *)calloc(1, sizeof(PQC_SIG));
    if (!sig) return NULL;

    sig->vtable = vt;
    return sig;
}

void pqc_sig_free(PQC_SIG *sig) {
    if (sig) {
        volatile uint8_t *p = (volatile uint8_t *)sig;
        for (size_t i = 0; i < sizeof(PQC_SIG); i++) {
            p[i] = 0;
        }
        free(sig);
    }
}

const char *pqc_sig_algorithm(const PQC_SIG *sig) {
    return sig ? sig->vtable->algorithm_name : NULL;
}

size_t pqc_sig_public_key_size(const PQC_SIG *sig) {
    return sig ? sig->vtable->public_key_size : 0;
}

size_t pqc_sig_secret_key_size(const PQC_SIG *sig) {
    return sig ? sig->vtable->secret_key_size : 0;
}

size_t pqc_sig_max_signature_size(const PQC_SIG *sig) {
    return sig ? sig->vtable->max_signature_size : 0;
}

pqc_security_level_t pqc_sig_security_level(const PQC_SIG *sig) {
    return sig ? sig->vtable->security_level : 0;
}

int pqc_sig_is_stateful(const PQC_SIG *sig) {
    return sig ? sig->vtable->is_stateful : 0;
}

pqc_status_t pqc_sig_keygen(const PQC_SIG *sig, uint8_t *pk, uint8_t *sk) {
    if (!sig || !pk || !sk) return PQC_ERROR_INVALID_ARGUMENT;
    return sig->vtable->keygen(pk, sk);
}

pqc_status_t pqc_sig_sign(const PQC_SIG *sig,
                           uint8_t *signature, size_t *signature_len,
                           const uint8_t *message, size_t message_len,
                           const uint8_t *secret_key) {
    if (!sig || !signature || !signature_len || !message || !secret_key)
        return PQC_ERROR_INVALID_ARGUMENT;
    return sig->vtable->sign(signature, signature_len, message, message_len,
                             secret_key);
}

pqc_status_t pqc_sig_verify(const PQC_SIG *sig,
                             const uint8_t *message, size_t message_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *public_key) {
    if (!sig || !message || !signature || !public_key)
        return PQC_ERROR_INVALID_ARGUMENT;
    return sig->vtable->verify(message, message_len, signature, signature_len,
                               public_key);
}

pqc_status_t pqc_sig_sign_stateful(const PQC_SIG *sig,
                                    uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    uint8_t *secret_key) {
    if (!sig || !signature || !signature_len || !message || !secret_key)
        return PQC_ERROR_INVALID_ARGUMENT;
    if (!sig->vtable->is_stateful || !sig->vtable->sign_stateful)
        return PQC_ERROR_NOT_SUPPORTED;
    return sig->vtable->sign_stateful(signature, signature_len, message,
                                      message_len, secret_key);
}

int pqc_sig_algorithm_count(void) {
    pqc_sig_register_all();
    return sig_count;
}

const char *pqc_sig_algorithm_name(int index) {
    pqc_sig_register_all();
    if (index < 0 || index >= sig_count) return NULL;
    return sig_vtables[index]->algorithm_name;
}

int pqc_sig_is_enabled(const char *algorithm) {
    return pqc_sig_find_vtable(algorithm) != NULL;
}
