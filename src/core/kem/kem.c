/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Unified KEM dispatcher and algorithm registry.
 */

#include <string.h>
#include <stdlib.h>

#include "pqc/kem.h"
#include "pqc/algorithms.h"
#include "pqc/pqc_config.h"
#include "core/kem/kem_internal.h"

static const pqc_kem_vtable_t *kem_vtables[PQC_KEM_MAX_ALGORITHMS];
static int kem_count = 0;
static int kem_initialized = 0;

int pqc_kem_add_vtable(const pqc_kem_vtable_t *vt) {
    if (kem_count >= PQC_KEM_MAX_ALGORITHMS) {
        return -1;
    }
    kem_vtables[kem_count++] = vt;
    return 0;
}

int pqc_kem_register_all(void) {
    if (kem_initialized) return 0;
    kem_initialized = 1;

#ifdef PQC_ENABLE_KEM_MLKEM
    pqc_kem_mlkem_register();
#endif
#ifdef PQC_ENABLE_KEM_HQC
    pqc_kem_hqc_register();
#endif
#ifdef PQC_ENABLE_KEM_BIKE
    pqc_kem_bike_register();
#endif
#ifdef PQC_ENABLE_KEM_MCELIECE
    pqc_kem_mceliece_register();
#endif
#ifdef PQC_ENABLE_KEM_FRODO
    pqc_kem_frodo_register();
#endif
#ifdef PQC_ENABLE_KEM_NTRU
    pqc_kem_ntru_register();
#endif
#ifdef PQC_ENABLE_KEM_NTRUPRIME
    pqc_kem_ntruprime_register();
#endif

    return 0;
}

const pqc_kem_vtable_t *pqc_kem_find_vtable(const char *algorithm) {
    pqc_kem_register_all();
    for (int i = 0; i < kem_count; i++) {
        if (strcmp(kem_vtables[i]->algorithm_name, algorithm) == 0) {
            return kem_vtables[i];
        }
    }
    return NULL;
}

/* Public API */

PQC_KEM *pqc_kem_new(const char *algorithm) {
    if (!algorithm) return NULL;

    const pqc_kem_vtable_t *vt = pqc_kem_find_vtable(algorithm);
    if (!vt) return NULL;

    PQC_KEM *kem = (PQC_KEM *)calloc(1, sizeof(PQC_KEM));
    if (!kem) return NULL;

    kem->vtable = vt;
    return kem;
}

void pqc_kem_free(PQC_KEM *kem) {
    if (kem) {
        /* Zeroize before freeing */
        volatile uint8_t *p = (volatile uint8_t *)kem;
        for (size_t i = 0; i < sizeof(PQC_KEM); i++) {
            p[i] = 0;
        }
        free(kem);
    }
}

const char *pqc_kem_algorithm(const PQC_KEM *kem) {
    return kem ? kem->vtable->algorithm_name : NULL;
}

size_t pqc_kem_public_key_size(const PQC_KEM *kem) {
    return kem ? kem->vtable->public_key_size : 0;
}

size_t pqc_kem_secret_key_size(const PQC_KEM *kem) {
    return kem ? kem->vtable->secret_key_size : 0;
}

size_t pqc_kem_ciphertext_size(const PQC_KEM *kem) {
    return kem ? kem->vtable->ciphertext_size : 0;
}

size_t pqc_kem_shared_secret_size(const PQC_KEM *kem) {
    return kem ? kem->vtable->shared_secret_size : 0;
}

pqc_security_level_t pqc_kem_security_level(const PQC_KEM *kem) {
    return kem ? kem->vtable->security_level : 0;
}

pqc_status_t pqc_kem_keygen(const PQC_KEM *kem, uint8_t *pk, uint8_t *sk) {
    if (!kem || !pk || !sk) return PQC_ERROR_INVALID_ARGUMENT;
    return kem->vtable->keygen(pk, sk);
}

pqc_status_t pqc_kem_encaps(const PQC_KEM *kem, uint8_t *ct, uint8_t *ss,
                             const uint8_t *pk) {
    if (!kem || !ct || !ss || !pk) return PQC_ERROR_INVALID_ARGUMENT;
    return kem->vtable->encaps(ct, ss, pk);
}

pqc_status_t pqc_kem_decaps(const PQC_KEM *kem, uint8_t *ss, const uint8_t *ct,
                             const uint8_t *sk) {
    if (!kem || !ss || !ct || !sk) return PQC_ERROR_INVALID_ARGUMENT;
    return kem->vtable->decaps(ss, ct, sk);
}

int pqc_kem_algorithm_count(void) {
    pqc_kem_register_all();
    return kem_count;
}

const char *pqc_kem_algorithm_name(int index) {
    pqc_kem_register_all();
    if (index < 0 || index >= kem_count) return NULL;
    return kem_vtables[index]->algorithm_name;
}

int pqc_kem_is_enabled(const char *algorithm) {
    return pqc_kem_find_vtable(algorithm) != NULL;
}
