/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Internal KEM vtable and registration.
 */

#ifndef PQC_KEM_INTERNAL_H
#define PQC_KEM_INTERNAL_H

#include "pqc/common.h"
#include "pqc/kem.h"

typedef struct {
    const char *algorithm_name;
    pqc_security_level_t security_level;
    const char *nist_standard;

    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;

    pqc_status_t (*keygen)(uint8_t *pk, uint8_t *sk);
    pqc_status_t (*encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    pqc_status_t (*decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} pqc_kem_vtable_t;

struct pqc_kem_s {
    const pqc_kem_vtable_t *vtable;
};

/* Registration functions for each algorithm family */
int pqc_kem_add_vtable(const pqc_kem_vtable_t *vt);
int pqc_kem_register_all(void);
const pqc_kem_vtable_t *pqc_kem_find_vtable(const char *algorithm);

/* Algorithm family registration */
#ifdef PQC_ENABLE_KEM_MLKEM
int pqc_kem_mlkem_register(void);
#endif
#ifdef PQC_ENABLE_KEM_HQC
int pqc_kem_hqc_register(void);
#endif
#ifdef PQC_ENABLE_KEM_BIKE
int pqc_kem_bike_register(void);
#endif
#ifdef PQC_ENABLE_KEM_MCELIECE
int pqc_kem_mceliece_register(void);
#endif
#ifdef PQC_ENABLE_KEM_FRODO
int pqc_kem_frodo_register(void);
#endif
#ifdef PQC_ENABLE_KEM_NTRU
int pqc_kem_ntru_register(void);
#endif
#ifdef PQC_ENABLE_KEM_NTRUPRIME
int pqc_kem_ntruprime_register(void);
#endif

/* Hybrid KEM registration */
#if defined(PQC_ENABLE_HYBRID_KEM) || defined(PQC_ENABLE_HYBRID)
int pqc_hybrid_kem_register(void);
#endif

#define PQC_KEM_MAX_ALGORITHMS 64

#endif /* PQC_KEM_INTERNAL_H */
