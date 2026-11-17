/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC registration. The implementation is the HQC v5.1.0 reference
 * (ref/, see README.md), one translation unit per level (hqc1.c,
 * hqc3.c, hqc5.c).
 */

#include "pqc/common.h"
#include "core/kem/kem_internal.h"

extern const pqc_kem_vtable_t pqc_hqc1_vtable;
extern const pqc_kem_vtable_t pqc_hqc3_vtable;
extern const pqc_kem_vtable_t pqc_hqc5_vtable;

int pqc_kem_hqc_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&pqc_hqc1_vtable);
    rc |= pqc_kem_add_vtable(&pqc_hqc3_vtable);
    rc |= pqc_kem_add_vtable(&pqc_hqc5_vtable);
    return rc;
}
