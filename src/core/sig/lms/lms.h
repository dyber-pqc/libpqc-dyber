/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS internal interface.
 */

#ifndef PQC_LMS_H
#define PQC_LMS_H

#include <stddef.h>
#include <stdint.h>

#include "lms_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Utility: big-endian u32 read/write                                   */
/* ------------------------------------------------------------------ */

static inline void lms_store_u32(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

static inline uint32_t lms_load_u32(const uint8_t *src) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

/* ------------------------------------------------------------------ */
/* LM-OTS (lmots.c)                                                     */
/* ------------------------------------------------------------------ */

void lmots_keygen(uint8_t *pk, const uint8_t *I, uint32_t q,
                  const uint8_t *seed);
void lmots_sign(uint8_t *sig, const uint8_t *msg, size_t msglen,
                const uint8_t *I, uint32_t q, const uint8_t *seed);
int  lmots_verify(const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, const uint8_t *I, uint32_t q,
                  uint8_t *computed_pk);

/* ------------------------------------------------------------------ */
/* HSS multi-tree (hss.c)                                               */
/* ------------------------------------------------------------------ */

void hss_compute_root(uint8_t *root, const uint8_t *I,
                      const uint8_t *seed, int h);

#ifdef __cplusplus
}
#endif

#endif /* PQC_LMS_H */
