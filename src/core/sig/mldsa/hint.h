/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hint packing/unpacking for ML-DSA signatures (FIPS 204).
 * Note: hint pack/unpack is now handled directly in packing.c.
 * This header is maintained for backward compatibility.
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#ifndef PQC_MLDSA_HINT_H
#define PQC_MLDSA_HINT_H

#include <stdint.h>

#include "core/sig/mldsa/mldsa_params.h"
#include "core/sig/mldsa/polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hint packing/unpacking functions are kept for compatibility but
 * are no longer called directly - packing.c handles hints inline. */

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_HINT_H */
