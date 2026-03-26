/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hybrid cryptographic scheme API (PQC + classical).
 */

#ifndef PQC_HYBRID_H
#define PQC_HYBRID_H

#include "pqc/kem.h"
#include "pqc/sig.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hybrid schemes combine a post-quantum algorithm with a classical one.
 * They use the same PQC_KEM / PQC_SIG API — just pass the hybrid algorithm
 * name (e.g., "ML-KEM-768+X25519") to pqc_kem_new() or pqc_sig_new().
 *
 * The combined shared secret / signature contains both components,
 * ensuring security holds even if one algorithm is broken.
 */

/* List available hybrid KEM algorithm names */
PQC_API int pqc_hybrid_kem_count(void);
PQC_API const char *pqc_hybrid_kem_name(int index);

/* List available hybrid signature algorithm names */
PQC_API int pqc_hybrid_sig_count(void);
PQC_API const char *pqc_hybrid_sig_name(int index);

#ifdef __cplusplus
}
#endif

#endif /* PQC_HYBRID_H */
