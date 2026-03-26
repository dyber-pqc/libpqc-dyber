/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hint packing/unpacking for ML-DSA signatures (FIPS 204).
 */

#ifndef PQC_MLDSA_HINT_H
#define PQC_MLDSA_HINT_H

#include <stdint.h>

#include "core/sig/mldsa/mldsa_params.h"
#include "core/sig/mldsa/polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pack hint polynomial vector into the signature hint section.
 * The hint format is: for each polynomial, list the indices of nonzero
 * coefficients, then write a cumulative count byte.
 *
 * @param sig_hint  Output buffer (omega + k bytes).
 * @param h         Hint vector.
 * @param k         Dimension.
 * @param omega     Maximum total number of ones.
 */
void pqc_mldsa_pack_hint(uint8_t *sig_hint,
                          const pqc_mldsa_polyveck *h,
                          unsigned k, unsigned omega);

/**
 * Unpack hint polynomial vector from signature.
 *
 * @param h         Output hint vector.
 * @param sig_hint  Packed hint bytes (omega + k bytes).
 * @param k         Dimension.
 * @param omega     Maximum total number of ones.
 * @return          0 on success, -1 if invalid encoding.
 */
int pqc_mldsa_unpack_hint(pqc_mldsa_polyveck *h,
                           const uint8_t *sig_hint,
                           unsigned k, unsigned omega);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_HINT_H */
