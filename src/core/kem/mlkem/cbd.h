/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Centered Binomial Distribution sampling for ML-KEM (FIPS 203).
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#ifndef PQC_MLKEM_CBD_H
#define PQC_MLKEM_CBD_H

#include <stdint.h>

#include "core/kem/mlkem/poly.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sample polynomial from CBD with eta=2.
 * buf must be at least 2*N/4 = 128 bytes.
 */
void pqc_mlkem_cbd2(pqc_mlkem_poly *r, const uint8_t buf[128]);

/**
 * Sample polynomial from CBD with eta=3.
 * buf must be at least 3*N/4 = 192 bytes.
 */
void pqc_mlkem_cbd3(pqc_mlkem_poly *r, const uint8_t buf[192]);

/**
 * Sample a polynomial from the centered binomial distribution CBD_eta.
 *
 * @param r    Output polynomial.
 * @param buf  Input buffer of eta * N/4 bytes of pseudorandom data.
 * @param eta  Distribution parameter (2 or 3).
 */
void pqc_mlkem_cbd_eta(pqc_mlkem_poly *r, const uint8_t *buf, unsigned int eta);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_CBD_H */
