/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Centered Binomial Distribution sampling for ML-KEM (FIPS 203).
 */

#ifndef PQC_MLKEM_CBD_H
#define PQC_MLKEM_CBD_H

#include <stdint.h>

#include "core/kem/mlkem/poly.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sample a polynomial from the centered binomial distribution CBD_eta.
 *
 * @param r    Output polynomial.
 * @param buf  Input buffer of 64 * eta bytes of pseudorandom data.
 * @param eta  Distribution parameter (2 or 3).
 */
void pqc_mlkem_cbd_eta(pqc_mlkem_poly *r, const uint8_t *buf, unsigned int eta);

/** CBD_2: sample from centered binomial distribution with eta=2.
 *  buf must be at least 128 bytes (= 64*2). */
void pqc_mlkem_cbd2(pqc_mlkem_poly *r, const uint8_t buf[128]);

/** CBD_3: sample from centered binomial distribution with eta=3.
 *  buf must be at least 192 bytes (= 64*3). */
void pqc_mlkem_cbd3(pqc_mlkem_poly *r, const uint8_t buf[192]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_CBD_H */
