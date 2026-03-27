/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Modular arithmetic helpers for ML-KEM (FIPS 203).
 * Barrett and Montgomery reductions modulo q = 3329.
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#include <stdint.h>
#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/reduce.h"

/*************************************************
* Name:        pqc_mlkem_montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^{-1} mod q, where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^{-1} modulo q.
**************************************************/
int16_t pqc_mlkem_montgomery_reduce(int32_t a)
{
    int16_t t;

    t = (int16_t)((int16_t)a * (int16_t)PQC_MLKEM_QINV);
    t = (int16_t)((a - (int32_t)t * PQC_MLKEM_Q) >> 16);
    return t;
}

/*************************************************
* Name:        pqc_mlkem_barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in
*              {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
int16_t pqc_mlkem_barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t v = (int16_t)(((1L << 26) + PQC_MLKEM_Q / 2) / PQC_MLKEM_Q);

    t  = (int16_t)(((int32_t)v * a + (1 << 25)) >> 26);
    t  = (int16_t)(t * PQC_MLKEM_Q);
    return (int16_t)(a - t);
}
