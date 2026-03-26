/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Constant-time operations for side-channel resistance.
 * All functions avoid branches and table lookups on secret data.
 */

#ifndef PQC_CT_OPS_H
#define PQC_CT_OPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constant-time equality test.
 * Returns 1 if a == b, 0 otherwise.
 */
uint32_t pqc_ct_eq(uint32_t a, uint32_t b);

/*
 * Constant-time inequality test.
 * Returns 1 if a != b, 0 otherwise.
 */
uint32_t pqc_ct_ne(uint32_t a, uint32_t b);

/*
 * Constant-time unsigned less-than.
 * Returns 1 if a < b, 0 otherwise.
 */
uint32_t pqc_ct_lt(uint32_t a, uint32_t b);

/*
 * Constant-time conditional select.
 * Returns a if selector == 0, b if selector == 1.
 * selector MUST be 0 or 1.
 */
uint32_t pqc_ct_select(uint32_t a, uint32_t b, uint32_t selector);

/*
 * Constant-time conditional move.
 * If selector == 1, copies src to dst. If selector == 0, dst is unchanged.
 * selector MUST be 0 or 1.
 */
void pqc_ct_cmov(uint8_t *dst, const uint8_t *src, size_t len,
                  uint32_t selector);

/*
 * Constant-time memory comparison.
 * Returns 0 if the first len bytes of a and b are equal, nonzero otherwise.
 * Timing does not depend on the contents of a or b.
 */
int pqc_ct_memcmp(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_CT_OPS_H */
