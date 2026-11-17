/*
 * Vendored from the HQC reference implementation, v5.1.0
 * (https://gitlab.com/pqc-hqc/hqc, tag v5.1.0, commit 06567ccbad10),
 * which is in the public domain. Changes for libpqc-dyber: the
 * unused <immintrin.h> includes are removed so the portable code
 * builds on every architecture, BITMASK shifts a 64-bit one (1UL is
 * 32 bits on Windows, which broke HQC-5 there), and SHA-3/SHAKE and
 * the RNG come from the library (fips202.h, randombytes.h); vector.c
 * marks the key sampler's accept bit public for ctgrind.
 * See ../README.md.
 */
/**
 * @file code.h
 * @brief Header file of code.c
 */

#ifndef HQC_CODE_H
#define HQC_CODE_H

#include <stddef.h>
#include <stdint.h>
#include "parameters.h"

void code_encode(uint64_t *em, const uint64_t *m);
void code_decode(uint64_t *m, const uint64_t *em);

#endif  // HQC_CODE_H
