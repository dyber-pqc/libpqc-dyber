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
 * @file gf2x.h
 * @brief Header file for gf2x.c
 */

#ifndef HQC_GF2X_H
#define HQC_GF2X_H

#include <stdint.h>

void vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2);

#endif  // HQC_GF2X_H
