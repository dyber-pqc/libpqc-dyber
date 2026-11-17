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
 * @file crypto_memset.h
 * @brief Header file for crypto_memset.c
 */

#ifndef HQC_CRYPTO_MEMSET_H
#define HQC_CRYPTO_MEMSET_H

#include <stddef.h>

/**
 * safer call to memset https://github.com/veorq/cryptocoding#problem-4
 */
extern void *(*volatile memset_volatile)(void *, int, size_t);

/**
 * @def memset_zero
 * @brief Securely zero a memory region.
 */
#define memset_zero(ptr, len) memset_volatile((ptr), 0, (len))

#endif  // HQC_CRYPTO_MEMSET_H
