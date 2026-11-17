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
 * @file    data_structures.h
 * @brief   HQC-PKE and HQC-KEM ciphertext data structures.
 */

#ifndef HQC_DATA_STRUCTURES_H
#define HQC_DATA_STRUCTURES_H

#include <stdint.h>
#include "parameters.h"

/**
 * @brief 128-bit codeword representation.
 *
 * A Reed-Muller RM(1,7) codeword is 128 bits long. This union allows
 * viewing the same data as an array of bytes or 32-bit words.
 */
typedef union {
    uint8_t u8[16];  /**< Byte-wise access (16 bytes) */
    uint32_t u32[4]; /**< Word-wise access (4 32-bit words) */
} rm_codeword_t;

#endif  // HQC_DATA_STRUCTURES_H
