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
 * @file hqc.h
 * @brief Header file for hqc.c
 */

#ifndef HQC_HQC_H
#define HQC_HQC_H

#include <stdint.h>
#include "parameters.h"
#include "parsing.h"

void hqc_pke_keygen(uint8_t *ek_pke, uint8_t *dk_pke, uint8_t *seed);
void hqc_pke_encrypt(uint64_t *u, uint64_t *v, const uint8_t *ek_pke, const uint64_t *m, const uint8_t *theta);
uint8_t hqc_pke_decrypt(uint64_t *m, const uint8_t *dk_pke, const uint64_t *u, const uint64_t *v);

#endif  // HQC_HQC_H
