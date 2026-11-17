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
 * @file parsing.h
 * @brief Header file for parsing.c
 */

#ifndef HQC_PARSING_H
#define HQC_PARSING_H

#include <stdint.h>
#include "parameters.h"

void hqc_dk_pke_from_string(uint64_t *y, const uint8_t *dk_pke);
void hqc_ek_pke_from_string(uint64_t *h, uint64_t *s, const uint8_t *ek_pke);

void hqc_c_kem_to_string(uint8_t *ct, const uint64_t *u, const uint64_t *v, const uint8_t *salt);
void hqc_c_kem_from_string(uint64_t *u, uint64_t *v, uint8_t *salt, const uint8_t *ct);

#endif  // HQC_PARSING_H
