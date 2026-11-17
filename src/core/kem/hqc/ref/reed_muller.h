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
 * @file reed_muller.h
 * @brief Header file of reed_muller.c
 */

#ifndef HQC_REED_MULLER_H
#define HQC_REED_MULLER_H

#include <stddef.h>
#include <stdint.h>
#include "parameters.h"

void reed_muller_encode(uint64_t* cdw, const uint64_t* msg);
void reed_muller_decode(uint64_t* msg, const uint64_t* cdw);

#endif  // HQC_REED_MULLER_H
