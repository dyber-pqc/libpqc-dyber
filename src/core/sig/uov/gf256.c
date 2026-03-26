/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV - GF(256) arithmetic.
 *
 * GF(256) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1).
 * Irreducible polynomial: 0x11B.
 * Multiplication via log/exp (discrete logarithm) tables with
 * generator g = 0x03.
 */

#include <stdint.h>
#include "uov.h"

/* ------------------------------------------------------------------ */
/* Log and exp tables for GF(256) with generator 0x03                   */
/* ------------------------------------------------------------------ */

static uint8_t gf256_exp_tab[512];
static uint8_t gf256_log_tab[256];
static int gf256_tables_initialized = 0;

static void gf256_init_tables(void)
{
    int i;
    uint16_t x = 1;

    if (gf256_tables_initialized) return;

    for (i = 0; i < 255; i++) {
        gf256_exp_tab[i] = (uint8_t)x;
        gf256_log_tab[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) {
            x ^= 0x11B;  /* reduce mod x^8 + x^4 + x^3 + x + 1 */
        }
    }
    /* Extend exp table for easy modular lookup */
    for (i = 255; i < 512; i++) {
        gf256_exp_tab[i] = gf256_exp_tab[i - 255];
    }
    gf256_log_tab[0] = 0; /* convention; log(0) is undefined */

    gf256_tables_initialized = 1;
}

/* ------------------------------------------------------------------ */
/* Public functions                                                     */
/* ------------------------------------------------------------------ */

uint8_t gf256_add(uint8_t a, uint8_t b)
{
    return a ^ b;
}

uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0) return 0;
    gf256_init_tables();
    return gf256_exp_tab[gf256_log_tab[a] + gf256_log_tab[b]];
}

uint8_t gf256_inv(uint8_t a)
{
    if (a == 0) return 0;
    gf256_init_tables();
    return gf256_exp_tab[255 - gf256_log_tab[a]];
}
