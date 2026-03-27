/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) parameter definitions.
 */

#ifndef PQC_SLHDSA_PARAMS_H
#define PQC_SLHDSA_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Hash mode identifiers                                                */
/* ------------------------------------------------------------------ */
#define SLHDSA_HASH_SHA2   0
#define SLHDSA_HASH_SHAKE  1

/* ------------------------------------------------------------------ */
/* Maximum parameter bounds (for stack allocation)                      */
/* ------------------------------------------------------------------ */
#define SLHDSA_MAX_N            32  /* max security parameter bytes     */
#define SLHDSA_MAX_WOTS_LEN     67  /* max WOTS+ chain count            */
#define SLHDSA_MAX_FORS_TREES   35  /* max k (FORS trees)               */
#define SLHDSA_MAX_D            22  /* max hypertree layers              */
#define SLHDSA_MAX_A            14  /* max FORS tree height              */
#define SLHDSA_MAX_TREE_HEIGHT  12  /* max height of single XMSS tree   */

/* ------------------------------------------------------------------ */
/* ADRS (address) constants                                             */
/* ------------------------------------------------------------------ */
#define SLHDSA_ADDR_BYTES       32

/* Address type values per FIPS 205 */
#define SLHDSA_ADDR_TYPE_WOTS       0
#define SLHDSA_ADDR_TYPE_WOTSPK     1
#define SLHDSA_ADDR_TYPE_HASHTREE   2
#define SLHDSA_ADDR_TYPE_FORSTREE   3
#define SLHDSA_ADDR_TYPE_FORSPK     4
#define SLHDSA_ADDR_TYPE_WOTSPRF    5
#define SLHDSA_ADDR_TYPE_FORSPRF    6

/* ------------------------------------------------------------------ */
/* Parameter set structure                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;       /* e.g. "SLH-DSA-SHA2-128s"                */
    int hash_id;            /* SLHDSA_HASH_SHA2 or SLHDSA_HASH_SHAKE   */

    uint32_t n;             /* security parameter (hash output bytes)  */
    uint32_t h;             /* total tree height                       */
    uint32_t d;             /* number of hypertree layers              */
    uint32_t hp;            /* height of each XMSS tree = h/d          */
    uint32_t a;             /* FORS tree height (log2 of leaves)       */
    uint32_t k;             /* number of FORS trees                    */
    uint32_t w;             /* Winternitz parameter                    */

    uint32_t wots_len1;     /* ceil(8n / log2(w))                      */
    uint32_t wots_len2;     /* floor(log2(wots_len1*(w-1))/log2(w))+1  */
    uint32_t wots_len;      /* wots_len1 + wots_len2                   */
    uint32_t wots_sig_bytes;/* n * wots_len                            */

    size_t pk_bytes;        /* public key = 2*n                        */
    size_t sk_bytes;        /* secret key = 4*n                        */
    size_t sig_bytes;       /* total signature size                    */

    size_t fors_sig_bytes;  /* k * (a+1) * n                           */
    size_t ht_sig_bytes;    /* d * (hp * n + wots_sig_bytes)           */
} slhdsa_params_t;

/* ------------------------------------------------------------------ */
/* The 12 FIPS 205 parameter sets                                       */
/* ------------------------------------------------------------------ */

/*
 * SHA2 parameter sets
 *
 * 128s: n=16, h=63, d=7,  hp=9,  a=12, k=14, w=16
 * 128f: n=16, h=66, d=22, hp=3,  a=6,  k=33, w=16
 * 192s: n=24, h=63, d=7,  hp=9,  a=14, k=17, w=16
 * 192f: n=24, h=66, d=22, hp=3,  a=8,  k=33, w=16
 * 256s: n=32, h=64, d=8,  hp=8,  a=14, k=22, w=16
 * 256f: n=32, h=68, d=17, hp=4,  a=9,  k=35, w=16
 */

/* WOTS+ lengths for w=16:
 * n=16: len1=32, len2=3, len=35
 * n=24: len1=48, len2=3, len=51
 * n=32: len1=64, len2=3, len=67
 */

static const slhdsa_params_t SLHDSA_SHA2_128S = {
    .name = "SLH-DSA-SHA2-128s",
    .hash_id = SLHDSA_HASH_SHA2,
    .n = 16, .h = 63, .d = 7, .hp = 9,
    .a = 12, .k = 14, .w = 16,
    .wots_len1 = 32, .wots_len2 = 3, .wots_len = 35,
    .wots_sig_bytes = 560,
    .pk_bytes = 32, .sk_bytes = 64,
    .sig_bytes = 7856,
    .fors_sig_bytes = 2912,     /* 14*(12+1)*16 */
    .ht_sig_bytes = 4944,       /* 7*(9*16 + 560) */
};

static const slhdsa_params_t SLHDSA_SHA2_128F = {
    .name = "SLH-DSA-SHA2-128f",
    .hash_id = SLHDSA_HASH_SHA2,
    .n = 16, .h = 66, .d = 22, .hp = 3,
    .a = 6, .k = 33, .w = 16,
    .wots_len1 = 32, .wots_len2 = 3, .wots_len = 35,
    .wots_sig_bytes = 560,
    .pk_bytes = 32, .sk_bytes = 64,
    .sig_bytes = 17088,
    .fors_sig_bytes = 3696,     /* 33*(6+1)*16 */
    .ht_sig_bytes = 13392,      /* 22*(3*16 + 560) */
};

static const slhdsa_params_t SLHDSA_SHA2_192S = {
    .name = "SLH-DSA-SHA2-192s",
    .hash_id = SLHDSA_HASH_SHA2,
    .n = 24, .h = 63, .d = 7, .hp = 9,
    .a = 14, .k = 17, .w = 16,
    .wots_len1 = 48, .wots_len2 = 3, .wots_len = 51,
    .wots_sig_bytes = 1224,
    .pk_bytes = 48, .sk_bytes = 96,
    .sig_bytes = 16224,
    .fors_sig_bytes = 6120,     /* 17*(14+1)*24 */
    .ht_sig_bytes = 10104,      /* 7*(9*24 + 1224) */
};

static const slhdsa_params_t SLHDSA_SHA2_192F = {
    .name = "SLH-DSA-SHA2-192f",
    .hash_id = SLHDSA_HASH_SHA2,
    .n = 24, .h = 66, .d = 22, .hp = 3,
    .a = 8, .k = 33, .w = 16,
    .wots_len1 = 48, .wots_len2 = 3, .wots_len = 51,
    .wots_sig_bytes = 1224,
    .pk_bytes = 48, .sk_bytes = 96,
    .sig_bytes = 35664,
    .fors_sig_bytes = 7128,     /* 33*(8+1)*24 */
    .ht_sig_bytes = 28512,      /* 22*(3*24 + 1224) */
};

static const slhdsa_params_t SLHDSA_SHA2_256S = {
    .name = "SLH-DSA-SHA2-256s",
    .hash_id = SLHDSA_HASH_SHA2,
    .n = 32, .h = 64, .d = 8, .hp = 8,
    .a = 14, .k = 22, .w = 16,
    .wots_len1 = 64, .wots_len2 = 3, .wots_len = 67,
    .wots_sig_bytes = 2144,
    .pk_bytes = 64, .sk_bytes = 128,
    .sig_bytes = 29792,
    .fors_sig_bytes = 10560,    /* 22*(14+1)*32 */
    .ht_sig_bytes = 19232,      /* 8*(8*32 + 2144) */
};

static const slhdsa_params_t SLHDSA_SHA2_256F = {
    .name = "SLH-DSA-SHA2-256f",
    .hash_id = SLHDSA_HASH_SHA2,
    .n = 32, .h = 68, .d = 17, .hp = 4,
    .a = 9, .k = 35, .w = 16,
    .wots_len1 = 64, .wots_len2 = 3, .wots_len = 67,
    .wots_sig_bytes = 2144,
    .pk_bytes = 64, .sk_bytes = 128,
    .sig_bytes = 49856,
    .fors_sig_bytes = 11200,    /* 35*(9+1)*32 */
    .ht_sig_bytes = 38656,      /* 17*(4*32 + 2144) */
};

/* SHAKE parameter sets (same structure, different hash) */

static const slhdsa_params_t SLHDSA_SHAKE_128S = {
    .name = "SLH-DSA-SHAKE-128s",
    .hash_id = SLHDSA_HASH_SHAKE,
    .n = 16, .h = 63, .d = 7, .hp = 9,
    .a = 12, .k = 14, .w = 16,
    .wots_len1 = 32, .wots_len2 = 3, .wots_len = 35,
    .wots_sig_bytes = 560,
    .pk_bytes = 32, .sk_bytes = 64,
    .sig_bytes = 7856,
    .fors_sig_bytes = 2912,
    .ht_sig_bytes = 4944,
};

static const slhdsa_params_t SLHDSA_SHAKE_128F = {
    .name = "SLH-DSA-SHAKE-128f",
    .hash_id = SLHDSA_HASH_SHAKE,
    .n = 16, .h = 66, .d = 22, .hp = 3,
    .a = 6, .k = 33, .w = 16,
    .wots_len1 = 32, .wots_len2 = 3, .wots_len = 35,
    .wots_sig_bytes = 560,
    .pk_bytes = 32, .sk_bytes = 64,
    .sig_bytes = 17088,
    .fors_sig_bytes = 3696,
    .ht_sig_bytes = 13392,
};

static const slhdsa_params_t SLHDSA_SHAKE_192S = {
    .name = "SLH-DSA-SHAKE-192s",
    .hash_id = SLHDSA_HASH_SHAKE,
    .n = 24, .h = 63, .d = 7, .hp = 9,
    .a = 14, .k = 17, .w = 16,
    .wots_len1 = 48, .wots_len2 = 3, .wots_len = 51,
    .wots_sig_bytes = 1224,
    .pk_bytes = 48, .sk_bytes = 96,
    .sig_bytes = 16224,
    .fors_sig_bytes = 6120,
    .ht_sig_bytes = 10104,
};

static const slhdsa_params_t SLHDSA_SHAKE_192F = {
    .name = "SLH-DSA-SHAKE-192f",
    .hash_id = SLHDSA_HASH_SHAKE,
    .n = 24, .h = 66, .d = 22, .hp = 3,
    .a = 8, .k = 33, .w = 16,
    .wots_len1 = 48, .wots_len2 = 3, .wots_len = 51,
    .wots_sig_bytes = 1224,
    .pk_bytes = 48, .sk_bytes = 96,
    .sig_bytes = 35664,
    .fors_sig_bytes = 7128,
    .ht_sig_bytes = 28512,
};

static const slhdsa_params_t SLHDSA_SHAKE_256S = {
    .name = "SLH-DSA-SHAKE-256s",
    .hash_id = SLHDSA_HASH_SHAKE,
    .n = 32, .h = 64, .d = 8, .hp = 8,
    .a = 14, .k = 22, .w = 16,
    .wots_len1 = 64, .wots_len2 = 3, .wots_len = 67,
    .wots_sig_bytes = 2144,
    .pk_bytes = 64, .sk_bytes = 128,
    .sig_bytes = 29792,
    .fors_sig_bytes = 10560,
    .ht_sig_bytes = 19232,
};

static const slhdsa_params_t SLHDSA_SHAKE_256F = {
    .name = "SLH-DSA-SHAKE-256f",
    .hash_id = SLHDSA_HASH_SHAKE,
    .n = 32, .h = 68, .d = 17, .hp = 4,
    .a = 9, .k = 35, .w = 16,
    .wots_len1 = 64, .wots_len2 = 3, .wots_len = 67,
    .wots_sig_bytes = 2144,
    .pk_bytes = 64, .sk_bytes = 128,
    .sig_bytes = 49856,
    .fors_sig_bytes = 11200,
    .ht_sig_bytes = 38656,
};

#ifdef __cplusplus
}
#endif

#endif /* PQC_SLHDSA_PARAMS_H */
